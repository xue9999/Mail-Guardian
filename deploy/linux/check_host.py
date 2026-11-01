#!/usr/bin/python3 -I
"""Read-only prerequisites for one Guardian Ubuntu amd64 host.

No packages, services, containers, files, credentials, or mailbox state are
changed. Successful checks are prerequisites, not deployment acceptance.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

RELEASES = frozenset(("24.04", "26.04", "26.10"))
MIN_FREE_BYTES = 2 << 30
DOCKER = "/usr/bin/docker"
DOCKER_HOST = "unix:///var/run/docker.sock"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
REQUIRED_EXECUTABLES = (
    "/usr/bin/python3", "/usr/bin/systemctl", "/usr/bin/sudo", "/usr/sbin/visudo",
    "/usr/sbin/useradd", "/usr/bin/dmesg", DOCKER,
)
STORAGE_PATHS = ("/var/lib/docker", "/var/lib/containerd", "/var/lib/mail-guardian")
STORAGE_ERRORS = re.compile(
    r"I/O error(?:,| on)|EXT4-fs.*(?:failed to convert unwritten|Aborting journal|Remounting filesystem read-only)|"
    r"EXT4-fs error|XFS.*(?:Corruption|I/O error|Filesystem has been shut down)|BTRFS.*(?:error|corrupt)",
    re.IGNORECASE,
)
LIMITATIONS = (
    "No container is started or pulled, and no mailbox or credentials are accessed.",
    "Network reachability, external IPv4/IPv6 exposure, image execution, scheduling, reboot and restore still require acceptance.",
)


class CheckError(Exception):
    pass


def run(args, timeout=15, max_output=64 << 10):
    """Bound both pipe streams and time; never return dependency diagnostics."""
    proc = None
    try:
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=ENV, close_fds=True, start_new_session=True)
        output = bytearray()
        counts = {"stdout": 0, "stderr": 0}
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
            selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CheckError("dependency timed out")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 16384)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    counts[key.data] += len(chunk)
                    if counts[key.data] > max_output:
                        raise CheckError("dependency output exceeded limit")
                    if key.data == "stdout":
                        output.extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CheckError("dependency timed out")
            try:
                code = proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise CheckError("dependency timed out") from None
            if code != 0:
                raise CheckError("dependency returned failure")
        return bytes(output)
    except OSError:
        raise CheckError("dependency unavailable") from None
    finally:
        if proc is not None:
            # Include descendants (for example the Compose CLI plugin).
            # The direct child can exit while a descendant still owns a pipe.
            # Its dedicated process group must be cleaned up in that case too.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            proc.stdout.close()
            proc.stderr.close()


def read_text(path, limit=16384):
    try:
        with open(path, "rb") as source:
            content = source.read(limit + 1)
        if len(content) > limit:
            raise CheckError("system metadata exceeded limit")
        return content.decode("utf-8", "strict")
    except (OSError, UnicodeError):
        raise CheckError("system metadata unavailable") from None


def executable(path):
    try:
        # Follow distribution alternatives (including sudo-rs), but a searchable
        # directory is not an executable dependency.
        return stat.S_ISREG(os.stat(path).st_mode) and os.access(path, os.X_OK)
    except OSError:
        return False


def read_release():
    values = {}
    for line in read_text("/etc/os-release").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in ("ID", "VERSION_ID"):
            if key in values:
                raise CheckError("ambiguous operating-system metadata")
            values[key] = value.strip().strip('"')
    return values


def version_tuple(text):
    match = re.fullmatch(r"v?(\d+)\.(\d+)(?:\.(\d+))?(?:[-+][A-Za-z0-9_.-]+)?", text.strip())
    if not match:
        raise CheckError("unrecognized dependency version")
    return tuple(int(value or 0) for value in match.groups())


def supported_v3(loader_output):
    return bool(re.search(r"^\s*x86-64-v3\s+\(supported(?:,\s*searched)?\)\s*$", loader_output, re.MULTILINE))


def docker_fields(raw):
    try:
        value = json.loads(raw)
        if (not isinstance(value, dict) or not isinstance(value.get("security_options"), list) or
                not all(isinstance(item, str) for item in value["security_options"]) or
                not all(isinstance(value.get(key), str) for key in ("server_version", "cgroup_version", "docker_root_dir"))):
            raise ValueError()
        version = version_tuple(value["server_version"])
        if version < (28, 0, 0):
            raise CheckError("Docker Engine 28 or newer is required for the loopback publication fix")
        if value["cgroup_version"] != "2":
            raise CheckError("Docker must use cgroup v2")
        if any(item.split(",", 1)[0] in ("name=rootless", "name=userns") for item in value["security_options"]):
            raise CheckError("rootless or user namespace remapped Docker is outside this deployment target")
        if value["docker_root_dir"] != "/var/lib/docker":
            raise CheckError("Docker must use /var/lib/docker for the current storage checks")
        # Do not relay arbitrary daemon strings or its complete security list.
        return {"engine_version": ".".join(map(str, version)), "cgroup_version": "2",
                "rootful": True, "docker_root_dir": "/var/lib/docker"}
    except (ValueError, TypeError):
        raise CheckError("Docker returned incomplete or invalid metadata") from None


def storage_sample(target):
    candidate = Path(target)
    while True:
        try:
            info = candidate.lstat()
            break
        except FileNotFoundError:
            if candidate == candidate.parent:
                raise CheckError("storage ancestor unavailable") from None
            candidate = candidate.parent
        except OSError:
            raise CheckError("storage metadata unavailable") from None
    try:
        device = info.st_dev
        for entry in (candidate, *candidate.parents):
            info = entry.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise CheckError("storage ancestor must be a real administrator-owned directory")
        space = os.statvfs(candidate)
        free = space.f_bavail * space.f_frsize
        return {"path": str(target), "existing_ancestor": str(candidate), "free_bytes": free,
                "total_bytes": space.f_blocks * space.f_frsize,
                "st_dev": device,
                "read_only": bool(space.f_flag & getattr(os, "ST_RDONLY", 1))}
    except OSError:
        raise CheckError("storage filesystem unavailable") from None


def collect():
    checks, resources = [], {}

    def add(name, status, summary):
        checks.append({"name": name, "status": status, "summary": summary})

    def check(name, function):
        try:
            summary = function()
            add(name, "pass", summary)
        except (CheckError, OSError, ValueError, IndexError, TypeError):
            # Each caller supplies its own safe diagnostic; no raw exception,
            # dependency output, kernel message, address or credential escapes.
            add(name, "fail", FAILURES[name])

    add("root", "pass" if os.geteuid() == 0 else "fail",
        "Running as root." if os.geteuid() == 0 else "Run as root to inspect the Docker daemon and kernel diagnostics.")
    release = {}

    def operating_system():
        release.update(read_release())
        if release.get("ID") != "ubuntu" or release.get("VERSION_ID") not in RELEASES or platform.machine() != "x86_64":
            raise CheckError("unsupported platform")
        resources["ubuntu_release"] = release["VERSION_ID"]
        resources["architecture"] = "amd64"
        return "Ubuntu " + release["VERSION_ID"] + " on amd64."
    check("platform", operating_system)

    missing = [path for path in REQUIRED_EXECUTABLES if not executable(path)]
    add("executables", "fail" if missing else "pass",
        "Missing executable paths: " + ", ".join(missing) if missing else "All fixed executable paths are available; GNU sudo and sudo-rs are both accepted.")
    add("python", "pass" if sys.version_info >= (3, 12) else "fail",
        "Python " + ".".join(map(str, sys.version_info[:3])) + "; Python 3.12 or newer is required.")

    def systemd():
        text = run(["/usr/bin/systemctl", "--version"]).decode("utf-8", "strict")
        match = re.match(r"systemd (\d+)\b", text)
        if not match or int(match.group(1)) < 249:
            raise CheckError("unsupported systemd")
        resources["systemd_version"] = int(match.group(1))
        return "systemd " + match.group(1) + " supports LoadCredential."
    check("systemd", systemd)

    def service_manager():
        if read_text("/proc/1/comm").strip() != "systemd":
            raise CheckError("systemd is not PID 1")
        return "systemd is the booted service manager."
    check("service_manager", service_manager)

    if release.get("ID") == "ubuntu" and release.get("VERSION_ID") in ("26.04", "26.10"):
        def cpu_baseline():
            if not supported_v3(run(["/lib64/ld-linux-x86-64.so.2", "--help"]).decode("utf-8", "strict")):
                raise CheckError("x86-64-v3 unavailable")
            resources["x86_64_v3"] = True
            return "The guest glibc loader reports x86-64-v3 supported."
        check("cpu_baseline", cpu_baseline)

    def sudo_policy():
        run(["/usr/sbin/visudo", "-c"])
        return "The installed sudo implementation accepts the current sudoers configuration."
    check("sudo_policy", sudo_policy)

    def docker():
        template = ('{"server_version":{{json .ServerVersion}},"cgroup_version":{{json .CgroupVersion}},'
                    '"security_options":{{json .SecurityOptions}},"docker_root_dir":{{json .DockerRootDir}}}')
        resources["docker"] = docker_fields(run([DOCKER, "--host", DOCKER_HOST, "info", "--format", template]))
        return "Rootful Docker Engine >=28 without user namespace remapping, cgroup v2 and default data root are available."
    check("docker", docker)

    def compose():
        parsed = version_tuple(run([DOCKER, "--host", DOCKER_HOST, "compose", "version", "--short"]).decode("utf-8", "strict"))
        if parsed[0] < 2:
            raise CheckError("legacy Compose")
        help_text = run([DOCKER, "--host", DOCKER_HOST, "compose", "up", "--help"]).decode("utf-8", "strict")
        if not re.search(r"^\s+--wait(?:\s|$)", help_text, re.MULTILINE):
            raise CheckError("Compose lacks required up --wait support")
        resources["compose_version"] = ".".join(map(str, parsed))
        return "The Docker Compose plugin (version >=2) supports up --wait."
    check("compose", compose)

    resources["storage"] = []
    for path in STORAGE_PATHS:
        name = "storage:" + path
        try:
            sample = storage_sample(path)
            resources["storage"].append(sample)
            if sample["read_only"] or sample["free_bytes"] < MIN_FREE_BYTES:
                add(name, "fail", "At least 2 GiB available on a writable filesystem is required.")
            else:
                add(name, "pass", "At least 2 GiB is available on the existing filesystem ancestor.")
        except (CheckError, OSError):
            add(name, "fail", "Storage ownership, filesystem or capacity could not be verified.")

    stores = {sample["path"]: sample for sample in resources["storage"]}
    if set(stores) == set(STORAGE_PATHS):
        monitored = {stores[path]["st_dev"] for path in ("/var/lib/docker", "/var/lib/mail-guardian")}
        if stores["/var/lib/containerd"]["st_dev"] in monitored:
            add("containerd_storage", "pass", "The containerd filesystem is covered by Guardian's runtime storage gates.")
        else:
            add("containerd_storage", "fail", "A separate containerd filesystem is outside the current runtime storage gates.")
    else:
        add("containerd_storage", "fail", "Containerd filesystem coverage could not be verified.")

    def kernel_storage():
        logs = run(["/usr/bin/dmesg", "--level=err,warn", "--notime"], max_output=8 << 20)
        if STORAGE_ERRORS.search(logs.decode("utf-8", "replace")):
            raise CheckError("kernel storage error")
        return "Available kernel warning/error diagnostics contain no recognized storage-error signature."
    check("kernel_storage", kernel_storage)

    try:
        cpus = os.cpu_count()
        if not isinstance(cpus, int) or cpus < 1:
            raise CheckError("CPU count unavailable")
        resources["logical_cpus"] = cpus
        add("cpu_capacity", "pass" if cpus >= 2 else "warn", str(cpus) + " logical CPUs; two are recommended.")
    except (CheckError, OSError):
        add("cpu_capacity", "fail", "The CPU allocation could not be determined.")
    try:
        match = re.search(r"^MemTotal:\s+(\d+)\s+kB$", read_text("/proc/meminfo"), re.MULTILINE)
        if not match or int(match.group(1)) <= 0:
            raise CheckError("memory unavailable")
        memory_bytes = int(match.group(1)) * 1024
        resources["memory_bytes"] = memory_bytes
        # A marketed 4 GB VPS reports less after firmware/kernel reservations.
        add("memory_capacity", "pass" if memory_bytes >= 3500 << 20 else "warn",
            str(memory_bytes // (1 << 20)) + " MiB total RAM; approximately 4 GB is recommended.")
    except (CheckError, OSError):
        add("memory_capacity", "fail", "The RAM allocation could not be determined.")
    try:
        synchronized = run(["/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value"]).strip()
        if synchronized not in (b"yes", b"no"):
            raise CheckError("unrecognized time status")
        resources["clock_synchronized"] = synchronized == b"yes"
        add("clock", "pass" if synchronized == b"yes" else "fail",
            "System clock synchronization is confirmed." if synchronized == b"yes" else "Clock synchronization is not confirmed; correct the host time service before deployment.")
    except (CheckError, OSError):
        add("clock", "fail", "Clock synchronization could not be checked; verify the host time service before deployment.")

    return {"schema_version": 1, "ready": not any(item["status"] == "fail" for item in checks),
            "checks": checks, "resources": resources, "limitations": list(LIMITATIONS)}


FAILURES = {
    "platform": "Require Ubuntu 24.04, 26.04 or 26.10 on amd64 with readable OS metadata.",
    "systemd": "A working systemctl reporting systemd >=249 is required.",
    "service_manager": "A booted systemd host is required; a disposable container is insufficient.",
    "cpu_baseline": "Ubuntu 26.04 and 26.10 require guest x86-64-v3 support confirmed by the glibc loader.",
    "sudo_policy": "The current sudoers configuration could not be validated with visudo.",
    "docker": "Require a reachable rootful Docker Engine >=28 without user namespace remapping at the fixed Unix socket, cgroup v2 and /var/lib/docker data root.",
    "compose": "The Docker Compose plugin version >=2 with up --wait support could not be verified.",
    "kernel_storage": "Kernel diagnostics are unavailable or contain a recognized storage-error signature; investigate before deployment.",
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit a sanitized machine-readable report")
    args = parser.parse_args(argv)
    report = collect()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for result in report["checks"]:
            print(result["status"].upper() + " " + result["name"] + ": " + result["summary"])
        print("Prerequisites passed." if report["ready"] else "Prerequisites incomplete; deployment must wait.")
        for limitation in report["limitations"]:
            print(limitation)
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
