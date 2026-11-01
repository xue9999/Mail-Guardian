#!/usr/bin/python3
"""Check Docker package candidates and Guardian image pin drift; never deploy."""

import argparse
import ast
import datetime as dt
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

PACKAGES = (
    "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin",
    "docker-compose-plugin", "docker-ce-rootless-extras", "docker-model-plugin",
    "docker-scout-plugin",
)
COMPOSE = "/etc/mail-guardian/pilot/deploy/compose.yaml"
RELEASE_COMPOSE = "/opt/mail-guardian/current/deploy/compose.yaml"
CANDIDATE_TOOL = "/usr/local/libexec/vps-guardian-image-candidates"
MAINTENANCE_HELPER = "/usr/local/libexec/mail-guardian-maintenance"
GUARDIAN_PROJECT = "mail-guardian-pilot"
COMPOSE_TIMEOUT = 30
COMPOSE_OUTPUT_LIMIT = 2 * 1024 * 1024
SAFE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/root"}
PIN = re.compile(r"^\s*image:\s*([^\s#]+)\s*(?:#.*)?$")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def run(args, timeout=60):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env=SAFE_ENV, check=False)


def refresh_apt():
    # apt itself owns its POSIX locks; never remove lock files. Retry only lock
    # contention, with a finite bound, and fail closed on repository errors.
    for attempt in range(3):
        result = run(["apt-get", "-o", "APT::Update::Error-Mode=any", "update"], timeout=300)
        if result.returncode == 0:
            return
        details = (result.stdout + "\n" + result.stderr).strip()
        locked = "Could not get lock" in details or "Unable to lock directory" in details
        if not locked or attempt == 2:
            raise RuntimeError("apt metadata refresh failed: " + details[-2500:])
        time.sleep(20)


def package_candidates():
    found = []
    for package in PACKAGES:
        installed = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Version}", package])
        if installed.returncode == 1 and "no packages found matching" in installed.stderr:
            continue
        if installed.returncode != 0:
            raise RuntimeError("dpkg-query failed for " + package + ": " + installed.stderr.strip())
        fields = installed.stdout.split("\t", 1)
        if len(fields) != 2:
            raise RuntimeError("unexpected dpkg-query output for " + package)
        status, version = fields
        if not status.startswith("ii"):
            continue
        version = version.strip()
        policy = run(["apt-cache", "policy", package])
        match = re.search(r"^\s*Candidate:\s*(\S+)\s*$", policy.stdout, re.M)
        if policy.returncode or not match:
            raise RuntimeError("cannot identify candidate for " + package)
        candidate = match.group(1)
        if candidate == "(none)":
            raise RuntimeError("no candidate available for installed " + package)
        newer = run(["dpkg", "--compare-versions", candidate, "gt", version])
        if newer.returncode not in (0, 1):
            raise RuntimeError("cannot compare versions for " + package)
        found.append({"name": package, "installed": version, "candidate": candidate,
                      "update_available": newer.returncode == 0})
    if not found:
        raise RuntimeError("no installed Docker packages found")
    return found


def image_pins(path):
    pins = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        match = PIN.match(line)
        if not match:
            continue
        reference = match.group(1).strip('"\'')
        if "@" not in reference:
            raise RuntimeError("image is not digest-pinned: " + reference)
        tag, digest = reference.rsplit("@", 1)
        if not tag or not DIGEST.fullmatch(digest):
            raise RuntimeError("invalid image reference: " + reference)
        pins.append((tag, digest))
    if not pins:
        raise RuntimeError("no image references found in " + str(path))
    return pins


def image_candidates(path):
    images, errors = [], []
    for tag, pinned in image_pins(path):
        try:
            result = run(["docker", "buildx", "imagetools", "inspect", tag,
                          "--format", "{{.Manifest.Digest}}"], timeout=60)
            digest = result.stdout.strip().strip('"')
            if result.returncode or not DIGEST.fullmatch(digest):
                raise RuntimeError((result.stderr.strip() or result.stdout.strip() or "empty response")[-1000:])
            images.append({"tag": tag, "pinned_digest": pinned, "tag_digest": digest,
                           "digest_changed": pinned != digest})
        except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
            errors.append("image check failed for " + tag + ": " + str(exc))
    return images, errors


def rendered_compose(path):
    """Render with Guardian's Compose environment; keep full output in memory only."""
    args = ["docker", "--host", "unix:///var/run/docker.sock", "compose",
            "--project-name", GUARDIAN_PROJECT, "--project-directory", str(Path(path).parent),
            "--file", str(path), "config", "--format", "json"]
    env = dict(SAFE_ENV, GUARDIAN_RUNTIME_DIR="/var/lib/mail-guardian-admin/pilot")
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=env, start_new_session=True)
    deadline = time.monotonic() + COMPOSE_TIMEOUT
    output = bytearray()
    completed = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise RuntimeError("Compose render timed out")
                block = os.read(proc.stdout.fileno(), 65536)
                if not block:
                    break
                output.extend(block)
                if len(output) > COMPOSE_OUTPUT_LIMIT:
                    raise RuntimeError("Compose render exceeded the output limit")
        try:
            exit_code = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Compose render timed out") from exc
        if exit_code != 0:
            raise RuntimeError("Compose render failed")
        try:
            result = json.loads(output)
            completed = True
            return result
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError("Compose render returned invalid JSON") from exc
    finally:
        # Docker Compose may run as a CLI plugin child. Killing only the
        # parent can leave that child holding our pipe open indefinitely.
        if not completed:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()


def expected_service_images(path):
    repositories = {"unbound": "klutchell/unbound", "redis": "redis", "rspamd": "rspamd/rspamd"}
    config = rendered_compose(path)
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        raise RuntimeError("rendered Compose has no services")
    services = config["services"]
    if set(services) != set(repositories):
        raise RuntimeError("rendered Compose does not describe exactly the Guardian services")
    expected = {}
    for service, repository in repositories.items():
        definition = services[service]
        if not isinstance(definition, dict) or "build" in definition:
            raise RuntimeError("rendered Compose has an unsupported service definition")
        image = definition.get("image")
        if not isinstance(image, str) or "@" not in image:
            raise RuntimeError("Guardian service image is not digest pinned")
        tag, digest = image.rsplit("@", 1)
        if (not DIGEST.fullmatch(digest) or ":" not in tag or
                tag.rsplit(":", 1)[0] != repository or not tag.rsplit(":", 1)[1]):
            raise RuntimeError("Guardian service image does not match its expected repository")
        expected[service] = image
    return expected


def rspamd_helper_image(path):
    """Read the helper's literal image pin without executing the helper."""
    source = Path(path).read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
        assignments = [node for node in tree.body if isinstance(node, ast.Assign) and
                       any(isinstance(target, ast.Name) and target.id == "RSPAMD_IMAGE"
                           for target in node.targets)]
        if len(assignments) != 1:
            raise ValueError("expected one Rspamd image assignment")
        value = ast.literal_eval(assignments[0].value)
        if not isinstance(value, str):
            raise ValueError("Rspamd image is not a string literal")
        return value
    except (SyntaxError, ValueError, TypeError) as exc:
        raise RuntimeError("could not read the maintenance helper image pin") from exc


def running_container_images(expected):
    """Compare configured images, including stopped persistent containers."""
    found = run(["docker", "--host", "unix:///var/run/docker.sock", "ps", "--all",
                 "--filter", "label=com.docker.compose.project=" + GUARDIAN_PROJECT,
                 "--filter", "label=com.docker.compose.oneoff=False", "--format", "{{.ID}}"])
    if found.returncode:
        raise RuntimeError("Docker container listing failed")
    ids = found.stdout.split()
    if not ids:
        raise RuntimeError("Guardian containers not present for image inspection")
    if len(ids) > 10 or any(not re.fullmatch(r"[0-9a-f]{12,64}", value) for value in ids):
        raise RuntimeError("unexpected Guardian container identifiers")
    fmt = '{{json (index .Config.Labels "com.docker.compose.service")}}\t{{json .Config.Image}}\t{{json .State.Status}}'
    inspected = run(["docker", "--host", "unix:///var/run/docker.sock", "inspect", "--format", fmt, *ids])
    if inspected.returncode:
        raise RuntimeError("Docker container inspection failed")
    rows, seen = [], set()
    for line in inspected.stdout.splitlines():
        try:
            service, image, status = [json.loads(field) for field in line.split("\t")]
        except (ValueError, TypeError) as exc:
            raise RuntimeError("invalid container inspection output") from exc
        if service not in expected or service in seen or not isinstance(image, str) or not isinstance(status, str):
            raise RuntimeError("unexpected Guardian service or duplicate container")
        seen.add(service)
        rows.append({"service": service, "image": image, "status": status,
                     "matches_compose": image == expected[service]})
    if seen != set(expected) or len(rows) != len(ids):
        raise RuntimeError("Guardian container inspection is incomplete")
    return sorted(rows, key=lambda item: item["service"])


def patch_candidates(path, tool):
    """Run allowlisted same-minor image discovery and reject incomplete reports."""
    result = run(["/usr/bin/python3", tool, "--compose", path], timeout=300)
    try:
        data = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("candidate discovery returned invalid JSON") from exc
    if (not isinstance(data, dict) or data.get("mode") != "discovery_only" or
            not isinstance(data.get("images"), list) or
            not isinstance(data.get("errors"), list) or
            not all(isinstance(e, str) for e in data["errors"]) or
            not isinstance(data.get("attention"), bool)):
        raise RuntimeError("candidate discovery returned an invalid report")
    images = data["images"]
    if not all(isinstance(item, dict) and isinstance(item.get("repo"), str) and
               (item.get("candidate") is None or isinstance(item.get("candidate"), dict))
               for item in images):
        raise RuntimeError("candidate discovery returned invalid image entries")
    if not data["errors"] and (len(images) != 3 or {item["repo"] for item in images} !=
                               {"redis", "rspamd/rspamd", "klutchell/unbound"}):
        raise RuntimeError("candidate discovery did not cover all Guardian images")
    if data["attention"] != any(item.get("candidate") is not None for item in images):
        raise RuntimeError("candidate discovery returned inconsistent attention")
    expected = 1 if data["errors"] else 2 if data["attention"] else 0
    if result.returncode != expected:
        raise RuntimeError("candidate discovery exited inconsistently")
    return data["images"], data["errors"], data["attention"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", default=COMPOSE, help="active Guardian compose file")
    parser.add_argument("--release-compose", default=RELEASE_COMPOSE,
                        help="compose template in the installed Guardian release")
    parser.add_argument("--candidate-tool", default=CANDIDATE_TOOL,
                        help="allowlisted Guardian image patch discovery tool")
    parser.add_argument("--maintenance-helper", default=MAINTENANCE_HELPER,
                        help="installed Guardian maintenance helper")
    args = parser.parse_args()
    report = {"checked_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "packages": [], "images": [], "patch_candidates": [], "errors": [],
              "compose_matches_release": None, "rspamd_helper_matches_compose": None,
              "runtime_images_match_compose": None, "containers": [],
              "limitations": ["Image checks cover same-tag digest changes and selected same-minor patch tags; other versions and vulnerabilities require advisory review.",
                              "A detected update or digest change is a review candidate, not proof of a security fix.",
                              "Container checks compare configured image references, not actual image content or service health; a stopped container can match."]}
    compose_before = None
    try:
        refresh_apt()
        report["packages"] = package_candidates()
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        report["errors"].append("package check failed: " + str(exc))
    try:
        compose_before = Path(args.compose).read_bytes()
        report["compose_matches_release"] = compose_before == Path(args.release_compose).read_bytes()
        if not report["compose_matches_release"]:
            report["errors"].append("active Guardian compose differs from release template")
    except OSError as exc:
        report["errors"].append("compose comparison failed: " + str(exc))
    try:
        expected = expected_service_images(args.compose)
        report["rspamd_helper_matches_compose"] = (
            rspamd_helper_image(args.maintenance_helper) == expected["rspamd"])
        if not report["rspamd_helper_matches_compose"]:
            report["errors"].append("maintenance helper Rspamd image differs from active Compose")
    except (OSError, UnicodeError, RuntimeError) as exc:
        report["errors"].append("helper image check failed: " + str(exc))
    try:
        expected = expected_service_images(args.compose)
        report["containers"] = running_container_images(expected)
        report["runtime_images_match_compose"] = all(
            container["matches_compose"] for container in report["containers"])
        if not report["runtime_images_match_compose"]:
            report["errors"].append("Guardian container image differs from active Compose")
    except (OSError, UnicodeError, subprocess.TimeoutExpired, RuntimeError) as exc:
        report["errors"].append("container image check failed: " + str(exc))
    try:
        report["images"], image_errors = image_candidates(args.compose)
        report["errors"].extend(image_errors)
    except (OSError, UnicodeError, subprocess.TimeoutExpired, RuntimeError) as exc:
        report["errors"].append("image check failed: " + str(exc))
    patch_attention = False
    try:
        report["patch_candidates"], patch_errors, patch_attention = patch_candidates(
            args.compose, args.candidate_tool)
        report["errors"].extend("patch discovery failed: " + e for e in patch_errors)
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        report["errors"].append("patch discovery failed: " + str(exc))
    for label, path, before in (("active Compose", args.compose, compose_before),):
        if before is not None:
            try:
                if Path(path).read_bytes() != before:
                    report["errors"].append(label + " changed during the check")
            except OSError:
                report["errors"].append(label + " became unavailable during the check")
    report["attention"] = any(p["update_available"] for p in report["packages"]) or any(
        i["digest_changed"] for i in report["images"]) or patch_attention
    print(json.dumps(report, indent=2, sort_keys=True))
    # Failures take precedence over attention, while attention remains in JSON.
    return 1 if report["errors"] else 2 if report["attention"] else 0


if __name__ == "__main__":
    sys.exit(main())
