#!/usr/bin/env python3
"""Qualify an approved Guardian source snapshot in a disposable Go container.

This helper never installs a release, touches mailbox state, or invokes source
code on the host. The caller owns approval and immutable source verification.
Only Go module files may change inside the candidate. Tests run without a
network; the separate download/analysis phase can reach trusted upstreams.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from urllib.parse import quote, urlsplit


class BuildError(RuntimeError):
    pass


STABLE = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\+incompatible)?$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9]+)*$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]
LABEL = "org.mail-guardian.application-builder"
MAX_SOURCE_BYTES = 128 << 20
MAX_SOURCE_FILES = 10000


def _run(args, *, log=None, timeout=1800, input_text=None):
    limit = 16 << 20
    def bound_output():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    try:
        # Child output cannot grow the root controller's memory without bound.
        # File-size limits kill a noisy Docker client; _container's finally
        # then removes its exact container before any output is consumed.
        with tempfile.TemporaryFile(dir=Path(log).parent if log else None) as output:
            result = subprocess.run(args, input=None if input_text is None else input_text.encode(),
                                    stdout=output, stderr=subprocess.STDOUT,
                                    timeout=timeout, check=False, preexec_fn=bound_output)
            output.seek(0)
            content = output.read(limit + 1)
        if len(content) >= limit:
            raise BuildError("command output exceeded the bounded log limit")
        text = content.decode("utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BuildError(f"command failed or timed out: {args[0]}") from exc
    if log:
        try:
            fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(content)
        except OSError as exc:
            raise BuildError("host log path is missing, already exists or unsafe") from exc
    if result.returncode:
        raise BuildError(f"{args[0]} exited {result.returncode}; inspect {log or 'upstream availability'}")
    return text


def _fetch_text(url, *, headers=None, missing_ok=False):
    """Use the platform curl CA store; never disable TLS verification."""
    if urlsplit(url).scheme != "https":
        raise BuildError("upstream URL must use HTTPS")
    args = ["curl", "--silent", "--show-error", "--proto", "=https", "--tlsv1.2",
            "--location", "--proto-redir", "=https", "--max-redirs", "5",
            "--max-time", "45", "--max-filesize", str(8 << 20),
            "--write-out", "\n%{http_code}"]
    header_text = None
    if headers:
        if any("\n" in k + v or "\r" in k + v for k, v in headers.items()):
            raise BuildError("invalid upstream header")
        args += ["--header", "@-"]
        header_text = "".join(f"{k}: {v}\n" for k, v in headers.items())
    output = _run(args + [url], input_text=header_text, timeout=60)
    try:
        body, status = output.rsplit("\n", 1)
        status = int(status)
    except (ValueError, TypeError) as exc:
        raise BuildError("invalid HTTPS response") from exc
    if status in (404, 410) and missing_ok:
        return None
    if status != 200:
        raise BuildError(f"HTTP {status} from {urlsplit(url).hostname}")
    return body


def _fetch_json(url, **kwargs):
    text = _fetch_text(url, **kwargs)
    try:
        return None if text is None else json.loads(text)
    except ValueError as exc:
        raise BuildError("invalid upstream JSON") from exc


def _version_key(value):
    match = STABLE.fullmatch(value)
    if not match:
        raise BuildError(f"not an exact stable module version: {value}")
    return tuple(map(int, match.groups()))


def choose_stable(versions, current=None):
    stable = [v for v in versions if STABLE.fullmatch(v)]
    if not stable:
        return current
    newest = max(stable, key=_version_key)
    # A preview of a later series must never be silently downgraded.
    if current and not STABLE.fullmatch(current):
        base = re.match(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)", current)
        if base and _version_key(newest) < tuple(map(int, base.groups())):
            return current
    if current and STABLE.fullmatch(current) and _version_key(newest) < _version_key(current):
        return current
    return newest


def _module_path(module):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~/-]*", module) or ".." in module.split("/"):
        raise BuildError("unsafe module path")
    return "".join("!" + c.lower() if c.isupper() else c for c in module)


def _semver_key(value):
    match = re.fullmatch(r"v([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([A-Za-z0-9.-]+))?(?:\+[A-Za-z0-9.-]+)?", value)
    if not match:
        raise BuildError("invalid upstream retraction version")
    major, minor, patch, preview = match.groups()
    identifiers = tuple((0, int(x)) if x.isdigit() else (1, x) for x in (preview or "").split("."))
    return int(major), int(minor), int(patch), int(preview is None), identifiers


def _retractions(go_mod):
    ranges, inside = [], False
    for raw in go_mod.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("retract"):
            line = line[len("retract"):].strip()
            if line == "(":
                inside = True
                continue
        elif not inside:
            continue
        if inside and line == ")":
            inside = False
            continue
        if not line:
            continue
        match = re.fullmatch(r"\[\s*(v[^,\s]+)\s*,\s*(v[^\]\s]+)\s*\]|(v[^\s]+)", line)
        if not match:
            raise BuildError("unsupported publisher retract directive")
        lower, upper, single = match.groups()
        lower, upper = (single, single) if single else (lower, upper)
        lo, hi = _semver_key(lower), _semver_key(upper)
        if lo > hi:
            raise BuildError("reversed publisher retraction range")
        ranges.append((lo, hi))
    if inside:
        raise BuildError("unterminated publisher retract block")
    return ranges


class _VersionList(list):
    def __init__(self, values=(), retracted=()):
        super().__init__(values)
        self.retracted = set(retracted)


def _versions(module, *, missing_ok=False, current=None):
    root = f"https://proxy.golang.org/{_module_path(module)}/@v/"
    body = _fetch_text(root + "list", missing_ok=missing_ok)
    if body is None:
        return _VersionList()
    versions = body.splitlines()
    stable = [value for value in versions if STABLE.fullmatch(value)]
    if stable:
        # Go retractions are defined by the newest release's go.mod, including
        # a newest release which retracts itself. The compiler authenticates
        # selected module bytes with the checksum database during download.
        latest = max(stable, key=_version_key)
    elif versions:
        latest = max(versions, key=_semver_key)
    else:
        # The proxy's list excludes pseudo-versions. @latest provides the
        # publisher go.mod for retraction checks without adopting that commit.
        metadata = _fetch_json(f"https://proxy.golang.org/{_module_path(module)}/@latest", missing_ok=missing_ok)
        if metadata is None:
            return _VersionList()
        latest = metadata.get("Version")
        if not isinstance(latest, str):
            raise BuildError("module has no effective publisher version")
        _semver_key(latest)
    ranges = _retractions(_fetch_text(root + latest + ".mod"))
    observed = set(versions)
    if current:
        observed.add(current)
    retracted = {v for v in observed if any(lo <= _semver_key(v) <= hi for lo, hi in ranges)}
    return _VersionList([v for v in versions if v not in retracted], retracted)


def _parse_requirements(go_mod):
    required, inside = [], False
    import shlex
    for raw in go_mod.splitlines():
        line = raw.split("//", 1)[0].strip()
        if re.match(r"^require(?:\s|\()", line):
            line = line[len("require"):].strip()
            if line == "(":
                inside = True
                continue
        elif not inside:
            continue
        if inside and line == ")":
            inside = False
            continue
        if not line:
            continue
        fields = shlex.split(line)
        if len(fields) != 2:
            raise BuildError("unsupported approved go.mod require directive")
        module, version = fields
        _module_path(module)
        _semver_key(version)
        required.append({"Path": module, "Version": version})
    if inside or len({item["Path"] for item in required}) != len(required):
        raise BuildError("invalid approved go.mod requirements")
    return required


def _next_major(module, version):
    match = re.match(r"^v([0-9]+)\.", version)
    if not match:
        return None
    major = max(2, int(match.group(1)) + 1)
    return re.sub(r"/v(?:[2-9]|[1-9][0-9]+)$", "", module) + f"/v{major}"


def sqlite_libc_pin(go_mod):
    match = re.search(r"^\s*(?:require\s+)?modernc\.org/libc\s+(v[0-9]+\.[0-9]+\.[0-9]+)\s*(?://.*)?$", go_mod, re.M)
    if not match:
        raise BuildError("SQLite publisher go.mod has no exact stable libc pin")
    return match.group(1)


def dependency_plan(required, *, patch_only=False):
    """Discover explicit stable versions; preserve previews only if necessary."""
    changes, blockers, available = {}, [], {}
    for item in required:
        module, current = item["Path"], item["Version"]
        versions = _versions(module, current=current)
        available[module] = versions
        withdrawn = current in getattr(versions, "retracted", ())
        candidate = choose_stable(versions, None if withdrawn else current)
        if candidate is None:
            raise BuildError(f"{module} has no non-retracted stable replacement for its withdrawn pin")
        if patch_only and candidate != current:
            same_line = [v for v in versions if STABLE.fullmatch(v)
                         and STABLE.fullmatch(current)
                         and _version_key(v)[:2] == _version_key(current)[:2]]
            permitted = choose_stable(same_line, current)
            if permitted != candidate:
                blockers.append({"module": module, "detected": candidate,
                                 "compatible": permitted,
                                 "reason": "New major/minor line requires manual review.",
                                 "next_action": "Review and qualify this version before updating the approved source baseline."})
                candidate = permitted
            if withdrawn and candidate == current:
                raise BuildError(f"{module}: withdrawn pin requires manual review of a new version line")
        changes[module] = {"current": current, "candidate": candidate}
        if withdrawn:
            blockers.append({"module": module, "detected": current, "compatible": candidate,
                             "reason": "Publisher withdrew the approved current version; qualify its non-retracted replacement.",
                             "next_action": "Install only after the full candidate compatibility checks pass."})
        if not STABLE.fullmatch(candidate):
            blockers.append({"module": module, "detected": candidate,
                             "reason": "No suitable stable tag in this module path; retain the approved exact preview/pseudo-version.",
                             "next_action": "Check upstream for a maintained stable release and qualify its API before replacing this pin."})
        major_path = _next_major(module, current)
        newer_major = choose_stable(_versions(major_path, missing_ok=True)) if major_path else None
        if newer_major:
            blockers.append({"module": module, "detected_module": major_path,
                             "detected": newer_major,
                             "reason": "New major module path requires reviewed import/API migration; this dependency-only builder cannot change approved app source.",
                             "next_action": "Prepare an approved source revision for the new major API and run the same qualification."})
    sqlite = changes.get("modernc.org/sqlite")
    if sqlite:
        version = sqlite["candidate"]
        if not STABLE.fullmatch(version):
            raise BuildError("SQLite candidate is not stable")
        go_mod = _fetch_text(f"https://proxy.golang.org/modernc.org/sqlite/@v/{version}.mod")
        exact = sqlite_libc_pin(go_mod)
        libc_versions = available.get("modernc.org/libc")
        if libc_versions is None:
            libc_versions = _versions("modernc.org/libc")
        if exact in getattr(libc_versions, "retracted", ()):
            raise BuildError("SQLite exact libc dependency was withdrawn; a corrected publisher pair is required")
        previous = changes.get("modernc.org/libc", {}).get("candidate")
        current = changes.get("modernc.org/libc", {}).get("current")
        if patch_only and current and _version_key(exact)[:2] != _version_key(current)[:2]:
            raise BuildError("SQLite publisher pair requires manual review of a new libc minor line")
        changes["modernc.org/libc"] = {"current": current, "candidate": exact,
                                      "constraint": "exact SQLite publisher go.mod dependency"}
        if previous and previous != exact:
            blockers.append({"module": "modernc.org/libc", "detected": previous,
                             "compatible": exact,
                             "reason": f"SQLite {version} explicitly requires its exact libc {exact}; newer standalone libc is outside that publisher pairing.",
                             "next_action": "Use the newest SQLite release carrying a newer libc pin, or qualify the complete SQLite/Linux ABI before overriding it."})
    return {"modules": changes, "blockers": blockers}


def _compiler_and_image(current_version=None, *, review=None):
    releases = _fetch_json("https://go.dev/dl/?mode=json&include=all")
    versions = [x["version"][2:] for x in releases
                if x.get("stable") is True and re.fullmatch(r"go[0-9]+\.[0-9]+\.[0-9]+", x.get("version", ""))]
    if not versions:
        raise BuildError("no official stable Go compiler found")
    newest = max(versions, key=lambda v: tuple(map(int, v.split('.'))))
    if current_version is not None:
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", current_version):
            raise BuildError("invalid approved compiler version")
        versions = [v for v in versions if v.split('.')[:2] == current_version.split('.')[:2]]
        if not versions:
            raise BuildError("approved Go compiler line is unavailable; manual review required")
        if review is not None and newest.split('.')[:2] != current_version.split('.')[:2]:
            review.update(detected=newest, approved=current_version,
                          next_action='Manually review and qualify the new Go compiler line.')
    version = max(versions, key=lambda v: tuple(map(int, v.split("."))))
    if current_version and tuple(map(int, version.split('.'))) < tuple(map(int, current_version.split('.'))):
        raise BuildError("official compiler metadata would downgrade the approved baseline")
    token = _fetch_json("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/golang:pull").get("token")
    if not isinstance(token, str) or not token or any(c.isspace() for c in token):
        raise BuildError("invalid official-image registry token")
    headers = {"Authorization": "Bearer " + token,
               "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"}
    root = "https://registry-1.docker.io/v2/library/golang/"
    body = _fetch_text(root + "manifests/" + version, headers=headers)
    index = json.loads(body)
    if "manifests" in index:
        choices = [x for x in index["manifests"]
                   if x.get("platform", {}).get("os") == "linux"
                   and x.get("platform", {}).get("architecture") == "amd64"
                   and x.get("platform", {}).get("variant", "") in ("", "v1")]
        if len(choices) != 1 or not DIGEST.fullmatch(choices[0].get("digest", "")):
            raise BuildError("official Go image has no unambiguous Linux amd64 manifest")
        digest = choices[0]["digest"]
        body = _fetch_text(root + "manifests/" + digest, headers=headers)
        if "sha256:" + hashlib.sha256(body.encode()).hexdigest() != digest:
            raise BuildError("official image manifest digest mismatch")
    else:
        digest = "sha256:" + hashlib.sha256(body.encode()).hexdigest()
    manifest = json.loads(body)
    config_digest = manifest.get("config", {}).get("digest", "")
    if not DIGEST.fullmatch(config_digest):
        raise BuildError("official image has no valid config digest")
    config_body = _fetch_text(root + "blobs/" + config_digest, headers=headers)
    if "sha256:" + hashlib.sha256(config_body.encode()).hexdigest() != config_digest:
        raise BuildError("official image config digest mismatch")
    config = json.loads(config_body)
    if (config.get("os"), config.get("architecture")) != ("linux", "amd64"):
        raise BuildError("official compiler image architecture mismatch")
    return version, "docker.io/library/golang@" + digest


def _copy_source(source, destination):
    source = Path(source).resolve(strict=True)
    destination.mkdir(mode=0o755)
    destination.chmod(0o755)  # Caller/service commonly has umask 077.
    total = 0
    manifest = {}
    for path in sorted(source.rglob("*")):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise BuildError("approved source contains a link or special file")
        relative = path.relative_to(source)
        if path.is_dir():
            (destination / relative).mkdir(mode=0o755)
            (destination / relative).chmod(0o755)
            continue
        total += path.stat().st_size
        if total > MAX_SOURCE_BYTES or len(manifest) >= MAX_SOURCE_FILES:
            raise BuildError("approved source exceeds builder bounds")
        content = _safe_read(path, source, max_bytes=MAX_SOURCE_BYTES)
        (destination / relative).write_bytes(content)
        (destination / relative).chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
        manifest[str(relative)] = hashlib.sha256(content).hexdigest()
    if not {"go.mod", "go.sum", "VERSION"} <= manifest.keys():
        raise BuildError("approved source is missing module/version inputs")
    return manifest


def _safe_read(path, root, max_bytes=8 << 20):
    """Read a bounded single-link regular file, refusing every symlink parent."""
    path, root = Path(path).absolute(), Path(root).absolute()
    try:
        parts = path.relative_to(root).parts
    except ValueError as exc:
        raise BuildError("output escapes builder work directory") from exc
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise BuildError("invalid builder output path")
    fd = None
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > max_bytes:
                raise BuildError("builder output has unsafe type/link count/size")
            content = stream.read(max_bytes + 1)
            after = os.fstat(stream.fileno())
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if len(content) > max_bytes or len(content) != before.st_size or identity(before) != identity(after):
                raise BuildError("builder output changed during inspection")
            return content
    except OSError as exc:
        raise BuildError("builder output path is missing or unsafe") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _safe_json(path, root):
    try:
        return json.loads(_safe_read(path, root))
    except (ValueError, RecursionError) as exc:
        raise BuildError("invalid bounded builder JSON") from exc


def _source_unchanged(candidate, manifest, work):
    if candidate.is_symlink() or not candidate.is_dir():
        raise BuildError("candidate source directory is unsafe")
    actual = set()
    for count, path in enumerate(candidate.rglob("*")):
        if count >= 2 * MAX_SOURCE_FILES:
            raise BuildError("candidate source exceeded inspection bounds")
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise BuildError("candidate source contains a link or special file")
        if path.is_file():
            actual.add(str(path.relative_to(candidate)))
    if actual != set(manifest):
        raise BuildError("candidate added or removed approved application source")
    for relative, digest in manifest.items():
        if relative not in ("go.mod", "go.sum"):
            content = _safe_read(candidate / relative, work, max_bytes=MAX_SOURCE_BYTES)
            if hashlib.sha256(content).hexdigest() != digest:
                raise BuildError("candidate changed approved application source")


def _container(image, source, work, script, token, phase, *, network):
    name = f"mg-app-build-{token}-{phase}"
    args = DOCKER + ["run", "--rm", "--pull=never", "--name", name,
        "--label", LABEL + "=" + token, "--platform", "linux/amd64",
        "--user", "65534:65534", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
        "--read-only", "--memory", "1536m", "--memory-swap", "1536m",
        "--cpus", "1", "--pids-limit", "256", "--network", network,
        "--log-driver=none",
        "--tmpfs", "/tmp:rw,nosuid,size=128m,mode=1777",
        "--mount", f"type=bind,source={source},target=/source,readonly",
        "--mount", f"type=bind,source={work},target=/work",
        "--workdir", "/work/src"]
    for env in ["GOENV=off", "GOTOOLCHAIN=local", "GOPROXY=https://proxy.golang.org",
                "GOSUMDB=sum.golang.org", "GOPRIVATE=", "GONOPROXY=", "GONOSUMDB=",
                "GOPATH=/work/gopath", "GOMODCACHE=/work/gopath/pkg/mod", "GOCACHE=/work/gocache",
                "GOTMPDIR=/work/gotmp", "TMPDIR=/work/test-tmp",
                "XDG_CACHE_HOME=/work/tool-cache", "GOBIN=/work/bin",
                "GOFLAGS=-buildvcs=false", "GOWORK=off", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOMAXPROCS=1"]:
        args += ["--env", env]
    try:
        return _run(args + [image, "/usr/bin/timeout", "--signal=TERM", "--kill-after=30s", "20m",
                            "/bin/sh", "-eu", "-c", script],
                    log=work.parent / f"{phase}.log", timeout=1800)
    finally:
        # Only this invocation's exact randomly named, labelled container.
        query = DOCKER + ["container", "ls", "--all", "--filter", "name=^/" + name + "$", "--format", "{{.ID}}"]
        if _run(query, timeout=30).strip():
            actual = _run(DOCKER + ["inspect", "--format", '{{index .Config.Labels "' + LABEL + '"}}', name], timeout=30).strip()
            if actual != token:
                raise BuildError("exact builder container label changed; cleanup unconfirmed")
            _run(DOCKER + ["rm", "--force", name], timeout=60)
        if _run(query, timeout=30).strip():
            raise BuildError("builder container remains after exact cleanup")


def _json_stream(text):
    decoder, cursor, result = json.JSONDecoder(), 0, []
    while text[cursor:].strip():
        cursor += len(text[cursor:]) - len(text[cursor:].lstrip())
        item, cursor = decoder.raw_decode(text, cursor)
        result.append(item)
    return result


def discover(source_dir, *, patch_only=False, compiler_version=None):
    """Cheap upstream discovery: no image pull, source changes or compilation."""
    source = Path(source_dir).resolve(strict=True)
    go_mod = _safe_read(source / "go.mod", source)
    current = _parse_requirements(go_mod.decode())
    if patch_only and compiler_version is None:
        raise BuildError("scheduled discovery requires the approved compiler baseline")
    compiler_review = {}
    compiler, image = _compiler_and_image(compiler_version, review=compiler_review) if patch_only else _compiler_and_image()
    scanner = choose_stable(_versions("golang.org/x/vuln"))
    if not scanner:
        raise BuildError("no stable official govulncheck release found")
    database = _fetch_json("https://vuln.go.dev/index/db.json")
    modified = database.get("modified")
    if not isinstance(modified, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", modified):
        raise BuildError("invalid official vulnerability database modification time")
    report = {"version": 1, "current_modules": current,
              "source_go_mod_sha256": hashlib.sha256(go_mod).hexdigest(),
              "dependency_plan": dependency_plan(current, patch_only=True) if patch_only else dependency_plan(current),
              "patch_only": patch_only,
              "compiler_manual_review": compiler_review,
              "compiler_version": compiler, "compiler_image": image,
              "govulncheck_version": scanner, "vulnerability_db_modified": modified}
    report["fingerprint"] = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return report


def _create_scratch(work):
    """Root-owned sticky shared ancestors, like /tmp, for the build UID.

    Guardian's recovery catalog deliberately rejects ordinary world-writable
    ancestors. Child Go/Python temporary directories remain caller-owned0700.
    """
    scratch = Path(work) / 'sandbox'
    scratch.mkdir(mode=0o1777)
    scratch.chmod(0o1777)
    for name in ('src', 'gopath', 'gocache', 'gotmp', 'test-tmp', 'tool-cache', 'bin', 'output'):
        (scratch / name).mkdir(mode=0o1777)
        (scratch / name).chmod(0o1777)
    return scratch


def build_candidate(source_dir, work_dir, discovery=None):
    """Return qualified binary paths/provenance; raise BuildError on any gap.

    work_dir must be new. Docker needs access to the local Unix daemon. All
    host-side writes are below work_dir except Docker's normal image cache.
    The caller must preserve a coherent recovery point before any installation.
    """
    source = Path(source_dir).resolve(strict=True)
    work = Path(work_dir).absolute()
    if work.exists() or "," in str(work) + str(source) or source in work.parents:
        raise BuildError("work directory must be new and mount paths must not contain commas")
    work.mkdir(mode=0o700, parents=True)
    approved = work / "approved-source"
    manifest = _copy_source(source, approved)
    # Do not expose parent's private path: bind-mount root is readable even if
    # its host ancestors are private. Only the container work area is writable.
    scratch = _create_scratch(work)
    discovery = discover(source) if discovery is None else discovery
    if discovery.get("source_go_mod_sha256") != hashlib.sha256(_safe_read(approved / "go.mod", work)).hexdigest():
        raise BuildError("discovery is not bound to this approved source go.mod")
    compiler, image, scanner = (discovery["compiler_version"], discovery["compiler_image"], discovery["govulncheck_version"])
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", compiler) or not re.fullmatch(r"docker\.io/library/golang@sha256:[0-9a-f]{64}", image) or not STABLE.fullmatch(scanner):
        raise BuildError("invalid discovery compiler/scanner pin")
    _run(DOCKER + ["pull", "--platform", "linux/amd64", image], log=work / "image-pull.log")
    platform = _run(DOCKER + ["image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image]).strip()
    if platform != "linux/amd64":
        raise BuildError("pulled compiler architecture mismatch")
    token = uuid.uuid4().hex
    prepare = ("cp -R /source/. /work/src/\n"
               "go version > /work/compiler.txt\n"
               "go mod edit -json > /work/current-go-mod.json\n"
               "go list -m -json all > /work/current-modules.json\n")
    _container(image, approved, scratch, prepare, token, "prepare", network="bridge")
    if _safe_read(scratch / "compiler.txt", work).decode().strip() != f"go version go{compiler} linux/amd64":
        raise BuildError("compiler binary does not match official selected Go version")
    mod = _safe_json(scratch / "current-go-mod.json", work)
    actual = {item["Path"]: item["Version"] for item in mod.get("Require", [])}
    expected = {item["Path"]: item["Version"] for item in discovery["current_modules"]}
    if actual != expected:
        raise BuildError("Go parser and cheap discovery disagree about approved requirements")
    plan = discovery["dependency_plan"]
    specs = [module + "@" + item["candidate"] for module, item in sorted(plan["modules"].items())]
    import shlex
    get = "go get " + " ".join(shlex.quote(x) for x in specs) if specs else ":"
    download = (get + "\ngo mod tidy\ngo mod download all\n"
                "go list -deps -test ./... > /work/test-dependencies.txt\n"
                f"go install golang.org/x/vuln/cmd/govulncheck@{scanner}\n"
                "CGO_ENABLED=0 /work/bin/govulncheck ./... > /work/govulncheck.txt\n"
                "CGO_ENABLED=0 /work/bin/govulncheck -json ./... > /work/govulncheck.json\n"
                "go list -m -json all > /work/candidate-modules.json\n")
    _container(image, approved, scratch, download, token, "download-and-scan", network="bridge")
    findings = [m["finding"] for m in _json_stream(_safe_read(scratch / "govulncheck.json", work).decode()) if "finding" in m]
    if any(any(frame.get("package") or frame.get("function") for frame in f.get("trace", [])) for f in findings):
        raise BuildError("govulncheck found an affected imported package or symbol")
    candidate = scratch / "src"
    _source_unchanged(candidate, manifest, work)
    candidate_modules = _json_stream(_safe_read(scratch / "candidate-modules.json", work).decode())
    selected = {item["Path"]: item.get("Version") for item in candidate_modules}
    if any(selected.get(module) != item["candidate"] for module, item in plan["modules"].items()):
        raise BuildError("resolved dependencies differ from the explicit stable/compatible plan")
    version = _safe_read(approved / "VERSION", work).decode().strip()
    if not VERSION.fullmatch(version):
        raise BuildError("unsafe application VERSION")
    offline = ("export GOPROXY=off\ngo mod verify\n"
               "go test -race ./...\ngo vet ./...\n"
               f"CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '-s -w -X main.version={version}' -o /work/output/guardian ./cmd/guardian\n"
               "CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '-s -w' -o /work/output/guardian-recovery ./cmd/guardian-recovery\n"
               "go version -m /work/output/guardian /work/output/guardian-recovery > /work/build-info.txt\n")
    _container(image, approved, scratch, offline, token, "offline-qualification", network="none")
    # A download/tool/test must not silently alter reviewed app source.
    _source_unchanged(candidate, manifest, work)
    binaries = {name: str(scratch / "output" / name) for name in ("guardian", "guardian-recovery")}
    sha256 = {}
    for name, value in binaries.items():
        path = Path(value)
        content = _safe_read(path, work, max_bytes=64 << 20)
        if content[:5] != b"\x7fELF\x02" or content[18:20] != b"\x3e\x00":
            raise BuildError("candidate binary missing or not 64-bit ELF")
        sha256[name] = hashlib.sha256(content).hexdigest()
    report = {"version": 1, "status": "qualified", "installed": False,
              "observed_unix": int(time.time()), "source_dir": str(candidate),
              "approved_source_dir": str(source), "approved_source_sha256": manifest,
              "compiler_version": compiler, "compiler_image": image,
              "govulncheck_version": scanner, "dependency_plan": plan,
              "discovery_fingerprint": discovery["fingerprint"],
              "vulnerability_db_modified": discovery["vulnerability_db_modified"],
              "current_modules": _json_stream(_safe_read(scratch / "current-modules.json", work).decode()),
              "candidate_modules": candidate_modules,
              "vulnerability_findings": findings, "binaries": binaries, "sha256": sha256,
              "go_mod_sha256": hashlib.sha256(_safe_read(candidate / "go.mod", work)).hexdigest(),
              "go_sum_sha256": hashlib.sha256(_safe_read(candidate / "go.sum", work)).hexdigest(),
              "builder_containers_remaining": 0,
              "qualification": ["official exact compiler/image architecture", "authenticated explicit stable dependency downloads", "current govulncheck", "network-disabled Go race tests and vet", "Linux amd64 static builds", "approved app source unchanged"],
              "limitations": ["Qualification does not install or prove actual mailbox behavior/recovery.", "New module major paths require reviewed source migration.", "Known-vulnerability detection is bounded by the current Go database and build configuration."]}
    receipt = work / "builder-receipt.json"
    report["receipt_path"] = str(receipt)
    receipt.write_text(json.dumps(report, indent=2) + "\n")
    receipt.chmod(0o600)
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_dir", type=Path)
    parser.add_argument("work_dir", type=Path)
    args = parser.parse_args()
    print(json.dumps(build_candidate(args.source_dir, args.work_dir), indent=2))
