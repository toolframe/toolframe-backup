"""Protected exact-lock payloads and final-path environment reconstruction."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import posixpath
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit

from packaging.markers import InvalidMarker, Marker
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import sys_tags
from packaging.utils import (
    InvalidWheelFilename,
    canonicalize_name,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from .archive import BackupError

LOCK_FIELDS = (
    "candidate_id",
    "purpose",
    "environment_id",
    "sha256",
    "python_version",
    "python_implementation",
    "platform_system",
    "platform_machine",
    "requires_python",
)
MAX_ENVIRONMENTS = 100
_ENV_ID = re.compile(r"[0-9a-f]{64}\Z")
_PYTHON_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?\Z"
)


def _fail(code: str, message: str):
    raise BackupError(code, message) from None


def capture(inventory, metadata: list[dict]) -> bytes:
    raw = []
    for lock in getattr(inventory, "environment_locks", ()):
        raw.append(
            {
                "candidate_id": lock.candidate_id,
                "purpose": lock.purpose,
                "environment_id": lock.environment_id,
                "lock": lock.lock,
            }
        )
    encoded = json.dumps(
        raw, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    validate(encoded, metadata)
    return encoded


def validate(raw: bytes, metadata: list[dict]) -> list[dict]:
    from .archive import SHA256, _unique_json

    try:
        content = json.loads(raw, object_pairs_hook=_unique_json)
    except ValueError, UnicodeError, RecursionError:
        _fail("invalid_environment_lock", "Protected environment locks are invalid.")
    expected = {
        (item["candidate_id"], item["purpose"], item["environment_id"]): item
        for item in metadata
    }
    if not isinstance(content, list) or len(content) != len(expected):
        _fail(
            "invalid_environment_lock",
            "Protected environment locks disagree with metadata.",
        )
    seen, environments = set(), {}
    for item in content:
        if not isinstance(item, dict) or set(item) != {
            "candidate_id",
            "purpose",
            "environment_id",
            "lock",
        }:
            _fail(
                "invalid_environment_lock",
                "Protected environment lock fields are invalid.",
            )
        if not all(isinstance(item[field], str) for field in item):
            _fail(
                "invalid_environment_lock",
                "Protected environment lock values are invalid.",
            )
        key = (item["candidate_id"], item["purpose"], item["environment_id"])
        if key not in expected or key in seen:
            _fail(
                "invalid_environment_lock",
                "Protected environment lock identity is invalid.",
            )
        seen.add(key)
        if not _ENV_ID.fullmatch(item["environment_id"]):
            _fail("invalid_environment_lock", "Environment identity is unsupported.")
        public = expected[key]
        if hashlib.sha256(item["lock"].encode()).hexdigest() != public["sha256"]:
            _fail(
                "checksum_mismatch",
                "Protected environment lock checksum disagrees with metadata.",
            )
        try:
            lock = tomllib.loads(item["lock"])
        except ValueError, RecursionError:
            _fail(
                "invalid_environment_lock",
                "Protected environment lock is invalid TOML.",
            )
        if lock.get("lock-version") != "1.0" or not isinstance(
            lock.get("packages"), list
        ):
            _fail(
                "invalid_environment_lock",
                "Only version 1.0 pylock environment locks are supported.",
            )
        try:
            requirement = SpecifierSet(public["requires_python"])
            source_python = Version(public["python_version"])
        except InvalidSpecifier, InvalidVersion, TypeError:
            _fail(
                "invalid_environment_lock", "Python compatibility metadata is invalid."
            )
        if not _PYTHON_VERSION.fullmatch(public["python_version"]):
            _fail(
                "invalid_environment_lock",
                "Recorded Python version must have two or three numeric components.",
            )
        if (
            lock.get("requires-python") != public["requires_python"]
            or len(source_python.release) == 3
            and source_python not in requirement
        ):
            _fail(
                "incompatible_environment",
                "Python requirement and original interpreter metadata disagree.",
            )
        _markers(lock)
        for package in lock["packages"]:
            # Both index wheels and direct wheel archives are normal uv pylocks.
            for wheel in _wheel_options(package):
                checksum = wheel.get("hashes", {}).get("sha256")
                if not isinstance(checksum, str) or not SHA256.fullmatch(checksum):
                    _fail(
                        "invalid_environment_lock",
                        "Environment wheels require exact SHA-256 hashes.",
                    )
                filename = _wheel_filename(wheel, item["environment_id"])
                try:
                    name, version, _, _ = parse_wheel_filename(filename)
                    same_package = name == canonicalize_name(
                        package["name"]
                    ) and version == Version(package["version"])
                except InvalidWheelFilename, InvalidVersion, TypeError, KeyError:
                    _fail(
                        "invalid_environment_lock",
                        "A dependency wheel identity is invalid.",
                    )
                if not same_package:
                    _fail(
                        "invalid_environment_lock",
                        "A dependency wheel differs from its locked package.",
                    )
            _package_marker(package)
        prior = environments.get(item["environment_id"])
        signature = (item["lock"], tuple(public[field] for field in LOCK_FIELDS[4:]))
        if prior is not None and prior != signature:
            _fail(
                "invalid_environment_lock", "Repeated environment identities disagree."
            )
        environments[item["environment_id"]] = signature
    if len(environments) > MAX_ENVIRONMENTS:
        _fail("limit_exceeded", "Recovery supports at most 100 distinct environments.")
    return content


def _markers(lock: dict) -> list[Marker]:
    markers = lock.get("environments", [])
    if not isinstance(markers, list) or any(
        not isinstance(marker, str) for marker in markers
    ):
        _fail("invalid_environment_lock", "Environment markers are invalid.")
    try:
        return [Marker(marker) for marker in markers]
    except InvalidMarker:
        _fail("invalid_environment_lock", "Environment markers are invalid.")


def _wheel_options(package: dict) -> list[dict]:
    if not isinstance(package, dict):
        _fail("invalid_environment_lock", "A dependency record is invalid.")
    if "archive" in package:
        if "wheels" in package or not isinstance(package["archive"], dict):
            _fail(
                "invalid_environment_lock", "A direct wheel archive record is invalid."
            )
        choices = [package["archive"]]
    else:
        choices = package.get("wheels")
    if not isinstance(choices, list) or not choices:
        _fail(
            "unsupported_environment_lock",
            "Recovery requires exact wheel-only environment locks.",
        )
    if any(
        not isinstance(choice, dict) or not isinstance(choice.get("hashes"), dict)
        for choice in choices
    ):
        _fail("invalid_environment_lock", "A dependency wheel record is invalid.")
    return choices


def _wheel_filename(wheel: dict, environment_id: str) -> str:
    locators = [key for key in ("path", "url") if key in wheel]
    if len(locators) != 1 or not isinstance(wheel[locators[0]], str):
        _fail("invalid_environment_lock", "A dependency wheel locator is invalid.")
    locator = wheel[locators[0]]
    if not locator or "\\" in locator or any(ord(char) < 32 for char in locator):
        _fail("invalid_environment_lock", "A dependency wheel locator is invalid.")
    if locators[0] == "url":
        try:
            uri = urlsplit(
                locator.replace("${TOOLFRAME_HOME}", "/toolframe-recovery-home")
            )
        except ValueError:
            _fail("invalid_environment_lock", "A dependency wheel locator is invalid.")
        if uri.scheme == "https" and uri.hostname:
            path = unquote(uri.path)
        elif uri.scheme == "file" and uri.netloc in ("", "localhost"):
            path = unquote(uri.path)
            original = (
                path.replace("/toolframe-recovery-home", "${TOOLFRAME_HOME}", 1)
                if "${TOOLFRAME_HOME}" in locator
                else path
            )
            _local_wheel_path(original, environment_id)
        else:
            _fail(
                "unsupported_environment_lock",
                "A dependency wheel location is unsupported.",
            )
    else:
        path = locator
        _local_wheel_path(path, environment_id)
    filename = posixpath.basename(path)
    if not filename.endswith(".whl"):
        _fail("unsupported_environment_lock", "Recovery refuses source archive builds.")
    return filename


def _local_wheel_path(path: str, environment_id: str) -> None:
    root = "/toolframe-recovery-home"
    if path.startswith("${TOOLFRAME_HOME}/"):
        resolved = posixpath.normpath(root + path[len("${TOOLFRAME_HOME}") :])
    elif not path.startswith("/") and "$" not in path and ":" not in path:
        resolved = posixpath.normpath(
            f"{root}/.toolframe/environments/{environment_id}/{path}"
        )
    else:
        _fail(
            "unsupported_environment_lock",
            "A local dependency wheel must remain within the recovered home.",
        )
    if not resolved.startswith(root + "/"):
        _fail(
            "unsupported_environment_lock",
            "A local dependency wheel escapes the recovered home.",
        )


def _package_marker(package: dict) -> Marker | None:
    marker = package.get("marker")
    if marker is None:
        return None
    if not isinstance(marker, str):
        _fail("invalid_environment_lock", "Package markers are invalid.")
    try:
        return Marker(marker)
    except InvalidMarker:
        _fail("invalid_environment_lock", "Package markers are invalid.")


def _filename_matches_tags(filename: str, tags: set) -> bool:
    try:
        return bool(tags & parse_wheel_filename(filename)[3])
    except InvalidWheelFilename, TypeError, ValueError:
        return False


def check_compatibility(
    metadata: list[dict],
    content: list[dict] | None = None,
    *,
    dependency_wheels: list[dict] | tuple = (),
) -> None:
    actual = Version(platform.python_version())
    for item in metadata:
        recorded = Version(item["python_version"])
        same_version = (
            recorded == actual
            if len(recorded.release) == 3
            else recorded.release == actual.release[:2]
        )
        if (
            not same_version
            or item["python_implementation"].lower()
            != platform.python_implementation().lower()
            or item["platform_system"] != platform.system()
            or item["platform_machine"] != platform.machine()
        ):
            _fail(
                "incompatible_environment",
                "Recovery requires matching recorded Python precision, implementation, operating system and machine architecture.",
            )
        if actual not in SpecifierSet(item["requires_python"]):
            _fail(
                "incompatible_environment",
                "The complete operator Python version does not meet Requires-Python.",
            )
    tags = set(sys_tags())
    grouped = {}
    for wheel in dependency_wheels:
        grouped.setdefault(
            (wheel["environment_id"], wheel["distribution"], wheel["version"]), []
        ).append(wheel)
    for choices in grouped.values():
        if not any(
            _filename_matches_tags(wheel["filename"], tags) for wheel in choices
        ):
            _fail(
                "incompatible_environment",
                "Recorded dependency wheels do not match the operator interpreter and platform.",
            )
    for protected in content or ():
        lock = tomllib.loads(protected["lock"])
        markers = _markers(lock)
        if markers and not any(marker.evaluate() for marker in markers):
            _fail(
                "incompatible_environment",
                "The operator does not match the recorded environment markers.",
            )
        for package in lock["packages"]:
            marker = _package_marker(package)
            applicable = marker is None or marker.evaluate()
            if applicable and not any(
                _filename_matches_tags(
                    _wheel_filename(wheel, protected["environment_id"]), tags
                )
                for wheel in _wheel_options(package)
            ):
                _fail(
                    "incompatible_environment",
                    "A locked package has no compatible operator wheel.",
                )


def _run(command: list[str], *, timeout: int = 300) -> None:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        )
    except OSError, subprocess.TimeoutExpired:
        _fail(
            "rehydration_failed",
            "Exact environment reconstruction failed; subprocess diagnostics are suppressed to protect credentials.",
        )
    if result.returncode:
        _fail(
            "rehydration_failed",
            "Exact environment reconstruction failed; supply compatible exact-hash wheels and check operator dependency prerequisites.",
        )


def rehydrate(
    home: Path,
    content: list[dict],
    *,
    uv_path: str = "uv",
    wheelhouse: Path | None = None,
    offline: bool = False,
) -> int:
    if not content:
        return 0
    executable = shutil.which(uv_path)
    if executable is None:
        _fail(
            "uv_missing",
            "Exact environment reconstruction requires uv on PATH or --uv-path.",
        )
    flags = ["--offline"] if offline else []
    if wheelhouse is not None:
        wheelhouse = Path(wheelhouse).absolute()
        if not wheelhouse.is_dir():
            _fail(
                "wheelhouse_missing",
                "A local operator-supplied wheelhouse directory is required.",
            )
        flags.extend(["--find-links", str(wheelhouse)])
    unique = {item["environment_id"]: item["lock"] for item in content}
    root = home / ".toolframe" / "environments"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for identifier, lock in unique.items():
        target = root / identifier
        if target.exists():
            _fail(
                "environment_exists",
                "Recovery payload unexpectedly contains a runtime environment.",
            )
        # Build at the final absolute path: console-script shebangs remain valid.
        _run(
            [executable, "--no-config", "venv", "--python", sys.executable, str(target)]
        )
        target.chmod(0o700)
        lockfile = target / "pylock.toml"
        fd = os.open(lockfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(lock.replace("${TOOLFRAME_HOME}", str(home)))
        _run(
            [
                executable,
                "--no-config",
                "pip",
                "sync",
                "--python",
                str(target / "bin" / "python"),
                "--require-hashes",
                "--only-binary",
                ":all:",
                *flags,
                str(lockfile),
            ]
        )
        ready = target / ".ready"
        fd = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(identifier)
            output.flush()
            os.fsync(output.fileno())
    return len(unique)
