"""Bounded recovery archive operations, independent of the running application.

Creation and environment restoration lazily use Core's public maintenance contexts.
Verification imports neither Core nor the plugin runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import uuid
import zipfile
import zlib
from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

FORMAT = "toolframe-backup"
FORMAT_VERSION = 1
BACKUP_ID = re.compile(r"[0-9a-f]{32}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MANIFEST = "manifest.json"
RECOVERY = "recovery/environment-locks.json"
CHUNK = 1024 * 1024


class BackupError(Exception):
    """A safe operator-facing error; no payload contents are included."""

    def __init__(self, code: str, message: str):
        self.code, self.message = code, message
        super().__init__(message)


@dataclass(frozen=True)
class Limits:
    max_files: int = 10_000
    max_total_bytes: int = 2 * 1024**3
    max_file_bytes: int = 512 * 1024**2
    max_manifest_bytes: int = 4 * 1024**2
    max_ratio: int = 200
    max_archive_bytes: int = 3 * 1024**3
    max_recovery_bytes: int = 16 * 1024**2


DEFAULT_LIMITS = Limits()


@dataclass(frozen=True)
class VerifiedBackup:
    manifest: dict[str, Any]
    archive_sha256: str

    def summary(self) -> dict[str, Any]:
        inventory = self.manifest["inventory"]
        return {
            "id": self.manifest["id"],
            "created_at": self.manifest["created_at"],
            "application_id": inventory["application_id"],
            "application_name": inventory["application_name"],
            "composition_revision": inventory["composition_revision"],
            "file_count": len(self.manifest["entries"]),
            "total_bytes": sum(item["size"] for item in self.manifest["entries"]),
            "archive_sha256": self.archive_sha256,
            "verified": True,
        }


def _fail(code: str = "invalid_archive", message: str = "Backup archive is invalid."):
    raise BackupError(code, message)


def safe_path(value: Any) -> str:
    """Accept exactly a portable, relative POSIX file path."""
    if not isinstance(value, str) or not value or len(value) > 1024:
        _fail("unsafe_path", "Backup contains an unsafe path.")
    if any(ord(character) < 32 for character in value) or "\\" in value or ":" in value:
        _fail("unsafe_path", "Backup contains an unsafe path.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        _fail("unsafe_path", "Backup contains an unsafe path.")
    return value


def _no_symlinks(path: Path) -> None:
    for part in (path, *path.parents):
        if part.is_symlink():
            _fail("unsafe_path", "Symlinked paths are not supported.")


def protected_directory(path: Path, *, create: bool = False) -> Path:
    path = Path(os.path.abspath(path))
    _no_symlinks(path)
    if create:
        missing = []
        current = path
        while not current.exists():
            missing.append(current)
            current = current.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
    if not path.is_dir():
        _fail("destination_missing", "A local backup directory is required.")
    metadata = path.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.geteuid():
        _fail("destination_permissions", "Backup directory must have mode 0700.")
    return path


def _sha_file(path: Path, limit: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while data := stream.read(CHUNK):
            total += len(data)
            if total > limit:
                _fail("limit_exceeded", "Backup exceeds the configured size limit.")
            digest.update(data)
    return digest.hexdigest()


def _text(value: Any, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 1024 or "://" in value:
        _fail("invalid_metadata", "Backup metadata is invalid.")
    if any(ord(character) < 32 for character in value):
        _fail("invalid_metadata", "Backup metadata is invalid.")
    return value


def _integer(value: Any, maximum: int, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("invalid_metadata", "Backup metadata exceeds supported limits.")
    return value


def _hash(value: Any) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        _fail("invalid_metadata", "Backup checksum metadata is invalid.")
    return value


def _object(value: Any, keys: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        _fail("invalid_metadata", "Backup metadata fields are invalid.")
    return value


def _list(value: Any, limits: Limits) -> list:
    if not isinstance(value, list) or len(value) > limits.max_files:
        _fail("limit_exceeded", "Backup has too many metadata entries.")
    return value


def _validate_inventory(inventory: dict, entries: list, limits: Limits) -> None:
    _object(
        inventory,
        {
            "format_version",
            "status",
            "application_id",
            "application_name",
            "composition_revision",
            "files",
            "stores",
            "retained_keys",
            "dependency_wheels",
            "environment_locks",
        },
    )
    if inventory["format_version"] != 1 or inventory["status"] != "STOPPED":
        _fail(
            "unsupported_format",
            "Backup requires inventory version 1 and STOPPED status.",
        )
    for field in ("application_id", "application_name"):
        _text(inventory[field])
    _text(inventory["composition_revision"], nullable=True)
    files = {}
    for item in _list(inventory["files"], limits):
        _object(item, {"path", "role", "size", "mode", "sha256"})
        path = safe_path(item["path"])
        if path in files:
            _fail()
        _text(item["role"])
        _integer(item["size"], limits.max_file_bytes)
        _integer(item["mode"], 0o777)
        _hash(item["sha256"])
        files[path] = item
    if set(files) != {entry["path"] for entry in entries}:
        _fail("inventory_mismatch", "Backup inventory and payload disagree.")
    stores = set()
    for store in _list(inventory["stores"], limits):
        _object(store, {"path", "owner", "provider"})
        path = safe_path(store["path"])
        if path not in files or path in stores:
            _fail("inventory_mismatch", "Backup store identity is invalid.")
        stores.add(path)
        _text(store["owner"], nullable=True)
        _text(store["provider"])
    for key in _list(inventory["retained_keys"], limits):
        _object(key, {"path", "owner", "name"})
        if safe_path(key["path"]) not in files:
            _fail("inventory_mismatch", "A retained key payload is missing.")
        _text(key["owner"], nullable=True)
        _text(key["name"])
    for wheel in _list(inventory["dependency_wheels"], limits):
        from packaging.utils import (
            InvalidWheelFilename,
            canonicalize_name,
            parse_wheel_filename,
        )
        from packaging.version import InvalidVersion, Version

        _object(
            wheel,
            {"environment_id", "distribution", "version", "filename", "sha256", "path"},
        )
        for field in ("environment_id", "distribution", "version"):
            _text(wheel[field])
        if "/" in safe_path(wheel["filename"]) or not wheel["filename"].endswith(
            ".whl"
        ):
            _fail()
        try:
            name, version, _, _ = parse_wheel_filename(wheel["filename"])
            matches = name == canonicalize_name(
                wheel["distribution"]
            ) and version == Version(wheel["version"])
        except InvalidWheelFilename, InvalidVersion:
            _fail()
        if not matches:
            _fail()
        _hash(wheel["sha256"])
        if wheel["path"] is not None:
            path = safe_path(wheel["path"])
            if path not in files or files[path]["sha256"] != wheel["sha256"]:
                _fail("inventory_mismatch", "A retained dependency wheel is missing.")
    for lock in _list(inventory["environment_locks"], limits):
        from .environments import LOCK_FIELDS

        _object(lock, set(LOCK_FIELDS))
        if not isinstance(lock["purpose"], str) or lock["purpose"] not in {
            "backend",
            "ui",
            "web",
        }:
            _fail()
        _text(lock["candidate_id"])
        _text(lock["environment_id"])
        _hash(lock["sha256"])
        for field in LOCK_FIELDS[4:]:
            _text(lock[field])
    for entry in entries:
        source = files[entry["path"]]
        if (
            entry["source_sha256"] != source["sha256"]
            or entry["role"] != source["role"]
        ):
            _fail(
                "inventory_mismatch", "Source artifact metadata disagrees with payload."
            )
        if entry["snapshot"] == "sqlite" and entry["path"] not in stores:
            _fail()
        if entry["snapshot"] == "file" and (
            entry["sha256"] != source["sha256"] or entry["size"] != source["size"]
        ):
            _fail()


def _validate_manifest(manifest: Any, limits: Limits) -> dict:
    _object(
        manifest,
        {"format", "format_version", "id", "created_at", "inventory", "entries"}
        | (
            {"environment_payload"}
            if isinstance(manifest, dict) and "environment_payload" in manifest
            else set()
        ),
    )
    if manifest["format"] != FORMAT or manifest["format_version"] != FORMAT_VERSION:
        _fail("unsupported_format", "Unsupported backup archive version.")
    if not isinstance(manifest["id"], str) or not BACKUP_ID.fullmatch(manifest["id"]):
        _fail()
    try:
        timestamp = datetime.fromisoformat(manifest["created_at"])
        if timestamp.utcoffset() is None:
            _fail()
    except TypeError, ValueError:
        _fail()
    paths = set()
    total = 0
    for entry in _list(manifest["entries"], limits):
        _object(
            entry,
            {"path", "role", "size", "mode", "sha256", "source_sha256", "snapshot"},
        )
        path = safe_path(entry["path"])
        if path in paths or any(
            path.startswith(previous + "/") or previous.startswith(path + "/")
            for previous in paths
        ):
            _fail("duplicate_entry", "Backup has conflicting file paths.")
        paths.add(path)
        _text(entry["role"])
        total += _integer(entry["size"], limits.max_file_bytes)
        if total > limits.max_total_bytes:
            _fail("limit_exceeded", "Backup exceeds total uncompressed size limit.")
        # All restored payloads remain operator-only, including formerly executable files.
        if (
            entry["mode"] != 0o600
            or not isinstance(entry["snapshot"], str)
            or entry["snapshot"] not in {"file", "sqlite"}
        ):
            _fail()
        _hash(entry["sha256"])
        _hash(entry["source_sha256"])
    _validate_inventory(manifest["inventory"], manifest["entries"], limits)
    if bool(manifest["inventory"]["environment_locks"]) != (
        "environment_payload" in manifest
    ):
        _fail("missing_entry", "Protected exact environment locks are required.")
    if "environment_payload" in manifest:
        payload = _object(manifest["environment_payload"], {"size", "sha256"})
        size = _integer(payload["size"], limits.max_recovery_bytes)
        _hash(payload["sha256"])
        if total + size > limits.max_total_bytes:
            _fail("limit_exceeded", "Backup exceeds total uncompressed size limit.")
    return manifest


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_entry", "Backup has duplicate metadata fields.")
        result[key] = value
    return result


def _inspect(archive: zipfile.ZipFile, limits: Limits) -> dict:
    members = archive.infolist()
    if len(members) > limits.max_files + 2:
        _fail("limit_exceeded", "Backup contains too many archive members.")
    names = set()
    total = 0
    for member in members:
        name = safe_path(member.orig_filename)
        if name != member.filename:
            _fail("unsafe_path", "Backup contains a truncated archive path.")
        mode = member.external_attr >> 16
        if name in names:
            _fail("duplicate_entry", "Backup has duplicate archive members.")
        names.add(name)
        if (
            stat.S_IFMT(mode) not in {0, stat.S_IFREG}
            or member.is_dir()
            or member.flag_bits & 1
            or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
        ):
            _fail("unsafe_member", "Backup contains unsupported archive members.")
        maximum = (
            limits.max_manifest_bytes
            if name == MANIFEST
            else limits.max_recovery_bytes
            if name == RECOVERY
            else limits.max_file_bytes
        )
        if (
            member.file_size > maximum
            or member.file_size > max(1, member.compress_size) * limits.max_ratio
        ):
            _fail(
                "limit_exceeded",
                "Backup exceeds a member size or decompression ratio limit.",
            )
        total += member.file_size
        if total > limits.max_total_bytes + limits.max_manifest_bytes:
            _fail("limit_exceeded", "Backup exceeds total uncompressed size limit.")
    if MANIFEST not in names:
        _fail("missing_entry", "Backup manifest is missing.")
    try:
        manifest = json.loads(archive.read(MANIFEST), object_pairs_hook=_unique_json)
    except ValueError, UnicodeError, RecursionError:
        _fail("invalid_metadata", "Backup manifest is invalid JSON.")
    _validate_manifest(manifest, limits)
    expected = {MANIFEST, *("payload/" + item["path"] for item in manifest["entries"])}
    if "environment_payload" in manifest:
        expected.add(RECOVERY)
    if names != expected:
        _fail("unexpected_entry", "Backup has unexpected or missing payload members.")
    if "environment_payload" in manifest:
        from .environments import validate

        raw = archive.read(RECOVERY)
        payload = manifest["environment_payload"]
        if (
            len(raw) != payload["size"]
            or hashlib.sha256(raw).hexdigest() != payload["sha256"]
        ):
            _fail(
                "checksum_mismatch",
                "Protected environment payload checksum disagrees with metadata.",
            )
        validate(raw, manifest["inventory"]["environment_locks"])
    for entry in manifest["entries"]:
        member = archive.getinfo("payload/" + entry["path"])
        if member.file_size != entry["size"]:
            _fail("checksum_mismatch", "Backup payload size disagrees with manifest.")
        digest, size = hashlib.sha256(), 0
        with archive.open(member) as source:
            while data := source.read(CHUNK):
                size += len(data)
                if size > entry["size"]:
                    _fail("limit_exceeded", "Backup payload exceeds declared size.")
                digest.update(data)
        if size != entry["size"] or digest.hexdigest() != entry["sha256"]:
            _fail(
                "checksum_mismatch", "Backup payload checksum disagrees with manifest."
            )
    return manifest


@contextmanager
def _open_verified(path: Path, limits: Limits):
    from .zipguard import check_zip_directory

    path = Path(os.path.abspath(path))
    _no_symlinks(path)
    with ExitStack() as resources:
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            stream = resources.enter_context(os.fdopen(descriptor, "rb"))
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size > limits.max_archive_bytes
            ):
                _fail(
                    "limit_exceeded",
                    "Backup file is not regular or exceeds archive size limit.",
                )
            try:
                check_zip_directory(
                    stream,
                    max_members=limits.max_files + 2,
                    max_directory_bytes=(limits.max_files + 2) * 2048,
                )
            except ValueError:
                _fail(
                    "invalid_archive",
                    "Backup ZIP directory exceeds bounds or is invalid.",
                )
            digest, count = hashlib.sha256(), 0
            while data := stream.read(CHUNK):
                count += len(data)
                if count > limits.max_archive_bytes:
                    _fail(
                        "limit_exceeded",
                        "Backup changed beyond the archive size limit.",
                    )
                digest.update(data)
            stream.seek(0)
            archive = resources.enter_context(zipfile.ZipFile(stream))
            manifest = _inspect(archive, limits)
            after = os.fstat(stream.fileno())
            if (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                _fail("archive_changed", "Backup changed during verification.")
        except BackupError:
            raise
        except (
            OSError,
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
            RuntimeError,
            EOFError,
            zlib.error,
            UnicodeError,
        ):
            _fail("invalid_archive", "Backup could not be read or verified.")
        # Exceptions from restoration/rehydration belong to the caller, not ZIP parsing.
        yield archive, VerifiedBackup(manifest, digest.hexdigest())


def verify_backup(path: Path, *, limits: Limits = DEFAULT_LIMITS) -> VerifiedBackup:
    """Verify every member and checksum without extracting payloads."""
    with _open_verified(Path(path), limits) as (_, result):
        return result


def restore_backup(
    path: Path,
    destination: Path,
    *,
    limits: Limits = DEFAULT_LIMITS,
    uv_path: str = "uv",
    wheelhouse: Path | None = None,
    offline: bool = False,
) -> dict:
    """Validate, publish under HostLock, then reconstruct exact final-path environments."""
    from .environments import check_compatibility, validate

    destination = Path(os.path.abspath(destination))
    if any(char in str(destination) for char in ('"', "'", "\\")) or any(
        ord(char) < 32 for char in str(destination)
    ):
        _fail(
            "unsupported_destination",
            "Restore paths cannot contain quotes, backslashes or control characters.",
        )
    _no_symlinks(destination)
    if destination.exists():
        _fail("destination_exists", "Restore requires an entirely new destination.")
    if not destination.parent.is_dir():
        _fail("destination_missing", "Restore parent directory must already exist.")
    staging = None
    try:
        with _open_verified(Path(path), limits) as (archive, result):
            metadata = result.manifest["inventory"]["environment_locks"]
            locks = validate(archive.read(RECOVERY), metadata) if metadata else []
            check_compatibility(
                metadata,
                locks,
                dependency_wheels=result.manifest["inventory"]["dependency_wheels"],
            )
            staging = Path(
                tempfile.mkdtemp(prefix=".backup-restore-", dir=destination.parent)
            )
            for entry in result.manifest["entries"]:
                target = staging / entry["path"]
                missing = []
                current = target.parent
                while current != staging and not current.exists():
                    missing.append(current)
                    current = current.parent
                for directory in reversed(missing):
                    directory.mkdir(mode=0o700)
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                digest, size = hashlib.sha256(), 0
                with (
                    os.fdopen(fd, "wb") as output,
                    archive.open("payload/" + entry["path"]) as source,
                ):
                    while data := source.read(CHUNK):
                        size += len(data)
                        if size > entry["size"]:
                            _fail("limit_exceeded", "Backup changed during extraction.")
                        digest.update(data)
                        output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
                if size != entry["size"] or digest.hexdigest() != entry["sha256"]:
                    _fail("checksum_mismatch", "Backup changed during extraction.")
            original = staging.stat()
            # Empty inventories need no environment construction. When environments
            # exist, the public guard follows the lock inode through publication.
            guard = _application_lock(staging) if locks else _empty_guard()
            with guard:
                _rename_new_directory(staging, destination)
                try:
                    count = _rehydrate_environments(
                        destination,
                        locks,
                        uv_path=uv_path,
                        wheelhouse=wheelhouse,
                        offline=offline,
                    )
                except BaseException:
                    current = destination.stat()
                    if (current.st_dev, current.st_ino) != (
                        original.st_dev,
                        original.st_ino,
                    ):
                        _fail(
                            "restore_conflict",
                            "Restore destination changed; unrelated content was preserved.",
                        )
                    # Remove the public name while its HostLock is still held;
                    # clean only our newly created tree after rolling it back.
                    _rename_new_directory(destination, staging)
                    raise
            staging = None
            return {**result.summary(), "ready": True, "rehydrated_environments": count}
    except BackupError:
        raise
    except OSError:
        _fail(
            "restore_failed",
            "Backup restoration failed; final destination was not published.",
        )
    except Exception:  # noqa: BLE001 - redact optional public lock/uv diagnostics after rollback
        _fail("restore_failed", "Backup restoration failed; no recovery home is ready.")
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


@contextmanager
def _empty_guard():
    yield


def _application_lock(home: Path):
    try:
        from toolframe_core.maintenance import application_lock
    except ImportError:
        _fail(
            "operator_dependency_missing",
            "Restore requires toolframe-backup[operator] with the public Core application lock API.",
        )
    return application_lock(home)


def _rehydrate_environments(home: Path, locks: list[dict], **kwargs) -> int:
    from .environments import rehydrate

    return rehydrate(home, locks, **kwargs)


def _rename_new_directory(source: Path, destination: Path) -> None:
    """Use OS no-replace rename; POSIX rename alone can overwrite an empty home."""
    import ctypes
    import errno
    import sys

    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.renamex_np(
            os.fsencode(source), os.fsencode(destination), 0x00000004
        )
    elif sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.renameat2(
            -100, os.fsencode(source), -100, os.fsencode(destination), 1
        )
    else:
        _fail("unsupported_platform", "Atomic restore requires Linux or macOS.")
    if result != 0:
        if ctypes.get_errno() in {errno.EEXIST, errno.ENOTEMPTY}:
            _fail(
                "destination_exists", "Restore destination appeared during extraction."
            )
        raise OSError(ctypes.get_errno(), "Atomic restore failed")


def _stopped_application(home: Path):
    try:
        from toolframe_core.maintenance import stopped_application
    except ImportError:
        _fail(
            "operator_dependency_missing",
            "Create requires toolframe-backup[operator] with the public Core maintenance API.",
        )
    return stopped_application(home)


def _public_inventory(inventory) -> dict:
    """Copy only documented public metadata, never journal lock contents or URLs."""
    data = inventory.as_dict()
    result = {
        "format_version": data.get("format_version"),
        "status": data.get("status"),
        "application_id": data.get("application_id"),
        "application_name": data.get("application_name"),
        "composition_revision": data.get("composition_revision"),
    }
    fields = {
        "files": ("path", "role", "size", "mode", "sha256"),
        "stores": ("path", "owner", "provider"),
        "retained_keys": ("path", "owner", "name"),
        "dependency_wheels": (
            "environment_id",
            "distribution",
            "version",
            "filename",
            "sha256",
            "path",
        ),
        "environment_locks": (
            "candidate_id",
            "purpose",
            "environment_id",
            "sha256",
            "python_version",
            "python_implementation",
            "platform_system",
            "platform_machine",
            "requires_python",
        ),
    }
    for name, keys in fields.items():
        result[name] = [
            {key: item.get(key) for key in keys} for item in data.get(name, ())
        ]
    return result


def _copy_inventory(inventory, staging: Path, limits: Limits) -> tuple[dict, list]:
    metadata = _public_inventory(inventory)
    home = Path(inventory.home)
    if len(metadata["files"]) > limits.max_files:
        _fail("limit_exceeded", "Source inventory contains too many files.")
    entries, total, seen = [], 0, set()
    for item in metadata["files"]:
        path = safe_path(item["path"])
        if path in seen:
            _fail()
        seen.add(path)
        source = home / path
        _no_symlinks(source)
        target = staging / path
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        digest, size = hashlib.sha256(), 0
        with source.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                _fail("unsafe_member", "Source inventory has a nonregular file.")
            with target.open("xb") as output:
                os.chmod(target, 0o600)
                while data := stream.read(CHUNK):
                    size += len(data)
                    total += len(data)
                    if size > limits.max_file_bytes or total > limits.max_total_bytes:
                        _fail(
                            "limit_exceeded", "Source exceeds configured backup limits."
                        )
                    digest.update(data)
                    output.write(data)
            after = os.fstat(stream.fileno())
        if (
            size != item["size"]
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            _fail("source_changed", "Source changed during stopped backup.")
        checksum = digest.hexdigest()
        if item["sha256"] is not None and checksum != item["sha256"]:
            _fail("source_changed", "Source checksum changed during stopped backup.")
        item["sha256"] = checksum
        entries.append(
            {
                "path": path,
                "role": item["role"],
                "size": size,
                "mode": 0o600,
                "sha256": checksum,
                "source_sha256": checksum,
                "snapshot": "file",
            }
        )
    by_path = {entry["path"]: entry for entry in entries}
    for store in metadata["stores"]:
        path = safe_path(store["path"])
        if path not in by_path:
            _fail("inventory_mismatch", "SQLite store is absent from inventory files.")
        source = staging / path
        snapshot = source.with_name(source.name + ".snapshot-" + uuid.uuid4().hex)
        try:
            with (
                closing(
                    sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
                ) as original,
                closing(sqlite3.connect(snapshot)) as output,
            ):
                original.backup(output)
                if output.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                    _fail(
                        "invalid_store",
                        "SQLite snapshot failed integrity verification.",
                    )
            snapshot.chmod(0o600)
            os.replace(snapshot, source)
            by_path[path].update(
                size=source.stat().st_size,
                sha256=_sha_file(source, limits.max_file_bytes),
                snapshot="sqlite",
            )
        except sqlite3.Error:
            _fail("invalid_store", "SQLite store could not be snapshotted.")
        finally:
            snapshot.unlink(missing_ok=True)
    return metadata, entries


def create_backup(
    home: Path, directory: Path, *, limits: Limits = DEFAULT_LIMITS
) -> dict:
    """Hold Core's stopped HostLock through every source read and archive publication."""
    home = Path(os.path.abspath(home))
    directory = Path(os.path.abspath(directory))
    _no_symlinks(home)
    _no_symlinks(directory)
    if directory == home or home in directory.parents:
        _fail(
            "unsafe_destination",
            "Backup output must be outside the source application home.",
        )
    directory = protected_directory(directory, create=True)
    identifier = uuid.uuid4().hex
    final = directory / f"backup-{identifier}.zip"
    partial = None
    published = False
    succeeded = False
    try:
        with (
            _stopped_application(home) as inventory,
            tempfile.TemporaryDirectory(
                prefix=".backup-create-", dir=directory
            ) as temporary,
        ):
            metadata, entries = _copy_inventory(inventory, Path(temporary), limits)
            manifest = {
                "format": FORMAT,
                "format_version": FORMAT_VERSION,
                "id": identifier,
                "created_at": datetime.now(UTC).isoformat(),
                "inventory": metadata,
                "entries": entries,
            }
            raw = None
            if metadata["environment_locks"]:
                from .environments import capture

                raw = capture(inventory, metadata["environment_locks"])
                manifest["environment_payload"] = {
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            _validate_manifest(manifest, limits)
            encoded = json.dumps(
                manifest, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
            if len(encoded) > limits.max_manifest_bytes:
                _fail(
                    "limit_exceeded",
                    "Backup manifest exceeds the configured size limit.",
                )
            fd, filename = tempfile.mkstemp(
                prefix=".backup-", suffix=".partial", dir=directory
            )
            partial = Path(filename)
            with os.fdopen(fd, "w+b") as stream:
                with zipfile.ZipFile(
                    stream, "w", compression=zipfile.ZIP_STORED
                ) as archive:
                    info = zipfile.ZipInfo(MANIFEST)
                    info.create_system, info.external_attr = (
                        3,
                        (stat.S_IFREG | 0o600) << 16,
                    )
                    archive.writestr(info, encoded)
                    if raw is not None:
                        info = zipfile.ZipInfo(RECOVERY)
                        info.create_system, info.external_attr = (
                            3,
                            (stat.S_IFREG | 0o600) << 16,
                        )
                        archive.writestr(info, raw)
                    for entry in entries:
                        archive.write(
                            Path(temporary) / entry["path"],
                            "payload/" + entry["path"],
                        )
                stream.flush()
                os.fsync(stream.fileno())
            result = verify_backup(partial, limits=limits)
            # Same-directory hard link publishes without replacing any existing archive.
            os.link(partial, final)
            published = True
            partial.unlink()
            partial = None
        succeeded = True
        return result.summary()
    except BackupError:
        raise
    except sqlite3.Error, OSError:
        _fail(
            "create_failed",
            "Backup creation failed; no complete archive was published.",
        )
    except Exception:  # noqa: BLE001 - redact maintenance diagnostics at the operator boundary
        _fail(
            "maintenance_refused",
            "Core refused the stopped source inventory; check application maintenance prerequisites.",
        )
    finally:
        if partial is not None:
            partial.unlink(missing_ok=True)
        if published and not succeeded:
            final.unlink(missing_ok=True)
