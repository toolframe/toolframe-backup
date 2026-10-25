"""Bounded local archive catalog and explicit, verified retention."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .archive import BackupError, verify_backup
from .operation import OperationStopped, catalog_lock, checkpoint, operation_scope

MAX_CANDIDATES = 1000
MAX_DIRECTORY_ENTRIES = 10_000
MAX_SCAN_BYTES = 4 * 1024**3
PLAN_LIFETIME_SECONDS = 600
_BACKUP_NAME = re.compile(r"backup-([0-9a-f]{32})\.zip\Z")
_BACKUP_ID = re.compile(r"[0-9a-f]{32}\Z")
_PLAN_TOKEN = re.compile(r"[0-9a-f]{64}\Z")
GUIDANCE = (
    "Stop the application, then use toolframe-backup create with the configured "
    "destination. Restart the application to inspect the archive here."
)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _error(code: str, message: str) -> BackupError:
    return BackupError(code, message)


def bounded_integer(value: Any, name: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise _error("backup_validation", f"{name} must be between 1 and {maximum}.")
    return value


def validate_backup_id(value: Any) -> str:
    if not isinstance(value, str) or not _BACKUP_ID.fullmatch(value):
        raise _error(
            "backup_validation",
            "backup_id must be 32 lowercase hexadecimal characters.",
        )
    return value


def _stamp(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _protected(value: os.stat_result, *, directory: bool) -> bool:
    correct_kind = (
        stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)
    )
    return (
        correct_kind
        and value.st_uid == os.geteuid()
        and stat.S_IMODE(value.st_mode) == (0o700 if directory else 0o600)
    )


@dataclass(frozen=True)
class _Scan:
    backups: list[dict[str, Any]]
    rejected: list[dict[str, str]]
    fingerprint: str
    stamps: dict[str, tuple[int, ...]]
    directory_stamp: tuple[int, int] | None


@dataclass(frozen=True)
class _Plan:
    application_id: str
    fingerprint: str
    delete: list[dict[str, Any]]
    expires: float


class BackupCatalog:
    """The directory is authoritative; caches never authorize deletion."""

    def __init__(self, destination: str | Path, *, retention_keep: int = 10):
        if not isinstance(destination, (str, Path)) or not str(destination):
            raise _error(
                "backup_configuration",
                "Configure an absolute local destination directory.",
            )
        self.destination = Path(destination)
        if (
            not self.destination.is_absolute()
            or ".." in self.destination.parts
            or "\x00" in str(self.destination)
        ):
            raise _error(
                "backup_configuration",
                "Destination must be an absolute local path without traversal.",
            )
        self.retention_keep = bounded_integer(retention_keep, "retention_keep", 1000)
        self._lock = threading.RLock()
        self._plans: dict[str, _Plan] = {}
        self._directory()

    def _directory(self) -> os.stat_result | None:
        """Reject symlink components without resolving them into a different directory."""
        current = Path(self.destination.anchor)
        for part in self.destination.parts[1:]:
            checkpoint()
            current /= part
            try:
                value = current.lstat()
            except FileNotFoundError:
                return None
            except OSError:
                raise _error(
                    "backup_destination", "Backup destination cannot be inspected."
                ) from None
            if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode):
                raise _error(
                    "backup_destination",
                    "Destination components must be directories without symlinks.",
                )
        try:
            value = self.destination.lstat()
        except OSError:
            raise _error(
                "backup_destination", "Backup destination changed during inspection."
            ) from None
        if not _protected(value, directory=True):
            raise _error(
                "backup_permissions",
                "Backup destination must be operator-owned with permissions 0700.",
            )
        return value

    def _entries(
        self,
    ) -> tuple[list[tuple[str, os.stat_result]], tuple[int, int] | None]:
        directory = self._directory()
        if directory is None:
            return [], None
        candidates: list[tuple[str, os.stat_result]] = []
        entries = 0
        total_bytes = 0
        try:
            with os.scandir(self.destination) as iterator:
                for entry in iterator:
                    checkpoint()
                    entries += 1
                    if entries > MAX_DIRECTORY_ENTRIES:
                        raise _error(
                            "backup_catalog_limit",
                            "Destination has too many directory entries to scan safely.",
                        )
                    if not _BACKUP_NAME.fullmatch(entry.name):
                        continue
                    if len(candidates) >= MAX_CANDIDATES:
                        raise _error(
                            "backup_catalog_limit",
                            "Destination has more than 1000 backup candidates.",
                        )
                    value = entry.stat(follow_symlinks=False)
                    if stat.S_ISREG(value.st_mode):
                        total_bytes += value.st_size
                    if total_bytes > MAX_SCAN_BYTES:
                        raise _error(
                            "backup_catalog_limit",
                            "Backup candidates exceed the 4 GiB scan budget.",
                        )
                    candidates.append((entry.name, value))
        except OSError:
            raise _error(
                "backup_destination", "Backup destination changed or cannot be scanned."
            ) from None
        current = self._directory()
        if current is None or (current.st_dev, current.st_ino) != (
            directory.st_dev,
            directory.st_ino,
        ):
            raise _error(
                "backup_catalog_changed", "Backup destination changed. Try again."
            )
        return sorted(candidates), (directory.st_dev, directory.st_ino)

    def _verified(self, name: str, before: os.stat_result) -> dict[str, Any]:
        if not _protected(before, directory=False):
            raise _error(
                "backup_permissions",
                "Archive must be an operator-owned regular file with permissions 0600.",
            )
        checkpoint()
        verified = verify_backup(self.destination / name)
        checkpoint()
        summary = verified.summary()
        if name != f"backup-{summary['id']}.zip":
            raise _error(
                "backup_identity", "Archive name does not match its backup identity."
            )
        try:
            after = (self.destination / name).lstat()
        except OSError:
            raise _error(
                "backup_catalog_changed",
                "Archive changed during verification. Try again.",
            ) from None
        if _stamp(after) != _stamp(before):
            raise _error(
                "backup_catalog_changed",
                "Archive changed during verification. Try again.",
            )
        return {**summary, "last_verified_at": _now()}

    def _scan(self) -> _Scan:
        entries, directory_stamp = self._entries()
        backups: list[dict[str, Any]] = []
        rejected: list[dict[str, str]] = []
        stamps: dict[str, tuple[int, ...]] = {}
        fingerprint: list[Any] = [directory_stamp]
        for name, value in entries:
            checkpoint()
            backup_id = _BACKUP_NAME.fullmatch(name).group(1)
            stamps[backup_id] = _stamp(value)
            try:
                summary = self._verified(name, value)
            except BackupError as error:
                rejected.append({"id": backup_id, "error_code": error.code})
                fingerprint.append([name, _stamp(value), error.code])
            else:
                backups.append(summary)
                fingerprint.append([name, _stamp(value), summary["archive_sha256"]])
        # A scan is a single directory observation. A concurrently created or
        # replaced candidate invalidates it even when all individual checks pass.
        after_entries, after_directory = self._entries()
        if after_directory != directory_stamp or [
            (name, _stamp(value)) for name, value in after_entries
        ] != [(name, _stamp(value)) for name, value in entries]:
            raise _error(
                "backup_catalog_changed",
                "Backup catalog changed during verification. Try again.",
            )
        backups.sort(
            key=lambda item: (datetime.fromisoformat(item["created_at"]), item["id"]),
            reverse=True,
        )
        encoded = json.dumps(fingerprint, separators=(",", ":"), sort_keys=True)
        return _Scan(
            backups,
            rejected,
            hashlib.sha256(encoded.encode()).hexdigest(),
            stamps,
            directory_stamp,
        )

    def list_backups(
        self, limit: int = 50, *, application_id: str | None = None
    ) -> dict[str, Any]:
        limit = bounded_integer(limit, "limit", 100)
        with catalog_lock(self._lock):
            scan = self._scan()
            eligible = [
                item
                for item in scan.backups
                if application_id is None or item["application_id"] == application_id
            ]
            return {
                "backups": eligible[:limit],
                "count": len(eligible[:limit]),
                "verified_count": len(eligible),
                "rejected_count": len(scan.rejected),
                "rejected": scan.rejected[:limit],
                "limit": limit,
                "destination": str(self.destination),
                "destination_kind": "local",
                "retention_keep": self.retention_keep,
                "status": "ready"
                if scan.directory_stamp is not None
                else "destination_missing",
                "guidance": GUIDANCE,
            }

    def verify(
        self, backup_id: str, *, application_id: str | None = None
    ) -> dict[str, Any]:
        backup_id = validate_backup_id(backup_id)
        with catalog_lock(self._lock):
            self._directory()
            name = f"backup-{backup_id}.zip"
            try:
                before = (self.destination / name).lstat()
            except FileNotFoundError:
                raise _error(
                    "backup_missing",
                    "Backup is absent from the configured destination.",
                ) from None
            except OSError:
                raise _error(
                    "backup_destination", "Backup cannot be inspected."
                ) from None
            summary = self._verified(name, before)
            if (
                application_id is not None
                and summary["application_id"] != application_id
            ):
                raise _error(
                    "backup_identity", "Backup belongs to a different application."
                )
            return summary

    def retention_preview(
        self, max_delete: int = 100, *, application_id: str
    ) -> dict[str, Any]:
        max_delete = bounded_integer(max_delete, "max_delete", 100)
        if not isinstance(application_id, str) or not application_id:
            raise _error(
                "backup_identity_missing",
                "Retention requires a host-issued application identity.",
            )
        with catalog_lock(self._lock):
            scan = self._scan()
            eligible = [
                item
                for item in scan.backups
                if item["application_id"] == application_id
            ]
            delete = list(reversed(eligible[self.retention_keep :]))[:max_delete]
            self._plans = {
                key: plan
                for key, plan in self._plans.items()
                if plan.expires > time.monotonic()
            }
            if len(self._plans) >= 10:
                self._plans.pop(next(iter(self._plans)))
            token = secrets.token_hex(32)
            self._plans[token] = _Plan(
                application_id,
                scan.fingerprint,
                delete,
                time.monotonic() + PLAN_LIFETIME_SECONDS,
            )
            return {
                "plan_token": token,
                "expires_at": (
                    datetime.now(UTC) + timedelta(seconds=PLAN_LIFETIME_SECONDS)
                )
                .isoformat()
                .replace("+00:00", "Z"),
                "retention_keep": self.retention_keep,
                "eligible_count": len(eligible),
                "delete_count": len(delete),
                "delete": delete,
                "remaining_count": len(eligible) - len(delete),
                "max_delete": max_delete,
                "preserved_rejected_count": len(scan.rejected),
            }

    def apply_retention(
        self, plan_token: str, *, application_id: str
    ) -> dict[str, Any]:
        if not isinstance(plan_token, str) or not _PLAN_TOKEN.fullmatch(plan_token):
            raise _error(
                "backup_validation", "plan_token must be a retention preview token."
            )
        with catalog_lock(self._lock):
            plan = self._plans.pop(plan_token, None)
            if plan is None or plan.expires <= time.monotonic():
                raise _error(
                    "backup_retention_stale",
                    "Retention preview expired or was already used. Preview again.",
                )
            if plan.application_id != application_id:
                raise _error(
                    "backup_identity",
                    "Retention preview belongs to a different application.",
                )
            scan = self._scan()
            if scan.fingerprint != plan.fingerprint:
                raise _error(
                    "backup_retention_stale",
                    "Backup catalog changed. Preview retention again.",
                )
            if not plan.delete:
                return {"deleted_ids": [], "deleted_count": 0}
            checkpoint()
            return self._delete_verified(plan, scan)

    def _delete_verified(self, plan: _Plan, scan: _Scan) -> dict[str, Any]:
        """Move candidates into a private staging directory and recheck before unlink."""
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            directory_fd = os.open(self.destination, flags)
        except OSError:
            raise _error(
                "backup_retention_failed", "Backup destination cannot be opened safely."
            ) from None
        staging_name = f".backup-retention-{secrets.token_hex(16)}"
        staging_fd: int | None = None
        moved: list[str] = []
        deleted: list[str] = []
        staged_stamps: dict[str, tuple[int, ...]] = {}
        try:
            opened = os.fstat(directory_fd)
            if (opened.st_dev, opened.st_ino) != scan.directory_stamp:
                raise _error(
                    "backup_retention_stale",
                    "Backup destination changed. Preview retention again.",
                )
            os.mkdir(staging_name, mode=0o700, dir_fd=directory_fd)
            staging_fd = os.open(staging_name, flags, dir_fd=directory_fd)
            for item in plan.delete:
                checkpoint()
                name = f"backup-{item['id']}.zip"
                value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if _stamp(value) != scan.stamps[item["id"]]:
                    raise _error(
                        "backup_retention_stale",
                        "Backup changed. Preview retention again.",
                    )
                os.rename(name, name, src_dir_fd=directory_fd, dst_dir_fd=staging_fd)
                moved.append(name)
                before_verify = os.stat(name, dir_fd=staging_fd, follow_symlinks=False)
                staged = self.destination / staging_name / name
                verified = verify_backup(staged).summary()
                current = os.stat(name, dir_fd=staging_fd, follow_symlinks=False)
                if (
                    not _protected(current, directory=False)
                    or _stamp(current) != _stamp(before_verify)
                    or verified["id"] != item["id"]
                    or verified["application_id"] != plan.application_id
                    or verified["archive_sha256"] != item["archive_sha256"]
                ):
                    raise _error(
                        "backup_retention_stale",
                        "Backup changed. Preview retention again.",
                    )
                staged_stamps[name] = _stamp(current)
            # All staged archives passed the same verification as the preview.
            # Unknown entries and rejected archives are never moved or removed.
            checkpoint()
            # Commit the verified deletion set without cancellation between unlinks.
            with operation_scope(None):
                for name in moved[:]:
                    current = os.stat(name, dir_fd=staging_fd, follow_symlinks=False)
                    if _stamp(current) != staged_stamps[name]:
                        raise _error(
                            "backup_retention_stale",
                            "Backup changed after verification. Preview retention again.",
                        )
                    os.unlink(name, dir_fd=staging_fd)
                    moved.remove(name)
                    deleted.append(_BACKUP_NAME.fullmatch(name).group(1))
        except (OSError, BackupError, OperationStopped) as error:
            recovery_failed = False
            for name in moved[:]:
                try:
                    # link is exclusive: an externally created replacement at
                    # the original name is preserved rather than overwritten.
                    os.link(
                        name,
                        name,
                        src_dir_fd=staging_fd,
                        dst_dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    os.unlink(name, dir_fd=staging_fd)
                    moved.remove(name)
                except OSError:
                    recovery_failed = True
            if recovery_failed:
                raise _error(
                    "backup_retention_recovery",
                    "Retention stopped. Preserved archives remain in a protected .backup-retention directory for operator recovery.",
                ) from None
            if isinstance(error, (BackupError, OperationStopped)):
                raise
            raise _error(
                "backup_retention_failed",
                "Retention stopped because the destination changed or could not be updated.",
            ) from None
        finally:
            if staging_fd is not None:
                os.close(staging_fd)
                if not moved:
                    try:
                        os.rmdir(staging_name, dir_fd=directory_fd)
                    except OSError:
                        # Preserve a changed staging directory rather than
                        # recursively deleting an unexpected entry inside it.
                        pass
            os.close(directory_fd)
        return {"deleted_ids": deleted, "deleted_count": len(deleted)}


Catalog = BackupCatalog

__all__ = [
    "GUIDANCE",
    "BackupCatalog",
    "Catalog",
    "bounded_integer",
    "validate_backup_id",
]
