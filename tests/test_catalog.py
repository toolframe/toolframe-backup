"""Catalog policy tests; fake archives isolate retention from archive-format tests."""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from toolframe_backup import archive, catalog
from toolframe_backup.archive import BackupError
from toolframe_backup.catalog import Catalog


def write_candidate(
    directory: Path,
    number: int,
    *,
    application_id: str = "app-1",
    created_at: str | None = None,
) -> Path:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"backup-{number:032x}.zip"
    data = {
        "id": f"{number:032x}",
        "application_id": application_id,
        "application_name": "Test application",
        "composition_revision": "revision-1",
        "created_at": created_at or f"2026-01-{number:02d}T00:00:00Z",
        "file_count": 1,
        "total_bytes": 16,
        "verified": True,
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(0o600)
    return path


def fake_verify(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "id" in data
    except ValueError, AssertionError:
        raise BackupError("invalid_archive", "Archive is invalid.") from None
    data["archive_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return SimpleNamespace(summary=lambda: data)


@pytest.fixture
def local_catalog(tmp_path, monkeypatch):
    # macOS's temporary directory may contain the /var symlink. The configured
    # destination itself is always a canonical, symlink-free operator path.
    directory = tmp_path.resolve() / "archives"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(catalog, "verify_backup", fake_verify)
    return directory, Catalog(directory, retention_keep=2)


def test_catalog_truth_filter_order_and_current_verification(local_catalog):
    directory, manager = local_catalog
    oldest = write_candidate(directory, 1)
    write_candidate(directory, 2)
    write_candidate(directory, 3, application_id="other-app")
    (directory / "notes.txt").write_text("preserve me")
    listed = manager.list_backups(limit=1, application_id="app-1")
    assert [item["id"] for item in listed["backups"]] == [f"{2:032x}"]
    assert listed["verified_count"] == 2
    assert listed["count"] == 1
    assert listed["backups"][0]["last_verified_at"].endswith("Z")
    oldest.unlink()
    assert manager.list_backups(application_id="app-1")["verified_count"] == 1
    assert (directory / "notes.txt").read_text() == "preserve me"


def test_retention_selects_oldest_bounded_and_preserves_unknown_foreign_corrupt(
    local_catalog,
):
    directory, manager = local_catalog
    paths = [write_candidate(directory, number) for number in range(1, 5)]
    foreign = write_candidate(directory, 5, application_id="other-app")
    corrupt = write_candidate(directory, 6)
    corrupt.write_text("corrupt payload")
    unknown = directory / "important.zip"
    unknown.write_text("unknown")
    plan = manager.retention_preview(1, application_id="app-1")
    assert plan["eligible_count"] == 4
    assert plan["delete_count"] == 1
    assert [item["id"] for item in plan["delete"]] == [f"{1:032x}"]
    assert plan["preserved_rejected_count"] == 1
    assert all(path.exists() for path in paths)  # preview has no filesystem effect
    result = manager.apply_retention(plan["plan_token"], application_id="app-1")
    assert result == {"deleted_ids": [f"{1:032x}"], "deleted_count": 1}
    assert not paths[0].exists()
    assert all(path.exists() for path in paths[1:] + [foreign, corrupt, unknown])
    assert not list(directory.glob(".backup-retention-*"))
    with pytest.raises(BackupError, match="already used"):
        manager.apply_retention(plan["plan_token"], application_id="app-1")


def test_retention_is_chronological_across_timezone_offsets(local_catalog):
    directory, manager = local_catalog
    write_candidate(directory, 1, created_at="2026-01-01T00:00:00Z")
    write_candidate(directory, 2, created_at="2026-01-01T00:30:00+01:00")
    write_candidate(directory, 3, created_at="2026-01-01T01:00:00Z")
    plan = manager.retention_preview(application_id="app-1")
    assert [item["id"] for item in plan["delete"]] == [f"{2:032x}"]


@pytest.mark.parametrize("change", ["new", "modify", "remove"])
def test_changed_catalog_invalidates_preview_without_deletion(local_catalog, change):
    directory, manager = local_catalog
    original = [write_candidate(directory, number) for number in range(1, 4)]
    plan = manager.retention_preview(application_id="app-1")
    if change == "new":
        write_candidate(directory, 4)
    elif change == "modify":
        original[0].write_text("corrupt")
    else:
        original[1].unlink()
    with pytest.raises(BackupError) as error:
        manager.apply_retention(plan["plan_token"], application_id="app-1")
    assert error.value.code == "backup_retention_stale"
    assert original[0].exists()
    assert original[2].exists()


def test_expired_and_wrong_identity_plans_cannot_delete(local_catalog, monkeypatch):
    directory, manager = local_catalog
    paths = [write_candidate(directory, number) for number in range(1, 4)]
    plan = manager.retention_preview(application_id="app-1")
    with pytest.raises(BackupError) as error:
        manager.apply_retention(plan["plan_token"], application_id="other-app")
    assert error.value.code == "backup_identity"
    plan = manager.retention_preview(application_id="app-1")
    original_clock = catalog.time.monotonic
    monkeypatch.setattr(catalog.time, "monotonic", lambda: original_clock() + 601)
    with pytest.raises(BackupError) as error:
        manager.apply_retention(plan["plan_token"], application_id="app-1")
    assert error.value.code == "backup_retention_stale"
    assert all(path.exists() for path in paths)


def test_stage_verification_failure_restores_archive_and_preserves_unknown(
    local_catalog, monkeypatch
):
    directory, manager = local_catalog
    paths = [write_candidate(directory, number) for number in range(1, 4)]
    unknown = directory / "keep.txt"
    unknown.write_text("untouched")
    plan = manager.retention_preview(application_id="app-1")

    def changed_at_staging(path):
        if path.parent.name.startswith(".backup-retention-"):
            path.write_text("changed while staging")
            raise BackupError("checksum_mismatch", "Archive changed.")
        return fake_verify(path)

    monkeypatch.setattr(catalog, "verify_backup", changed_at_staging)
    with pytest.raises(BackupError) as error:
        manager.apply_retention(plan["plan_token"], application_id="app-1")
    assert error.value.code == "checksum_mismatch"
    assert paths[0].read_text() == "changed while staging"
    assert all(path.exists() for path in paths)
    assert unknown.read_text() == "untouched"
    assert not list(directory.glob(".backup-retention-*"))


def test_recovery_preserves_replacement_and_staged_archive(local_catalog, monkeypatch):
    directory, manager = local_catalog
    originals = [write_candidate(directory, number) for number in range(1, 4)]
    original_bytes = originals[0].read_bytes()
    plan = manager.retention_preview(application_id="app-1")

    def replacement_while_staged(path):
        if path.parent.name.startswith(".backup-retention-"):
            originals[0].write_text("external replacement must survive")
            raise BackupError("checksum_mismatch", "Archive changed.")
        return fake_verify(path)

    monkeypatch.setattr(catalog, "verify_backup", replacement_while_staged)
    with pytest.raises(BackupError) as error:
        manager.apply_retention(plan["plan_token"], application_id="app-1")
    assert error.value.code == "backup_retention_recovery"
    assert originals[0].read_text() == "external replacement must survive"
    staged = list(directory.glob(".backup-retention-*"))
    assert len(staged) == 1
    assert staged[0].stat().st_mode & 0o777 == 0o700
    assert (staged[0] / originals[0].name).read_bytes() == original_bytes
    assert originals[1].exists() and originals[2].exists()


def test_change_after_staged_verification_is_preserved(local_catalog, monkeypatch):
    directory, manager = local_catalog
    originals = [write_candidate(directory, number) for number in range(1, 5)]
    plan = manager.retention_preview(application_id="app-1")
    staged_first = None

    def mutate_after_another_verification(path):
        nonlocal staged_first
        verified = fake_verify(path)
        if path.parent.name.startswith(".backup-retention-"):
            if staged_first is None:
                staged_first = path
            else:
                staged_first.write_text("modified after its successful verification")
        return verified

    monkeypatch.setattr(catalog, "verify_backup", mutate_after_another_verification)
    with pytest.raises(BackupError) as error:
        manager.apply_retention(plan["plan_token"], application_id="app-1")
    assert error.value.code == "backup_retention_stale"
    assert originals[0].read_text() == "modified after its successful verification"
    assert all(path.exists() for path in originals)
    assert not list(directory.glob(".backup-retention-*"))


def test_permissions_match_exact_operator_contract(local_catalog):
    directory, manager = local_catalog
    archive_path = write_candidate(directory, 1)
    archive_path.chmod(0o400)
    assert manager.list_backups()["rejected_count"] == 1
    directory.chmod(0o500)
    with pytest.raises(BackupError) as error:
        manager.list_backups()
    assert error.value.code == "backup_permissions"


def test_symlink_candidates_and_broad_archive_permissions_are_preserved(local_catalog):
    directory, manager = local_catalog
    valid = write_candidate(directory, 1)
    broad = write_candidate(directory, 2)
    broad.chmod(0o644)
    linked = directory / f"backup-{3:032x}.zip"
    linked.symlink_to(valid)
    listed = manager.list_backups()
    assert listed["verified_count"] == 1
    assert listed["rejected_count"] == 2
    assert {item["error_code"] for item in listed["rejected"]} == {"backup_permissions"}
    assert linked.is_symlink()
    with pytest.raises(BackupError):
        manager.verify(f"{3:032x}")


def test_directory_symlink_relative_and_permissions_rejected(tmp_path):
    base = tmp_path.resolve()
    destination = base / "safe"
    destination.mkdir(mode=0o700)
    linked = base / "linked"
    linked.symlink_to(destination, target_is_directory=True)
    for value in ("relative/path", base / ".." / "archives", linked, linked / "nested"):
        with pytest.raises(BackupError):
            Catalog(value)
    destination.chmod(0o755)
    with pytest.raises(BackupError) as error:
        Catalog(destination)
    assert error.value.code == "backup_permissions"
    assert destination.stat().st_mode & 0o777 == 0o755


def test_missing_directory_does_not_create_it_and_empty_retention_is_safe(tmp_path):
    directory = tmp_path.resolve() / "not-created"
    manager = Catalog(directory)
    assert manager.list_backups()["status"] == "destination_missing"
    plan = manager.retention_preview(application_id="app-1")
    assert (
        manager.apply_retention(plan["plan_token"], application_id="app-1")[
            "deleted_count"
        ]
        == 0
    )
    assert not directory.exists()


@pytest.mark.parametrize("value", [True, 0, 101, "50"])
def test_runtime_limits_reject_noninteger_and_unbounded_work(local_catalog, value):
    _, manager = local_catalog
    with pytest.raises(BackupError):
        manager.list_backups(value)
    with pytest.raises(BackupError):
        manager.retention_preview(value, application_id="app-1")


def test_ids_identity_and_scan_limits(local_catalog, monkeypatch):
    directory, manager = local_catalog
    for value in (
        "../archive",
        "/tmp/archive",
        "f" * 31,
        "F" * 32,
        "f" * 32 + "\\name",
    ):
        with pytest.raises(BackupError):
            manager.verify(value)
    with pytest.raises(BackupError) as error:
        manager.retention_preview(application_id=None)
    assert error.value.code == "backup_identity_missing"
    for number in range(1, 4):
        write_candidate(directory, number)
    monkeypatch.setattr(catalog, "MAX_CANDIDATES", 2)
    with pytest.raises(BackupError) as error:
        manager.list_backups()
    assert error.value.code == "backup_catalog_limit"
    monkeypatch.setattr(catalog, "MAX_CANDIDATES", 1000)
    monkeypatch.setattr(catalog, "MAX_DIRECTORY_ENTRIES", 2)
    with pytest.raises(BackupError) as error:
        manager.list_backups()
    assert error.value.code == "backup_catalog_limit"
    monkeypatch.setattr(catalog, "MAX_DIRECTORY_ENTRIES", 10_000)
    monkeypatch.setattr(catalog, "MAX_SCAN_BYTES", 1)
    with pytest.raises(BackupError) as error:
        manager.retention_preview(application_id="app-1")
    assert error.value.code == "backup_catalog_limit"


def test_real_archive_catalog_with_mock_stopped_inventory(tmp_path, monkeypatch):
    """Use the real format, while Core inventory ownership is a separate integration check."""
    home = tmp_path.resolve() / "home"
    home.mkdir(mode=0o700)
    payload = home / "settings.json"
    payload.write_text('{"setting":"kept"}')
    metadata = {
        "format_version": 1,
        "status": "STOPPED",
        "application_id": "app-1",
        "application_name": "Recovery app",
        "composition_revision": None,
        "files": [
            {
                "path": "settings.json",
                "role": "state",
                "size": payload.stat().st_size,
                "mode": 0o600,
                "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
            }
        ],
        "stores": [],
        "retained_keys": [],
        "dependency_wheels": [],
        "environment_locks": [],
    }

    @contextmanager
    def stopped(path):
        assert path == home
        yield SimpleNamespace(home=home, as_dict=lambda: metadata)

    monkeypatch.setattr(archive, "_stopped_application", stopped)
    destination = tmp_path.resolve() / "real-archives"
    created = archive.create_backup(home, destination)
    manager = Catalog(destination)
    listed = manager.list_backups(application_id="app-1")
    assert listed["verified_count"] == 1
    assert listed["backups"][0]["id"] == created["id"]
    assert (
        manager.verify(created["id"], application_id="app-1")["archive_sha256"]
        == created["archive_sha256"]
    )
    with pytest.raises(BackupError) as error:
        manager.verify(created["id"], application_id="other-app")
    assert error.value.code == "backup_identity"
