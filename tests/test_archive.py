from __future__ import annotations

import hashlib
import json
import sqlite3
import stat
import zipfile
from contextlib import contextmanager

import pytest

from toolframe_backup import archive


def contents(home):
    return {
        path.relative_to(home).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in home.rglob("*")
        if path.is_file()
    }


def test_stopped_mock_inventory_roundtrip_preserves_source_and_secrets(
    backup_factory, source_home, tmp_path
):
    before = contents(source_home)
    path = backup_factory()
    result = archive.verify_backup(path)
    assert contents(source_home) == before
    assert result.manifest["inventory"]["application_id"] == "app-recovery-test"
    assert result.manifest["inventory"]["dependency_wheels"][0]["path"] is None
    assert len(result.manifest["inventory"]["environment_locks"][0]["sha256"]) == 64
    assert "PRIVATE-RECOVERY" not in json.dumps(result.manifest)
    assert "secret:password" not in json.dumps(result.manifest)
    restored = tmp_path / "recovery"
    summary = archive.restore_backup(path, restored)
    assert summary["application_id"] == "app-recovery-test"
    assert (
        restored / ".toolframe/keys/auth/signing"
    ).read_bytes() == b"PRIVATE-RECOVERY-KEY-DO-NOT-PRINT"
    with sqlite3.connect(
        restored / ".toolframe/state/storage-sqlite/notes/data.sqlite"
    ) as db:
        assert db.execute("SELECT label FROM notes").fetchone() == (
            "preserve this row",
        )
    for file in source_home.rglob("*"):
        if file.is_file() and not file.name.endswith(".sqlite"):
            assert (
                restored / file.relative_to(source_home)
            ).read_bytes() == file.read_bytes()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(restored.stat().st_mode) == 0o700
    for file in restored.rglob("*"):
        assert stat.S_IMODE(file.stat().st_mode) == (0o700 if file.is_dir() else 0o600)


def test_context_remains_held_for_all_reads_and_verification(
    inventory, tmp_path, monkeypatch
):
    held = False

    @contextmanager
    def stopped(home):
        nonlocal held
        held = True
        try:
            yield inventory
        finally:
            held = False

    copy, verify = archive._copy_inventory, archive.verify_backup

    def copying(*args, **kwargs):
        assert held
        return copy(*args, **kwargs)

    def verifying(*args, **kwargs):
        assert held
        return verify(*args, **kwargs)

    monkeypatch.setattr(archive, "_stopped_application", stopped)
    monkeypatch.setattr(archive, "_copy_inventory", copying)
    monkeypatch.setattr(archive, "verify_backup", verifying)
    archive.create_backup(inventory.home, tmp_path / "backups")
    assert not held


def test_failed_create_leaves_source_and_no_final_archive(
    backup_factory, source_home, tmp_path, monkeypatch
):
    before = contents(source_home)

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(zipfile.ZipFile, "write", interrupted)
    with pytest.raises(KeyboardInterrupt):
        backup_factory()
    assert contents(source_home) == before
    assert list((tmp_path / "backups").iterdir()) == []


def test_create_rejects_home_output_before_reading(source_home):
    with pytest.raises(archive.BackupError, match="outside"):
        archive.create_backup(source_home, source_home / "backups")
    assert not (source_home / "backups").exists()


def test_source_hash_mismatch_fails_without_publication(
    backup_factory, source_home, tmp_path
):
    (source_home / "toolframe.toml").write_bytes(b"modified after inventory")
    before = contents(source_home)
    with pytest.raises(archive.BackupError) as error:
        backup_factory()
    assert error.value.code == "source_changed"
    assert contents(source_home) == before
    assert list((tmp_path / "backups").iterdir()) == []


def test_core_refusal_is_safe_and_leaves_no_archive(source_home, tmp_path, monkeypatch):
    @contextmanager
    def stopped(home):
        raise RuntimeError("credential-secret-core-diagnostic")
        yield

    monkeypatch.setattr(archive, "_stopped_application", stopped)
    with pytest.raises(archive.BackupError) as error:
        archive.create_backup(source_home, tmp_path / "backups")
    assert error.value.code == "maintenance_refused"
    assert "credential-secret" not in str(error.value)
    assert list((tmp_path / "backups").iterdir()) == []


def test_core_owned_journal_and_key_metadata_allow_null_owners(
    backup_factory, inventory
):
    inventory.as_dict()["stores"][0]["owner"] = None
    inventory.as_dict()["retained_keys"][0]["owner"] = None
    result = archive.verify_backup(backup_factory())
    assert result.manifest["inventory"]["stores"][0]["owner"] is None
    assert result.manifest["inventory"]["retained_keys"][0]["owner"] is None
