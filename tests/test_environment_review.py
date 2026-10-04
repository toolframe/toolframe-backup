"""Regressions for reviewed interpreter, wheel identity and path boundaries."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import zipfile
from types import SimpleNamespace

import pytest
from test_environments import write_probe_wheel

from toolframe_backup import archive, environments
from toolframe_backup.archive import BackupError


def _source_hashes(home):
    return {
        path.relative_to(home).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in home.rglob("*")
        if path.is_file()
    }


def _no_staging(monkeypatch):
    def stage(*args, **kwargs):
        pytest.fail("Restore reached staging before rejecting unsupported input")

    monkeypatch.setattr(archive.tempfile, "mkdtemp", stage)


def test_full_recorded_version_refuses_matching_release_prerelease_operator(
    inventory,
    backup_factory,
    tmp_path,
    monkeypatch,
):
    lock = 'lock-version = "1.0"\ncreated-by = "uv"\nrequires-python = ">=3.14.0rc1"\npackages = []\n'
    public = {
        **inventory.as_dict()["environment_locks"][0],
        "python_version": "3.14.7",
        "requires_python": ">=3.14.0rc1",
        "sha256": hashlib.sha256(lock.encode()).hexdigest(),
    }
    inventory.as_dict()["environment_locks"] = [public]
    inventory.environment_locks = (SimpleNamespace(**public, lock=lock),)
    path = backup_factory()
    monkeypatch.setattr(environments.platform, "python_version", lambda: "3.14.7rc1")
    _no_staging(monkeypatch)
    destination = tmp_path / "recovery"
    with pytest.raises(BackupError) as caught:
        archive.restore_backup(path, destination)
    assert caught.value.code == "incompatible_environment"
    assert not destination.exists()


INVALID_DEPENDENCIES = [
    {"filename": "other_dependency-1.0-py3-none-any.whl"},
    {"filename": "dependency-2.0-py3-none-any.whl"},
    {"filename": "malformed.whl"},
    {"version": "not-a-version"},
]


@pytest.mark.parametrize("change", INVALID_DEPENDENCIES)
def test_public_dependency_identity_refused_before_archive_publication(
    inventory,
    backup_factory,
    tmp_path,
    change,
):
    inventory.as_dict()["dependency_wheels"][0].update(change)
    source_hashes = _source_hashes(inventory.home)
    destination = tmp_path / "invalid-wheel-metadata"
    with pytest.raises(BackupError) as caught:
        backup_factory(destination)
    assert caught.value.code == "invalid_archive"
    assert not list(destination.glob("backup-*.zip"))
    assert not list(destination.glob("*.partial"))
    assert _source_hashes(inventory.home) == source_hashes


@pytest.mark.parametrize("change", INVALID_DEPENDENCIES)
def test_public_dependency_identity_refused_by_archive_verification(
    backup_factory,
    change,
):
    path = backup_factory()
    with zipfile.ZipFile(path) as source:
        members = [
            (copy.copy(member), source.read(member)) for member in source.infolist()
        ]
    malformed = path.with_name("invalid-wheel-metadata.zip")
    with zipfile.ZipFile(malformed, "w") as output:
        for member, data in members:
            if member.filename == archive.MANIFEST:
                manifest = json.loads(data)
                manifest["inventory"]["dependency_wheels"][0].update(change)
                data = json.dumps(manifest).encode()
            output.writestr(member, data)
    malformed.chmod(0o600)
    with pytest.raises(BackupError) as caught:
        archive.verify_backup(malformed)
    assert caught.value.code == "invalid_archive"


def test_public_dependency_identity_accepts_normalized_name_and_version(
    inventory,
    backup_factory,
):
    inventory.as_dict()["dependency_wheels"][0].update(
        {
            "distribution": "Dependency_Probe",
            "version": "1.0.0",
            "filename": "dependency_probe-1.0-py3-none-any.whl",
        }
    )
    assert archive.verify_backup(backup_factory()).summary()["verified"] is True


@pytest.mark.parametrize(
    "name",
    [
        'recovery"quoted',
        "recovery'quoted",
        "recovery\\slash",
        "recovery\nline",
        "recovery\ttab",
    ],
)
def test_unsupported_destination_characters_refused_before_staging(
    inventory,
    backup_factory,
    tmp_path,
    monkeypatch,
    name,
):
    path = backup_factory()
    source_hashes = _source_hashes(inventory.home)
    archive_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    _no_staging(monkeypatch)
    destination = tmp_path / name
    with pytest.raises(BackupError) as caught:
        archive.restore_backup(path, destination)
    assert caught.value.code == "unsupported_destination"
    assert not destination.exists()
    assert not list(tmp_path.glob(".backup-restore-*"))
    assert hashlib.sha256(path.read_bytes()).hexdigest() == archive_hash
    assert _source_hashes(inventory.home) == source_hashes


def test_real_uv_file_url_restore_accepts_spaces_in_final_home(
    inventory,
    backup_factory,
    tmp_path,
    monkeypatch,
):
    uv_path = shutil.which("uv")
    if uv_path is None:
        pytest.skip("Real file URL reconstruction requires local uv.")
    filename = "recovery_probe-1.0-py3-none-any.whl"
    relative = f".toolframe/artifacts/{filename}"
    wheel = inventory.home / relative
    write_probe_wheel(wheel)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    inventory.as_dict()["files"].append(
        {
            "path": relative,
            "role": "artifact",
            "size": wheel.stat().st_size,
            "mode": 0o600,
            "sha256": digest,
        }
    )
    lock = (
        'lock-version = "1.0"\ncreated-by = "uv"\nrequires-python = ">=3.14"\n'
        '[[packages]]\nname = "recovery-probe"\nversion = "1.0"\n'
        f'wheels = [{{url = "file://${{TOOLFRAME_HOME}}/{relative}", hashes = {{sha256 = "{digest}"}}}}]\n'
    )
    public = {
        **inventory.as_dict()["environment_locks"][0],
        "requires_python": ">=3.14",
        "sha256": hashlib.sha256(lock.encode()).hexdigest(),
    }
    inventory.as_dict()["environment_locks"] = [public]
    inventory.environment_locks = (SimpleNamespace(**public, lock=lock),)
    inventory.as_dict()["dependency_wheels"] = [
        {
            "environment_id": public["environment_id"],
            "distribution": "recovery-probe",
            "version": "1.0",
            "filename": filename,
            "sha256": digest,
            "path": relative,
        }
    ]
    source_hashes = _source_hashes(inventory.home)
    path = backup_factory()
    archive_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    destination = tmp_path / "recovery home with spaces"
    monkeypatch.setattr(archive, "_rehydrate_environments", environments.rehydrate)
    result = archive.restore_backup(path, destination, uv_path=uv_path, offline=True)
    assert result["ready"] is True
    assert result["rehydrated_environments"] == 1
    target = destination / ".toolframe" / "environments" / public["environment_id"]
    executable = target / "bin" / "recovery-probe"
    script = executable.read_text()
    assert script.startswith("#!")
    assert str(target / "bin" / "python") in script
    assert ".backup-restore-" not in script
    assert "${TOOLFRAME_HOME}" not in (target / "pylock.toml").read_text()
    command = subprocess.run(
        [str(executable)], check=True, capture_output=True, text=True
    )
    assert command.stdout.strip() == "RECOVERY_READY"
    assert (target / ".ready").read_text() == public["environment_id"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == archive_hash
    assert _source_hashes(inventory.home) == source_hashes
