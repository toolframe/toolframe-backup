"""Direct wheel pylock records, including real offline final-home recovery."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_environments import write_probe_wheel

from toolframe_backup import archive, environments
from toolframe_backup.archive import BackupError

FILENAME = "recovery_probe-1.0-py3-none-any.whl"
RELATIVE_ARTIFACT = f".toolframe/artifacts/{FILENAME}"
ENVIRONMENT_ID = "e" * 64
HASH = "a" * 64


def _toml(value):
    if isinstance(value, dict):
        return (
            "{"
            + ", ".join(f"{key} = {_toml(item)}" for key, item in value.items())
            + "}"
        )
    if isinstance(value, list):
        return "[" + ", ".join(_toml(item) for item in value) + "]"
    return json.dumps(value)


def _lock(record, *, name="recovery-probe", version="1.0"):
    return (
        'lock-version = "1.0"\ncreated-by = "uv"\nrequires-python = ">=3.14"\n'
        f"[[packages]]\nname = {_toml(name)}\nversion = {_toml(version)}\n"
        f"archive = {_toml(record)}\n"
    )


def _configure(inventory, lock):
    public = {
        **inventory.as_dict()["environment_locks"][0],
        "requires_python": ">=3.14",
        "sha256": hashlib.sha256(lock.encode()).hexdigest(),
    }
    inventory.as_dict()["environment_locks"] = [public]
    inventory.environment_locks = (SimpleNamespace(**public, lock=lock),)
    inventory.as_dict()["dependency_wheels"] = []
    return public


def _validate(inventory, lock):
    public = _configure(inventory, lock)
    raw = json.dumps(
        [
            {
                "candidate_id": public["candidate_id"],
                "purpose": public["purpose"],
                "environment_id": public["environment_id"],
                "lock": lock,
            }
        ]
    ).encode()
    return environments.validate(raw, [public])


@pytest.mark.parametrize(
    "record",
    [
        {"path": f"../../artifacts/{FILENAME}", "hashes": {"sha256": HASH}},
        {
            "path": f"${{TOOLFRAME_HOME}}/{RELATIVE_ARTIFACT}",
            "hashes": {"sha256": HASH},
        },
        {"url": f"https://wheels.invalid/{FILENAME}", "hashes": {"sha256": HASH}},
        {
            "url": f"file://${{TOOLFRAME_HOME}}/{RELATIVE_ARTIFACT}",
            "hashes": {"sha256": HASH},
        },
    ],
)
def test_exact_hash_direct_wheel_path_and_url_records_are_accepted(inventory, record):
    lock = _lock(record)
    parsed = _validate(inventory, lock)
    assert parsed[0]["lock"] == lock
    environments.check_compatibility(inventory.as_dict()["environment_locks"], parsed)


@pytest.mark.parametrize(
    "record",
    [
        "not an archive table",
        [{"path": FILENAME, "hashes": {"sha256": HASH}}],
        {"path": FILENAME},
        {"path": FILENAME, "hashes": {}},
        {"path": FILENAME, "hashes": {"sha256": "a" * 63}},
        {"path": FILENAME, "hashes": {"sha256": "A" * 64}},
        {"path": FILENAME, "hashes": {"md5": "a" * 32}},
        {"path": [], "hashes": {"sha256": HASH}},
        {"hashes": {"sha256": HASH}},
        {
            "path": FILENAME,
            "url": f"https://wheels.invalid/{FILENAME}",
            "hashes": {"sha256": HASH},
        },
        {"path": "recovery_probe-1.0.tar.gz", "hashes": {"sha256": HASH}},
        {
            "url": "https://wheels.invalid/recovery_probe-1.0.tar.gz",
            "hashes": {"sha256": HASH},
        },
    ],
)
def test_malformed_unhashed_ambiguous_or_source_archives_are_refused(inventory, record):
    with pytest.raises(BackupError) as caught:
        _validate(inventory, _lock(record))
    assert caught.value.code in {
        "invalid_environment_lock",
        "unsupported_environment_lock",
    }


@pytest.mark.parametrize(
    "filename",
    [
        "other_probe-1.0-py3-none-any.whl",
        "recovery_probe-2.0-py3-none-any.whl",
    ],
)
def test_direct_wheel_filename_must_match_package_name_and_version(inventory, filename):
    with pytest.raises(BackupError) as caught:
        _validate(inventory, _lock({"path": filename, "hashes": {"sha256": HASH}}))
    assert caught.value.code in {
        "invalid_environment_lock",
        "unsupported_environment_lock",
    }


@pytest.mark.parametrize(
    "record",
    [
        {"path": f"/operator/cache/{FILENAME}", "hashes": {"sha256": HASH}},
        {"path": f"../../../../{FILENAME}", "hashes": {"sha256": HASH}},
        {"path": f"${{TOOLFRAME_HOME}}/../{FILENAME}", "hashes": {"sha256": HASH}},
        {"url": f"file:///operator/cache/{FILENAME}", "hashes": {"sha256": HASH}},
    ],
)
def test_nontransplantable_or_escaping_direct_paths_are_refused(inventory, record):
    with pytest.raises(BackupError) as caught:
        _validate(inventory, _lock(record))
    assert caught.value.code in {
        "invalid_environment_lock",
        "unsupported_environment_lock",
        "unsafe_path",
    }


@pytest.mark.parametrize("locator_kind", ["relative", "home_placeholder"])
def test_real_uv_offline_direct_path_restore_resolves_from_final_pylock(
    inventory,
    backup_factory,
    tmp_path,
    monkeypatch,
    locator_kind,
):
    uv_path = shutil.which("uv")
    if uv_path is None:
        pytest.skip("Real direct wheel reconstruction requires local uv.")
    wheel = inventory.home / RELATIVE_ARTIFACT
    write_probe_wheel(wheel)
    wheel_bytes = wheel.read_bytes()
    digest = hashlib.sha256(wheel_bytes).hexdigest()
    inventory.as_dict()["files"].append(
        {
            "path": RELATIVE_ARTIFACT,
            "role": "artifact",
            "size": wheel.stat().st_size,
            "mode": 0o600,
            "sha256": digest,
        }
    )
    locator = (
        f"../../artifacts/{FILENAME}"
        if locator_kind == "relative"
        else f"${{TOOLFRAME_HOME}}/{RELATIVE_ARTIFACT}"
    )
    lock = _lock({"path": locator, "hashes": {"sha256": digest}})
    _configure(inventory, lock)
    inventory.as_dict()["dependency_wheels"] = [
        {
            "environment_id": ENVIRONMENT_ID,
            "distribution": "recovery-probe",
            "version": "1.0",
            "filename": FILENAME,
            "sha256": digest,
            "path": RELATIVE_ARTIFACT,
        }
    ]
    path = backup_factory()
    archive_bytes = path.read_bytes()
    destination = tmp_path / "direct-recovery"
    monkeypatch.setattr(archive, "_rehydrate_environments", environments.rehydrate)
    result = archive.restore_backup(path, destination, uv_path=uv_path, offline=True)
    assert result["ready"] is True
    assert result["rehydrated_environments"] == 1
    target = destination / ".toolframe" / "environments" / ENVIRONMENT_ID
    lockfile = target / "pylock.toml"
    reconstructed = tomllib.loads(lockfile.read_text())
    final_locator = Path(reconstructed["packages"][0]["archive"]["path"])
    resolved = (
        final_locator
        if final_locator.is_absolute()
        else lockfile.parent / final_locator
    )
    assert resolved.resolve() == (destination / RELATIVE_ARTIFACT).resolve()
    assert "${TOOLFRAME_HOME}" not in lockfile.read_text()
    assert str(inventory.home) not in lockfile.read_text()
    assert ".backup-restore-" not in lockfile.read_text()
    assert lockfile.stat().st_mode & 0o777 == 0o600
    executable = target / "bin" / "recovery-probe"
    assert str(target / "bin" / "python") in executable.read_text()
    command = subprocess.run(
        [str(executable)], check=True, capture_output=True, text=True
    )
    assert command.stdout.strip() == "RECOVERY_READY"
    assert (target / ".ready").read_text() == ENVIRONMENT_ID
    assert path.read_bytes() == archive_bytes
    assert wheel.read_bytes() == wheel_bytes
