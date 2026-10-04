"""Source interpreter precision and restore-time compatibility regressions.

The stopped inventory and recovery guard are mock public contexts. These tests
exercise archive validation/restore admission, without invoking Core or uv.
"""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from toolframe_backup import archive, environments
from toolframe_backup.archive import BackupError

OPERATOR_VERSION = "3.14.7"
ENVIRONMENT_ID = "e" * 64


@pytest.fixture
def operator_version(monkeypatch):
    monkeypatch.setattr(
        environments.platform, "python_version", lambda: OPERATOR_VERSION
    )


def _configure(
    inventory, *, source="3.14", requirement=">=3.14", markers=None, wheels=()
):
    lock = (
        'lock-version = "1.0"\ncreated-by = "uv"\n'
        f"requires-python = {json.dumps(requirement)}\n"
    )
    if markers is not None:
        lock += f"environments = {json.dumps(markers)}\n"
    if not wheels:
        lock += "packages = []\n"
    groups = {}
    for filename, distribution in wheels:
        groups.setdefault(distribution, []).append(filename)
    for distribution, names in groups.items():
        records = ",".join(
            f'{{name = "{name}", url = "https://wheels.invalid/{name}", hashes = {{sha256 = "{"a" * 64}"}}}}'
            for name in names
        )
        lock += (
            f'\n[[packages]]\nname = "{distribution}"\nversion = "1.0"\n'
            f"wheels = [{records}]\n"
        )
    public = {
        **inventory.as_dict()["environment_locks"][0],
        "python_version": source,
        "requires_python": requirement,
        "sha256": hashlib.sha256(lock.encode()).hexdigest(),
    }
    inventory.as_dict()["environment_locks"] = [public]
    inventory.environment_locks = (SimpleNamespace(**public, lock=lock),)
    inventory.as_dict()["dependency_wheels"] = [
        {
            "environment_id": ENVIRONMENT_ID,
            "distribution": distribution,
            "version": "1.0",
            "filename": filename,
            "sha256": "a" * 64,
            "path": None,
        }
        for filename, distribution in wheels
    ]
    return public


def _restore_refused_before_staging(path, destination, monkeypatch, *, codes=None):
    def premature_staging(*args, **kwargs):
        pytest.fail("Incompatible environment reached restore staging")

    monkeypatch.setattr(archive.tempfile, "mkdtemp", premature_staging)
    with pytest.raises(BackupError) as caught:
        archive.restore_backup(path, destination)
    assert caught.value.code in (codes or {"incompatible_environment"})
    assert not destination.exists()
    assert not list(destination.parent.glob(".backup-restore-*"))


@pytest.mark.parametrize("source", ["3.14", OPERATOR_VERSION])
def test_short_source_and_matching_full_source_restore_on_actual_operator(
    inventory,
    backup_factory,
    tmp_path,
    operator_version,
    source,
):
    _configure(inventory, source=source)
    path = backup_factory()
    result = archive.restore_backup(path, tmp_path / "recovery")
    assert result["ready"] is True
    assert result["rehydrated_environments"] == 1


def test_short_source_preserves_unknown_patch_in_public_manifest(
    inventory,
    backup_factory,
    operator_version,
):
    _configure(inventory, source="3.14")
    path = backup_factory()
    source = archive.verify_backup(path).manifest["inventory"]["environment_locks"][0]
    assert source["python_version"] == "3.14"
    assert "lock" not in source
    assert inventory.environment_locks[0].python_version == "3.14"


@pytest.mark.parametrize("source", ["3.14.6", "3.14.8"])
def test_full_source_requires_its_exact_patch_before_restore_staging(
    inventory,
    backup_factory,
    tmp_path,
    monkeypatch,
    operator_version,
    source,
):
    _configure(inventory, source=source)
    path = backup_factory()
    _restore_refused_before_staging(path, tmp_path / "recovery", monkeypatch)


def test_short_source_still_requires_matching_major_and_minor(
    inventory,
    backup_factory,
    tmp_path,
    monkeypatch,
    operator_version,
):
    _configure(inventory, source="3.13", requirement=">=3.0")
    path = backup_factory()
    _restore_refused_before_staging(path, tmp_path / "recovery", monkeypatch)


@pytest.mark.parametrize(
    "source", ["3", "3.14.7.0", "three.14", "3.14.7rc1", "3.14.7+local"]
)
def test_source_version_must_have_exactly_two_or_three_numeric_parts(
    inventory,
    backup_factory,
    tmp_path,
    operator_version,
    source,
):
    _configure(inventory, source=source)
    directory = tmp_path / "bad-source"
    with pytest.raises(BackupError) as caught:
        backup_factory(directory)
    assert caught.value.code in {"invalid_environment_lock", "invalid_metadata"}
    assert not list(directory.glob("backup-*.zip"))


def test_short_source_requirement_uses_actual_full_operator_patch(
    inventory,
    backup_factory,
    tmp_path,
    operator_version,
):
    _configure(inventory, source="3.14", requirement=">=3.14.7")
    path = backup_factory()
    assert archive.restore_backup(path, tmp_path / "recovery")["ready"] is True


def test_short_source_cannot_hide_an_unsatisfied_operator_patch_requirement(
    inventory,
    backup_factory,
    tmp_path,
    monkeypatch,
    operator_version,
):
    _configure(inventory, source="3.14", requirement=">=3.14.8")
    path = backup_factory()
    _restore_refused_before_staging(path, tmp_path / "recovery", monkeypatch)


def test_environment_marker_evaluates_actual_full_operator_version(
    inventory,
    backup_factory,
    tmp_path,
    operator_version,
):
    _configure(
        inventory,
        source="3.14",
        markers=["python_full_version == '0.0'", "python_full_version == '3.14.7'"],
    )
    path = backup_factory()
    assert archive.restore_backup(path, tmp_path / "recovery")["ready"] is True


def test_nonmatching_environment_marker_refuses_before_restore_staging(
    inventory,
    backup_factory,
    tmp_path,
    monkeypatch,
    operator_version,
):
    _configure(inventory, source="3.14", markers=["python_full_version >= '3.14.8'"])
    path = backup_factory()
    _restore_refused_before_staging(path, tmp_path / "recovery", monkeypatch)


def test_invalid_environment_marker_refuses_without_publishing_an_archive(
    inventory,
    backup_factory,
    tmp_path,
    operator_version,
):
    _configure(inventory, markers=["python_full_version >>> '3.14'"])
    directory = tmp_path / "invalid-marker"
    with pytest.raises(BackupError) as caught:
        backup_factory(directory)
    assert caught.value.code in {"invalid_environment_lock", "incompatible_environment"}
    assert not list(directory.glob("backup-*.zip"))


def test_incompatible_wheel_tag_refuses_before_restore_staging(
    inventory,
    backup_factory,
    tmp_path,
    monkeypatch,
    operator_version,
):
    _configure(
        inventory,
        wheels=[("recovery_probe-1.0-cp27-cp27m-win32.whl", "recovery-probe")],
    )
    path = backup_factory()
    _restore_refused_before_staging(path, tmp_path / "recovery", monkeypatch)


def test_one_compatible_wheel_choice_for_a_distribution_is_sufficient(
    inventory,
    backup_factory,
    tmp_path,
    operator_version,
):
    _configure(
        inventory,
        wheels=[
            ("recovery_probe-1.0-cp27-cp27m-win32.whl", "recovery-probe"),
            ("recovery_probe-1.0-py3-none-any.whl", "recovery-probe"),
        ],
    )
    path = backup_factory()
    assert archive.restore_backup(path, tmp_path / "recovery")["ready"] is True


def test_every_distribution_needs_its_own_compatible_wheel_choice(
    inventory,
    backup_factory,
    tmp_path,
    monkeypatch,
    operator_version,
):
    _configure(
        inventory,
        wheels=[
            ("recovery_probe-1.0-py3-none-any.whl", "recovery-probe"),
            ("other_probe-1.0-cp27-cp27m-win32.whl", "other-probe"),
        ],
    )
    path = backup_factory()
    _restore_refused_before_staging(path, tmp_path / "recovery", monkeypatch)
