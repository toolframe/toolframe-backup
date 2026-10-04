"""File URI encoding and filesystem path expansion in fresh recovery homes."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_environments import write_probe_wheel

from toolframe_backup import archive, environments

FILENAME = "recovery_probe-1.0-py3-none-any.whl"
ARTIFACT = f".toolframe/artifacts/{FILENAME}"
TOKEN = "${TOOLFRAME_HOME}"
HOMES = [
    "ordinary-recovery",
    "recovery#home",
    "recovery?home",
    "recovery%home",
    "還原資料",
    "recovery home with spaces",
]


def _lock(digest, kind, *, syntax="basic", preserve_note=False):
    locator = (
        f"file://{TOKEN}/{ARTIFACT}" if kind == "file_url" else f"{TOKEN}/{ARTIFACT}"
    )
    if syntax == "literal":
        value = f"'{locator}'"
    elif syntax == "escaped_basic":
        value = '"' + locator.replace("$", r"\u0024") + '"'
    else:
        value = f'"{locator}"'
    key = "url" if kind == "file_url" else "path"
    record = f'{{{key} = {value}, hashes = {{sha256 = "{digest}"}}}}'
    raw = 'lock-version = "1.0"\ncreated-by = "uv"\nrequires-python = ">=3.14"\n'
    if preserve_note:
        raw += f"# retain the unrelated {TOKEN} comment\n[tool.backup_probe]\nnote = '{TOKEN}'\n"
    raw += '[[packages]]\nname = "recovery-probe"\nversion = "1.0"\n'
    raw += f"wheels = [{record}]\n" if kind == "file_url" else f"archive = {record}\n"
    return raw


def _configure(inventory, lock, digest):
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
            "filename": FILENAME,
            "sha256": digest,
            "path": ARTIFACT,
        }
    ]
    return public


def _hashes(home):
    return {
        path.relative_to(home).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in home.rglob("*")
        if path.is_file()
    }


def _locator(parsed, kind):
    package = parsed["packages"][0]
    return (
        package["wheels"][0]["url"]
        if kind == "file_url"
        else package["archive"]["path"]
    )


@pytest.mark.parametrize("name", HOMES)
@pytest.mark.parametrize("kind", ["file_url", "archive_path"])
def test_real_uv_offline_restore_encodes_uri_but_preserves_filesystem_path(
    inventory,
    backup_factory,
    tmp_path,
    monkeypatch,
    name,
    kind,
):
    uv_path = shutil.which("uv")
    if uv_path is None:
        pytest.skip("Real URI/path recovery requires local uv.")
    wheel = inventory.home / ARTIFACT
    write_probe_wheel(wheel)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    inventory.as_dict()["files"].append(
        {
            "path": ARTIFACT,
            "role": "artifact",
            "size": wheel.stat().st_size,
            "mode": 0o600,
            "sha256": digest,
        }
    )
    raw_lock = _lock(digest, kind)
    public = _configure(inventory, raw_lock, digest)
    source_hashes = _hashes(inventory.home)
    path = backup_factory()
    archive_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    destination = tmp_path / name
    monkeypatch.setattr(archive, "_rehydrate_environments", environments.rehydrate)
    result = archive.restore_backup(path, destination, uv_path=uv_path, offline=True)
    assert result["ready"] is True
    assert result["rehydrated_environments"] == 1
    target = destination / ".toolframe" / "environments" / public["environment_id"]
    lockfile = target / "pylock.toml"
    reconstructed = tomllib.loads(lockfile.read_text())
    expected_wheel = destination / ARTIFACT
    expected = expected_wheel.as_uri() if kind == "file_url" else str(expected_wheel)
    assert _locator(reconstructed, kind) == expected
    assert TOKEN not in lockfile.read_text()
    assert ".backup-restore-" not in lockfile.read_text()
    executable = target / "bin" / "recovery-probe"
    script = executable.read_text()
    assert script.startswith("#!")
    assert str(target / "bin" / "python") in script
    assert ".backup-restore-" not in script
    command = subprocess.run(
        [str(executable)], check=True, capture_output=True, text=True
    )
    assert command.stdout.strip() == "RECOVERY_READY"
    assert (target / ".ready").read_text() == public["environment_id"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == archive_hash
    assert _hashes(inventory.home) == source_hashes
    assert inventory.environment_locks[0].lock == raw_lock


@pytest.mark.parametrize("syntax", ["escaped_basic", "literal"])
@pytest.mark.parametrize("kind", ["file_url", "archive_path"])
def test_parsed_locator_expansion_handles_toml_string_forms_without_rewriting_notes(
    tmp_path,
    monkeypatch,
    syntax,
    kind,
):
    home = tmp_path / "recovery #?% Unicode 還原"
    identifier = "e" * 64
    raw = _lock("a" * 64, kind, syntax=syntax, preserve_note=True)
    content = [
        {
            "candidate_id": "candidate",
            "purpose": "backend",
            "environment_id": identifier,
            "lock": raw,
        }
    ]
    monkeypatch.setattr(environments.shutil, "which", lambda value: "/mock/uv")

    def mock_uv(command, **kwargs):
        if "venv" in command:
            (Path(command[-1]) / "bin").mkdir(parents=True)
        else:
            # A parser failure here represents the real sync admission failure.
            tomllib.loads(Path(command[-1]).read_text())

    monkeypatch.setattr(environments, "_run", mock_uv)
    assert environments.rehydrate(home, content, offline=True) == 1
    lockfile = home / ".toolframe" / "environments" / identifier / "pylock.toml"
    reconstructed = tomllib.loads(lockfile.read_text())
    expected_wheel = home / ARTIFACT
    expected = expected_wheel.as_uri() if kind == "file_url" else str(expected_wheel)
    assert _locator(reconstructed, kind) == expected
    assert reconstructed["tool"]["backup_probe"]["note"] == TOKEN
    assert f"# retain the unrelated {TOKEN} comment" in lockfile.read_text()
    assert content[0]["lock"] == raw
