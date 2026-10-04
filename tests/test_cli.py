"""Operator CLI behavior and secret-free output with mock stopped inventory."""

from __future__ import annotations

import builtins
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from toolframe_backup import cli
from toolframe_backup.archive import BackupError

PRIVATE_VALUES = (
    "PRIVATE-RECOVERY-KEY-DO-NOT-PRINT",
    "https://secret:password@internal.invalid/simple",
    "secret:password",
)


def _safe_output(capsys) -> tuple[dict, str]:
    captured = capsys.readouterr()
    for private in PRIVATE_VALUES:
        assert private not in captured.out + captured.err
    return json.loads(captured.out or captured.err), captured.err


def test_create_prints_only_safe_recovery_summary(
    source_home, tmp_path, backup_factory, capsys
):
    # The factory installs only the mock public maintenance context; main itself
    # creates the archive so CLI create errors/output are exercised as well.
    directory = tmp_path / "cli-backups"
    assert (
        cli.main(["create", "--home", str(source_home), "--directory", str(directory)])
        == 0
    )
    result, stderr = _safe_output(capsys)
    assert result["application_id"] == "app-recovery-test"
    assert result["verified"] is True
    assert result["file_count"] > 0
    assert stderr == ""
    assert list(directory.glob("backup-*.zip"))
    assert "inventory" not in result


@pytest.mark.parametrize("command", ["verify", "restore", "list"])
def test_read_restore_and_list_print_no_payload_or_credentials(
    backup_factory, tmp_path, capsys, command
):
    path = backup_factory()
    if command == "verify":
        arguments = ["verify", str(path)]
    elif command == "restore":
        arguments = ["restore", str(path), "--destination", str(tmp_path / "restored")]
    else:
        arguments = ["list", "--directory", str(path.parent), "--limit", "1"]
    assert cli.main(arguments) == 0
    result, stderr = _safe_output(capsys)
    assert stderr == ""
    if command == "list":
        assert result["count"] == 1
        assert result["backups"][0]["verified"] is True
    else:
        assert result["verified"] is True
    assert "inventory" not in result


def test_verify_restore_and_list_do_not_import_core_or_runtime(
    backup_factory, tmp_path, monkeypatch, capsys
):
    path = backup_factory()
    original_import = builtins.__import__

    def isolated_import(name, *args, **kwargs):
        if name.partition(".")[0] in {"toolframe_core", "toolframe_sdk", "streamlit"}:
            pytest.fail(f"Offline archive operation imported {name}")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", isolated_import)
    for arguments in (
        ["verify", str(path)],
        ["restore", str(path), "--destination", str(tmp_path / "offline-recovery")],
        ["list", "--directory", str(path.parent)],
    ):
        assert cli.main(arguments) == 0
        _safe_output(capsys)


def test_cli_module_is_usable_in_a_fresh_process(backup_factory):
    path = backup_factory()
    environment = {
        **os.environ,
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
    }
    result = subprocess.run(
        [sys.executable, "-m", "toolframe_backup.cli", "verify", str(path)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["verified"] is True
    assert result.stderr == ""
    for private in PRIVATE_VALUES:
        assert private not in result.stdout


def test_invalid_archive_returns_safe_error_without_traceback(tmp_path, capsys):
    path = tmp_path / "bad.zip"
    path.write_bytes(b"PRIVATE-RECOVERY-KEY-DO-NOT-PRINT is not a zip file")
    assert cli.main(["verify", str(path)]) == 2
    result, stderr = _safe_output(capsys)
    assert result["error"] == "invalid_archive"
    assert "Traceback" not in stderr


def test_restore_refusal_preserves_existing_home(backup_factory, tmp_path, capsys):
    path = backup_factory()
    destination = tmp_path / "existing"
    destination.mkdir(mode=0o700)
    sentinel = destination / "keep"
    sentinel.write_bytes(b"existing application data")
    assert cli.main(["restore", str(path), "--destination", str(destination)]) == 2
    result, _ = _safe_output(capsys)
    assert result["error"] == "destination_exists"
    assert sentinel.read_bytes() == b"existing application data"


@pytest.mark.parametrize("limit", ["0", "101", "-1"])
def test_list_rejects_unbounded_limits(backup_factory, capsys, limit):
    path = backup_factory()
    assert cli.main(["list", "--directory", str(path.parent), "--limit", limit]) == 2
    result, _ = _safe_output(capsys)
    assert result["error"] == "backup_validation"


def test_interruption_has_distinct_exit_status_and_safe_output(monkeypatch, capsys):
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(cli, "verify_backup", interrupted)
    assert cli.main(["verify", "archive.zip"]) == 130
    result, _ = _safe_output(capsys)
    assert result["error"] == "interrupted"


def test_operator_dependency_refusal_is_actionable_and_safe(
    monkeypatch, tmp_path, capsys
):
    def missing(*args, **kwargs):
        raise BackupError(
            "operator_dependency_missing",
            "Create requires toolframe-backup[operator] with the public Core maintenance API.",
        )

    monkeypatch.setattr(cli, "create_backup", missing)
    assert (
        cli.main(
            [
                "create",
                "--home",
                str(tmp_path / "source"),
                "--directory",
                str(tmp_path / "backups"),
            ]
        )
        == 2
    )
    result, stderr = _safe_output(capsys)
    assert result["error"] == "operator_dependency_missing"
    assert "toolframe-backup[operator]" in result["message"]
    assert "Traceback" not in stderr


def test_version_is_available_without_an_application(capsys):
    with pytest.raises(SystemExit) as caught:
        cli.main(["--version"])
    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == "0.1.0"
