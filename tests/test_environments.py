"""Exact-lock boundaries and real local uv reconstruction in fresh recovery homes."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import platform
import shutil
import subprocess
import zipfile
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from toolframe_backup import archive, cli, environments
from toolframe_backup.archive import BackupError

EMPTY_LOCK = 'lock-version = "1.0"\ncreated-by = "toolframe-backup-test"\nrequires-python = ">=3.14"\npackages = []\n'
ENVIRONMENT_ID = "e" * 64
SECRET_URL = "https://recovery-user:KEEP-PRIVATE-PASSWORD@internal.invalid/simple"


def metadata(lock=EMPTY_LOCK, **overrides):
    return {
        "candidate_id": "candidate",
        "purpose": "backend",
        "environment_id": ENVIRONMENT_ID,
        "sha256": hashlib.sha256(lock.encode()).hexdigest(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "requires_python": ">=3.14",
        **overrides,
    }


def protected(lock=EMPTY_LOCK, **overrides):
    return {
        "candidate_id": "candidate",
        "purpose": "backend",
        "environment_id": ENVIRONMENT_ID,
        "lock": lock,
        **overrides,
    }


def encoded(items):
    return json.dumps(items).encode()


def replace_inventory_lock(inventory, lock, **overrides):
    public = metadata(lock, **overrides)
    inventory.as_dict()["environment_locks"] = [public]
    inventory.environment_locks = (SimpleNamespace(**public, lock=lock),)
    return public


def test_raw_lock_credentials_only_in_protected_payload(
    backup_factory, inventory, capsys
):
    lock = EMPTY_LOCK + f"# protected index credential: {SECRET_URL}\n"
    replace_inventory_lock(inventory, lock)
    path = backup_factory()
    verified = archive.verify_backup(path)
    assert SECRET_URL not in json.dumps(verified.manifest)
    assert SECRET_URL not in json.dumps(verified.summary())
    with zipfile.ZipFile(path) as source:
        raw = source.read(archive.RECOVERY)
    assert SECRET_URL.encode() in raw
    assert (
        environments.validate(raw, verified.manifest["inventory"]["environment_locks"])[
            0
        ]["lock"]
        == lock
    )
    assert cli.main(["verify", str(path)]) == 0
    output = capsys.readouterr()
    assert SECRET_URL not in output.out + output.err
    assert "KEEP-PRIVATE-PASSWORD" not in output.out + output.err


def test_capture_binds_hash_and_strips_raw_fields_from_public_inventory(inventory):
    raw = environments.capture(inventory, inventory.as_dict()["environment_locks"])
    parsed = environments.validate(raw, inventory.as_dict()["environment_locks"])
    assert parsed[0]["lock"] == inventory.environment_locks[0].lock
    public = archive._public_inventory(inventory)
    assert "lock" not in public["environment_locks"][0]
    corrupt = json.loads(raw)
    corrupt[0]["lock"] += "# modified\n"
    with pytest.raises(BackupError) as error:
        environments.validate(encoded(corrupt), public["environment_locks"])
    assert error.value.code == "checksum_mismatch"


@pytest.mark.parametrize(
    "change",
    [
        "wrong_candidate",
        "wrong_purpose",
        "wrong_environment",
        "duplicate",
        "unknown_field",
    ],
)
def test_raw_lock_identity_must_match_metadata(change):
    content = [protected()]
    if change == "duplicate":
        content.append(protected())
    elif change == "unknown_field":
        content[0]["credential"] = SECRET_URL
    else:
        field = {
            "wrong_candidate": "candidate_id",
            "wrong_purpose": "purpose",
            "wrong_environment": "environment_id",
        }[change]
        content[0][field] = "other"
    with pytest.raises(BackupError) as error:
        environments.validate(encoded(content), [metadata()])
    assert error.value.code == "invalid_environment_lock"
    assert SECRET_URL not in str(error.value)


def wheel_lock(*, digest="a" * 64, source_build=False):
    if source_build:
        artifact = f'sdist = {{url = "https://example.invalid/package.tar.gz", hashes = {{sha256 = "{digest}"}}}}'
    else:
        artifact = f'wheels = [{{url = "https://example.invalid/recovery_probe-1.0-py3-none-any.whl", hashes = {{sha256 = "{digest}"}}}}]'
    return f'lock-version = "1.0"\ncreated-by = "toolframe-backup-test"\nrequires-python = ">=3.14"\n[[packages]]\nname = "recovery-probe"\nversion = "1.0"\n{artifact}\n'


def test_source_distribution_lock_is_refused_before_uv():
    lock = wheel_lock(source_build=True)
    with pytest.raises(BackupError) as error:
        environments.validate(encoded([protected(lock)]), [metadata(lock)])
    assert error.value.code == "unsupported_environment_lock"


def test_wheel_lock_preserves_optional_source_alternative():
    lock = (
        wheel_lock()
        + 'sdist = {url = "https://example.invalid/source.tar.gz", hashes = {sha256 = "'
        + "b" * 64
        + '"}}\n'
    )
    validated = environments.validate(encoded([protected(lock)]), [metadata(lock)])
    assert validated[0]["lock"] == lock


def test_python_requirement_metadata_must_match_exact_lock():
    with pytest.raises(BackupError) as error:
        environments.validate(
            encoded([protected()]), [metadata(requires_python=">=3.0")]
        )
    assert error.value.code == "incompatible_environment"


def test_repeated_environment_identity_must_have_same_lock_and_platform():
    second_lock = EMPTY_LOCK + "# incompatible repeated environment\n"
    public = [metadata(), metadata(second_lock, candidate_id="other", purpose="ui")]
    content = [protected(), protected(second_lock, candidate_id="other", purpose="ui")]
    with pytest.raises(BackupError) as error:
        environments.validate(encoded(content), public)
    assert error.value.code == "invalid_environment_lock"


@pytest.mark.parametrize("digest", ["not-a-sha256", "a" * 63, "G" * 64, "A" * 64])
def test_wheel_hashes_require_exact_lowercase_sha256(digest):
    lock = wheel_lock(digest=digest)
    with pytest.raises(BackupError) as error:
        environments.validate(encoded([protected(lock)]), [metadata(lock)])
    assert error.value.code == "invalid_environment_lock"


@pytest.mark.parametrize(
    "field,value",
    [
        ("python_version", "99.0.0"),
        ("python_implementation", "unsupported-interpreter"),
        ("platform_system", "UnsupportedOS"),
        ("platform_machine", "unsupported-machine"),
    ],
)
def test_incompatible_platform_refused_before_extraction(
    backup_factory, inventory, tmp_path, monkeypatch, field, value
):
    replace_inventory_lock(inventory, EMPTY_LOCK, **{field: value})
    path = backup_factory()
    original_archive = path.read_bytes()
    destination = tmp_path / "new-home"
    calls = []
    monkeypatch.setattr(
        archive.tempfile, "mkdtemp", lambda **kwargs: calls.append(kwargs)
    )
    with pytest.raises(BackupError) as error:
        archive.restore_backup(path, destination)
    assert error.value.code == "incompatible_environment"
    assert not calls
    assert not destination.exists()
    assert path.read_bytes() == original_archive


def test_incompatible_requires_python_refused_in_lock_validation():
    lock = EMPTY_LOCK.replace(">=3.14", ">=99.0")
    with pytest.raises(BackupError) as error:
        environments.validate(
            encoded([protected(lock)]), [metadata(lock, requires_python=">=99.0")]
        )
    assert error.value.code == "incompatible_environment"


@pytest.mark.parametrize("failure", ["returncode", "timeout", "oserror"])
def test_subprocess_failure_suppresses_credentials(monkeypatch, capsys, failure):
    observed = []

    def fail_run(command, **kwargs):
        observed.append(kwargs)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(
                command, 1, output=SECRET_URL, stderr=SECRET_URL
            )
        if failure == "oserror":
            raise OSError(SECRET_URL)
        return subprocess.CompletedProcess(
            command, 1, stdout=SECRET_URL, stderr=SECRET_URL
        )

    monkeypatch.setattr(environments.subprocess, "run", fail_run)
    with pytest.raises(BackupError) as error:
        environments._run(["uv", "private-command"])
    assert error.value.code == "rehydration_failed"
    assert SECRET_URL not in str(error.value)
    assert observed[0]["stdout"] == subprocess.DEVNULL
    assert observed[0]["stderr"] == subprocess.DEVNULL
    output = capsys.readouterr()
    assert SECRET_URL not in output.out + output.err


def test_ready_written_only_after_successful_hash_locked_sync(tmp_path, monkeypatch):
    home = tmp_path.resolve() / "recovery"
    home.mkdir(mode=0o700)
    target = home / ".toolframe" / "environments" / ENVIRONMENT_ID
    wheelhouse = tmp_path.resolve() / "wheelhouse"
    wheelhouse.mkdir()
    calls = []

    def run(command, **kwargs):
        assert not (target / ".ready").exists()
        calls.append(command)
        if "venv" in command:
            (target / "bin").mkdir(parents=True)
        else:
            assert command[-1] == str(target / "pylock.toml")
            assert "--require-hashes" in command
            assert command[command.index("--only-binary") + 1] == ":all:"
            assert "--offline" in command
            assert command[command.index("--find-links") + 1] == str(wheelhouse)
            assert command[command.index("--python") + 1] == str(
                target / "bin" / "python"
            )
            assert (target / "pylock.toml").stat().st_mode & 0o777 == 0o600

    monkeypatch.setattr(environments, "_run", run)
    monkeypatch.setattr(environments.shutil, "which", lambda value: "/operator/uv")
    content = [protected(), protected(purpose="ui")]
    assert (
        environments.rehydrate(home, content, wheelhouse=wheelhouse, offline=True) == 1
    )
    assert len(calls) == 2
    assert (target / ".ready").read_text() == ENVIRONMENT_ID
    assert (target / ".ready").stat().st_mode & 0o777 == 0o600
    assert target.stat().st_mode & 0o777 == 0o700


def test_failed_sync_never_marks_environment_ready(tmp_path, monkeypatch):
    home = tmp_path.resolve() / "recovery"
    target = home / ".toolframe" / "environments" / ENVIRONMENT_ID

    def run(command, **kwargs):
        if "venv" in command:
            (target / "bin").mkdir(parents=True)
        else:
            raise BackupError(
                "rehydration_failed", "Exact environment reconstruction failed."
            )

    monkeypatch.setattr(environments, "_run", run)
    monkeypatch.setattr(environments.shutil, "which", lambda value: "/operator/uv")
    with pytest.raises(BackupError):
        environments.rehydrate(home, [protected()])
    assert not (target / ".ready").exists()


def tracking_guard(state):
    @contextmanager
    def guard(home):
        lockfile = home / ".toolframe" / "recovery-test.lock"
        fd = os.open(lockfile, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state.update(held=True, inode=os.fstat(fd).st_ino, initial_home=home)
        try:
            yield
        finally:
            state["exit_destination_exists"] = state["destination"].exists()
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            state["held"] = False

    return guard


def assert_guard_follows_publication(home, state):
    assert state["held"]
    assert home == state["destination"]
    assert home.exists()
    lockfile = home / ".toolframe" / "recovery-test.lock"
    assert lockfile.stat().st_ino == state["inode"]
    with lockfile.open("rb") as contender, pytest.raises(BlockingIOError):
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)


@pytest.mark.parametrize(
    "failure", ["backup_error", "os_error", "interruption", "unexpected_exception"]
)
def test_failed_hydration_rolls_back_new_home_while_guard_held(
    backup_factory, inventory, tmp_path, monkeypatch, failure
):
    path = backup_factory()
    source_bytes = {
        file: file.read_bytes() for file in inventory.home.rglob("*") if file.is_file()
    }
    archive_bytes = path.read_bytes()
    destination = tmp_path / "failed-recovery"
    state = {"destination": destination}
    monkeypatch.setattr(archive, "_application_lock", tracking_guard(state))

    def fail_hydration(home, locks, **kwargs):
        assert_guard_follows_publication(home, state)
        (home / "partial-environment").mkdir()
        if failure == "os_error":
            raise OSError("synthetic sync failure")
        if failure == "interruption":
            raise KeyboardInterrupt()
        if failure == "unexpected_exception":
            raise RuntimeError(SECRET_URL)
        raise BackupError("rehydration_failed", "Synthetic sync failure.")

    monkeypatch.setattr(archive, "_rehydrate_environments", fail_hydration)
    expected = KeyboardInterrupt if failure == "interruption" else BackupError
    with pytest.raises(expected) as error:
        archive.restore_backup(path, destination)
    if failure == "unexpected_exception":
        assert error.value.code == "restore_failed"
        assert SECRET_URL not in str(error.value)
    assert not state["exit_destination_exists"]
    assert not state["held"]
    assert not destination.exists()
    assert not list(tmp_path.glob(".backup-restore-*"))
    assert path.read_bytes() == archive_bytes
    assert all(file.read_bytes() == data for file, data in source_bytes.items())


def write_probe_wheel(path):
    directory = "recovery_probe-1.0.dist-info"
    content = {
        "recovery_probe.py": b'def main():\n    print("RECOVERY_READY")\n',
        f"{directory}/METADATA": b"Metadata-Version: 2.3\nName: recovery-probe\nVersion: 1.0\n",
        f"{directory}/WHEEL": b"Wheel-Version: 1.0\nGenerator: recovery-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{directory}/entry_points.txt": b"[console_scripts]\nrecovery-probe = recovery_probe:main\n",
    }
    record = "".join(
        f"{name},sha256={base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')},{len(data)}\n"
        for name, data in content.items()
    )
    content[f"{directory}/RECORD"] = (record + f"{directory}/RECORD,,\n").encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as wheel:
        for name, data in content.items():
            wheel.writestr(name, data)
    path.chmod(0o600)


def test_real_uv_restore_console_script_uses_final_home(
    backup_factory, inventory, tmp_path, monkeypatch
):
    uv_path = shutil.which("uv")
    if uv_path is None:
        pytest.skip("Real environment reconstruction requires local uv.")
    relative = ".toolframe/artifacts/recovery_probe-1.0-py3-none-any.whl"
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
    lock = f'lock-version = "1.0"\ncreated-by = "toolframe-backup-test"\nrequires-python = ">=3.14"\n[[packages]]\nname = "recovery-probe"\nversion = "1.0"\nwheels = [{{url = "file://${{TOOLFRAME_HOME}}/{relative}", hashes = {{sha256 = "{digest}"}}}}]\n'
    replace_inventory_lock(inventory, lock)
    path = backup_factory()
    archive_bytes = path.read_bytes()
    source_bytes = {
        file: file.read_bytes() for file in inventory.home.rglob("*") if file.is_file()
    }
    destination = tmp_path / "final-recovery"
    state = {"destination": destination}
    monkeypatch.setattr(archive, "_application_lock", tracking_guard(state))

    def hydrate(home, locks, **kwargs):
        assert_guard_follows_publication(home, state)
        return environments.rehydrate(home, locks, **kwargs)

    monkeypatch.setattr(archive, "_rehydrate_environments", hydrate)
    result = archive.restore_backup(path, destination, uv_path=uv_path, offline=True)
    assert result["ready"] is True
    assert result["rehydrated_environments"] == 1
    target = destination / ".toolframe" / "environments" / ENVIRONMENT_ID
    executable = target / "bin" / "recovery-probe"
    assert str(target / "bin" / "python") in executable.read_text()
    assert ".backup-restore-" not in executable.read_text()
    invocation = subprocess.run(
        [str(executable)], text=True, capture_output=True, check=True
    )
    assert invocation.stdout.strip() == "RECOVERY_READY"
    assert (target / ".ready").read_text() == ENVIRONMENT_ID
    assert (target / "pylock.toml").stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == archive_bytes
    assert all(file.read_bytes() == data for file, data in source_bytes.items())


def test_real_uv_empty_lock_reconstruction(tmp_path):
    uv_path = shutil.which("uv")
    if uv_path is None:
        pytest.skip("Real environment reconstruction requires local uv.")
    home = tmp_path.resolve() / "minimal-recovery"
    assert (
        environments.rehydrate(home, [protected()], uv_path=uv_path, offline=True) == 1
    )
    target = home / ".toolframe" / "environments" / ENVIRONMENT_ID
    result = subprocess.run(
        [str(target / "bin" / "python"), "-c", "import sys; print(sys.prefix)"],
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip() == str(target)
    assert (target / ".ready").read_text() == ENVIRONMENT_ID
    assert (target / ".ready").stat().st_mode & 0o777 == 0o600
