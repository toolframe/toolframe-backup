"""Exercise the operator wheel against an installed Core maintenance contract."""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from importlib import metadata
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    home = output / "application"
    restored = output / "restored"
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("TOOLFRAME_") and key not in {"PYTHONPATH", "PYTHONHOME"}
    }
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    def command(module, *arguments, expected=0):
        result = subprocess.run(
            [sys.executable, "-I", "-m", module, *map(str, arguments)],
            cwd=output,
            env=env,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == expected, result.stderr
        return json.loads(result.stdout if expected == 0 else result.stderr)

    def start(application):
        log = (output / f"{application.name}.log").open("w")
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-m",
                "toolframe_core.cli",
                "--home",
                str(application),
                "serve",
            ],
            cwd=output,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                assert process.poll() is None, "Core exited during startup"
                try:
                    with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/_toolframe/v1/status", timeout=1
                    ) as response:
                        assert response.status == 200
                        return process, log
                except urllib.error.URLError, TimeoutError:
                    time.sleep(0.1)
            raise TimeoutError("Core startup")
        except BaseException:
            stop(process, log)
            raise

    def stop(process, log):
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()

    command("toolframe_core.cli", "--home", home, "init", "--port", port, "--json")
    process, log = start(home)
    try:
        refused = command(
            "toolframe_backup.cli",
            "create",
            "--home",
            home,
            "--directory",
            output / "refused",
            expected=2,
        )
        assert refused["error"] == "maintenance_refused"
    finally:
        stop(process, log)
    config = (home / "toolframe.toml").read_bytes()
    created = command(
        "toolframe_backup.cli",
        "create",
        "--home",
        home,
        "--directory",
        output / "backups",
    )
    archive = output / "backups" / f"backup-{created['id']}.zip"
    verified = command("toolframe_backup.cli", "verify", archive)
    assert created == verified and created["verified"]
    command("toolframe_backup.cli", "restore", archive, "--destination", restored)
    assert (restored / "toolframe.toml").read_bytes() == config
    assert (home / "toolframe.toml").read_bytes() == config
    process, log = start(restored)
    stop(process, log)
    report = {
        "core": metadata.version("toolframe-core"),
        "backup": metadata.version("toolframe-backup"),
        "running_application_refused": True,
        "stopped_backup_verified_restored_restarted": True,
        "archive_sha256": created["archive_sha256"],
        "passed": True,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
