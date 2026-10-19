from __future__ import annotations

import hashlib
import platform
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from toolframe_backup import archive


@pytest.fixture
def source_home(tmp_path):
    home = tmp_path / "source"
    home.mkdir(mode=0o700)
    files = {
        "toolframe.toml": b'[application]\nid="app-recovery-test"\nname="Recovery test"\n',
        ".toolframe/keys/auth/signing": b"PRIVATE-RECOVERY-KEY-DO-NOT-PRINT",
        ".toolframe/artifacts/plugin.whl": b"retained-captured-wheel",
        ".toolframe/journal-locks/lock.json": b'{"index_url":"https://secret:password@internal.invalid/simple"}',
        ".toolframe/state/files-local/photo.png": b"photo-bytes",
    }
    for name, data in files.items():
        path = home / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)
    database = home / ".toolframe/state/sql-sqlite/notes/data.sqlite"
    database.parent.mkdir(mode=0o700, parents=True)
    with sqlite3.connect(database) as connection:
        connection.executescript(
            "CREATE TABLE notes(id INTEGER PRIMARY KEY,label TEXT); INSERT INTO notes VALUES(1,'preserve this row');"
        )
    database.chmod(0o600)
    return home


@pytest.fixture
def inventory(source_home):
    raw_lock = 'lock-version = "1.0"\ncreated-by = "uv"\nrequires-python = ">=3.14"\npackages = []\n'
    environment = {
        "candidate_id": "candidate",
        "purpose": "backend",
        "environment_id": "e" * 64,
        "sha256": hashlib.sha256(raw_lock.encode()).hexdigest(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "requires_python": ">=3.14",
    }
    files = []
    for path in sorted(source_home.rglob("*")):
        if path.is_file():
            files.append(
                {
                    "path": path.relative_to(source_home).as_posix(),
                    "role": "application_file",
                    "size": path.stat().st_size,
                    "mode": 0o600,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    metadata = {
        "format_version": 1,
        "status": "STOPPED",
        "application_id": "app-recovery-test",
        "application_name": "Recovery test",
        "composition_revision": "composition-exact",
        "files": files,
        "stores": [
            {
                "path": ".toolframe/state/sql-sqlite/notes/data.sqlite",
                "owner": "notes",
                "provider": "sql-sqlite",
            }
        ],
        "retained_keys": [
            {"path": ".toolframe/keys/auth/signing", "owner": "auth", "name": "signing"}
        ],
        "dependency_wheels": [
            {
                "environment_id": "env",
                "distribution": "dependency",
                "version": "1.0",
                "filename": "dependency-1.0-py3-none-any.whl",
                "sha256": "a" * 64,
                "path": None,
            }
        ],
        "environment_locks": [environment],
    }
    return SimpleNamespace(
        home=source_home,
        as_dict=lambda: metadata,
        environment_locks=(SimpleNamespace(**environment, lock=raw_lock),),
    )


@pytest.fixture
def backup_factory(tmp_path, inventory, monkeypatch):
    @contextmanager
    def stopped(home):
        assert Path(home) == inventory.home
        yield inventory

    monkeypatch.setattr(archive, "_stopped_application", stopped)
    monkeypatch.setattr(archive, "_application_lock", stopped_restore)
    monkeypatch.setattr(
        archive, "_rehydrate_environments", lambda home, locks, **kwargs: len(locks)
    )

    def create(directory=None):
        directory = directory or tmp_path / "backups"
        result = archive.create_backup(inventory.home, directory)
        return directory / f"backup-{result['id']}.zip"

    return create


@contextmanager
def stopped_restore(home):
    yield
