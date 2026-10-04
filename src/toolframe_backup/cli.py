"""Operator CLI with nonsecret output and no dependency on a running host."""

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .archive import BackupError, create_backup, restore_backup, verify_backup


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="toolframe-backup")
    result.add_argument("--version", action="version", version=__version__)
    commands = result.add_subparsers(dest="command", required=True)
    create = commands.add_parser(
        "create", help="Back up a cleanly stopped local application"
    )
    create.add_argument("--home", type=Path, required=True)
    create.add_argument("--directory", type=Path, required=True)
    verify = commands.add_parser(
        "verify", help="Validate an archive without extracting"
    )
    verify.add_argument("archive", type=Path)
    restore = commands.add_parser(
        "restore", help="Validate and restore into a new application home"
    )
    restore.add_argument("archive", type=Path)
    restore.add_argument("--destination", type=Path, required=True)
    restore.add_argument("--uv-path", default="uv")
    restore.add_argument("--wheelhouse", type=Path)
    restore.add_argument(
        "--offline",
        action="store_true",
        help="Reconstruct dependencies from available local assets only",
    )
    listing = commands.add_parser(
        "list", help="Scan a protected local backup directory"
    )
    listing.add_argument("--directory", type=Path, required=True)
    listing.add_argument("--limit", type=int, default=50)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "create":
            result = create_backup(arguments.home, arguments.directory)
        elif arguments.command == "verify":
            result = verify_backup(arguments.archive).summary()
        elif arguments.command == "restore":
            result = restore_backup(
                arguments.archive,
                arguments.destination,
                uv_path=arguments.uv_path,
                wheelhouse=arguments.wheelhouse,
                offline=arguments.offline,
            )
        else:
            from .catalog import Catalog

            result = Catalog(arguments.directory).list_backups(arguments.limit)
        print(json.dumps(result, sort_keys=True))
        return 0
    except BackupError as error:
        print(
            json.dumps({"error": error.code, "message": error.message}), file=sys.stderr
        )
        return 2
    except KeyboardInterrupt:
        print(
            json.dumps(
                {"error": "interrupted", "message": "Backup operation interrupted."}
            ),
            file=sys.stderr,
        )
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
