"""Adversarial archive checks without Core or a running application."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import struct
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from toolframe_backup import archive

SECRET = b"operator-retained-key-that-must-not-appear-in-output"


def _manifest(payloads: dict[str, bytes]) -> dict:
    files, entries = [], []
    for path, content in payloads.items():
        digest = hashlib.sha256(content).hexdigest()
        role = "retained_key" if path.endswith(".key") else "configuration"
        files.append(
            {
                "path": path,
                "role": role,
                "size": len(content),
                "mode": 0o600,
                "sha256": digest,
            }
        )
        entries.append(
            {
                "path": path,
                "role": role,
                "size": len(content),
                "mode": 0o600,
                "sha256": digest,
                "source_sha256": digest,
                "snapshot": "file",
            }
        )
    return {
        "format": archive.FORMAT,
        "format_version": 1,
        "id": "a" * 32,
        "created_at": "2026-10-04T01:00:00+00:00",
        "inventory": {
            "format_version": 1,
            "status": "STOPPED",
            "application_id": "recovery-app",
            "application_name": "Recovery fixture",
            "composition_revision": "composition-1",
            "files": files,
            "stores": [],
            "retained_keys": [
                {"path": path, "owner": "auth", "name": "signing"}
                for path in payloads
                if path.endswith(".key")
            ],
            "dependency_wheels": [],
            "environment_locks": [],
        },
        "entries": entries,
    }


def _regular(name: str) -> zipfile.ZipInfo:
    member = zipfile.ZipInfo(name)
    member.create_system = 3
    member.external_attr = (stat.S_IFREG | 0o600) << 16
    return member


def _write(
    path: Path,
    payloads: dict[str, bytes] | None = None,
    *,
    manifest: dict | None = None,
    members: list[tuple[zipfile.ZipInfo, bytes]] | None = None,
    compression: int = zipfile.ZIP_STORED,
    manifest_bytes: bytes | None = None,
) -> Path:
    payloads = (
        payloads
        if payloads is not None
        else {"application.json": b'{"id":"recovery-app"}', "keys/signing.key": SECRET}
    )
    manifest = manifest if manifest is not None else _manifest(payloads)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    encoded = (
        manifest_bytes
        if manifest_bytes is not None
        else json.dumps(manifest, sort_keys=True).encode()
    )
    with zipfile.ZipFile(path, "w") as output:
        output.writestr(_regular(archive.MANIFEST), encoded, compress_type=compression)
        for member, content in (
            members
            if members is not None
            else [
                (_regular("payload/" + name), value) for name, value in payloads.items()
            ]
        ):
            output.writestr(member, content, compress_type=compression)
    path.chmod(0o600)
    return path


@pytest.fixture
def security_archive(tmp_path: Path) -> Path:
    return _write(tmp_path / "archives" / f"backup-{'a' * 32}.zip")


def _assert_rejected(path: Path, code: str | set[str], **kwargs) -> archive.BackupError:
    with pytest.raises(archive.BackupError) as caught:
        archive.verify_backup(path, **kwargs)
    assert caught.value.code in ({code} if isinstance(code, str) else code)
    assert SECRET.decode() not in str(caught.value)
    return caught.value


@pytest.mark.parametrize(
    "name",
    [
        "../outside",
        "/absolute",
        "payload/../../outside",
        "payload\\outside",
        "C:/outside",
        "payload//double",
        "payload/./dot",
        "payload/line\nbreak",
    ],
)
def test_rejects_nonportable_member_paths(tmp_path, name):
    path = _write(tmp_path / "archives" / "bad.zip", members=[(_regular(name), b"bad")])
    _assert_rejected(path, "unsafe_path")
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize(
    "file_type",
    [
        stat.S_IFLNK,
        stat.S_IFIFO,
        stat.S_IFSOCK,
        stat.S_IFBLK,
        stat.S_IFCHR,
        stat.S_IFDIR,
    ],
)
def test_rejects_links_and_special_members(tmp_path, file_type):
    member = _regular("payload/special")
    member.external_attr = (file_type | 0o600) << 16
    path = _write(tmp_path / "archives" / "bad.zip", members=[(member, b"../outside")])
    _assert_rejected(path, "unsafe_member")


def test_rejects_explicit_directory_member(tmp_path):
    path = _write(
        tmp_path / "archives" / "bad.zip",
        members=[(_regular("payload/directory/"), b"")],
    )
    _assert_rejected(path, {"unsafe_path", "unsafe_member"})


def test_rejects_duplicate_archive_members(tmp_path):
    member = _regular("payload/application.json")
    with pytest.warns(UserWarning, match="Duplicate name"):
        path = _write(
            tmp_path / "archives" / "bad.zip",
            members=[(member, b"first"), (copy.copy(member), b"second")],
        )
    _assert_rejected(path, "duplicate_entry")


@pytest.mark.parametrize("kind", ["unexpected", "missing"])
def test_rejects_unexpected_or_missing_payload(tmp_path, kind):
    payloads = {"application.json": b"application"}
    members = [(_regular("payload/application.json"), b"application")]
    if kind == "unexpected":
        members.append((_regular("payload/extra"), b"extra"))
    else:
        members.clear()
    path = _write(tmp_path / "archives" / "bad.zip", payloads, members=members)
    _assert_rejected(path, "unexpected_entry")


def test_rejects_missing_manifest(tmp_path):
    path = tmp_path / "missing.zip"
    with zipfile.ZipFile(path, "w") as output:
        output.writestr(_regular("payload/file"), b"data")
    _assert_rejected(path, "missing_entry")


@pytest.mark.parametrize("content", [b"changed!!", b"different-length"])
def test_rejects_payload_checksum_or_size_mismatch(tmp_path, content):
    path = _write(
        tmp_path / "archives" / "bad.zip",
        {"file": b"original!"},
        members=[(_regular("payload/file"), content)],
    )
    _assert_rejected(path, "checksum_mismatch")


@pytest.mark.parametrize("hash_value", ["f" * 63, "F" * 64, "not-a-checksum", None])
def test_rejects_malformed_checksums(tmp_path, hash_value):
    payloads = {"file": b"data"}
    manifest = _manifest(payloads)
    manifest["entries"][0]["sha256"] = hash_value
    path = _write(tmp_path / "archives" / "bad.zip", payloads, manifest=manifest)
    _assert_rejected(path, "invalid_metadata")


@pytest.mark.parametrize("kind", ["duplicate", "ancestor"])
def test_rejects_conflicting_manifest_paths(tmp_path, kind):
    payloads = {"file": b"data"}
    manifest = _manifest(payloads)
    extra = copy.deepcopy(manifest["entries"][0])
    if kind == "ancestor":
        extra["path"] = "file/child"
    manifest["entries"].append(extra)
    path = _write(tmp_path / "archives" / "bad.zip", payloads, manifest=manifest)
    _assert_rejected(path, "duplicate_entry")


def test_rejects_duplicate_json_keys(tmp_path):
    encoded = b'{"format":"toolframe-backup","format":"toolframe-backup"}'
    path = _write(tmp_path / "archives" / "bad.zip", manifest_bytes=encoded)
    _assert_rejected(path, "duplicate_entry")


@pytest.mark.parametrize(
    "encoded", [b"{", b"null", b"[]", b"\xff", b"[" * 2000 + b"]" * 2000]
)
def test_rejects_malformed_or_nonobject_json(tmp_path, encoded):
    path = _write(tmp_path / "archives" / "bad.zip", manifest_bytes=encoded)
    _assert_rejected(path, "invalid_metadata")


def test_rejects_encrypted_members_before_requesting_a_password(tmp_path):
    path = _write(tmp_path / "archives" / "encrypted.zip")
    encoded = bytearray(path.read_bytes())
    # Set encryption in both ZIP headers; no decryption is attempted.
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        offset = 0
        while (offset := encoded.find(signature, offset)) != -1:
            flags = struct.unpack_from("<H", encoded, offset + flag_offset)[0]
            struct.pack_into("<H", encoded, offset + flag_offset, flags | 1)
            offset += len(signature)
    path.write_bytes(encoded)
    _assert_rejected(path, "unsafe_member")


def test_rejects_unsupported_compression(tmp_path):
    path = _write(tmp_path / "archives" / "bad.zip", compression=zipfile.ZIP_BZIP2)
    _assert_rejected(path, "unsafe_member")


@pytest.mark.parametrize("name", [archive.MANIFEST, "payload/file"])
def test_invalid_deflate_data_returns_safe_archive_error(tmp_path, name):
    path = _write(
        tmp_path / "archives" / "bad-deflate.zip",
        {"file": b"abcdefgh" * 20},
        compression=zipfile.ZIP_DEFLATED,
    )
    with zipfile.ZipFile(path) as source:
        member = source.getinfo(name)
    encoded = bytearray(path.read_bytes())
    name_size, extra_size = struct.unpack_from(
        "<HH", encoded, member.header_offset + 26
    )
    compressed_offset = member.header_offset + 30 + name_size + extra_size
    # DEFLATE block type 3 is reserved and must produce a safe operator error.
    encoded[compressed_offset] = (encoded[compressed_offset] & ~7) | 7
    path.write_bytes(encoded)
    _assert_rejected(path, "invalid_archive")


def test_invalid_utf8_member_name_returns_safe_archive_error(tmp_path):
    path = _write(tmp_path / "archives" / "bad-name.zip")
    encoded = bytearray(path.read_bytes())
    for signature, flag_offset, name_offset in (
        (b"PK\x03\x04", 6, 30),
        (b"PK\x01\x02", 8, 46),
    ):
        offset = encoded.find(signature)
        flags = struct.unpack_from("<H", encoded, offset + flag_offset)[0]
        struct.pack_into("<H", encoded, offset + flag_offset, flags | 0x800)
        encoded[offset + name_offset] = 0xFF
    path.write_bytes(encoded)
    _assert_rejected(path, "invalid_archive")


@pytest.mark.parametrize("field", ["snapshot", "purpose"])
@pytest.mark.parametrize("value", [[], {}])
def test_container_valued_enum_metadata_returns_safe_error(tmp_path, field, value):
    payloads = {"file": b"data"}
    manifest = _manifest(payloads)
    if field == "snapshot":
        manifest["entries"][0]["snapshot"] = value
    else:
        manifest["inventory"]["environment_locks"] = [
            {
                "candidate_id": "candidate",
                "purpose": value,
                "environment_id": "environment",
                "sha256": "b" * 64,
            }
        ]
    path = _write(
        tmp_path / "archives" / "bad-metadata.zip", payloads, manifest=manifest
    )
    _assert_rejected(path, {"invalid_archive", "invalid_metadata"})


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_archive_bytes", 1),
        ("max_files", 1),
        ("max_file_bytes", 1),
        ("max_manifest_bytes", 1),
        ("max_total_bytes", 1),
    ],
)
def test_enforces_archive_count_and_size_bounds(security_archive, field, value):
    _assert_rejected(
        security_archive,
        "limit_exceeded",
        limits=replace(archive.Limits(), **{field: value}),
    )


def test_rejects_decompression_ratio_bomb(tmp_path):
    path = _write(
        tmp_path / "archives" / "bomb.zip",
        {"large": b"0" * 65536},
        compression=zipfile.ZIP_DEFLATED,
    )
    _assert_rejected(
        path, "limit_exceeded", limits=replace(archive.Limits(), max_ratio=20)
    )


def test_accepts_deflated_archive_within_ratio_bound(tmp_path):
    payload = os.urandom(1024)
    path = _write(
        tmp_path / "archives" / "valid.zip",
        {"random": payload},
        compression=zipfile.ZIP_DEFLATED,
    )
    assert archive.verify_backup(path).summary()["verified"] is True


def test_invalid_archive_is_rejected_before_staging(tmp_path, monkeypatch):
    path = _write(
        tmp_path / "archives" / "bad.zip",
        {"file": b"good"},
        members=[(_regular("payload/file"), b"evil")],
    )
    destination = tmp_path / "restored"

    def unexpected_staging(*args, **kwargs):
        pytest.fail("Restore staged files before archive validation completed")

    monkeypatch.setattr(archive.tempfile, "mkdtemp", unexpected_staging)
    with pytest.raises(archive.BackupError, match="checksum"):
        archive.restore_backup(path, destination)
    assert not destination.exists()
    assert not list(tmp_path.glob(".backup-restore-*"))


@pytest.mark.parametrize("kind", ["directory", "file"])
def test_restore_never_overwrites_existing_destination(
    security_archive, tmp_path, kind
):
    destination = tmp_path / "existing"
    if kind == "directory":
        destination.mkdir(mode=0o700)
        sentinel = destination / "sentinel"
    else:
        sentinel = destination
    sentinel.write_bytes(b"preserve existing data")
    with pytest.raises(archive.BackupError) as caught:
        archive.restore_backup(security_archive, destination)
    assert caught.value.code == "destination_exists"
    assert sentinel.read_bytes() == b"preserve existing data"
    assert not list(tmp_path.glob(".backup-restore-*"))


@pytest.mark.parametrize("populate", [False, True])
def test_restore_publish_race_preserves_new_destination(
    security_archive, tmp_path, monkeypatch, populate
):
    destination = tmp_path / "raced-home"
    real_publish = archive._rename_new_directory

    def race(source, final):
        final.mkdir(mode=0o700)
        if populate:
            (final / "sentinel").write_bytes(b"created by another operator")
        real_publish(source, final)

    monkeypatch.setattr(archive, "_rename_new_directory", race)
    with pytest.raises(archive.BackupError) as caught:
        archive.restore_backup(security_archive, destination)
    assert caught.value.code == "destination_exists"
    if populate:
        assert (destination / "sentinel").read_bytes() == b"created by another operator"
    else:
        assert list(destination.iterdir()) == []
    assert not list(tmp_path.glob(".backup-restore-*"))


@pytest.mark.parametrize(
    "error", [OSError("injected I/O failure"), KeyboardInterrupt()]
)
def test_failed_or_interrupted_restore_removes_staging(
    security_archive, tmp_path, monkeypatch, error
):
    destination = tmp_path / "never-published"

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(archive, "_rename_new_directory", fail)
    expected = (
        KeyboardInterrupt
        if isinstance(error, KeyboardInterrupt)
        else archive.BackupError
    )
    with pytest.raises(expected):
        archive.restore_backup(security_archive, destination)
    assert not destination.exists()
    assert not list(tmp_path.glob(".backup-restore-*"))


def test_restore_protects_all_payload_files_and_directories(security_archive, tmp_path):
    destination = tmp_path / "recovery"
    archive.restore_backup(security_archive, destination)
    assert (destination / "keys/signing.key").read_bytes() == SECRET
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    for path in destination.rglob("*"):
        assert stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)


@pytest.mark.parametrize("kind", ["archive", "parent"])
def test_verification_rejects_symlinked_paths(security_archive, tmp_path, kind):
    link = tmp_path / "link"
    if kind == "archive":
        link.symlink_to(security_archive)
        path = link
    else:
        link.symlink_to(security_archive.parent, target_is_directory=True)
        path = link / security_archive.name
    _assert_rejected(path, "unsafe_path")


def test_restore_rejects_symlinked_destination_parent(security_archive, tmp_path):
    parent = tmp_path / "real-parent"
    parent.mkdir(mode=0o700)
    link = tmp_path / "linked-parent"
    link.symlink_to(parent, target_is_directory=True)
    with pytest.raises(archive.BackupError) as caught:
        archive.restore_backup(security_archive, link / "recovery")
    assert caught.value.code == "unsafe_path"
    assert list(parent.iterdir()) == []


def test_recomputed_hashes_provide_integrity_not_authentication(tmp_path):
    original = _write(tmp_path / "archives" / "original.zip", {"file": b"original"})
    rewritten = _write(tmp_path / "archives" / "rewritten.zip", {"file": b"changed!"})
    # A party able to replace the manifest can update its hashes. V1 makes no
    # signature/authentication claim; callers must protect archive storage.
    assert (
        archive.verify_backup(original).archive_sha256
        != archive.verify_backup(rewritten).archive_sha256
    )
    assert archive.verify_backup(rewritten).summary()["verified"] is True
