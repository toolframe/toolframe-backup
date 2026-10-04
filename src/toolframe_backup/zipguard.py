"""Bound a ZIP central directory before the standard library allocates its index.

Record layouts follow PKWARE APPNOTE sections 4.3.12 and 4.3.14–4.3.16:
https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
This is the recovery archive's single-disk profile, not a general ZIP parser.
Payload names, member types and checksums remain the archive verifier's job.
"""

from __future__ import annotations

import os
import struct
from typing import BinaryIO

_ERROR = "ZIP directory is invalid or exceeds supported bounds."
_EOCD = struct.Struct("<4s4H2LH")
_LOCATOR = struct.Struct("<4sLQL")
_ZIP64 = struct.Struct("<4sQ2H2L4Q")
_CENTRAL = struct.Struct("<4s6H3I5H2I")
_TAIL_BYTES = _EOCD.size + 65535
_ZIP64_BYTES = 1024
_NAME_BYTES = 4096
_SHORT_MAX = 0xFFFF
_LONG_MAX = 0xFFFFFFFF


def _reject() -> None:
    raise ValueError(_ERROR)


def _read_at(stream: BinaryIO, offset: int, size: int) -> bytes:
    if offset < 0:
        _reject()
    stream.seek(offset)
    value = stream.read(size)
    if len(value) != size:
        _reject()
    return value


def _directory(stream: BinaryIO, end: tuple, end_offset: int) -> tuple[int, int, int]:
    _, disk, directory_disk, disk_count, count, size, offset, _ = end
    requires_zip64 = (
        disk == _SHORT_MAX
        or directory_disk == _SHORT_MAX
        or disk_count == _SHORT_MAX
        or count == _SHORT_MAX
        or size == _LONG_MAX
        or offset == _LONG_MAX
    )
    locator_offset = end_offset - _LOCATOR.size
    locator = (
        _read_at(stream, locator_offset, _LOCATOR.size) if locator_offset >= 0 else b""
    )
    if not locator.startswith(b"PK\x06\x07"):
        if requires_zip64 or disk != 0 or directory_disk != 0 or disk_count != count:
            _reject()
        directory_end = end_offset
    else:
        _, locator_disk, record_offset, total_disks = _LOCATOR.unpack(locator)
        if (
            locator_disk != 0
            or total_disks != 1
            or record_offset + _ZIP64.size > locator_offset
        ):
            _reject()
        record = _ZIP64.unpack(_read_at(stream, record_offset, _ZIP64.size))
        (
            signature,
            record_size,
            _,
            _,
            disk64,
            directory_disk64,
            disk_count64,
            count64,
            size64,
            offset64,
        ) = record
        if (
            signature != b"PK\x06\x06"
            or record_size < _ZIP64.size - 12
            or record_size + 12 > _ZIP64_BYTES
            or record_offset + record_size + 12 != locator_offset
            or disk64 != 0
            or directory_disk64 != 0
            or disk_count64 != count64
        ):
            _reject()
        for classic, extended, sentinel in (
            (disk, disk64, _SHORT_MAX),
            (directory_disk, directory_disk64, _SHORT_MAX),
            (disk_count, disk_count64, _SHORT_MAX),
            (count, count64, _SHORT_MAX),
            (size, size64, _LONG_MAX),
            (offset, offset64, _LONG_MAX),
        ):
            if classic != sentinel and classic != extended:
                _reject()
        count, size, offset = count64, size64, offset64
        directory_end = record_offset
    if offset + size != directory_end:
        _reject()
    return offset, size, count


def _check(stream: BinaryIO, max_members: int, max_directory_bytes: int) -> None:
    stream.seek(0, os.SEEK_END)
    file_size = stream.tell()
    if file_size < _EOCD.size:
        _reject()
    tail_size = min(file_size, _TAIL_BYTES)
    tail_offset = file_size - tail_size
    tail = _read_at(stream, tail_offset, tail_size)
    relative_end = tail.rfind(b"PK\x05\x06")
    if relative_end < 0 or relative_end + _EOCD.size > tail_size:
        _reject()
    end = _EOCD.unpack_from(tail, relative_end)
    if relative_end + _EOCD.size + end[-1] != tail_size:
        _reject()
    offset, size, count = _directory(stream, end, tail_offset + relative_end)
    if (
        count > max_members
        or size > max_directory_bytes
        or count * _CENTRAL.size > size
    ):
        _reject()
    central_end = offset + size
    position, actual = offset, 0
    while position < central_end:
        if (
            position + _CENTRAL.size > central_end
            or actual >= max_members
            or actual >= count
        ):
            _reject()
        header = _CENTRAL.unpack(_read_at(stream, position, _CENTRAL.size))
        name_size, extra_size, comment_size, disk = header[10:14]
        if header[0] != b"PK\x01\x02" or disk != 0 or not 1 <= name_size <= _NAME_BYTES:
            _reject()
        next_position = position + _CENTRAL.size + name_size + extra_size + comment_size
        if next_position > central_end:
            _reject()
        position = next_position
        actual += 1
    if position != central_end or actual != count:
        _reject()


def check_zip_directory(
    stream: BinaryIO, *, max_members: int, max_directory_bytes: int
) -> None:
    """Check directory bounds with fixed-size reads and preserve stream position.

    ZIP64 records are supported; split archives, unrecognized directory records,
    trailing data and inconsistent declarations are rejected. Every invalid
    header or bound uses one fixed error string, without archive metadata.
    """
    if (
        type(max_members) is not int
        or type(max_directory_bytes) is not int
        or max_members < 0
        or max_directory_bytes < 0
    ):
        _reject()
    try:
        original = stream.tell()
    except OSError, ValueError:
        raise ValueError(_ERROR) from None
    try:
        _check(stream, max_members, max_directory_bytes)
    except OSError, ValueError, struct.error, OverflowError:
        raise ValueError(_ERROR) from None
    finally:
        try:
            stream.seek(original)
        except OSError, ValueError:
            raise ValueError(_ERROR) from None
