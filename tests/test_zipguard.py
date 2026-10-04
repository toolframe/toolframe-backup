"""Small malformed indices exercise preflight limits before eager ZIP parsing."""

from __future__ import annotations

import io
import struct
import zipfile

import pytest

from toolframe_backup import archive
from toolframe_backup.zipguard import check_zip_directory

ERROR = "ZIP directory is invalid or exceeds supported bounds."
END = struct.Struct("<4s4H2LH")
ZIP64 = struct.Struct("<4sQ2H2L4Q")
LOCATOR = struct.Struct("<4sLQL")


def _zip(count=2, *, comment=b"", filename=None) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as output:
        for index in range(count):
            output.writestr(filename or f"file-{index}", b"payload")
        output.comment = comment
    return stream.getvalue()


def _zip64(data: bytes, *, placeholders=True, extension=b"") -> bytes:
    position = data.rfind(b"PK\x05\x06")
    values = list(END.unpack_from(data, position))
    _, _, _, disk_count, count, size, offset, _ = values
    record = ZIP64.pack(
        b"PK\x06\x06",
        44 + len(extension),
        45,
        45,
        0,
        0,
        disk_count,
        count,
        size,
        offset,
    )
    locator = LOCATOR.pack(b"PK\x06\x07", 0, position, 1)
    if placeholders:
        values[3:7] = [0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF]
    return (
        data[:position]
        + record
        + extension
        + locator
        + END.pack(*values)
        + data[position + END.size :]
    )


def _change_end(data: bytes, field: int, value: int) -> bytes:
    position = data.rfind(b"PK\x05\x06")
    values = list(END.unpack_from(data, position))
    values[field] = value
    return data[:position] + END.pack(*values) + data[position + END.size :]


def _check(data: bytes, *, members=100, directory_bytes=100_000) -> None:
    check_zip_directory(
        io.BytesIO(data), max_members=members, max_directory_bytes=directory_bytes
    )


def _reject(data: bytes, **kwargs) -> None:
    with pytest.raises(ValueError) as caught:
        _check(data, **kwargs)
    assert str(caught.value) == ERROR


@pytest.mark.parametrize(
    "count,comment", [(0, b""), (1, b""), (4, b"comment"), (2, b"c" * 65535)]
)
def test_accepts_normal_single_disk_zip(count, comment):
    data = _zip(count, comment=comment)
    _check(data)
    with zipfile.ZipFile(io.BytesIO(data)) as value:
        assert len(value.infolist()) == count


@pytest.mark.parametrize("placeholders", [True, False])
@pytest.mark.parametrize("extension", [b"", b"\0" * 64])
def test_accepts_bounded_zip64_records(placeholders, extension):
    data = _zip64(_zip(), placeholders=placeholders, extension=extension)
    _check(data)
    with zipfile.ZipFile(io.BytesIO(data)) as value:
        assert value.read("file-0") == b"payload"


def test_accepts_zip64_generated_by_standard_library(monkeypatch):
    monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 0)
    data = _zip(3)
    assert b"PK\x06\x06" in data
    _check(data)
    with zipfile.ZipFile(io.BytesIO(data)) as value:
        assert value.read("file-2") == b"payload"


class _SparseOffsetStream:
    """Represent a large leading extent without allocating or creating it."""

    def __init__(self, prefix: int):
        self.prefix = prefix
        self.position = prefix
        self.data = bytearray()

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        if whence == 1:
            offset += self.position
        elif whence == 2:
            offset += self.prefix + len(self.data)
        if offset < 0:
            raise ValueError("negative seek")
        self.position = offset
        return offset

    def write(self, value):
        start = self.position - self.prefix
        assert start >= 0
        end = start + len(value)
        if end > len(self.data):
            self.data.extend(b"\0" * (end - len(self.data)))
        self.data[start:end] = value
        self.position += len(value)
        return len(value)

    def read(self, size=-1):
        assert 0 <= size <= 65557, "unbounded read"
        end = min(self.position + size, self.prefix + len(self.data))
        padding = max(0, min(end, self.prefix) - self.position)
        start = max(self.position, self.prefix) - self.prefix
        value = b"\0" * padding + bytes(self.data[start : max(0, end - self.prefix)])
        self.position = end
        return value

    def flush(self):
        pass

    def seekable(self):
        return True


def test_supports_actual_zip64_offsets_without_a_large_input():
    stream = _SparseOffsetStream(2**32 + 1)
    with zipfile.ZipFile(stream, "w") as output:
        output.writestr("file", b"payload")
    assert len(stream.data) < 500
    check_zip_directory(stream, max_members=1, max_directory_bytes=2048)
    with zipfile.ZipFile(stream) as value:
        assert value.read("file") == b"payload"


@pytest.mark.parametrize(
    "data", [b"", b"not a zip", _zip()[:-1], _zip()[:-22], _zip() + b"trailing"]
)
def test_rejects_missing_truncated_or_trailing_end_records(data):
    _reject(data)


@pytest.mark.parametrize(
    "field,value",
    [
        (1, 1),
        (2, 1),
        (3, 1),
        (4, 3),
        (5, 0),
        (6, 0xFFFFFFFE),
        (7, 1),
    ],
)
def test_rejects_inconsistent_or_multidisk_classic_records(field, value):
    _reject(_change_end(_zip(), field, value))


def test_rejects_declared_member_bound_before_reading_directory():
    _reject(_zip(3), members=2)


def test_rejects_directory_bound_at_exact_boundary():
    data = _zip(2)
    size = END.unpack_from(data, data.rfind(b"PK\x05\x06"))[5]
    _check(data, directory_bytes=size)
    _reject(data, directory_bytes=size - 1)


@pytest.mark.parametrize("count", [0, 1])
def test_rejects_false_low_member_declarations(count):
    data = _change_end(_change_end(_zip(2), 3, count), 4, count)
    _reject(data)


def test_rejects_false_high_member_declarations():
    data = _change_end(_change_end(_zip(2), 3, 3), 4, 3)
    _reject(data)


@pytest.mark.parametrize(
    "field_offset,value", [(28, 0), (28, 65535), (30, 65535), (32, 65535), (34, 1)]
)
def test_rejects_central_header_length_and_disk_lies(field_offset, value):
    data = bytearray(_zip(1))
    position = data.find(b"PK\x01\x02")
    struct.pack_into("<H", data, position + field_offset, value)
    _reject(bytes(data))


def test_rejects_names_exceeding_utf8_safe_path_bound():
    _reject(_zip(1, filename="x" * 4097))


def test_rejects_unrecognized_central_header():
    data = bytearray(_zip())
    position = data.find(b"PK\x01\x02")
    data[position : position + 4] = b"NOPE"
    _reject(bytes(data))


@pytest.mark.parametrize("field", [3, 4, 5, 6])
def test_rejects_zip64_placeholders_without_locator(field):
    sentinel = 0xFFFF if field in {3, 4} else 0xFFFFFFFF
    _reject(_change_end(_zip(), field, sentinel))


@pytest.mark.parametrize(
    "field_offset,value,encoding",
    [(4, 1, "<L"), (8, 0xFFFFFFFFFFFFFFFF, "<Q"), (16, 2, "<L")],
)
def test_rejects_zip64_locator_bounds_and_multidisk_fields(
    field_offset, value, encoding
):
    data = bytearray(_zip64(_zip()))
    position = data.find(b"PK\x06\x07")
    struct.pack_into(encoding, data, position + field_offset, value)
    _reject(bytes(data))


@pytest.mark.parametrize(
    "field_offset,value,encoding",
    [
        (4, 43, "<Q"),
        (4, 1024, "<Q"),
        (4, 45, "<Q"),
        (16, 1, "<L"),
        (20, 1, "<L"),
        (24, 3, "<Q"),
        (32, 3, "<Q"),
        (40, 1, "<Q"),
        (48, 0xFFFFFFFFFFFFFFFF, "<Q"),
    ],
)
def test_rejects_zip64_record_size_identity_count_and_extent_lies(
    field_offset, value, encoding
):
    data = bytearray(_zip64(_zip()))
    position = data.find(b"PK\x06\x06")
    struct.pack_into(encoding, data, position + field_offset, value)
    _reject(bytes(data))


def test_zip64_classic_nonplaceholder_fields_must_agree():
    _reject(_change_end(_zip64(_zip(), placeholders=False), 4, 1))


def test_rejects_zip64_actual_count_lie_even_with_matching_end_fields():
    data = bytearray(_zip64(_zip()))
    position = data.find(b"PK\x06\x06")
    struct.pack_into("<Q", data, position + 24, 1)
    struct.pack_into("<Q", data, position + 32, 1)
    _reject(bytes(data))


@pytest.mark.parametrize("bad", [False, True])
def test_preserves_stream_position_on_success_and_failure(bad):
    stream = io.BytesIO(_zip() + (b"trailing" if bad else b""))
    stream.seek(5)
    if bad:
        with pytest.raises(ValueError, match="ZIP directory"):
            check_zip_directory(stream, max_members=10, max_directory_bytes=20480)
    else:
        check_zip_directory(stream, max_members=10, max_directory_bytes=20480)
    assert stream.tell() == 5


def test_reads_at_most_the_bounded_tail_or_one_fixed_header():
    class BoundedReads(io.BytesIO):
        def read(self, size=-1):
            assert 0 <= size <= 65557
            return super().read(size)

    stream = BoundedReads(_zip(200))
    check_zip_directory(stream, max_members=200, max_directory_bytes=409600)


@pytest.mark.parametrize(
    "members,directory_bytes", [(-1, 1), (1, -1), (True, 1), (1, True)]
)
def test_rejects_invalid_limit_values(members, directory_bytes):
    _reject(_zip(), members=members, directory_bytes=directory_bytes)


@pytest.mark.parametrize("kind", ["count", "header"])
def test_archive_preflight_rejects_lies_before_eager_zip_parser(
    tmp_path, monkeypatch, kind
):
    data = _zip(2)
    if kind == "count":
        data = _change_end(_change_end(data, 3, 1), 4, 1)
    else:
        data = bytearray(data)
        struct.pack_into("<H", data, data.find(b"PK\x01\x02") + 28, 65535)
    path = tmp_path / "bad.zip"
    path.write_bytes(data)

    def eager_parse(*args, **kwargs):
        pytest.fail("Eager ZIP parser reached before invalid directory was rejected")

    monkeypatch.setattr(archive.zipfile, "ZipFile", eager_parse)
    with pytest.raises(archive.BackupError):
        archive.verify_backup(path)
