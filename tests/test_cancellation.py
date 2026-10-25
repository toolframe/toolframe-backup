"""Event-controlled cancellation tests; no production application is required."""

from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest
from test_catalog import fake_verify, write_candidate
from toolframe_sdk import PluginError, RuntimeContext, call_context

from toolframe_backup import archive, catalog
from toolframe_backup.operation import Operation, OperationStopped, operation_scope
from toolframe_backup.service import BackupPlugin


@pytest.fixture
async def service(tmp_path, monkeypatch):
    destination = tmp_path.resolve() / "archives"
    destination.mkdir(mode=0o700)
    monkeypatch.setattr(catalog, "verify_backup", fake_verify)
    runtime = BackupPlugin(
        RuntimeContext(
            None,
            plugin_id="backup",
            generation="test",
            config={"destination": str(destination), "retention_keep": 1},
        )
    )
    await runtime.activate()
    yield runtime
    await runtime.dispose()


@contextmanager
def pause_thread(monkeypatch, obj, name):
    """Pause one safe boundary, with a bounded failure escape for broken tests."""
    started = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    original = getattr(obj, name)
    calls = []

    def paused(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            loop.call_soon_threadsafe(started.set)
            assert release.wait(3), "Test did not release the worker"
        return original(*args, **kwargs)

    monkeypatch.setattr(obj, name, paused)
    try:
        yield started, release, calls
    finally:
        release.set()


async def entered(event):
    await asyncio.wait_for(event.wait(), 2)


async def cancelled(task):
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)


async def test_running_cancel_is_owned_through_repeated_cancel_and_next_caller(
    service, monkeypatch
):
    path = write_candidate(service.catalog.destination, 1)
    write_candidate(service.catalog.destination, 2)
    with pause_thread(monkeypatch, service.catalog, "_verified") as (
        start,
        release,
        calls,
    ):
        first = asyncio.create_task(service.list_backups())
        await entered(start)
        first.cancel()
        await asyncio.sleep(0)
        first.cancel()
        await asyncio.sleep(0)
        assert not first.done(), "Cancellation must retain ownership of the thread"
        release.set()
        await cancelled(first)
        assert len(calls) == 1, "Cancelled scan must not verify the second archive"
    assert not service._workers
    assert path.exists()
    assert (await service.list_backups())["verified_count"] == 2


@pytest.mark.parametrize("reason", ["cancel", "deadline"])
async def test_cancelled_lock_waiter_never_scans(service, monkeypatch, reason):
    write_candidate(service.catalog.destination, 1)
    with pause_thread(monkeypatch, service.catalog, "_verified") as (
        start,
        release,
        calls,
    ):
        first = asyncio.create_task(service.list_backups())
        await entered(start)
        waiting = asyncio.Event()
        loop = asyncio.get_running_loop()
        original = service.catalog.list_backups

        def waiter(*args, **kwargs):
            loop.call_soon_threadsafe(waiting.set)
            return original(*args, **kwargs)

        monkeypatch.setattr(service.catalog, "list_backups", waiter)
        token = call_context.set({"deadline": time.time() + 60})
        try:
            second = asyncio.create_task(service.list_backups())
        finally:
            call_context.reset(token)
        await entered(waiting)
        if reason == "cancel":
            second.cancel()
            await cancelled(second)
        else:
            list(service._workers.values())[-1].deadline = time.monotonic() - 1
            with pytest.raises(PluginError) as error:
                await asyncio.wait_for(second, 2)
            assert error.value.code == "deadline_exceeded"
        # Both cases settle while the first caller still owns the lock.
        assert len(calls) == 1
        release.set()
        assert (await first)["verified_count"] == 1
    assert (await service.verify_backup(f"{1:032x}"))["verified"]


async def test_cancelled_executor_waiter_never_enters_catalog(service, monkeypatch):
    loop = asyncio.get_running_loop()
    previous = loop._default_executor
    pool = ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(pool)
    blocked = threading.Event()
    started = asyncio.Event()

    def occupy():
        loop.call_soon_threadsafe(started.set)
        assert blocked.wait(3)

    blocker = loop.run_in_executor(None, occupy)
    calls = []
    monkeypatch.setattr(
        service.catalog, "list_backups", lambda *a, **kw: calls.append(1)
    )
    try:
        await entered(started)
        task = asyncio.create_task(service.list_backups())
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        blocked.set()
        await cancelled(task)
        await blocker
        assert calls == []
        assert not service._workers
    finally:
        blocked.set()
        loop.set_default_executor(previous)
        pool.shutdown(wait=True)


async def test_deadline_stops_running_scan_at_next_boundary(service, monkeypatch):
    write_candidate(service.catalog.destination, 1)
    write_candidate(service.catalog.destination, 2)
    with pause_thread(monkeypatch, service.catalog, "_verified") as (
        start,
        release,
        calls,
    ):
        token = call_context.set({"deadline": time.time() + 60})
        try:
            task = asyncio.create_task(service.list_backups())
        finally:
            call_context.reset(token)
        await entered(start)
        # Advance the operation's monotonic deadline without a long sleep.
        next(iter(service._workers.values())).deadline = time.monotonic() - 1
        release.set()
        with pytest.raises(PluginError) as error:
            await task
        assert error.value.code == "deadline_exceeded"
        assert len(calls) == 1
    assert (await service.list_backups())["verified_count"] == 2


async def test_expired_host_deadline_never_starts_scan(service, monkeypatch):
    calls = []
    monkeypatch.setattr(service.catalog, "_scan", lambda: calls.append(1))
    token = call_context.set({"deadline": time.time() - 1})
    try:
        with pytest.raises(PluginError) as error:
            await service.list_backups()
    finally:
        call_context.reset(token)
    assert error.value.code == "deadline_exceeded"
    assert calls == []


async def test_dispose_cancels_and_joins_workers_even_when_dispose_is_cancelled(
    service, monkeypatch
):
    write_candidate(service.catalog.destination, 1)
    with pause_thread(monkeypatch, service.catalog, "_verified") as (start, release, _):
        caller = asyncio.create_task(service.list_backups())
        await entered(start)
        disposal = asyncio.create_task(service.dispose())
        await asyncio.sleep(0)
        disposal.cancel()
        await asyncio.sleep(0)
        disposal.cancel()
        await asyncio.sleep(0)
        assert not disposal.done()
        release.set()
        await cancelled(disposal)
        await cancelled(caller)
    await service.dispose()
    assert service.catalog is None
    assert not service._workers
    with pytest.raises(PluginError) as error:
        await service.list_backups()
    assert error.value.code == "backup_not_ready"


async def test_retention_finishes_atomic_phase_before_cancel_returns(
    service, monkeypatch
):
    first = write_candidate(service.catalog.destination, 1)
    second = write_candidate(service.catalog.destination, 2)
    third = write_candidate(service.catalog.destination, 3)
    token = call_context.set({"application_id": "app-1"})
    try:
        plan = await service.retention_preview()
        with pause_thread(monkeypatch, catalog.os, "unlink") as (start, release, _):
            task = asyncio.create_task(service.apply_retention(plan["plan_token"]))
            await entered(start)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            release.set()
            await cancelled(task)
    finally:
        call_context.reset(token)
    assert not first.exists() and not second.exists() and third.exists()
    assert not list(second.parent.glob(".backup-retention-*"))
    assert (await service.list_backups())["verified_count"] == 1


async def test_retention_cancel_during_staging_restores_all_archives(
    service, monkeypatch
):
    paths = [write_candidate(service.catalog.destination, n) for n in (1, 2, 3)]
    original_bytes = [path.read_bytes() for path in paths]
    token = call_context.set({"application_id": "app-1"})
    try:
        plan = await service.retention_preview()
        with pause_thread(monkeypatch, catalog.os, "rename") as (start, release, _):
            task = asyncio.create_task(service.apply_retention(plan["plan_token"]))
            await entered(start)
            task.cancel()
            await asyncio.sleep(0)
            release.set()
            await cancelled(task)
    finally:
        call_context.reset(token)
    assert [path.read_bytes() for path in paths] == original_bytes
    assert not list(paths[0].parent.glob(".backup-retention-*"))
    assert (await service.list_backups())["verified_count"] == 3


@pytest.mark.parametrize("stage", ["archive", "payload"])
def test_archive_chunk_cancel_closes_resources(backup_factory, monkeypatch, stage):
    path = backup_factory()
    operation = Operation()
    observed = []
    real_open = archive.os.fdopen

    def track(*args, **kwargs):
        stream = real_open(*args, **kwargs)
        observed.append(stream)
        return stream

    monkeypatch.setattr(archive.os, "fdopen", track)
    if stage == "archive":
        original = archive.checkpoint
        calls = 0

        def stop():
            nonlocal calls
            calls += 1
            operation.cancelled.set()
            original()

        monkeypatch.setattr(archive, "checkpoint", stop)
    else:
        original = archive.zipfile.ZipExtFile.read

        def read(self, *args, **kwargs):
            data = original(self, *args, **kwargs)
            if self.name.startswith("payload/"):
                operation.cancelled.set()
            return data

        monkeypatch.setattr(archive.zipfile.ZipExtFile, "read", read)
    with pytest.raises(OperationStopped), operation_scope(operation):
        archive.verify_backup(path)
    assert observed and all(stream.closed for stream in observed)
    monkeypatch.undo()
    assert archive.verify_backup(path).summary()["verified"]
