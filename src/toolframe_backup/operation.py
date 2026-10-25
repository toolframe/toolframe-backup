"""Cooperative cancellation shared by runtime threads and synchronous readers."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field


class OperationStopped(Exception):
    """Internal control flow; never classify cancellation as an invalid archive."""


@dataclass(eq=False)
class Operation:
    deadline: float | None = None
    cancelled: threading.Event = field(default_factory=threading.Event)

    def check(self):
        if self.cancelled.is_set():
            raise OperationStopped
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise OperationStopped


_current: ContextVar[Operation | None] = ContextVar("backup_operation", default=None)


def checkpoint():
    operation = _current.get()
    if operation is not None:
        operation.check()


@contextmanager
def operation_scope(operation: Operation | None):
    token = _current.set(operation)
    try:
        checkpoint()
        yield
    finally:
        _current.reset(token)


@contextmanager
def catalog_lock(lock):
    if _current.get() is None:
        with lock:
            yield
        return
    checkpoint()
    while not lock.acquire(timeout=0.05):
        checkpoint()
    try:
        checkpoint()
        yield
    finally:
        lock.release()
