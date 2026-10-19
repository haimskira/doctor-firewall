"""Thread-safe lazy singletons.

``functools.lru_cache`` is not atomic: under concurrent first calls (FastAPI's
thread pool, worker threads) several threads can each build the object and all but
one leak — e.g. extra SQLAlchemy engines whose pooled connections are never closed.
"""

from __future__ import annotations

import threading
from collections.abc import Callable


class Singleton[T]:
    def __init__(self, factory: Callable[[], T]) -> None:
        self._factory = factory
        self._lock = threading.Lock()
        self._value: T | None = None
        self._ready = False
        self.__doc__ = factory.__doc__
        self.__name__ = factory.__name__

    def __call__(self) -> T:
        if not self._ready:
            with self._lock:
                if not self._ready:
                    self._value = self._factory()
                    self._ready = True
        return self._value  # type: ignore[return-value]  # set together with _ready

    @property
    def is_initialized(self) -> bool:
        return self._ready

    def cache_clear(self) -> None:
        with self._lock:
            self._value = None
            self._ready = False


def singleton[T](factory: Callable[[], T]) -> Singleton[T]:
    return Singleton(factory)
