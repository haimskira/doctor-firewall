"""Walk every API route of the app, including routers FastAPI mounts lazily.

FastAPI >= 0.140 keeps ``include_router`` results as private ``_IncludedRouter`` entries in
``app.routes`` instead of copying the routes, so ``isinstance(route, APIRoute)`` alone sees
none of them — a security test written that way passes vacuously. This walker follows the
``original_router`` of such entries (duck-typed, no private import), and callers assert a
minimum route count so the walk can never silently become empty again.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from fastapi.routing import APIRoute

# The app has well over this many API routes; fewer means the walk is broken.
MIN_EXPECTED_ROUTES = 45


def iter_api_routes(routes: Iterable[Any]) -> Iterator[APIRoute]:
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
            continue
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from iter_api_routes(inner.routes)
