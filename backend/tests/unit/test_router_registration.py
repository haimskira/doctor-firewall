"""Every API module's router must be mounted (a forgotten include_router is a silent 404)."""

from __future__ import annotations

import importlib
import pkgutil

from fastapi import APIRouter
from fastapi.routing import APIRoute

import app.api
from app.main import create_app


def test_every_api_router_is_registered() -> None:
    mounted = {
        (route.path, method)
        for route in create_app().routes
        if isinstance(route, APIRoute)
        for method in route.methods or set()
    }
    missing = []
    for info in pkgutil.iter_modules(app.api.__path__):
        module = importlib.import_module(f"app.api.{info.name}")
        router = getattr(module, "router", None)
        if not isinstance(router, APIRouter):
            continue
        for route in router.routes:
            if isinstance(route, APIRoute):
                missing += [
                    (info.name, route.path, m)
                    for m in route.methods or set()
                    if (route.path, m) not in mounted
                ]
    assert missing == []
