"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI

from app.api import (
    assets,
    audit,
    auth,
    changesets,
    connectivity,
    dashboard,
    fmc,
    health,
    inventory,
    recommendations,
    users,
)
from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.core.logging import configure_logging
from app.core.middleware import SecurityMiddleware


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title="Doctor Firewall",
        version="0.1.0",
        # Interactive docs only in dev; production exposes no schema browser.
        docs_url="/api/docs" if settings.is_dev else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.is_dev else None,
    )
    register_error_handlers(app)
    for module in (
        health,
        auth,
        users,
        fmc,
        inventory,
        assets,
        recommendations,
        connectivity,
        dashboard,
        changesets,
        audit,
    ):
        app.include_router(module.router)
    app.add_middleware(SecurityMiddleware, max_body_bytes=settings.max_request_bytes)
    return app
