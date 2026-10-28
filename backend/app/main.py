"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI

from app.api import (
    assets,
    attack,
    audit,
    auth,
    changesets,
    connectivity,
    dashboard,
    developer,
    fmc,
    health,
    history,
    inventory,
    jobs,
    recommendations,
    relations,
    roadmap,
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
        version="0.7",
        # Interactive docs only in dev; production exposes no schema browser.
        docs_url="/api/docs" if settings.is_dev else None,
        redoc_url=None,
        # The served schema is /api/openapi.json (signed in, read API only: app.api.developer).
        openapi_url="/api/dev/openapi.json" if settings.is_dev else None,
    )
    register_error_handlers(app)
    for module in (
        health,
        attack,
        auth,
        users,
        fmc,
        inventory,
        assets,
        recommendations,
        relations,
        connectivity,
        dashboard,
        changesets,
        audit,
        jobs,
        history,
        roadmap,
        developer,
    ):
        app.include_router(module.router)
    app.add_middleware(SecurityMiddleware, max_body_bytes=settings.max_request_bytes)
    return app
