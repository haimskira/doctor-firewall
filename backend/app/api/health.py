from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.runtime import get_redis

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("")
def live() -> dict[str, str]:
    """Liveness: the process answers. Public, reveals nothing."""
    return {"status": "ok"}


@router.get("/ready")
def ready(db: Annotated[Session, Depends(get_db)]) -> dict[str, str]:
    """Readiness: DB and Redis reachable. Public, returns no details on failure."""
    try:
        db.execute(text("SELECT 1"))
        get_redis().ping()
    except (SQLAlchemyError, RedisError, OSError) as exc:
        log.warning("readiness check failed", extra={"error": type(exc).__name__})
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "not_ready") from exc
    return {"status": "ready"}
