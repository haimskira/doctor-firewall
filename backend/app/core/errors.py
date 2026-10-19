"""Fail-closed error handling.

Clients get a short machine-readable code and a request id — never a stack trace,
SQL, file path, or the value that failed validation (it might be a password).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger(__name__)


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "-"))


def _sanitize_validation_errors(errors: Any) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    for err in errors:
        # Drop "input" and "ctx": they echo the submitted value back.
        cleaned.append(
            {
                "loc": [str(p) for p in err.get("loc", ())],
                "type": str(err.get("type", "invalid")),
                "msg": str(err.get("msg", "invalid value")),
            }
        )
    return cleaned


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            {"detail": exc.detail, "request_id": _request_id(request)},
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            {
                "detail": "validation_error",
                "errors": _sanitize_validation_errors(exc.errors()),
                "request_id": _request_id(request),
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.error(
            "unhandled error",
            exc_info=exc,
            extra={"request_id": _request_id(request), "path": request.url.path},
        )
        return JSONResponse(
            {"detail": "internal_error", "request_id": _request_id(request)},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
