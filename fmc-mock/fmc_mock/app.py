"""FMC 10.1 REST API emulator (development and tests only — never shipped to production).

Run: ``uvicorn fmc_mock.app:create_app --factory --ssl-certfile ... --ssl-keyfile ...``

Configuration (environment):
  MOCK_USERNAME            API user name (default ``api_user``)
  MOCK_PASSWORD_FILE       file holding the API password (required)
  MOCK_TOKEN_TTL_SECONDS   token lifetime (default 1800, as on a real FMC)
  MOCK_GET_PER_MINUTE      GET rate limit per IP (default 300, as on a real FMC)
  MOCK_CLUSTERS            number of FTD HA pairs to generate (default 3)
  MOCK_RULES_PER_POLICY    approximate rules per access policy (default 200)
  MOCK_SEED                generator seed (default 1) — same seed, same data
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from fmc_mock.auth import TokenStore
from fmc_mock.limits import GET_PER_MINUTE, FmcLimitsMiddleware
from fmc_mock.network import NetworkFaultsMiddleware
from fmc_mock.resources import build_router
from fmc_mock.seed import FmcData, generate
from fmc_mock.writes import build_write_router

GLOBAL_DOMAIN_UUID = "e276abec-e0f2-11e3-8169-6d9ed49b625f"
SERVER_VERSION = "10.1.0 (build 117)"
AUTH = "/api/fmc_platform/v1/auth"


def _unauthorized() -> JSONResponse:
    return JSONResponse(
        {
            "error": {
                "category": "FRAMEWORK",
                "messages": [{"description": "Access token invalid."}],
                "severity": "ERROR",
            }
        },
        status_code=401,
    )


def create_app(
    store: TokenStore | None = None,
    get_per_minute: int | None = None,
    data: FmcData | None = None,
) -> FastAPI:
    if store is None:
        password = Path(os.environ["MOCK_PASSWORD_FILE"]).read_text(encoding="utf-8").strip()
        store = TokenStore(
            username=os.environ.get("MOCK_USERNAME", "api_user"),
            password=password,
            ttl_seconds=float(os.environ.get("MOCK_TOKEN_TTL_SECONDS", "1800")),
        )
    limit = get_per_minute or int(os.environ.get("MOCK_GET_PER_MINUTE", str(GET_PER_MINUTE)))

    def regenerate() -> FmcData:
        return generate(
            clusters=int(os.environ.get("MOCK_CLUSTERS", "3")),
            rules_per_policy=int(os.environ.get("MOCK_RULES_PER_POLICY", "200")),
            seed=int(os.environ.get("MOCK_SEED", "1")),
        )

    if data is None:
        data = regenerate()

    app = FastAPI(title="FMC 10.1 mock", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.tokens = store
    app.state.data = data
    app.add_middleware(FmcLimitsMiddleware, get_per_minute=limit)

    def token_headers(access: str, refresh: str) -> dict[str, str]:
        return {
            "X-auth-access-token": access,
            "X-auth-refresh-token": refresh,
            "DOMAIN_UUID": GLOBAL_DOMAIN_UUID,
            "global": GLOBAL_DOMAIN_UUID,
            "DOMAINS": json.dumps([{"name": "Global", "uuid": GLOBAL_DOMAIN_UUID}]),
        }

    @app.post(f"{AUTH}/generatetoken")
    async def generate_token(request: Request) -> Response:
        if not store.check_basic(request.headers.get("Authorization")):
            return _unauthorized()
        access, refresh = store.issue()
        return Response(status_code=204, headers=token_headers(access, refresh))

    @app.post(f"{AUTH}/refreshtoken")
    async def refresh_token(request: Request) -> Response:
        pair = store.refresh(
            request.headers.get("X-auth-access-token"), request.headers.get("X-auth-refresh-token")
        )
        if pair is None:
            return _unauthorized()
        return Response(status_code=204, headers=token_headers(*pair))

    @app.post(f"{AUTH}/revokeaccess")
    async def revoke(request: Request) -> Response:
        if not store.revoke(request.headers.get("X-auth-access-token")):
            return _unauthorized()
        return Response(status_code=204)

    @app.get("/api/fmc_platform/v1/info/serverversion")
    async def server_version(request: Request) -> Response:
        if not store.valid(request.headers.get("X-auth-access-token")):
            return _unauthorized()
        return JSONResponse(
            {
                "links": {"self": str(request.url)},
                "items": [
                    {
                        "serverVersion": SERVER_VERSION,
                        "geoVersion": "2026-10-01-001",
                        "vdbVersion": "build 400 ( 2026-10-01 )",
                        "sruVersion": "2026-10-01-001-vrt",
                        "type": "ServerVersion",
                    }
                ],
                "paging": {"offset": 0, "limit": 25, "count": 1, "pages": 1},
            }
        )

    def token_ok(request: Request) -> bool:
        return store.valid(request.headers.get("X-auth-access-token"))

    app.include_router(build_router(data, GLOBAL_DOMAIN_UUID, token_ok))
    writes, write_state = build_write_router(data, GLOBAL_DOMAIN_UUID, token_ok, regenerate)
    app.include_router(writes)
    app.state.writes = write_state
    app.add_middleware(NetworkFaultsMiddleware, state=write_state)
    return app
