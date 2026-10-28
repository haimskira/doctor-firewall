"""Read-only API tokens for other systems, and the OpenAPI document of the read API."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.db.session import get_sessionmaker
from app.models.audit import AuditRecord
from app.models.user import ApiToken
from tests.integration.conftest import login, make_user


def test_a_token_reads_everything_its_owner_may_read_and_writes_nothing(
    client: TestClient,
) -> None:
    make_user("api-reader", ["viewer", "approver"])
    h = {"X-CSRF-Token": login(client, "api-reader")}
    made = client.post("/api/tokens", headers=h, json={"name": "SIEM export", "days": 30})
    assert made.status_code == 201, made.text
    token = made.json()["token"]
    assert token.startswith("dfk_")
    assert made.json()["prefix"] in token
    with get_sessionmaker()() as s:
        row = s.scalar(select(ApiToken).where(ApiToken.id == made.json()["id"]))
        assert row is not None
        assert token not in row.token_hash  # only the hash is kept

    with TestClient(client.app, base_url="https://testserver") as other:  # no session at all
        bearer = {"Authorization": f"Bearer {token}"}
        assert other.get("/api/snapshots", headers=bearer).status_code == 200
        assert other.get("/api/audit", headers=bearer).status_code == 200  # owner may read audit
        # Writes never: not even what the owner (an approver) may do in the UI.
        refused = other.post("/api/changesets/1/batches/1/approve", headers=bearer)
        assert refused.status_code == 403
        assert refused.json()["detail"] == "token_read_only"
        assert other.post("/api/tokens", headers=bearer, json={"name": "x" * 5}).status_code == 403
        assert other.get("/api/snapshots").status_code == 401
        assert (
            other.get("/api/snapshots", headers={"Authorization": "Bearer dfk_nope"}).status_code
            == 401
        )

        # The schema of the read API: signed-in only, GET operations only.
        assert other.get("/api/openapi.json").status_code == 401
        schema = other.get("/api/openapi.json", headers=bearer).json()
        assert "/api/snapshots/{snapshot_id}/findings" in schema["paths"]
        assert all(set(ops) == {"get"} for ops in schema["paths"].values())
        assert not any(p.startswith("/api/tokens") for p in schema["paths"])
        assert "shadowed_rule" in schema["info"]["description"]
        assert "compact_group" in schema["info"]["description"]
        everything = other.get("/api/openapi.json?scope=all", headers=bearer).json()
        assert "post" in everything["paths"]["/api/changesets"]
        assert {t["name"] for t in everything["tags"]} >= {"inventory", "recommendations"}

        # Revoked or expired: refused.
        listed = client.get("/api/tokens", headers=h).json()
        assert [t["name"] for t in listed] == ["SIEM export"]
        assert "token" not in listed[0]
        with get_sessionmaker()() as s:
            s.execute(
                update(ApiToken)
                .where(ApiToken.id == made.json()["id"])
                .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
            )
            s.commit()
        assert other.get("/api/snapshots", headers=bearer).status_code == 401
    second = client.post("/api/tokens", headers=h, json={"name": "BI pull"}).json()
    assert client.delete(f"/api/tokens/{second['id']}", headers=h).json()["revoked_at"]
    with TestClient(client.app, base_url="https://testserver") as other:
        gone = other.get("/api/snapshots", headers={"Authorization": f"Bearer {second['token']}"})
        assert gone.status_code == 401
    with get_sessionmaker()() as s:
        actions = set(
            s.scalars(
                select(AuditRecord.action).where(
                    AuditRecord.actor == "api-reader", AuditRecord.action.like("api_token.%")
                )
            )
        )
    assert actions == {"api_token.created", "api_token.revoked"}
