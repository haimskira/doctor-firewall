"""The map tells when the asset table changed after the snapshot was analysed."""

from __future__ import annotations

from datetime import UTC, datetime

from app.analysis.assets import AssetRow, fingerprint
from app.api.connectivity import _assets_changed
from app.models.inventory import Snapshot


def _row(network: str, system: str = "PAY", tier: str = "GOLD") -> AssetRow:
    return AssetRow(network, system, tier, "App", None, "", system)


def _snap(stats: dict[str, object], analysed: bool = True) -> Snapshot:
    return Snapshot(stats=stats, analyzed_at=datetime.now(UTC) if analysed else None)


def test_fingerprint_ignores_order_and_sees_every_change() -> None:
    rows = [_row("10.0.0.1/32"), _row("10.0.0.2/32")]
    assert fingerprint(rows) == fingerprint(list(reversed(rows)))
    assert fingerprint(rows) != fingerprint([*rows, _row("10.0.0.3/32")])
    assert fingerprint(rows) != fingerprint([_row("10.0.0.1/32"), _row("10.0.0.2/32", "HR")])
    assert fingerprint(rows) != fingerprint([_row("10.0.0.1/32"), _row("10.0.0.2/32", tier="CORE")])


def test_assets_changed_compares_with_what_the_analysis_used() -> None:
    rows = [_row("10.0.0.1/32")]
    assert not _assets_changed(_snap({"assets_fingerprint": fingerprint(rows)}), rows)
    assert _assets_changed(_snap({"assets_fingerprint": fingerprint(rows)}), [])
    # Analysed before the fingerprint existed: the count is all there is.
    assert _assets_changed(_snap({"assets_used": 0}), rows)
    assert not _assets_changed(_snap({"assets_used": 1}), rows)
    assert not _assets_changed(_snap({}, analysed=False), rows)
