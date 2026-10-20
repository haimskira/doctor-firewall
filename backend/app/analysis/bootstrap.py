"""Suggest an initial asset classification from the object names found in a snapshot.

Suggestions are stored unconfirmed; an operator accepts or corrects each one. Only
confirmed assets feed the analysis. Matching uses whole name tokens (split on ``_ - .``
and spaces), most specific tier first, and an object's own name beats the name of a
group that contains it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.expand import Resolver
from app.models.inventory import FwObject

# (tier, tokens) in priority order.
TIER_TOKENS: tuple[tuple[str, frozenset[str]], ...] = (
    ("CORE", frozenset({"CORE", "DNS", "AD", "DC", "NTP", "PKI", "LDAP", "KERBEROS", "CA"})),
    ("GOLD", frozenset({"GOLD", "PCI", "CROWN", "SQL", "DB", "FIN"})),
    ("BRONZE", frozenset({"BRONZE", "DEV", "TEST", "LAB", "QA", "STAGING"})),
    ("SILVER", frozenset({"SILVER", "APP", "APPS"})),
)
USER_TOKENS = frozenset({"USER", "USERS", "SRC", "CLIENTS", "PAW", "VDI"})
USER_TYPES = (("FIN", "FIN"), ("IT", "IT"), ("DBA", "IT"), ("GENERAL", "General"))
MIN_PREFIX = 8  # never suggest blocks larger than a /8 (e.g. any-ipv4)
_SPLIT = re.compile(r"[_\-.\s]+")


@dataclass(frozen=True)
class Suggestion:
    network: str
    system: str
    tier: str
    user_type: str | None


def classify_name(name: str) -> tuple[str, str | None] | None:
    tokens = {t for t in _SPLIT.split(name.upper()) if t}
    if tokens & USER_TOKENS:
        user_type = next((ut for token, ut in USER_TYPES if token in tokens), "General")
        return "USERS", user_type
    for tier, keywords in TIER_TOKENS:
        if tokens & keywords:
            return tier, None
    return None


def _acceptable(network: str) -> bool:
    if "-" in network:
        return True
    return ipaddress.ip_network(network, strict=False).prefixlen >= MIN_PREFIX


def suggest(session: Session, snapshot_id: int, existing: set[str]) -> list[Suggestion]:
    objects = session.execute(
        select(FwObject.fmc_id, FwObject.name, FwObject.kind, FwObject.value)
        .where(
            FwObject.snapshot_id == snapshot_id,
            FwObject.stub.is_(False),
            FwObject.kind.in_(["host", "network", "range", "network_group"]),
        )
        .order_by(FwObject.name)
    ).all()
    resolver = Resolver.load(session, snapshot_id)
    chosen: dict[str, Suggestion] = {}
    # Pass 1: the object's own name. Pass 2: groups, for leaves not classified yet.
    for own in (True, False):
        for fid, name, kind, value in objects:
            if (kind != "network_group") != own:
                continue
            verdict = classify_name(name)
            if verdict is None:
                continue
            tier, user_type = verdict
            networks = [value] if own and value else sorted(resolver.leaves(fid).addresses)
            for network in networks:
                if network in existing or network in chosen or not _acceptable(network):
                    continue
                chosen[network] = Suggestion(network, name[:128], tier, user_type)
    return list(chosen.values())
