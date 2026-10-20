"""Naming convention: templates, compliance checks and computed names.

A template is literal text plus ``<TOKEN>`` placeholders, e.g. ``NET_<ROLE>_<VALUE>`` or
``<SRC>_TO_<DST>_<SVC>``. Each object kind allows a fixed token set; token values are
derived from data the system already has (the object's value, the asset table, the
rule's own ports and applications) — never typed by hand and never guessed: when a
token cannot be resolved unambiguously, no name is proposed.

Token semantics (docs/recommendations.md):

* ``VALUE``  — the object's own value (``10.1.1.5``, ``10.20.0.0-16``, ``a-b``, FQDN).
* ``SYSTEM`` — the asset-table system that alone covers every address of the object.
* ``TIER``   — the single doctrine tier covering every address (CORE/GOLD/...).
* ``TYPE``   — the single asset system type (DB, App, ...).
* ``ROLE``   — ``SYSTEM`` when resolvable, else ``TIER``.
* ``PROTO`` / ``PORT`` — a port object's protocol and port (range) — ``TCP`` / ``1433``.
* ``SVC``    — the service: a single application's name, else well-known port names
  (``SQL``, ``SSH``...) or ``<PROTO><PORT>``; up to three joined with ``-``.
* ``SRC`` / ``DST`` — for rules: the system name; else ``<TIER>-<TYPE>``; else the tier;
  for user space (USERS) the user type.
* ``ACTION`` — the rule action.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

TOKENS_BY_KIND: Mapping[str, frozenset[str]] = {
    "host": frozenset({"VALUE", "SYSTEM", "TIER", "TYPE", "ROLE"}),
    "network": frozenset({"VALUE", "SYSTEM", "TIER", "TYPE", "ROLE"}),
    "range": frozenset({"VALUE", "SYSTEM", "TIER", "TYPE", "ROLE"}),
    "fqdn": frozenset({"VALUE"}),
    "network_group": frozenset({"SYSTEM", "TIER", "TYPE", "ROLE"}),
    "port": frozenset({"PROTO", "PORT", "SVC"}),
    "port_group": frozenset({"SVC"}),
    "rule": frozenset({"SRC", "DST", "SVC", "TIER", "ACTION"}),
}
# FMC object names: letters, digits and a few separators. Longer names are not proposed.
MAX_NAME = 64
_TEMPLATE = re.compile(r"^(?:[A-Za-z0-9_.\-]|<[A-Z]{3,8}>)+$")
_TOKEN = re.compile(r"<([A-Z]{3,8})>")
_VALUE_CHARS = re.compile(r"[^A-Za-z0-9.\-]+")
_VALUE_REGEX = r"[A-Za-z0-9.\-]+"

WELL_KNOWN_PORTS: Mapping[str, str] = {
    "TCP/22": "SSH",
    "TCP/23": "TELNET",
    "TCP/25": "SMTP",
    "UDP/53": "DNS",
    "TCP/53": "DNS",
    "TCP/80": "HTTP",
    "UDP/123": "NTP",
    "UDP/161": "SNMP",
    "TCP/389": "LDAP",
    "TCP/443": "HTTPS",
    "TCP/445": "SMB",
    "TCP/636": "LDAPS",
    "TCP/1433": "SQL",
    "TCP/1521": "ORACLE",
    "TCP/3306": "MYSQL",
    "TCP/3389": "RDP",
    "TCP/5432": "PGSQL",
    "UDP/514": "SYSLOG",
    "TCP/8080": "HTTP-ALT",
    "TCP/8443": "HTTPS-ALT",
}


class TemplateError(ValueError):
    """The template is malformed or uses a token the kind does not support."""


@dataclass(frozen=True)
class Convention:
    kind: str
    template: str
    letter_case: str  # upper | lower | keep

    def tokens(self) -> list[str]:
        return _TOKEN.findall(self.template)

    def _cased(self, text: str) -> str:
        if self.letter_case == "upper":
            return text.upper()
        if self.letter_case == "lower":
            return text.lower()
        return text

    def pattern(self) -> re.Pattern[str]:
        """Regex of compliant names: literal parts (in the configured case) + token values."""
        parts: list[str] = []
        last = 0
        for m in _TOKEN.finditer(self.template):
            parts.append(re.escape(self._cased(self.template[last : m.start()])))
            parts.append(_VALUE_REGEX)
            last = m.end()
        parts.append(re.escape(self._cased(self.template[last:])))
        return re.compile("^" + "".join(parts) + "$")

    def complies(self, name: str) -> bool:
        if self._cased(name) != name:
            return False
        return self.pattern().fullmatch(name) is not None

    def render(self, values: Mapping[str, str | None]) -> str | None:
        """The name for these token values; ``None`` if any token is unresolved."""
        out = self.template
        for token in self.tokens():
            value = values.get(token)
            if value is None or value == "":
                return None
            out = out.replace(f"<{token}>", clean(value))
        out = self._cased(out)
        return out if len(out) <= MAX_NAME else None


def validate_template(kind: str, template: str) -> None:
    if kind not in TOKENS_BY_KIND:
        raise TemplateError("unknown_kind")
    if not 1 <= len(template) <= 128 or not _TEMPLATE.fullmatch(template):
        raise TemplateError("template_syntax")
    tokens = _TOKEN.findall(template)
    if not tokens:
        raise TemplateError("template_without_tokens")
    unknown = sorted(set(tokens) - TOKENS_BY_KIND[kind])
    if unknown:
        raise TemplateError("template_unknown_token")
    if re.search(r">\s*<", template):
        raise TemplateError("template_adjacent_tokens")  # ambiguous: no separator


def clean(value: str) -> str:
    """Token value made safe for an object name (separators collapse to ``-``)."""
    return _VALUE_CHARS.sub("-", value.strip()).strip("-")


def value_token(kind: str, value: str | None) -> str | None:
    if not value:
        return None
    if kind == "host":
        return value.split("/", 1)[0]
    if kind == "network":
        return value.replace("/", "-")
    return value


def port_tokens(value: str | None) -> tuple[str | None, str | None]:
    if not value or "/" not in value:
        return None, None
    proto, _, port = value.partition("/")
    return proto, (None if port == "any" else port)


def service_name(port_values: Iterable[str], app_names: Iterable[str]) -> str | None:
    """``SVC``: one application, else up to three port names; ``None`` if ambiguous."""
    apps = sorted(set(app_names))
    ports = sorted(set(port_values))
    if apps and ports:
        return None
    if len(apps) == 1:
        return apps[0]
    if apps or not ports or len(ports) > 3:
        return None
    names: list[str] = []
    for spec in ports:
        proto, port = port_tokens(spec)
        if proto is None or port is None:
            return None
        names.append(WELL_KNOWN_PORTS.get(spec, f"{proto}{port}"))
    return "-".join(dict.fromkeys(names))


def disambiguate(name: str, taken: set[str]) -> str:
    """Append ``_2``, ``_3``... until the name is free (case-insensitive, as in the FMC)."""
    lowered = {t.lower() for t in taken}
    if name.lower() not in lowered:
        return name
    n = 2
    while True:
        candidate = f"{name}_{n}"
        if candidate.lower() not in lowered and len(candidate) <= MAX_NAME:
            return candidate
        n += 1
