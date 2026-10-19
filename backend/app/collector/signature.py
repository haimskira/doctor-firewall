"""Match signature of a rule: identical signature = identical traffic match + action.

The name, position, logging and inspection profile are deliberately excluded: two
rules that allow the same flow are duplicates even if they are named or inspected
differently. Order of objects inside a field does not matter.
"""

from __future__ import annotations

import hashlib
import json

from app.fmc.records import Ref, RuleField


def rule_signature(action: str, refs: tuple[tuple[RuleField, Ref], ...]) -> str:
    fields: dict[str, list[str]] = {}
    for field, ref in refs:
        token = f"o:{ref.object_id}" if ref.object_id else f"l:{ref.literal}"
        fields.setdefault(field.value, []).append(token)
    canonical = {
        "action": action,
        "match": {k: sorted(set(v)) for k, v in sorted(fields.items())},
    }
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
