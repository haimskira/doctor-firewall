"""Operator CLI: ``python -m app.cli <command>`` (run inside the api container).

Commands:
  create-user      create a local user (password read interactively or from stdin)
  rotate-secrets   re-encrypt stored credentials with the keyring's active key
  verify-audit     verify the audit hash chain (exit code 1 on failure)
  reset-data       delete every snapshot and everything derived from it (fresh start)
"""

from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy import delete, func, select

from app.audit.chain import AuditEvent
from app.auth.passwords import PasswordPolicyError, check_policy, hash_password
from app.auth.rbac import Role
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import get_sessionmaker
from app.models.assets import Asset, AssetGroup, ClusterSetting
from app.models.enforce import Changeset
from app.models.fmc import FmcConnection
from app.models.inventory import Snapshot
from app.models.recommendations import RecommendationDecision
from app.models.user import User
from app.runtime import get_audit, get_secretbox

CLI_ACTOR = "system:cli"


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("Password: ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        raise SystemExit("passwords do not match")
    return first


def cmd_create_user(args: argparse.Namespace) -> int:
    username = args.username.lower()
    roles = sorted({Role(r).value for r in args.role})
    password = _read_password(args.password_stdin)
    try:
        check_policy(password, username)
    except PasswordPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    with get_sessionmaker()() as session:
        if session.scalar(select(User.id).where(User.username == username)) is not None:
            print(f"error: user {username!r} already exists", file=sys.stderr)
            return 1
        session.add(
            User(
                username=username,
                display_name=args.display_name or "",
                auth_provider="local",
                password_hash=hash_password(password),
                roles=roles,
                is_active=True,
                must_change_password=not args.no_force_change,
                language="he",
            )
        )
        get_audit().record(
            session,
            AuditEvent(
                actor=CLI_ACTOR,
                action="user.create",
                outcome="success",
                target=username,
                details={"roles": roles},
            ),
        )
        session.commit()
    print(f"created user {username} with roles {', '.join(roles)}")
    return 0


def cmd_rotate_secrets(_: argparse.Namespace) -> int:
    box = get_secretbox()
    rotated = 0
    with get_sessionmaker()() as session:
        for conn in session.scalars(select(FmcConnection).with_for_update()):
            if box.needs_rotation(conn.password_enc):
                conn.password_enc = box.rotate(
                    conn.password_enc, FmcConnection.password_context(conn.id)
                )
                rotated += 1
        get_audit().record(
            session,
            AuditEvent(
                actor=CLI_ACTOR,
                action="keyring.rotate_secrets",
                outcome="success",
                details={"rotated": rotated},
            ),
        )
        session.commit()
    print(f"re-encrypted {rotated} secret(s) with the active key")
    return 0


def cmd_verify_audit(_: argparse.Namespace) -> int:
    with get_sessionmaker()() as session:
        result = get_audit().verify(session)
    if result.ok:
        print(
            f"audit chain OK: {result.checked} records, head id={result.head_id} "
            f"hash={result.head_hash}"
        )
        return 0
    print(f"AUDIT CHAIN BROKEN at id={result.broken_at_id}: {result.reason}", file=sys.stderr)
    return 1


def cmd_reset_data(args: argparse.Namespace) -> int:
    """A fresh start against the same FMCs: snapshots (with their inventory, findings, scores,
    map and recommendations), changesets, decisions and — unless kept — the asset table and the
    per-cluster settings are deleted. Users, FMC connections, naming conventions, inspection
    profiles and the audit log (a tamper-evident chain) stay."""
    if not args.yes:
        print("refusing without --yes (this deletes every snapshot and changeset)", file=sys.stderr)
        return 2
    counts: dict[str, int] = {}
    with get_sessionmaker()() as session:
        tables: list[tuple[str, type[object]]] = [
            ("changesets", Changeset),
            ("recommendation_decisions", RecommendationDecision),
            ("snapshots", Snapshot),
        ]
        if not args.keep_assets:
            tables += [
                ("assets", Asset),
                ("asset_groups", AssetGroup),
                ("cluster_settings", ClusterSetting),
            ]
        for name, model in tables:
            counts[name] = session.scalar(select(func.count()).select_from(model)) or 0
            session.execute(delete(model))
        get_audit().record(
            session,
            AuditEvent(actor=CLI_ACTOR, action="data.reset", outcome="success", details=counts),
        )
        session.commit()
    print("deleted: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-user", help="create a local user")
    create.add_argument("username")
    create.add_argument(
        "--role",
        action="append",
        required=True,
        choices=[r.value for r in Role],
        help="repeat for several roles",
    )
    create.add_argument("--display-name", default="")
    create.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from the first line of stdin",
    )
    create.add_argument(
        "--no-force-change",
        action="store_true",
        help="do not require a password change at first login",
    )
    create.set_defaults(func=cmd_create_user)

    rotate = sub.add_parser("rotate-secrets", help="re-encrypt secrets with the active key")
    rotate.set_defaults(func=cmd_rotate_secrets)

    verify = sub.add_parser("verify-audit", help="verify the audit hash chain")
    verify.set_defaults(func=cmd_verify_audit)

    reset = sub.add_parser("reset-data", help="delete all snapshots and derived data")
    reset.add_argument("--yes", action="store_true", help="confirm the deletion")
    reset.add_argument("--keep-assets", action="store_true", help="keep the asset table")
    reset.set_defaults(func=cmd_reset_data)
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_logging(get_settings().log_level)
    args = build_parser().parse_args(argv)
    code: int = args.func(args)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
