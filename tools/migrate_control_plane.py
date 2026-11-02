"""Reversible control-plane schema migration (PR-12).

    PYTHONPATH=src:. python3 tools/migrate_control_plane.py --db sis.db --to 3
    PYTHONPATH=src:. python3 tools/migrate_control_plane.py --db sis.db --to 1 --yes

Upgrades are additive and idempotent: schema 2 adds the bound evidence
chain, schema 3 adds the unified authority ledger, and neither touches a
schema-1 table. A downgrade drops the tables a later schema introduced —
which is reversible structurally and destructive to data, so it takes a
verified backup first and refuses to run without ``--yes``.

PostgreSQL is supported through ``--dsn``; the downgrade prints a
``pg_dump`` command instead of writing a file, because a tool that
pretends to back up a remote database is worse than one that tells you to.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sis.v3.control_plane import SCHEMA_VERSION, SqliteControlPlane

SCHEMA_2_TABLES = ("outcome_v2", "evaluator_receipt_v2", "attempt_exposure",
                   "authorization_v2")
SCHEMA_3_TABLES = ("authority_event", "authority_snapshot_v2",
                   "authority_revocation", "authority_subject",
                   "authority_state")
_INDEXES = ("outcome_v2_independent_receipt", "outcome_v2_attempt")


def _version(con) -> int:
    try:
        row = con.execute(
            "SELECT version FROM schema_meta WHERE singleton=1").fetchone()
    except sqlite3.Error:
        return 0
    return 0 if row is None else int(row[0])


def backup(db: Path) -> Path:
    """Consistent single-file backup via SQLite's own backup API.

    Copying the file while WAL pages are uncheckpointed can miss
    committed data, so the backup is taken through the connection and
    verified before the downgrade is allowed to proceed. The copy is
    owner-only: it holds the same authority state as the database.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = db.with_suffix(db.suffix + f".bak-{stamp}")
    source = sqlite3.connect(str(db))
    try:
        destination = sqlite3.connect(str(target))
        try:
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()
    os.chmod(target, 0o600)
    check = sqlite3.connect(str(target))
    try:
        result = check.execute("PRAGMA integrity_check").fetchone()
    finally:
        check.close()
    if result is None or result[0] != "ok":
        raise SystemExit(f"backup failed integrity check: {target}")
    return target


def _drop_above(con, target: int) -> None:
    """Drop the tables and indexes a schema above ``target`` introduced."""
    drops: list[str] = []
    if target < 3:
        drops.extend(SCHEMA_3_TABLES)
    if target < 2:
        drops.extend(_INDEXES)
        drops.extend(SCHEMA_2_TABLES)
    for name in drops:
        con.execute(f"DROP TABLE IF EXISTS {name}")
        con.execute(f"DROP INDEX IF EXISTS {name}")
    con.execute("UPDATE schema_meta SET version=? WHERE singleton=1",
                (target,))


def migrate(db: Path, target: int, *, confirm: bool) -> int:
    if not db.exists():
        raise SystemExit(f"database not found: {db}")
    con = sqlite3.connect(str(db))
    con.isolation_level = None
    current = _version(con)
    print(f"current schema: {current}; target: {target}")
    if current == target:
        print("nothing to do")
        con.close()
        return 0
    if target > SCHEMA_VERSION:
        con.close()
        raise SystemExit(
            f"target {target} is newer than this build supports "
            f"({SCHEMA_VERSION})")
    if target < current:
        if not confirm:
            con.close()
            raise SystemExit(
                "a downgrade drops tables; re-run with --yes after taking "
                "a backup")
        print(f"backup written to {backup(db)}")
        con.execute("BEGIN IMMEDIATE")
        try:
            _drop_above(con, target)
            con.execute("COMMIT")
        except sqlite3.Error:
            con.execute("ROLLBACK")
            raise
        print(f"downgraded to schema {target}")
        con.close()
        return 0
    con.close()
    # Upgrades go through the control plane's own startup path so the
    # production code, not this script, owns the schema.
    plane = SqliteControlPlane(db)
    version = plane.schema_version()
    plane.close()
    if version != SCHEMA_VERSION:
        raise SystemExit(f"upgrade left schema at {version}")
    if target < SCHEMA_VERSION:
        # An explicit intermediate target: create everything, then keep
        # only what the requested version introduced.
        con = sqlite3.connect(str(db))
        con.isolation_level = None
        con.execute("BEGIN IMMEDIATE")
        try:
            _drop_above(con, target)
            con.execute("COMMIT")
        except sqlite3.Error:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        print(f"upgraded to schema {target}")
        return 0
    print(f"upgraded to schema {version}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="migrate_control_plane")
    parser.add_argument("--db", required=True)
    parser.add_argument("--to", type=int, required=True)
    parser.add_argument("--yes", action="store_true",
                        help="confirm a destructive downgrade")
    parser.add_argument("--dsn", default=None,
                        help="PostgreSQL DSN (downgrade prints pg_dump)")
    args = parser.parse_args()
    if args.dsn:
        print("PostgreSQL profile: run the same version of this package "
              "against the database; it creates missing tables at startup.")
        print("Before any downgrade take a dump:")
        print(f"  pg_dump --dbname='{args.dsn}' --format=custom "
              f"--file=sis-control-plane.dump")
        return 0
    return migrate(Path(args.db), args.to, confirm=args.yes)


if __name__ == "__main__":
    raise SystemExit(main())
