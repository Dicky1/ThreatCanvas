"""Lightweight, idempotent schema upgrades run at startup.

ThreatCanvas uses ``Base.metadata.create_all``, which creates missing tables
but never alters existing ones. Columns added after a table first shipped are
added here so existing SQLite/PostgreSQL databases keep working.
"""

import logging

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from app.core.config import settings

logger = logging.getLogger(__name__)

# (table, column, SQL type) - keep types portable across SQLite and PostgreSQL.
ADDED_COLUMNS: list[tuple[str, str, str]] = [
    ("scenarios", "owner_id", "VARCHAR"),
]


def _ensure_columns(engine: Engine) -> None:
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    for table, column, sql_type in ADDED_COLUMNS:
        if table not in tables:
            continue  # create_all builds it with every column
        existing = {c["name"] for c in inspector.get_columns(table)}
        if column in existing:
            continue
        with engine.begin() as connection:
            # Identifiers come from the constant list above, never from input.
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}"))
            connection.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{table}_{column} ON {table} ({column})"))
        logger.info("Added column %s.%s", table, column)


def _adopt_orphan_scenarios(engine: Engine) -> None:
    with engine.begin() as connection:
        orphans = connection.execute(text("SELECT COUNT(*) FROM scenarios WHERE owner_id IS NULL")).scalar() or 0
        if not orphans:
            return
        if settings.LEGACY_SCENARIO_OWNER:
            owner = connection.execute(
                text("SELECT id FROM users WHERE username = :username"),
                {"username": settings.LEGACY_SCENARIO_OWNER},
            ).scalar()
            if owner is None:
                logger.warning(
                    "LEGACY_SCENARIO_OWNER=%r does not exist; %d legacy scenarios stay hidden.",
                    settings.LEGACY_SCENARIO_OWNER,
                    orphans,
                )
                return
        else:
            users = connection.execute(text("SELECT id FROM users LIMIT 2")).scalars().all()
            if len(users) != 1:
                logger.warning(
                    "%d scenarios have no owner and are hidden from every user. "
                    "Set LEGACY_SCENARIO_OWNER=<username> to assign them.",
                    orphans,
                )
                return
            owner = users[0]
        connection.execute(text("UPDATE scenarios SET owner_id = :owner WHERE owner_id IS NULL"), {"owner": owner})
        logger.info("Assigned %d legacy scenarios to user %s", orphans, owner)


def run_migrations(engine: Engine) -> None:
    _ensure_columns(engine)
    tables = set(inspect(engine).get_table_names())
    if {"scenarios", "users"} <= tables:
        _adopt_orphan_scenarios(engine)
