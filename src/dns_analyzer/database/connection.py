"""
Database connection, session factory, and declarative base.

Provides:
    - Async SQLAlchemy engine configured from settings
    - Session factory for dependency injection
    - Declarative base model with shared audit columns
    - Health check utility
    - Lifespan helpers for FastAPI startup / shutdown

Usage (in FastAPI dependency):
    from dns_analyzer.database.connection import get_db_session

    async def endpoint(db: AsyncSession = Depends(get_db_session)):
        result = await db.execute(select(Domain))

Usage (standalone / tests):
    async with db_session() as session:
        result = await session.execute(select(Domain))
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, String, event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from dns_analyzer.config.settings import get_settings
from dns_analyzer.utils.logger import get_logger

log = get_logger(__name__)

# ==============================================================================
# ENGINE
# ==============================================================================

def _build_engine() -> AsyncEngine:
    """
    Create and configure the async SQLAlchemy engine from settings.

    Connection pool settings are tuned for production workloads:
    - pool_pre_ping:  Recycles stale connections before use
    - pool_recycle:   Forces connection replacement every 30 minutes
                      to avoid hitting server-side timeout limits
    """
    settings = get_settings()
    db = settings.database

    connect_args: dict[str, Any] = {}

    # SQLite requires check_same_thread=False for async usage
    if db.is_sqlite:
        connect_args["check_same_thread"] = False
        engine = create_async_engine(
            db.url,
            echo=db.echo,
            connect_args=connect_args,
        )
    else:
        engine = create_async_engine(
            db.url,
            echo=db.echo,
            pool_size=db.pool_size,
            max_overflow=db.max_overflow,
            pool_timeout=db.pool_timeout,
            pool_pre_ping=True,
            pool_recycle=1800,
            connect_args=connect_args,
        )

    log.info(
        "database.engine_created",
        url=_safe_url(db.url),
        pool_size=db.pool_size if not db.is_sqlite else "N/A",
        echo=db.echo,
    )
    return engine


def _safe_url(url: str) -> str:
    """Strip password from DB URL for safe logging."""
    if "@" in url:
        scheme_and_creds, rest = url.split("@", 1)
        if ":" in scheme_and_creds.split("//")[-1]:
            parts = scheme_and_creds.split(":")
            parts[-1] = "****"
            return ":".join(parts) + "@" + rest
    return url


# Module-level engine and session factory (created lazily on first import)
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Return the module-level async engine, creating it if necessary."""
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the module-level session factory, creating it if necessary."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,   # Prevent lazy-load errors after commit
            autocommit=False,
            autoflush=False,
        )
    return _session_factory


# ==============================================================================
# SESSION HELPERS
# ==============================================================================

@asynccontextmanager
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager that provides a database session with
    automatic commit on success and rollback on exception.

    Usage:
        async with db_session() as session:
            session.add(domain)
            # commits automatically on exit

    Raises:
        Any exception from the session is re-raised after rollback.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields a database session per request.

    Commits on success, rolls back on any exception, always closes.

    Usage:
        async def endpoint(db: AsyncSession = Depends(get_db_session)):
            ...
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ==============================================================================
# LIFESPAN HELPERS
# ==============================================================================

async def init_db() -> None:
    """
    Initialize the database schema.

    Creates all tables defined by SQLAlchemy models.
    In production, prefer Alembic migrations over this function.
    Safe to call multiple times (uses CREATE TABLE IF NOT EXISTS).
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    log.info("database.schema_initialized")


async def close_db() -> None:
    """
    Dispose of the database connection pool.

    Call this during application shutdown to release all connections cleanly.
    """
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        log.info("database.connection_pool_closed")


async def check_db_health() -> dict[str, Any]:
    """
    Execute a lightweight query to verify database connectivity.

    Returns:
        dict with "status" ("ok" or "error") and optional "detail".
    """
    try:
        async with db_session() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "ok"}
    except Exception as exc:
        log.error("database.health_check_failed", exc_info=True)
        return {"status": "error", "detail": str(exc)}


# ==============================================================================
# DECLARATIVE BASE MODEL
# ==============================================================================

class Base(DeclarativeBase):
    """
    Shared SQLAlchemy declarative base.

    All ORM models inherit from this class, which provides:
        - UUID primary key (id)
        - created_at / updated_at audit timestamps (auto-managed)
        - __repr__ that shows the model class and primary key
        - to_dict() for quick serialization (tests, logging)
    """

    # Shared type annotation map so subclasses don't need to repeat these
    type_annotation_map = {
        datetime: DateTime(timezone=True),
    }

    # ── Primary key ────────────────────────────────────────────────────────────
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )

    # ── Audit timestamps ───────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.id!r}>"

    def to_dict(self) -> dict[str, Any]:
        """
        Return a plain dict of all mapped column values.

        Useful for logging and unit tests. Not intended as a replacement
        for Pydantic schemas in API responses.
        """
        return {
            col.key: getattr(self, col.key)
            for col in self.__mapper__.column_attrs  # type: ignore[attr-defined]
        }