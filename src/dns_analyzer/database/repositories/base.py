"""
Generic base repository providing reusable async CRUD operations.

All concrete repositories inherit from BaseRepository and gain:
    - get(id)           — fetch by primary key
    - get_or_raise(id)  — fetch or raise RecordNotFoundError
    - list(...)         — paginated listing with optional filters
    - create(model)     — persist a new record
    - update(model)     — merge and persist changes
    - delete(id)        — hard delete by primary key
    - count(...)        — count matching records
    - exists(id)        — check existence without loading the full row

Concrete repositories extend this with domain-specific query methods.

Usage:
    class DomainRepository(BaseRepository[Domain]):
        model = Domain

        async def get_by_name(self, name: str) -> Domain | None:
            result = await self.session.execute(
                select(self.model).where(self.model.name == name)
            )
            return result.scalar_one_or_none()
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from dns_analyzer.database.connection import Base
from dns_analyzer.utils.exceptions import RecordNotFoundError
from dns_analyzer.utils.logger import get_logger

log = get_logger(__name__)

# Generic type variable constrained to Base subclasses
ModelT = TypeVar("ModelT", bound=Base)


class BaseRepository(Generic[ModelT]):
    """
    Generic async repository providing standard CRUD operations.

    Subclasses must set the `model` class attribute to the SQLAlchemy model
    class they manage.

    Args:
        session: An open AsyncSession. The repository does NOT manage the
                 session lifecycle — the caller is responsible for commit/rollback.
    """

    model: type[ModelT]

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ── Read ───────────────────────────────────────────────────────────────────

    async def get(self, record_id: str) -> ModelT | None:
        """
        Fetch a record by its primary key.

        Returns:
            The model instance, or None if not found.
        """
        result = await self.session.get(self.model, record_id)
        return result

    async def get_or_raise(self, record_id: str) -> ModelT:
        """
        Fetch a record by its primary key, raising if not found.

        Raises:
            RecordNotFoundError: If no record with that ID exists.
        """
        record = await self.get(record_id)
        if record is None:
            raise RecordNotFoundError(
                model=self.model.__name__,
                identifier=record_id,
            )
        return record

    async def list(
        self,
        *,
        offset: int = 0,
        limit: int = 50,
        order_by: Any | None = None,
        **filters: Any,
    ) -> list[ModelT]:
        """
        Return a paginated list of records with optional equality filters.

        Args:
            offset:   Number of records to skip (for pagination).
            limit:    Maximum number of records to return (max 500).
            order_by: SQLAlchemy column expression for ordering
                      (e.g. Domain.created_at.desc()).
            **filters: Equality filters applied as WHERE clauses
                       (e.g. is_monitored=True, status="completed").

        Returns:
            List of model instances.
        """
        limit = min(limit, 500)   # Hard cap to prevent runaway queries
        stmt = select(self.model)

        for field, value in filters.items():
            col = getattr(self.model, field, None)
            if col is not None and value is not None:
                stmt = stmt.where(col == value)

        if order_by is not None:
            stmt = stmt.order_by(order_by)

        stmt = stmt.offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count(self, **filters: Any) -> int:
        """
        Count matching records.

        Args:
            **filters: Same equality filters as list().

        Returns:
            Integer count of matching records.
        """
        stmt = select(func.count()).select_from(self.model)
        for field, value in filters.items():
            col = getattr(self.model, field, None)
            if col is not None and value is not None:
                stmt = stmt.where(col == value)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def exists(self, record_id: str) -> bool:
        """Return True if a record with the given ID exists."""
        stmt = select(func.count()).select_from(self.model).where(
            self.model.id == record_id  # type: ignore[attr-defined]
        )
        result = await self.session.execute(stmt)
        return result.scalar_one() > 0

    # ── Write ──────────────────────────────────────────────────────────────────

    async def create(self, instance: ModelT) -> ModelT:
        """
        Persist a new model instance to the database.

        The caller is responsible for committing the session.

        Args:
            instance: An unsaved model instance.

        Returns:
            The same instance after being added to the session.
        """
        self.session.add(instance)
        await self.session.flush()    # Flush to get DB-generated values (e.g. defaults)
        await self.session.refresh(instance)
        log.debug(
            "repository.record_created",
            model=self.model.__name__,
            id=instance.id,   # type: ignore[attr-defined]
        )
        return instance

    async def update(self, instance: ModelT) -> ModelT:
        """
        Merge and persist changes to an existing model instance.

        Args:
            instance: A model instance with modified fields.

        Returns:
            The refreshed instance.
        """
        merged = await self.session.merge(instance)
        await self.session.flush()
        await self.session.refresh(merged)
        log.debug(
            "repository.record_updated",
            model=self.model.__name__,
            id=merged.id,   # type: ignore[attr-defined]
        )
        return merged

    async def delete(self, record_id: str) -> bool:
        """
        Hard-delete a record by primary key.

        Args:
            record_id: The UUID primary key.

        Returns:
            True if the record was found and deleted, False if not found.
        """
        record = await self.get(record_id)
        if record is None:
            return False
        await self.session.delete(record)
        await self.session.flush()
        log.debug(
            "repository.record_deleted",
            model=self.model.__name__,
            id=record_id,
        )
        return True

    async def bulk_create(self, instances: list[ModelT]) -> list[ModelT]:
        """
        Persist multiple model instances in a single flush.

        More efficient than calling create() in a loop for large batches.

        Args:
            instances: List of unsaved model instances.

        Returns:
            The same list after being flushed.
        """
        if not instances:
            return []
        for instance in instances:
            self.session.add(instance)
        await self.session.flush()
        for instance in instances:
            await self.session.refresh(instance)
        log.debug(
            "repository.bulk_created",
            model=self.model.__name__,
            count=len(instances),
        )
        return instances