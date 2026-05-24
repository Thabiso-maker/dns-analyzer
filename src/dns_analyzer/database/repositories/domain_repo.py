"""
Concrete repositories for Domain, Scan, and Report models.

Each repository extends BaseRepository with model-specific query methods
that encapsulate all SQL logic. The API and core layers never write
raw SQLAlchemy queries — they always go through a repository.

This keeps:
    - Business logic free of persistence concerns
    - SQL isolated in one testable layer
    - Queries optimized and reusable
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import and_, desc, func, select, update

from dns_analyzer.database.repositories.base import BaseRepository
from dns_analyzer.models.domain import Domain
from dns_analyzer.models.finding import Finding
from dns_analyzer.models.report import Report
from dns_analyzer.models.scan import Scan
from dns_analyzer.utils.exceptions import DuplicateRecordError, RecordNotFoundError
from dns_analyzer.utils.logger import get_logger

log = get_logger(__name__)


# ==============================================================================
# DOMAIN REPOSITORY
# ==============================================================================

class DomainRepository(BaseRepository[Domain]):
    """
    Repository for Domain records.

    Provides all persistence operations for domains including monitoring
    enrollment and last-scan summary updates.
    """

    model = Domain

    async def get_by_name(self, name: str) -> Domain | None:
        """Fetch a domain by its exact name (case-insensitive)."""
        result = await self.session.execute(
            select(Domain).where(func.lower(Domain.name) == name.lower())
        )
        return result.scalar_one_or_none()

    async def get_by_name_or_raise(self, name: str) -> Domain:
        """Fetch a domain by name or raise RecordNotFoundError."""
        domain = await self.get_by_name(name)
        if domain is None:
            raise RecordNotFoundError(model="Domain", identifier=name)
        return domain

    async def create_domain(
        self,
        name: str,
        *,
        description: str | None = None,
        is_monitored: bool = False,
        monitor_interval_h: int = 24,
        tags: list[str] | None = None,
        owner_email: str | None = None,
        notes: str | None = None,
    ) -> Domain:
        """
        Create a new domain, raising DuplicateRecordError if name already exists.

        Raises:
            DuplicateRecordError: If a domain with this name is already registered.
        """
        existing = await self.get_by_name(name)
        if existing is not None:
            raise DuplicateRecordError(model="Domain", field="name", value=name)

        domain = Domain(
            name=name,
            description=description,
            is_monitored=is_monitored,
            monitor_interval_h=monitor_interval_h,
            owner_email=owner_email,
            notes=notes,
        )
        if tags:
            domain.set_tags(tags)

        return await self.create(domain)

    async def list_monitored(self) -> list[Domain]:
        """Return all domains enrolled in scheduled monitoring."""
        result = await self.session.execute(
            select(Domain)
            .where(Domain.is_monitored == True)  # noqa: E712
            .order_by(Domain.last_scanned_at.asc().nulls_first())
        )
        return list(result.scalars().all())

    async def list_due_for_scan(self, now: datetime | None = None) -> list[Domain]:
        """
        Return monitored domains that are due for a new scan.

        A domain is due if:
            - It has never been scanned (last_scanned_at IS NULL), OR
            - last_scanned_at + monitor_interval_h hours <= now
        """
        from sqlalchemy import text, or_

        if now is None:
            now = datetime.now(timezone.utc)

        result = await self.session.execute(
            select(Domain).where(
                and_(
                    Domain.is_monitored == True,  # noqa: E712
                    or_(
                        Domain.last_scanned_at.is_(None),
                        text(
                            "last_scanned_at + (monitor_interval_h * interval '1 hour') <= :now"
                        ).bindparams(now=now),
                    ),
                )
            )
        )
        return list(result.scalars().all())

    async def update_last_scan_summary(
        self,
        domain_id: str,
        *,
        score: int,
        grade: str,
        scanned_at: datetime,
    ) -> None:
        """
        Update the denormalized last-scan summary fields without loading the full model.

        Uses a targeted UPDATE statement to avoid unnecessary data transfer.
        """
        await self.session.execute(
            update(Domain)
            .where(Domain.id == domain_id)
            .values(
                last_score=score,
                last_grade=grade,
                last_scanned_at=scanned_at,
            )
        )
        log.debug(
            "domain_repo.scan_summary_updated",
            domain_id=domain_id,
            score=score,
            grade=grade,
        )

    async def search(self, query: str, *, limit: int = 20) -> list[Domain]:
        """
        Full-text search domains by name or description.

        Args:
            query: Partial domain name or keyword.
            limit: Maximum results to return.
        """
        pattern = f"%{query.lower()}%"
        result = await self.session.execute(
            select(Domain)
            .where(
                func.lower(Domain.name).like(pattern)
            )
            .order_by(Domain.name.asc())
            .limit(limit)
        )
        return list(result.scalars().all())


# ==============================================================================
# SCAN REPOSITORY
# ==============================================================================

class ScanRepository(BaseRepository[Scan]):
    """
    Repository for Scan records.

    Covers the full scan lifecycle: creation, status transitions,
    finding persistence, and historical queries.
    """

    model = Scan

    async def get_with_findings(self, scan_id: str) -> Scan | None:
        """
        Fetch a scan and eagerly load all its findings in a single query.

        Use this instead of get() when you know you'll need the findings,
        to avoid N+1 queries.
        """
        from sqlalchemy.orm import selectinload

        result = await self.session.execute(
            select(Scan)
            .options(selectinload(Scan.findings))
            .where(Scan.id == scan_id)
        )
        return result.scalar_one_or_none()

    async def get_latest_for_domain(self, domain_name: str) -> Scan | None:
        """Return the most recently completed scan for a domain."""
        result = await self.session.execute(
            select(Scan)
            .where(
                and_(
                    Scan.domain_name == domain_name,
                    Scan.status == "completed",
                )
            )
            .order_by(desc(Scan.completed_at))
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def get_running_for_domain(self, domain_name: str) -> Scan | None:
        """Return an in-progress scan for a domain (if any)."""
        result = await self.session.execute(
            select(Scan).where(
                and_(
                    Scan.domain_name == domain_name,
                    Scan.status.in_(["pending", "running"]),
                )
            )
        )
        return result.scalar_one_or_none()

    async def list_for_domain(
        self,
        domain_name: str,
        *,
        offset: int = 0,
        limit: int = 20,
        status: str | None = None,
    ) -> list[Scan]:
        """Return paginated scan history for a domain."""
        stmt = (
            select(Scan)
            .where(Scan.domain_name == domain_name)
            .order_by(desc(Scan.created_at))
            .offset(offset)
            .limit(limit)
        )
        if status:
            stmt = stmt.where(Scan.status == status)

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_recent(self, *, limit: int = 50) -> list[Scan]:
        """Return the most recently created scans across all domains."""
        result = await self.session.execute(
            select(Scan)
            .order_by(desc(Scan.created_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def create_scan(
        self,
        domain_id: str,
        domain_name: str,
        *,
        triggered_by: str = "api",
        requested_by_ip: str | None = None,
    ) -> Scan:
        """Create a new scan record in pending state."""
        scan = Scan(
            domain_id=domain_id,
            domain_name=domain_name,
            triggered_by=triggered_by,
            requested_by_ip=requested_by_ip,
            status="pending",
        )
        return await self.create(scan)

    async def save_findings(self, findings: list[Finding]) -> list[Finding]:
        """Bulk-insert all findings for a completed scan."""
        return await self.bulk_create(findings)

    async def count_by_status(self) -> dict[str, int]:
        """Return a count breakdown of scans by status."""
        result = await self.session.execute(
            select(Scan.status, func.count(Scan.id))
            .group_by(Scan.status)
        )
        return {row[0]: row[1] for row in result.all()}

    async def delete_old_scans(self, domain_name: str, keep_last: int = 50) -> int:
        """
        Delete scan history beyond the most recent N scans for a domain.

        Returns:
            Number of scans deleted.
        """
        # Get IDs of scans to keep
        keep_result = await self.session.execute(
            select(Scan.id)
            .where(Scan.domain_name == domain_name)
            .order_by(desc(Scan.created_at))
            .limit(keep_last)
        )
        keep_ids = [row[0] for row in keep_result.all()]

        if not keep_ids:
            return 0

        # Delete the rest
        from sqlalchemy import delete

        delete_result = await self.session.execute(
            delete(Scan).where(
                and_(
                    Scan.domain_name == domain_name,
                    Scan.id.not_in(keep_ids),
                )
            )
        )
        deleted = delete_result.rowcount
        if deleted > 0:
            log.info(
                "scan_repo.old_scans_pruned",
                domain=domain_name,
                deleted=deleted,
                kept=keep_last,
            )
        return deleted


# ==============================================================================
# REPORT REPOSITORY
# ==============================================================================

class ReportRepository(BaseRepository[Report]):
    """
    Repository for Report records.

    Manages report creation, retrieval by scan, and cleanup of
    expired or orphaned report files.
    """

    model = Report

    async def get_by_scan(self, scan_id: str, format: str | None = None) -> Report | None:
        """
        Fetch the report for a given scan, optionally filtered by format.

        Args:
            scan_id: The UUID of the parent scan.
            format:  Optional format filter ("html", "pdf", "json").
        """
        stmt = select(Report).where(Report.scan_id == scan_id)
        if format:
            stmt = stmt.where(Report.format == format)
        result = await self.session.execute(stmt.order_by(desc(Report.created_at)).limit(1))
        return result.scalar_one_or_none()

    async def list_for_domain(
        self,
        domain_name: str,
        *,
        offset: int = 0,
        limit: int = 20,
        format: str | None = None,
    ) -> list[Report]:
        """Return paginated reports for a domain."""
        stmt = (
            select(Report)
            .where(Report.domain_name == domain_name)
            .order_by(desc(Report.created_at))
            .offset(offset)
            .limit(limit)
        )
        if format:
            stmt = stmt.where(Report.format == format)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_expired(self) -> list[Report]:
        """Return all reports whose expiry date has passed."""
        now = datetime.now(timezone.utc)
        result = await self.session.execute(
            select(Report).where(
                and_(
                    Report.expires_at.is_not(None),
                    Report.expires_at <= now,
                )
            )
        )
        return list(result.scalars().all())

    async def list_recent(self, *, limit: int = 20) -> list[Report]:
        """Return the most recently generated reports across all domains."""
        result = await self.session.execute(
            select(Report)
            .order_by(desc(Report.generated_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def create_report(
        self,
        scan: Scan,
        *,
        format: str,
        file_path: str,
        file_size_bytes: int | None = None,
        title: str = "DNS Security Report",
        summary: str | None = None,
        expires_at: datetime | None = None,
    ) -> Report:
        """
        Create a new Report record for a completed scan.

        Automatically populates finding counts from the scan's findings.
        """
        report = Report(
            scan_id=scan.id,
            domain_name=scan.domain_name,
            format=format,
            file_path=file_path,
            file_size_bytes=file_size_bytes,
            title=title,
            summary=summary,
            score=scan.score,
            grade=scan.grade,
            generated_at=datetime.now(timezone.utc),
            expires_at=expires_at,
        )
        report.populate_finding_counts(scan.findings)
        return await self.create(report)

    async def delete_expired(self) -> int:
        """
        Delete all expired report records (and their files).

        Returns:
            Number of reports deleted.
        """
        import os

        expired = await self.list_expired()
        deleted = 0
        for report in expired:
            try:
                if report.file_exists:
                    os.remove(report.file_path)
            except OSError as exc:
                log.warning(
                    "report_repo.file_delete_failed",
                    report_id=report.id,
                    path=report.file_path,
                    error=str(exc),
                )
            await self.delete(report.id)
            deleted += 1

        if deleted > 0:
            log.info("report_repo.expired_reports_cleaned", count=deleted)
        return deleted