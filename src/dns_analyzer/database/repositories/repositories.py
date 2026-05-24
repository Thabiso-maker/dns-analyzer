"""
Concrete repositories for Domain, Scan, and Report models.
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


class DomainRepository(BaseRepository[Domain]):
    model = Domain

    async def get_by_name(self, name: str) -> Domain | None:
        result = await self.session.execute(
            select(Domain).where(func.lower(Domain.name) == name.lower())
        )
        return result.scalar_one_or_none()

    async def get_by_name_or_raise(self, name: str) -> Domain:
        domain = await self.get_by_name(name)
        if domain is None:
            raise RecordNotFoundError(model="Domain", identifier=name)
        return domain

    async def create_domain(self, name: str, *, description: str | None = None,
                            is_monitored: bool = False, monitor_interval_h: int = 24,
                            tags: list[str] | None = None, owner_email: str | None = None,
                            notes: str | None = None) -> Domain:
        existing = await self.get_by_name(name)
        if existing is not None:
            raise DuplicateRecordError(model="Domain", field="name", value=name)
        domain = Domain(name=name, description=description, is_monitored=is_monitored,
                        monitor_interval_h=monitor_interval_h, owner_email=owner_email, notes=notes)
        if tags:
            domain.set_tags(tags)
        return await self.create(domain)

    async def list_monitored(self) -> list[Domain]:
        result = await self.session.execute(
            select(Domain).where(Domain.is_monitored == True).order_by(Domain.last_scanned_at.asc().nulls_first())
        )
        return list(result.scalars().all())

    async def update_last_scan_summary(self, domain_id: str, *, score: int,
                                        grade: str, scanned_at: datetime) -> None:
        await self.session.execute(
            update(Domain).where(Domain.id == domain_id)
            .values(last_score=score, last_grade=grade, last_scanned_at=scanned_at)
        )

    async def search(self, query: str, *, limit: int = 20) -> list[Domain]:
        pattern = f"%{query.lower()}%"
        result = await self.session.execute(
            select(Domain).where(func.lower(Domain.name).like(pattern))
            .order_by(Domain.name.asc()).limit(limit)
        )
        return list(result.scalars().all())


class ScanRepository(BaseRepository[Scan]):
    model = Scan

    async def get_with_findings(self, scan_id: str) -> Scan | None:
        from sqlalchemy.orm import selectinload
        result = await self.session.execute(
            select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan_id)
        )
        return result.scalar_one_or_none()

    async def get_latest_for_domain(self, domain_name: str) -> Scan | None:
        result = await self.session.execute(
            select(Scan).where(and_(Scan.domain_name == domain_name, Scan.status == "completed"))
            .order_by(desc(Scan.completed_at)).limit(1)
        )
        return result.scalar_one_or_none()

    async def get_running_for_domain(self, domain_name: str) -> Scan | None:
        result = await self.session.execute(
            select(Scan).where(and_(Scan.domain_name == domain_name,
                                    Scan.status.in_(["pending", "running"])))
        )
        return result.scalar_one_or_none()

    async def list_for_domain(self, domain_name: str, *, offset: int = 0,
                               limit: int = 20, status: str | None = None) -> list[Scan]:
        stmt = (select(Scan).where(Scan.domain_name == domain_name)
                .order_by(desc(Scan.created_at)).offset(offset).limit(limit))
        if status:
            stmt = stmt.where(Scan.status == status)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_recent(self, *, limit: int = 50) -> list[Scan]:
        result = await self.session.execute(
            select(Scan).order_by(desc(Scan.created_at)).limit(limit)
        )
        return list(result.scalars().all())

    async def create_scan(self, domain_id: str, domain_name: str, *,
                          triggered_by: str = "api", requested_by_ip: str | None = None) -> Scan:
        scan = Scan(domain_id=domain_id, domain_name=domain_name,
                    triggered_by=triggered_by, requested_by_ip=requested_by_ip, status="pending")
        return await self.create(scan)

    async def save_findings(self, findings: list[Finding]) -> list[Finding]:
        return await self.bulk_create(findings)

    async def count_by_status(self) -> dict[str, int]:
        result = await self.session.execute(
            select(Scan.status, func.count(Scan.id)).group_by(Scan.status)
        )
        return {row[0]: row[1] for row in result.all()}


class ReportRepository(BaseRepository[Report]):
    model = Report

    async def get_by_scan(self, scan_id: str, format: str | None = None) -> Report | None:
        stmt = select(Report).where(Report.scan_id == scan_id)
        if format:
            stmt = stmt.where(Report.format == format)
        result = await self.session.execute(stmt.order_by(desc(Report.created_at)).limit(1))
        return result.scalar_one_or_none()

    async def list_for_domain(self, domain_name: str, *, offset: int = 0,
                               limit: int = 20, format: str | None = None) -> list[Report]:
        stmt = (select(Report).where(Report.domain_name == domain_name)
                .order_by(desc(Report.created_at)).offset(offset).limit(limit))
        if format:
            stmt = stmt.where(Report.format == format)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_recent(self, *, limit: int = 20) -> list[Report]:
        result = await self.session.execute(
            select(Report).order_by(desc(Report.generated_at)).limit(limit)
        )
        return list(result.scalars().all())

    async def list_expired(self) -> list[Report]:
        now = datetime.now(timezone.utc)
        result = await self.session.execute(
            select(Report).where(and_(Report.expires_at.is_not(None), Report.expires_at <= now))
        )
        return list(result.scalars().all())

    async def create_report(self, scan: Scan, *, format: str, file_path: str,
                             file_size_bytes: int | None = None, title: str = "DNS Security Report",
                             summary: str | None = None, expires_at: datetime | None = None) -> Report:
        report = Report(scan_id=scan.id, domain_name=scan.domain_name, format=format,
                        file_path=file_path, file_size_bytes=file_size_bytes, title=title,
                        summary=summary, score=scan.score, grade=scan.grade,
                        generated_at=datetime.now(timezone.utc), expires_at=expires_at)
        report.populate_finding_counts(scan.findings)
        return await self.create(report)

    async def delete_expired(self) -> int:
        import os
        expired = await self.list_expired()
        deleted = 0
        for report in expired:
            try:
                if report.file_exists:
                    os.remove(report.file_path)
            except OSError:
                pass
            await self.delete(report.id)
            deleted += 1
        return deleted
