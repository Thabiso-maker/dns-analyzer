"""
API v1 router — aggregates all endpoint routers under /api/v1.

Adding a new resource:
    1. Create src/dns_analyzer/api/v1/endpoints/your_resource.py
    2. Define an APIRouter with prefix and tags
    3. Include it here with api_router.include_router(...)
"""

from __future__ import annotations

from fastapi import APIRouter

from dns_analyzer.api.v1.endpoints.auth import router as auth_router
from dns_analyzer.api.v1.endpoints.domains import router as domains_router
from dns_analyzer.api.v1.endpoints.health import router as health_router
from dns_analyzer.api.v1.endpoints.reports import router as reports_router
from dns_analyzer.api.v1.endpoints.scan import router as scan_router

api_router = APIRouter()

api_router.include_router(health_router,  prefix="/health",  tags=["Health"])
api_router.include_router(auth_router,    prefix="/auth",    tags=["Authentication"])
api_router.include_router(domains_router, prefix="/domains", tags=["Domains"])
api_router.include_router(scan_router,    prefix="/scan",    tags=["Scans"])
api_router.include_router(reports_router, prefix="/reports", tags=["Reports"])