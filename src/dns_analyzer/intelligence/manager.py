from __future__ import annotations
from typing import Any
from dns_analyzer.utils.logger import get_logger
log = get_logger(__name__)

class IntelligenceManager:
    def __init__(self, providers=None): self.providers = providers or []
    @classmethod
    def from_settings(cls): return cls(providers=[])
    async def enrich_domain(self, domain: str) -> dict[str, Any]:
        return {}
    async def enrich_domain_with_findings(self, domain: str):
        return {}, []
    async def close(self): pass
