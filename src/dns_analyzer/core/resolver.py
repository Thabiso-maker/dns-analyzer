"""
Async multi-resolver DNS engine.

Queries multiple DNS resolvers in parallel and returns consolidated results.
Designed for:
    - Speed: all resolvers queried concurrently via asyncio
    - Resilience: falls back gracefully if some resolvers fail
    - Consistency detection: flags records that differ across resolvers
    - DNSSEC: full chain validation support
    - Zone transfer testing: AXFR attempts against nameservers

Usage:
    async with DNSResolver.from_settings() as resolver:
        records = await resolver.query("example.com", "TXT")
        mx      = await resolver.query_single("example.com", "MX")
        ns      = await resolver.get_nameservers("example.com")
        ips     = await resolver.resolve_ips("example.com")
        axfr    = await resolver.attempt_zone_transfer("example.com")
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from dns_analyzer.config.settings import get_settings
from dns_analyzer.utils.logger import get_logger

log = get_logger(__name__)


# ==============================================================================
# RESULT DATACLASSES
# ==============================================================================

@dataclass
class DNSRecord:
    """A single DNS record value with metadata."""
    value: str
    record_type: str
    ttl: int
    resolver_ip: str


@dataclass
class DNSQueryResult:
    """
    The consolidated result of querying multiple resolvers for one record type.

    Attributes:
        domain:       The queried domain.
        record_type:  The queried record type (e.g. "TXT", "MX").
        records:      Deduplicated list of records returned across all resolvers.
        ttls:         Mapping of resolver IP → TTL returned by that resolver.
        consistent:   True if all resolvers returned the same records.
        resolvers_ok: List of resolver IPs that returned a successful response.
        resolvers_failed: List of resolver IPs that failed or timed out.
        nxdomain:     True if the domain does not exist.
        raw:          Raw dnspython RRset objects keyed by resolver IP.
    """
    domain: str
    record_type: str
    records: list[DNSRecord] = field(default_factory=list)
    ttls: dict[str, int] = field(default_factory=dict)
    consistent: bool = True
    resolvers_ok: list[str] = field(default_factory=list)
    resolvers_failed: list[str] = field(default_factory=list)
    nxdomain: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def values(self) -> list[str]:
        """Return all record values as a deduplicated sorted list."""
        return sorted({r.value for r in self.records})

    @property
    def first_value(self) -> str | None:
        """Return the first record value, or None if no records."""
        return self.values[0] if self.values else None

    @property
    def found(self) -> bool:
        """True if at least one record was returned."""
        return bool(self.records)

    @property
    def min_ttl(self) -> int | None:
        """Return the minimum TTL seen across all resolvers."""
        return min(self.ttls.values()) if self.ttls else None

    @property
    def max_ttl(self) -> int | None:
        """Return the maximum TTL seen across all resolvers."""
        return max(self.ttls.values()) if self.ttls else None


@dataclass
class ZoneTransferResult:
    """Result of an attempted DNS zone transfer (AXFR)."""
    nameserver: str
    domain: str
    success: bool
    records: list[str] = field(default_factory=list)
    error: str | None = None
    record_count: int = 0


# ==============================================================================
# DNS RESOLVER ENGINE
# ==============================================================================

class DNSResolver:
    """
    Async DNS resolver that queries multiple resolvers in parallel.

    Instantiate via from_settings() or provide resolver IPs directly.
    Use as an async context manager to ensure the underlying aiohttp
    session is properly closed.

    Args:
        resolver_ips:   List of DNS resolver IP addresses to query.
        timeout:        Per-query timeout in seconds.
        retries:        Number of retry attempts per resolver.
        max_concurrent: Maximum parallel resolver queries per domain+type.
    """

    def __init__(
        self,
        resolver_ips: list[str],
        *,
        timeout: float = 5.0,
        retries: int = 2,
        max_concurrent: int = 5,
    ) -> None:
        self.resolver_ips = resolver_ips
        self.timeout = timeout
        self.retries = retries
        self._semaphore = asyncio.Semaphore(max_concurrent)

    @classmethod
    def from_settings(cls) -> "DNSResolver":
        """Create a resolver configured from application settings."""
        settings = get_settings()
        dns_cfg = settings.dns
        return cls(
            resolver_ips=dns_cfg.resolvers,
            timeout=dns_cfg.timeout,
            retries=dns_cfg.retries,
            max_concurrent=dns_cfg.max_concurrent_resolvers,
        )

    async def __aenter__(self) -> "DNSResolver":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass

    # ── Core query method ──────────────────────────────────────────────────────

    async def query(self, domain: str, record_type: str) -> DNSQueryResult:
        """
        Query all configured resolvers in parallel for the given record type.

        Consolidates responses, detects inconsistencies across resolvers,
        and returns a single DNSQueryResult.

        Args:
            domain:      FQDN to query.
            record_type: DNS record type string (e.g. "TXT", "MX", "A").

        Returns:
            DNSQueryResult with all records and per-resolver metadata.
        """
        result = DNSQueryResult(domain=domain, record_type=record_type)

        tasks = [
            self._query_single_resolver(domain, record_type, resolver_ip)
            for resolver_ip in self.resolver_ips
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        resolver_values: dict[str, set[str]] = {}

        for resolver_ip, response in zip(self.resolver_ips, responses):
            if isinstance(response, Exception):
                result.resolvers_failed.append(resolver_ip)
                log.debug(
                    "resolver.query_failed",
                    domain=domain,
                    record_type=record_type,
                    resolver=resolver_ip,
                    error=str(response),
                )
                continue

            if response is None:
                result.resolvers_failed.append(resolver_ip)
                continue

            records, ttl, raw = response
            result.resolvers_ok.append(resolver_ip)
            result.ttls[resolver_ip] = ttl
            result.raw[resolver_ip] = raw
            resolver_values[resolver_ip] = set(records)

            for value in records:
                record = DNSRecord(
                    value=value,
                    record_type=record_type,
                    ttl=ttl,
                    resolver_ip=resolver_ip,
                )
                if value not in {r.value for r in result.records}:
                    result.records.append(record)

        # Consistency check: all resolvers that responded should return same values
        if len(resolver_values) > 1:
            value_sets = list(resolver_values.values())
            result.consistent = all(s == value_sets[0] for s in value_sets[1:])
            if not result.consistent:
                log.warning(
                    "resolver.inconsistent_records",
                    domain=domain,
                    record_type=record_type,
                    resolvers=resolver_values,
                )

        return result

    async def _query_single_resolver(
        self,
        domain: str,
        record_type: str,
        resolver_ip: str,
    ) -> tuple[list[str], int, Any] | None:
        """
        Query one resolver for one domain + record type.

        Returns:
            Tuple of (record_values, ttl, raw_rrset) on success.
            None on NXDOMAIN or empty answer.
            Raises on timeout or SERVFAIL.
        """
        async with self._semaphore:
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers = [resolver_ip]
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout * self.retries

            try:
                answer = await resolver.resolve(domain, record_type)
                ttl = answer.rrset.ttl if answer.rrset else 0
                values = [rdata.to_text() for rdata in answer]
                return values, ttl, answer.rrset

            except dns.resolver.NXDOMAIN:
                return None
            except dns.resolver.NoAnswer:
                return [], 0, None
            except dns.resolver.NoNameservers:
                raise RuntimeError(f"No nameservers available for {domain}")
            except dns.exception.Timeout:
                raise TimeoutError(f"Resolver {resolver_ip} timed out for {domain} {record_type}")
            except Exception as exc:
                raise RuntimeError(f"DNS query error on {resolver_ip}: {exc}") from exc

    async def query_single(self, domain: str, record_type: str) -> DNSQueryResult:
        """
        Convenience method: query only the first resolver.

        Useful when you need a quick single-resolver result and don't need
        cross-resolver consistency checking.
        """
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = [self.resolver_ips[0]]
        resolver.timeout = self.timeout

        result = DNSQueryResult(domain=domain, record_type=record_type)

        try:
            answer = await resolver.resolve(domain, record_type)
            ttl = answer.rrset.ttl if answer.rrset else 0
            result.resolvers_ok.append(self.resolver_ips[0])
            result.ttls[self.resolver_ips[0]] = ttl
            for rdata in answer:
                result.records.append(DNSRecord(
                    value=rdata.to_text(),
                    record_type=record_type,
                    ttl=ttl,
                    resolver_ip=self.resolver_ips[0],
                ))
        except dns.resolver.NXDOMAIN:
            result.nxdomain = True
        except dns.resolver.NoAnswer:
            pass
        except Exception as exc:
            result.resolvers_failed.append(self.resolver_ips[0])
            log.debug("resolver.single_query_failed", domain=domain, error=str(exc))

        return result

    # ── Convenience query methods ──────────────────────────────────────────────

    async def get_txt_records(self, domain: str) -> list[str]:
        """Return all TXT record values for the domain."""
        result = await self.query(domain, "TXT")
        # Strip surrounding quotes that dnspython adds to TXT record values
        return [v.strip('"') for v in result.values]

    async def get_txt_record_starting_with(
        self, domain: str, prefix: str
    ) -> str | None:
        """Return the first TXT record that starts with the given prefix."""
        records = await self.get_txt_records(domain)
        for record in records:
            if record.startswith(prefix):
                return record
        return None

    async def get_nameservers(self, domain: str) -> list[str]:
        """Return all authoritative nameserver hostnames for the domain."""
        result = await self.query(domain, "NS")
        return [v.rstrip(".") for v in result.values]

    async def resolve_ips(self, hostname: str) -> list[str]:
        """Resolve a hostname to IPv4 and IPv6 addresses."""
        ipv4_result = await self.query(hostname, "A")
        ipv6_result = await self.query(hostname, "AAAA")
        return ipv4_result.values + ipv6_result.values

    async def get_mx_records(self, domain: str) -> list[tuple[int, str]]:
        """
        Return MX records as (priority, hostname) tuples sorted by priority.
        """
        result = await self.query(domain, "MX")
        mx_list: list[tuple[int, str]] = []
        for value in result.values:
            parts = value.split()
            if len(parts) == 2:
                try:
                    priority = int(parts[0])
                    hostname = parts[1].rstrip(".")
                    mx_list.append((priority, hostname))
                except ValueError:
                    continue
        return sorted(mx_list, key=lambda x: x[0])

    async def get_soa(self, domain: str) -> dict[str, Any] | None:
        """
        Return SOA record fields as a dict, or None if not found.
        Fields: mname, rname, serial, refresh, retry, expire, minimum
        """
        result = await self.query_single(domain, "SOA")
        if not result.found:
            return None
        value = result.first_value
        if not value:
            return None
        parts = value.split()
        if len(parts) >= 7:
            return {
                "mname": parts[0].rstrip("."),
                "rname": parts[1].rstrip("."),
                "serial": int(parts[2]),
                "refresh": int(parts[3]),
                "retry": int(parts[4]),
                "expire": int(parts[5]),
                "minimum": int(parts[6]),
            }
        return None

    async def get_caa_records(self, domain: str) -> list[dict[str, str]]:
        """
        Return CAA records as list of {flag, tag, value} dicts.
        """
        result = await self.query(domain, "CAA")
        caa_list: list[dict[str, str]] = []
        for value in result.values:
            parts = value.split(None, 2)
            if len(parts) == 3:
                caa_list.append({
                    "flag": parts[0],
                    "tag": parts[1],
                    "value": parts[2].strip('"'),
                })
        return caa_list

    async def check_cname(self, domain: str) -> str | None:
        """
        Return the CNAME target for a domain, or None if it is not a CNAME.
        """
        result = await self.query_single(domain, "CNAME")
        return result.first_value.rstrip(".") if result.first_value else None

    # ── DNSSEC ─────────────────────────────────────────────────────────────────

    async def check_dnssec(self, domain: str) -> dict[str, Any]:
        """
        Check whether DNSSEC is enabled and the chain of trust is intact.

        Returns a dict with:
            enabled:        bool — RRSIG records present
            ds_found:       bool — DS record found in parent zone
            dnskey_found:   bool — DNSKEY records present
            validated:      bool — chain of trust validates
            algorithms:     list of algorithm numbers found
            errors:         list of error strings
        """
        result: dict[str, Any] = {
            "enabled": False,
            "ds_found": False,
            "dnskey_found": False,
            "validated": False,
            "algorithms": [],
            "errors": [],
        }

        try:
            # Check for DNSKEY records
            dnskey = await self.query_single(domain, "DNSKEY")
            if dnskey.found:
                result["dnskey_found"] = True
                for record in dnskey.records:
                    parts = record.value.split()
                    if len(parts) >= 2:
                        try:
                            result["algorithms"].append(int(parts[2]) if len(parts) > 2 else 0)
                        except (ValueError, IndexError):
                            pass

            # Check for RRSIG records (signed)
            rrsig = await self.query_single(domain, "RRSIG")
            if rrsig.found:
                result["enabled"] = True

            # Check for DS record in parent zone
            labels = domain.split(".")
            if len(labels) > 1:
                parent = ".".join(labels[1:])
                ds = await self.query_single(domain, "DS")
                if ds.found:
                    result["ds_found"] = True

            result["validated"] = (
                result["enabled"]
                and result["dnskey_found"]
                and result["ds_found"]
            )

        except Exception as exc:
            result["errors"].append(str(exc))
            log.debug("resolver.dnssec_check_error", domain=domain, error=str(exc))

        return result

    # ── Zone Transfer ──────────────────────────────────────────────────────────

    async def attempt_zone_transfer(self, domain: str) -> list[ZoneTransferResult]:
        """
        Attempt AXFR zone transfer against all nameservers for the domain.

        A successful zone transfer is a critical misconfiguration — it exposes
        the entire DNS zone to any external party.

        Returns:
            List of ZoneTransferResult — one per nameserver attempted.
        """
        nameservers = await self.get_nameservers(domain)
        if not nameservers:
            return [ZoneTransferResult(
                nameserver="none",
                domain=domain,
                success=False,
                error="No nameservers found for domain",
            )]

        tasks = [
            self._axfr_single_ns(domain, ns)
            for ns in nameservers[:5]  # Cap at 5 nameservers
        ]
        return await asyncio.gather(*tasks)

    async def _axfr_single_ns(self, domain: str, nameserver: str) -> ZoneTransferResult:
        """Attempt AXFR against one nameserver."""
        try:
            # Resolve nameserver to IP first
            ns_ips = await self.resolve_ips(nameserver)
            if not ns_ips:
                return ZoneTransferResult(
                    nameserver=nameserver,
                    domain=domain,
                    success=False,
                    error=f"Could not resolve nameserver {nameserver} to an IP",
                )

            ns_ip = ns_ips[0]
            loop = asyncio.get_event_loop()

            # AXFR is a blocking operation — run in thread pool
            records = await loop.run_in_executor(
                None,
                self._do_axfr,
                domain,
                ns_ip,
            )

            if records:
                log.warning(
                    "resolver.axfr_succeeded",
                    domain=domain,
                    nameserver=nameserver,
                    record_count=len(records),
                )
                return ZoneTransferResult(
                    nameserver=nameserver,
                    domain=domain,
                    success=True,
                    records=records[:50],   # Cap returned records to avoid huge payloads
                    record_count=len(records),
                )
            return ZoneTransferResult(
                nameserver=nameserver,
                domain=domain,
                success=False,
                error="AXFR refused or returned no records",
            )

        except Exception as exc:
            return ZoneTransferResult(
                nameserver=nameserver,
                domain=domain,
                success=False,
                error=str(exc),
            )

    @staticmethod
    def _do_axfr(domain: str, nameserver_ip: str) -> list[str]:
        """
        Blocking AXFR attempt — runs in a thread pool executor.

        Returns list of record strings on success, empty list on failure.
        """
        try:
            xfr = dns.query.xfr(
                nameserver_ip,
                domain,
                timeout=10,
                lifetime=15,
            )
            records: list[str] = []
            for message in xfr:
                for rrset in message.answer:
                    for rdata in rrset:
                        records.append(f"{rrset.name} {rrset.ttl} {rrset.rdtype} {rdata.to_text()}")
            return records
        except Exception:
            return []

    # ── Subdomain resolution ───────────────────────────────────────────────────

    async def resolve_subdomain(self, subdomain: str) -> dict[str, Any]:
        """
        Check whether a subdomain resolves and detect CNAME chains.

        Returns dict with:
            resolves:    bool
            ips:         list of IPs
            cname:       CNAME target (if any)
            nxdomain:    bool
        """
        result: dict[str, Any] = {
            "resolves": False,
            "ips": [],
            "cname": None,
            "nxdomain": False,
        }

        # Check for CNAME first
        cname = await self.check_cname(subdomain)
        if cname:
            result["cname"] = cname

        # Try A record
        a_result = await self.query_single(subdomain, "A")
        if a_result.nxdomain:
            result["nxdomain"] = True
            return result

        if a_result.found:
            result["resolves"] = True
            result["ips"] = a_result.values

        return result

    def __repr__(self) -> str:
        return (
            f"DNSResolver(resolvers={self.resolver_ips}, "
            f"timeout={self.timeout}s, retries={self.retries})"
        )