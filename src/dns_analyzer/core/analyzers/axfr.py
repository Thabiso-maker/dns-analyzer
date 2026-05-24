"""
Remaining DNS security analyzers:
    - DKIMAnalyzer    : DKIM selector discovery and key strength
    - DNSSECAnalyzer  : DNSSEC chain of trust validation
    - AXFRAnalyzer    : Zone transfer vulnerability test
    - CAAAnalyzer     : CAA record presence and configuration
    - MTASTSAnalyzer  : MTA-STS policy and TLSRPT record
    - SubdomainAnalyzer: Subdomain enumeration and takeover detection
    - TTLAnalyzer     : TTL anomaly and cross-resolver consistency
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from dns_analyzer.config.constants import (
    CAA_TAGS,
    DKIM,
    DNSSEC,
    MTA_STS_POLICY_URL,
    TAKEOVER_FINGERPRINTS,
    TLSRPT_RECORD_PREFIX,
)
from dns_analyzer.config.settings import get_settings
from dns_analyzer.core.base_analyzer import AnalyzerResult, BaseAnalyzer

if TYPE_CHECKING:
    from dns_analyzer.core.resolver import DNSResolver


# ==============================================================================
# DKIM ANALYZER
# ==============================================================================

class DKIMAnalyzer(BaseAnalyzer):
    """
    Checks for DKIM selectors, validates key strength, and detects weak keys.

    Brute-forces common DKIM selectors and checks configured selectors
    from the wordlist for RSA key size (minimum 1024, recommended 2048 bits).
    """

    name = "dkim"
    description = "Discovers DKIM selectors and validates cryptographic key strength"
    timeout_seconds = 30.0

    async def analyze(self, domain: str, resolver: "DNSResolver") -> list[AnalyzerResult]:
        results: list[AnalyzerResult] = []
        settings = get_settings()

        # Build selector list: common selectors + wordlist
        selectors = list(DKIM.COMMON_SELECTORS)
        wordlist_path = Path(settings.dns.dkim_selectors_path)
        if wordlist_path.exists():
            extra = wordlist_path.read_text().splitlines()
            selectors.extend([s.strip() for s in extra if s.strip()])

        selectors = list(dict.fromkeys(selectors))  # Deduplicate, preserve order

        # Query all selectors concurrently
        tasks = {
            selector: resolver.get_txt_record_starting_with(
                f"{selector}{DKIM.RECORD_SUFFIX}.{domain}", "v=DKIM1"
            )
            for selector in selectors
        }

        found_selectors: dict[str, str] = {}
        query_results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for selector, result in zip(tasks.keys(), query_results):
            if isinstance(result, Exception) or result is None:
                continue
            found_selectors[selector] = result

        # ── No DKIM selectors found ───────────────────────────────────────────
        if not found_selectors:
            return [self.fail(
                check="dkim_selector_found",
                title="No DKIM selectors found",
                description=(
                    f"No DKIM TXT records were found for {domain} after checking "
                    f"{len(selectors)} common selectors. Without DKIM, email from "
                    "your domain cannot be cryptographically signed, making it easier "
                    "to forge and reducing deliverability."
                ),
                severity="high",
                cvss_score=6.5,
                remediation=(
                    "Configure DKIM signing with your mail provider and publish the "
                    "public key as a TXT record at <selector>._domainkey.<domain>. "
                    "Use a 2048-bit RSA key or an Ed25519 key."
                ),
                reference_url="https://datatracker.ietf.org/doc/html/rfc6376",
            )]

        results.append(self.pass_check(
            check="dkim_selector_found",
            title=f"DKIM selectors found: {', '.join(found_selectors.keys())}",
            description=f"Found {len(found_selectors)} active DKIM selector(s) for {domain}.",
            evidence="\n".join(f"{s}: {v}" for s, v in found_selectors.items()),
        ))

        # ── Key strength validation ───────────────────────────────────────────
        for selector, record in found_selectors.items():
            key_check = self._check_key_strength(selector, record)
            if key_check:
                results.append(key_check)

        return results

    def _check_key_strength(self, selector: str, record: str) -> AnalyzerResult | None:
        """Check RSA key size in a DKIM record."""
        import re
        p_match = re.search(r"\bp=([A-Za-z0-9+/=]+)", record)
        if not p_match:
            return self.fail(
                check="dkim_key_present",
                title=f"DKIM selector '{selector}' has no public key (p=)",
                description=(
                    f"The DKIM record for selector '{selector}' has an empty or missing p= tag. "
                    "This selector has been revoked and cannot be used for signing."
                ),
                severity="medium",
                evidence=record,
            )

        import base64
        try:
            key_bytes = base64.b64decode(p_match.group(1))
            # RSA public key DER: first bytes indicate key size
            key_bits = len(key_bytes) * 8

            if key_bits < DKIM.MIN_KEY_BITS:
                return self.fail(
                    check="dkim_key_strength",
                    title=f"DKIM selector '{selector}' uses a weak key (<{DKIM.MIN_KEY_BITS} bits)",
                    description=(
                        f"The RSA key for DKIM selector '{selector}' appears to be approximately "
                        f"{key_bits} bits, below the minimum recommended size of {DKIM.MIN_KEY_BITS} bits."
                    ),
                    severity="high",
                    evidence=record,
                    cvss_score=7.0,
                    remediation=f"Rotate to a {DKIM.RECOMMENDED_KEY_BITS}-bit RSA key or an Ed25519 key.",
                )
        except Exception:
            pass  # Key format not parseable — skip size check

        return None


# ==============================================================================
# DNSSEC ANALYZER
# ==============================================================================

class DNSSECAnalyzer(BaseAnalyzer):
    """Validates DNSSEC chain of trust — DNSKEY, DS, and RRSIG records."""

    name = "dnssec"
    description = "Validates DNSSEC chain of trust including DNSKEY, DS, and RRSIG records"
    timeout_seconds = 20.0

    async def analyze(self, domain: str, resolver: "DNSResolver") -> list[AnalyzerResult]:
        results: list[AnalyzerResult] = []
        dnssec = await resolver.check_dnssec(domain)

        # ── DNSKEY present ────────────────────────────────────────────────────
        if not dnssec["dnskey_found"]:
            results.append(self.fail(
                check="dnssec_dnskey",
                title="No DNSKEY records found — DNSSEC not configured",
                description=(
                    f"No DNSKEY records were found for {domain}. "
                    "Without DNSSEC, DNS responses can be forged (cache poisoning), "
                    "redirecting users to malicious servers without their knowledge."
                ),
                severity="medium",
                cvss_score=5.0,
                remediation=(
                    "Enable DNSSEC in your DNS registrar and hosting provider. "
                    "Most modern registrars support DNSSEC with a single click. "
                    "Ensure DS records are published in the parent zone."
                ),
                reference_url="https://datatracker.ietf.org/doc/html/rfc4033",
            ))
            return results

        results.append(self.pass_check(
            check="dnssec_dnskey",
            title="DNSKEY records found",
            description="DNSKEY records are present for this domain.",
        ))

        # ── DS record in parent ───────────────────────────────────────────────
        if not dnssec["ds_found"]:
            results.append(self.fail(
                check="dnssec_ds",
                title="No DS record found in parent zone",
                description=(
                    "DNSKEY records exist but no DS (Delegation Signer) record was found "
                    "in the parent zone. Without DS records, resolvers cannot establish "
                    "the chain of trust and will treat the zone as unsigned."
                ),
                severity="high",
                cvss_score=7.0,
                remediation=(
                    "Publish the DS record at your domain registrar. "
                    "Generate it from your DNSKEY and submit it via your registrar's control panel."
                ),
            ))
        else:
            results.append(self.pass_check(
                check="dnssec_ds",
                title="DS record found in parent zone",
                description="The DS record is properly published, establishing the chain of trust.",
            ))

        # ── RRSIG (signed) ────────────────────────────────────────────────────
        if not dnssec["enabled"]:
            results.append(self.fail(
                check="dnssec_rrsig",
                title="No RRSIG records found — zone is not signed",
                description="DNSKEY exists but no RRSIG records were found. The zone may not be actively signing.",
                severity="high",
                remediation="Ensure your DNS server is actively signing the zone and RRSIG records are published.",
            ))
        else:
            results.append(self.pass_check(
                check="dnssec_rrsig",
                title="RRSIG records present — zone is signed",
                description="RRSIG records confirm the zone is being actively signed.",
            ))

        # ── Algorithm strength ────────────────────────────────────────────────
        for algo_num in dnssec.get("algorithms", []):
            if algo_num in DNSSEC.WEAK_ALGORITHMS:
                algo_name = DNSSEC.ALGORITHM_NAMES.get(algo_num, f"Algorithm {algo_num}")
                results.append(self.fail(
                    check="dnssec_algorithm",
                    title=f"DNSSEC uses weak algorithm: {algo_name}",
                    description=(
                        f"The DNSSEC algorithm {algo_name} (algorithm number {algo_num}) "
                        "is considered weak. Modern resolvers prefer ECDSA (algorithm 13) "
                        "or Ed25519 (algorithm 15)."
                    ),
                    severity="medium",
                    cvss_score=4.0,
                    remediation=(
                        "Migrate to ECDSA P-256 (algorithm 13) or Ed25519 (algorithm 15). "
                        "Coordinate with your DNS provider for a key rollover."
                    ),
                ))

        # ── Full chain validation ─────────────────────────────────────────────
        if dnssec["validated"]:
            results.append(self.pass_check(
                check="dnssec_chain",
                title="DNSSEC chain of trust is complete",
                description="DNSKEY, DS, and RRSIG records are all present and the chain of trust is intact.",
            ))

        return results


# ==============================================================================
# AXFR ANALYZER
# ==============================================================================

class AXFRAnalyzer(BaseAnalyzer):
    """
    Tests for zone transfer (AXFR) vulnerability.

    A successful zone transfer exposes the complete DNS zone to any external
    party — this is a critical misconfiguration that maps the entire
    infrastructure and enables targeted attacks.
    """

    name = "axfr"
    description = "Tests whether DNS zone transfers (AXFR) are permitted from external hosts"
    timeout_seconds = 30.0

    async def analyze(self, domain: str, resolver: "DNSResolver") -> list[AnalyzerResult]:
        results: list[AnalyzerResult] = []
        xfr_results = await resolver.attempt_zone_transfer(domain)

        vulnerable_ns = [r for r in xfr_results if r.success]
        secure_ns     = [r for r in xfr_results if not r.success]

        if vulnerable_ns:
            exposed_records = "\n".join(
                f"{r.nameserver}: {r.record_count} records exposed"
                for r in vulnerable_ns
            )
            sample = "\n".join(vulnerable_ns[0].records[:10]) if vulnerable_ns[0].records else ""

            results.append(self.fail(
                check="axfr_refused",
                title=f"Zone transfer (AXFR) succeeded on {len(vulnerable_ns)} nameserver(s) — CRITICAL",
                description=(
                    f"A full zone transfer was successfully performed against "
                    f"{len(vulnerable_ns)} nameserver(s) for {domain}. This exposes "
                    "all DNS records (subdomains, mail servers, internal infrastructure) "
                    "to any external party, providing a complete attack map of your domain."
                ),
                severity="critical",
                evidence=exposed_records + ("\n\nSample records:\n" + sample if sample else ""),
                affected_record=", ".join(r.nameserver for r in vulnerable_ns),
                cvss_score=9.8,
                remediation=(
                    "Immediately restrict zone transfers on all nameservers:\n"
                    "  BIND: allow-transfer { none; };\n"
                    "  Windows DNS: disable zone transfer in DNS Manager > Zone Properties\n"
                    "  PowerDNS: allow-axfr-ips = 127.0.0.1\n"
                    "Only allow transfers to secondary nameservers by their explicit IP."
                ),
                reference_url="https://attack.mitre.org/techniques/T1590/002/",
            ))
        else:
            results.append(self.pass_check(
                check="axfr_refused",
                title="Zone transfer (AXFR) correctly refused on all nameservers",
                description=(
                    f"Zone transfer attempts were refused by all {len(secure_ns)} "
                    f"nameserver(s) tested: {', '.join(r.nameserver for r in secure_ns)}."
                ),
            ))

        return results


# ==============================================================================
# CAA ANALYZER
# ==============================================================================

class CAAAnalyzer(BaseAnalyzer):
    """
    Checks CAA (Certification Authority Authorization) records.

    CAA records restrict which Certificate Authorities are permitted to
    issue TLS certificates for the domain, preventing rogue cert issuance.
    """

    name = "caa"
    description = "Checks CAA records to restrict unauthorized TLS certificate issuance"
    timeout_seconds = 15.0

    async def analyze(self, domain: str, resolver: "DNSResolver") -> list[AnalyzerResult]:
        results: list[AnalyzerResult] = []
        caa_records = await resolver.get_caa_records(domain)

        # ── CAA record exists ─────────────────────────────────────────────────
        if not caa_records:
            results.append(self.fail(
                check="caa_exists",
                title="No CAA records found",
                description=(
                    f"No CAA records were found for {domain}. Without CAA records, "
                    "any Certificate Authority can issue TLS certificates for your domain. "
                    "A compromised or rogue CA could issue fraudulent certificates, "
                    "enabling HTTPS man-in-the-middle attacks."
                ),
                severity="medium",
                cvss_score=5.0,
                remediation=(
                    "Add CAA records to restrict certificate issuance to your CA:\n"
                    f'  {domain}. CAA 0 issue "letsencrypt.org"\n'
                    f'  {domain}. CAA 0 issuewild "letsencrypt.org"\n'
                    f'  {domain}. CAA 0 iodef "mailto:security@{domain}"\n'
                    "Replace letsencrypt.org with your actual CA."
                ),
                reference_url="https://datatracker.ietf.org/doc/html/rfc8659",
            ))
            return results

        evidence = "\n".join(
            f"{r['flag']} {r['tag']} {r['value']}" for r in caa_records
        )
        results.append(self.pass_check(
            check="caa_exists",
            title=f"CAA records found ({len(caa_records)} record(s))",
            description=f"CAA records restrict certificate issuance for {domain}.",
            evidence=evidence,
        ))

        # ── iodef (incident reporting) ────────────────────────────────────────
        has_iodef = any(r["tag"] == "iodef" for r in caa_records)
        if not has_iodef:
            results.append(self.info(
                check="caa_iodef",
                title="No CAA iodef (incident reporting) record",
                description=(
                    "No iodef= tag found. Adding iodef=mailto:security@yourdomain.com "
                    "allows CAs to notify you if an unauthorized certificate request is made."
                ),
            ))

        # ── issuewild ─────────────────────────────────────────────────────────
        has_issuewild = any(r["tag"] == "issuewild" for r in caa_records)
        has_issue     = any(r["tag"] == "issue" for r in caa_records)
        if has_issue and not has_issuewild:
            results.append(self.info(
                check="caa_issuewild",
                title="No CAA issuewild record — wildcard certs may be unrestricted",
                description=(
                    "CAA 'issue' records restrict non-wildcard certificates, but without "
                    "'issuewild', wildcard certificate issuance (*.domain.com) may fall "
                    "back to the 'issue' restriction or be treated as unrestricted by some CAs."
                ),
                evidence=evidence,
            ))

        return results


# ==============================================================================
# MTA-STS ANALYZER
# ==============================================================================

class MTASTSAnalyzer(BaseAnalyzer):
    """
    Checks MTA-STS (Mail Transfer Agent Strict Transport Security) and TLSRPT.

    MTA-STS forces TLS encryption for inbound email delivery, preventing
    SMTP downgrade attacks. TLSRPT provides reporting on TLS failures.
    """

    name = "mta_sts"
    description = "Checks MTA-STS policy and TLSRPT reporting configuration"
    timeout_seconds = 20.0

    async def analyze(self, domain: str, resolver: "DNSResolver") -> list[AnalyzerResult]:
        results: list[AnalyzerResult] = []

        # ── MTA-STS DNS record ────────────────────────────────────────────────
        mta_sts_domain = f"_mta-sts.{domain}"
        mta_sts_record = await resolver.get_txt_record_starting_with(mta_sts_domain, "v=STSv1")

        if not mta_sts_record:
            results.append(self.fail(
                check="mta_sts_record",
                title="No MTA-STS DNS record found",
                description=(
                    f"No MTA-STS TXT record was found at {mta_sts_domain}. "
                    "Without MTA-STS, email delivered to your domain is vulnerable to "
                    "SMTP downgrade attacks and man-in-the-middle interception of inbound mail."
                ),
                severity="medium",
                cvss_score=5.5,
                remediation=(
                    f"Add a TXT record at _mta-sts.{domain}:\n"
                    "  v=STSv1; id=20240101T000000\n"
                    f"And publish an MTA-STS policy at {MTA_STS_POLICY_URL.format(domain=domain)}"
                ),
                reference_url="https://datatracker.ietf.org/doc/html/rfc8461",
            ))
        else:
            results.append(self.pass_check(
                check="mta_sts_record",
                title="MTA-STS DNS record found",
                description="MTA-STS is configured for this domain.",
                evidence=mta_sts_record,
            ))

            # Check policy mode via HTTPS fetch
            policy_result = await self._fetch_mta_sts_policy(domain)
            if policy_result:
                results.append(policy_result)

        # ── TLSRPT record ─────────────────────────────────────────────────────
        tlsrpt_domain = f"_smtp._tls.{domain}"
        tlsrpt_record = await resolver.get_txt_record_starting_with(
            tlsrpt_domain, TLSRPT_RECORD_PREFIX
        )

        if not tlsrpt_record:
            results.append(self.info(
                check="tlsrpt_record",
                title="No TLSRPT record found",
                description=(
                    "No TLSRPT TXT record found at _smtp._tls.{domain}. "
                    "TLSRPT provides reports about TLS negotiation failures for inbound email. "
                    "While optional, it's recommended for visibility."
                ),
            ))
        else:
            results.append(self.pass_check(
                check="tlsrpt_record",
                title="TLSRPT record found",
                description="TLS failure reporting is configured.",
                evidence=tlsrpt_record,
            ))

        return results

    async def _fetch_mta_sts_policy(self, domain: str) -> AnalyzerResult | None:
        """Attempt to fetch the MTA-STS policy file via HTTPS."""
        import aiohttp
        url = MTA_STS_POLICY_URL.format(domain=domain)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        if "mode: enforce" in content:
                            return self.pass_check(
                                check="mta_sts_policy_mode",
                                title="MTA-STS policy mode is 'enforce'",
                                description="The MTA-STS policy enforces TLS for inbound email delivery.",
                                evidence=content[:500],
                            )
                        elif "mode: testing" in content:
                            return self.fail(
                                check="mta_sts_policy_mode",
                                title="MTA-STS policy mode is 'testing' — not enforced",
                                description=(
                                    "The MTA-STS policy is in 'testing' mode. TLS is not enforced. "
                                    "Change to 'enforce' once you have verified your mail servers support TLS."
                                ),
                                severity="low",
                                evidence=content[:500],
                                remediation="Change 'mode: testing' to 'mode: enforce' in your MTA-STS policy file.",
                            )
        except Exception:
            pass
        return None


# ==============================================================================
# SUBDOMAIN ANALYZER
# ==============================================================================

class SubdomainAnalyzer(BaseAnalyzer):
    """
    Enumerates subdomains and detects subdomain takeover vulnerabilities.

    Uses a wordlist to brute-force common subdomains, then checks each
    discovered subdomain for dangling CNAME records pointing to unclaimed
    third-party services (GitHub Pages, Heroku, S3, etc.)
    """

    name = "subdomain"
    description = "Enumerates subdomains and detects dangling DNS / subdomain takeover vulnerabilities"
    timeout_seconds = 60.0

    async def analyze(self, domain: str, resolver: "DNSResolver") -> list[AnalyzerResult]:
        results: list[AnalyzerResult] = []
        settings = get_settings()

        wordlist_path = Path(settings.dns.subdomain_wordlist_path)
        if not wordlist_path.exists():
            return [self.info(
                check="subdomain_enumeration",
                title="Subdomain wordlist not found — enumeration skipped",
                description=f"Wordlist file not found at {wordlist_path}. Subdomain enumeration was skipped.",
            )]

        subdomains = wordlist_path.read_text().splitlines()
        subdomains = [s.strip() for s in subdomains if s.strip() and not s.startswith("#")]

        semaphore = asyncio.Semaphore(settings.dns.subdomain_max_concurrent)
        tasks = [
            self._check_subdomain(f"{sub}.{domain}", resolver, semaphore)
            for sub in subdomains
        ]

        subdomain_results = await asyncio.gather(*tasks, return_exceptions=True)

        found: list[str] = []
        takeover_risks: list[dict] = []

        for result in subdomain_results:
            if isinstance(result, Exception) or result is None:
                continue
            subdomain, resolves, cname, is_takeover_risk, service = result
            if resolves or cname:
                found.append(subdomain)
            if is_takeover_risk:
                takeover_risks.append({
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": service,
                })

        # ── Summary result ────────────────────────────────────────────────────
        results.append(self.info(
            check="subdomain_enumeration",
            title=f"Subdomain enumeration complete — {len(found)} found",
            description=(
                f"Enumerated {len(subdomains)} common subdomains. "
                f"Found {len(found)} active subdomains."
            ),
            evidence="\n".join(found[:50]) if found else "No subdomains found",
            extra={"found_count": len(found), "subdomains": found[:100]},
        ))

        # ── Takeover risks ────────────────────────────────────────────────────
        for risk in takeover_risks:
            results.append(self.fail(
                check="subdomain_takeover",
                title=f"Potential subdomain takeover: {risk['subdomain']}",
                description=(
                    f"The subdomain {risk['subdomain']} has a CNAME pointing to "
                    f"{risk['cname']!r} ({risk['service']}), which appears to be unclaimed. "
                    "An attacker could register this service and serve malicious content "
                    "from your subdomain."
                ),
                severity="high",
                evidence=f"CNAME: {risk['cname']}",
                affected_record=risk["subdomain"],
                cvss_score=8.0,
                remediation=(
                    f"Either claim the {risk['service']} resource that {risk['cname']!r} "
                    f"points to, or remove the CNAME record for {risk['subdomain']}."
                ),
                reference_url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
            ))

        return results

    async def _check_subdomain(
        self,
        subdomain: str,
        resolver: "DNSResolver",
        semaphore: asyncio.Semaphore,
    ) -> tuple[str, bool, str | None, bool, str | None] | None:
        """
        Check a single subdomain for existence and takeover risk.

        Returns:
            (subdomain, resolves, cname, is_takeover_risk, service_name) or None
        """
        async with semaphore:
            try:
                result = await resolver.resolve_subdomain(subdomain)
                cname = result.get("cname")
                resolves = result.get("resolves", False)
                is_takeover = False
                service = None

                if cname:
                    for pattern, svc_name in TAKEOVER_FINGERPRINTS.items():
                        if pattern in cname:
                            is_takeover = not resolves  # CNAME exists but nothing resolves
                            service = svc_name
                            break

                return subdomain, resolves, cname, is_takeover, service
            except Exception:
                return None


# ==============================================================================
# TTL ANALYZER
# ==============================================================================

class TTLAnalyzer(BaseAnalyzer):
    """
    Checks for TTL anomalies that may indicate DNS hijacking or misconfiguration.

    Flags:
        - Abnormally low TTLs (< 300 seconds) on key records
        - Inconsistent TTLs for the same record across resolvers
        - Very high TTLs that could delay propagation of security fixes
    """

    name = "ttl"
    description = "Detects TTL anomalies and cross-resolver inconsistencies that may indicate DNS hijacking"
    timeout_seconds = 20.0

    _MIN_TTL      = 300     # 5 minutes — below this is suspicious
    _MAX_TTL      = 86400   # 24 hours — above this delays security updates
    _WARN_LOW_TTL = 60      # Below 60 seconds is very suspicious

    async def analyze(self, domain: str, resolver: "DNSResolver") -> list[AnalyzerResult]:
        results: list[AnalyzerResult] = []

        # Check TTLs for key record types
        record_types = ["A", "MX", "NS", "TXT"]
        tasks = {rt: resolver.query(domain, rt) for rt in record_types}
        query_results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for record_type, result in zip(tasks.keys(), query_results):
            if isinstance(result, Exception) or not result.found:
                continue

            min_ttl = result.min_ttl
            max_ttl = result.max_ttl

            if min_ttl is None:
                continue

            # ── Critically low TTL ────────────────────────────────────────────
            if min_ttl < self._WARN_LOW_TTL:
                results.append(self.fail(
                    check=f"ttl_critically_low_{record_type.lower()}",
                    title=f"{record_type} record has critically low TTL ({min_ttl}s)",
                    description=(
                        f"The {record_type} record for {domain} has a TTL of {min_ttl} seconds. "
                        f"TTLs below {self._WARN_LOW_TTL}s are highly unusual and may indicate "
                        "DNS hijacking (an attacker lowered TTLs before swapping records)."
                    ),
                    severity="high",
                    evidence=f"TTL: {min_ttl}s across resolvers: {result.ttls}",
                    cvss_score=7.0,
                    remediation=(
                        f"Investigate why the {record_type} TTL is so low. "
                        "If this was not deliberately set, check for unauthorized DNS changes. "
                        f"Set TTL to at least {self._MIN_TTL} seconds for stable records."
                    ),
                ))

            elif min_ttl < self._MIN_TTL:
                results.append(self.fail(
                    check=f"ttl_low_{record_type.lower()}",
                    title=f"{record_type} record TTL is low ({min_ttl}s)",
                    description=(
                        f"The {record_type} record TTL of {min_ttl}s is below the recommended "
                        f"minimum of {self._MIN_TTL}s, causing excessive DNS query load."
                    ),
                    severity="low",
                    evidence=f"TTL: {min_ttl}s",
                    remediation=f"Increase the {record_type} TTL to at least {self._MIN_TTL} seconds.",
                ))

            # ── Very high TTL ──────────────────────────────────────────────────
            elif max_ttl and max_ttl > self._MAX_TTL:
                results.append(self.info(
                    check=f"ttl_high_{record_type.lower()}",
                    title=f"{record_type} record TTL is very high ({max_ttl}s)",
                    description=(
                        f"The {record_type} record TTL of {max_ttl}s means changes "
                        f"could take up to {max_ttl // 3600} hours to propagate globally. "
                        "This delays emergency security updates (e.g. removing a compromised MX server)."
                    ),
                    evidence=f"TTL: {max_ttl}s",
                ))
            else:
                results.append(self.pass_check(
                    check=f"ttl_normal_{record_type.lower()}",
                    title=f"{record_type} record TTL is within normal range ({min_ttl}s)",
                    description=f"The {record_type} record TTL is healthy.",
                    evidence=f"TTL: {min_ttl}s",
                ))

            # ── Cross-resolver inconsistency ───────────────────────────────────
            if not result.consistent and len(result.resolvers_ok) > 1:
                results.append(self.fail(
                    check=f"ttl_inconsistent_{record_type.lower()}",
                    title=f"{record_type} records are inconsistent across resolvers",
                    description=(
                        f"The {record_type} records for {domain} differ across DNS resolvers. "
                        "This may indicate DNS cache poisoning, split-horizon DNS misconfiguration, "
                        "or an in-progress DNS change that has not fully propagated."
                    ),
                    severity="medium",
                    evidence=f"Resolver responses differ: {result.ttls}",
                    cvss_score=5.0,
                    remediation=(
                        "Check your DNS provider for recent unauthorized changes. "
                        "If this is expected (e.g. during migration), verify propagation completes. "
                        "If unexpected, investigate for cache poisoning."
                    ),
                ))

        return results