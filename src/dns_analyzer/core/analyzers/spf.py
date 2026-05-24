"""
SPF (Sender Policy Framework) Analyzer.

Checks:
    1. spf_exists          — SPF TXT record present at the domain
    2. spf_syntax          — Record starts with correct v=spf1 prefix
    3. spf_lookup_count    — DNS lookup mechanisms don't exceed RFC 7208's limit of 10
    4. spf_all_mechanism   — Record ends with a hard fail (-all) not soft fail (~all)
    5. spf_ptr_mechanism   — Record does not use the deprecated 'ptr' mechanism
    6. spf_multiple_records — Only one SPF record exists (multiple = undefined behavior)

References:
    RFC 7208: https://datatracker.ietf.org/doc/html/rfc7208
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dns_analyzer.config.constants import SPF
from dns_analyzer.core.base_analyzer import AnalyzerResult, BaseAnalyzer

if TYPE_CHECKING:
    from dns_analyzer.core.resolver import DNSResolver


class SPFAnalyzer(BaseAnalyzer):
    """Analyzes SPF records for correctness, safety, and RFC compliance."""

    name = "spf"
    description = "Validates SPF record existence, syntax, DNS lookup limits, and policy strength"
    timeout_seconds = 20.0

    # Mechanisms that each count as one DNS lookup (RFC 7208 §4.6.4)
    _LOOKUP_MECHANISMS = re.compile(
        r"\b(include|a|mx|ptr|exists):[^\s]*|\b(a|mx|ptr)\b(?!:)",
        re.IGNORECASE,
    )
    _REDIRECT_RE = re.compile(r"\bredirect=([^\s]+)", re.IGNORECASE)
    _INCLUDE_RE  = re.compile(r"\binclude:([^\s]+)", re.IGNORECASE)

    async def analyze(self, domain: str, resolver: "DNSResolver") -> list[AnalyzerResult]:
        results: list[AnalyzerResult] = []
        txt_records = await resolver.get_txt_records(domain)

        # Filter to SPF records only
        spf_records = [r for r in txt_records if r.startswith(SPF.PREFIX)]

        # ── Check 1: SPF record exists ────────────────────────────────────────
        if not spf_records:
            return [self.fail(
                check="spf_exists",
                title="No SPF record found",
                description=(
                    f"No SPF TXT record was found for {domain}. Without an SPF record, "
                    "receiving mail servers cannot verify that email claiming to be from "
                    "your domain was authorized, making it trivial to spoof your domain."
                ),
                severity="high",
                cvss_score=7.5,
                remediation=(
                    "Add a TXT record to your DNS zone:\n"
                    '  v=spf1 include:_spf.google.com -all\n'
                    "Replace the include with your actual mail provider's SPF include, "
                    "and end with -all to reject unauthorized senders."
                ),
                reference_url="https://datatracker.ietf.org/doc/html/rfc7208",
            )]

        # ── Check 2: Multiple SPF records ─────────────────────────────────────
        if len(spf_records) > 1:
            results.append(self.fail(
                check="spf_multiple_records",
                title="Multiple SPF records found",
                description=(
                    f"{len(spf_records)} SPF records were found for {domain}. "
                    "RFC 7208 §3.2 states that a domain MUST NOT have more than one SPF record. "
                    "Multiple records produce undefined behavior and many receivers will "
                    "fail to validate your email correctly."
                ),
                severity="high",
                evidence="\n".join(spf_records),
                cvss_score=6.0,
                remediation=(
                    "Merge all SPF records into a single TXT record. "
                    "Delete all but one SPF record and combine the mechanisms."
                ),
                reference_url="https://datatracker.ietf.org/doc/html/rfc7208#section-3.2",
            ))

        # Work with the first SPF record for remaining checks
        spf = spf_records[0]

        # ── Check 3: Syntax validation ────────────────────────────────────────
        if not spf.startswith(SPF.PREFIX):
            results.append(self.fail(
                check="spf_syntax",
                title="SPF record has invalid syntax",
                description=(
                    f"The SPF record does not begin with 'v=spf1'. "
                    f"Found: {spf[:50]!r}"
                ),
                severity="high",
                evidence=spf,
                remediation="Ensure your SPF record starts exactly with 'v=spf1 '.",
                reference_url="https://datatracker.ietf.org/doc/html/rfc7208#section-4.5",
            ))
            return results
        else:
            results.append(self.pass_check(
                check="spf_syntax",
                title="SPF record syntax is valid",
                description="The SPF record begins with the correct 'v=spf1' prefix.",
                evidence=spf,
            ))

        # ── Check 4: DNS lookup count ─────────────────────────────────────────
        lookup_count = await self._count_lookups(spf, domain, resolver, depth=0)

        if lookup_count > SPF.MAX_DNS_LOOKUPS:
            results.append(self.fail(
                check="spf_lookup_count",
                title=f"SPF exceeds DNS lookup limit ({lookup_count}/10)",
                description=(
                    f"The SPF record for {domain} requires {lookup_count} DNS lookups, "
                    f"exceeding the RFC 7208 hard limit of {SPF.MAX_DNS_LOOKUPS}. "
                    "Receivers MUST return a PermError result, causing legitimate email "
                    "from your domain to be rejected."
                ),
                severity="high",
                evidence=spf,
                cvss_score=6.5,
                remediation=(
                    "Flatten your SPF record by replacing 'include:' directives with "
                    "the actual IP ranges they contain. Tools like 'spf-flatten' can help. "
                    f"You currently have {lookup_count} lookups; reduce to ≤{SPF.MAX_DNS_LOOKUPS}."
                ),
                reference_url="https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4",
            ))
        elif lookup_count >= SPF.WARN_DNS_LOOKUPS:
            results.append(self.fail(
                check="spf_lookup_count",
                title=f"SPF is approaching the DNS lookup limit ({lookup_count}/10)",
                description=(
                    f"The SPF record requires {lookup_count} DNS lookups. "
                    f"The RFC 7208 limit is {SPF.MAX_DNS_LOOKUPS}. Adding more senders "
                    "may push you over the limit."
                ),
                severity="medium",
                evidence=spf,
                remediation=(
                    "Monitor your lookup count and consider flattening your SPF record "
                    "before adding new mail providers."
                ),
                reference_url="https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4",
            ))
        else:
            results.append(self.pass_check(
                check="spf_lookup_count",
                title=f"SPF DNS lookup count is within limits ({lookup_count}/10)",
                description=f"The SPF record requires {lookup_count} DNS lookups, within the RFC 7208 limit of 10.",
                evidence=spf,
            ))

        # ── Check 5: -all vs ~all vs ?all ────────────────────────────────────
        if spf.endswith("-all") or " -all " in spf:
            results.append(self.pass_check(
                check="spf_all_mechanism",
                title="SPF uses hard fail (-all)",
                description="The SPF record ends with '-all', rejecting all unauthorized senders.",
                evidence=spf,
            ))
        elif "~all" in spf:
            results.append(self.fail(
                check="spf_all_mechanism",
                title="SPF uses soft fail (~all) instead of hard fail (-all)",
                description=(
                    "The SPF record ends with '~all' (soft fail), which marks unauthorized "
                    "email as suspicious but does not reject it. Many receivers treat ~all "
                    "the same as pass, providing little protection against spoofing."
                ),
                severity="medium",
                evidence=spf,
                cvss_score=4.5,
                remediation=(
                    "Change '~all' to '-all' to enforce hard rejection of unauthorized senders. "
                    "Test first with DMARC p=none to ensure legitimate senders are authorized."
                ),
                reference_url="https://datatracker.ietf.org/doc/html/rfc7208#section-5.1",
            ))
        elif "?all" in spf:
            results.append(self.fail(
                check="spf_all_mechanism",
                title="SPF uses neutral (?all) — no protection",
                description=(
                    "The SPF record ends with '?all' (neutral), which provides no "
                    "protection against email spoofing whatsoever."
                ),
                severity="high",
                evidence=spf,
                cvss_score=7.0,
                remediation="Replace '?all' with '-all' to enforce rejection of unauthorized senders.",
            ))
        elif "+all" in spf:
            results.append(self.fail(
                check="spf_all_mechanism",
                title="SPF uses pass-all (+all) — allows anyone to send",
                description=(
                    "The SPF record ends with '+all', which explicitly authorizes ANY "
                    "server to send email on behalf of your domain. This completely "
                    "defeats the purpose of SPF."
                ),
                severity="critical",
                evidence=spf,
                cvss_score=9.0,
                remediation=(
                    "Immediately replace '+all' with '-all'. "
                    "This is a critical misconfiguration that enables unrestricted spoofing."
                ),
            ))

        # ── Check 6: ptr mechanism (deprecated) ───────────────────────────────
        if " ptr" in spf or " ptr:" in spf:
            results.append(self.fail(
                check="spf_ptr_mechanism",
                title="SPF uses deprecated 'ptr' mechanism",
                description=(
                    "The SPF record uses the 'ptr' mechanism, which is deprecated in "
                    "RFC 7208 §5.5. It is slow, unreliable, and should be removed."
                ),
                severity="low",
                evidence=spf,
                remediation=(
                    "Replace the 'ptr' mechanism with explicit IP ranges (ip4:, ip6:) "
                    "or 'include:' directives pointing to your mail provider's SPF record."
                ),
                reference_url="https://datatracker.ietf.org/doc/html/rfc7208#section-5.5",
            ))

        return results

    async def _count_lookups(
        self,
        spf: str,
        domain: str,
        resolver: "DNSResolver",
        depth: int,
    ) -> int:
        """
        Recursively count DNS lookups required to evaluate an SPF record.

        Each include:, a, mx, ptr, and exists mechanism counts as one lookup.
        redirect= also counts as one. Recursion is capped at depth 5 to
        prevent infinite loops on circular includes.
        """
        if depth > 5:
            return 0

        count = 0
        mechanisms = spf.split()

        for mech in mechanisms:
            mech_lower = mech.lower().lstrip("+-~?")

            # These mechanisms each consume one DNS lookup
            if mech_lower.startswith(("include:", "a:", "mx:", "exists:")):
                count += 1
                # Recursively count lookups inside include: directives
                if mech_lower.startswith("include:"):
                    included_domain = mech_lower[len("include:"):]
                    try:
                        included_spf = await resolver.get_txt_record_starting_with(
                            included_domain, SPF.PREFIX
                        )
                        if included_spf:
                            count += await self._count_lookups(
                                included_spf, included_domain, resolver, depth + 1
                            )
                    except Exception:
                        pass

            elif mech_lower in ("a", "mx", "ptr"):
                count += 1

            elif mech_lower.startswith("redirect="):
                count += 1
                redirect_domain = mech_lower[len("redirect="):]
                try:
                    redirect_spf = await resolver.get_txt_record_starting_with(
                        redirect_domain, SPF.PREFIX
                    )
                    if redirect_spf:
                        count += await self._count_lookups(
                            redirect_spf, redirect_domain, resolver, depth + 1
                        )
                except Exception:
                    pass

        return count