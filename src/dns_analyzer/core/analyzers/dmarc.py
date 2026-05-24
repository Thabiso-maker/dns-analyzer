"""
DMARC (Domain-based Message Authentication, Reporting and Conformance) Analyzer.

Checks:
    1. dmarc_exists        — _dmarc.<domain> TXT record present
    2. dmarc_policy        — Policy is quarantine or reject (not none)
    3. dmarc_subdomain_policy — Subdomain policy is set
    4. dmarc_pct           — Percentage applies to 100% of mail
    5. dmarc_rua           — Aggregate report URI configured
    6. dmarc_ruf           — Forensic report URI configured
    7. dmarc_alignment     — SPF and DKIM alignment modes

References:
    RFC 7489: https://datatracker.ietf.org/doc/html/rfc7489
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dns_analyzer.config.constants import DMARC
from dns_analyzer.core.base_analyzer import AnalyzerResult, BaseAnalyzer

if TYPE_CHECKING:
    from dns_analyzer.core.resolver import DNSResolver


class DMARCAnalyzer(BaseAnalyzer):
    """Analyzes DMARC records for policy strength, reporting, and alignment."""

    name = "dmarc"
    description = "Validates DMARC record existence, policy enforcement level, and reporting configuration"
    timeout_seconds = 15.0

    async def analyze(self, domain: str, resolver: "DNSResolver") -> list[AnalyzerResult]:
        results: list[AnalyzerResult] = []
        dmarc_domain = f"{DMARC.RECORD_NAME}.{domain}"

        # Query the _dmarc subdomain for TXT records
        txt_records = await resolver.get_txt_records(dmarc_domain)
        dmarc_records = [r for r in txt_records if r.startswith(DMARC.PREFIX)]

        # ── Check 1: DMARC record exists ──────────────────────────────────────
        if not dmarc_records:
            return [self.fail(
                check="dmarc_exists",
                title="No DMARC record found",
                description=(
                    f"No DMARC TXT record was found at {dmarc_domain}. "
                    "Without DMARC, you have no visibility into who is sending email "
                    "using your domain, and no way to instruct receivers to reject "
                    "unauthorized email. Your domain is vulnerable to phishing attacks."
                ),
                severity="high",
                cvss_score=7.5,
                remediation=(
                    f"Add a TXT record at _dmarc.{domain}:\n"
                    "  v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; pct=100\n"
                    "Start with p=none to monitor, then progress to quarantine, then reject."
                ),
                reference_url="https://datatracker.ietf.org/doc/html/rfc7489",
            )]

        dmarc = dmarc_records[0]
        tags = self._parse_dmarc(dmarc)

        results.append(self.pass_check(
            check="dmarc_exists",
            title="DMARC record found",
            description=f"A valid DMARC record was found at {dmarc_domain}.",
            evidence=dmarc,
        ))

        # ── Check 2: Policy strength ──────────────────────────────────────────
        policy = tags.get("p", "").lower()
        results.extend(self._check_policy(policy, dmarc))

        # ── Check 3: Subdomain policy ─────────────────────────────────────────
        sp = tags.get("sp", "").lower()
        if sp:
            results.extend(self._check_subdomain_policy(sp, policy, dmarc))

        # ── Check 4: pct tag ─────────────────────────────────────────────────
        pct = tags.get("pct", "100")
        results.extend(self._check_pct(pct, policy, dmarc))

        # ── Check 5: Aggregate reporting URI ──────────────────────────────────
        rua = tags.get("rua", "")
        if not rua:
            results.append(self.fail(
                check="dmarc_rua",
                title="No DMARC aggregate reporting address (rua) configured",
                description=(
                    "No aggregate reporting URI (rua=) is configured. "
                    "Without rua=, you receive no reports about who is sending email "
                    "using your domain, making it impossible to monitor abuse or fix "
                    "authentication failures."
                ),
                severity="medium",
                evidence=dmarc,
                remediation=(
                    "Add rua=mailto:dmarc-reports@yourdomain.com to your DMARC record. "
                    "Consider using a DMARC report aggregator (Postmark, Valimail, etc.) "
                    "to parse the XML reports automatically."
                ),
                reference_url="https://datatracker.ietf.org/doc/html/rfc7489#section-6.2",
            ))
        else:
            results.append(self.pass_check(
                check="dmarc_rua",
                title="DMARC aggregate reporting is configured",
                description=f"Aggregate reports will be sent to: {rua}",
                evidence=dmarc,
            ))

        # ── Check 6: Forensic reporting URI ───────────────────────────────────
        ruf = tags.get("ruf", "")
        if not ruf:
            results.append(self.info(
                check="dmarc_ruf",
                title="No DMARC forensic reporting address (ruf) configured",
                description=(
                    "No forensic reporting URI (ruf=) is configured. "
                    "Forensic reports provide sample failed messages, which can help "
                    "diagnose authentication failures. This is optional."
                ),
                evidence=dmarc,
            ))

        # ── Check 7: Alignment modes ──────────────────────────────────────────
        adkim = tags.get("adkim", "r")
        aspf  = tags.get("aspf", "r")
        results.extend(self._check_alignment(adkim, aspf, dmarc))

        return results

    def _parse_dmarc(self, record: str) -> dict[str, str]:
        """Parse DMARC record into a tag→value dict."""
        tags: dict[str, str] = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                key, _, value = part.partition("=")
                tags[key.strip().lower()] = value.strip()
        return tags

    def _check_policy(self, policy: str, record: str) -> list[AnalyzerResult]:
        results = []
        if policy == DMARC.POLICY_REJECT:
            results.append(self.pass_check(
                check="dmarc_policy",
                title="DMARC policy is set to reject",
                description="The strongest DMARC policy (p=reject) is in place. Unauthorized email will be rejected.",
                evidence=record,
            ))
        elif policy == DMARC.POLICY_QUARANTINE:
            results.append(self.fail(
                check="dmarc_policy",
                title="DMARC policy is quarantine — consider upgrading to reject",
                description=(
                    "The DMARC policy is p=quarantine. Unauthorized email will be moved to "
                    "spam but not outright rejected. Upgrading to p=reject provides stronger protection."
                ),
                severity="low",
                evidence=record,
                cvss_score=3.0,
                remediation=(
                    "Once you have confirmed all legitimate senders pass DMARC checks "
                    "(check your rua= reports), change p=quarantine to p=reject."
                ),
            ))
        elif policy == DMARC.POLICY_NONE:
            results.append(self.fail(
                check="dmarc_policy",
                title="DMARC policy is none — no enforcement",
                description=(
                    "The DMARC policy is p=none. This is a monitoring-only mode — "
                    "receivers take no action on unauthorized email. Your domain is "
                    "not protected against spoofing or phishing."
                ),
                severity="high",
                evidence=record,
                cvss_score=7.0,
                remediation=(
                    "Analyze your rua= aggregate reports to identify all legitimate senders, "
                    "then progress to p=quarantine, and finally p=reject once you are confident "
                    "all authorized senders pass authentication."
                ),
            ))
        else:
            results.append(self.fail(
                check="dmarc_policy",
                title=f"DMARC policy is missing or invalid: {policy!r}",
                description="The p= tag in the DMARC record is missing or has an unrecognized value.",
                severity="high",
                evidence=record,
                remediation="Set p=none, p=quarantine, or p=reject in your DMARC record.",
            ))
        return results

    def _check_subdomain_policy(self, sp: str, parent_policy: str, record: str) -> list[AnalyzerResult]:
        results = []
        if sp == "none" and parent_policy in ("quarantine", "reject"):
            results.append(self.fail(
                check="dmarc_subdomain_policy",
                title="DMARC subdomain policy (sp=none) is weaker than domain policy",
                description=(
                    f"The parent domain uses p={parent_policy} but subdomains use sp=none. "
                    "Attackers could send spoofed email from subdomains of your domain."
                ),
                severity="medium",
                evidence=record,
                remediation=f"Set sp={parent_policy} to apply the same policy to subdomains.",
            ))
        return results

    def _check_pct(self, pct: str, policy: str, record: str) -> list[AnalyzerResult]:
        results = []
        try:
            pct_int = int(pct)
        except ValueError:
            return results

        if pct_int < 100 and policy in ("quarantine", "reject"):
            results.append(self.fail(
                check="dmarc_pct",
                title=f"DMARC pct={pct_int} — policy only applies to {pct_int}% of mail",
                description=(
                    f"The pct={pct_int} tag means the DMARC policy is only applied to "
                    f"{pct_int}% of failing messages. The remaining {100 - pct_int}% are "
                    "treated as if p=none, leaving a gap for spoofed email to get through."
                ),
                severity="medium",
                evidence=record,
                remediation="Set pct=100 to enforce your DMARC policy on all email.",
            ))
        return results

    def _check_alignment(self, adkim: str, aspf: str, record: str) -> list[AnalyzerResult]:
        results = []
        if adkim == "s":
            results.append(self.pass_check(
                check="dmarc_dkim_alignment",
                title="DKIM alignment is strict (adkim=s)",
                description="Strict DKIM alignment requires an exact domain match.",
                evidence=record,
            ))
        if aspf == "s":
            results.append(self.pass_check(
                check="dmarc_spf_alignment",
                title="SPF alignment is strict (aspf=s)",
                description="Strict SPF alignment requires an exact domain match.",
                evidence=record,
            ))
        return results