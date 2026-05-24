"""
Risk scoring engine — converts scan findings into a structured score report.

Produces:
    - Overall score (0–100) and letter grade (A+ to F)
    - Per-category scores for each analyzer (SPF, DMARC, DKIM, etc.)
    - Severity breakdown counts
    - Actionable priority queue — findings ranked by impact
    - Executive summary paragraph generated from findings

Scoring algorithm:
    Each analyzer category has a maximum weight (out of 100 total points).
    Within a category, findings deduct points proportional to severity.
    The overall score is the weighted sum across all categories.

Category weights:
    DMARC       20  — highest: email authentication policy
    SPF         15  — email sender authorization
    DNSSEC      15  — DNS integrity and authenticity
    DKIM        12  — email signing
    AXFR        10  — zone transfer (binary: either exposed or not)
    Subdomain    8  — takeover risk
    CAA          7  — certificate issuance control
    MTA-STS      7  — mail transport security
    TTL          4  — anomaly detection
    Intel        2  — threat intelligence signals
    Total       100
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from dns_analyzer.config.constants import Grade, Severity
from dns_analyzer.core.base_analyzer import AnalyzerResult
from dns_analyzer.utils.logger import get_logger

log = get_logger(__name__)


# ==============================================================================
# CATEGORY WEIGHTS
# ==============================================================================

CATEGORY_WEIGHTS: dict[str, int] = {
    "dmarc":     20,
    "spf":       15,
    "dnssec":    15,
    "dkim":      12,
    "axfr":      10,
    "subdomain":  8,
    "caa":        7,
    "mta_sts":    7,
    "ttl":        4,
    "intel":      2,
}

# Severity deduction percentages within a category
# A single critical finding wipes the entire category score
_SEVERITY_DEDUCTIONS: dict[str, float] = {
    "critical": 1.00,   # 100% deduction → category score = 0
    "high":     0.75,   # 75% deduction
    "medium":   0.40,   # 40% deduction
    "low":      0.15,   # 15% deduction
    "info":     0.00,   # No deduction (informational only)
}


# ==============================================================================
# SCORE DATACLASSES
# ==============================================================================

@dataclass
class CategoryScore:
    """Score and findings for one analyzer category."""

    name: str
    weight: int
    score: int                           # 0–100 within this category
    weighted_score: float                # score × weight / 100
    grade: str
    findings: list[AnalyzerResult] = field(default_factory=list)
    issues: list[AnalyzerResult] = field(default_factory=list)

    @property
    def max_severity(self) -> str | None:
        """Return the highest severity issue found in this category."""
        order = ["critical", "high", "medium", "low", "info"]
        for sev in order:
            if any(f.severity == sev and not f.passed for f in self.findings):
                return sev
        return None

    @property
    def passed(self) -> bool:
        return len(self.issues) == 0


@dataclass
class ScoreReport:
    """
    Complete scoring output for one scan.

    Contains the overall score, per-category breakdown, finding counts,
    a prioritized action queue, and an auto-generated executive summary.
    """

    domain: str
    overall_score: int
    overall_grade: str

    # Per-category breakdown
    categories: dict[str, CategoryScore] = field(default_factory=dict)

    # Severity counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total_findings: int = 0
    total_issues: int = 0

    # Prioritized action queue (issues sorted by impact)
    priority_queue: list[AnalyzerResult] = field(default_factory=list)

    # Auto-generated summaries
    executive_summary: str = ""
    risk_headline: str = ""

    @property
    def is_passing(self) -> bool:
        """True if the overall grade is B or better."""
        return self.overall_score >= 70

    @property
    def has_critical(self) -> bool:
        return self.critical_count > 0

    @property
    def has_high(self) -> bool:
        return self.high_count > 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON export and template rendering."""
        return {
            "domain": self.domain,
            "overall_score": self.overall_score,
            "overall_grade": self.overall_grade,
            "is_passing": self.is_passing,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "total_findings": self.total_findings,
            "total_issues": self.total_issues,
            "executive_summary": self.executive_summary,
            "risk_headline": self.risk_headline,
            "categories": {
                name: {
                    "name": cat.name,
                    "weight": cat.weight,
                    "score": cat.score,
                    "weighted_score": round(cat.weighted_score, 2),
                    "grade": cat.grade,
                    "passed": cat.passed,
                    "max_severity": cat.max_severity,
                    "issue_count": len(cat.issues),
                    "issues": [
                        {
                            "check": f.check_name,
                            "title": f.title,
                            "severity": f.severity,
                            "description": f.description,
                            "remediation": f.remediation,
                            "reference_url": f.reference_url,
                            "evidence": f.evidence,
                            "cvss_score": f.cvss_score,
                        }
                        for f in cat.issues
                    ],
                    "findings": [
                        {
                            "check": f.check_name,
                            "title": f.title,
                            "severity": f.severity,
                            "passed": f.passed,
                            "description": f.description,
                            "remediation": f.remediation,
                            "evidence": f.evidence,
                        }
                        for f in cat.findings
                    ],
                }
                for name, cat in self.categories.items()
            },
            "priority_queue": [
                {
                    "analyzer": f.analyzer,
                    "check": f.check_name,
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "remediation": f.remediation,
                    "cvss_score": f.cvss_score,
                }
                for f in self.priority_queue[:10]
            ],
        }


# ==============================================================================
# SCORER
# ==============================================================================

class RiskScorer:
    """
    Converts a list of AnalyzerResult objects into a full ScoreReport.

    Usage:
        scorer = RiskScorer()
        report = scorer.score("example.com", findings)
        print(report.overall_grade, report.overall_score)
        print(report.executive_summary)
    """

    def score(self, domain: str, findings: list[AnalyzerResult]) -> ScoreReport:
        """
        Compute a complete ScoreReport from raw analyzer findings.

        Args:
            domain:   The scanned domain name.
            findings: All AnalyzerResult objects from all analyzers.

        Returns:
            A fully populated ScoreReport.
        """
        report = ScoreReport(domain=domain, overall_score=0, overall_grade="F")

        if not findings:
            report.overall_score = 100
            report.overall_grade = "A+"
            report.executive_summary = f"{domain} has no DNS security issues detected."
            report.risk_headline = "Excellent DNS security posture."
            return report

        # ── Group findings by analyzer (category) ─────────────────────────────
        grouped: dict[str, list[AnalyzerResult]] = {}
        for finding in findings:
            grouped.setdefault(finding.analyzer, []).append(finding)

        # ── Score each category ───────────────────────────────────────────────
        total_weighted_score = 0.0
        total_weight_used = 0

        for analyzer_name, category_findings in grouped.items():
            weight = CATEGORY_WEIGHTS.get(analyzer_name, 2)
            cat_score = self._score_category(analyzer_name, weight, category_findings)
            report.categories[analyzer_name] = cat_score
            total_weighted_score += cat_score.weighted_score
            total_weight_used += weight

        # Account for analyzers that ran but produced no findings
        # (full weight goes to their max possible score)
        for name, weight in CATEGORY_WEIGHTS.items():
            if name not in grouped:
                # Analyzer didn't run — don't penalize, just skip
                pass

        # ── Normalize overall score ────────────────────────────────────────────
        if total_weight_used > 0:
            raw_score = (total_weighted_score / total_weight_used) * 100
            report.overall_score = max(0, min(100, round(raw_score)))
        else:
            report.overall_score = 100

        report.overall_grade = Grade.from_score(report.overall_score)

        # ── Severity counts ───────────────────────────────────────────────────
        for f in findings:
            report.total_findings += 1
            if f.severity == "critical":
                report.critical_count += 1
            elif f.severity == "high":
                report.high_count += 1
            elif f.severity == "medium":
                report.medium_count += 1
            elif f.severity == "low":
                report.low_count += 1
            else:
                report.info_count += 1
            if f.is_issue:
                report.total_issues += 1

        # ── Priority queue ────────────────────────────────────────────────────
        _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        issues = [f for f in findings if f.is_issue]
        report.priority_queue = sorted(
            issues,
            key=lambda f: (
                _SEVERITY_ORDER.get(f.severity, 5),
                -(f.cvss_score or 0),
            ),
        )

        # ── Executive summary ─────────────────────────────────────────────────
        report.risk_headline   = self._generate_headline(report)
        report.executive_summary = self._generate_summary(report)

        log.info(
            "scorer.completed",
            domain=domain,
            score=report.overall_score,
            grade=report.overall_grade,
            critical=report.critical_count,
            high=report.high_count,
            total_issues=report.total_issues,
        )

        return report

    def _score_category(
        self,
        name: str,
        weight: int,
        findings: list[AnalyzerResult],
    ) -> CategoryScore:
        """
        Score a single analyzer category.

        Algorithm:
            Start at 100. For each failing finding, apply the severity
            deduction to the remaining score (cascading penalties).
            This means one critical + one high scores lower than just
            one critical alone.
        """
        issues = [f for f in findings if f.is_issue]

        if not issues:
            cat_score = 100
        else:
            remaining = 100.0
            for finding in sorted(
                issues,
                key=lambda f: _SEVERITY_DEDUCTIONS.get(f.severity, 0),
                reverse=True,
            ):
                deduction_pct = _SEVERITY_DEDUCTIONS.get(finding.severity, 0)
                remaining -= remaining * deduction_pct
                remaining = max(0.0, remaining)

            cat_score = round(remaining)

        weighted = (cat_score / 100) * weight

        return CategoryScore(
            name=name,
            weight=weight,
            score=cat_score,
            weighted_score=weighted,
            grade=Grade.from_score(cat_score),
            findings=findings,
            issues=issues,
        )

    def _generate_headline(self, report: ScoreReport) -> str:
        """Generate a one-line risk headline based on the overall grade."""
        grade = report.overall_grade
        if grade == "A+":
            return "Excellent DNS security posture — no issues detected."
        if grade == "A":
            return "Strong DNS security posture — minor improvements available."
        if grade == "B":
            return "Good DNS security posture — some issues should be addressed."
        if grade == "C":
            return "Moderate DNS security risk — several issues require attention."
        if grade == "D":
            return "Poor DNS security posture — significant vulnerabilities present."
        return "Critical DNS security failures — immediate action required."

    def _generate_summary(self, report: ScoreReport) -> str:
        """
        Generate a 2–4 sentence executive summary paragraph.

        Written for a non-technical audience (CISO, management report).
        """
        domain = report.domain
        score  = report.overall_score
        grade  = report.overall_grade

        parts: list[str] = []

        # Opening sentence
        parts.append(
            f"The DNS security assessment for {domain} received an overall score of "
            f"{score}/100 (grade: {grade})."
        )

        # Critical issues
        if report.critical_count > 0:
            critical_cats = [
                cat.name.upper()
                for cat in report.categories.values()
                if any(f.severity == "critical" for f in cat.issues)
            ]
            parts.append(
                f"Critical security failures were identified in "
                f"{', '.join(critical_cats)}, requiring immediate remediation."
            )

        # High issues
        elif report.high_count > 0:
            high_cats = [
                cat.name.upper()
                for cat in report.categories.values()
                if any(f.severity == "high" for f in cat.issues)
            ]
            parts.append(
                f"High-severity issues were found in {', '.join(high_cats)}, "
                f"which significantly increase the risk of email spoofing and domain abuse."
            )

        # Category highlights
        passing_cats  = [c for c in report.categories.values() if c.passed]
        failing_cats  = [c for c in report.categories.values() if not c.passed]

        if passing_cats and not report.has_critical:
            parts.append(
                f"{len(passing_cats)} of {len(report.categories)} security checks passed cleanly "
                f"({', '.join(c.name.upper() for c in passing_cats[:3])}"
                + (" and others" if len(passing_cats) > 3 else "") + ")."
            )

        # Remediation call to action
        if report.total_issues > 0:
            top = report.priority_queue[0] if report.priority_queue else None
            if top:
                parts.append(
                    f"The highest-priority action is: {top.title}. "
                    f"A full remediation plan is provided in the findings section below."
                )
        else:
            parts.append(
                "No actionable issues were identified. Continue monitoring for changes."
            )

        return " ".join(parts)