"""
Report exporters — render a ScoreReport to HTML, PDF, and JSON files.

Three exporters:
    HTMLExporter  — renders a full styled HTML report via Jinja2
    PDFExporter   — converts the HTML report to PDF via WeasyPrint
    JSONExporter  — writes the ScoreReport dict as formatted JSON

All exporters implement the same async render() interface so the builder
can swap between them without any other code changes.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dns_analyzer.reporting.scorer import ScoreReport
from dns_analyzer.utils.logger import get_logger

log = get_logger(__name__)


# ==============================================================================
# SHARED TEMPLATE CONTEXT BUILDER
# ==============================================================================

def _build_template_context(
    score_report: ScoreReport,
    title: str,
    include_passing_checks: bool,
    scan_id: str,
    generated_at: str,
) -> dict[str, Any]:
    """
    Build the Jinja2 template context dict from a ScoreReport.

    Centralised so HTMLExporter and PDFExporter use identical data.
    """
    report_dict = score_report.to_dict()

    # Filter findings based on include_passing_checks flag
    for cat_data in report_dict["categories"].values():
        if not include_passing_checks:
            cat_data["findings"] = [
                f for f in cat_data["findings"] if not f["passed"]
            ]

    return {
        "title":                 title,
        "domain":                score_report.domain,
        "scan_id":               scan_id,
        "generated_at":          generated_at,
        "overall_score":         score_report.overall_score,
        "overall_grade":         score_report.overall_grade,
        "is_passing":            score_report.is_passing,
        "executive_summary":     score_report.executive_summary,
        "risk_headline":         score_report.risk_headline,
        "critical_count":        score_report.critical_count,
        "high_count":            score_report.high_count,
        "medium_count":          score_report.medium_count,
        "low_count":             score_report.low_count,
        "info_count":            score_report.info_count,
        "total_issues":          score_report.total_issues,
        "total_findings":        score_report.total_findings,
        "categories":            report_dict["categories"],
        "priority_queue":        report_dict["priority_queue"],
        "include_passing":       include_passing_checks,
        "grade_color": {
            "A+": "#16a34a", "A": "#22c55e",
            "B":  "#ca8a04", "C": "#d97706",
            "D":  "#dc2626", "F": "#991b1b",
        }.get(score_report.overall_grade, "#6b7280"),
    }


# ==============================================================================
# HTML EXPORTER
# ==============================================================================

class HTMLExporter:
    """
    Renders a ScoreReport to a self-contained styled HTML file.

    Uses Jinja2 for templating. If the template file is not found,
    falls back to a built-in inline template so reports always work
    even without the template directory set up.
    """

    def __init__(self, template_dir: Path) -> None:
        self.template_dir = template_dir

    async def render(
        self,
        score_report: ScoreReport,
        output_path: Path,
        title: str,
        include_passing_checks: bool,
        scan_id: str,
        generated_at: str,
    ) -> None:
        """Render the ScoreReport to an HTML file at output_path."""
        ctx = _build_template_context(
            score_report, title, include_passing_checks, scan_id, generated_at
        )

        html = self._render_template(ctx)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")

    def _render_template(self, ctx: dict[str, Any]) -> str:
        """Try Jinja2 template first, fall back to inline template."""
        template_file = self.template_dir / "report.html"

        if template_file.exists():
            try:
                from jinja2 import Environment, FileSystemLoader, select_autoescape
                env = Environment(
                    loader=FileSystemLoader(str(self.template_dir)),
                    autoescape=select_autoescape(["html"]),
                )
                template = env.get_template("report.html")
                return template.render(**ctx)
            except Exception as exc:
                log.warning("html_exporter.template_error", error=str(exc))

        # Built-in fallback template
        return self._inline_template(ctx)

    def _inline_template(self, ctx: dict[str, Any]) -> str:
        """
        Comprehensive self-contained HTML report template.
        No external dependencies — works completely offline.
        """
        grade_color = ctx["grade_color"]
        cats_html   = self._render_categories(ctx["categories"])
        priority_html = self._render_priority_queue(ctx["priority_queue"])

        sev_colors = {
            "critical": "#991b1b", "high": "#dc2626",
            "medium": "#d97706",  "low": "#2563eb", "info": "#6b7280",
        }

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{ctx['title']}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: #f8fafc; color: #1e293b; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}
  .header {{ background: #0f172a; color: white; padding: 40px; border-radius: 12px;
             margin-bottom: 32px; }}
  .header h1 {{ font-size: 28px; font-weight: 700; margin-bottom: 8px; }}
  .header .meta {{ opacity: 0.7; font-size: 14px; }}
  .score-card {{ background: white; border-radius: 12px; padding: 32px;
                 box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 24px;
                 display: flex; align-items: center; gap: 32px; }}
  .grade-circle {{ width: 100px; height: 100px; border-radius: 50%;
                   background: {grade_color}; color: white; display: flex;
                   align-items: center; justify-content: center;
                   font-size: 36px; font-weight: 800; flex-shrink: 0; }}
  .score-details h2 {{ font-size: 22px; margin-bottom: 8px; }}
  .score-details p {{ color: #64748b; margin-bottom: 4px; }}
  .score-bar {{ background: #e2e8f0; border-radius: 9999px; height: 12px;
               margin-top: 12px; overflow: hidden; width: 400px; }}
  .score-fill {{ height: 100%; border-radius: 9999px;
                 background: {grade_color};
                 width: {ctx['overall_score']}%; transition: width 0.3s; }}
  .summary-box {{ background: #eff6ff; border-left: 4px solid #3b82f6;
                  padding: 20px 24px; border-radius: 0 8px 8px 0;
                  margin-bottom: 32px; }}
  .counts-grid {{ display: grid; grid-template-columns: repeat(5, 1fr);
                  gap: 16px; margin-bottom: 32px; }}
  .count-card {{ background: white; border-radius: 8px; padding: 20px;
                 box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
  .count-card .number {{ font-size: 32px; font-weight: 700; }}
  .count-card .label {{ font-size: 12px; text-transform: uppercase;
                        letter-spacing: 0.05em; color: #64748b; }}
  .section {{ background: white; border-radius: 12px; padding: 24px;
              box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 24px; }}
  .section h2 {{ font-size: 18px; font-weight: 600; margin-bottom: 20px;
                 padding-bottom: 12px; border-bottom: 1px solid #e2e8f0; }}
  .category {{ border: 1px solid #e2e8f0; border-radius: 8px;
               margin-bottom: 16px; overflow: hidden; }}
  .category-header {{ display: flex; align-items: center; justify-content: space-between;
                      padding: 16px 20px; background: #f8fafc;
                      cursor: pointer; }}
  .category-header h3 {{ font-size: 15px; font-weight: 600; text-transform: uppercase;
                          letter-spacing: 0.05em; }}
  .category-score {{ display: flex; align-items: center; gap: 12px; }}
  .cat-grade {{ padding: 4px 12px; border-radius: 9999px; font-weight: 700;
               font-size: 14px; color: white; }}
  .finding {{ padding: 16px 20px; border-top: 1px solid #e2e8f0; }}
  .finding-title {{ font-weight: 600; margin-bottom: 4px; }}
  .finding-desc {{ color: #64748b; font-size: 14px; margin-bottom: 8px; }}
  .finding-remedy {{ background: #f0fdf4; padding: 10px 14px; border-radius: 6px;
                     font-size: 13px; color: #166534; border-left: 3px solid #22c55e; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 9999px;
            font-size: 12px; font-weight: 600; color: white; margin-right: 8px; }}
  .badge-critical {{ background: #991b1b; }}
  .badge-high {{ background: #dc2626; }}
  .badge-medium {{ background: #d97706; }}
  .badge-low {{ background: #2563eb; }}
  .badge-info {{ background: #6b7280; }}
  .priority-item {{ display: flex; gap: 16px; padding: 16px;
                    border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 12px; }}
  .priority-num {{ font-size: 24px; font-weight: 800; color: #cbd5e1;
                   flex-shrink: 0; width: 32px; }}
  .priority-content h4 {{ font-weight: 600; margin-bottom: 4px; }}
  .priority-content p {{ color: #64748b; font-size: 14px; }}
  .footer {{ text-align: center; color: #94a3b8; font-size: 13px; margin-top: 40px; }}
  @media print {{ body {{ background: white; }}
    .container {{ padding: 0; }} }}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>{ctx['title']}</h1>
    <div class="meta">
      Domain: {ctx['domain']} &nbsp;|&nbsp;
      Scan ID: {ctx['scan_id']} &nbsp;|&nbsp;
      Generated: {ctx['generated_at'][:19].replace('T', ' ')} UTC
    </div>
  </div>

  <div class="score-card">
    <div class="grade-circle">{ctx['overall_grade']}</div>
    <div class="score-details">
      <h2>{ctx['risk_headline']}</h2>
      <p>Overall Security Score: <strong>{ctx['overall_score']}/100</strong></p>
      <p>{ctx['total_issues']} issue(s) found across {ctx['total_findings']} checks</p>
      <div class="score-bar"><div class="score-fill"></div></div>
    </div>
  </div>

  <div class="summary-box">
    <strong>Executive Summary</strong><br>
    {ctx['executive_summary']}
  </div>

  <div class="counts-grid">
    <div class="count-card">
      <div class="number" style="color:#991b1b">{ctx['critical_count']}</div>
      <div class="label">Critical</div>
    </div>
    <div class="count-card">
      <div class="number" style="color:#dc2626">{ctx['high_count']}</div>
      <div class="label">High</div>
    </div>
    <div class="count-card">
      <div class="number" style="color:#d97706">{ctx['medium_count']}</div>
      <div class="label">Medium</div>
    </div>
    <div class="count-card">
      <div class="number" style="color:#2563eb">{ctx['low_count']}</div>
      <div class="label">Low</div>
    </div>
    <div class="count-card">
      <div class="number" style="color:#6b7280">{ctx['info_count']}</div>
      <div class="label">Info</div>
    </div>
  </div>

  {f'<div class="section"><h2>Priority Actions</h2>{priority_html}</div>' if ctx["priority_queue"] else ''}

  <div class="section">
    <h2>Detailed Findings by Category</h2>
    {cats_html}
  </div>

  <div class="footer">
    Generated by DNS Security Analyzer &nbsp;|&nbsp;
    {ctx['generated_at'][:10]}
  </div>

</div>
</body>
</html>"""

    def _render_categories(self, categories: dict[str, Any]) -> str:
        """Render all category sections as HTML."""
        sev_colors = {
            "critical": "#991b1b", "high": "#dc2626",
            "medium": "#d97706", "low": "#2563eb", "info": "#6b7280",
        }
        grade_colors = {
            "A+": "#16a34a", "A": "#22c55e", "B": "#ca8a04",
            "C": "#d97706", "D": "#dc2626", "F": "#991b1b",
        }

        html_parts = []
        for cat_name, cat in categories.items():
            findings_html = ""
            all_findings = cat.get("issues", []) + [
                f for f in cat.get("findings", [])
                if f.get("passed")
            ]

            for finding in all_findings:
                sev   = finding.get("severity", "info")
                color = sev_colors.get(sev, "#6b7280")
                remedy = (
                    f'<div class="finding-remedy">&#9654; {finding["remediation"]}</div>'
                    if finding.get("remediation") else ""
                )
                evidence = (
                    f'<pre style="background:#f1f5f9;padding:8px;border-radius:4px;'
                    f'font-size:12px;overflow-x:auto;margin-top:8px;">'
                    f'{finding["evidence"]}</pre>'
                    if finding.get("evidence") else ""
                )
                status_badge = (
                    '<span style="color:#16a34a;font-weight:600;">&#10003; PASS</span>'
                    if finding.get("passed")
                    else f'<span style="color:{color};font-weight:600;">&#10007; FAIL</span>'
                )
                findings_html += f"""
                <div class="finding">
                  <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
                    <span class="badge badge-{sev}">{sev.upper()}</span>
                    {status_badge}
                    <span class="finding-title">{finding.get('title', '')}</span>
                  </div>
                  <div class="finding-desc">{finding.get('description', '')}</div>
                  {remedy}
                  {evidence}
                </div>"""

            grade       = cat.get("grade", "F")
            grade_color = grade_colors.get(grade, "#6b7280")
            score       = cat.get("score", 0)
            weight      = cat.get("weight", 0)

            html_parts.append(f"""
            <div class="category">
              <div class="category-header">
                <h3>{cat_name.replace('_', ' ').upper()}</h3>
                <div class="category-score">
                  <span style="color:#64748b;font-size:14px;">
                    Weight: {weight}pts &nbsp;|&nbsp; Score: {score}/100
                  </span>
                  <span class="cat-grade" style="background:{grade_color};">{grade}</span>
                </div>
              </div>
              {findings_html if findings_html else
               '<div class="finding" style="color:#64748b;">No findings for this category.</div>'}
            </div>""")

        return "\n".join(html_parts)

    def _render_priority_queue(self, priority_queue: list[dict]) -> str:
        """Render the top-10 priority actions list."""
        sev_colors = {
            "critical": "#991b1b", "high": "#dc2626",
            "medium": "#d97706", "low": "#2563eb", "info": "#6b7280",
        }
        parts = []
        for i, item in enumerate(priority_queue[:10], 1):
            sev   = item.get("severity", "info")
            color = sev_colors.get(sev, "#6b7280")
            cvss  = f" &nbsp; CVSS: {item['cvss_score']}" if item.get("cvss_score") else ""
            parts.append(f"""
            <div class="priority-item">
              <div class="priority-num">#{i}</div>
              <div class="priority-content">
                <div style="margin-bottom:6px;">
                  <span class="badge badge-{sev}">{sev.upper()}</span>
                  <strong>{item.get('title', '')}</strong>{cvss}
                </div>
                <p>{item.get('description', '')[:200]}...</p>
                {f'<div style="margin-top:8px;color:#166534;font-size:13px;">&#9654; {item["remediation"]}</div>' if item.get("remediation") else ''}
              </div>
            </div>""")
        return "\n".join(parts)


# ==============================================================================
# PDF EXPORTER
# ==============================================================================

class PDFExporter:
    """
    Converts the HTML report to a PDF using WeasyPrint.

    WeasyPrint renders HTML+CSS to PDF with excellent fidelity.
    Falls back to saving the HTML file if WeasyPrint is unavailable
    (e.g. missing system libraries in some environments).
    """

    def __init__(self, template_dir: Path) -> None:
        self._html_exporter = HTMLExporter(template_dir)

    async def render(
        self,
        score_report: ScoreReport,
        output_path: Path,
        title: str,
        include_passing_checks: bool,
        scan_id: str,
        generated_at: str,
    ) -> None:
        """Render HTML and convert to PDF via WeasyPrint."""
        import asyncio

        # Generate HTML first
        html_path = output_path.with_suffix(".html")
        await self._html_exporter.render(
            score_report=score_report,
            output_path=html_path,
            title=title,
            include_passing_checks=include_passing_checks,
            scan_id=scan_id,
            generated_at=generated_at,
        )

        # Convert HTML → PDF in thread pool (WeasyPrint is blocking)
        loop = asyncio.get_event_loop()
        success = await loop.run_in_executor(
            None,
            self._html_to_pdf,
            html_path,
            output_path,
        )

        # Clean up intermediate HTML file
        if success and html_path.exists():
            html_path.unlink(missing_ok=True)
        elif not success:
            # WeasyPrint failed — rename HTML to PDF path as fallback
            log.warning(
                "pdf_exporter.weasyprint_unavailable",
                domain=score_report.domain,
                fallback="saving as HTML",
            )
            html_path.rename(output_path.with_suffix(".html"))
            # Write a minimal placeholder at the expected PDF path
            output_path.write_bytes(b"%PDF-1.4 (WeasyPrint unavailable - see .html file)")

    @staticmethod
    def _html_to_pdf(html_path: Path, pdf_path: Path) -> bool:
        """Blocking PDF conversion — runs in thread executor."""
        try:
            from weasyprint import HTML
            html_doc = HTML(filename=str(html_path))
            html_doc.write_pdf(str(pdf_path))
            return True
        except ImportError:
            log.warning("pdf_exporter.weasyprint_not_installed")
            return False
        except Exception as exc:
            log.error("pdf_exporter.conversion_failed", error=str(exc))
            return False


# ==============================================================================
# JSON EXPORTER
# ==============================================================================

class JSONExporter:
    """
    Exports the ScoreReport as a machine-readable JSON file.

    The JSON output is the full ScoreReport.to_dict() payload,
    formatted with 2-space indentation for readability.

    Ideal for:
        - Integration with SIEM systems
        - CI/CD pipeline gate checks
        - Dashboard data feeds
        - Long-term historical comparison
    """

    async def render(
        self,
        score_report: ScoreReport,
        output_path: Path,
        title: str,
        include_passing_checks: bool,
        scan_id: str,
        generated_at: str,
    ) -> None:
        """Serialize ScoreReport to a formatted JSON file."""
        report_dict = score_report.to_dict()

        # Add report metadata to the JSON output
        report_dict["_meta"] = {
            "title":          title,
            "scan_id":        scan_id,
            "generated_at":   generated_at,
            "report_format":  "json",
            "generator":      "DNS Security Analyzer",
        }

        # Filter passing checks if requested
        if not include_passing_checks:
            for cat in report_dict.get("categories", {}).values():
                cat["findings"] = [
                    f for f in cat.get("findings", [])
                    if not f.get("passed", True)
                ]

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report_dict, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        log.debug(
            "json_exporter.written",
            domain=score_report.domain,
            output_path=str(output_path),
        )