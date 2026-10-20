
"""Pathfinder Security Auditor - JSON and standalone HTML reporting.

Generates JSON and self-contained HTML reports from the same
assessment dictionary.

Security scoring is calculated in core/scoring.py.
This module only presents the results.

No external packages, JavaScript or active security checks are required.
"""

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"

STATUS_ORDER = {
    "FAIL": 0,
    "ERROR": 1,
    "WARN": 2,
    "PASS": 3,
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def _text(value) -> str:
    """Escape untrusted scan data before inserting it into HTML."""
    if value is None:
        return "—"

    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, indent=2)

    return html.escape(str(value), quote=True)


def _evidence(value) -> str:
    """Pretty-print JSON evidence; preserve plain text if not JSON."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            pass

    return _text(value)


def _badge(value: str, kind: str = "status") -> str:
    """Display a safely escaped status or severity label."""
    normalized = str(value or "UNKNOWN").upper()

    allowed = {
        "PASS",
        "FAIL",
        "WARN",
        "ERROR",
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    }

    css_class = normalized.lower() if normalized in allowed else "unknown"

    return (
        f'<span class="badge {kind}-{css_class}">'
        f'{_text(normalized)}'
        f'</span>'
    )


def _baseline_html(baseline) -> str:
    """Render baseline results without assuming a specific schema."""
    if baseline is None:
        return "<p>No baseline data available.</p>"

    if isinstance(baseline, (dict, list)):
        return (
            "<details>"
            "<summary>View Baseline Results (JSON)</summary>"
            f"<pre>{_evidence(baseline)}</pre>"
            "</details>"
        )

    return f"<pre>{_text(baseline)}</pre>"


def _security_score_html(score_data) -> str:
    """Render the security posture score and its deductions.

    The score is calculated by core/scoring.py.
    The reporter does not modify or recalculate it.
    """
    if not isinstance(score_data, dict):
        score_data = {}

    raw_score = score_data.get("score")

    if type(raw_score) is int and 0 <= raw_score <= 100:
        score = raw_score
        score_display = f"{score} / 100"
        bar_width = score

        if score >= 90:
            color = "#25865c"
        elif score >= 75:
            color = "#d69a32"
        else:
            color = "#c74747"
    else:
        score = None
        score_display = "Not calculated"
        bar_width = 0
        color = "#64748b"

    rating = score_data.get("rating", "NOT CALCULATED")
    deductions = score_data.get("deductions", [])
    errors = score_data.get("errors", 0)

    if not isinstance(deductions, list):
        deductions = []

    deduction_rows = []

    for item in deductions:
        if not isinstance(item, dict):
            continue

        check_id = _text(item.get("check_id", "UNKNOWN"))
        title = _text(item.get("title", "Unknown finding"))
        severity = _text(item.get("severity", "INFO"))
        points = _text(item.get("points", 0))

        deduction_rows.append(
            '<li class="deduction-item">'
            "<div>"
            f"<strong>{check_id}</strong> — {title}"
            f'<div class="muted">Severity: {severity}</div>'
            "</div>"
            f'<strong class="deduction-points">−{points}</strong>'
            "</li>"
        )

    if not deduction_rows:
        deduction_rows.append(
            "<li>No score deductions from assessed findings.</li>"
        )

    deduction_html = "\n".join(deduction_rows)

    try:
        error_count = int(errors)
    except (TypeError, ValueError):
        error_count = 0

    if error_count > 0:
        error_warning = (
            '<p class="score-warning">'
            f"{_text(error_count)} security check(s) could not be completed. "
            "The assessment is incomplete and the score must not be "
            "interpreted as an overall security rating."
            "</p>"
        )
    else:
        error_warning = ""

    method = _text(
        score_data.get(
            "method",
            "Project-defined severity-weighted heuristic",
        )
    )

    limitations = _text(
        score_data.get(
            "limitations",
            "This score is a project-defined heuristic and does not "
            "measure overall system security.",
        )
    )

    return f"""
    <section class="score-section">
      <div class="score-heading">
        <div>
          <h2>Security Posture Score</h2>
          <p class="muted">
            Risk prioritization indicator based on selected findings
          </p>
        </div>

        <span class="score-rating">{_text(rating)}</span>
      </div>

      <div class="score-value" style="color:{color}">
        {score_display}
      </div>

      <div
        class="score-track"
        role="progressbar"
        aria-label="Security posture score"
        aria-valuemin="0"
        aria-valuemax="100"
        {f'aria-valuenow="{score}"' if score is not None else ""}
      >
        <div
          class="score-fill"
          style="width:{bar_width}%;background:{color}"
        ></div>
      </div>

      {error_warning}

      <p class="score-explanation">
        A higher score indicates fewer weighted deviations among
        the checks assessed by Pathfinder. It does not represent
        the probability that the system is secure.
      </p>

      <details>
        <summary>View Score Deductions &amp; Methodology</summary>

        <h3>Findings Reducing the Score</h3>

        <ul class="deductions">
          {deduction_html}
        </ul>

        <p><strong>Method:</strong> {method}</p>

        <p class="muted">
          Standard deductions: CRITICAL −25, HIGH −15,
          MEDIUM −8, LOW −3 and INFO 0.
          Only selected WARN and FAIL findings reduce the score.
          Overlapping inventory and correlation findings are excluded
          to reduce double counting.
        </p>

        <p class="muted">
          <strong>Limitations:</strong> {limitations}
        </p>
      </details>
    </section>
    """


def render_html_report(report: dict) -> str:
    """Build a self-contained HTML document from a scan report."""
    findings = report.get("findings", [])

    if not isinstance(findings, list):
        findings = []

    findings = [
        item
        for item in findings
        if isinstance(item, dict)
    ]

    counts = Counter(
        str(f.get("status", "UNKNOWN")).upper()
        for f in findings
    )

    ordered = sorted(
        findings,
        key=lambda f: (
            STATUS_ORDER.get(
                str(f.get("status", "")).upper(),
                9,
            ),
            SEVERITY_ORDER.get(
                str(f.get("severity", "")).upper(),
                9,
            ),
            str(f.get("check_id", "")),
        ),
    )

    rows = []

    for finding in ordered:
        check_id = _text(finding.get("check_id", "UNKNOWN"))
        title = _text(finding.get("title", "Untitled finding"))
        status = _badge(finding.get("status", "UNKNOWN"))

        severity = _badge(
            finding.get("severity", "INFO"),
            "severity",
        )

        description = _text(
            finding.get("description", "")
        )

        recommendation = _text(
            finding.get("recommendation", "")
        )

        evidence = _evidence(
            finding.get("evidence", "")
        )

        rows.append(f"""
        <article class="finding">
          <div class="finding-heading">
            <div>
              <span class="check-id">{check_id}</span>
              <h3>{title}</h3>
            </div>

            <div class="badges">
              {status}{severity}
            </div>
          </div>

          <p>{description}</p>

          <div class="recommendation">
            <strong>Recommendation</strong>
            <p>{recommendation}</p>
          </div>

          <details>
            <summary>View Technical Evidence</summary>
            <pre>{evidence}</pre>
          </details>
        </article>
        """)

    summary_cards = "".join(
        (
            '<div class="metric">'
            f'<strong>{counts.get(status, 0)}</strong>'
            f'<span>{status}</span>'
            "</div>"
        )
        for status in ("FAIL", "WARN", "ERROR", "PASS")
    )

    system = report.get("system", {})

    if not isinstance(system, dict):
        system = {}

    system_summary = " · ".join(
        f"{_text(key)}: {_text(value)}"
        for key, value in system.items()
    ) or "Not specified"

    scanner = _text(
        report.get(
            "scanner",
            "Pathfinder Security Auditor",
        )
    )

    version = _text(
        report.get("version", "unknown")
    )

    timestamp = _text(
        report.get("timestamp", "unknown")
    )

    baseline_html = _baseline_html(
        report.get("baseline")
    )

    score_html = _security_score_html(
        report.get("security_score")
    )

    finding_html = (
        "\n".join(rows)
        if rows
        else "<p>No findings in the report.</p>"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pathfinder | Security Report</title>

<style>
:root {{
  color-scheme: light;
  --ink: #15243b;
  --muted: #5a697c;
  --border: #dce4ed;
  --paper: #ffffff;
  --bg: #f3f6fa;
  --blue: #1761a0;
}}

* {{
  box-sizing: border-box;
}}

body {{
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif;
}}

header {{
  background: #132a45;
  color: white;
  padding: 38px max(22px, calc((100vw - 1040px)/2));
}}

header h1 {{
  font-size: 2rem;
  margin: 0 0 7px;
}}

header p {{
  color: #d4e2f0;
  margin: 5px 0;
}}

main {{
  max-width: 1040px;
  margin: auto;
  padding: 26px 22px 70px;
}}

section {{
  background: var(--paper);
  border: 1px solid var(--border);
  border-radius: 13px;
  padding: 24px;
  margin-bottom: 22px;
}}

h2 {{
  font-size: 1.25rem;
  margin: 0 0 15px;
}}

h3 {{
  font-size: 1.03rem;
  margin: 3px 0 0;
}}

p {{
  margin: 10px 0;
}}

.muted {{
  color: var(--muted);
}}

.metrics {{
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}}

.metric {{
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px;
  display: flex;
  flex-direction: column;
}}

.metric strong {{
  font-size: 2rem;
}}

.metric span {{
  color: var(--muted);
  font-size: .82rem;
  letter-spacing: .06em;
}}

.score-section {{
  border-top: 4px solid #1761a0;
}}

.score-heading {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
}}

.score-heading h2 {{
  margin-bottom: 4px;
}}

.score-rating {{
  background: #edf1f5;
  color: #34445a;
  border-radius: 999px;
  padding: 6px 12px;
  font-size: .8rem;
  font-weight: 750;
  white-space: nowrap;
}}

.score-value {{
  font-size: clamp(2.8rem, 7vw, 4.5rem);
  font-weight: 800;
  line-height: 1.2;
  margin: 15px 0;
}}

.score-track {{
  height: 16px;
  background: #e2e8f0;
  border-radius: 999px;
  overflow: hidden;
}}

.score-fill {{
  height: 100%;
  border-radius: inherit;
}}

.score-explanation {{
  margin-top: 17px;
  color: var(--muted);
}}

.score-warning {{
  padding: 12px 15px;
  border-left: 4px solid #c74747;
  background: #fff0f0;
  color: #872626;
}}

.deductions {{
  padding-left: 22px;
}}

.deduction-item {{
  padding: 10px 0;
  display: flex;
  justify-content: space-between;
  gap: 20px;
  border-bottom: 1px solid var(--border);
}}

.deduction-points {{
  color: #b73c3c;
  white-space: nowrap;
}}

.finding {{
  padding: 20px 0;
  border-top: 1px solid var(--border);
}}

.finding:first-of-type {{
  border-top: 0;
  padding-top: 0;
}}

.finding-heading {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 15px;
}}

.check-id {{
  color: var(--muted);
  font: 600 .8rem ui-monospace, monospace;
}}

.badges {{
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  justify-content: flex-end;
}}

.badge {{
  display: inline-block;
  border-radius: 999px;
  padding: 3px 10px;
  font-size: .75rem;
  font-weight: 750;
  white-space: nowrap;
  background: #edf1f5;
  color: #44556b;
}}

.status-fail,
.severity-critical,
.severity-high {{
  background: #fde7e7;
  color: #962727;
}}

.status-warn,
.severity-medium {{
  background: #fff0ce;
  color: #8a5900;
}}

.status-error {{
  background: #f5dffc;
  color: #753387;
}}

.status-pass {{
  background: #e2f5e9;
  color: #216c3c;
}}

.severity-low {{
  background: #e8f0ff;
  color: #27518a;
}}

.recommendation {{
  border-left: 3px solid var(--blue);
  padding: 8px 14px;
  background: #f3f8fd;
  margin: 14px 0;
}}

.recommendation p {{
  margin: 4px 0 0;
}}

details {{
  margin-top: 12px;
}}

summary {{
  cursor: pointer;
  color: var(--blue);
  font-weight: 600;
}}

pre {{
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 480px;
  overflow: auto;
  background: #101f31;
  color: #e7eff8;
  padding: 16px;
  border-radius: 8px;
  font-size: .8rem;
}}

.note {{
  border-left: 3px solid #d6a340;
  padding-left: 14px;
}}

footer {{
  text-align: center;
  color: var(--muted);
  font-size: .85rem;
  padding: 0 20px 30px;
}}

@media (max-width: 600px) {{
  .metrics {{
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }}

  .finding-heading,
  .score-heading {{
    flex-direction: column;
  }}

  header h1 {{
    font-size: 1.55rem;
  }}
}}

@media print {{
  body {{
    background: white;
  }}

  header {{
    padding: 20px;
  }}

  main {{
    padding: 15px;
  }}

  section {{
    break-inside: avoid;
  }}

  details:not([open]) {{
    display: none;
  }}
}}
</style>
</head>

<body>
<header>
  <h1>Pathfinder Security Auditor</h1>
  <p>Host-Based Security Report · Version {version}</p>
  <p>Scan Date (UTC): {timestamp}</p>
</header>

<main>

  {score_html}

  <section>
    <h2>Overview</h2>

    <p>
      <strong>{scanner}</strong> · {_text(len(findings))} findings
    </p>

    <div class="metrics">{summary_cards}</div>

    <p class="muted">System: {system_summary}</p>

    <p class="note">
      Finding status and severity are project-defined assessments.
      A WARN status or a CVE search result does not establish
      the existence of an exploitable vulnerability.
    </p>
  </section>

  <section>
    <h2>Methodology &amp; Scope</h2>

    <p>
      Pathfinder performs local, read-only configuration and
      inventory checks on Windows systems. The results are
      observations intended to support manual risk assessment
      and remediation.
    </p>

    <p>
      Firewall correlation and exposure prioritization are
      heuristic and do not confirm external network reachability.
      NVD-based CVE search results are potential references,
      not version-validated vulnerabilities.
      The scan does not perform active penetration testing,
      exploitation or network verification from another machine.
    </p>
  </section>

  <section>
    <h2>Baseline</h2>

    <p class="muted">
      Project-specific security baseline.
      This is not a certified CIS or ISO 27001 compliance assessment.
    </p>

    {baseline_html}
  </section>

  <section>
    <h2>Findings &amp; Recommendations</h2>

    <p class="muted">
      Findings are sorted by status and then by severity.
      Expand each finding to view its technical evidence.
    </p>

    {finding_html}
  </section>

  <section>
    <h2>Future Development</h2>

    <p>
      Possible future improvements include version-validated
      CVE matching, more detailed patch verification and
      authorized network testing from a separate machine
      within an isolated laboratory environment.
      AI-assisted analysis and penetration testing remain
      future development concepts and are not implemented
      in this version.
    </p>
  </section>

</main>

<footer>
  Pathfinder Security Auditor · Generated locally from JSON scan data
</footer>
</body>
</html>"""


def save_report(report: dict) -> Path:
    """Save a timestamped JSON report and return its path."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    report_path = REPORTS_DIR / f"pathfinder_{timestamp}.json"

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
        )

    return report_path


def save_html_report(report: dict, json_path: Path) -> Path:
    """Save HTML beside the JSON report using the same filename stem."""
    html_path = Path(json_path).with_suffix(".html")

    html_path.write_text(
        render_html_report(report),
        encoding="utf-8",
    )

    return html_path
