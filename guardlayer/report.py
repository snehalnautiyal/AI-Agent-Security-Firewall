"""
Report Generator — builds an HTML security report from session data.
Uses Jinja2 to render the report template with all scan findings.
"""

from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from guardlayer import __version__
from guardlayer.models import SessionRecord, ThreatCategory
from guardlayer.session_store import SessionStore

# Template lives next to this file in guardlayer/templates/
TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_report(store: SessionStore, output_path: Path) -> Path:
    """
    Render the HTML report and write it to output_path.
    Returns the path to the written file.
    """
    records = store.all_records()
    now = datetime.now(tz=timezone.utc)

    # Calculate summary stats
    blocked_count = sum(1 for r in records if r.was_blocked)
    suspicious_count = sum(
        1 for r in records
        if not r.was_blocked and r.request_scan.highest_score > 30
    )
    safe_count = len(records) - blocked_count - suspicious_count
    total_findings = sum(len(r.request_scan.findings) for r in records)

    # Count occurrences of each threat category
    category_counter: Counter[str] = Counter()
    for record in records:
        for finding in record.request_scan.findings:
            category_counter[finding.category.value] += 1

    # Compute session duration from first to last record
    if records:
        first_ts = records[0].timestamp
        last_ts = records[-1].timestamp
        duration_seconds = int((last_ts - first_ts).total_seconds())
        session_duration = f"{duration_seconds // 60}m {duration_seconds % 60}s"
    else:
        session_duration = "0s"

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html")

    html_content = template.render(
        records=records,
        generated_at=now.strftime("%Y-%m-%d %H:%M UTC"),
        session_duration=session_duration,
        total_requests=len(records),
        blocked_count=blocked_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
        total_findings=total_findings,
        threat_counts=dict(category_counter),
        version=__version__,
    )

    output_path.write_text(html_content, encoding="utf-8")
    return output_path
