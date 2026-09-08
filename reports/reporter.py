import json
from datetime import datetime
from typing import List, Dict, Any

class FIMReporter:
    """
    Exports host integrity violations to SIEM-compatible JSON
    and generates visual HTML forensic dossiers for SOC analysts.
    """

    @staticmethod
    def export_json(findings: List[Dict[str, Any]], filepath: str = "fim_audit_report.json") -> None:
        payload = {
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "engine": "Linux-Host-FIM-Auditor-v1.0",
                "total_drifts_detected": len(findings)
            },
            "findings": findings
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    @staticmethod
    def export_html(findings: List[Dict[str, Any]], filepath: str = "fim_forensic_dossier.html") -> None:
        critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in findings if f["severity"] == "HIGH")
        medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")

        rows_html = ""
        for f in findings:
            sev = f["severity"]
            badge_class = "badge-critical" if sev == "CRITICAL" else ("badge-high" if sev == "HIGH" else "badge-medium")
            threat = f.get("threat", {})

            rows_html += f"""
            <tr>
                <td><strong><code>{f['filepath']}</code></strong></td>
                <td><span class="event-tag">{f['event_type']}</span></td>
                <td><span class="badge {badge_class}">{sev}</span></td>
                <td><code style="color: #38bdf8;">{threat.get('technique_id', 'N/A')}</code></td>
                <td>{threat.get('tactic', 'N/A')}</td>
                <td>{f['description']}</td>
                <td><strong>{threat.get('soc_action', 'Review changes immediately.')}</strong></td>
            </tr>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Host File Integrity Forensic Dossier</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 30px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 25px; }}
        .header h1 {{ margin: 0 0 8px 0; color: #38bdf8; font-size: 26px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: #1e293b; padding: 18px; border-radius: 8px; border-left: 4px solid #38bdf8; }}
        .stat-card.critical {{ border-left-color: #ef4444; }}
        .stat-card.high {{ border-left-color: #f59e0b; }}
        .stat-card.clean {{ border-left-color: #10b981; }}
        .stat-val {{ font-size: 28px; font-weight: bold; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; font-size: 14px; }}
        th, td {{ padding: 14px 16px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; text-transform: uppercase; font-size: 12px; letter-spacing: 0.05em; }}
        tr:hover {{ background: #243248; }}
        .badge {{ padding: 4px 10px; border-radius: 9999px; font-weight: bold; font-size: 11px; }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid #ef4444; }}
        .badge-high {{ background: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid #f59e0b; }}
        .badge-medium {{ background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid #3b82f6; }}
        .event-tag {{ background: #334155; padding: 3px 8px; border-radius: 4px; font-size: 11px; color: #cbd5e1; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Linux Host File Integrity Forensic Dossier</h1>
            <div style="color: #94a3b8; font-size: 13px;">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')} | Host Intrusion Detection Engine (HIDS)</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div style="color: #94a3b8; font-size: 13px;">Total Drifts</div>
                <div class="stat-val" style="color: #38bdf8;">{len(findings)}</div>
            </div>
            <div class="stat-card critical">
                <div style="color: #94a3b8; font-size: 13px;">Critical Tampering</div>
                <div class="stat-val" style="color: #ef4444;">{critical_count}</div>
            </div>
            <div class="stat-card high">
                <div style="color: #94a3b8; font-size: 13px;">High Drift</div>
                <div class="stat-val" style="color: #f59e0b;">{high_count}</div>
            </div>
            <div class="stat-card clean">
                <div style="color: #94a3b8; font-size: 13px;">Medium Severity</div>
                <div class="stat-val" style="color: #3b82f6;">{medium_count}</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Monitored Asset</th>
                    <th>Drift Type</th>
                    <th>Severity</th>
                    <th>MITRE ID</th>
                    <th>Tactic</th>
                    <th>Forensic Description</th>
                    <th>Recommended SOC Action</th>
                </tr>
            </thead>
            <tbody>
                {rows_html if findings else '<tr><td colspan="7" style="text-align: center; color: #10b981;">No file tampering or permission drifts detected. System integrity intact.</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_template)
