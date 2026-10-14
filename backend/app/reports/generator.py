import json
from datetime import datetime
import html


def generate_report_data(project_id: str, findings: list, audit_logs: list) -> dict:
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Calculate summary by severity
    severity_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    # Calculate summary by category
    category_summary = {}

    # Reviewer status counts
    status_summary = {"PENDING_REVIEW": 0, "ACCEPTED": 0, "EDITED": 0, "REJECTED": 0}

    # Get repo_version from latest audit log if available
    repo_version = "UNKNOWN"
    if audit_logs:
        for log in audit_logs:
            if log.get("repo_version"):
                repo_version = log.get("repo_version")
                break

    # Combine findings with their audit data
    enriched_findings = []

    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in severity_summary:
            severity_summary[sev] += 1

        cat = f.get("category", "Uncategorized")
        category_summary[cat] = category_summary.get(cat, 0) + 1

        status = f.get("status", "PENDING_REVIEW")
        status_summary[status] = status_summary.get(status, 0) + 1

        # Find related audit log for this finding (latest analysis event)
        f_audit = [
            a
            for a in audit_logs
            if a.get("finding_id") == f.get("finding_id")
            and a.get("event_type") == "ANALYSIS"
        ]
        latest_audit = f_audit[0] if f_audit else {}

        rag_sources = []
        if latest_audit.get("rag_sources"):
            try:
                rag_sources = json.loads(latest_audit.get("rag_sources"))
            except Exception:
                pass

        enriched_findings.append(
            {
                "finding_id": f.get("finding_id"),
                "status": status,
                "severity": sev,
                "category": cat,
                "title": f.get("title"),
                "file": f.get("file"),
                "line_start": f.get("line_start"),
                "function": f.get("function"),
                "confidence": f.get("confidence"),
                "diagnostic_message": f.get("diagnostic_message"),
                "evidence_status": f.get("evidence_status", "INSUFFICIENT_CONTEXT"),
                "source": f.get("source"),
                "rule": f.get("rule"),
                "evidence": f.get("evidence"),  # Source evidence
                "finding": f.get("finding"),  # Static-analysis evidence / explanation
                "root_cause": f.get("root_cause"),
                "recommendation": f.get("recommendation"),  # AI recommendation
                "suggested_fix": f.get("suggested_fix"),
                "rag_references": rag_sources,
            }
        )

    return {
        "project_info": {
            "project_id": project_id,
            "repo_version": repo_version,
            "analysis_timestamp": timestamp,
        },
        "summaries": {
            "severity": severity_summary,
            "category": category_summary,
            "status": status_summary,
        },
        "findings": enriched_findings,
    }


def generate_json_report(project_id: str, findings: list, audit_logs: list) -> str:
    data = generate_report_data(project_id, findings, audit_logs)
    return json.dumps(data, indent=2)


def generate_html_report(project_id: str, findings: list, audit_logs: list) -> str:
    data = generate_report_data(project_id, findings, audit_logs)
    pi = data["project_info"]
    ss = data["summaries"]["severity"]
    sc = data["summaries"]["category"]
    st = data["summaries"]["status"]

    html_out = f"""
    <html>
    <head>
        <title>Automotive Secure Code Review Report - {pi['project_id']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
            h1, h2, h3 {{ color: #222; }}
            .container {{ max-width: 1200px; margin: auto; }}
            .metadata-box {{ display: flex; gap: 20px; margin-bottom: 30px; }}
            .summary-card {{ flex: 1; background: #f9f9f9; padding: 20px; border-radius: 8px; border: 1px solid #ddd; }}
            .finding {{ border: 1px solid #e0e0e0; padding: 20px; margin-bottom: 25px; border-radius: 8px; background: #fff; }}
            .CRITICAL {{ border-left: 6px solid #d9534f; }}
            .HIGH {{ border-left: 6px solid #f0ad4e; }}
            .MEDIUM {{ border-left: 6px solid #5bc0de; }}
            .LOW {{ border-left: 6px solid #5cb85c; }}
            .INFO {{ border-left: 6px solid #aaa; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 15px; }}
            th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #eee; }}
            th {{ width: 150px; color: #666; }}
            pre {{ background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: Consolas, monospace; font-size: 14px; border: 1px solid #e0e0e0; }}
            .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
            .badge-status {{ background: #e9ecef; color: #495057; border: 1px solid #ced4da; }}
            .badge-severity {{ background: #343a40; color: #fff; }}
            ul.no-bullets {{ list-style-type: none; padding: 0; }}
            ul.no-bullets li {{ margin-bottom: 5px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Automotive Secure Code Review Report</h1>
            
            <div class="metadata-box">
                <div class="summary-card">
                    <h2>Project Information</h2>
                    <p><strong>Project ID:</strong> {html.escape(pi['project_id'])}</p>
                    <p><strong>Repo Version:</strong> {html.escape(pi['repo_version'])}</p>
                    <p><strong>Analysis Timestamp:</strong> {html.escape(pi['analysis_timestamp'])}</p>
                </div>
                
                <div class="summary-card">
                    <h2>Summary by Severity</h2>
                    <ul class="no-bullets">
                        <li><span class="badge badge-severity" style="background:#d9534f">CRITICAL</span> : {ss['CRITICAL']}</li>
                        <li><span class="badge badge-severity" style="background:#f0ad4e">HIGH</span> : {ss['HIGH']}</li>
                        <li><span class="badge badge-severity" style="background:#5bc0de">MEDIUM</span> : {ss['MEDIUM']}</li>
                        <li><span class="badge badge-severity" style="background:#5cb85c">LOW</span> : {ss['LOW']}</li>
                        <li><span class="badge badge-severity" style="background:#aaa">INFO</span> : {ss['INFO']}</li>
                    </ul>
                </div>

                <div class="summary-card">
                    <h2>Reviewer Status</h2>
                    <ul class="no-bullets">
                        <li><strong>Pending Review:</strong> {st.get('PENDING_REVIEW', 0)}</li>
                        <li><strong>Accepted:</strong> {st.get('ACCEPTED', 0)}</li>
                        <li><strong>Edited:</strong> {st.get('EDITED', 0)}</li>
                        <li><strong>Rejected:</strong> {st.get('REJECTED', 0)}</li>
                    </ul>
                </div>
            </div>

            <div class="metadata-box">
                <div class="summary-card" style="width: 100%;">
                    <h2>Summary by Category</h2>
                    <ul>
                        {"".join(f"<li>{html.escape(k)}: {v}</li>" for k, v in sc.items())}
                    </ul>
                </div>
            </div>
            
            <h2>Detailed Findings ({len(data['findings'])})</h2>
    """

    for f in data["findings"]:
        rag_html = ""
        if f["rag_references"]:
            rag_html = (
                "<ul>"
                + "".join(
                    f"<li>{html.escape(str(r))}</li>" for r in f["rag_references"]
                )
                + "</ul>"
            )
        else:
            rag_html = "<em>No RAG references retrieved for this finding.</em>"

        html_out += f"""
            <div class="finding {f['severity']}">
                <h3>[{html.escape(f['finding_id'])}] {html.escape(f['title'])}</h3>
                <div style="margin-bottom: 15px;">
                    <span class="badge badge-status">{html.escape(f['status'])}</span>
                    <span class="badge badge-severity">{html.escape(f['severity'])}</span>
                </div>
                <table>
                    <tr><th>Category</th><td>{html.escape(f['category'])}</td></tr>
                    <tr><th>Location</th><td>{html.escape(f.get('file', ''))} : Line {f.get('line_start', '')}</td></tr>
                    <tr><th>Function</th><td>{html.escape(f.get('function') or 'N/A')}</td></tr>
                    <tr><th>Confidence</th><td>{f.get('confidence')}</td></tr>
                    <tr><th>Evidence Status</th><td>{html.escape(f.get('evidence_status') or 'INSUFFICIENT_CONTEXT')}</td></tr>
                    <tr><th>Diagnostic</th><td>{html.escape(f.get('rule') or '')}: {html.escape(f.get('diagnostic_message') or '')}</td></tr>
                    <tr><th>Source/Rule</th><td>{html.escape(f.get('source', ''))} / {html.escape(f.get('rule') or 'N/A')}</td></tr>
                </table>
                
                <h4>Source Evidence (Code)</h4>
                <pre>{html.escape(f.get('evidence') or 'No code evidence provided.')}</pre>
                
                <h4>Static Analysis / AI Explanation</h4>
                <p>{html.escape(f.get('finding') or 'N/A')}</p>
                
                <h4>AI Recommendations</h4>
                <p>{html.escape(f.get('recommendation') or 'No recommendation provided.')}</p>
                
                <h4>RAG Context References</h4>
                {rag_html}
            </div>
        """

    html_out += """
        </div>
    </body>
    </html>
    """
    return html_out
