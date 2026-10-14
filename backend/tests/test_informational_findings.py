import json

from app.reports.generator import generate_report_data
from app.security.cppcheck import run_cppcheck_on_code


def test_missing_include_findings_are_informational():
    findings = run_cppcheck_on_code(
        '#include <missing_one.h>\n#include <missing_two.h>\nint main() { return 0; }\n',
        "c",
    )

    include_findings = [
        finding for finding in findings
        if finding["type"] in {"missingInclude", "missingIncludeSystem"}
    ]

    assert include_findings
    assert all(finding["severity"] == "INFO" for finding in include_findings)


def test_report_keeps_severity_and_confidence_independent():
    findings = [
        {
            "finding_id": str(index),
            "status": "PENDING_REVIEW",
            "severity": "INFO",
            "category": "STATIC_ANALYSIS",
            "title": "missingIncludeSystem detected",
            "confidence": 0.9,
            "evidence_status": "INSUFFICIENT_CONTEXT",
            "rule": "missingIncludeSystem",
            "diagnostic_message": "Include file not found",
        }
        for index in range(4)
    ]

    report = generate_report_data("project", findings, [])

    assert report["summaries"]["severity"] == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 4,
    }
    assert all(item["severity"] == "INFO" for item in report["findings"])
    assert all(item["confidence"] == 0.9 for item in report["findings"])
    assert all(item["evidence_status"] == "INSUFFICIENT_CONTEXT" for item in report["findings"])
    assert json.loads(json.dumps(report))["findings"][0]["rule"] == "missingIncludeSystem"
