import json

from web_scanner.reporting.report_generator import generate_report


def test_generate_report_deduplicates_by_normalized_fingerprint():
    scan_results = {
        "target": "https://example.com",
        "findings": [
            {
                "type": "Information Disclosure",
                "severity": "Medium",
                "url": "https://example.com/",
                "description": "Found potential email addresses",
                "evidence": "Found 2 instances of potential email addresses",
            },
            {
                "title": "information disclosure",
                "severity": "medium",
                "url": "https://example.com",
                "description": "Found potential email addresses",
                "evidence": "  Found   2 instances of potential email addresses ",
            },
        ],
    }

    report = json.loads(generate_report(scan_results, output_format="json"))
    assert len(report["findings"]) == 1


def test_generate_report_sets_confidence_and_adjusts_expected_ssh_severity():
    scan_results = {
        "target": "https://example.com",
        "findings": [
            {
                "type": "Missing Security Headers",
                "severity": "High",
                "url": "https://example.com",
                "description": "Missing high priority security headers",
                "evidence": "Missing HSTS",
            },
            {
                "type": "CSRF Protection",
                "severity": "Medium",
                "url": "https://example.com/login",
                "description": "No CSRF protection detected",
                "evidence": "Missing CSRF tokens",
            },
            {
                "type": "Expected Service Not Found",
                "severity": "Medium",
                "url": "https://example.com",
                "description": "Expected SSH service not found on standard port 22",
                "evidence": "Connection attempt failed",
            },
        ],
    }

    report = json.loads(generate_report(scan_results, output_format="json"))
    findings = report["findings"]
    by_type = {f["type"]: f for f in findings}

    assert by_type["Missing Security Headers"]["confidence_score"] == "high"
    assert by_type["CSRF Protection"]["confidence_score"] == "low"
    assert by_type["Expected Service Not Found"]["severity"] == "Info"
    assert all(f.get("confidence_score") in {"high", "medium", "low"} for f in findings)


def test_generate_report_suppresses_basic_security_headers_overview_and_merges_evidence():
    scan_results = {
        "target": "https://example.com",
        "findings": [
            {
                "type": "Missing Security Headers",
                "severity": "Medium",
                "url": "https://example.com",
                "description": "Basic security headers check",
                "evidence": "Missing recommended security headers",
            },
            {
                "type": "Missing Security Headers",
                "severity": "Medium",
                "url": "https://example.com",
                "description": "Missing medium priority security headers",
                "evidence": "Missing X-Frame-Options",
            },
            {
                "type": "Information Disclosure",
                "severity": "Medium",
                "url": "https://example.com",
                "description": "Found potential email addresses",
                "evidence": "Found 2 email indicators",
            },
            {
                "type": "Information Disclosure",
                "severity": "Medium",
                "url": "https://example.com",
                "description": "Found potential email addresses",
                "evidence": "Found 1 API token indicator",
            },
        ],
    }

    report = json.loads(generate_report(scan_results, output_format="json"))
    findings = report["findings"]

    header_findings = [f for f in findings if f["type"] == "Missing Security Headers"]
    assert len(header_findings) == 1
    assert "basic security headers check" not in header_findings[0]["description"].lower()

    info_disclosure = [f for f in findings if f["type"] == "Information Disclosure"][0]
    assert "Found 2 email indicators" in info_disclosure["evidence"]
    assert "Found 1 API token indicator" in info_disclosure["evidence"]
    assert report["risk_score"] >= 0
