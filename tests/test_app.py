import app as training_app


def test_app_starts_and_index_loads():
    client = training_app.app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"GitHub Advanced Security demo lab" in response.data


def test_dashboard_loads_sample_reports():
    client = training_app.app.test_client()
    response = client.get("/security-dashboard")
    assert response.status_code == 200
    assert b"SAST" in response.data
    assert b"Dependencies" in response.data


def test_sample_report_parser_returns_findings():
    findings = training_app.collect_findings()
    summary = training_app.summarize_findings(findings)
    assert summary["total"] >= 3
    assert summary["by_type"]["sast"] >= 1
