import json

from incident_triage.analyzer import analyze_incident
from incident_triage.schemas import IncidentRequest


class FakeProvider:
    def __init__(self, payload):
        self.payload = payload
        self.prompt = ""

    def assess(self, prompt):
        self.prompt = prompt
        return json.dumps(self.payload)


def report(log_lines=None, severity="sev2"):
    return IncidentRequest(incident_id="inc-1", service="payments-api", severity=severity,
                           summary="Elevated checkout failures after deploy", log_lines=log_lines or [
                               "db connection timeout for checkout", "request failed"])


def test_heuristic_finds_database_signal_and_escalates_sev2():
    result = analyze_incident(report())
    assert result.analysis_mode == "deterministic_fallback"
    assert result.assessment.evidence[0].line_id == "log-01"
    assert "database" in result.assessment.likely_cause.lower()
    assert result.assessment.escalation_required


def test_redacts_secrets_and_email_before_provider_call():
    provider = FakeProvider({"likely_cause":"A token-bearing request failed.", "confidence":0.8,
        "evidence":[{"line_id":"log-01","quote":"Authorization: Bearer [REDACTED]"}],
        "immediate_actions":["Rotate the exposed credential and inspect access logs."],
        "escalation_required":True,"uncertainty":"The log does not establish token use."})
    result = analyze_incident(report(["Authorization: Bearer abc123 user=a@example.test"]), provider)
    assert "abc123" not in provider.prompt and "a@example.test" not in provider.prompt
    assert result.privacy_redactions == 2
    assert result.analysis_mode == "vertex_gemini"

def test_redacts_secrets_in_summary_too():
    provider = FakeProvider({"likely_cause":"A request failed after authentication.", "confidence":0.5,
        "evidence":[],"immediate_actions":["Review authentication failures."],
        "escalation_required":False,"uncertainty":"Limited log evidence."})
    body = report(["request failed"])
    body.summary = "Authorization: Bearer summary-secret failed during checkout"
    result = analyze_incident(body, provider)
    assert "summary-secret" not in provider.prompt
    assert result.privacy_redactions == 1


def test_model_citations_must_match_real_log_text():
    provider = FakeProvider({"likely_cause":"A database failed to connect.", "confidence":0.9,
        "evidence":[{"line_id":"log-01","quote":"imaginary evidence"}],
        "immediate_actions":["Check database health."],"escalation_required":True,"uncertainty":""})
    result = analyze_incident(report(), provider)
    assert result.analysis_mode == "deterministic_fallback"
    assert all(item.quote in report().log_lines[int(item.line_id[-2:])-1] for item in result.assessment.evidence)


def test_malformed_model_json_falls_back_without_leaking_exception():
    class BrokenProvider:
        def assess(self, prompt):
            raise RuntimeError("provider secret=do-not-return")
    result = analyze_incident(report(), BrokenProvider())
    assert result.analysis_mode == "deterministic_fallback"
    assert "do-not-return" not in result.model_dump_json()


def test_api_validates_bounds_and_exposes_offline_fallback(monkeypatch):
    from fastapi.testclient import TestClient
    from incident_triage.app import app
    monkeypatch.setenv("GEMINI_ENABLED", "false")
    client = TestClient(app)
    good = {"incident_id":"inc-2","service":"api","severity":"sev3",
            "summary":"Intermittent upstream timeout","log_lines":["upstream timeout after 5s"]}
    response = client.post("/incidents/analyze", json=good)
    assert response.status_code == 200
    assert response.json()["analysis_mode"] == "deterministic_fallback"
    assert client.post("/incidents/analyze", json={**good,"log_lines":[]}).status_code == 422
    assert client.get("/health").status_code == 200
