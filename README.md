# AI Incident Triage Copilot

An API prototype for turning a bounded set of production symptoms and log lines into an evidence-linked incident brief. It combines deterministic signal checks with structured Gemini generation on Vertex AI. If model access is off, fails, returns malformed output, or cites text that is not present in the supplied logs, the service falls back to a local heuristic assessment.

## What it demonstrates

- A small FastAPI service with bounded request schemas and typed response contracts.
- Gemini structured output through the Google Gen AI SDK and Vertex AI ADC.
- A deterministic triage path for database connection failures, upstream timeouts, memory pressure, and HTTP 5xx signals.
- Evidence checks that reject model citations unless the line ID and quoted text match the submitted, redacted logs.
- Basic pre-prompt redaction for bearer tokens, common secret assignments, and email addresses.
- Failure containment: model errors are not returned to callers, and no generated action is executed.
- Mocked model tests, including injection-shaped input, invalid citations, and provider failure.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
pytest -q
uvicorn incident_triage.app:app --reload
```

Open `http://127.0.0.1:8000/docs`. The deterministic fallback works without Google Cloud credentials.

## Enable Gemini on Vertex AI

Install the optional SDK extra and configure Application Default Credentials for your local account. The Google Cloud project needs billing, the Vertex AI API, and the `roles/aiplatform.user` permission.

```bash
pip install -e '.[vertex]'
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_LOCATION="global"
export GEMINI_ENABLED="true"
export GEMINI_MODEL="gemini-2.5-flash"
uvicorn incident_triage.app:app --reload
```

On PowerShell, use `$env:GOOGLE_CLOUD_PROJECT="your-project-id"` syntax for each variable. Vertex calls may incur charges. Do not commit credentials or real production logs.

## Example request

```json
{
  "incident_id": "inc-2026-014",
  "service": "checkout-api",
  "severity": "sev2",
  "summary": "Checkout errors increased after the last deployment",
  "log_lines": [
    "2026-10-13T13:42:10Z database connection timeout after 5s",
    "2026-10-13T13:42:12Z request failed status=503"
  ]
}
```

Send it to `POST /incidents/analyze`. The result includes an analysis mode, likely cause, confidence, cited lines, suggested checks, escalation flag, and count of redactions.

## Safety and scope

This is a triage aid, not an autonomous operator. It never runs commands, restarts services, or changes infrastructure. The redactor is intentionally simple and is not a substitute for structured secret filtering, access controls, or an approved telemetry pipeline. Inputs are transient and are not persisted. The fallback rules are illustrative, and generated recommendations require on-call review.
