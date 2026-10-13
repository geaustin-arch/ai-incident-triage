# AI Incident Triage Copilot

An API prototype for turning a bounded set of production symptoms and log lines into an evidence-linked incident brief. It combines deterministic signal checks with structured Gemini generation through the Google Gen AI SDK on Google Cloud. If model access is off, fails, returns malformed output, or cites text that is not present in the supplied logs, the service falls back to a local heuristic assessment.

## What it demonstrates

- A small FastAPI service with bounded request schemas and typed response contracts.
- Gemini structured output through the Google Gen AI SDK and Google Cloud Application Default Credentials (ADC).
- A deterministic triage path for database connection failures, upstream timeouts, memory pressure, and HTTP 5xx signals.
- Evidence checks that reject model citations unless the line ID and quoted text match the submitted, redacted logs.
- Best-effort pre-prompt redaction for bearer tokens, common secret assignments, Google API keys, and email addresses.
- Failure containment: model errors are not returned to callers, and no generated action is executed.
- Mocked model tests for data minimization, severity escalation, secret redaction, invalid or missing citations, and provider failure.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
pytest -q
uvicorn incident_triage.app:app --reload
```

Open `http://127.0.0.1:8000/docs`. The deterministic fallback works without Google Cloud credentials.

## Enable Gemini on Google Cloud

Install the optional SDK extra and configure Application Default Credentials for your local account. The Google Cloud project needs billing, the Gemini Enterprise Agent Platform API (`aiplatform.googleapis.com`), and permission to invoke models, such as `roles/aiplatform.user`.

```bash
pip install -e '.[google-cloud]'
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_LOCATION="global"
export GEMINI_ENABLED="true"
export GEMINI_MODEL="gemini-3.5-flash-lite"
uvicorn incident_triage.app:app --reload
```

On PowerShell, use `$env:GOOGLE_CLOUD_PROJECT="your-project-id"` syntax for each variable. Model calls may incur charges. Do not commit credentials or real production logs.

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

This is a triage aid, not an autonomous operator. It never runs commands, restarts services, or changes infrastructure. The redactor is best-effort and is not a substitute for structured secret filtering, access controls, or an approved telemetry pipeline. Only the redacted summary and log excerpts are sent to the model; inputs are transient and are not persisted. The fallback rules are illustrative, and generated recommendations require on-call review.
