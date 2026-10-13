import os
from fastapi import FastAPI
from .analyzer import analyze_incident
from .schemas import IncidentRequest, IncidentResponse

app = FastAPI(title="AI Incident Triage Copilot", version="0.1.0")


@app.get("/health")
def health():
    return {"status": "ok", "model_enabled": os.getenv("GEMINI_ENABLED", "false").lower() == "true"}


@app.post("/incidents/analyze", response_model=IncidentResponse)
def analyze(body: IncidentRequest):
    return analyze_incident(body)
