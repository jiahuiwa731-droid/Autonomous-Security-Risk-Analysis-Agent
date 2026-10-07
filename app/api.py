import os
import math
from fastapi import FastAPI
from app.schemas import AssessmentRequest, SecurityDecision
from app.integrations import NVD, Neo4jContext
from app.tools import RunState
from app.agent import assess
from app.demo import DemoCVE, DemoContext, demo_assess


def create_app():
    application = FastAPI(title="Security Risk Agent", version="0.1.0")

    @application.get("/healthz")
    async def health():
        # Liveness only: do not expose credentials or imply upstream readiness.
        return {"status": "ok"}

    @application.post("/v1/assessments", response_model=SecurityDecision)
    async def assessment(request: AssessmentRequest):
        mode = os.getenv("AGENT_MODE", "live")
        if mode not in {"live", "demo"}:
            raise RuntimeError("AGENT_MODE must be live or demo")
        try:
            configured_steps = int(os.getenv("MAX_AGENT_STEPS", "12"))
        except ValueError:
            configured_steps = 12
        try:
            configured_timeout = float(os.getenv("ASSESSMENT_TIMEOUT", "90"))
        except ValueError:
            configured_timeout = 90
        if not math.isfinite(configured_timeout):
            configured_timeout = 90
        state = RunState(request, DemoCVE() if mode == "demo" else NVD(),
            DemoContext() if mode == "demo" else Neo4jContext(),
            max_steps=max(1, min(50, configured_steps)))
        if mode == "demo":
            return await demo_assess(state)
        return await assess(state, timeout=max(1, min(300, configured_timeout)))

    return application


app = create_app()
