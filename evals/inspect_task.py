"""Optional Inspect adapter; no live API calls unless live_model is supplied."""
import json
from pathlib import Path
from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.model import ModelOutput
from inspect_ai.solver import solver
from evals.run import evaluate_case
from evals.scorers import decision_quality


@solver
def security_solver(live_model=None):
    async def solve(state, generate):
        result, latency = await evaluate_case(state.metadata["case"], live_model=live_model)
        state.output = ModelOutput.from_content("security-risk-agent", result.decision)
        state.metadata["assessment"] = result.model_dump(mode="json")
        state.metadata["latency_ms"] = latency
        return state
    return solve


@task
def security_risk(live_model=None):
    cases = json.loads(Path(__file__).with_name("cases.json").read_text())
    return Task(dataset=[Sample(id=c["id"], input=c["justification"], target=c["expected"],
        metadata={"case": c}) for c in cases], solver=security_solver(live_model), scorer=decision_quality())
