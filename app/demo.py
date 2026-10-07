"""Explicit synthetic fixtures. Demo orchestration is deterministic, not an LLM."""
import asyncio
import json
from app.schemas import Vulnerability, AssetContext, Asset, AssessmentRequest, Proposal
from app.tools import RunState


class DemoCVE:
    async def lookup(self, cve_id):
        scores = {"CVE-2026-1234": 9.8, "CVE-2026-1235": 3.1, "CVE-2026-1236": 7.5}
        if cve_id not in scores:
            raise LookupError("No fixture")
        return Vulnerability(cve_id=cve_id, description="SYNTHETIC demo vulnerability",
            cvss=scores[cve_id], attack_vector="NETWORK", affected_products=["demo-service 1.0"],
            source="fixture:synthetic-cve")


class DemoContext:
    async def lookup(self, request):
        return AssetContext(**request.model_dump(), complete=True, source="fixture:synthetic-graph",
            assets=[Asset(asset_id="demo-service", environment=request.environment,
                internet_facing=True, criticality="high", owner="demo-platform-team")])


async def demo_assess(state):
    for _ in range(2):
        if "error" not in await state.get_cve_details():
            break
    if state.cve is None:
        return await state.finish(None, "deterministic-demo")
    for _ in range(2):
        if "error" not in await state.get_asset_context():
            break
    if state.context is None:
        return await state.finish(None, "deterministic-demo")
    await state.check_policy("ALLOW")
    if state.policy:
        await state.remediation()
    return await state.finish(Proposal(decision=state.policy.decision if state.policy else "REVIEW",
        summary="Synthetic demonstration using configured SHACL rules."), "deterministic-demo")


if __name__ == "__main__":
    state = RunState(AssessmentRequest(cve_id="CVE-2026-1234"), DemoCVE(), DemoContext())
    print(asyncio.run(demo_assess(state)).model_dump_json(indent=2))
