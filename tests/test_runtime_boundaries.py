import asyncio
import pytest
from app.demo import DemoCVE, DemoContext
from app.schemas import AssessmentRequest, Proposal
from app.tools import RunState


def make_state(**kwargs):
    return RunState(AssessmentRequest(cve_id="CVE-2026-1235"), DemoCVE(), DemoContext(), **kwargs)


@pytest.mark.parametrize("provider,tool,field", [
    ("cve_provider", "get_cve_details", "cve"),
    ("context_provider", "get_asset_context", "context"),
])
async def test_failed_refresh_invalidates_old_evidence(provider, tool, field):
    state = make_state()
    await state.get_cve_details()
    await state.get_asset_context()
    await state.check_policy("ALLOW")
    assert state.policy.decision == "ALLOW"

    async def fail(_):
        raise ConnectionError("provider failed")
    getattr(state, provider).lookup = fail
    observation = await getattr(state, tool)()
    assert "error" in observation
    assert getattr(state, field) is None
    result = await state.finish(Proposal(decision="ALLOW", summary="Stale evidence"), "test")
    assert result.decision == "REVIEW"
    assert not result.policy_validated


async def test_concurrent_tools_cannot_exceed_budget():
    state = make_state(max_steps=1)
    original = state.cve_provider.lookup
    async def delayed(cve_id):
        await asyncio.sleep(0.01)
        return await original(cve_id)
    state.cve_provider.lookup = delayed
    results = await asyncio.gather(state.get_cve_details(), state.get_asset_context())
    assert len(state.trace) == 1
    assert sum("error" in result for result in results) == 1
    assert state.context is None and state.halted


async def test_cancelled_tool_is_auditable_and_cannot_allow():
    state = make_state()
    started = asyncio.Event()
    async def blocked(_):
        started.set()
        await asyncio.Event().wait()
    state.cve_provider.lookup = blocked
    task = asyncio.create_task(state.get_cve_details())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert state.trace[-1].status == "error"
    assert "cancelled" in state.trace[-1].observation["error"]
    result = await state.finish(Proposal(decision="ALLOW", summary="Unsupported"), "test")
    assert result.decision == "REVIEW"


async def test_empty_context_has_actionable_review():
    state = make_state()
    await state.get_cve_details()
    await state.get_asset_context()
    state.context.assets = []
    result = await state.finish(Proposal(decision="ALLOW", summary="No assets"), "test")
    assert result.decision == "REVIEW"
    assert result.remediation and result.remediation[0].owner == "security-team"


async def test_model_observations_are_bounded_but_final_evidence_is_complete():
    from app.schemas import Asset, AssetContext, Vulnerability

    class LargeCVE:
        async def lookup(self, cve_id):
            return Vulnerability(cve_id=cve_id, description="x" * 5000, cvss=3.0,
                affected_products=[f"product-{i}" for i in range(100)], source="fixture:cve")

    class LargeGraph:
        async def lookup(self, request):
            return AssetContext(**request.model_dump(), complete=True, source="fixture:graph",
                assets=[Asset(asset_id=f"asset-{i}", environment=request.environment,
                    internet_facing=False, criticality="low", owner="team",
                    dependencies=[f"dep-{i}-{j}" for j in range(10)]) for i in range(30)])

    state = RunState(AssessmentRequest(cve_id="CVE-2026-1235"), LargeCVE(), LargeGraph())
    await state.get_cve_details()
    await state.get_asset_context()
    cve_observation, graph_observation = [t.observation for t in state.trace]
    assert len(cve_observation["description"]) == 3000
    assert len(cve_observation["affected_products_sample"]) == 20
    assert cve_observation["products_truncated"]
    assert len(graph_observation["assets_sample"]) == 20
    assert graph_observation["assets_truncated"]
    assert len(graph_observation["assets_sample"][0]["dependencies_sample"]) == 5
    result = await state.finish(Proposal(decision="ALLOW", summary="Low risk"), "test")
    assert result.decision == "ALLOW"
    assert len(result.evidence[1].details["assets"]) == 30
