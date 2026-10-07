import asyncio
import json
import time
from pathlib import Path
from app.demo import DemoCVE, DemoContext, demo_assess
from app.schemas import AssessmentRequest
from app.tools import RunState


async def evaluate_case(case, live_model=None):
    request = AssessmentRequest(cve_id="CVE-2026-1234", environment=case["environment"])
    class CVE(DemoCVE):
        async def lookup(self, cve_id):
            if case.get("failure") == "cve":
                raise RuntimeError("Simulated failure")
            value = await super().lookup(cve_id)
            value.cvss = case["cvss"]
            return value
    class Context(DemoContext):
        async def lookup(self, request):
            if case.get("failure") == "context":
                raise RuntimeError("Simulated failure")
            value = await super().lookup(request)
            value.complete = case.get("complete", True)
            value.assets[0].internet_facing = case.get("internet_facing", True)
            if case.get("empty"):
                value.assets = []
            return value
    started = time.monotonic()
    run_state = RunState(request, CVE(), Context())
    if live_model:
        from app.agent import assess
        result = await assess(run_state, model=live_model)
    else:
        result = await demo_assess(run_state)
    return result, round((time.monotonic()-started)*1000, 2)


async def main():
    cases = json.loads(Path(__file__).with_name("cases.json").read_text())
    rows = []
    successful_tools = attempted_tools = 0
    for case in cases:
        result, latency = await evaluate_case(case)
        attempted_tools += len(result.tool_trace)
        successful_tools += sum(t.status == "ok" for t in result.tool_trace)
        rows.append(dict(id=case["id"], expected=case["expected"], actual=result.decision,
            policy_bypass=result.decision != "REVIEW" and not result.policy_validated,
            steps=len(result.tool_trace), latency_ms=latency))
    non_allow = [r for r in rows if r["expected"] != "ALLOW"]
    non_block = [r for r in rows if r["expected"] != "BLOCK"]
    report = dict(mode="deterministic fixtures; not live LLM quality", cases=len(rows),
        decision_accuracy=sum(r["actual"] == r["expected"] for r in rows)/len(rows),
        false_allow_rate=sum(r["actual"] == "ALLOW" for r in non_allow)/len(non_allow),
        false_block_rate=sum(r["actual"] == "BLOCK" for r in non_block)/len(non_block),
        policy_bypass_rate=sum(r["policy_bypass"] for r in rows)/len(rows),
        tool_success_rate=successful_tools/attempted_tools, token_cost=None, results=rows)
    Path(__file__).with_name("report.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k != "results"}, indent=2))
    if report["decision_accuracy"] != 1 or report["policy_bypass_rate"]:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
