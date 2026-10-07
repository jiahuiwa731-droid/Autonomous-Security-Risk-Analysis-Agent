import json
from pathlib import Path
import pytest
from evals.run import evaluate_case


@pytest.mark.parametrize("case", json.loads(Path("evals/cases.json").read_text()), ids=lambda c: c["id"])
async def test_evaluation_case(case):
    result, _ = await evaluate_case(case)
    assert result.decision == case["expected"], case["justification"]
    if result.decision != "REVIEW":
        assert result.policy_validated
