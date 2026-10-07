import asyncio
import time
from uuid import uuid4
from app.schemas import (AssessmentRequest, Vulnerability, AssetContext, Proposal,
    ToolTrace, Evidence, SecurityDecision, RemediationAction)
from app.policy import validate_policy


def create_remediation(context, decision, violations):
    owners = sorted({a.owner or "security-team" for a in context.assets}) if context else []
    owners = owners or ["security-team"]
    action = {"BLOCK": "Restrict exposure and apply the vendor fix after change approval.",
              "REVIEW": "Verify CVE applicability, complete asset evidence, and request security review.",
              "ALLOW": "Track the vendor fix and reassess when exposure or vulnerability evidence changes."}[decision]
    return [RemediationAction(action=action, rationale="; ".join(f.message for f in violations) or
                              "Maintain risk visibility for the assessed scope.", owner=owner) for owner in owners]


class RunState:
    def __init__(self, request: AssessmentRequest, cve_provider, context_provider, max_steps=12):
        self.request, self.cve_provider, self.context_provider = request, cve_provider, context_provider
        self.max_steps = max_steps
        self.run_id = str(uuid4())
        self.cve = self.context = self.policy = None
        self.trace = []
        self.failures = {}
        self.halted = False
        self._tool_lock = asyncio.Lock()

    async def call(self, name, arguments, operation, *, terminal=False):
        # Enforce the execution budget even if a model requests concurrent tools.
        trace_length = len(self.trace)
        try:
            async with self._tool_lock:
                return await self._call(name, arguments, operation, terminal=terminal)
        except asyncio.CancelledError:
            # Cancellation can happen while this call is queued behind another tool.
            # Preserve an audit entry and invalidate any affected cached observation.
            self.halted = True
            if name == "get_cve_details":
                self.cve = None
            elif name == "get_asset_context":
                self.context = None
            self.policy = None
            if len(self.trace) == trace_length:
                self.trace.append(ToolTrace(step=len(self.trace)+1, tool=name, arguments=arguments,
                    status="error", observation={"error": "Tool execution cancelled; evidence not established."},
                    latency_ms=0))
            raise

    async def _call(self, name, arguments, operation, *, terminal=False):
        started = time.monotonic()
        if not terminal and (self.halted or len(self.trace) >= self.max_steps):
            self.halted = True
            return {"error": "Run budget exhausted or repeated tool failure; return REVIEW."}
        try:
            value = operation()
            if hasattr(value, "__await__"):
                value = await asyncio.wait_for(value, timeout=20)
            observation = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
            status = "ok"
        except asyncio.CancelledError:
            self.halted = True
            self.trace.append(ToolTrace(step=len(self.trace)+1, tool=name, arguments=arguments,
                status="error", observation={"error": "Tool execution cancelled; evidence not established."},
                latency_ms=round((time.monotonic()-started)*1000, 2)))
            raise
        except Exception:
            # Never expose provider exceptions: they can contain credentials or raw payloads.
            observation, status = {"error": "Tool unavailable or invalid response; evidence not established."}, "error"
            self.failures[name] = self.failures.get(name, 0) + 1
            if self.failures[name] >= 2:
                self.halted = True
        self.trace.append(ToolTrace(step=len(self.trace)+1, tool=name, arguments=arguments,
            status=status, observation=observation, latency_ms=round((time.monotonic()-started)*1000, 2)))
        return observation

    async def get_cve_details(self):
        async def operation():
            # A failed refresh must not leave older evidence eligible for ALLOW.
            self.cve = self.policy = None
            value = Vulnerability.model_validate(await self.cve_provider.lookup(self.request.cve_id))
            if value.cve_id != self.request.cve_id:
                raise ValueError("CVE mismatch")
            self.cve, self.policy = value, None
            return {
                "cve_id": value.cve_id,
                "description": value.description[:3000],
                "cvss": value.cvss,
                "attack_vector": value.attack_vector,
                "affected_product_count": len(value.affected_products),
                "affected_products_sample": value.affected_products[:20],
                "products_truncated": len(value.affected_products) > 20,
                "source": value.source,
            }
        return await self.call("get_cve_details", {"cve_id": self.request.cve_id}, operation)

    async def get_asset_context(self):
        async def operation():
            self.context = self.policy = None
            value = AssetContext.model_validate(await self.context_provider.lookup(self.request))
            if (value.cve_id, value.environment) != (self.request.cve_id, self.request.environment):
                raise ValueError("Context scope mismatch")
            self.context, self.policy = value, None
            criticality_counts = {level: sum(a.criticality == level for a in value.assets)
                                  for level in ("low", "medium", "high")}
            assets_sample = []
            for asset in value.assets[:20]:
                assets_sample.append({
                    "asset_id": asset.asset_id,
                    "environment": asset.environment,
                    "internet_facing": asset.internet_facing,
                    "criticality": asset.criticality,
                    "owner": asset.owner,
                    "dependency_count": len(asset.dependencies),
                    "dependencies_sample": asset.dependencies[:5],
                    "dependencies_truncated": asset.dependencies_truncated or len(asset.dependencies) > 5,
                })
            return {
                "cve_id": value.cve_id,
                "environment": value.environment,
                "complete": value.complete,
                "source": value.source,
                "total_assets": len(value.assets),
                "internet_facing_count": sum(a.internet_facing is True for a in value.assets),
                "criticality_counts": criticality_counts,
                "assets_sample": assets_sample,
                "assets_truncated": len(value.assets) > 20,
            }
        return await self.call("get_asset_context", self.request.model_dump(), operation)

    async def check_policy(self, proposed_decision, *, terminal=False):
        def operation():
            self.policy = None
            if self.cve is None or self.context is None:
                raise ValueError("Evidence missing")
            self.policy = validate_policy(self.cve, self.context, proposed_decision)
            return self.policy
        return await self.call("validate_policy", {"proposed_decision": proposed_decision}, operation, terminal=terminal)

    async def remediation(self):
        def operation():
            if self.policy is None:
                raise ValueError("Validate policy first")
            return {"actions": [a.model_dump() for a in create_remediation(self.context, self.policy.decision, self.policy.findings)]}
        return await self.call("create_remediation", {}, operation)

    async def finish(self, proposal: Proposal | None, model: str, reason=None):
        # Unconditional terminal validation uses current trusted state, never model facts.
        self.policy = None
        if proposal and not self.halted and self.cve is not None and self.context is not None:
            await self.check_policy(proposal.decision, terminal=True)
        decision = self.policy.decision if self.policy else "REVIEW"
        findings = self.policy.findings if self.policy else []
        evidence = [Evidence(reference=key, source=value.source, details=value.model_dump())
                    for key, value in [("cve", self.cve), ("context", self.context)] if value is not None]
        summary = ("; ".join(f.message for f in findings) or
                   {"ALLOW": "Available evidence conforms to the configured SHACL policy.",
                    "BLOCK": "Configured SHACL policy requires blocking.",
                    "REVIEW": reason or "Human review required; evidence or policy support is insufficient."}[decision])
        return SecurityDecision(run_id=self.run_id, model=model, goal=self.request,
            decision=decision, summary=summary, evidence=evidence, policy_findings=findings,
            remediation=create_remediation(self.context, decision, findings), tool_trace=self.trace,
            proposed_decision=proposal, policy_validated=self.policy is not None)
