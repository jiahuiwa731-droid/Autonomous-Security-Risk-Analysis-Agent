from pathlib import Path
from rdflib import Graph, Namespace, Literal, RDF, URIRef
from rdflib.namespace import SH
from pyshacl import validate
from app.schemas import Vulnerability, AssetContext, PolicyFinding, PolicyResult, Decision

EX = Namespace("urn:security:")
SHAPES = Path(__file__).parent / "policies" / "security.ttl"


def validate_policy(vulnerability: Vulnerability, context: AssetContext,
                    proposed_decision: Decision) -> PolicyResult:
    """Only server-held, validated observations enter the policy graph."""
    if (vulnerability.cvss is None or not context.complete or not context.assets
            or vulnerability.cve_id != context.cve_id
            or any(a.internet_facing is None or a.criticality is None
                   or a.environment != context.environment for a in context.assets)):
        return PolicyResult(conforms=False, decision="REVIEW", findings=[PolicyFinding(
            rule="evidence-completeness", severity="REVIEW",
            message="Missing, mismatched, or incomplete vulnerability/asset evidence.",
            evidence_refs=["cve", "context"])])
    data = Graph()
    for index, asset in enumerate(context.assets):
        node = URIRef(f"urn:security:asset:{index}")
        data.add((node, RDF.type, EX.Asset))
        data.add((node, EX.environment, Literal(asset.environment)))
        data.add((node, EX.internetFacing, Literal(asset.internet_facing)))
        data.add((node, EX.cvss, Literal(vulnerability.cvss)))
    conforms, report, _ = validate(data, shacl_graph=str(SHAPES), allow_warnings=False)
    findings = []
    for result in report.subjects(RDF.type, SH.ValidationResult):
        severity = "BLOCK" if report.value(result, SH.resultSeverity) == SH.Violation else "REVIEW"
        findings.append(PolicyFinding(rule=str(report.value(result, SH.sourceShape)),
            severity=severity, message=str(report.value(result, SH.resultMessage)),
            evidence_refs=["cve", "context"]))
    if not conforms and not findings:
        findings.append(PolicyFinding(rule="shacl-unclassified", severity="REVIEW",
            message="SHACL reported nonconformance without a classifiable finding; manual review required.",
            evidence_refs=["cve", "context"]))
    decision = "BLOCK" if any(f.severity == "BLOCK" for f in findings) else "REVIEW" if findings else "ALLOW"
    # The model may conservatively request review, but cannot invent a blocking rule.
    if not findings and proposed_decision != "ALLOW":
        decision = "REVIEW"
    return PolicyResult(conforms=bool(conforms), decision=decision, findings=findings)
