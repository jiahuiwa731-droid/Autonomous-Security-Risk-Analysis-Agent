import httpx
import pytest
from app.integrations import NVD, Neo4jContext
from app.schemas import AssessmentRequest


async def test_nvd_parses_score_versions_and_source(monkeypatch):
    matches = [{"vulnerable": True, "criteria": "cpe:2.3:a:test",
                "versionEndExcluding": "2.0"}]
    matches.extend({"vulnerable": True, "criteria": f"cpe:2.3:a:test-{index}"}
                   for index in range(149))
    async def get(self, url, **kwargs):
        assert kwargs["params"] == {"cveId": "CVE-2026-1234"}
        return httpx.Response(200, request=httpx.Request("GET", url), json={"vulnerabilities": [{"cve": {
            "id": "CVE-2026-1234", "descriptions": [{"lang": "en", "value": "Example"}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "attackVector": "NETWORK"}}]},
            "configurations": [{"nodes": [{"cpeMatch": matches}]}]
        }}]})
    monkeypatch.setattr(httpx.AsyncClient, "get", get)
    result = await NVD().lookup("CVE-2026-1234")
    assert result.cvss == 9.8 and any("2.0" in product for product in result.affected_products)
    assert len(result.affected_products) == 100
    assert result.source.endswith("CVE-2026-1234")


async def test_graph_uses_bound_parameters_and_explicit_completeness(monkeypatch):
    class Result:
        async def data(self):
            return [{"complete": False, "assets": []}]
    class Driver:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        def session(self, **kwargs): return self
        async def run(self, query, **kwargs):
            assert "$cve_id" in query.text and "$environment" in query.text
            assert kwargs["environment"] == "production"
            return Result()
    for key, value in {"NEO4J_URI": "neo4j://example", "NEO4J_USER": "test", "NEO4J_PASSWORD": "secret"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("app.integrations.AsyncGraphDatabase.driver", lambda *a, **kw: Driver())
    result = await Neo4jContext().lookup(AssessmentRequest(cve_id="CVE-2026-1234"))
    assert not result.complete and result.assets == []
