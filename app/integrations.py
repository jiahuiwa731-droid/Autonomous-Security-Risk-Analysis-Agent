import os
import httpx
from neo4j import AsyncGraphDatabase, READ_ACCESS
from app.schemas import AssessmentRequest, Vulnerability, AssetContext


class NVD:
    async def lookup(self, cve_id: str) -> Vulnerability:
        headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else {}
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                        params={"cveId": cve_id}, headers=headers)
            response.raise_for_status()
        cve = response.json()["vulnerabilities"][0]["cve"]
        if cve["id"] != cve_id:
            raise ValueError("Mismatched CVE response")
        metrics = cve.get("metrics", {})
        scores = next((metrics[k] for k in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] if metrics.get(k)), [])
        metric = next((m for m in scores if m.get("type") == "Primary"), scores[0] if scores else {})
        cvss = metric.get("cvssData", {})
        products = []
        def walk(node):
            if len(products) >= 100:
                return
            if isinstance(node, dict):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        bounds = {k: v for k, v in match.items() if k.startswith("version")}
                        products.append(str(match["criteria"]) + (f" {bounds}" if bounds else ""))
                        if len(products) >= 100:
                            break
                for value in node.values():
                    if len(products) >= 100:
                        break
                    if isinstance(value, (list, dict)):
                        walk(value)
            elif isinstance(node, list):
                for value in node:
                    if len(products) >= 100:
                        break
                    walk(value)
        walk(cve.get("configurations", []))
        return Vulnerability(cve_id=cve_id,
            description=next((d["value"][:6000] for d in cve.get("descriptions", []) if d["lang"] == "en"), "Description unavailable"),
            cvss=cvss.get("baseScore"), attack_vector=cvss.get("attackVector", cvss.get("accessVector")),
            affected_products=sorted(set(products)), source=f"https://nvd.nist.gov/vuln/detail/{cve_id}")


class Neo4jContext:
    async def lookup(self, request: AssessmentRequest) -> AssetContext:
        # Inventory completeness is explicitly attested, never inferred from zero rows.
        query = """
        MATCH (s:AssessmentScope {cve_id: $cve_id, environment: $environment})
        CALL {
            WITH s
            OPTIONAL MATCH (s)-[:AFFECTS]->(asset:Asset)
            RETURN collect(DISTINCT asset) AS affected_assets
        }
        UNWIND CASE WHEN size(affected_assets) = 0 THEN [null]
                    ELSE affected_assets[0..101] END AS a
        OPTIONAL MATCH (a)-[:DEPENDS_ON]->(d:Asset)
        WITH s, affected_assets, a, collect(DISTINCT d.asset_id) AS all_dependencies
        WITH s, size(affected_assets) AS total_assets, collect(CASE WHEN a IS NULL THEN null ELSE {
            asset_id: a.asset_id, environment: a.environment,
            internet_facing: a.internet_facing, criticality: a.criticality,
            owner: a.owner, dependencies: all_dependencies[0..20],
            dependencies_truncated: size(all_dependencies) > 20} END) AS asset_rows
        RETURN s.complete AND total_assets <= 100 AS complete, asset_rows[0..100] AS assets
        """
        async with AsyncGraphDatabase.driver(os.environ["NEO4J_URI"],
                auth=(os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"]),
                connection_timeout=10) as driver:
            async with driver.session(database=os.getenv("NEO4J_DATABASE", "neo4j"),
                                      default_access_mode=READ_ACCESS) as session:
                from neo4j import Query
                result = await session.run(Query(query, timeout=15), **request.model_dump())
                rows = await result.data()
        if len(rows) != 1:
            return AssetContext(**request.model_dump(), assets=[], complete=False, source="neo4j:AssessmentScope")
        return AssetContext(**request.model_dump(), **rows[0], source="neo4j:AssessmentScope")
