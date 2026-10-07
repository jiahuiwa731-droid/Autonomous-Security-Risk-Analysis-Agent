// Run once as a Neo4j administrator before connecting the read-only agent.
// Keep Scope.complete under the control of the trusted inventory sync process.
CREATE CONSTRAINT assessment_scope_identity IF NOT EXISTS
FOR (scope:AssessmentScope)
REQUIRE (scope.cve_id, scope.environment) IS UNIQUE;

CREATE CONSTRAINT asset_identity IF NOT EXISTS
FOR (asset:Asset)
REQUIRE asset.asset_id IS UNIQUE;
