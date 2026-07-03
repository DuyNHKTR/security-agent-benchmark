import type { SecurityReport } from "../src/types.js";

export function validReport(): SecurityReport {
  return {
    schema_version: "1.0",
    scan_summary: { repository_understanding: "A small HTTP service", scope_examined: ["src"], validation_performed: ["static trace"], limitations: [] },
    attack_surface: [{ name: "HTTP", entry_points: ["GET /item"], trust_boundary: "public request", sensitive_operations: ["database query"] }],
    findings: [{
      id: "SEC-001", title: "Untrusted identifier reaches query construction", severity: "high", confidence: "high", cwe: "CWE-89", category: "injection",
      locations: [{ path: "src/server.js", start_line: 10, end_line: 12, symbol: "getItem" }],
      entry_point: "GET /item?id=", source_to_sink: ["req.query.id", "db.query"], preconditions: ["Unauthenticated network access"],
      exploitability: "The identifier is concatenated without parameterization.", impact: "Unauthorized database reads.", evidence: ["Direct data-flow trace."],
      validation: { status: "supported", commands: ["npm test"], observations: ["Existing tests pass but do not cover hostile identifiers."] },
      remediation: "Use a parameterized query.", regression_test: "Send a metacharacter identifier and assert it is treated as data.", uncertainty: "Database permissions may limit impact."
    }],
    top_risks: ["SEC-001"], uncertainties: [], next_steps: ["Add regression coverage"], overall_risk: "high"
  };
}
