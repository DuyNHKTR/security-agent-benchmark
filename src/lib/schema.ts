import { Ajv } from "ajv";
import type { ErrorObject } from "ajv";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { SecurityReport } from "../types.js";

export async function validateReport(root: string, file: string, findingLimit: number): Promise<SecurityReport> {
  const schema = JSON.parse(await readFile(path.join(root, "schemas", "report.schema.json"), "utf8"));
  const report = JSON.parse(await readFile(file, "utf8")) as SecurityReport;
  const ajv = new Ajv({ allErrors: true, strict: false });
  const validate = ajv.compile(schema);
  if (!validate(report)) {
    const details = validate.errors?.map((error: ErrorObject) => `${error.instancePath || "/"} ${error.message}`).join("; ");
    throw new Error(`Report schema validation failed: ${details}`);
  }
  if (report.findings.length > findingLimit) {
    throw new Error(`Report has ${report.findings.length} findings; limit is ${findingLimit}`);
  }
  for (const finding of report.findings) {
    for (const location of finding.locations) {
      if (location.end_line < location.start_line) throw new Error(`${finding.id}: end_line precedes start_line`);
    }
  }
  return report;
}
