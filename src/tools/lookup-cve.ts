import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { formatCveRecord } from "../format.js";
import { cveIdSchema } from "../lib/cve-id.js";
import { READ_ONLY_ANNOTATIONS, type ToolDeps } from "./deps.js";
import { runTool } from "./result.js";

export function registerLookupCve(server: McpServer, { nvd }: ToolDeps): void {
  server.registerTool(
    "lookup_cve",
    {
      title: "Look up a CVE (NVD)",
      description:
        "Fetch a CVE from the NIST National Vulnerability Database: description, CVSS v4.0/v3.1 base score and vector, CWE, publication dates and references.",
      inputSchema: {
        cve_id: cveIdSchema,
        max_references: z
          .number()
          .int()
          .min(0)
          .max(50)
          .default(10)
          .describe("Maximum number of reference URLs to include (default 10)"),
      },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    ({ cve_id, max_references }) =>
      runTool(async () => {
        const record = await nvd.getCve(cve_id);
        if (!record) {
          throw new Error(`${cve_id} was not found in NVD. It may be reserved, rejected, or not yet published.`);
        }
        return formatCveRecord(record, max_references);
      }),
  );
}
