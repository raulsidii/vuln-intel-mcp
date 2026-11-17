import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PRIORITIZE_MAX_CVES } from "../config.js";
import { formatPriorityTable } from "../format.js";
import { cveIdSchema, uniqueCveIds } from "../lib/cve-id.js";
import { prioritize } from "../prioritize.js";
import { READ_ONLY_ANNOTATIONS, type ToolDeps } from "./deps.js";
import { runTool } from "./result.js";

export function registerPrioritizeCves(server: McpServer, deps: ToolDeps): void {
  server.registerTool(
    "prioritize_cves",
    {
      title: "Prioritize CVEs (KEV + EPSS + CVSS)",
      description:
        "Rank a list of CVEs for remediation. Combines CISA KEV (known exploitation), FIRST EPSS (predicted exploitation) and NVD CVSS (severity) into a transparent 0-100 priority score with a one-line rationale per CVE. Without NVD_API_KEY, NVD allows ~5 lookups per 30 s, so large lists take a while.",
      inputSchema: {
        cve_ids: z
          .array(cveIdSchema)
          .min(1)
          .max(PRIORITIZE_MAX_CVES)
          .describe(`CVE IDs to rank (max ${PRIORITIZE_MAX_CVES})`),
      },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    ({ cve_ids }) =>
      runTool(async () => {
        const ids = uniqueCveIds(cve_ids);
        const notes = deps.nvd.hasApiKey || ids.length <= 5
          ? []
          : ["no NVD_API_KEY set, so NVD lookups were throttled to 5 per 30 s"];
        const outcome = await prioritize(ids, deps);
        return formatPriorityTable(outcome.results, [...outcome.notes, ...notes]);
      }),
  );
}
