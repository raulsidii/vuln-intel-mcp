import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { formatEpss } from "../format.js";
import { cveIdSchema, uniqueCveIds } from "../lib/cve-id.js";
import { READ_ONLY_ANNOTATIONS, type ToolDeps } from "./deps.js";
import { runTool } from "./result.js";

export function registerEpssScore(server: McpServer, { epss }: ToolDeps): void {
  server.registerTool(
    "epss_score",
    {
      title: "EPSS exploit prediction score",
      description:
        "Get the FIRST EPSS score (probability of exploitation in the next 30 days) and percentile for one or more CVEs.",
      inputSchema: {
        cve_ids: z.array(cveIdSchema).min(1).max(100).describe("One or more CVE IDs (max 100)"),
      },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    ({ cve_ids }) =>
      runTool(async () => formatEpss(await epss.getScores(uniqueCveIds(cve_ids)))),
  );
}
