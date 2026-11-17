import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { SEARCH_MAX_RESULTS } from "../config.js";
import { formatSearchResults } from "../format.js";
import { READ_ONLY_ANNOTATIONS, type ToolDeps } from "./deps.js";
import { runTool } from "./result.js";

export function registerSearchCves(server: McpServer, { nvd }: ToolDeps): void {
  server.registerTool(
    "search_cves",
    {
      title: "Search CVEs by keyword (NVD)",
      description:
        "Keyword search over NVD CVE descriptions (e.g. a product, library or vulnerability class). Returns CVE IDs with CVSS and a short summary; use lookup_cve or prioritize_cves to dig deeper.",
      inputSchema: {
        keyword: z
          .string()
          .trim()
          .min(2)
          .max(200)
          .describe('Words that must all appear in the description, e.g. "log4j jndi"'),
        limit: z
          .number()
          .int()
          .min(1)
          .max(SEARCH_MAX_RESULTS)
          .default(5)
          .describe(`Maximum results to return (1-${SEARCH_MAX_RESULTS}, default 5)`),
        exact_match: z
          .boolean()
          .default(false)
          .describe("Match the keyword as an exact phrase instead of all words"),
      },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    ({ keyword, limit, exact_match }) =>
      runTool(async () => {
        const result = await nvd.search({ keyword, limit, exactMatch: exact_match });
        return formatSearchResults(keyword, result.totalResults, result.records);
      }),
  );
}
