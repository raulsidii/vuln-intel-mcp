import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SERVER_NAME, SERVER_VERSION, type RuntimeConfig } from "./config.js";
import type { FetchLike, Sleep } from "./lib/http.js";
import { EpssClient } from "./sources/epss.js";
import { KevClient } from "./sources/kev.js";
import { NvdClient } from "./sources/nvd.js";
import type { ToolDeps } from "./tools/deps.js";
import { registerEpssScore } from "./tools/epss-score.js";
import { registerKnownExploited } from "./tools/known-exploited.js";
import { registerLookupCve } from "./tools/lookup-cve.js";
import { registerPrioritizeCves } from "./tools/prioritize-cves.js";
import { registerSearchCves } from "./tools/search-cves.js";

export interface ClientOverrides {
  readonly fetchImpl?: FetchLike;
  readonly sleep?: Sleep;
}

export function createDeps(config: RuntimeConfig, overrides: ClientOverrides = {}): ToolDeps {
  return {
    nvd: new NvdClient({ apiKey: config.nvdApiKey, ...overrides }),
    epss: new EpssClient(overrides),
    kev: new KevClient(overrides),
  };
}

export function createServer(deps: ToolDeps): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    {
      instructions:
        "Vulnerability intelligence for triage. Use prioritize_cves to rank a list of CVEs; " +
        "lookup_cve, epss_score and is_known_exploited for single-source detail; search_cves to find CVE IDs by keyword.",
    },
  );
  for (const register of [
    registerLookupCve,
    registerEpssScore,
    registerKnownExploited,
    registerPrioritizeCves,
    registerSearchCves,
  ]) {
    register(server, deps);
  }
  return server;
}
