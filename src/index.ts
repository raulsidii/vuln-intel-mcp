#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig, SERVER_NAME, SERVER_VERSION } from "./config.js";
import { createDeps, createServer } from "./server.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const server = createServer(createDeps(config));
  await server.connect(new StdioServerTransport());
  // stdout is the MCP channel; diagnostics go to stderr.
  console.error(
    `${SERVER_NAME} ${SERVER_VERSION} running on stdio (NVD API key: ${config.nvdApiKey ? "set" : "not set"})`,
  );
}

main().catch((error: unknown) => {
  console.error(`${SERVER_NAME} failed to start:`, error);
  process.exit(1);
});
