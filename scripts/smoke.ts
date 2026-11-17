/**
 * Live smoke test: runs the real server in-process against the real NVD, FIRST
 * and CISA endpoints and prints each tool's output. Requires network access.
 *
 *   npm run smoke
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { loadConfig } from "../src/config.js";
import { createDeps, createServer } from "../src/server.js";

const CALLS: ReadonlyArray<{ name: string; arguments: Record<string, unknown> }> = [
  { name: "lookup_cve", arguments: { cve_id: "CVE-2021-44228", max_references: 3 } },
  { name: "epss_score", arguments: { cve_ids: ["CVE-2021-44228"] } },
  { name: "is_known_exploited", arguments: { cve_ids: ["CVE-2021-44228"] } },
  {
    name: "prioritize_cves",
    arguments: {
      cve_ids: ["CVE-2023-38545", "CVE-2024-45337", "CVE-2021-44228", "CVE-2024-24790", "CVE-2024-3400"],
    },
  },
  { name: "search_cves", arguments: { keyword: "log4j jndi", limit: 3 } },
];

async function main(): Promise<void> {
  const server = createServer(createDeps(loadConfig()));
  const client = new Client({ name: "smoke", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  let failures = 0;
  for (const call of CALLS) {
    const started = Date.now();
    const result = await client.callTool(call);
    const text = (result.content as Array<{ text?: string }>).map((c) => c.text ?? "").join("\n");
    const status = result.isError ? "ERROR" : "ok";
    if (result.isError) failures++;
    console.log(`\n===== ${call.name} ${JSON.stringify(call.arguments)} [${status}, ${Date.now() - started} ms]\n`);
    console.log(text);
  }

  await client.close();
  process.exitCode = failures ? 1 : 0;
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
