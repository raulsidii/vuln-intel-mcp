import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { createDeps, createServer } from "../src/server.js";
import {
  allRoutes,
  epssRoute,
  fakeFetch,
  jsonResponse,
  kevRoute,
  noSleep,
  nvdRoute,
  type Route,
} from "./helpers.js";

async function connect(routes: readonly Route[] = allRoutes, nvdApiKey?: string) {
  const server = createServer(createDeps({ nvdApiKey }, { fetchImpl: fakeFetch(routes), sleep: noSleep }));
  const client = new Client({ name: "test-client", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

async function callText(client: Client, name: string, args: Record<string, unknown>) {
  const result = await client.callTool({ name, arguments: args });
  const content = result.content as Array<{ type: string; text: string }>;
  return { isError: result.isError === true, text: content.map((c) => c.text).join("\n") };
}

describe("MCP server", () => {
  it("exposes the five tools as read-only", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      "epss_score",
      "is_known_exploited",
      "lookup_cve",
      "prioritize_cves",
      "search_cves",
    ]);
    expect(tools.every((t) => t.annotations?.readOnlyHint === true)).toBe(true);
  });

  it("lookup_cve returns CVSS, CWE and references", async () => {
    const client = await connect();
    const { isError, text } = await callText(client, "lookup_cve", { cve_id: "cve-2021-44228", max_references: 2 });
    expect(isError).toBe(false);
    expect(text).toContain("## CVE-2021-44228");
    expect(text).toContain("**CVSS v3.1:** 10.0 CRITICAL");
    expect(text).toContain("CWE-917");
    expect(text).toMatch(/\*\*References\*\* \(2 of \d+\)/);
  });

  it("lookup_cve reports unknown CVEs as a tool error", async () => {
    const client = await connect();
    const { isError, text } = await callText(client, "lookup_cve", { cve_id: "CVE-1999-99999" });
    expect(isError).toBe(true);
    expect(text).toContain("not found in NVD");
  });

  it("rejects malformed CVE IDs via schema validation", async () => {
    const client = await connect();
    const { isError, text } = await callText(client, "lookup_cve", { cve_id: "log4shell" });
    expect(isError).toBe(true);
    expect(text).toContain("Expected a CVE ID");
  });

  it("turns upstream outages into tool errors instead of crashing", async () => {
    const down: Route = { match: nvdRoute.match, respond: () => jsonResponse({}, 503) };
    const client = await connect([down, epssRoute, kevRoute]);
    const { isError, text } = await callText(client, "lookup_cve", { cve_id: "CVE-2021-44228" });
    expect(isError).toBe(true);
    expect(text).toContain("NVD is unavailable (HTTP 503)");
    // Server is still alive afterwards.
    expect((await client.listTools()).tools).toHaveLength(5);
  });

  it("epss_score and is_known_exploited format their sources", async () => {
    const client = await connect();
    const epss = await callText(client, "epss_score", { cve_ids: ["CVE-2023-38545"] });
    expect(epss.text).toContain("| CVE-2023-38545 | 78.3% | p99.5 |");

    const kev = await callText(client, "is_known_exploited", { cve_ids: ["CVE-2021-44228", "CVE-2023-38545"] });
    expect(kev.text).toContain("CVE-2021-44228 — LISTED in CISA KEV");
    expect(kev.text).toContain("Known ransomware use:** Known");
    expect(kev.text).toContain("CVE-2023-38545 — not in CISA KEV");
  });

  it("search_cves lists matching CVEs", async () => {
    const client = await connect();
    const { text } = await callText(client, "search_cves", { keyword: "log4j jndi", limit: 3 });
    expect(text).toContain('Showing 3 of 7 NVD results for "log4j jndi"');
    expect(text).toContain("| CVE-2021-45046 |");
  });

  it("prioritize_cves ranks KEV entries first and explains each row", async () => {
    const client = await connect();
    const { isError, text } = await callText(client, "prioritize_cves", {
      cve_ids: ["CVE-2023-38545", "CVE-2021-44228", "CVE-2024-3400", "CVE-2021-44228"],
    });
    expect(isError).toBe(false);
    const rows = text.split("\n").filter((line) => /^\| \d+ \|/.test(line));
    expect(rows).toHaveLength(3);
    expect(rows[0]).toMatch(/^\| 1 \| CVE-2021-44228 \| CRITICAL \| 100\.0 \| yes \(ransomware\)/);
    expect(rows[1]).toMatch(/^\| 2 \| CVE-2024-3400 \| CRITICAL \|/);
    expect(rows[2]).toMatch(/^\| 3 \| CVE-2023-38545 \| HIGH \| 86\.2 \| no \|/);
    expect(text).toContain("Score = 100 × (0.4 × CVSS/10 + 0.6 × EPSS)");
  });

  it("prioritize_cves degrades gracefully when one source is down", async () => {
    const epssDown: Route = { match: epssRoute.match, respond: () => jsonResponse({}, 500) };
    const client = await connect([nvdRoute, epssDown, kevRoute]);
    const { isError, text } = await callText(client, "prioritize_cves", { cve_ids: ["CVE-2021-44228"] });
    expect(isError).toBe(false);
    expect(text).toContain("CVE-2021-44228 | CRITICAL");
    expect(text).toContain("FIRST EPSS unavailable");
  });

  it("prioritize_cves errors only when every source fails", async () => {
    const fail = (match: Route["match"]): Route => ({ match, respond: () => jsonResponse({}, 500) });
    const client = await connect([fail(nvdRoute.match), fail(epssRoute.match), fail(kevRoute.match)]);
    const { isError, text } = await callText(client, "prioritize_cves", { cve_ids: ["CVE-2021-44228"] });
    expect(isError).toBe(true);
    expect(text).toContain("All data sources failed");
  });
});
