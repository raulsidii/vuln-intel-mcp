import { describe, expect, it } from "vitest";
import { parseNvdResponse, selectPrimaryCvss } from "../src/sources/nvd-parse.js";
import { NvdClient } from "../src/sources/nvd.js";
import { fakeFetch, fixture, jsonResponse, noSleep, nvdRoute } from "./helpers.js";

describe("parseNvdResponse", () => {
  it("parses Log4Shell (CVE-2021-44228)", () => {
    const { totalResults, records } = parseNvdResponse(fixture("nvd-cve-2021-44228.json"));
    const record = records[0]!;

    expect(totalResults).toBe(1);
    expect(record.id).toBe("CVE-2021-44228");
    expect(record.published.startsWith("2021-12-10")).toBe(true);
    expect(record.description).toMatch(/^Apache Log4j2/);
    expect(record.cwes).toEqual(["CWE-20", "CWE-400", "CWE-502", "CWE-917"]);
    expect(record.references.length).toBeGreaterThan(0);

    const v31 = record.cvss.find((m) => m.version === "3.1");
    expect(v31).toMatchObject({
      baseScore: 10,
      severity: "CRITICAL",
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      source: "nvd@nist.gov",
      type: "Primary",
    });
  });

  it("keeps CVSS v2 severity, which NVD stores outside cvssData", () => {
    const record = parseNvdResponse(fixture("nvd-cve-2021-44228.json")).records[0]!;
    expect(record.cvss.find((m) => m.version === "2.0")).toMatchObject({ baseScore: 9.3, severity: "HIGH" });
  });

  it("parses CVSS v4.0 metrics and lists newest version first", () => {
    const record = parseNvdResponse(fixture("nvd-cve-v4.json")).records[0]!;
    expect(record.cvss.map((m) => m.version)).toEqual(["4.0", "3.1", "2.0"]);
    expect(record.cvss[0]).toMatchObject({ baseScore: 9.3, severity: "CRITICAL" });
    expect(record.cvss[0]!.vector.startsWith("CVSS:4.0/")).toBe(true);
  });

  it("prefers CVSS v3.1 for scoring when several versions exist", () => {
    const record = parseNvdResponse(fixture("nvd-cve-v4.json")).records[0]!;
    expect(selectPrimaryCvss(record.cvss)?.version).toBe("3.1");
    expect(selectPrimaryCvss([])).toBeUndefined();
  });

  it("parses keyword search pages", () => {
    const result = parseNvdResponse(fixture("nvd-search-log4j.json"));
    expect(result.totalResults).toBe(7);
    expect(result.records.map((r) => r.id)).toEqual(["CVE-2021-44228", "CVE-2021-4104", "CVE-2021-45046"]);
  });

  it("returns no records for an unknown CVE", () => {
    expect(parseNvdResponse(fixture("nvd-empty.json")).records).toEqual([]);
  });

  it("rejects payloads that are not NVD responses", () => {
    expect(() => parseNvdResponse({ message: "Invalid apiKey" })).toThrow(/Unexpected NVD response shape/);
  });
});

describe("NvdClient", () => {
  it("returns null for CVEs NVD does not know", async () => {
    const client = new NvdClient({ fetchImpl: fakeFetch([nvdRoute]), sleep: noSleep });
    await expect(client.getCve("CVE-1999-99999")).resolves.toBeNull();
  });

  it("caches lookups", async () => {
    const fetchImpl = fakeFetch([nvdRoute]);
    const client = new NvdClient({ fetchImpl, sleep: noSleep });
    await client.getCve("CVE-2021-44228");
    await client.getCve("CVE-2021-44228");
    expect(fetchImpl.calls).toHaveLength(1);
  });

  it("sends the API key header when configured", async () => {
    let seen: Headers | undefined;
    const client = new NvdClient({
      apiKey: "test-key",
      sleep: noSleep,
      fetchImpl: async (_url, init) => {
        seen = new Headers(init?.headers);
        return jsonResponse(fixture("nvd-cve-2021-44228.json"));
      },
    });
    await client.getCve("CVE-2021-44228");
    expect(seen?.get("apiKey")).toBe("test-key");
  });

  it("builds keyword search URLs with the exact-match flag", async () => {
    const fetchImpl = fakeFetch([nvdRoute]);
    const client = new NvdClient({ fetchImpl, sleep: noSleep });
    await client.search({ keyword: "log4j jndi", limit: 3, exactMatch: true });
    const url = new URL(fetchImpl.calls[0]!);
    expect(url.searchParams.get("keywordSearch")).toBe("log4j jndi");
    expect(url.searchParams.get("resultsPerPage")).toBe("3");
    expect(url.searchParams.has("keywordExactMatch")).toBe(true);
  });
});
