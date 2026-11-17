import { describe, expect, it } from "vitest";
import { EpssClient, parseEpssResponse } from "../src/sources/epss.js";
import { KevClient, parseKevFeed } from "../src/sources/kev.js";
import { epssRoute, fakeFetch, fixture, kevRoute, noSleep } from "./helpers.js";

describe("parseEpssResponse", () => {
  it("converts FIRST's string-encoded numbers", () => {
    const scores = parseEpssResponse(fixture("epss.json"));
    const log4shell = scores.find((s) => s.cve === "CVE-2021-44228");
    expect(log4shell).toEqual({ cve: "CVE-2021-44228", epss: 0.99999, percentile: 1, date: "2026-11-16" });
  });

  it("rejects out-of-range probabilities", () => {
    expect(() =>
      parseEpssResponse({ data: [{ cve: "CVE-1", epss: "1.5", percentile: "0.5", date: "" }] }),
    ).toThrow(/Unexpected EPSS response shape/);
  });
});

describe("EpssClient", () => {
  it("batches IDs into one request and caches the answers", async () => {
    const fetchImpl = fakeFetch([epssRoute]);
    const client = new EpssClient({ fetchImpl, sleep: noSleep });

    const first = await client.getScores(["CVE-2021-44228", "CVE-2023-38545"]);
    const second = await client.getScores(["CVE-2021-44228"]);

    expect(fetchImpl.calls).toHaveLength(1);
    expect(new URL(fetchImpl.calls[0]!).searchParams.get("cve")).toBe("CVE-2021-44228,CVE-2023-38545");
    expect(first.get("CVE-2023-38545")?.epss).toBeCloseTo(0.78317);
    expect(second.get("CVE-2021-44228")?.percentile).toBe(1);
  });

  it("returns null (and caches it) for CVEs FIRST has not scored", async () => {
    const fetchImpl = fakeFetch([epssRoute]);
    const client = new EpssClient({ fetchImpl, sleep: noSleep });
    expect(await client.getScore("CVE-2099-0001")).toBeNull();
    expect(await client.getScore("CVE-2099-0001")).toBeNull();
    expect(fetchImpl.calls).toHaveLength(1);
  });
});

describe("parseKevFeed", () => {
  it("indexes the catalog by CVE ID", () => {
    const catalog = parseKevFeed(fixture("kev.json"));
    expect(catalog.count).toBe(4);
    expect(catalog.catalogVersion).toBe("2026.11.13");
    expect(catalog.entries.get("CVE-2021-44228")).toMatchObject({
      vendorProject: "Apache",
      dateAdded: "2021-12-10",
      knownRansomwareCampaignUse: "Known",
    });
    expect(catalog.entries.has("CVE-2023-38545")).toBe(false);
  });

  it("rejects payloads without a vulnerabilities array", () => {
    expect(() => parseKevFeed({ title: "nope" })).toThrow(/Unexpected CISA KEV feed shape/);
  });
});

describe("KevClient", () => {
  it("downloads the catalog once and serves it from memory for 12 hours", async () => {
    let now = 0;
    const fetchImpl = fakeFetch([kevRoute]);
    const client = new KevClient({ fetchImpl, sleep: noSleep, now: () => now });

    await client.getCatalog();
    now += 11 * 60 * 60 * 1000;
    await client.getCatalog();
    expect(fetchImpl.calls).toHaveLength(1);

    now += 2 * 60 * 60 * 1000;
    await client.getCatalog();
    expect(fetchImpl.calls).toHaveLength(2);
  });

  it("coalesces concurrent first loads into one download", async () => {
    const fetchImpl = fakeFetch([kevRoute]);
    const client = new KevClient({ fetchImpl, sleep: noSleep });
    await Promise.all([client.getCatalog(), client.getCatalog(), client.getCatalog()]);
    expect(fetchImpl.calls).toHaveLength(1);
  });
});
