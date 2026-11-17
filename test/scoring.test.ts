import { describe, expect, it } from "vitest";
import {
  baseScore,
  formatPercentile,
  formatProbability,
  rankCves,
  scoreCve,
  tierFor,
  type PriorityInput,
} from "../src/scoring.js";
import type { CvssMetric, EpssScore, KevEntry } from "../src/types.js";

const cvss = (baseScore: number, severity = "CRITICAL"): CvssMetric => ({
  version: "3.1",
  baseScore,
  severity,
  vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  source: "nvd@nist.gov",
  type: "Primary",
});

const epss = (cve: string, score: number, percentile = 0.5): EpssScore => ({
  cve,
  epss: score,
  percentile,
  date: "2026-11-16",
});

const kev = (cveId: string, ransomware = "Unknown"): KevEntry => ({
  cveId,
  vendorProject: "Vendor",
  product: "Product",
  vulnerabilityName: "Some vulnerability",
  dateAdded: "2024-01-01",
  shortDescription: "",
  requiredAction: "",
  dueDate: "2024-01-22",
  knownRansomwareCampaignUse: ransomware,
  notes: "",
});

const input = (overrides: Partial<PriorityInput> & { cveId: string }): PriorityInput => ({
  cvss: undefined,
  epss: undefined,
  kev: undefined,
  ...overrides,
});

describe("baseScore", () => {
  it("weights CVSS at 40% and EPSS at 60%", () => {
    expect(baseScore(10, 1)).toBeCloseTo(100);
    expect(baseScore(10, 0)).toBeCloseTo(40);
    expect(baseScore(0, 1)).toBeCloseTo(60);
    expect(baseScore(9.8, 0.5)).toBeCloseTo(69.2);
  });

  it("assumes a neutral CVSS of 5.0 and EPSS of 0 when data is missing", () => {
    expect(baseScore(undefined, undefined)).toBeCloseTo(20);
  });
});

describe("tierFor", () => {
  it("always returns CRITICAL for KEV-listed CVEs", () => {
    expect(tierFor(0, true)).toBe("CRITICAL");
  });

  it("caps non-KEV CVEs at HIGH and applies the 60 / 35 thresholds", () => {
    expect(tierFor(100, false)).toBe("HIGH");
    expect(tierFor(60, false)).toBe("HIGH");
    expect(tierFor(59.9, false)).toBe("MEDIUM");
    expect(tierFor(35, false)).toBe("MEDIUM");
    expect(tierFor(34.9, false)).toBe("LOW");
  });
});

describe("scoreCve", () => {
  it("lifts KEV-listed CVEs into the 90-100 band", () => {
    const result = scoreCve(input({ cveId: "CVE-1", cvss: cvss(5.0, "MEDIUM"), epss: epss("CVE-1", 0.01), kev: kev("CVE-1") }));
    expect(result.tier).toBe("CRITICAL");
    expect(result.score).toBeCloseTo(90 + (20 + 0.6) / 10, 1);
    expect(result.inKev).toBe(true);
  });

  it("explains a high-CVSS / low-EPSS CVE as low exploitation likelihood", () => {
    const result = scoreCve(input({ cveId: "CVE-2", cvss: cvss(9.8), epss: epss("CVE-2", 0.0004, 0.12) }));
    expect(result.tier).toBe("MEDIUM");
    expect(result.score).toBe(39.2);
    expect(result.rationale).toBe(
      "Schedule — severe on paper, but low exploitation likelihood: not in KEV, EPSS 0.04% (p12.0), CVSS 9.8 CRITICAL.",
    );
  });

  it("flags a moderate-CVSS CVE with high EPSS", () => {
    const result = scoreCve(input({ cveId: "CVE-3", cvss: cvss(6.1, "MEDIUM"), epss: epss("CVE-3", 0.85, 0.99) }));
    expect(result.tier).toBe("HIGH");
    expect(result.rationale).toMatch(/^Patch soon — moderate severity, but likely to be exploited/);
  });

  it("mentions ransomware use and KEV date in the rationale", () => {
    const result = scoreCve(input({ cveId: "CVE-4", cvss: cvss(10), epss: epss("CVE-4", 0.97, 0.999), kev: kev("CVE-4", "Known") }));
    expect(result.ransomware).toBe(true);
    expect(result.rationale).toContain("CISA KEV since 2024-01-01 (ransomware use)");
    expect(result.rationale).toMatch(/^Patch now — exploited in the wild/);
  });

  it("reports missing data instead of hiding it", () => {
    const result = scoreCve(input({ cveId: "CVE-5", epss: null, notes: ["not found in NVD"] }));
    expect(result.cvssScore).toBeUndefined();
    expect(result.rationale).toContain("no EPSS score");
    expect(result.rationale).toContain("no CVSS yet (assumed 5.0)");
    expect(result.rationale).toContain("not found in NVD");
  });
});

describe("rankCves", () => {
  it("orders by tier, then score, then EPSS, then CVSS", () => {
    const ranked = rankCves([
      input({ cveId: "CVE-LOW", cvss: cvss(4.3, "MEDIUM"), epss: epss("CVE-LOW", 0.001) }),
      input({ cveId: "CVE-HIGH-CVSS", cvss: cvss(9.8), epss: epss("CVE-HIGH-CVSS", 0.002) }),
      input({ cveId: "CVE-KEV", cvss: cvss(7.5, "HIGH"), epss: epss("CVE-KEV", 0.02), kev: kev("CVE-KEV") }),
      input({ cveId: "CVE-HOT", cvss: cvss(8.1, "HIGH"), epss: epss("CVE-HOT", 0.9) }),
    ]);
    expect(ranked.map((r) => r.cveId)).toEqual(["CVE-KEV", "CVE-HOT", "CVE-HIGH-CVSS", "CVE-LOW"]);
  });

  it("puts a KEV entry with low scores above a non-KEV entry with perfect scores", () => {
    const ranked = rankCves([
      input({ cveId: "CVE-A", cvss: cvss(10), epss: epss("CVE-A", 1) }),
      input({ cveId: "CVE-B", cvss: cvss(3.1, "LOW"), epss: epss("CVE-B", 0), kev: kev("CVE-B") }),
    ]);
    expect(ranked[0]?.cveId).toBe("CVE-B");
  });
});

describe("formatting helpers", () => {
  it("formats probabilities with extra precision below 1%", () => {
    expect(formatProbability(0.00036)).toBe("0.04%");
    expect(formatProbability(0.97431)).toBe("97.4%");
    expect(formatProbability(0.99999)).toBe("99.9%");
  });

  it("formats percentiles without rounding up to p100", () => {
    expect(formatPercentile(0.99999)).toBe("p99.9");
    expect(formatPercentile(1)).toBe("p100.0");
    expect(formatPercentile(0.4)).toBe("p40.0");
  });
});
