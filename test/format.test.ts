import { describe, expect, it } from "vitest";
import { cell, formatCveRecord, formatKev, truncate } from "../src/format.js";
import { parseKevFeed } from "../src/sources/kev.js";
import { parseNvdResponse } from "../src/sources/nvd-parse.js";
import { fixture } from "./helpers.js";

describe("format helpers", () => {
  it("escapes pipes and newlines inside table cells", () => {
    expect(cell("a | b\n  c")).toBe("a \\| b c");
  });

  it("truncates long text on a single line", () => {
    expect(truncate("one   two\nthree", 50)).toBe("one two three");
    expect(truncate("abcdefghij", 5)).toBe("abcd…");
  });
});

describe("formatCveRecord", () => {
  it("renders a CVE without references or CVSS", () => {
    const record = { ...parseNvdResponse(fixture("nvd-cve-2021-44228.json")).records[0]!, cvss: [], references: [] };
    const text = formatCveRecord(record, 5);
    expect(text).toContain("**CVSS:** not scored yet");
    expect(text).toContain("**References** (0):\n- none");
  });
});

describe("formatKev", () => {
  it("separates listed and unlisted CVEs and ends with the catalog version", () => {
    const text = formatKev(["CVE-2024-3400", "CVE-2023-38545"], parseKevFeed(fixture("kev.json")));
    expect(text).toContain("### CVE-2024-3400 — LISTED in CISA KEV");
    expect(text).toContain("### CVE-2023-38545 — not in CISA KEV\n\nCatalog version 2026.11.13 (4 entries).");
  });
});
