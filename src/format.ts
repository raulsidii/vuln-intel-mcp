import { formatPercentile, formatProbability, type PriorityResult } from "./scoring.js";
import type { CveRecord, CvssMetric, EpssScore, KevCatalog, KevEntry } from "./types.js";

const DESCRIPTION_PREVIEW_CHARS = 220;

export const dateOnly = (iso: string): string => iso.slice(0, 10) || "unknown";

/** Escapes characters that would break a Markdown table cell. */
export const cell = (text: string): string => text.replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ");

export function truncate(text: string, max: number): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length <= max ? flat : `${flat.slice(0, max - 1).trimEnd()}…`;
}

function formatCvssLine(metric: CvssMetric): string {
  const severity = metric.severity ? ` ${metric.severity}` : "";
  return `- **CVSS v${metric.version}:** ${metric.baseScore.toFixed(1)}${severity} — \`${metric.vector}\` (${metric.source}, ${metric.type})`;
}

export function formatCveRecord(record: CveRecord, maxReferences: number): string {
  const cvssLines = record.cvss.length
    ? record.cvss.map(formatCvssLine)
    : ["- **CVSS:** not scored yet"];
  const shown = record.references.slice(0, maxReferences);
  const refHeader =
    record.references.length > shown.length
      ? `**References** (${shown.length} of ${record.references.length}):`
      : `**References** (${shown.length}):`;
  const refs = shown.map((r) => `- ${r.url}${r.tags.length ? ` — ${r.tags.join(", ")}` : ""}`);

  return [
    `## ${record.id}`,
    `**Status:** ${record.status} · **Published:** ${dateOnly(record.published)} · **Last modified:** ${dateOnly(record.lastModified)}`,
    "",
    ...cvssLines,
    `- **CWE:** ${record.cwes.length ? record.cwes.join(", ") : "none listed"}`,
    "",
    `**Description:** ${record.description || "(none)"}`,
    "",
    refHeader,
    ...(refs.length ? refs : ["- none"]),
    "",
    `Source: https://nvd.nist.gov/vuln/detail/${record.id}`,
  ].join("\n");
}

export function formatSearchResults(keyword: string, total: number, records: readonly CveRecord[]): string {
  if (records.length === 0) return `No NVD results for "${keyword}".`;
  const rows = records.map((r) => {
    const top = r.cvss.find((m) => m.version === "3.1") ?? r.cvss[0];
    const score = top ? `${top.baseScore.toFixed(1)} (v${top.version})` : "—";
    return `| ${r.id} | ${score} | ${dateOnly(r.published)} | ${cell(truncate(r.description, DESCRIPTION_PREVIEW_CHARS))} |`;
  });
  return [
    `Showing ${records.length} of ${total} NVD results for "${keyword}":`,
    "",
    "| CVE | CVSS | Published | Summary |",
    "|---|---|---|---|",
    ...rows,
    "",
    total > records.length ? "Refine the keywords or raise `limit` to see more." : "",
  ]
    .join("\n")
    .trimEnd();
}

export function formatEpss(scores: ReadonlyMap<string, EpssScore | null>): string {
  const rows = [...scores].map(([id, s]) =>
    s
      ? `| ${id} | ${formatProbability(s.epss)} | ${formatPercentile(s.percentile)} | ${s.date} |`
      : `| ${id} | — | — | not scored by FIRST |`,
  );
  return [
    "| CVE | EPSS (30-day exploit probability) | Percentile | Model date |",
    "|---|---|---|---|",
    ...rows,
    "",
    "EPSS = probability of exploitation activity in the next 30 days (FIRST.org). Percentile = share of all CVEs with a lower score.",
  ].join("\n");
}

function formatKevEntry(entry: KevEntry): string {
  return [
    `### ${entry.cveId} — LISTED in CISA KEV`,
    `- **Name:** ${entry.vulnerabilityName}`,
    `- **Vendor / product:** ${entry.vendorProject} / ${entry.product}`,
    `- **Date added:** ${entry.dateAdded} · **Federal due date:** ${entry.dueDate}`,
    `- **Known ransomware use:** ${entry.knownRansomwareCampaignUse}`,
    `- **Required action:** ${entry.requiredAction}`,
    `- **Summary:** ${entry.shortDescription}`,
  ].join("\n");
}

export function formatKev(ids: readonly string[], catalog: KevCatalog): string {
  const sections = ids.map((id) => {
    const entry = catalog.entries.get(id);
    return entry ? formatKevEntry(entry) : `### ${id} — not in CISA KEV`;
  });
  const footer = `Catalog version ${catalog.catalogVersion} (${catalog.count} entries). Absence from KEV is not proof that a CVE is unexploited.`;
  return [...sections, footer].join("\n\n");
}

export function formatPriorityTable(results: readonly PriorityResult[], notes: readonly string[]): string {
  const rows = results.map((r, i) => {
    const epss = r.epss === undefined ? "—" : formatProbability(r.epss);
    const cvss = r.cvssScore === undefined ? "—" : `${r.cvssScore.toFixed(1)} (v${r.cvssVersion})`;
    const kev = r.inKev ? (r.ransomware ? "yes (ransomware)" : "yes") : "no";
    return `| ${i + 1} | ${r.cveId} | ${r.tier} | ${r.score.toFixed(1)} | ${kev} | ${epss} | ${cvss} | ${cell(r.rationale)} |`;
  });
  return [
    "| # | CVE | Tier | Score | KEV | EPSS | CVSS | Rationale |",
    "|---|---|---|---|---|---|---|---|",
    ...rows,
    "",
    "Score = 100 × (0.4 × CVSS/10 + 0.6 × EPSS). KEV-listed CVEs are lifted to 90 + base/10 and always rank CRITICAL. Non-KEV tiers: HIGH ≥ 60, MEDIUM ≥ 35, LOW < 35.",
    ...notes.map((n) => `_Note: ${n}_`),
  ].join("\n");
}
