import { z } from "zod";
import type { CveRecord, CveSearchResult, CvssMetric, CvssVersion } from "../types.js";

const cvssEntrySchema = z.object({
  source: z.string().default("unknown"),
  type: z.string().default("Secondary"),
  cvssData: z.object({
    version: z.string(),
    vectorString: z.string(),
    baseScore: z.number(),
    baseSeverity: z.string().optional(),
  }),
  // CVSS v2 keeps severity outside cvssData.
  baseSeverity: z.string().optional(),
});

const cveSchema = z.object({
  id: z.string(),
  published: z.string().default(""),
  lastModified: z.string().default(""),
  vulnStatus: z.string().default("Unknown"),
  descriptions: z.array(z.object({ lang: z.string(), value: z.string() })).default([]),
  metrics: z.record(z.string(), z.unknown()).default({}),
  weaknesses: z
    .array(z.object({ description: z.array(z.object({ lang: z.string(), value: z.string() })) }))
    .default([]),
  references: z
    .array(z.object({ url: z.string(), tags: z.array(z.string()).default([]) }))
    .default([]),
});

export const nvdResponseSchema = z.object({
  totalResults: z.number(),
  vulnerabilities: z.array(z.object({ cve: cveSchema })),
});

type NvdCve = z.infer<typeof cveSchema>;
type CvssEntry = z.infer<typeof cvssEntrySchema>;

/** NVD metric keys, newest CVSS version first. */
const METRIC_KEYS: ReadonlyArray<readonly [string, CvssVersion]> = [
  ["cvssMetricV40", "4.0"],
  ["cvssMetricV31", "3.1"],
  ["cvssMetricV30", "3.0"],
  ["cvssMetricV2", "2.0"],
];

function pickEntry(raw: unknown): CvssEntry | undefined {
  const parsed = z.array(cvssEntrySchema).safeParse(raw);
  if (!parsed.success || parsed.data.length === 0) return undefined;
  return parsed.data.find((m) => m.type === "Primary") ?? parsed.data[0];
}

function toMetric(entry: CvssEntry, version: CvssVersion): CvssMetric {
  return {
    version,
    baseScore: entry.cvssData.baseScore,
    severity: entry.cvssData.baseSeverity ?? entry.baseSeverity,
    vector: entry.cvssData.vectorString,
    source: entry.source,
    type: entry.type === "Primary" ? "Primary" : "Secondary",
  };
}

export function extractCvss(metrics: Record<string, unknown>): CvssMetric[] {
  return METRIC_KEYS.flatMap(([key, version]) => {
    const entry = pickEntry(metrics[key]);
    return entry ? [toMetric(entry, version)] : [];
  });
}

function toRecord(cve: NvdCve): CveRecord {
  const english = cve.descriptions.find((d) => d.lang === "en") ?? cve.descriptions[0];
  const cwes = cve.weaknesses.flatMap((w) => w.description.map((d) => d.value));
  const references = [...new Map(cve.references.map((r) => [r.url, r] as const)).values()];

  return {
    id: cve.id,
    description: english?.value.trim() ?? "",
    published: cve.published,
    lastModified: cve.lastModified,
    status: cve.vulnStatus,
    cvss: extractCvss(cve.metrics),
    cwes: [...new Set(cwes)],
    references: references.map((r) => ({ url: r.url, tags: r.tags })),
  };
}

/** Validates an NVD CVE API 2.0 response and maps it to domain records. */
export function parseNvdResponse(raw: unknown): CveSearchResult {
  const parsed = nvdResponseSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`Unexpected NVD response shape: ${parsed.error.issues[0]?.message ?? "invalid"}`);
  }
  return {
    totalResults: parsed.data.totalResults,
    records: parsed.data.vulnerabilities.map((v) => toRecord(v.cve)),
  };
}

/**
 * The score used for prioritization. v3.1 is preferred because almost every CVE
 * has one and scores are comparable across the set; v4.0 is still sparse in NVD.
 */
const PREFERRED_ORDER: readonly CvssVersion[] = ["3.1", "4.0", "3.0", "2.0"];

export function selectPrimaryCvss(cvss: readonly CvssMetric[]): CvssMetric | undefined {
  for (const version of PREFERRED_ORDER) {
    const metric = cvss.find((m) => m.version === version);
    if (metric) return metric;
  }
  return undefined;
}
