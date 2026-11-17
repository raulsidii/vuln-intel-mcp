import { z } from "zod";
import { CACHE_MAX_ENTRIES, EPSS_API_URL, EPSS_BATCH_SIZE, EPSS_CACHE_TTL_MS } from "../config.js";
import { TtlCache } from "../lib/cache.js";
import { fetchJson, type FetchLike, type Sleep } from "../lib/http.js";
import type { EpssScore } from "../types.js";

// FIRST returns the numbers as strings, e.g. "epss": "0.999990000".
const numeric = z.union([z.string(), z.number()]).transform(Number).pipe(z.number().min(0).max(1));

const epssResponseSchema = z.object({
  status: z.string().optional(),
  data: z.array(
    z.object({
      cve: z.string(),
      epss: numeric,
      percentile: numeric,
      date: z.string().default(""),
    }),
  ),
});

export function parseEpssResponse(raw: unknown): EpssScore[] {
  const parsed = epssResponseSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`Unexpected EPSS response shape: ${parsed.error.issues[0]?.message ?? "invalid"}`);
  }
  return parsed.data.data.map((d) => ({
    cve: d.cve.toUpperCase(),
    epss: d.epss,
    percentile: d.percentile,
    date: d.date,
  }));
}

export interface EpssClientOptions {
  readonly fetchImpl?: FetchLike;
  readonly sleep?: Sleep;
  readonly baseUrl?: string;
}

function chunk<T>(items: readonly T[], size: number): T[][] {
  return Array.from({ length: Math.ceil(items.length / size) }, (_, i) =>
    items.slice(i * size, (i + 1) * size),
  );
}

export class EpssClient {
  /** `null` caches "FIRST has no score for this CVE" so we don't re-ask. */
  private readonly cache = new TtlCache<EpssScore | null>(EPSS_CACHE_TTL_MS, CACHE_MAX_ENTRIES);

  constructor(private readonly options: EpssClientOptions = {}) {}

  /** Returns a map with an entry for every requested ID (`null` when unscored). */
  async getScores(cveIds: readonly string[]): Promise<Map<string, EpssScore | null>> {
    const missing = cveIds.filter((id) => this.cache.get(id) === undefined);

    for (const batch of chunk(missing, EPSS_BATCH_SIZE)) {
      const params = new URLSearchParams({ cve: batch.join(",") });
      const raw = await fetchJson(`${this.options.baseUrl ?? EPSS_API_URL}?${params.toString()}`, {
        source: "FIRST EPSS",
        ...(this.options.fetchImpl && { fetchImpl: this.options.fetchImpl }),
        ...(this.options.sleep && { sleep: this.options.sleep }),
      });
      const scores = new Map(parseEpssResponse(raw).map((s) => [s.cve, s] as const));
      for (const id of batch) this.cache.set(id, scores.get(id) ?? null);
    }

    return new Map(cveIds.map((id) => [id, this.cache.get(id) ?? null] as const));
  }

  async getScore(cveId: string): Promise<EpssScore | null> {
    return (await this.getScores([cveId])).get(cveId) ?? null;
  }
}
