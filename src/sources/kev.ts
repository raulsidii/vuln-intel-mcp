import { z } from "zod";
import { KEV_CACHE_TTL_MS, KEV_FEED_URL, KEV_TIMEOUT_MS } from "../config.js";
import { TtlCache, type Clock } from "../lib/cache.js";
import { fetchJson, type FetchLike, type Sleep } from "../lib/http.js";
import type { KevCatalog, KevEntry } from "../types.js";

const kevFeedSchema = z.object({
  catalogVersion: z.string().default("unknown"),
  dateReleased: z.string().default(""),
  vulnerabilities: z.array(
    z.object({
      cveID: z.string(),
      vendorProject: z.string().default(""),
      product: z.string().default(""),
      vulnerabilityName: z.string().default(""),
      dateAdded: z.string().default(""),
      shortDescription: z.string().default(""),
      requiredAction: z.string().default(""),
      dueDate: z.string().default(""),
      knownRansomwareCampaignUse: z.string().default("Unknown"),
      notes: z.string().default(""),
    }),
  ),
});

export function parseKevFeed(raw: unknown): KevCatalog {
  const parsed = kevFeedSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`Unexpected CISA KEV feed shape: ${parsed.error.issues[0]?.message ?? "invalid"}`);
  }
  const entries = new Map<string, KevEntry>(
    parsed.data.vulnerabilities.map(({ cveID, ...rest }) => {
      const id = cveID.trim().toUpperCase();
      return [id, { cveId: id, ...rest }] as const;
    }),
  );
  return {
    catalogVersion: parsed.data.catalogVersion,
    dateReleased: parsed.data.dateReleased,
    count: entries.size,
    entries,
  };
}

export interface KevClientOptions {
  readonly fetchImpl?: FetchLike;
  readonly sleep?: Sleep;
  readonly feedUrl?: string;
  readonly now?: Clock;
}

const CATALOG_KEY = "catalog";

/** Downloads the full KEV catalog (~1.8 MB) once and keeps it in memory for 12 hours. */
export class KevClient {
  private readonly cache: TtlCache<KevCatalog>;
  private inFlight: Promise<KevCatalog> | undefined;

  constructor(private readonly options: KevClientOptions = {}) {
    this.cache = new TtlCache<KevCatalog>(KEV_CACHE_TTL_MS, 1, options.now);
  }

  async getCatalog(): Promise<KevCatalog> {
    const cached = this.cache.get(CATALOG_KEY);
    if (cached) return cached;
    // Coalesce concurrent callers onto a single download.
    this.inFlight ??= this.download().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  private async download(): Promise<KevCatalog> {
    const raw = await fetchJson(this.options.feedUrl ?? KEV_FEED_URL, {
      source: "CISA KEV",
      timeoutMs: KEV_TIMEOUT_MS,
      ...(this.options.fetchImpl && { fetchImpl: this.options.fetchImpl }),
      ...(this.options.sleep && { sleep: this.options.sleep }),
    });
    const catalog = parseKevFeed(raw);
    this.cache.set(CATALOG_KEY, catalog);
    return catalog;
  }
}
