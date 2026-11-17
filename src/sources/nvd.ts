import {
  CACHE_MAX_ENTRIES,
  NVD_API_URL,
  NVD_CACHE_TTL_MS,
  NVD_RATE_LIMIT_ANON,
  NVD_RATE_LIMIT_KEYED,
  NVD_RATE_WINDOW_MS,
} from "../config.js";
import { TtlCache } from "../lib/cache.js";
import { fetchJson, type FetchLike, type Sleep } from "../lib/http.js";
import { SlidingWindowLimiter } from "../lib/rate-limiter.js";
import type { CveRecord, CveSearchResult } from "../types.js";
import { parseNvdResponse } from "./nvd-parse.js";

export interface NvdClientOptions {
  readonly apiKey?: string | undefined;
  readonly fetchImpl?: FetchLike;
  readonly sleep?: Sleep;
  readonly baseUrl?: string;
}

export interface SearchOptions {
  readonly keyword: string;
  readonly limit: number;
  readonly exactMatch?: boolean;
}

export class NvdClient {
  private readonly cveCache = new TtlCache<CveRecord | null>(NVD_CACHE_TTL_MS, CACHE_MAX_ENTRIES);
  private readonly searchCache = new TtlCache<CveSearchResult>(NVD_CACHE_TTL_MS, 100);
  private readonly limiter: SlidingWindowLimiter;

  constructor(private readonly options: NvdClientOptions = {}) {
    const limit = options.apiKey ? NVD_RATE_LIMIT_KEYED : NVD_RATE_LIMIT_ANON;
    this.limiter = new SlidingWindowLimiter(limit, NVD_RATE_WINDOW_MS, Date.now, options.sleep);
  }

  get hasApiKey(): boolean {
    return Boolean(this.options.apiKey);
  }

  /** Returns the CVE, or `null` if NVD has no record for it. */
  async getCve(cveId: string): Promise<CveRecord | null> {
    return this.cveCache.getOrLoad(cveId, async () => {
      const result = await this.request(new URLSearchParams({ cveId }));
      return result.records.find((r) => r.id === cveId) ?? null;
    });
  }

  async search({ keyword, limit, exactMatch = false }: SearchOptions): Promise<CveSearchResult> {
    const key = `${keyword.toLowerCase()}|${limit}|${exactMatch}`;
    return this.searchCache.getOrLoad(key, async () => {
      const params = new URLSearchParams({ keywordSearch: keyword, resultsPerPage: String(limit) });
      // keywordExactMatch is a value-less flag in the NVD API.
      const query = exactMatch ? `${params.toString()}&keywordExactMatch` : params.toString();
      const result = await this.request(query);
      for (const record of result.records) this.cveCache.set(record.id, record);
      return result;
    });
  }

  private async request(query: URLSearchParams | string): Promise<CveSearchResult> {
    await this.limiter.acquire();
    const headers: Record<string, string> = this.options.apiKey ? { apiKey: this.options.apiKey } : {};
    const raw = await fetchJson(`${this.options.baseUrl ?? NVD_API_URL}?${query.toString()}`, {
      headers,
      source: "NVD",
      ...(this.options.fetchImpl && { fetchImpl: this.options.fetchImpl }),
      ...(this.options.sleep && { sleep: this.options.sleep }),
    });
    return parseNvdResponse(raw);
  }
}
