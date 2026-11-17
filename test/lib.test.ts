import { describe, expect, it } from "vitest";
import { TtlCache } from "../src/lib/cache.js";
import { cveIdSchema, isValidCveId, uniqueCveIds } from "../src/lib/cve-id.js";
import { backoffDelay, fetchJson, HttpError, parseRetryAfter } from "../src/lib/http.js";
import { SlidingWindowLimiter } from "../src/lib/rate-limiter.js";
import { jsonResponse } from "./helpers.js";

describe("CVE ID helpers", () => {
  it("normalizes case and whitespace", () => {
    expect(cveIdSchema.parse("  cve-2021-44228 ")).toBe("CVE-2021-44228");
    expect(isValidCveId("CVE-2026-114713")).toBe(true);
  });

  it("rejects malformed IDs", () => {
    expect(isValidCveId("CVE-21-44228")).toBe(false);
    expect(isValidCveId("2021-44228")).toBe(false);
    expect(cveIdSchema.safeParse("CVE-2021-44228; DROP TABLE").success).toBe(false);
  });

  it("dedupes while preserving order", () => {
    expect(uniqueCveIds(["CVE-2024-3400", "cve-2021-44228", "CVE-2024-3400"])).toEqual([
      "CVE-2024-3400",
      "CVE-2021-44228",
    ]);
  });
});

describe("TtlCache", () => {
  it("expires entries after the TTL", () => {
    let now = 0;
    const cache = new TtlCache<string>(1_000, 10, () => now);
    cache.set("a", "1");
    now = 999;
    expect(cache.get("a")).toBe("1");
    now = 1_000;
    expect(cache.get("a")).toBeUndefined();
  });

  it("evicts the oldest entry when full", () => {
    const cache = new TtlCache<number>(60_000, 2);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);
    expect(cache.get("a")).toBeUndefined();
    expect(cache.size).toBe(2);
  });

  it("does not cache failed loads", async () => {
    const cache = new TtlCache<number>(60_000);
    await expect(cache.getOrLoad("k", () => Promise.reject(new Error("boom")))).rejects.toThrow("boom");
    await expect(cache.getOrLoad("k", async () => 42)).resolves.toBe(42);
  });
});

describe("SlidingWindowLimiter", () => {
  it("waits once the window is full", async () => {
    let now = 0;
    const sleeps: number[] = [];
    const limiter = new SlidingWindowLimiter(2, 30_000, () => now, async (ms) => {
      sleeps.push(ms);
      now += ms;
    });
    await limiter.acquire();
    await limiter.acquire();
    expect(sleeps).toEqual([]);
    await limiter.acquire();
    expect(sleeps).toHaveLength(1);
    expect(now).toBeGreaterThanOrEqual(30_000);
  });
});

describe("fetchJson", () => {
  const url = "https://example.test/api";

  it("retries on 429, honouring Retry-After, then succeeds", async () => {
    const sleeps: number[] = [];
    const responses = [jsonResponse({}, 429, { "retry-after": "2" }), jsonResponse({ ok: true })];
    const result = await fetchJson(url, {
      fetchImpl: async () => responses.shift()!,
      sleep: async (ms) => void sleeps.push(ms),
    });
    expect(result).toEqual({ ok: true });
    expect(sleeps).toEqual([2_000]);
  });

  it("gives up after maxRetries on NVD's 403 rate limit with a helpful message", async () => {
    let calls = 0;
    const attempt = fetchJson(url, {
      source: "NVD",
      maxRetries: 2,
      fetchImpl: async () => {
        calls++;
        return jsonResponse({}, 403);
      },
      sleep: async () => {},
    });
    await expect(attempt).rejects.toThrow(/NVD rate limit hit \(HTTP 403\).*NVD_API_KEY/);
    expect(calls).toBe(3);
  });

  it("does not retry client errors like 404", async () => {
    let calls = 0;
    const attempt = fetchJson(url, {
      fetchImpl: async () => {
        calls++;
        return jsonResponse({}, 404);
      },
      sleep: async () => {},
    });
    await expect(attempt).rejects.toBeInstanceOf(HttpError);
    expect(calls).toBe(1);
  });

  it("retries timeouts and network errors", async () => {
    const timeout = Object.assign(new Error("aborted"), { name: "TimeoutError" });
    const outcomes: Array<() => Promise<Response>> = [
      () => Promise.reject(timeout),
      () => Promise.reject(new TypeError("fetch failed")),
      async () => jsonResponse({ ok: 1 }),
    ];
    const result = await fetchJson(url, { fetchImpl: () => outcomes.shift()!(), sleep: async () => {} });
    expect(result).toEqual({ ok: 1 });
  });

  it("reports a timeout clearly when every attempt times out", async () => {
    const timeout = Object.assign(new Error("aborted"), { name: "TimeoutError" });
    const attempt = fetchJson(url, {
      source: "FIRST EPSS",
      timeoutMs: 5,
      maxRetries: 1,
      fetchImpl: () => Promise.reject(timeout),
      sleep: async () => {},
    });
    await expect(attempt).rejects.toThrow("FIRST EPSS request timed out after 5 ms");
  });

  it("rejects non-JSON bodies", async () => {
    const attempt = fetchJson(url, { fetchImpl: async () => new Response("<html>", { status: 200 }) });
    await expect(attempt).rejects.toThrow(/not valid JSON/);
  });

  it("parses Retry-After in seconds and HTTP-date form", () => {
    expect(parseRetryAfter("5")).toBe(5_000);
    expect(parseRetryAfter(new Date(10_000).toUTCString(), 4_000)).toBe(6_000);
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(backoffDelay(0, 999_999)).toBe(30_000);
  });
});
