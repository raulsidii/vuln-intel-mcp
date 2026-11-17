import {
  HTTP_BACKOFF_BASE_MS,
  HTTP_BACKOFF_MAX_MS,
  HTTP_MAX_RETRIES,
  HTTP_TIMEOUT_MS,
  USER_AGENT,
} from "../config.js";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;
export type Sleep = (ms: number) => Promise<void>;

export const defaultSleep: Sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Status codes worth retrying. NVD answers 403 (not 429) when you exceed its rate limit. */
const RETRYABLE_STATUS = new Set([403, 429, 500, 502, 503, 504]);

export class HttpError extends Error {
  constructor(
    message: string,
    readonly status: number | undefined,
    readonly url: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export interface RequestOptions {
  readonly headers?: Record<string, string>;
  readonly timeoutMs?: number;
  readonly maxRetries?: number;
  readonly fetchImpl?: FetchLike;
  readonly sleep?: Sleep;
  /** Human-readable name used in error messages, e.g. "NVD". */
  readonly source?: string;
}

/** Parses a Retry-After header (seconds or HTTP date) into milliseconds. */
export function parseRetryAfter(header: string | null, now: number = Date.now()): number | undefined {
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1_000;
  const date = Date.parse(header);
  return Number.isNaN(date) ? undefined : Math.max(0, date - now);
}

export function backoffDelay(attempt: number, retryAfterMs?: number): number {
  if (retryAfterMs !== undefined) return Math.min(retryAfterMs, HTTP_BACKOFF_MAX_MS);
  const exponential = HTTP_BACKOFF_BASE_MS * 2 ** attempt;
  const jitter = Math.random() * HTTP_BACKOFF_BASE_MS;
  return Math.min(exponential + jitter, HTTP_BACKOFF_MAX_MS);
}

function isTimeout(error: unknown): boolean {
  return error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError");
}

/**
 * GETs a URL and parses JSON, with a per-attempt timeout and exponential backoff
 * on rate-limit / transient server errors. Network failures and timeouts are retried too.
 */
export async function fetchJson<T = unknown>(url: string, options: RequestOptions = {}): Promise<T> {
  const {
    headers = {},
    timeoutMs = HTTP_TIMEOUT_MS,
    maxRetries = HTTP_MAX_RETRIES,
    fetchImpl = fetch,
    sleep = defaultSleep,
    source = new URL(url).hostname,
  } = options;

  let lastError: HttpError | undefined;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    let response: Response;
    try {
      response = await fetchImpl(url, {
        headers: { Accept: "application/json", "User-Agent": USER_AGENT, ...headers },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      const reason = isTimeout(error)
        ? `timed out after ${timeoutMs} ms`
        : `network error: ${(error as Error).message}`;
      lastError = new HttpError(`${source} request ${reason}`, undefined, url);
      if (attempt < maxRetries) await sleep(backoffDelay(attempt));
      continue;
    }

    if (response.ok) {
      try {
        return (await response.json()) as T;
      } catch {
        throw new HttpError(`${source} returned a response that is not valid JSON`, response.status, url);
      }
    }

    lastError = new HttpError(describeStatus(source, response.status), response.status, url);
    if (!RETRYABLE_STATUS.has(response.status) || attempt === maxRetries) break;
    await sleep(backoffDelay(attempt, parseRetryAfter(response.headers.get("retry-after"))));
  }

  throw lastError ?? new HttpError(`${source} request failed`, undefined, url);
}

function describeStatus(source: string, status: number): string {
  if (status === 403 || status === 429) {
    return `${source} rate limit hit (HTTP ${status}) and retries were exhausted. Try again shortly${
      source === "NVD" ? " or set NVD_API_KEY for a 10x higher limit" : ""
    }.`;
  }
  if (status === 404) return `${source} returned 404 Not Found`;
  if (status >= 500) return `${source} is unavailable (HTTP ${status})`;
  return `${source} request failed with HTTP ${status}`;
}
