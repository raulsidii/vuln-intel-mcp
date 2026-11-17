export const SERVER_NAME = "vuln-intel-mcp";
export const SERVER_VERSION = "0.1.0";

export const USER_AGENT = `${SERVER_NAME}/${SERVER_VERSION} (+https://github.com/raulsidii/vuln-intel-mcp)`;

export const NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
export const EPSS_API_URL = "https://api.first.org/data/v1/epss";
export const KEV_FEED_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;

export const HTTP_TIMEOUT_MS = 20_000;
export const KEV_TIMEOUT_MS = 45_000;
export const HTTP_MAX_RETRIES = 3;
export const HTTP_BACKOFF_BASE_MS = 1_000;
export const HTTP_BACKOFF_MAX_MS = 30_000;

export const NVD_CACHE_TTL_MS = 6 * HOUR_MS;
export const EPSS_CACHE_TTL_MS = 6 * HOUR_MS;
export const KEV_CACHE_TTL_MS = 12 * HOUR_MS;
export const CACHE_MAX_ENTRIES = 1_000;

/**
 * NVD public rate limits: 5 requests / 30 s without a key, 50 / 30 s with one.
 * https://nvd.nist.gov/developers/start-here
 */
export const NVD_RATE_WINDOW_MS = 30_000;
export const NVD_RATE_LIMIT_ANON = 5;
export const NVD_RATE_LIMIT_KEYED = 50;

export const EPSS_BATCH_SIZE = 100;
export const PRIORITIZE_MAX_CVES = 30;
export const SEARCH_MAX_RESULTS = 20;

export interface RuntimeConfig {
  readonly nvdApiKey: string | undefined;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): RuntimeConfig {
  const key = env.NVD_API_KEY?.trim();
  return { nvdApiKey: key ? key : undefined };
}
