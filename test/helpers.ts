import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { FetchLike } from "../src/lib/http.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

/** Loads a recorded API response from test/fixtures. */
export function fixture(name: string): unknown {
  return JSON.parse(readFileSync(join(FIXTURES, name), "utf8"));
}

export function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

export const noSleep = async (): Promise<void> => {};

export interface Route {
  readonly match: (url: URL) => boolean;
  readonly respond: (url: URL) => Response | Promise<Response>;
}

export interface FakeFetch extends FetchLike {
  readonly calls: string[];
}

/** A fetch stand-in that serves fixtures by URL and records every request. No network. */
export function fakeFetch(routes: readonly Route[]): FakeFetch {
  const calls: string[] = [];
  const impl = async (input: string): Promise<Response> => {
    calls.push(input);
    const url = new URL(input);
    const route = routes.find((r) => r.match(url));
    if (!route) throw new Error(`Unexpected request in test: ${input}`);
    return route.respond(url);
  };
  return Object.assign(impl, { calls });
}

const NVD_BY_ID: Readonly<Record<string, string>> = {
  "CVE-2021-44228": "nvd-cve-2021-44228.json",
  "CVE-2023-38545": "nvd-cve-2023-38545.json",
  "CVE-2024-3400": "nvd-cve-2024-3400.json",
  "CVE-2026-120189": "nvd-cve-v4.json",
};

export const nvdRoute: Route = {
  match: (url) => url.hostname === "services.nvd.nist.gov",
  respond: (url) => {
    const cveId = url.searchParams.get("cveId");
    if (cveId) return jsonResponse(fixture(NVD_BY_ID[cveId] ?? "nvd-empty.json"));
    return jsonResponse(fixture("nvd-search-log4j.json"));
  },
};

/** Serves the recorded EPSS payload, filtered to the requested CVEs like the real API. */
export const epssRoute: Route = {
  match: (url) => url.hostname === "api.first.org",
  respond: (url) => {
    const wanted = new Set((url.searchParams.get("cve") ?? "").split(","));
    const body = fixture("epss.json") as { data: Array<{ cve: string }> };
    return jsonResponse({ ...body, data: body.data.filter((d) => wanted.has(d.cve)) });
  },
};

export const kevRoute: Route = {
  match: (url) => url.hostname === "www.cisa.gov",
  respond: () => jsonResponse(fixture("kev.json")),
};

export const allRoutes: readonly Route[] = [nvdRoute, epssRoute, kevRoute];
