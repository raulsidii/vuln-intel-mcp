import { errorMessage } from "./lib/errors.js";
import type { ToolDeps } from "./tools/deps.js";
import { selectPrimaryCvss } from "./sources/nvd-parse.js";
import { rankCves, type PriorityInput, type PriorityResult } from "./scoring.js";
import type { CveRecord, EpssScore, KevCatalog } from "./types.js";

export interface PrioritizeOutcome {
  readonly results: PriorityResult[];
  /** Source-wide problems worth surfacing under the table. */
  readonly notes: string[];
}

type Settled<T> = PromiseSettledResult<T>;

const settle = async <T>(promise: Promise<T>): Promise<Settled<T>> =>
  promise.then(
    (value) => ({ status: "fulfilled", value }) as const,
    (reason: unknown) => ({ status: "rejected", reason }) as const,
  );

function nvdNote(outcome: Settled<CveRecord | null> | undefined): string[] {
  if (!outcome) return [];
  if (outcome.status === "rejected") return ["NVD unavailable"];
  return outcome.value ? [] : ["not found in NVD"];
}

function buildInput(
  cveId: string,
  nvd: Settled<CveRecord | null> | undefined,
  epss: ReadonlyMap<string, EpssScore | null> | undefined,
  kev: KevCatalog | undefined,
): PriorityInput {
  const record = nvd?.status === "fulfilled" ? nvd.value : null;
  return {
    cveId,
    cvss: record ? selectPrimaryCvss(record.cvss) : undefined,
    epss: epss?.get(cveId) ?? null,
    kev: kev?.entries.get(cveId),
    notes: nvdNote(nvd),
  };
}

/**
 * Fetches NVD, EPSS and KEV for every CVE and ranks them. A failing source
 * degrades the result (and is reported) instead of failing the whole call;
 * only if all three sources fail is an error thrown.
 */
export async function prioritize(cveIds: readonly string[], deps: ToolDeps): Promise<PrioritizeOutcome> {
  const [kevOutcome, epssOutcome, nvd] = await Promise.all([
    settle(deps.kev.getCatalog()),
    settle(deps.epss.getScores(cveIds)),
    Promise.allSettled(cveIds.map((id) => deps.nvd.getCve(id))),
  ]);

  const kev = kevOutcome.status === "fulfilled" ? kevOutcome.value : undefined;
  const epss = epssOutcome.status === "fulfilled" ? epssOutcome.value : undefined;

  const nvdFailures = nvd.filter((o): o is PromiseRejectedResult => o.status === "rejected");
  const notes = [
    ...(kevOutcome.status === "rejected" ? [`CISA KEV unavailable: ${errorMessage(kevOutcome.reason)}`] : []),
    ...(epssOutcome.status === "rejected" ? [`FIRST EPSS unavailable: ${errorMessage(epssOutcome.reason)}`] : []),
    ...(nvdFailures[0]
      ? [`NVD failed for ${nvdFailures.length} CVE(s): ${errorMessage(nvdFailures[0].reason)}`]
      : []),
  ];

  if (!kev && !epss && nvdFailures.length === cveIds.length) {
    throw new Error(`All data sources failed. ${notes.join(" ")}`);
  }

  const inputs = cveIds.map((id, i) => buildInput(id, nvd[i], epss, kev));
  return { results: rankCves(inputs), notes };
}
