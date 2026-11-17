import type { CvssMetric, EpssScore, KevEntry } from "./types.js";

/**
 * Priority model (documented in the README):
 *
 *   base  = 100 * (W_CVSS * cvss/10 + W_EPSS * epss)
 *   score = KEV listed ? 90 + base/10   (always 90-100, tier CRITICAL)
 *                      : base           (0-100, tier HIGH / MEDIUM / LOW)
 *
 * EPSS gets the larger weight because it estimates the probability of real-world
 * exploitation, while CVSS only measures technical severity. KEV membership is
 * evidence rather than prediction, so it overrides both.
 */
export const WEIGHTS = { cvss: 0.4, epss: 0.6 } as const;
export const KEV_FLOOR = 90;
export const TIER_THRESHOLDS = { high: 60, medium: 35 } as const;
/** Used when NVD has not scored a CVE yet; flagged in the output. */
export const NEUTRAL_CVSS = 5.0;

export type Tier = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export const TIER_RANK: Readonly<Record<Tier, number>> = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };

export interface PriorityInput {
  readonly cveId: string;
  readonly cvss: CvssMetric | undefined;
  readonly epss: EpssScore | null | undefined;
  readonly kev: KevEntry | undefined;
  /** Data-quality caveats (e.g. a source was unreachable); appended to the rationale. */
  readonly notes?: readonly string[];
}

export interface PriorityResult {
  readonly cveId: string;
  readonly score: number;
  readonly tier: Tier;
  readonly cvssScore: number | undefined;
  readonly cvssSeverity: string | undefined;
  readonly cvssVersion: string | undefined;
  readonly epss: number | undefined;
  readonly epssPercentile: number | undefined;
  readonly inKev: boolean;
  readonly ransomware: boolean;
  readonly rationale: string;
}

const round1 = (n: number): number => Math.round(n * 10) / 10;

export function baseScore(cvss: number | undefined, epss: number | undefined): number {
  const cvssPart = (cvss ?? NEUTRAL_CVSS) / 10;
  const epssPart = epss ?? 0;
  return 100 * (WEIGHTS.cvss * cvssPart + WEIGHTS.epss * epssPart);
}

export function tierFor(score: number, inKev: boolean): Tier {
  if (inKev) return "CRITICAL";
  if (score >= TIER_THRESHOLDS.high) return "HIGH";
  if (score >= TIER_THRESHOLDS.medium) return "MEDIUM";
  return "LOW";
}

/** Formats a 0-1 probability as a percentage, truncating so 0.99999 never shows as 100%. */
export function formatProbability(p: number): string {
  const pct = p * 100;
  return pct < 1 ? `${pct.toFixed(2)}%` : `${(Math.floor(pct * 10) / 10).toFixed(1)}%`;
}

export function formatPercentile(p: number): string {
  return `p${(Math.floor(p * 1000) / 10).toFixed(1)}`;
}

/** EPSS bands used only to word the rationale; they do not affect the score. */
const LOW_EPSS = 0.05;
const ELEVATED_EPSS = 0.1;
const HIGH_EPSS = 0.5;

const VERDICT: Readonly<Record<Tier, string>> = {
  CRITICAL: "Patch now",
  HIGH: "Patch soon",
  MEDIUM: "Schedule",
  LOW: "Monitor",
};

function qualifier(cvss: number | undefined, epss: number | undefined, inKev: boolean): string | undefined {
  if (inKev) return "exploited in the wild";
  if (epss === undefined) return undefined;
  if (cvss !== undefined && cvss >= 9 && epss < LOW_EPSS) return "severe on paper, but low exploitation likelihood";
  if (cvss !== undefined && cvss < 7 && epss >= ELEVATED_EPSS) return "moderate severity, but likely to be exploited";
  if (epss >= HIGH_EPSS) return "exploitation highly likely";
  return undefined;
}

function facts(input: PriorityInput): string[] {
  const { cvss, epss, kev } = input;
  const kevFact = kev
    ? `CISA KEV since ${kev.dateAdded}${kev.knownRansomwareCampaignUse === "Known" ? " (ransomware use)" : ""}`
    : "not in KEV";
  const epssFact = epss
    ? `EPSS ${formatProbability(epss.epss)} (${formatPercentile(epss.percentile)})`
    : "no EPSS score";
  const cvssFact = cvss
    ? `CVSS ${cvss.baseScore.toFixed(1)}${cvss.severity ? ` ${cvss.severity}` : ""}`
    : `no CVSS yet (assumed ${NEUTRAL_CVSS.toFixed(1)})`;
  return [kevFact, epssFact, cvssFact, ...(input.notes ?? [])];
}

export function buildRationale(input: PriorityInput, tier: Tier): string {
  const note = qualifier(input.cvss?.baseScore, input.epss?.epss, Boolean(input.kev));
  const head = note ? `${VERDICT[tier]} — ${note}` : VERDICT[tier];
  return `${head}: ${facts(input).join(", ")}.`;
}

export function scoreCve(input: PriorityInput): PriorityResult {
  const inKev = Boolean(input.kev);
  const base = baseScore(input.cvss?.baseScore, input.epss?.epss);
  const score = round1(inKev ? KEV_FLOOR + base / 10 : base);
  const tier = tierFor(score, inKev);
  return {
    cveId: input.cveId,
    score,
    tier,
    cvssScore: input.cvss?.baseScore,
    cvssSeverity: input.cvss?.severity,
    cvssVersion: input.cvss?.version,
    epss: input.epss?.epss,
    epssPercentile: input.epss?.percentile,
    inKev,
    ransomware: input.kev?.knownRansomwareCampaignUse === "Known",
    rationale: buildRationale(input, tier),
  };
}

export function compareResults(a: PriorityResult, b: PriorityResult): number {
  return (
    TIER_RANK[b.tier] - TIER_RANK[a.tier] ||
    b.score - a.score ||
    (b.epss ?? -1) - (a.epss ?? -1) ||
    (b.cvssScore ?? -1) - (a.cvssScore ?? -1) ||
    a.cveId.localeCompare(b.cveId)
  );
}

export function rankCves(inputs: readonly PriorityInput[]): PriorityResult[] {
  return inputs.map(scoreCve).sort(compareResults);
}
