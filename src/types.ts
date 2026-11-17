export type CvssVersion = "4.0" | "3.1" | "3.0" | "2.0";

export interface CvssMetric {
  readonly version: CvssVersion;
  readonly baseScore: number;
  readonly severity: string | undefined;
  readonly vector: string;
  /** Who scored it: "nvd@nist.gov" or the CNA. */
  readonly source: string;
  readonly type: "Primary" | "Secondary";
}

export interface CveReference {
  readonly url: string;
  readonly tags: readonly string[];
}

export interface CveRecord {
  readonly id: string;
  readonly description: string;
  readonly published: string;
  readonly lastModified: string;
  readonly status: string;
  /** One metric per CVSS version (Primary preferred), newest version first. */
  readonly cvss: readonly CvssMetric[];
  readonly cwes: readonly string[];
  readonly references: readonly CveReference[];
}

export interface CveSearchResult {
  readonly totalResults: number;
  readonly records: readonly CveRecord[];
}

export interface EpssScore {
  readonly cve: string;
  /** Probability (0-1) of exploitation activity in the next 30 days. */
  readonly epss: number;
  /** Rank of this score among all scored CVEs (0-1). */
  readonly percentile: number;
  readonly date: string;
}

export interface KevEntry {
  readonly cveId: string;
  readonly vendorProject: string;
  readonly product: string;
  readonly vulnerabilityName: string;
  readonly dateAdded: string;
  readonly shortDescription: string;
  readonly requiredAction: string;
  readonly dueDate: string;
  readonly knownRansomwareCampaignUse: string;
  readonly notes: string;
}

export interface KevCatalog {
  readonly catalogVersion: string;
  readonly dateReleased: string;
  readonly count: number;
  readonly entries: ReadonlyMap<string, KevEntry>;
}
