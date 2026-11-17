import type { EpssClient } from "../sources/epss.js";
import type { KevClient } from "../sources/kev.js";
import type { NvdClient } from "../sources/nvd.js";

export interface ToolDeps {
  readonly nvd: NvdClient;
  readonly epss: EpssClient;
  readonly kev: KevClient;
}

export const READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;
