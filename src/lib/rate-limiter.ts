import type { Clock } from "./cache.js";
import { defaultSleep, type Sleep } from "./http.js";

/**
 * Sliding-window limiter: at most `limit` acquisitions per `windowMs`.
 * Calls are serialized so concurrent callers queue fairly instead of bursting.
 */
export class SlidingWindowLimiter {
  private timestamps: readonly number[] = [];
  private queue: Promise<void> = Promise.resolve();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly now: Clock = Date.now,
    private readonly sleep: Sleep = defaultSleep,
  ) {}

  acquire(): Promise<void> {
    const next = this.queue.then(() => this.waitForSlot());
    this.queue = next.catch(() => undefined);
    return next;
  }

  private async waitForSlot(): Promise<void> {
    for (;;) {
      const now = this.now();
      this.timestamps = this.timestamps.filter((t) => now - t < this.windowMs);
      if (this.timestamps.length < this.limit) {
        this.timestamps = [...this.timestamps, now];
        return;
      }
      const oldest = this.timestamps[0] ?? now;
      await this.sleep(this.windowMs - (now - oldest) + 50);
    }
  }
}
