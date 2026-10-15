import { afterEach, describe, expect, it, vi } from "vitest";

import {
  admitRecords,
  admittedRecords,
  delayWithCancellation,
} from "./CdpCaptureValues.js";

describe("cancellable browser observation delays", () => {
  afterEach(() => vi.useRealTimers());

  it("schedules durations beyond the native timer range in consecutive waits", async () => {
    vi.useFakeTimers();
    let completed = false;
    const waiting = delayWithCancellation(
      2_147_483_648,
      "observe_javascript_runtime",
    ).then(() => {
      completed = true;
    });

    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(2_147_483_647);
    expect(completed).toBe(false);
    expect(vi.getTimerCount()).toBe(1);

    await vi.advanceTimersByTimeAsync(1);
    await waiting;
    expect(completed).toBe(true);
  });
});

describe("producer array admission", () => {
  it("keeps an absent field distinct from a present empty array", () => {
    expect(admitRecords(undefined)).toBeUndefined();
    expect(admitRecords([])).toEqual([]);
    expect(admitRecords("not-an-array")).toBeUndefined();
    expect(admitRecords(null)).toBeUndefined();
  });

  it("retains every present entry so the caller can account for malformed ones", () => {
    const present = [null, { id: "kept" }, "malformed"];
    expect(admitRecords(present)).toEqual(present);
    expect(admitRecords(present)).toHaveLength(3);
  });

  it("filters admitted entries to records for callers that need no ledger", () => {
    expect(admittedRecords([null, { id: "kept" }, "malformed"])).toEqual([
      { id: "kept" },
    ]);
    expect(admittedRecords(undefined)).toEqual([]);
    expect(admittedRecords([1, 2])).toEqual([]);
  });
});
