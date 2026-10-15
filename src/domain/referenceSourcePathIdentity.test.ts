import { expect, it, vi } from "vitest";
import { createReferenceSourcePathLookup } from "./referenceSourcePathIdentity.js";

it("terminates ancestor lookup at relative and absolute fixed points", () => {
  const lookup = createReferenceSourcePathLookup(["dist"]);
  for (const path of ["..", "../..", ".", "/", ""]) {
    expect(lookup.resolvePrefixes(path)).toEqual([]);
  }
  expect(lookup.resolvePrefixes("dist/nested/file.js")).toEqual(["dist"]);
  expect(lookup.resolvePrefixes("dist-other/file.js")).toEqual([]);
});

it("normalizes a deep ancestor query at most once", () => {
  const lookup = createReferenceSourcePathLookup(["dist"]);
  const path = `dist/${Array.from({ length: 128 }, (_, i) => `part${i}`).join("/")}`;
  const normalize = vi.spyOn(String.prototype, "normalize");
  let result: readonly string[] | undefined;
  let calls: number;
  try {
    result = lookup.resolvePrefixes(path);
    calls = normalize.mock.calls.length;
  } finally {
    normalize.mockRestore();
  }
  expect(result).toEqual(["dist"]);
  expect(calls).toBeLessThanOrEqual(1);
});

it("preserves exact spelling and ambiguity at the nearest recorded ancestor", () => {
  const lookup = createReferenceSourcePathLookup([
    "outer",
    "outer/Å",
    "outer/A\u030a",
  ]);
  expect(lookup.resolvePrefixes("outer/A\u030a/child")).toEqual([
    "outer",
    "outer/A\u030a",
  ]);
  expect(lookup.resolvePrefixes("outer/\u212b/child")).toBeUndefined();
});
