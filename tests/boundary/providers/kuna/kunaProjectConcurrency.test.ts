import { createHash } from "node:crypto";
import { appendFileSync } from "node:fs";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, expect, it as test, onTestFinished, vi } from "vitest";

import { inspectKunaInstallation } from "../../../../src/kuna/KunaInstallation.js";
import { KunaProjectCache } from "../../../../src/kuna/KunaProjectCache.js";
import type { KunaExportStatus } from "../../../../src/kuna/KunaProjectExport.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { fakeKunaCalls, writeFakeKuna } from "./fakeKuna.js";

// Reproduce concurrent eviction's shared directory snapshot while retaining
// real exports, publication, hashing and file removal underneath it.
const listing = vi.hoisted(() => ({
  directory: "",
  names: [] as string[],
  gate: undefined as Promise<void> | undefined,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    readdir: async (...args: Parameters<typeof actual.readdir>) => {
      if (String(args[0]) === listing.directory && listing.gate !== undefined) {
        await listing.gate;
        return listing.names;
      }
      return actual.readdir(...args);
    },
  };
});

afterEach(() => {
  listing.directory = "";
  listing.gate = undefined;
  listing.names = [];
});

const it = test.skipIf(process.platform === "win32");

const fixture = async (maxBytes = 64 * 1024 ** 2) => {
  const root = await createTestTempDirectory("rea-kuna-concurrency-");
  const kuna = await writeFakeKuna(root, {
    delayMs: 300,
    asmPadding: 400 * 1024,
  });
  const inspected = await inspectKunaInstallation({
    REA_KUNA_COMMAND: kuna,
    REA_KUNA_CACHE_DIR: join(root, "cache"),
  });
  if (!inspected.ok) throw new Error(inspected.error.reason);
  const installation = inspected.value;
  const cache = new KunaProjectCache(installation.configuration.cacheRoot, {
    maxBytes,
  });
  const request = async (name: string) => {
    const targetPath = join(root, name);
    await writeFile(targetPath, name);
    return {
      installation,
      targetPath,
      targetSha256: createHash("sha256").update(name).digest("hex"),
    };
  };
  return {
    kuna,
    cache,
    request,
    cacheRoot: installation.configuration.cacheRoot,
  };
};

it.each([true, false])(
  "preserves concurrent results and reclaims capacity (pin: %s)",
  async (pin) => {
    const { cache, request, cacheRoot } = await fixture(600 * 1024);
    const actual =
      await vi.importActual<typeof import("node:fs/promises")>(
        "node:fs/promises",
      );
    let releaseListing = () => {};
    const gate = new Promise<void>((resolve) => {
      releaseListing = resolve;
    });
    listing.directory = join(cacheRoot, "projects");
    listing.gate = gate;
    const releases: (() => void)[] = [];
    const inputs = await Promise.all([request("first"), request("second")]);
    const builds = inputs.map(async (input) => {
      const result = await cache.build(input);
      if (!result.ok) throw result.error;
      if (pin) releases.push(cache.pin(result.value.key));
      return result.value;
    });
    onTestFinished(async () => {
      releaseListing();
      await Promise.allSettled(builds);
      for (const release of releases) release();
      const closed = await cache.close();
      if (!closed.ok) throw closed.error;
    });
    await expect
      .poll(() => actual.readdir(listing.directory).catch(() => []))
      .toHaveLength(2);
    listing.names = await actual.readdir(listing.directory);
    releaseListing();
    const projects = await Promise.all(builds);
    if (!pin) {
      expect(await cache.close()).toEqual({ ok: true, value: null });
      expect(await actual.readdir(listing.directory)).toHaveLength(1);
      return;
    }
    for (const project of projects) {
      expect(
        await readFile(
          join(project.directory, project.manifest.files.c.path),
          "utf8",
        ),
      ).toContain("// Function: main @ 0x1000");
    }
  },
);

it.each(["decompiling", "sealing"] as const)(
  "rejects an executable changed during %s",
  async (phase) => {
    const { kuna, cache, request, cacheRoot } = await fixture();
    const input = await request("program");
    const result = await cache.build({
      ...input,
      onStatus: (status) => {
        if (status.phase === phase)
          appendFileSync(kuna, "\n// installation replaced\n");
      },
    });
    expect(result).toMatchObject({
      ok: false,
      error: {
        diagnostics: {
          expected_sha256: input.installation.sha256,
          observed_sha256: expect.any(String),
        },
      },
    });
    expect(await readdir(join(cacheRoot, "projects"))).toEqual([]);
    expect(await cache.close()).toEqual({ ok: true, value: null });
  },
);

it("keeps a shared progress callback registered for the remaining waiter", async () => {
  const { kuna, cache, request } = await fixture();
  const input = await request("program");
  const controller = new AbortController();
  const statuses: KunaExportStatus[] = [];
  const onStatus = (status: KunaExportStatus) => {
    statuses.push(status);
    if (status.phase === "decompiling") controller.abort();
  };
  const first = cache.build({ ...input, signal: controller.signal, onStatus });
  const second = cache.build({ ...input, onStatus });
  expect(await first).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
  const result = await second;
  if (!result.ok) throw result.error;
  expect(statuses.map(({ phase }) => phase)).toContain("sealing");
  expect(
    (await fakeKunaCalls(kuna)).filter(
      ({ argv }) => argv[0] === "decompile-project",
    ),
  ).toHaveLength(1);
  expect(await cache.close()).toEqual({ ok: true, value: null });
});
