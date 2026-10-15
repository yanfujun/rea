import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { CdpCaptureCompleteness } from "./CdpCaptureCompleteness.js";
import type { CdpConnection } from "./CdpConnection.js";
import type { CdpEndpointTarget } from "./CdpEndpoint.js";
import { CdpCaptureEvents } from "./CdpCaptureEvents.js";
import { captureWorkers } from "./CdpPageCaptureWorkers.js";
import { captureElectronWorkers } from "./CdpElectronWorkers.js";
import { inspectWebPageInputSchema } from "../domain/browserObservation.js";

const temporary: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporary
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

/** A connection that answers `Target.getTargets` with one fixed payload. */
const targetInventoryConnection = (payload: unknown): CdpConnection =>
  ({
    async send() {
      return payload;
    },
  }) as unknown as CdpConnection;

const endpointTarget = (id: string): CdpEndpointTarget =>
  ({ id }) as unknown as CdpEndpointTarget;

describe("web worker target inventory", () => {
  const origin = "http://127.0.0.1:43127";
  const events = () =>
    new CdpCaptureEvents(
      inspectWebPageInputSchema.parse({
        cdp_endpoint: origin,
        allowed_origins: [origin],
        target_id: "allowed-page",
      }),
      new Set([origin]),
    );

  const context = (payload: unknown) => ({
    connection: targetInventoryConnection(payload),
    sessionId: undefined,
    target: endpointTarget("target-page"),
  });
  it("retains one authorized worker beside a worker that is out of scope", async () => {
    const browser = events();
    const workers = await captureWorkers(
      {
        context: context({
          targetInfos: [
            {
              targetId: "worker-1",
              type: "service_worker",
              url: `${origin}/worker.js`,
              attached: true,
              openerId: "target-page",
            },
            {
              targetId: "worker-2",
              type: "service_worker",
              url: `${origin}/other.js`,
              attached: true,
              openerId: "target-other",
              parentFrameId: "frame-other",
            },
          ],
        }) as never,
        allowedOrigins: new Set([origin]),
        limitations: [],
        events: browser,
      },
      new Set<string>(),
    );

    expect(workers.map((worker) => worker.target_id)).toEqual(["worker-1"]);
    expect(browser.completeness.snapshot()).toMatchObject({
      unavailable_sections: [],
    });
  });

  it("reports a missing target inventory as unavailable rather than no workers", async () => {
    const browser = events();
    const workers = await captureWorkers(
      {
        context: context({ targetInfos: undefined }) as never,
        allowedOrigins: new Set([origin]),
        limitations: [],
        events: browser,
      },
      new Set<string>(),
    );

    expect(workers).toEqual([]);
    expect(browser.completeness.snapshot()).toMatchObject({
      unavailable_sections: ["workers"],
      excluded: [
        { section: "workers", reason: "provider_unavailable", count: null },
      ],
    });
    expect(browser.completeness.snapshot().conditions).toContain(
      "attach_limited",
    );
  });

  it("reports a non-array target inventory as unavailable", async () => {
    const browser = events();
    const workers = await captureWorkers(
      {
        context: context({ targetInfos: "not-an-array" }) as never,
        allowedOrigins: new Set([origin]),
        limitations: [],
        events: browser,
      },
      new Set<string>(),
    );

    expect(workers).toEqual([]);
    expect(browser.completeness.snapshot().unavailable_sections).toContain(
      "workers",
    );
  });

  it("counts each malformed target entry instead of dropping it silently", async () => {
    const browser = events();
    const workers = await captureWorkers(
      {
        context: context({
          targetInfos: [
            null,
            {
              targetId: "worker-1",
              type: "service_worker",
              url: `${origin}/worker.js`,
              attached: true,
              openerId: "target-page",
            },
            "not-a-record",
          ],
        }) as never,
        allowedOrigins: new Set([origin]),
        limitations: [],
        events: browser,
      },
      new Set<string>(),
    );

    expect(workers.map((worker) => worker.target_id)).toEqual(["worker-1"]);
    expect(browser.completeness.snapshot().excluded).toContainEqual({
      section: "workers",
      reason: "invalid_protocol_value",
      count: 2,
    });
  });
});

describe("Electron worker target inventory", () => {
  const root = async (): Promise<string> => {
    const created = await mkdtemp(join(tmpdir(), "rea-electron-worker-"));
    temporary.push(created);
    return created;
  };

  const electronInput = () => ({
    connection: undefined as never,
    target: endpointTarget("target-page"),
    request: {} as never,
    frameIds: new Set<string>(),
    completeness: new CdpCaptureCompleteness(),
    limitations: [],
  });

  it("retains one local worker beside an out-of-scope one", async () => {
    const directory = await root();
    await writeFile(join(directory, "worker.js"), "worker");
    const completeness = new CdpCaptureCompleteness();

    const workers = await captureElectronWorkers({
      ...electronInput(),
      connection: targetInventoryConnection({
        targetInfos: [
          {
            targetId: "worker-1",
            type: "service_worker",
            url: pathToFileURL(join(directory, "worker.js")).href,
            attached: true,
            openerId: "target-page",
          },
          {
            targetId: "worker-2",
            type: "service_worker",
            url: pathToFileURL(join(directory, "worker.js")).href,
            attached: true,
            openerId: "target-other",
            parentFrameId: "frame-other",
          },
        ],
      }),
      completeness,
    });

    expect(workers.map((worker) => worker.target_id)).toEqual(["worker-1"]);
    expect(completeness.snapshot()).toMatchObject({
      unavailable_sections: [],
    });
  });

  it("reports a missing target inventory as unavailable rather than no workers", async () => {
    const completeness = new CdpCaptureCompleteness();

    const workers = await captureElectronWorkers({
      ...electronInput(),
      connection: targetInventoryConnection({ targetInfos: undefined }),
      completeness,
    });

    expect(workers).toEqual([]);
    expect(completeness.snapshot()).toMatchObject({
      unavailable_sections: ["workers"],
      excluded: [
        { section: "workers", reason: "provider_unavailable", count: null },
      ],
    });
  });

  it("counts each malformed target entry instead of dropping it silently", async () => {
    const directory = await root();
    await writeFile(join(directory, "worker.js"), "worker");
    const completeness = new CdpCaptureCompleteness();

    const workers = await captureElectronWorkers({
      ...electronInput(),
      connection: targetInventoryConnection({
        targetInfos: [
          null,
          {
            targetId: "worker-1",
            type: "service_worker",
            url: pathToFileURL(join(directory, "worker.js")).href,
            attached: true,
            openerId: "target-page",
          },
          "not-a-record",
        ],
      }),
      completeness,
    });

    expect(workers.map((worker) => worker.target_id)).toEqual(["worker-1"]);
    expect(completeness.snapshot().excluded).toContainEqual({
      section: "workers",
      reason: "invalid_protocol_value",
      count: 2,
    });
  });
});
