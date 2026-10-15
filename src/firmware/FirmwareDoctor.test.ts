import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { expect, it, vi } from "vitest";
import {
  ProviderProcessSupervisor,
  type ProviderProcessSnapshot,
} from "../process/ProviderProcess.js";
import { OwnedCommandFailure } from "../process/OwnedCommand.js";
import type { FirmwareDoctorHost } from "./FirmwareDoctor.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { runDoctor } from "../application/Doctor.js";
import { createDoctorHostFixture } from "../application/Doctor.fixture.js";
import { FirmwareDoctor } from "./FirmwareDoctor.js";

const HEADER =
  "The following executables found installed, which are needed by unblob:";

it("reports unsupported firmware hosts without launching configured tools", async () => {
  const doctor = new FirmwareDoctor(
    { REA_BINWALK_COMMAND: "/not/launched" },
    "darwin",
  );
  const inspections = await doctor.inspect();
  expect(inspections).toHaveLength(2);
  for (const inspection of inspections) {
    expect(inspection.available).toBe(false);
    expect(inspection.checks).toContainEqual(
      expect.objectContaining({
        name: "platform",
        ok: false,
        classification: "unsupported_host",
      }),
    );
    expect(inspection.checks.some(({ name }) => name === "version")).toBe(
      false,
    );
  }
  expect(await doctor.close()).toBeUndefined();
});

const linuxIt = it.skipIf(process.platform !== "linux");

linuxIt(
  "exposes configured firmware readiness independently of absent native engines",
  async () => {
    const { doctor } = await fixture();
    const inspections = await doctor.inspect();
    expect(
      inspections.map(({ id, available, providerVersion }) => ({
        id,
        available,
        providerVersion,
      })),
    ).toEqual([
      { id: "binwalk", available: true, providerVersion: "3.1.0" },
      { id: "unblob", available: true, providerVersion: "26.6.4" },
    ]);
    expect(
      inspections.every(
        ({ registrationEnvironment }) =>
          Object.keys(registrationEnvironment).length === 0,
      ),
    ).toBe(true);
    const report = await runDoctor(
      undefined,
      createDoctorHostFixture({
        executable: () => Promise.resolve(false),
        providerInspections: () => Promise.resolve(inspections),
      }),
      { providers: ["binwalk", "unblob"] },
    );
    expect(report.healthy).toBe(true);
    expect(
      report.scope_checks.some(({ name }) => name.startsWith("hopper")),
    ).toBe(false);
    expect(report.informational_checks).toContainEqual(
      expect.objectContaining({ name: "hopper", ok: false }),
    );
    expect(await doctor.close()).toBeUndefined();
  },
);

linuxIt(
  "treats absent firmware tools as optional and names their settings",
  async () => {
    const doctor = new FirmwareDoctor({ PATH: process.env.PATH });
    const inspections = await doctor.inspect();
    expect(
      inspections.every(
        ({ configured, available }) => !configured && !available,
      ),
    ).toBe(true);
    expect(inspections[0]?.checks).toContainEqual(
      expect.objectContaining({
        name: "configuration",
        classification: "missing_analysis_engine",
        remediation: expect.stringContaining("REA_BINWALK_COMMAND"),
      }),
    );
    const report = await runDoctor(
      undefined,
      createDoctorHostFixture({
        providerInspections: () => Promise.resolve(inspections),
      }),
    );
    expect(report.healthy).toBe(true);
    expect(await doctor.close()).toBeUndefined();
  },
);

linuxIt.each(["relative", "directory", "not-executable", "missing"])(
  "rejects %s engine paths while preserving a healthy peer",
  async (kind) => {
    const { environment, root, host } = await fixture();
    let path = join(root, kind);
    if (kind === "relative") path = "binwalk";
    if (kind === "directory") await mkdir(path);
    if (kind === "not-executable")
      await writeFile(path, "not executable", { mode: 0o600 });
    const doctor = new FirmwareDoctor(
      {
        ...environment,
        REA_BINWALK_COMMAND: path,
      },
      "linux",
      host,
    );
    const [binwalk, unblob] = await doctor.inspect();
    expect(binwalk).toMatchObject({ configured: true, available: false });
    expect(binwalk?.checks).toContainEqual(
      expect.objectContaining({
        name: "configuration",
        ok: false,
        classification: "config_drift",
      }),
    );
    expect(unblob?.available).toBe(true);
    expect(await doctor.close()).toBeUndefined();
  },
);

linuxIt.each(["binwalk 3.2.0", "nonsense"])(
  "refuses an unsupported or unknown version banner: %s",
  async (banner) => {
    const { doctor } = await fixture({ binwalkBanner: banner });
    const [binwalk, unblob] = await doctor.inspect();
    expect(binwalk).toMatchObject({
      available: false,
      providerVersion: null,
    });
    expect(binwalk?.checks).toContainEqual(
      expect.objectContaining({ name: "version", ok: false }),
    );
    expect(unblob?.available).toBe(true);
    expect(await doctor.close()).toBeUndefined();
  },
);

linuxIt(
  "labels compatible patch releases as accepted but unverified",
  async () => {
    const { doctor } = await fixture({ binwalkBanner: "binwalk 3.1.2" });
    const [binwalk] = await doctor.inspect();
    expect(binwalk).toMatchObject({
      available: true,
      providerVersion: "3.1.2",
    });
    expect(binwalk?.checks).toContainEqual(
      expect.objectContaining({
        name: "version",
        detail: expect.stringContaining("verified against 3.1.0"),
      }),
    );
    expect(await doctor.close()).toBeUndefined();
  },
);

linuxIt(
  "retains missing external extractors from Unblob's ordinary exit 1 report",
  async () => {
    const { doctor } = await fixture({
      dependencies: `${HEADER}\n    7z    ✓\n    sasquatch    ✗\n`,
      dependencyExit: 1,
    });
    const [binwalk, unblob] = await doctor.inspect();
    expect(binwalk?.available).toBe(true);
    expect(unblob).toMatchObject({
      available: false,
      providerVersion: "26.6.4",
    });
    expect(unblob?.checks).toContainEqual(
      expect.objectContaining({
        name: "external-dependencies",
        classification: "missing_dependency",
        details: { installed: ["7z"], missing: ["sasquatch"] },
      }),
    );
    expect(await doctor.close()).toBeUndefined();
  },
);

linuxIt.each([
  ["unexpected output", 0],
  [`${HEADER}\n`, 0],
  [`${HEADER}\n    7z    ✓\n    7z    ✓\n`, 0],
  [`${HEADER}\n    7z    ✗\n`, 0],
  [`${HEADER}\n    7z    ✓\n`, 1],
  [`${HEADER}\n    7z    ✓\n`, 2],
])(
  "preserves unknown dependency output or inconsistent exit %s/%s",
  async (dependencies, dependencyExit) => {
    const { doctor } = await fixture({ dependencies, dependencyExit });
    const [, unblob] = await doctor.inspect();
    expect(unblob?.available).toBe(false);
    expect(unblob?.checks).toContainEqual(
      expect.objectContaining({
        name: "external-dependencies",
        classification: "unknown",
        ok: false,
      }),
    );
    expect(await doctor.close()).toBeUndefined();
  },
);

linuxIt(
  "reports missing ps before launching any selected provider",
  async () => {
    const { environment, root } = await fixture();
    const doctor = new FirmwareDoctor({ ...environment, PATH: root });
    const inspections = await doctor.inspect();
    for (const inspection of inspections) {
      expect(inspection.available).toBe(false);
      expect(inspection.checks).toContainEqual(
        expect.objectContaining({
          name: "ps",
          ok: false,
          detail: expect.stringContaining("procps-compatible ps"),
        }),
      );
      expect(inspection.checks.some(({ name }) => name === "version")).toBe(
        false,
      );
    }
    expect(await doctor.close()).toBeUndefined();
  },
);

linuxIt(
  "rejects a non-util-linux limiter without probing engines",
  async () => {
    const { environment, root, host } = await fixture();
    const limiter = join(root, "other-prlimit");
    await executable(limiter, "printf 'not util-linux\\n'\n");
    const doctor = new FirmwareDoctor(
      {
        ...environment,
        REA_FIRMWARE_PRLIMIT_COMMAND: limiter,
      },
      "linux",
      { ...host, runCommand: async () => snapshot("not util-linux", 0) },
    );
    const inspections = await doctor.inspect();
    expect(inspections.every(({ available }) => !available)).toBe(true);
    expect(inspections[0]?.checks).toContainEqual(
      expect.objectContaining({ name: "prlimit", ok: false }),
    );
    expect(inspections[0]?.checks.some(({ name }) => name === "version")).toBe(
      false,
    );
    expect(await doctor.close()).toBeUndefined();
  },
);

linuxIt.each(["timeout", "output-limit", "process"] as const)(
  "reports a %s probe failure without aborting the peer inspection",
  async (reason) => {
    const { root, environment, host } = await fixture();
    const doctor = new FirmwareDoctor(environment, "linux", {
      ...host,
      runCommand: async (spawn, limits, options) => {
        if (spawn.arguments.includes(join(root, "binwalk")))
          throw new OwnedCommandFailure(
            reason,
            `Observed ${reason}`,
            snapshot("partial banner", 1),
          );
        if (host.runCommand === undefined)
          throw new Error("Expected recording host");
        return host.runCommand(spawn, limits, options);
      },
    });
    const [binwalk, unblob] = await doctor.inspect();
    expect(binwalk?.available).toBe(false);
    expect(binwalk?.checks).toContainEqual(
      expect.objectContaining({
        name: "version",
        classification: "runtime_failure",
        detail: expect.stringContaining("partial banner"),
      }),
    );
    expect(unblob?.available).toBe(true);
    expect(await doctor.close()).toBeUndefined();
  },
);

linuxIt(
  "retains incomplete cleanup, blocks later launches and retries on close",
  async () => {
    const { environment, host } = await fixture();
    const process = Object.assign(new EventEmitter(), {
      stdout: null,
      stderr: null,
      exitCode: 0,
      signalCode: null,
      kill: () => false,
    });
    const owner = new ProviderProcessSupervisor({
      process,
      ownsProcessLifetime: false,
    });
    const stop = vi
      .spyOn(owner, "stop")
      .mockResolvedValueOnce({
        status: "incomplete",
        reason: "Fixture ownership unavailable",
      })
      .mockResolvedValue({ status: "verified-cleanup" });
    const run = vi.fn<NonNullable<FirmwareDoctorHost["runCommand"]>>(
      async (_spawn, _limits, options) => {
        options?.retainCleanup?.(owner, {
          status: "incomplete",
          reason: "Fixture ownership unavailable",
        });
        throw new OwnedCommandFailure("process", "Fixture cleanup incomplete");
      },
    );
    const doctor = new FirmwareDoctor(environment, "linux", {
      ...host,
      runCommand: run,
    });
    try {
      const inspections = await doctor.inspect();
      expect(inspections.every(({ available }) => !available)).toBe(true);
      expect(run).toHaveBeenCalledTimes(1);
      expect(await doctor.close()).toContain("Fixture ownership unavailable");
      expect(await doctor.close()).toBeUndefined();
      expect(stop).toHaveBeenCalledTimes(2);
    } finally {
      owner.dispose();
    }
  },
);

const executable = async (path: string, body: string): Promise<void> => {
  await writeFile(path, `#!/bin/sh\n${body}`);
  await chmod(path, 0o700);
};

const fixture = async (
  options: {
    binwalkBanner?: string;
    dependencies?: string;
    dependencyExit?: number;
  } = {},
) => {
  const root = await createTestTempDirectory("rea-firmware-doctor-");
  const binwalk = join(root, "binwalk");
  const unblob = join(root, "unblob");
  // File admission is real; the recording host below supplies tool observations.
  await executable(binwalk, "exit 9\n");
  await executable(unblob, "exit 9\n");
  const environment = {
    PATH: process.env.PATH,
    REA_BINWALK_COMMAND: binwalk,
    REA_UNBLOB_COMMAND: unblob,
  };
  const host: FirmwareDoctorHost = {
    prepareOwnership: async () => {},
    runCommand: vi.fn(async (spawn, limits) => {
      expect(limits.timeoutMs).toBe(5000);
      expect(limits.diagnosticBytes).toBe(64 * 1024);
      if (spawn.arguments.length === 1 && spawn.arguments[0] === "--version")
        return snapshot("prlimit from util-linux 2.39.3\n", 0);
      expect(spawn.arguments.slice(0, 5)).toEqual([
        "--as=1073741824",
        "--fsize=0",
        "--core=0",
        "--cpu=5",
        "--",
      ]);
      if (spawn.arguments[5] === binwalk)
        return snapshot(options.binwalkBanner ?? "binwalk 3.1.0", 0);
      expect(spawn.arguments[5]).toBe(unblob);
      return spawn.arguments[6] === "--version"
        ? snapshot("26.6.4", 0)
        : snapshot(
            options.dependencies ?? `${HEADER}\n    7z    ✓\n`,
            options.dependencyExit ?? 0,
          );
    }),
  };
  return {
    root,
    environment,
    host,
    doctor: new FirmwareDoctor(environment, "linux", host),
  };
};

const snapshot = (text: string, exitCode: number): ProviderProcessSnapshot => ({
  stdout: {
    text,
    bytes: Buffer.byteLength(text),
    observedBytes: Buffer.byteLength(text),
  },
  stderr: { text: "", bytes: 0, observedBytes: 0 },
  exitCode,
  signal: null,
});
