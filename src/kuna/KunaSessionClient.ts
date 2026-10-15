import { createReadStream } from "node:fs";
import { open } from "node:fs/promises";
import { basename, join } from "node:path";

import { z } from "zod";

import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisExecution,
  type AnalysisOperation,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import {
  analysisSearchPredicate,
  analysisSearchQuerySchema,
} from "../domain/analysisSearch.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { EvidenceLocation } from "../domain/evidence.js";
import { functionDossierSchema } from "../domain/hopperValues.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import { prepareProcessOwnershipInspection } from "../process/ProcessOwnershipObservation.js";
import type { ProviderProcessSupervisor } from "../process/ProviderProcess.js";
import {
  copyAndHash,
  KUNA_INVENTORY_OUTPUT_BYTES,
  runKunaCommand,
  type KunaProcessLauncher,
} from "./KunaCommand.js";
import {
  inspectKunaInstallation,
  type KunaInstallation,
} from "./KunaInstallation.js";
import {
  kunaProjectKey,
  type KunaProject,
  type KunaProjectCache,
} from "./KunaProjectCache.js";
import type { KunaExportStatus } from "./KunaProjectExport.js";
import {
  parseKunaInventory,
  scanKunaAssembly,
  type KunaAssemblyIndex,
  type KunaInventoryFunction,
  type KunaProjectFunction,
} from "./KunaProjectFiles.js";
import {
  isKunaOperation,
  KUNA_SINGLE_FUNCTION_LIMITATION,
  kunaLimitations,
  type KunaOperation,
} from "./KunaProviderCapabilities.js";
import { KUNA_PROVIDER_ID } from "./KunaRelease.js";

/** One function's pseudocode is far below this; sqlite3VdbeExec is 240 KB. */
const PSEUDOCODE_OUTPUT_BYTES = 16 * 1024 * 1024;

/** How often a request waiting on the project export reports that it still waits. */
const WAIT_PROGRESS_INTERVAL_MS = 10_000;

const HEX_ADDRESS = /^0x[0-9a-f]+$/iu;

/** Where one answer's text came from, recorded in its raw result. */
type AnswerSource =
  | { readonly kind: "project-export"; readonly project: KunaProject }
  | { readonly kind: "single-function" };

interface InventoryIndex {
  readonly inventory: readonly KunaInventoryFunction[];
  readonly byAddress: ReadonlyMap<string, KunaInventoryFunction>;
  readonly byName: ReadonlyMap<string, readonly KunaInventoryFunction[]>;
}

interface Answer {
  readonly result: JsonValue;
  readonly source: AnswerSource | null;
  readonly file?: {
    readonly path: string;
    readonly byteOffset: number;
    readonly byteLength: number;
  };
  readonly locations: readonly EvidenceLocation[];
  readonly limitations: readonly string[];
}

/**
 * Wait for work this session owns, stopping only this caller's wait when its
 * signal aborts; the work itself continues for other callers.
 */
const waitFor = <T>(
  work: Promise<Result<T, AnalysisError>>,
  signal: AbortSignal | undefined,
  operation: string,
): Promise<Result<T, AnalysisError>> => {
  if (signal === undefined) return work;
  if (signal.aborted)
    return Promise.resolve(err(new AnalysisCancelledError(operation)));
  return new Promise((resolve) => {
    const onAbort = () => resolve(err(new AnalysisCancelledError(operation)));
    signal.addEventListener("abort", onAbort, { once: true });
    void work.then((result) => {
      signal.removeEventListener("abort", onAbort);
      resolve(result);
    });
  });
};

/** A file the adopted export named is gone, e.g. evicted by another REA process. */
const isMissing = (cause: unknown): boolean =>
  cause instanceof Error &&
  "code" in cause &&
  (cause.code === "ENOENT" || cause.code === "ENOTDIR");

/** Read through a call so a check before an await does not narrow later ones. */
const cancelled = (signal: AbortSignal | undefined): boolean =>
  signal?.aborted === true;

const message = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

const failure = (operation: string, cause: unknown): AnalysisError =>
  cause instanceof AnalysisError
    ? cause
    : new ProviderAdapterError(KUNA_PROVIDER_ID, operation, {
        cause,
        userMessage: `Kuna ${operation} failed: ${message(cause)}`,
      });

/** Read exactly one recorded span of a project file. */
const readSpan = async (
  path: string,
  offset: number,
  length: number,
): Promise<string> => {
  const handle = await open(path, "r");
  try {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, offset);
    if (bytesRead !== length)
      throw new Error(`${path} is shorter than its recorded span`);
    return buffer.toString("utf8");
  } finally {
    await handle.close();
  }
};

/** A `.c` block without its `// Function:` header and trailing separator. */
const blockCode = (block: string): string =>
  block.slice(block.indexOf("\n") + 1).replace(/\n+$/u, "");

/** Kuna names a procedure by its inventory entry or by an exact entry address. */
const procedureSelectorSchema = z.string().min(1);

/**
 * One Kuna analysis session for one target.
 *
 * Reads come from the verified project export in REA's cache. Until that
 * export exists, listings use a quick `kuna functions` inventory and
 * pseudocode a single-function `kuna decompile`, while the export builds in
 * the background; assembly waits for it. Kuna always runs on a private copy
 * whose digest matches the selected target.
 */
export class KunaSessionClient implements AnalysisClient {
  readonly #target: BinaryTarget;
  readonly #profile: AnalysisProfileCommitment | undefined;
  readonly #cache: KunaProjectCache;
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #launcher: KunaProcessLauncher | undefined;
  /** Owns background work: aborting it cancels this session's export interest. */
  readonly #session = new AbortController();
  /** Single-function runs that could not be proven stopped, with their retry owners. */
  readonly #retained: {
    readonly error: ProviderCleanupError;
    owner: ProviderProcessSupervisor | undefined;
  }[] = [];
  /** Private roots whose removal failed during setup or close. */
  readonly #leakedRoots: PrivateRuntimeRoot[] = [];
  #installation: Promise<Result<KunaInstallation, AnalysisError>> | undefined;
  #workspace:
    | Promise<
        Result<
          { readonly root: PrivateRuntimeRoot; readonly input: string },
          AnalysisError
        >
      >
    | undefined;
  #inventory:
    | Promise<Result<readonly KunaInventoryFunction[], AnalysisError>>
    | undefined;
  #project: Promise<Result<KunaProject, AnalysisError>> | undefined;
  #ready: KunaProject | undefined;
  #blocks: ReadonlyMap<string, KunaProjectFunction> | undefined;
  #assembly: Promise<Result<KunaAssemblyIndex, AnalysisError>> | undefined;
  #inventoryIndex: InventoryIndex | undefined;
  #status: KunaExportStatus | undefined;
  #key: string | undefined;
  #exportFailure: string | undefined;
  #releasePin: (() => void) | undefined;
  /** Set once close starts; new requests are refused from then on. */
  #closing = false;
  /** Set only when close has released every owned resource. */
  #closed = false;

  constructor(
    target: BinaryTarget,
    profile: AnalysisProfileCommitment | undefined,
    dependencies: {
      readonly cache: KunaProjectCache;
      readonly environment: Readonly<NodeJS.ProcessEnv>;
      readonly launcher?: KunaProcessLauncher;
    },
  ) {
    this.#target = target;
    this.#profile = profile;
    this.#cache = dependencies.cache;
    this.#environment = dependencies.environment;
    this.#launcher = dependencies.launcher;
  }

  async execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions = {},
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (this.#closing)
      return err(
        new AnalysisCapabilityUnavailableError(
          KUNA_PROVIDER_ID,
          operation,
          "This Kuna session is closed.",
        ),
      );
    if (cancelled(options.signal))
      return err(new AnalysisCancelledError(operation));
    if (operation !== "health" && !isKunaOperation(operation))
      return err(
        new AnalysisCapabilityUnavailableError(
          KUNA_PROVIDER_ID,
          operation,
          "Kuna answers procedure listings, lookups, pseudocode and assembly; this operation needs another provider.",
        ),
      );
    const document = parameters.document;
    if (document !== undefined && document !== this.#target.path)
      return err(
        new AnalysisInputError(
          operation,
          {
            userMessage:
              "A Kuna session analyzes one program; omit document or pass the selected target path.",
          },
          [
            {
              path: ["document"],
              reason: "invalid_value",
              expected: this.#target.path,
            },
          ],
        ),
      );
    const installation = await this.#ensureInstallation();
    if (!installation.ok) return installation;
    try {
      if (operation === "health")
        return ok(
          this.#execution([], installation.value, {
            result: {
              ready: true,
              kuna: {
                version: installation.value.version,
                verified: installation.value.verified,
                sha256: installation.value.sha256,
              },
            },
            source: null,
            locations: [],
            limitations: [],
          }),
        );
      await this.#startProject(installation.value);
      const answer = await this.#answer(
        operation,
        parameters,
        installation.value,
        options,
      );
      if (!answer.ok) return answer;
      if (cancelled(options.signal))
        return err(new AnalysisCancelledError(operation));
      return ok(
        this.#execution(
          kunaLimitations(operation),
          installation.value,
          answer.value,
        ),
      );
    } catch (cause: unknown) {
      if (cancelled(options.signal))
        return err(new AnalysisCancelledError(operation, { cause }));
      return err(failure(operation, cause));
    }
  }

  /**
   * Release everything this session owns. A failed close keeps reporting its
   * failure, and each later call retries the cleanup that remains.
   */
  async close(): Promise<Result<null, AnalysisError>> {
    if (this.#closed) return ok(null);
    if (!this.#closing) {
      this.#closing = true;
      this.#session.abort();
      await this.#project;
      await this.#inventory;
    }
    const failures: ProviderCleanupError[] = [];
    // Kuna runs in its own process group; an export no other session wants
    // must stop before this session reports itself closed.
    if (this.#key !== undefined) {
      const settled = await this.#cache.settled(this.#key);
      if (!settled.ok) failures.push(settled.error);
    }
    for (const retained of [...this.#retained]) {
      const stopped = await retained.owner?.stop();
      if (stopped !== undefined && stopped.status !== "incomplete")
        this.#retained.splice(this.#retained.indexOf(retained), 1);
    }
    failures.push(...this.#retained.map(({ error }) => error));
    const workspace = await this.#workspace;
    // A single-function run that may still be running keeps its copy.
    if (this.#retained.length === 0) {
      if (workspace?.ok === true) {
        this.#leakedRoots.push(workspace.value.root);
        this.#workspace = undefined;
      }
      for (const root of [...this.#leakedRoots])
        try {
          await root.close();
          this.#leakedRoots.splice(this.#leakedRoots.indexOf(root), 1);
        } catch (cause: unknown) {
          failures.push(
            new ProviderCleanupError(
              KUNA_PROVIDER_ID,
              [root.path],
              { reason: message(cause) },
              { cause },
            ),
          );
        }
    }
    if (failures.length > 0)
      return err(
        new ProviderCleanupError(
          KUNA_PROVIDER_ID,
          failures.flatMap((failed) => failed.cleanupResources),
          {
            reason: failures
              .map((failed) =>
                String(failed.diagnostics?.["reason"] ?? failed.message),
              )
              .join("; "),
          },
        ),
      );
    this.#releasePin?.();
    this.#releasePin = undefined;
    this.#closed = true;
    return ok(null);
  }

  #execution(
    operationLimitations: readonly string[],
    installation: KunaInstallation,
    answer: Answer,
  ): AnalysisExecution {
    const source = answer.source;
    return createAnalysisExecution(
      answer.result,
      {
        id: KUNA_PROVIDER_ID,
        name: "Kuna",
        version: installation.version,
      },
      {
        // Kuna's identity is in the analysis profile; the raw result records
        // only where file-backed text came from.
        ...(source === null
          ? {}
          : {
              rawResult: {
                source:
                  source.kind === "single-function"
                    ? { kind: "single-function" }
                    : {
                        kind: "project-export",
                        key: source.project.key,
                        directory: source.project.directory,
                        ...(answer.file === undefined
                          ? {}
                          : {
                              file: answer.file.path,
                              file_sha256:
                                Object.values(
                                  source.project.manifest.files,
                                ).find(({ path }) => path === answer.file?.path)
                                  ?.sha256 ?? null,
                              byte_offset: answer.file.byteOffset,
                              byte_length: answer.file.byteLength,
                            }),
                      },
                project_export: this.#exportState(),
              },
            }),
        limitations: [...operationLimitations, ...answer.limitations],
        locations: [
          { kind: "artifact-path", path: this.#target.path },
          ...answer.locations,
        ],
        ...(this.#profile === undefined
          ? {}
          : { analysisProfile: this.#profile }),
      },
    );
  }

  /** Where the background export stands, for callers deciding whether to wait. */
  #exportState(): JsonValue {
    if (this.#ready !== undefined)
      return { state: "ready", key: this.#ready.key };
    if (this.#project === undefined) return { state: "not-started" };
    if (this.#exportFailure !== undefined)
      return { state: "failed", reason: this.#exportFailure };
    return {
      state: "building",
      phase: this.#status?.phase ?? null,
      inventory_functions: this.#status?.inventoryFunctions ?? null,
    };
  }

  async #answer(
    operation: KunaOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    installation: KunaInstallation,
    options: ExecutionOptions,
  ): Promise<Result<Answer, AnalysisError>> {
    if (operation === "list_documents")
      return ok({
        result: [this.#target.path],
        source: null,
        locations: [],
        limitations: [],
      });
    const inventory = await this.#ensureInventory(installation, options);
    if (!inventory.ok) return inventory;
    if (operation === "list_procedures" || operation === "search_procedures") {
      const items = inventory.value.map(({ address, name }) => ({
        address,
        value: name,
      }));
      const matches =
        operation === "search_procedures"
          ? analysisSearchPredicate(analysisSearchQuerySchema.parse(parameters))
          : undefined;
      return ok({
        result:
          matches === undefined
            ? items
            : items.filter(({ value }) => matches(value)),
        source: null,
        locations: [],
        limitations: [],
      });
    }
    if (operation === "address_name")
      return this.#withExport(installation, () =>
        this.#addressName(parameters, inventory.value, options),
      );
    const entry = this.#resolve(operation, parameters, inventory.value);
    if (!entry.ok) return entry;
    const locations = [
      { kind: "address", address: entry.value.address } as const,
    ];
    switch (operation) {
      case "procedure_address":
        return ok({
          result: entry.value.address,
          source: null,
          locations,
          limitations: [],
        });
      case "procedure_pseudo_code": {
        const pseudocode = await this.#withExport(installation, () =>
          this.#pseudocode(operation, entry.value, installation, options),
        );
        if (!pseudocode.ok) return pseudocode;
        return ok({ ...pseudocode.value, locations });
      }
      case "procedure_assembly": {
        const assembly = await this.#withExport(installation, () =>
          this.#assemblyText(operation, entry.value, options),
        );
        if (!assembly.ok) return assembly;
        return ok({ ...assembly.value, locations });
      }
      case "analyze_function":
        return this.#withExport(installation, () =>
          this.#dossier(operation, entry.value, installation, options),
        );
    }
  }

  /** Resolve an exact inventory name, alias or entry address. */
  #resolve(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    inventory: readonly KunaInventoryFunction[],
  ): Result<KunaInventoryFunction, AnalysisError> {
    const parsed = procedureSelectorSchema.safeParse(parameters.procedure);
    if (!parsed.success)
      return err(
        new AnalysisInputError(
          operation,
          { userMessage: "procedure is required." },
          [{ path: ["procedure"], reason: "missing_argument" }],
        ),
      );
    const selector = parsed.data;
    if (HEX_ADDRESS.test(selector)) {
      const address = `0x${BigInt(selector).toString(16)}`;
      const entry = this.#index(inventory).byAddress.get(address);
      return entry === undefined
        ? err(
            new AnalysisInputError(operation, {
              userMessage: `${address} is not a procedure entry Kuna found; list_procedures shows the entries it found.`,
            }),
          )
        : ok(entry);
    }
    const matches = this.#index(inventory).byName.get(selector) ?? [];
    if (matches.length === 1 && matches[0] !== undefined) return ok(matches[0]);
    return err(
      new AnalysisInputError(operation, {
        userMessage:
          matches.length === 0
            ? `Kuna found no procedure named ${selector}; search_procedures finds similar names.`
            : `${selector} names ${String(matches.length)} Kuna entries (${matches.map(({ address }) => address).join(", ")}); select one by address.`,
      }),
    );
  }

  async #addressName(
    parameters: Readonly<Record<string, JsonValue>>,
    inventory: readonly KunaInventoryFunction[],
    options: ExecutionOptions,
  ): Promise<Result<Answer, AnalysisError>> {
    const raw = parameters.address;
    if (typeof raw !== "string" || !HEX_ADDRESS.test(raw))
      return err(
        new AnalysisInputError(
          "address_name",
          {
            userMessage:
              "Kuna has no cursor; pass an explicit 0x-prefixed address.",
          },
          [{ path: ["address"], reason: "invalid_format" }],
        ),
      );
    const address = `0x${BigInt(raw).toString(16)}`;
    const locations = [{ kind: "address", address } as const];
    const entry = this.#index(inventory).byAddress.get(address);
    if (entry !== undefined)
      return ok({
        result: entry.name,
        source: null,
        locations,
        limitations: [],
      });
    // Data names live only in the export's `.asm` data tail.
    const index = await this.#ensureAssembly("address_name", options);
    if (!index.ok) return index;
    const project = this.#ready;
    return ok({
      result: index.value.data.get(address) ?? null,
      source:
        project === undefined ? null : { kind: "project-export", project },
      locations,
      limitations: [
        "Kuna names function entries and the data its export references; null means Kuna assigned no name at this address, not that no symbol exists.",
      ],
    });
  }

  async #pseudocode(
    operation: string,
    entry: KunaInventoryFunction,
    installation: KunaInstallation,
    options: ExecutionOptions,
  ): Promise<Result<Omit<Answer, "locations">, AnalysisError>> {
    const project = this.#ready;
    if (project !== undefined) {
      const block = this.#blockOf(project, entry.address);
      if (block === undefined)
        return ok({
          result: null,
          source: { kind: "project-export", project },
          limitations: [
            "Kuna's export decompiles code entries only; this inventory entry, such as an import slot, has no body.",
          ],
        });
      if (block.error !== null)
        return ok({
          result: null,
          source: { kind: "project-export", project },
          file: {
            path: project.manifest.files.c.path,
            byteOffset: block.cOffset,
            byteLength: block.cLength,
          },
          limitations: [
            `Kuna could not decompile this function: ${block.error}`,
          ],
        });
      const text = await readSpan(
        join(project.directory, project.manifest.files.c.path),
        block.cOffset,
        block.cLength,
      );
      return ok({
        result: blockCode(text),
        source: { kind: "project-export", project },
        file: {
          path: project.manifest.files.c.path,
          byteOffset: block.cOffset,
          byteLength: block.cLength,
        },
        limitations: [],
      });
    }
    const workspace = await this.#ensureWorkspace();
    if (!workspace.ok) return workspace;
    const run = await runKunaCommand({
      installation,
      arguments: ["decompile", workspace.value.input, entry.address, "--addr"],
      workspace: workspace.value.root.path,
      operation,
      timeoutMs: installation.configuration.functionTimeoutMs,
      reportedTimeoutMs: installation.configuration.functionTimeoutMs,
      outputBytes: PSEUDOCODE_OUTPUT_BYTES,
      signal: options.signal ?? this.#session.signal,
      launcher: this.#launcher,
    });
    if (run.kind === "retained") {
      this.#retained.push({ error: run.error, owner: run.owner });
      return err(run.error);
    }
    if (run.kind === "failed") return err(run.error);
    const exportFailure = await this.#settledExportFailure();
    return ok({
      result: run.snapshot.stdout.text.replace(/\n+$/u, ""),
      source: { kind: "single-function" },
      limitations: [
        KUNA_SINGLE_FUNCTION_LIMITATION,
        ...(exportFailure === undefined
          ? []
          : [
              `The project export failed, so later requests also use single-function runs: ${exportFailure}`,
            ]),
      ],
    });
  }

  async #assemblyText(
    operation: string,
    entry: KunaInventoryFunction,
    options: ExecutionOptions,
  ): Promise<Result<Omit<Answer, "locations">, AnalysisError>> {
    const index = await this.#ensureAssembly(operation, options);
    if (!index.ok) return index;
    const project = this.#ready;
    const span = index.value.code.get(entry.address);
    if (project === undefined || span === undefined)
      return err(
        new AnalysisCapabilityUnavailableError(
          KUNA_PROVIDER_ID,
          operation,
          `Kuna's export lists no code at ${entry.address}; import slots and data entries have no listing.`,
        ),
      );
    const text = await readSpan(
      join(project.directory, project.manifest.files.asm.path),
      span.offset,
      span.length,
    );
    return ok({
      result: text.replace(/\n+$/u, ""),
      source: { kind: "project-export", project },
      file: {
        path: project.manifest.files.asm.path,
        byteOffset: span.offset,
        byteLength: span.length,
      },
      limitations: [],
    });
  }

  async #dossier(
    operation: string,
    entry: KunaInventoryFunction,
    installation: KunaInstallation,
    options: ExecutionOptions,
  ): Promise<Result<Answer, AnalysisError>> {
    // The dossier pairs pseudocode and assembly from one export.
    const assembly = await this.#assemblyText(operation, entry, options);
    if (!assembly.ok) return assembly;
    const pseudocode = await this.#pseudocode(
      operation,
      entry,
      installation,
      options,
    );
    if (!pseudocode.ok) return pseudocode;
    const text =
      typeof pseudocode.value.result === "string"
        ? pseudocode.value.result
        : null;
    const unavailable = (reason: string) =>
      ({ available: false, reason }) as const;
    const dossier = functionDossierSchema.parse({
      procedure: {
        address: entry.address,
        name: entry.name,
        classification: null,
        body: unavailable(
          "Kuna reports an inventory extent that is an upper bound, not observed body ranges.",
        ),
        signature: null,
        locals: [],
      },
      pseudocode: text ?? "",
      assembly:
        typeof assembly.value.result === "string"
          ? assembly.value.result.split("\n")
          : [],
      comments: [],
      callers: [],
      callees: [],
      incoming_references: [],
      outgoing_references: [],
      referenced_strings: [],
      referenced_names: [],
      basic_blocks: [],
      native_api: null,
      native_value_flow: null,
      facet_availability: {
        pseudocode:
          text === null
            ? unavailable(
                pseudocode.value.limitations.at(-1) ??
                  "Kuna did not supply pseudocode.",
              )
            : { available: true },
        assembly: { available: true },
        comments: unavailable("Kuna exports no analyst comments."),
        callers: unavailable(
          "This provider does not report Kuna cross-references.",
        ),
        callees: unavailable(
          "This provider does not report Kuna cross-references.",
        ),
        references: unavailable(
          "This provider does not report typed references.",
        ),
        strings_names: unavailable(
          "This provider does not report function-referenced strings and names.",
        ),
        cfg: unavailable("Kuna exports no basic blocks."),
      },
      limitations: [
        ...kunaLimitations("analyze_function"),
        ...pseudocode.value.limitations,
      ],
    });
    return ok({
      result: dossier,
      source: pseudocode.value.source,
      locations: [{ kind: "address", address: entry.address }],
      limitations: pseudocode.value.limitations,
    });
  }

  /** Address and name lookups over one inventory, built once. */
  #index(inventory: readonly KunaInventoryFunction[]): InventoryIndex {
    if (this.#inventoryIndex?.inventory === inventory)
      return this.#inventoryIndex;
    const byAddress = new Map<string, KunaInventoryFunction>();
    const byName = new Map<string, KunaInventoryFunction[]>();
    for (const entry of inventory) {
      byAddress.set(entry.address, entry);
      for (const name of new Set([entry.name, ...entry.aliases])) {
        const named = byName.get(name);
        if (named === undefined) byName.set(name, [entry]);
        else named.push(entry);
      }
    }
    this.#inventoryIndex = { inventory, byAddress, byName };
    return this.#inventoryIndex;
  }

  #blockOf(
    project: KunaProject,
    address: string,
  ): KunaProjectFunction | undefined {
    this.#blocks ??= new Map(
      project.functions.map((block) => [block.address, block]),
    );
    return this.#blocks.get(address);
  }

  async #ensureInstallation(): Promise<
    Result<KunaInstallation, AnalysisError>
  > {
    this.#installation ??= inspectKunaInstallation(this.#environment).then(
      (inspected): Result<KunaInstallation, AnalysisError> => {
        if (!inspected.ok)
          return err(
            new AnalysisCapabilityUnavailableError(
              KUNA_PROVIDER_ID,
              "health",
              inspected.error.reason,
              { userMessage: inspected.error.reason },
            ),
          );
        const committed = this.#profile?.parameters["kuna_sha256"];
        if (committed !== undefined && committed !== inspected.value.sha256)
          return err(
            new ProviderAdapterError(KUNA_PROVIDER_ID, "health", {
              userMessage:
                "The Kuna executable changed after this target was opened; reopen the target to analyze it with the current executable.",
              diagnostics: {
                committed_sha256: committed,
                observed_sha256: inspected.value.sha256,
              },
            }),
          );
        return ok(inspected.value);
      },
    );
    return this.#installation;
  }

  /** Reuse a verified export, or start building one in the background. */
  async #startProject(installation: KunaInstallation): Promise<void> {
    if (this.#project !== undefined) return;
    const key = kunaProjectKey({
      targetSha256: this.#target.sha256,
      kunaSha256: installation.sha256,
      kunaVersion: installation.version,
      jobs: installation.configuration.jobs,
    });
    this.#key = key;
    const cached = await this.#cache.lookup(key, this.#session.signal);
    if (cached !== undefined) {
      this.#adopt(cached);
      this.#project = Promise.resolve(ok(cached));
      return;
    }
    this.#project = this.#cache
      .build({
        installation,
        targetPath: this.#target.path,
        targetSha256: this.#target.sha256,
        signal: this.#session.signal,
        onStatus: (status) => {
          this.#status = status;
        },
      })
      .then((result) => {
        if (result.ok && !this.#closing) this.#adopt(result.value);
        else if (!result.ok && !this.#closing)
          this.#exportFailure =
            result.error.userMessage ?? result.error.message;
        return result;
      });
  }

  /**
   * Run a read against the adopted export. Cache pins hold only within this
   * process, so another REA server can evict the files; then forget the export,
   * start it again and run the read once more, which falls back or waits.
   */
  async #withExport<T>(
    installation: KunaInstallation,
    read: () => Promise<T>,
  ): Promise<T> {
    try {
      return await read();
    } catch (cause: unknown) {
      if (!isMissing(cause) || this.#ready === undefined) throw cause;
      this.#forgetProject();
      await this.#startProject(installation);
      return read();
    }
  }

  #forgetProject(): void {
    this.#releasePin?.();
    this.#releasePin = undefined;
    this.#ready = undefined;
    this.#blocks = undefined;
    this.#assembly = undefined;
    this.#project = undefined;
    this.#status = undefined;
    this.#exportFailure = undefined;
  }

  #adopt(project: KunaProject): void {
    this.#ready = project;
    this.#releasePin ??= this.#cache.pin(project.key);
  }

  /** The export's failure once it has settled; undefined while it builds or after success. */
  async #settledExportFailure(): Promise<string | undefined> {
    const settled = await Promise.race([
      this.#project,
      Promise.resolve(undefined),
    ]);
    if (settled === undefined || settled.ok) return undefined;
    return settled.error.userMessage ?? settled.error.message;
  }

  /** Wait for the export, reporting progress, without cancelling it for other callers. */
  async #awaitProject(
    operation: string,
    options: ExecutionOptions,
  ): Promise<Result<KunaProject, AnalysisError>> {
    if (this.#ready !== undefined) return ok(this.#ready);
    const project = this.#project;
    if (project === undefined)
      return err(
        new ProviderAdapterError(KUNA_PROVIDER_ID, operation, {
          userMessage: "The Kuna project export was never started.",
        }),
      );
    const started = Date.now();
    const progress = options.progress;
    // Report waiting only; Kuna exposes no measure of completed export work.
    const timer = setInterval(() => {
      void progress
        ?.report({
          phase: "kuna_export",
          completed: 0,
          total: null,
          message: `Waiting for Kuna's project export (${this.#status?.phase ?? "starting"}, ${String(Math.floor((Date.now() - started) / 1000))}s elapsed); it serves this request and every later one`,
        })
        .catch(() => undefined);
    }, WAIT_PROGRESS_INTERVAL_MS);
    try {
      return await waitFor(project, options.signal, operation);
    } finally {
      clearInterval(timer);
    }
  }

  async #ensureAssembly(
    operation: string,
    options: ExecutionOptions,
  ): Promise<Result<KunaAssemblyIndex, AnalysisError>> {
    const project = await this.#awaitProject(operation, options);
    if (!project.ok) return project;
    this.#assembly ??= scanKunaAssembly(
      createReadStream(
        join(project.value.directory, project.value.manifest.files.asm.path),
      ),
    ).then((index) =>
      index.ok
        ? ok(index.value)
        : err(
            new ProviderAdapterError(KUNA_PROVIDER_ID, operation, {
              userMessage: `Kuna's .asm cannot be indexed: ${index.error}`,
            }),
          ),
    );
    return this.#assembly;
  }

  /** The export's inventory when ready, otherwise one quick `kuna functions` run. */
  async #ensureInventory(
    installation: KunaInstallation,
    options: ExecutionOptions,
  ): Promise<Result<readonly KunaInventoryFunction[], AnalysisError>> {
    if (this.#ready !== undefined) return ok(this.#ready.inventory);
    if (this.#inventory === undefined) {
      // The session owns the shared run; each caller only stops waiting.
      const run = this.#listInventory(installation);
      this.#inventory = run;
      void run.then((listed) => {
        // A failed quick listing is retried by the next request.
        if (!listed.ok && this.#inventory === run) this.#inventory = undefined;
      });
    }
    return waitFor(this.#inventory, options.signal, "list_procedures");
  }

  async #listInventory(
    installation: KunaInstallation,
  ): Promise<Result<readonly KunaInventoryFunction[], AnalysisError>> {
    const workspace = await this.#ensureWorkspace();
    if (!workspace.ok) return workspace;
    const run = await runKunaCommand({
      installation,
      arguments: ["functions", workspace.value.input, "--json"],
      workspace: workspace.value.root.path,
      operation: "list_procedures",
      timeoutMs: installation.configuration.functionTimeoutMs,
      reportedTimeoutMs: installation.configuration.functionTimeoutMs,
      outputBytes: KUNA_INVENTORY_OUTPUT_BYTES,
      signal: this.#session.signal,
      launcher: this.#launcher,
    });
    if (run.kind === "retained") {
      this.#retained.push({ error: run.error, owner: run.owner });
      return err(run.error);
    }
    if (run.kind === "failed") return err(run.error);
    const inventory = parseKunaInventory(run.snapshot.stdout.text);
    return inventory.ok
      ? ok(inventory.value)
      : err(
          new ProviderAdapterError(KUNA_PROVIDER_ID, "list_procedures", {
            userMessage: `Kuna's function inventory is not usable: ${inventory.error}`,
          }),
        );
  }

  /** A private, digest-verified copy of the target for single-function runs. */
  async #ensureWorkspace(): Promise<
    Result<
      { readonly root: PrivateRuntimeRoot; readonly input: string },
      AnalysisError
    >
  > {
    this.#workspace ??= (async () => {
      const root = await PrivateRuntimeRoot.create({ prefix: "rea-kuna-" });
      try {
        const input = join(root.path, basename(this.#target.path));
        const digest = await copyAndHash(
          this.#target.path,
          input,
          this.#session.signal,
        );
        if (digest !== this.#target.sha256) {
          await this.#release(root);
          return err(
            new AnalysisArtifactChangedError(
              "kuna:workspace",
              this.#target.path,
              "the target no longer matches the digest selected for analysis",
            ),
          );
        }
        await prepareProcessOwnershipInspection(this.#session.signal);
        return ok({ root, input });
      } catch (cause: unknown) {
        await this.#release(root);
        throw cause;
      }
    })().catch((cause: unknown) => err(failure("kuna:workspace", cause)));
    const workspace = await this.#workspace;
    if (!workspace.ok) this.#workspace = undefined;
    return workspace;
  }

  /** Remove a private root, keeping it for close to retry when removal fails. */
  async #release(root: PrivateRuntimeRoot): Promise<void> {
    try {
      await root.close();
    } catch {
      this.#leakedRoots.push(root);
    }
  }
}
