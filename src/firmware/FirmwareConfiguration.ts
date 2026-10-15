import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { err, ok, type Result } from "../domain/result.js";

/** Explicit tool settings shared by execution and readiness diagnostics. */
export const FIRMWARE_COMMAND_VARIABLES = {
  binwalk: "REA_BINWALK_COMMAND",
  unblob: "REA_UNBLOB_COMMAND",
} as const;

/** Match the execution adapter's default without requiring an environment override. */
export const firmwareLimiterPath = (
  environment: Readonly<NodeJS.ProcessEnv>,
): string => environment.REA_FIRMWARE_PRLIMIT_COMMAND ?? "/usr/bin/prlimit";

/** Resolve a readable executable regular file; never search for or install tools. */
export const inspectFirmwareExecutable = async (
  path: string | undefined,
  variable: string,
  readable = true,
): Promise<Result<string, string>> => {
  if (path === undefined || !isAbsolute(path))
    return err(
      `${variable} must be an absolute path to a caller-supplied executable.`,
    );
  try {
    const resolved = await realpath(path);
    await access(resolved, (readable ? constants.R_OK : 0) | constants.X_OK);
    if (!(await stat(resolved)).isFile())
      return err(
        `${variable} is not a readable executable regular file: ${path}`,
      );
    return ok(resolved);
  } catch (cause: unknown) {
    return err(
      `${variable} is unavailable at ${path}: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
};
