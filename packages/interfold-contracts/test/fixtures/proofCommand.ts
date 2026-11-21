// SPDX-License-Identifier: LGPL-3.0-only
import { type SpawnOptions, execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

export class ProofCleanupError extends Error {}

async function stopGroup(pid: number) {
  try {
    process.kill(-pid, "SIGKILL");
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ESRCH")
      return;
    throw error;
  }
  // Reparented workers may outlive the leader. Zombies can no longer use the fixture.
  const end = performance.now() + 5_000;
  do {
    const { stdout } = await promisify(execFile)(
      "ps",
      ["-axo", "pgid=,stat="],
      { timeout: 2_000 },
    );
    if (
      !stdout.split("\n").some((line) => {
        const [group, state] = line.trim().split(/\s+/);
        return Number(group) === pid && !state?.startsWith("Z");
      })
    )
      return;
    await delay(50);
  } while (performance.now() < end);
  throw new Error(`process group ${pid} still running`);
}

/** The POSIX proof tools and their workers share a process group and a caller-owned monotonic deadline. */
export async function runProofCommand(
  deadline: number,
  command: string,
  args: string[],
  options: Pick<SpawnOptions, "cwd" | "env">,
) {
  if (process.platform === "win32")
    throw new Error("Proof qualification requires POSIX process groups");
  const remaining = Math.ceil(deadline - performance.now());
  if (remaining <= 0)
    throw new Error(`Proof deadline expired before ${command}`);
  const child = spawn(command, args, {
    ...options,
    detached: true,
    stdio: "inherit",
  });
  const controller = new AbortController();
  const interrupt = () => controller.abort(new Error(`Interrupted ${command}`));
  const timer = setTimeout(
    () =>
      controller.abort(new Error(`Proof deadline expired running ${command}`)),
    remaining,
  );
  process.once("SIGTERM", interrupt);
  process.once("SIGINT", interrupt);
  try {
    const [code, signal] = await once(child, "close", {
      signal: controller.signal,
    });
    if (code !== 0) throw new Error(`${command} exited with ${signal ?? code}`);
  } catch (error) {
    throw controller.signal.reason ?? error;
  } finally {
    clearTimeout(timer);
    try {
      if (child.pid !== undefined) {
        await stopGroup(child.pid).catch((cause) => {
          throw new ProofCleanupError(
            `Could not confirm ${command} workers stopped`,
            { cause },
          );
        });
      }
    } finally {
      process.off("SIGTERM", interrupt);
      process.off("SIGINT", interrupt);
    }
  }
}
