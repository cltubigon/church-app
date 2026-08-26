import { invoke } from "@tauri-apps/api/core";

export type StartupStatus =
  | "starting"
  | "ready"
  | "unavailable"
  | "stopping"
  | "shutdownIncomplete";

const startupStatuses = new Set<StartupStatus>([
  "starting",
  "ready",
  "unavailable",
  "stopping",
  "shutdownIncomplete",
]);

export async function getStartupStatus(): Promise<StartupStatus> {
  try {
    const status = await invoke<unknown>("startup_status");
    return typeof status === "string" && startupStatuses.has(status as StartupStatus)
      ? (status as StartupStatus)
      : "unavailable";
  } catch {
    return "unavailable";
  }
}
