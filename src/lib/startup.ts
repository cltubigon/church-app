import { invoke } from "@tauri-apps/api/core";

export type StartupStatus =
  | "starting"
  | "ready"
  | "unavailable"
  | "setupInProgress"
  | "setupRestartRequired"
  | "stopping"
  | "shutdownIncomplete";

export type FirstTimeSetupRequestResult =
  | "started"
  | "alreadyInProgress"
  | "startupInProgress"
  | "notAllowed"
  | "restartRequired"
  | "unavailable";

const startupStatuses = new Set<StartupStatus>([
  "starting",
  "ready",
  "unavailable",
  "setupInProgress",
  "setupRestartRequired",
  "stopping",
  "shutdownIncomplete",
]);

const firstTimeSetupRequestResults = new Set<FirstTimeSetupRequestResult>([
  "started",
  "alreadyInProgress",
  "startupInProgress",
  "notAllowed",
  "restartRequired",
  "unavailable",
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

export async function requestFirstTimeSetup(): Promise<FirstTimeSetupRequestResult> {
  try {
    const result = await invoke<unknown>("request_first_time_setup");
    return typeof result === "string" &&
      firstTimeSetupRequestResults.has(result as FirstTimeSetupRequestResult)
      ? (result as FirstTimeSetupRequestResult)
      : "unavailable";
  } catch {
    return "unavailable";
  }
}
