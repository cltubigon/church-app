import { invoke } from "@tauri-apps/api/core";

export type StartupStatus =
  | "starting"
  | "ready"
  | "unavailable"
  | "setupInProgress"
  | "setupRestartRequired"
  | "stopping"
  | "shutdownIncomplete"
  | "migrationPreparationInProgress"
  | "migrationRecoveryKeyCustodyInProgress"
  | "migrationRecoveryKeyCustodyAwaitingRetry"
  | "firstRecoveryVolumeAcceptedAwaitingSecondDevice"
  | "twoCompleteRecoverySetsVerifiedAwaitingMigrationExecution"
  | "migrationExecutionConfirmedAwaitingWritablePreparation"
  | "writableV1MigrationPreparedAwaitingTransaction"
  | "migrationCommittedRestartRequired"
  | "migrationFailedRestartRequired";

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
  "migrationPreparationInProgress",
  "migrationRecoveryKeyCustodyInProgress",
  "migrationRecoveryKeyCustodyAwaitingRetry",
  "firstRecoveryVolumeAcceptedAwaitingSecondDevice",
  "twoCompleteRecoverySetsVerifiedAwaitingMigrationExecution",
  "migrationExecutionConfirmedAwaitingWritablePreparation",
  "writableV1MigrationPreparedAwaitingTransaction",
  "migrationCommittedRestartRequired",
  "migrationFailedRestartRequired",
]);

export type PostRecoveryMigrationExecutionConfirmationRequestResult =
  | "started"
  | "notAllowed"
  | "unavailable";

export type ProductionDatabaseMigrationRequestResult = "started" | "notAllowed" | "unavailable";

export type MigrationRecoveryKeyCustodyRetryRequestResult =
  | "started"
  | "notAllowed"
  | "unavailable";

export type SecondRecoveryVolumeSelectionRequestResult = "started" | "notAllowed" | "unavailable";

const postRecoveryMigrationExecutionConfirmationRequestResults =
  new Set<PostRecoveryMigrationExecutionConfirmationRequestResult>([
    "started",
    "notAllowed",
    "unavailable",
  ]);

const productionDatabaseMigrationRequestResults = new Set<ProductionDatabaseMigrationRequestResult>(
  ["started", "notAllowed", "unavailable"],
);

const migrationRecoveryKeyCustodyRetryRequestResults =
  new Set<MigrationRecoveryKeyCustodyRetryRequestResult>(["started", "notAllowed", "unavailable"]);

const secondRecoveryVolumeSelectionRequestResults =
  new Set<SecondRecoveryVolumeSelectionRequestResult>(["started", "notAllowed", "unavailable"]);

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

export async function getMigrationInitiationAvailable(): Promise<boolean> {
  try {
    return (await invoke<unknown>("migration_initiation_available")) === true;
  } catch {
    return false;
  }
}

export async function getFirstTimeSetupAvailable(): Promise<boolean> {
  try {
    return (await invoke<unknown>("first_time_setup_available")) === true;
  } catch {
    return false;
  }
}

export async function requestProductionDatabaseMigration(): Promise<ProductionDatabaseMigrationRequestResult> {
  try {
    const result = await invoke<unknown>("request_production_database_migration");
    return typeof result === "string" &&
      productionDatabaseMigrationRequestResults.has(
        result as ProductionDatabaseMigrationRequestResult,
      )
      ? (result as ProductionDatabaseMigrationRequestResult)
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

export async function retryMigrationRecoveryKeyCustody(): Promise<MigrationRecoveryKeyCustodyRetryRequestResult> {
  try {
    const result = await invoke<unknown>("retry_migration_recovery_key_custody");
    return typeof result === "string" &&
      migrationRecoveryKeyCustodyRetryRequestResults.has(
        result as MigrationRecoveryKeyCustodyRetryRequestResult,
      )
      ? (result as MigrationRecoveryKeyCustodyRetryRequestResult)
      : "unavailable";
  } catch {
    return "unavailable";
  }
}

export async function requestPostRecoveryMigrationExecutionConfirmation(): Promise<PostRecoveryMigrationExecutionConfirmationRequestResult> {
  try {
    const result = await invoke<unknown>("request_post_recovery_migration_execution_confirmation");
    return typeof result === "string" &&
      postRecoveryMigrationExecutionConfirmationRequestResults.has(
        result as PostRecoveryMigrationExecutionConfirmationRequestResult,
      )
      ? (result as PostRecoveryMigrationExecutionConfirmationRequestResult)
      : "unavailable";
  } catch {
    return "unavailable";
  }
}

export async function requestSecondRecoveryVolumeSelection(): Promise<SecondRecoveryVolumeSelectionRequestResult> {
  try {
    const result = await invoke<unknown>("request_second_recovery_volume_selection");
    return typeof result === "string" &&
      secondRecoveryVolumeSelectionRequestResults.has(
        result as SecondRecoveryVolumeSelectionRequestResult,
      )
      ? (result as SecondRecoveryVolumeSelectionRequestResult)
      : "unavailable";
  } catch {
    return "unavailable";
  }
}
