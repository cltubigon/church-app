import { readFileSync } from "node:fs";
import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getStartupStatus } from "./lib/startup";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

const mockedInvoke = vi.mocked(invoke);
const startupSource = readFileSync("src/lib/startup.ts", "utf8");
const appSource = readFileSync("src/App.tsx", "utf8");

describe("migration status diagnostic tracing", () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
  });

  it("traces the fixed startup status received from the command boundary", async () => {
    const info = vi.spyOn(console, "info").mockImplementation(() => undefined);
    mockedInvoke.mockResolvedValue("firstRecoveryVolumeAcceptedAwaitingSecondDevice");

    await expect(getStartupStatus()).resolves.toBe(
      "firstRecoveryVolumeAcceptedAwaitingSecondDevice",
    );
    expect(info).toHaveBeenCalledWith(
      "[migration-status] phase=status_received status=firstRecoveryVolumeAcceptedAwaitingSecondDevice",
    );
  });

  it("keeps frontend tracing development-only at every emitter", () => {
    expect(startupSource.match(/if \(import\.meta\.env\.DEV\)/g)).toHaveLength(2);
    expect(startupSource).toContain("phase=polling_decision continue=$" + "{shouldContinue}");
    expect(appSource).toContain('traceMigrationStatus("state_update", status)');
    expect(appSource).toContain("traceMigrationPollingDecision(shouldContinuePolling, status)");
    expect(appSource).toContain('traceMigrationStatus("render", status)');
  });

  it("logs only fixed status values and booleans, never device or secret data", () => {
    const traceSource = startupSource
      .split("type MigrationStatusTracePhase")[1]
      .split("export type PostRecoveryMigrationExecutionConfirmationRequestResult")[0];

    expect(traceSource).toContain("status: StartupStatus");
    expect(traceSource).toContain("shouldContinue: boolean");
    for (const forbidden of [
      "drive",
      "path",
      "volumeGuid",
      "diskNumber",
      "serial",
      "handle",
      "recoveryKey",
      "secret",
      "migrationId",
    ]) {
      expect(traceSource).not.toContain(forbidden);
    }
  });

  it("preserves the existing accepted-first-volume mapping and polling decision", () => {
    expect(startupSource).toContain('"firstRecoveryVolumeAcceptedAwaitingSecondDevice"');
    expect(appSource).toContain('status === "firstRecoveryVolumeAcceptedAwaitingSecondDevice" ||');
    expect(appSource).toContain(
      'firstRecoveryVolumeAcceptedAwaitingSecondDevice:\n      "The first recovery destination was accepted.',
    );
  });
});
