import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  getStartupStatus,
  requestFirstRecoveryKeyReentry,
  requestFirstTimeSetup,
  requestSecondRecoveryVolumeSelection,
} from "./startup";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

const mockedInvoke = vi.mocked(invoke);

describe("getStartupStatus", () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
  });

  it("recognizes active migration preparation", async () => {
    mockedInvoke.mockResolvedValue("migrationPreparationInProgress");

    await expect(getStartupStatus()).resolves.toBe("migrationPreparationInProgress");
    expect(mockedInvoke).toHaveBeenCalledWith("startup_status");
  });

  it("recognizes verified custody awaiting recovery publication", async () => {
    mockedInvoke.mockResolvedValue("migrationRecoveryKeyCustodyVerifiedAwaitingPublication");

    await expect(getStartupStatus()).resolves.toBe(
      "migrationRecoveryKeyCustodyVerifiedAwaitingPublication",
    );
    expect(mockedInvoke).toHaveBeenCalledWith("startup_status");
  });

  it("recognizes first recovery-key re-entry awaiting verification", async () => {
    mockedInvoke.mockResolvedValue("migrationRecoveryKeyReentryAwaitingVerification");

    await expect(getStartupStatus()).resolves.toBe(
      "migrationRecoveryKeyReentryAwaitingVerification",
    );
    expect(mockedInvoke).toHaveBeenCalledWith("startup_status");
  });
});

describe("requestFirstTimeSetup", () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
  });

  it.each([
    "started",
    "alreadyInProgress",
    "startupInProgress",
    "notAllowed",
    "restartRequired",
    "unavailable",
  ] as const)("accepts the known %s result", async (result) => {
    mockedInvoke.mockResolvedValue(result);
    await expect(requestFirstTimeSetup()).resolves.toBe(result);
    expect(mockedInvoke).toHaveBeenCalledOnce();
    expect(mockedInvoke).toHaveBeenCalledWith("request_first_time_setup");
  });

  it.each(["unknown", { result: "started" }, null])(
    "fails closed for an unknown backend result",
    async (result) => {
      mockedInvoke.mockResolvedValue(result);
      await expect(requestFirstTimeSetup()).resolves.toBe("unavailable");
    },
  );

  it("fails closed when invocation rejects", async () => {
    mockedInvoke.mockRejectedValue(new Error("sensitive backend detail"));
    await expect(requestFirstTimeSetup()).resolves.toBe("unavailable");
  });
});

describe("requestSecondRecoveryVolumeSelection", () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
  });

  it.each(["started", "notAllowed", "unavailable"] as const)(
    "accepts the known %s result without renderer arguments",
    async (result) => {
      mockedInvoke.mockResolvedValue(result);
      await expect(requestSecondRecoveryVolumeSelection()).resolves.toBe(result);
      expect(mockedInvoke).toHaveBeenCalledWith("request_second_recovery_volume_selection");
    },
  );

  it.each(["unknown", { result: "started" }, null])(
    "fails closed for an unknown backend result",
    async (result) => {
      mockedInvoke.mockResolvedValue(result);
      await expect(requestSecondRecoveryVolumeSelection()).resolves.toBe("unavailable");
    },
  );

  it("fails closed when invocation rejects", async () => {
    mockedInvoke.mockRejectedValue(new Error("sensitive backend detail"));
    await expect(requestSecondRecoveryVolumeSelection()).resolves.toBe("unavailable");
  });
});

describe("requestFirstRecoveryKeyReentry", () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
  });

  it.each(["started", "notAllowed", "unavailable"] as const)(
    "accepts the known %s result without renderer arguments",
    async (result) => {
      mockedInvoke.mockResolvedValue(result);
      await expect(requestFirstRecoveryKeyReentry()).resolves.toBe(result);
      expect(mockedInvoke).toHaveBeenCalledWith("request_first_recovery_key_reentry");
    },
  );

  it.each(["unknown", { result: "started" }, null])(
    "fails closed for an unknown backend result",
    async (result) => {
      mockedInvoke.mockResolvedValue(result);
      await expect(requestFirstRecoveryKeyReentry()).resolves.toBe("unavailable");
    },
  );

  it("fails closed when invocation rejects", async () => {
    mockedInvoke.mockRejectedValue(new Error("sensitive backend detail"));
    await expect(requestFirstRecoveryKeyReentry()).resolves.toBe("unavailable");
  });
});
