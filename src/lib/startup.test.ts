import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { requestFirstTimeSetup, requestSecondRecoveryVolumeSelection } from "./startup";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

const mockedInvoke = vi.mocked(invoke);

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
