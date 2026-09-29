import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  BusinessError,
  createRequest,
  fromCanonicalDate,
  fromCanonicalTime,
  scheduleRequest,
  toBusinessError,
  toCanonicalDate,
  toCanonicalTime,
} from "./business";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
const mockedInvoke = vi.mocked(invoke);

describe("business IPC client", () => {
  beforeEach(() => mockedInvoke.mockReset());

  it("converts display dates without accepting invalid Gregorian dates", () => {
    expect(toCanonicalDate("02/29/2028")).toBe("2028-02-29");
    expect(toCanonicalDate("02/29/2027")).toBeNull();
    expect(fromCanonicalDate("2028-02-29")).toBe("02/29/2028");
  });

  it("converts 12-hour presentation times to canonical values and back", () => {
    expect(toCanonicalTime("12:05 AM")).toBe("00:05");
    expect(toCanonicalTime("1:30 pm")).toBe("13:30");
    expect(toCanonicalTime("13:30 PM")).toBeNull();
    expect(fromCanonicalTime("00:05")).toBe("12:05 AM");
    expect(fromCanonicalTime("13:30")).toBe("1:30 PM");
  });

  it("sends bounded business input without IDs, status, timestamps, keys, paths, or SQL", async () => {
    mockedInvoke.mockResolvedValue({ requestRef: "opaque" });
    await createRequest({
      serviceCategory: "baptism",
      requesterFullName: "Synthetic Person",
      requesterPhone: "555-0100",
      requesterEmail: null,
    });
    const [, args] = mockedInvoke.mock.calls[0];
    expect(args).toEqual({
      input: {
        serviceCategory: "baptism",
        requesterFullName: "Synthetic Person",
        requesterPhone: "555-0100",
        requesterEmail: null,
      },
    });
    const payload = JSON.stringify(args);
    for (const forbidden of ["Id", "status", "timestamp", "key", "path", "sql"]) {
      expect(payload.toLowerCase()).not.toContain(forbidden.toLowerCase());
    }
  });

  it("uses only an opaque request reference for status transitions", async () => {
    mockedInvoke.mockResolvedValue(undefined);
    await scheduleRequest("request_opaque");
    expect(mockedInvoke).toHaveBeenCalledWith("business_schedule_request", {
      requestRef: "request_opaque",
    });
  });

  it("maps backend failures to stable safe messages without rendering raw details", () => {
    const failure = toBusinessError({
      code: "scheduleConflict",
      message: "C:\\private\\parish-data.db SQL token=secret",
    });
    expect(failure).toBeInstanceOf(BusinessError);
    expect(failure).toMatchObject({
      code: "scheduleConflict",
      message: "The selected date and time are already occupied.",
    });
    expect(String(failure)).not.toContain("parish-data.db");
    expect(String(failure)).not.toContain("token=secret");
  });
});
