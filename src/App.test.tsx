import { invoke } from "@tauri-apps/api/core";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { getHealth } from "./lib/health";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
const mockedInvoke = vi.mocked(invoke);

function renderApp(path = "/") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe("application foundation", () => {
  beforeEach(() => {
    mockedInvoke.mockReset();
    mockedInvoke.mockImplementation((command) => {
      if (command === "startup_status") return Promise.resolve("ready");
      if (command === "business_features_available") return Promise.resolve(true);
      if (command === "business_list_requests") return Promise.resolve([]);
      return Promise.resolve(undefined);
    });
  });

  it("renders an accessible unfinished shell with only approved area links", async () => {
    renderApp();
    expect(await screen.findByRole("banner")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: "Church App" })).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.getByRole("contentinfo")).toBeInTheDocument();
    expect(screen.getByText("Parish request workflows")).toBeInTheDocument();
    const navigation = screen.getByRole("navigation", { name: "Staff areas" });
    for (const name of ["Requests", "Scheduling", "Cancellation Review"]) {
      expect(navigation).toContainElement(screen.getByRole("link", { name }));
    }
    expect(navigation.querySelectorAll("a")).toHaveLength(3);
  });

  it("supports keyboard workflow navigation", async () => {
    const user = userEvent.setup();
    renderApp();
    await screen.findByRole("banner");
    await user.tab();
    expect(screen.getByRole("link", { name: "Skip to main content" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("link", { name: "Requests" })).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("heading", { level: 2, name: "Requests" })).toBeInTheDocument();
    expect(screen.getByText("No requests found.")).toBeInTheDocument();
  });

  it("renders a safe fallback for an unknown route", async () => {
    renderApp("/not-a-route");
    expect(await screen.findByRole("heading", { name: "Page unavailable" })).toBeInTheDocument();
    expect(
      screen.getByText("The requested page is not part of this application foundation."),
    ).toBeInTheDocument();
  });

  it("renders a successful typed health response", async () => {
    mockedInvoke.mockImplementation((command) => {
      if (command === "startup_status") return Promise.resolve("ready");
      if (command === "business_features_available") return Promise.resolve(true);
      return Promise.resolve({
        applicationName: "Church App Foundation",
        bootstrapStatus: "ready",
        applicationVersion: "0.1.0",
      });
    });
    const user = userEvent.setup();
    renderApp();
    await user.click(await screen.findByRole("button", { name: "Check foundation health" }));
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent("Church App Foundation");
    expect(status).toHaveTextContent("ready");
    expect(status).toHaveTextContent("0.1.0");
    expect(mockedInvoke).toHaveBeenCalledWith("health_check");
  });

  it("renders a safe health error without exposing the backend error", async () => {
    const rawError = "panic at C:\\private\\parish.db with token=secret";
    mockedInvoke.mockRejectedValueOnce({ code: "backend_debug", message: rawError });
    await expect(getHealth()).resolves.toEqual({
      error: {
        code: "health_unavailable",
        message: "The application foundation could not confirm its status.",
      },
      ok: false,
    });
    mockedInvoke.mockImplementation((command) => {
      if (command === "startup_status") return Promise.resolve("ready");
      if (command === "business_features_available") return Promise.resolve(true);
      return Promise.resolve({ code: "backend_debug", message: rawError });
    });
    const user = userEvent.setup();
    renderApp();
    await user.click(await screen.findByRole("button", { name: "Check foundation health" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The application foundation could not confirm its status. Please try again.",
    );
    expect(document.body.textContent).not.toContain(rawError);
    expect(document.body.textContent).not.toContain("parish.db");
    expect(document.body.textContent).not.toContain("token=secret");
  });

  it("keeps the shell unavailable until Rust reports ready", async () => {
    mockedInvoke.mockResolvedValue("starting");
    renderApp();
    expect(
      await screen.findByText("Preparing the application securely. This may take some time."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
    await waitFor(() => expect(mockedInvoke).toHaveBeenCalledWith("startup_status"));
  });

  it.each([
    ["starting", "Preparing the application securely. This may take some time."],
    ["ready", "Parish request workflows"],
    ["setupInProgress", "First-time setup is in progress."],
    ["setupRestartRequired", "First-time setup is complete. Restart the application to continue."],
    ["stopping", "The application is stopping."],
    ["shutdownIncomplete", "The application could not complete shutdown."],
    [
      "twoCompleteRecoverySetsVerifiedAwaitingMigrationExecution",
      "Both recovery sets are verified. Migration execution is awaiting your confirmation.",
    ],
    [
      "migrationExecutionConfirmedAwaitingWritablePreparation",
      "Migration execution is confirmed. Writable migration preparation has not begun.",
    ],
    [
      "writableV1MigrationPreparedAwaitingTransaction",
      "The writable V1 migration database is prepared and verified. The migration transaction has not begun.",
    ],
  ])("does not offer first-time setup while startup status is %s", async (status, message) => {
    mockedInvoke.mockImplementation((command) =>
      command === "business_features_available" ? Promise.resolve(true) : Promise.resolve(status),
    );
    renderApp();
    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Set up Church App" })).not.toBeInTheDocument();
    if (status !== "twoCompleteRecoverySetsVerifiedAwaitingMigrationExecution") {
      expect(
        screen.queryByRole("button", { name: "Confirm migration authorization" }),
      ).not.toBeInTheDocument();
    }
    if (status === "ready") {
      expect(screen.getByRole("navigation", { name: "Staff areas" })).toBeInTheDocument();
    } else {
      expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
    }
  });

  it("renders only a coarse unavailable state when startup status cannot be read", async () => {
    mockedInvoke.mockResolvedValue("sensitive backend detail");
    renderApp();
    expect(await screen.findByText("The application is unavailable.")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("sensitive backend detail");
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });

  it("offers one explicit first-time setup action only on the unavailable surface", async () => {
    mockedInvoke.mockResolvedValue("unavailable");
    renderApp();

    expect(await screen.findByText("The application is unavailable.")).toBeInTheDocument();
    expect(
      screen.getByText("Use this only to set up Church App for the first time."),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Set up Church App" })).toHaveLength(1);
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });

  it("offers migration confirmation only in the exact post-recovery awaiting state", async () => {
    mockedInvoke.mockResolvedValue("twoCompleteRecoverySetsVerifiedAwaitingMigrationExecution");
    renderApp();

    expect(
      await screen.findByText(
        "Both recovery sets are verified. Migration execution is awaiting your confirmation.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Confirm migration authorization" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Set up Church App" })).not.toBeInTheDocument();
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });

  it("requests only the argument-free native confirmation command", async () => {
    mockedInvoke.mockImplementation((command) => {
      if (command === "startup_status") {
        return Promise.resolve("twoCompleteRecoverySetsVerifiedAwaitingMigrationExecution");
      }
      if (command === "request_post_recovery_migration_execution_confirmation") {
        return Promise.resolve("started");
      }
      return Promise.reject(new Error("unexpected command"));
    });
    const user = userEvent.setup();
    renderApp();

    await user.click(
      await screen.findByRole("button", { name: "Confirm migration authorization" }),
    );

    expect(
      mockedInvoke.mock.calls.filter(
        ([command]) => command === "request_post_recovery_migration_execution_confirmation",
      ),
    ).toEqual([["request_post_recovery_migration_execution_confirmation"]]);
  });

  it("renders confirmed-awaiting-preparation truthfully without claiming migration completion", async () => {
    mockedInvoke.mockResolvedValue("migrationExecutionConfirmedAwaitingWritablePreparation");
    renderApp();

    expect(
      await screen.findByText(
        "Migration execution is confirmed. Writable migration preparation has not begun.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Confirm migration authorization" }),
    ).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("Migration is complete");
    expect(document.body.textContent).not.toContain("Migration completed");
  });

  it("renders writable-prepared as transaction-not-started", async () => {
    mockedInvoke.mockResolvedValue("writableV1MigrationPreparedAwaitingTransaction");
    renderApp();

    expect(
      await screen.findByText(
        "The writable V1 migration database is prepared and verified. The migration transaction has not begun.",
      ),
    ).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("Migration is complete");
    expect(document.body.textContent).not.toContain("Migration completed");
  });

  it("renders successful migration as restart-required without an action", async () => {
    mockedInvoke.mockResolvedValue("migrationCommittedRestartRequired");
    renderApp();

    expect(await screen.findByText("Migration completed. Restart required.")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Confirm migration authorization" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });

  it("requests setup once without arguments and promptly re-checks startup status", async () => {
    mockedInvoke.mockImplementation((command) => {
      if (command === "startup_status") return Promise.resolve("unavailable");
      if (command === "request_first_time_setup") return Promise.resolve("started");
      return Promise.reject(new Error("unexpected command"));
    });
    const user = userEvent.setup();
    renderApp();

    await user.click(await screen.findByRole("button", { name: "Set up Church App" }));

    await waitFor(() => {
      expect(
        mockedInvoke.mock.calls.filter(([command]) => command === "startup_status"),
      ).toHaveLength(2);
    });
    expect(
      mockedInvoke.mock.calls.filter(([command]) => command === "request_first_time_setup"),
    ).toEqual([["request_first_time_setup"]]);
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });

  it("suppresses duplicate setup submissions while the request is pending", async () => {
    let finishSetup: ((result: "started") => void) | undefined;
    mockedInvoke.mockImplementation((command) => {
      if (command === "startup_status") return Promise.resolve("unavailable");
      if (command === "request_first_time_setup") {
        return new Promise((resolve) => {
          finishSetup = resolve;
        });
      }
      return Promise.reject(new Error("unexpected command"));
    });
    const user = userEvent.setup();
    renderApp();
    const button = await screen.findByRole("button", { name: "Set up Church App" });

    await user.click(button);
    expect(screen.getByRole("button", { name: "Starting first-time setup…" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Starting first-time setup…" }));
    expect(
      mockedInvoke.mock.calls.filter(([command]) => command === "request_first_time_setup"),
    ).toHaveLength(1);

    await act(async () => finishSetup?.("started"));
  });

  it.each(["started", "alreadyInProgress", "startupInProgress", "notAllowed"] as const)(
    "keeps the %s request result non-operational and re-checks canonical status",
    async (result) => {
      mockedInvoke.mockImplementation((command) => {
        if (command === "startup_status") return Promise.resolve("unavailable");
        if (command === "request_first_time_setup") return Promise.resolve(result);
        return Promise.reject(new Error("unexpected command"));
      });
      const user = userEvent.setup();
      renderApp();

      await user.click(await screen.findByRole("button", { name: "Set up Church App" }));

      await waitFor(() => {
        expect(
          mockedInvoke.mock.calls.filter(([command]) => command === "startup_status"),
        ).toHaveLength(2);
      });
      expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
    },
  );

  it("uses refreshed status as authority for restart-required and never renders Ready locally", async () => {
    let startupReadCount = 0;
    mockedInvoke.mockImplementation((command) => {
      if (command === "startup_status") {
        startupReadCount += 1;
        return Promise.resolve(startupReadCount === 1 ? "unavailable" : "setupRestartRequired");
      }
      if (command === "request_first_time_setup") return Promise.resolve("restartRequired");
      return Promise.reject(new Error("unexpected command"));
    });
    const user = userEvent.setup();
    renderApp();

    await user.click(await screen.findByRole("button", { name: "Set up Church App" }));

    expect(
      await screen.findByText("First-time setup is complete. Restart the application to continue."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
    expect(mockedInvoke.mock.calls.map(([command]) => command)).toEqual([
      "startup_status",
      "request_first_time_setup",
      "startup_status",
    ]);
  });

  it.each([
    ["the unavailable result", () => Promise.resolve("unavailable")],
    ["an unknown result", () => Promise.resolve("sensitive unexpected setup result")],
    ["a rejected request", () => Promise.reject(new Error("C:\\private\\setup-secret"))],
  ])("shows only a coarse setup failure for %s", async (_case, getSetupOutcome) => {
    mockedInvoke.mockImplementation((command) => {
      if (command === "startup_status") return Promise.resolve("unavailable");
      if (command === "request_first_time_setup") return getSetupOutcome();
      return Promise.reject(new Error("unexpected command"));
    });
    const user = userEvent.setup();
    renderApp();

    await user.click(await screen.findByRole("button", { name: "Set up Church App" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "First-time setup could not be started.",
    );
    expect(document.body.textContent).not.toContain("sensitive unexpected setup result");
    expect(document.body.textContent).not.toContain("setup-secret");
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });

  it("renders request summaries and Pending draft actions without a synthetic cancellation status", async () => {
    const request = {
      requestRef: "request_opaque",
      serviceCategory: "baptism",
      status: "pending",
      requester: { fullName: "Synthetic Person", phone: "555-0100", email: null },
      createdAt: 1_700_000_000_000,
    };
    mockedInvoke.mockImplementation((command) => {
      if (command === "startup_status") return Promise.resolve("ready");
      if (command === "business_features_available") return Promise.resolve(true);
      if (command === "business_list_requests") return Promise.resolve([request]);
      if (command === "business_get_request") {
        return Promise.resolve({
          request,
          occurrences: [
            {
              occurrenceRef: "occurrence_opaque",
              kind: "primary",
              localDate: "2028-04-12",
              localTime: "09:30",
              location: null,
            },
          ],
          cancellationReviews: [],
        });
      }
      return Promise.resolve(undefined);
    });
    const user = userEvent.setup();
    renderApp("/requests");
    await user.click(await screen.findByRole("button", { name: /Synthetic Person/ }));
    expect(await screen.findByRole("heading", { name: "Synthetic Person" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete draft" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Schedule" })).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("Cancellation requested");
  });

  it("keeps Scheduled visible while a Pending review exists and keeps its occupied slot", async () => {
    const request = {
      requestRef: "request_scheduled",
      serviceCategory: "weddingMarriage",
      status: "scheduled",
      requester: { fullName: "Synthetic Couple", phone: "555-0101", email: null },
      createdAt: 1_700_000_000_000,
    };
    mockedInvoke.mockImplementation((command) => {
      if (command === "startup_status") return Promise.resolve("ready");
      if (command === "business_features_available") return Promise.resolve(true);
      if (command === "business_list_schedule_occupancy") {
        return Promise.resolve([
          {
            requestRef: request.requestRef,
            serviceCategory: request.serviceCategory,
            occurrence: {
              occurrenceRef: "occurrence_scheduled",
              kind: "primary",
              localDate: "2028-05-20",
              localTime: "13:00",
              location: "Parish Church",
            },
          },
        ]);
      }
      return Promise.resolve([]);
    });
    renderApp("/scheduling");
    expect(await screen.findByText("05/20/2028")).toBeInTheDocument();
    expect(screen.getByText("1:00 PM")).toBeInTheDocument();
    expect(screen.getByText("Parish Church")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("Cancellation requested");
  });

  it("uses the dedicated pending-review query and refreshes the queue after approval", async () => {
    let approved = false;
    mockedInvoke.mockImplementation((command) => {
      if (command === "startup_status") return Promise.resolve("ready");
      if (command === "business_features_available") return Promise.resolve(true);
      if (command === "business_list_pending_cancellation_reviews") {
        return Promise.resolve(
          approved
            ? []
            : [
                {
                  cancellationReviewRef: "review_opaque",
                  requestRef: "request_opaque",
                  serviceCategory: "burialFuneral",
                  requestStatus: "scheduled",
                  requesterDisplayName: "Synthetic Family",
                  requestedAt: 1_700_000_000_000,
                },
              ],
        );
      }
      if (command === "business_approve_cancellation_review") {
        approved = true;
        return Promise.resolve(undefined);
      }
      return Promise.resolve(undefined);
    });
    const user = userEvent.setup();
    renderApp("/cancellation-review");
    expect(await screen.findByText("Synthetic Family")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Approve" }));
    expect(await screen.findByText("No pending cancellation reviews.")).toBeInTheDocument();
    expect(mockedInvoke).toHaveBeenCalledWith("business_approve_cancellation_review", {
      cancellationReviewRef: "review_opaque",
    });
  });

  it("uses the dedicated pending-review filter without adding a row badge", async () => {
    mockedInvoke.mockImplementation((command) => {
      if (command === "startup_status") return Promise.resolve("ready");
      if (command === "business_features_available") return Promise.resolve(true);
      if (command === "business_list_requests") return Promise.resolve([]);
      if (command === "business_list_requests_with_pending_cancellation_review") {
        return Promise.resolve([
          {
            requestRef: "request_filtered",
            serviceCategory: "confirmation",
            status: "scheduled",
            requester: { fullName: "Synthetic Candidate", phone: "555-0102", email: null },
            createdAt: 1_700_000_000_000,
          },
        ]);
      }
      return Promise.resolve(undefined);
    });
    const user = userEvent.setup();
    renderApp("/requests");
    await user.click(await screen.findByRole("checkbox", { name: "Pending cancellation review" }));
    expect(await screen.findByText("Synthetic Candidate")).toBeInTheDocument();
    expect(screen.getByText("Scheduled")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("Cancellation requested");
  });
});
