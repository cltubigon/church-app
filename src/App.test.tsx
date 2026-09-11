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
    mockedInvoke.mockResolvedValue("ready");
  });

  it("renders an accessible unfinished shell with only approved area links", async () => {
    renderApp();
    expect(await screen.findByRole("banner")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: "Church App" })).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.getByRole("contentinfo")).toBeInTheDocument();
    expect(screen.getByText("Unfinished application foundation")).toBeInTheDocument();
    const navigation = screen.getByRole("navigation", { name: "Staff area placeholders" });
    for (const name of ["Requests", "Schedule", "Permanent Records", "Requirements"]) {
      expect(navigation).toContainElement(screen.getByRole("link", { name }));
    }
    expect(navigation.querySelectorAll("a")).toHaveLength(4);
  });

  it("supports keyboard placeholder navigation", async () => {
    const user = userEvent.setup();
    renderApp();
    await screen.findByRole("banner");
    await user.tab();
    expect(screen.getByRole("link", { name: "Skip to main content" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("link", { name: "Requests" })).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("heading", { level: 2, name: "Requests" })).toBeInTheDocument();
    expect(
      screen.getByText("Requests is unavailable and has not yet been implemented."),
    ).toBeInTheDocument();
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
    ["ready", "Unfinished application foundation"],
    ["setupInProgress", "First-time setup is in progress."],
    [
      "setupRestartRequired",
      "First-time setup is complete. Restart the application to continue.",
    ],
    ["stopping", "The application is stopping."],
    ["shutdownIncomplete", "The application could not complete shutdown."],
  ])("does not offer first-time setup while startup status is %s", async (status, message) => {
    mockedInvoke.mockResolvedValue(status);
    renderApp();
    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Set up Church App" })).not.toBeInTheDocument();
    if (status === "ready") {
      expect(screen.getByRole("navigation", { name: "Staff area placeholders" })).toBeInTheDocument();
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
        return Promise.resolve(
          startupReadCount === 1 ? "unavailable" : "setupRestartRequired",
        );
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
});
