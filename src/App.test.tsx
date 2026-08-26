import { invoke } from "@tauri-apps/api/core";
import { render, screen, waitFor } from "@testing-library/react";
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

  it("renders only a coarse unavailable state when startup status cannot be read", async () => {
    mockedInvoke.mockResolvedValue("sensitive backend detail");
    renderApp();
    expect(await screen.findByText("The application is unavailable.")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("sensitive backend detail");
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });
});
