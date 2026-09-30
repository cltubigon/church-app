import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router";
import styles from "./App.module.css";
import {
  CancellationReviewScreen,
  RequestsScreen,
  SchedulingScreen,
} from "./components/BusinessScreens";
import { HealthPanel } from "./components/HealthPanel";
import { getBusinessFeaturesAvailable } from "./lib/business";
import {
  getMigrationInitiationAvailable,
  getStartupStatus,
  requestFirstTimeSetup,
  requestProductionDatabaseMigration,
  requestPostRecoveryMigrationExecutionConfirmation,
  type StartupStatus,
} from "./lib/startup";

const areas = [
  { label: "Requests", path: "/requests" },
  { label: "Scheduling", path: "/scheduling" },
  { label: "Cancellation Review", path: "/cancellation-review" },
] as const;

function FoundationOverview() {
  return (
    <section aria-labelledby="foundation-heading" className={styles.panel}>
      <p className={styles.eyebrow}>Exact-V2 parish operations</p>
      <h2 id="foundation-heading">Parish request workflows</h2>
      <p>
        Create and schedule service requests, review the live schedule, and decide cancellation
        reviews using the approved workflow areas.
      </p>
      <HealthPanel />
    </section>
  );
}

function UnknownRoute() {
  return (
    <section aria-labelledby="not-found-heading" className={styles.panel}>
      <p className={styles.eyebrow}>Unknown route</p>
      <h2 id="not-found-heading">Page unavailable</h2>
      <p>The requested page is not part of this application foundation.</p>
      <NavLink className={styles.returnLink} to="/">
        Return to foundation overview
      </NavLink>
    </section>
  );
}

interface StartupBoundaryProps {
  migrationConfirmationError: string | null;
  migrationConfirmationPending: boolean;
  onRequestMigrationConfirmation: () => void;
  onRequestSetup: () => void;
  setupError: string | null;
  setupRequestPending: boolean;
  status: Exclude<StartupStatus, "ready">;
}

function StartupBoundary({
  migrationConfirmationError,
  migrationConfirmationPending,
  onRequestMigrationConfirmation,
  onRequestSetup,
  setupError,
  setupRequestPending,
  status,
}: StartupBoundaryProps) {
  const content = {
    starting: "Preparing the application securely. This may take some time.",
    unavailable: "The application is unavailable.",
    setupInProgress: "First-time setup is in progress.",
    setupRestartRequired: "First-time setup is complete. Restart the application to continue.",
    stopping: "The application is stopping.",
    shutdownIncomplete: "The application could not complete shutdown.",
    twoCompleteRecoverySetsVerifiedAwaitingMigrationExecution:
      "Both recovery sets are verified. Migration execution is awaiting your confirmation.",
    migrationExecutionConfirmedAwaitingWritablePreparation:
      "Migration execution is confirmed. Writable migration preparation has not begun.",
    writableV1MigrationPreparedAwaitingTransaction:
      "The writable V1 migration database is prepared and verified. The migration transaction has not begun.",
    migrationCommittedRestartRequired: "Migration completed. Restart required.",
    migrationFailedRestartRequired:
      "Migration could not be confirmed as complete. Restart is required before further action.",
  }[status];

  return (
    <main className={styles.main}>
      <section aria-live="polite" className={styles.panel}>
        <h1>Church App</h1>
        <p>{content}</p>
        {status === "unavailable" && (
          <div aria-busy={setupRequestPending} className={styles.setupAction}>
            <p>Use this only to set up Church App for the first time.</p>
            <button disabled={setupRequestPending} onClick={onRequestSetup} type="button">
              {setupRequestPending ? "Starting first-time setup…" : "Set up Church App"}
            </button>
            {setupError !== null && <p role="alert">{setupError}</p>}
          </div>
        )}
        {status === "twoCompleteRecoverySetsVerifiedAwaitingMigrationExecution" && (
          <div aria-busy={migrationConfirmationPending} className={styles.setupAction}>
            <p>Review the trusted Windows confirmation before authorizing the future migration.</p>
            <button
              disabled={migrationConfirmationPending}
              onClick={onRequestMigrationConfirmation}
              type="button"
            >
              {migrationConfirmationPending
                ? "Opening migration confirmation…"
                : "Confirm migration authorization"}
            </button>
            {migrationConfirmationError !== null && (
              <p role="alert">{migrationConfirmationError}</p>
            )}
          </div>
        )}
      </section>
    </main>
  );
}

export function App() {
  const [startupStatus, setStartupStatus] = useState<StartupStatus>("starting");
  const [statusRefreshKey, setStatusRefreshKey] = useState(0);
  const [setupRequestPending, setSetupRequestPending] = useState(false);
  const [setupError, setSetupError] = useState<string | null>(null);
  const [migrationConfirmationPending, setMigrationConfirmationPending] = useState(false);
  const [migrationConfirmationError, setMigrationConfirmationError] = useState<string | null>(null);
  const [businessFeaturesAvailable, setBusinessFeaturesAvailable] = useState<boolean | null>(null);
  const [migrationInitiationAvailable, setMigrationInitiationAvailable] = useState<boolean | null>(
    null,
  );
  const [migrationInitiationPending, setMigrationInitiationPending] = useState(false);
  const [migrationInitiationError, setMigrationInitiationError] = useState<string | null>(null);

  useEffect(() => {
    void statusRefreshKey;
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const refresh = async () => {
      const status = await getStartupStatus();
      if (!active) return;
      setStartupStatus(status);
      if (
        status === "starting" ||
        status === "ready" ||
        status === "setupInProgress" ||
        status === "twoCompleteRecoverySetsVerifiedAwaitingMigrationExecution" ||
        status === "writableV1MigrationPreparedAwaitingTransaction" ||
        status === "stopping"
      ) {
        timer = setTimeout(refresh, 500);
      }
    };

    void refresh();
    return () => {
      active = false;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [statusRefreshKey]);

  useEffect(() => {
    if (startupStatus !== "unavailable") setSetupError(null);
    if (startupStatus !== "twoCompleteRecoverySetsVerifiedAwaitingMigrationExecution") {
      setMigrationConfirmationError(null);
    }
  }, [startupStatus]);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    if (startupStatus !== "ready") {
      setBusinessFeaturesAvailable(null);
      setMigrationInitiationAvailable(null);
      return () => {
        active = false;
      };
    }
    const refreshCapabilities = async () => {
      const [businessAvailable, migrationAvailable] = await Promise.all([
        getBusinessFeaturesAvailable(),
        getMigrationInitiationAvailable(),
      ]);
      if (!active) return;
      setBusinessFeaturesAvailable(businessAvailable);
      setMigrationInitiationAvailable(migrationAvailable);
      if (!businessAvailable) timer = setTimeout(refreshCapabilities, 500);
    };
    void refreshCapabilities();
    return () => {
      active = false;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [startupStatus]);

  async function requestSetup() {
    if (setupRequestPending) return;

    setSetupRequestPending(true);
    setSetupError(null);
    const result = await requestFirstTimeSetup();
    if (result === "unavailable") {
      setSetupError("First-time setup could not be started.");
    }
    setStatusRefreshKey((key) => key + 1);
    setSetupRequestPending(false);
  }

  async function requestMigrationConfirmation() {
    if (migrationConfirmationPending) return;

    setMigrationConfirmationPending(true);
    setMigrationConfirmationError(null);
    const result = await requestPostRecoveryMigrationExecutionConfirmation();
    if (result === "unavailable") {
      setMigrationConfirmationError("Migration confirmation could not be opened.");
    }
    setStatusRefreshKey((key) => key + 1);
    setMigrationConfirmationPending(false);
  }

  async function requestMigrationInitiation() {
    if (migrationInitiationPending) return;

    setMigrationInitiationPending(true);
    setMigrationInitiationError(null);
    const result = await requestProductionDatabaseMigration();
    if (result === "unavailable") {
      setMigrationInitiationError("Database upgrade preparation could not be started.");
    }
    setStatusRefreshKey((key) => key + 1);
    setMigrationInitiationPending(false);
  }

  if (startupStatus !== "ready") {
    return (
      <StartupBoundary
        migrationConfirmationError={migrationConfirmationError}
        migrationConfirmationPending={migrationConfirmationPending}
        onRequestMigrationConfirmation={() => void requestMigrationConfirmation()}
        onRequestSetup={() => void requestSetup()}
        setupError={setupError}
        setupRequestPending={setupRequestPending}
        status={startupStatus}
      />
    );
  }

  if (businessFeaturesAvailable === null || migrationInitiationAvailable === null) {
    return (
      <main className={styles.main}>
        <section className={styles.panel}>
          <h1>Church App</h1>
          <p>Preparing parish workflows…</p>
        </section>
      </main>
    );
  }

  if (!businessFeaturesAvailable) {
    return (
      <main className={styles.main}>
        <section className={styles.panel}>
          <h1>Church App</h1>
          <p>Parish workflows are unavailable for this database.</p>
          {migrationInitiationAvailable && (
            <div aria-busy={migrationInitiationPending} className={styles.setupAction}>
              <p>A protected database upgrade is required before parish workflows can be used.</p>
              <button
                disabled={migrationInitiationPending}
                onClick={() => void requestMigrationInitiation()}
                type="button"
              >
                {migrationInitiationPending
                  ? "Preparing database upgrade…"
                  : "Prepare database upgrade"}
              </button>
              {migrationInitiationError !== null && <p role="alert">{migrationInitiationError}</p>}
            </div>
          )}
        </section>
      </main>
    );
  }

  return (
    <div className={styles.app}>
      <a className={styles.skipLink} href="#main-content">
        Skip to main content
      </a>
      <header className={styles.header}>
        <p className={styles.kicker}>Parish operations</p>
        <h1>Church App</h1>
        <p className={styles.subtitle}>Requests, scheduling, and cancellation review</p>
      </header>
      <nav aria-label="Staff areas" className={styles.navigation}>
        <ul>
          {areas.map((area) => (
            <li key={area.path}>
              <NavLink
                className={({ isActive }) => (isActive ? styles.activeLink : styles.navLink)}
                to={area.path}
              >
                {area.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <main className={styles.main} id="main-content">
        <Routes>
          <Route element={<FoundationOverview />} path="/" />
          <Route element={<RequestsScreen />} path="/requests" />
          <Route element={<SchedulingScreen />} path="/scheduling" />
          <Route element={<CancellationReviewScreen />} path="/cancellation-review" />
          <Route element={<UnknownRoute />} path="*" />
        </Routes>
      </main>
      <footer className={styles.footer}>
        Exact-V2 business workflows. Times are shown in Asia/Manila.
      </footer>
    </div>
  );
}
