import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router";
import styles from "./App.module.css";
import { HealthPanel } from "./components/HealthPanel";
import { getStartupStatus, type StartupStatus } from "./lib/startup";

const areas = [
  { label: "Requests", path: "/requests" },
  { label: "Schedule", path: "/schedule" },
  { label: "Permanent Records", path: "/permanent-records" },
  { label: "Requirements", path: "/requirements" },
] as const;

function FoundationOverview() {
  return (
    <section aria-labelledby="foundation-heading" className={styles.panel}>
      <p className={styles.eyebrow}>Initial repository bootstrap</p>
      <h2 id="foundation-heading">Unfinished application foundation</h2>
      <p>
        This shell confirms the desktop foundation only. Parish workflows and data storage are not
        implemented, and no real parish data should be entered.
      </p>
      <HealthPanel />
    </section>
  );
}

function Placeholder({ area }: { area: (typeof areas)[number]["label"] }) {
  return (
    <section aria-labelledby="placeholder-heading" className={styles.panel}>
      <p className={styles.eyebrow}>Placeholder area</p>
      <h2 id="placeholder-heading">{area}</h2>
      <p>{area} is unavailable and has not yet been implemented.</p>
      <p>This page does not accept, store, or simulate parish data.</p>
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

function StartupBoundary({ status }: { status: Exclude<StartupStatus, "ready"> }) {
  const content = {
    starting: "Preparing the application securely. This may take some time.",
    unavailable: "The application is unavailable.",
    stopping: "The application is stopping.",
    shutdownIncomplete: "The application could not complete shutdown.",
  }[status];

  return (
    <main className={styles.main}>
      <section aria-live="polite" className={styles.panel}>
        <h1>Church App</h1>
        <p>{content}</p>
      </section>
    </main>
  );
}

export function App() {
  const [startupStatus, setStartupStatus] = useState<StartupStatus>("starting");

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const refresh = async () => {
      const status = await getStartupStatus();
      if (!active) return;
      setStartupStatus(status);
      if (status === "starting" || status === "ready" || status === "stopping") {
        timer = setTimeout(refresh, 500);
      }
    };

    void refresh();
    return () => {
      active = false;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, []);

  if (startupStatus !== "ready") return <StartupBoundary status={startupStatus} />;

  return (
    <div className={styles.app}>
      <a className={styles.skipLink} href="#main-content">
        Skip to main content
      </a>
      <header className={styles.header}>
        <p className={styles.kicker}>Windows desktop foundation</p>
        <h1>Church App</h1>
        <p className={styles.subtitle}>An unfinished, non-production application shell</p>
      </header>
      <nav aria-label="Staff area placeholders" className={styles.navigation}>
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
          {areas.map((area) => (
            <Route element={<Placeholder area={area.label} />} key={area.path} path={area.path} />
          ))}
          <Route element={<UnknownRoute />} path="*" />
        </Routes>
      </main>
      <footer className={styles.footer}>
        Foundation status only. No parish workflow is available.
      </footer>
    </div>
  );
}
