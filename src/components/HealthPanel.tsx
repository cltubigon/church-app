import { useState } from "react";
import styles from "./HealthPanel.module.css";
import { getHealth, type HealthResponse } from "../lib/health";

type HealthState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "success"; value: HealthResponse }
  | { status: "error"; message: string };

export function HealthPanel() {
  const [state, setState] = useState<HealthState>({ status: "idle" });

  function checkHealth() {
    setState({ status: "loading" });
    void getHealth().then((result) => {
      if (result.ok) {
        setState({ status: "success", value: result.value });
      } else {
        setState({
          status: "error",
          message: "The application foundation could not confirm its status. Please try again.",
        });
      }
    });
  }

  return (
    <section aria-labelledby="health-heading" className={styles.health}>
      <h3 id="health-heading">Foundation health</h3>
      <button disabled={state.status === "loading"} onClick={checkHealth} type="button">
        {state.status === "loading" ? "Checking…" : "Check foundation health"}
      </button>
      {state.status === "success" && (
        <div aria-live="polite" role="status">
          <dl className={styles.result}>
            <div>
              <dt>Application</dt>
              <dd>{state.value.applicationName}</dd>
            </div>
            <div>
              <dt>Bootstrap status</dt>
              <dd>{state.value.bootstrapStatus}</dd>
            </div>
            <div>
              <dt>Version</dt>
              <dd>{state.value.applicationVersion}</dd>
            </div>
          </dl>
        </div>
      )}
      {state.status === "error" && (
        <p className={styles.error} role="alert">
          {state.message}
        </p>
      )}
    </section>
  );
}
