import { invoke } from "@tauri-apps/api/core";

export interface HealthResponse {
  applicationName: string;
  bootstrapStatus: "ready";
  applicationVersion: string;
}

export interface HealthCommandError {
  code: "health_unavailable";
  message: string;
}

export type HealthResult =
  | { ok: true; value: HealthResponse }
  | { error: HealthCommandError; ok: false };

function isHealthResponse(value: unknown): value is HealthResponse {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.applicationName === "string" &&
    candidate.bootstrapStatus === "ready" &&
    typeof candidate.applicationVersion === "string"
  );
}

function safeError(): HealthCommandError {
  return {
    code: "health_unavailable",
    message: "The application foundation could not confirm its status.",
  };
}

export async function getHealth(): Promise<HealthResult> {
  try {
    const response: unknown = await invoke("health_check");
    if (!isHealthResponse(response)) throw safeError();
    return { ok: true, value: response };
  } catch {
    console.error(
      JSON.stringify({ event: "health_check", outcome: "error", code: "health_unavailable" }),
    );
    return { error: safeError(), ok: false };
  }
}
