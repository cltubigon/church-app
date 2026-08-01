use serde::Serialize;

mod database_freshness_classification;
mod database_key;
mod database_metadata_contract;
mod database_metadata_correspondence;
mod database_metadata_decoding;
mod freshness_anchor_authenticated_envelope;
mod freshness_anchor_authentication_key;
mod freshness_anchor_authentication_key_generation;
mod freshness_anchor_contract;
mod freshness_anchor_plaintext;
mod freshness_anchor_presence;
mod freshness_anchor_protected_key_payload;
mod installation_evidence_authenticated_envelope;
mod installation_evidence_authentication_key;
mod installation_evidence_authentication_key_generation;
pub mod installation_evidence_contract;
mod installation_evidence_persistence;
mod installation_evidence_protection;
pub mod installation_state;
pub mod storage_foundation;

#[cfg(all(test, target_os = "windows"))]
mod sqlcipher_windows_feasibility;

const SAFE_HEALTH_MESSAGE: &str = "The application foundation could not confirm its status.";

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    application_name: String,
    bootstrap_status: &'static str,
    application_version: String,
}

#[derive(Debug, PartialEq, Serialize)]
struct HealthError {
    code: &'static str,
    message: &'static str,
}

fn build_health_response(
    application_name: &str,
    application_version: &str,
) -> Result<HealthResponse, HealthError> {
    if application_name.trim().is_empty() || application_version.trim().is_empty() {
        return Err(HealthError {
            code: "health_unavailable",
            message: SAFE_HEALTH_MESSAGE,
        });
    }
    Ok(HealthResponse {
        application_name: application_name.to_owned(),
        bootstrap_status: "ready",
        application_version: application_version.to_owned(),
    })
}

#[tauri::command]
fn health_check() -> Result<HealthResponse, HealthError> {
    let result = build_health_response("Church App", env!("CARGO_PKG_VERSION"));
    match &result {
        Ok(_) => eprintln!(r#"event="health_check" outcome="success""#),
        Err(error) => eprintln!(
            r#"event="health_check" outcome="error" code="{}""#,
            error.code
        ),
    }
    result
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![health_check])
        .run(tauri::generate_context!())
        .expect("the Church App foundation runtime could not start");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_check_returns_only_safe_bootstrap_metadata() {
        let command_without_frontend_arguments: fn() -> Result<HealthResponse, HealthError> =
            health_check;
        let result = command_without_frontend_arguments().expect("health check should succeed");
        assert_eq!(result.application_name, "Church App");
        assert_eq!(result.bootstrap_status, "ready");
        assert_eq!(result.application_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn health_error_is_stable_and_safe() {
        let error = build_health_response("", "0.1.0").expect_err("empty metadata should fail");
        assert_eq!(error.code, "health_unavailable");
        assert_eq!(error.message, SAFE_HEALTH_MESSAGE);
        assert!(!error.message.contains("path"));
        assert!(!error.message.contains("environment"));
    }
}
