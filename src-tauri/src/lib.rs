use serde::Serialize;

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
    let result = build_health_response("Church App Foundation", env!("CARGO_PKG_VERSION"));
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
        let result = health_check().expect("health check should succeed");
        assert_eq!(result.application_name, "Church App Foundation");
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
