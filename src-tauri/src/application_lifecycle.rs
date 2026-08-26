//! Rust-owned application startup and orderly-shutdown orchestration.
//!
//! The frontend can observe only [`StartupStatus`]. All database authority and
//! ownership-bearing failures remain in this module.

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use serde::Serialize;
use tauri::{AppHandle, Manager};

#[cfg(windows)]
use crate::{
    database_key_active_wrapper_loader::load_active_database_key_wrapper,
    database_key_presence::inspect_database_key_active_presence,
    installation_evidence_persistence::observe_production_installation_evidence,
    installation_evidence_protection::{
        bind_database_key_candidate_to_trusted_installation_evidence,
        load_trusted_current_installation_evidence_assessment,
        observe_normalized_current_freshness_anchor,
        recover_database_key_candidate_from_loaded_wrapper,
    },
    installation_state::{ExpectedStorageEvidence, InstallationEvidence},
    production_database_connection_handoff::{
        DatabaseEvidenceCorrespondenceValidationCloseFailure,
        DatabaseEvidenceCorrespondenceValidationOutcome,
        LiveMetadataAndHeaderValidationCloseFailure, LiveMetadataAndHeaderValidationOutcome,
        OperationalProductionDatabase, ProductionDatabaseConnectionCloseOutcome,
        ProductionDatabaseConnectionConstructionCloseFailure,
        ProductionDatabaseFreshnessValidationCloseFailure,
        ProductionDatabaseFreshnessValidationOutcome,
        ProductionDatabaseStartupAuthorizationCloseFailure,
        ProductionDatabaseStartupAuthorizationOutcome, ProductionDatabaseValidationCloseFailure,
        ProductionDatabaseValidationOutcome, activate_production_database_for_operational_use,
        authorize_production_database_startup, open_keyed_production_database_read_only,
        validate_production_database_evidence_correspondence,
        validate_production_database_freshness,
        validate_production_database_live_metadata_and_headers,
        validate_production_database_readability_and_integrity,
    },
    production_database_file::{ProductionDatabaseInspection, inspect_production_database_file},
    storage_foundation::{
        DatabaseKeyPersistencePaths, FreshnessAnchorPersistencePaths,
        InstallationEvidencePersistencePaths, ProductionDatabasePath,
        database_key_persistence_paths, freshness_anchor_persistence_paths,
        installation_evidence_persistence_paths, production_database_path,
    },
};

#[cfg(all(windows, debug_assertions))]
use crate::manual_startup_debug_support::{
    ManualStartupPauseOutcome, pause_before_final_installation_observation, select_startup_root,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum StartupStatus {
    Starting,
    Ready,
    Unavailable,
    Stopping,
    ShutdownIncomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoarseStartupFailure {
    StartupUnavailable,
    StartupInterrupted,
}

enum LifecycleState<Operational, CloseFailure> {
    NotStarted,
    Starting,
    Ready(Operational),
    Failed(CoarseStartupFailure),
    Stopping,
    CloseRetryRequired(CloseFailure),
}

impl<Operational, CloseFailure> LifecycleState<Operational, CloseFailure> {
    fn status(&self) -> StartupStatus {
        match self {
            Self::NotStarted | Self::Starting => StartupStatus::Starting,
            Self::Ready(_) => StartupStatus::Ready,
            Self::Failed(_) => StartupStatus::Unavailable,
            Self::Stopping => StartupStatus::Stopping,
            Self::CloseRetryRequired(_) => StartupStatus::ShutdownIncomplete,
        }
    }

    fn reserve_startup(&mut self) -> bool {
        if matches!(self, Self::NotStarted) {
            *self = Self::Starting;
            true
        } else {
            false
        }
    }

    fn shutdown_pending(&self) -> bool {
        !matches!(self, Self::Starting)
    }

    fn begin_shutdown(&mut self) -> ShutdownAction<Operational> {
        match std::mem::replace(self, Self::Stopping) {
            Self::NotStarted => {
                *self = Self::Failed(CoarseStartupFailure::StartupInterrupted);
                ShutdownAction::Exit
            }
            Self::Starting => ShutdownAction::WaitForStartup,
            Self::Ready(owner) => ShutdownAction::Close(owner),
            Self::Failed(failure) => {
                *self = Self::Failed(failure);
                ShutdownAction::Exit
            }
            Self::Stopping => ShutdownAction::WaitForStartup,
            Self::CloseRetryRequired(failure) => {
                *self = Self::CloseRetryRequired(failure);
                ShutdownAction::Blocked
            }
        }
    }

    fn finish_startup(
        &mut self,
        result: StartupWorkerResult<Operational, CloseFailure>,
    ) -> StartupCompletion<Operational> {
        match (&self, result) {
            (Self::Starting, StartupWorkerResult::Ready(owner)) => {
                *self = Self::Ready(owner);
                StartupCompletion::ReadyInstalled
            }
            (Self::Starting, StartupWorkerResult::Failed(failure)) => {
                *self = Self::Failed(failure);
                StartupCompletion::FinishedWithoutOwner {
                    shutdown_requested: false,
                }
            }
            (Self::Starting, StartupWorkerResult::CloseRetryRequired(failure)) => {
                *self = Self::CloseRetryRequired(failure);
                StartupCompletion::ShutdownIncomplete
            }
            (Self::Stopping, StartupWorkerResult::Ready(owner)) => {
                StartupCompletion::CloseLateOwner(owner)
            }
            (Self::Stopping, StartupWorkerResult::Failed(_)) => {
                *self = Self::Failed(CoarseStartupFailure::StartupInterrupted);
                StartupCompletion::FinishedWithoutOwner {
                    shutdown_requested: true,
                }
            }
            (Self::Stopping, StartupWorkerResult::CloseRetryRequired(failure)) => {
                *self = Self::CloseRetryRequired(failure);
                StartupCompletion::ShutdownIncomplete
            }
            (_, StartupWorkerResult::Ready(owner)) => StartupCompletion::CloseLateOwner(owner),
            (_, StartupWorkerResult::Failed(_)) => StartupCompletion::StaleResultIgnored,
            (_, StartupWorkerResult::CloseRetryRequired(failure)) => {
                *self = Self::CloseRetryRequired(failure);
                StartupCompletion::ShutdownIncomplete
            }
        }
    }

    fn finish_close(&mut self, failure: Option<CloseFailure>) {
        *self = match failure {
            Some(failure) => Self::CloseRetryRequired(failure),
            None => Self::Failed(CoarseStartupFailure::StartupInterrupted),
        };
    }
}

enum ShutdownAction<Operational> {
    Exit,
    WaitForStartup,
    Close(Operational),
    Blocked,
}

enum StartupWorkerResult<Operational, CloseFailure> {
    Ready(Operational),
    Failed(CoarseStartupFailure),
    CloseRetryRequired(CloseFailure),
}

enum StartupCompletion<Operational> {
    ReadyInstalled,
    CloseLateOwner(Operational),
    FinishedWithoutOwner { shutdown_requested: bool },
    ShutdownIncomplete,
    StaleResultIgnored,
}

#[cfg(windows)]
enum RetainedCloseFailure {
    Construction(ProductionDatabaseConnectionConstructionCloseFailure),
    Validation(ProductionDatabaseValidationCloseFailure),
    Metadata(LiveMetadataAndHeaderValidationCloseFailure),
    Correspondence(DatabaseEvidenceCorrespondenceValidationCloseFailure),
    Freshness(ProductionDatabaseFreshnessValidationCloseFailure),
    Authorization(ProductionDatabaseStartupAuthorizationCloseFailure),
    Operational(
        crate::production_database_connection_handoff::ProductionDatabaseConnectionCloseFailure,
    ),
}

#[cfg(windows)]
impl fmt::Debug for RetainedCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Construction(failure) => retain_redacted(failure),
            Self::Validation(failure) => retain_redacted(failure),
            Self::Metadata(failure) => retain_redacted(failure),
            Self::Correspondence(failure) => retain_redacted(failure),
            Self::Freshness(failure) => retain_redacted(failure),
            Self::Authorization(failure) => retain_redacted(failure),
            Self::Operational(failure) => retain_redacted(failure),
        }
        formatter.write_str("RetainedCloseFailure([REDACTED])")
    }
}

#[cfg(windows)]
fn retain_redacted<T>(retained: &T) {
    let _ = std::mem::size_of_val(retained);
}

#[cfg(not(windows))]
type OperationalProductionDatabase = ();
#[cfg(not(windows))]
struct RetainedCloseFailure;

struct LifecycleInner {
    state: LifecycleState<OperationalProductionDatabase, RetainedCloseFailure>,
    startup_worker: Option<tauri::async_runtime::JoinHandle<()>>,
    close_worker: Option<tauri::async_runtime::JoinHandle<()>>,
    startup_work_resolved: bool,
    close_work_resolved: bool,
}

pub(crate) struct ApplicationLifecycle {
    inner: Mutex<LifecycleInner>,
}

impl ApplicationLifecycle {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(LifecycleInner {
                state: LifecycleState::NotStarted,
                startup_worker: None,
                close_worker: None,
                startup_work_resolved: false,
                close_work_resolved: true,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, LifecycleInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn status(&self) -> StartupStatus {
        self.lock().state.status()
    }

    fn shutdown_pending(&self) -> bool {
        self.lock().state.shutdown_pending()
    }

    pub(crate) fn start(self: &Arc<Self>, app: AppHandle) {
        {
            let mut inner = self.lock();
            if !inner.state.reserve_startup() {
                return;
            }
            inner.startup_work_resolved = false;
        }
        eprintln!(r#"event="application_startup" outcome="reserved""#);

        let lifecycle = Arc::clone(self);
        let worker_app = app.clone();
        let worker = tauri::async_runtime::spawn_blocking(move || {
            eprintln!(r#"event="application_startup" outcome="worker_started""#);
            let result = run_production_startup(&worker_app, &lifecycle);
            lifecycle.complete_startup(result, &worker_app);
        });
        self.lock().startup_worker = Some(worker);
    }

    fn complete_startup(
        self: &Arc<Self>,
        result: StartupWorkerResult<OperationalProductionDatabase, RetainedCloseFailure>,
        app: &AppHandle,
    ) {
        let completion = {
            let mut inner = self.lock();
            let completion = inner.state.finish_startup(result);
            inner.startup_work_resolved = true;
            completion
        };
        eprintln!(r#"event="application_startup" outcome="worker_completed""#);

        match completion {
            StartupCompletion::ReadyInstalled => {
                eprintln!(r#"event="application_startup" outcome="ready_installed""#);
            }
            StartupCompletion::CloseLateOwner(owner) => {
                eprintln!(r#"event="application_shutdown" outcome="late_owner_close_attempted""#);
                self.close_on_worker(owner, app.clone());
            }
            StartupCompletion::FinishedWithoutOwner { shutdown_requested } => {
                eprintln!(r#"event="application_startup" outcome="unavailable""#);
                if shutdown_requested {
                    app.exit(0);
                }
            }
            StartupCompletion::ShutdownIncomplete => {
                eprintln!(r#"event="application_shutdown" outcome="close_failed""#);
            }
            StartupCompletion::StaleResultIgnored => {}
        }
    }

    pub(crate) fn request_shutdown(self: &Arc<Self>, app: AppHandle) {
        let action = {
            let mut inner = self.lock();
            inner.state.begin_shutdown()
        };
        eprintln!(r#"event="application_shutdown" outcome="requested""#);
        match action {
            ShutdownAction::Exit => app.exit(0),
            ShutdownAction::WaitForStartup => {
                eprintln!(r#"event="application_shutdown" outcome="pending""#);
            }
            ShutdownAction::Close(owner) => self.close_on_worker(owner, app),
            ShutdownAction::Blocked => {}
        }
    }

    fn close_on_worker(self: &Arc<Self>, owner: OperationalProductionDatabase, app: AppHandle) {
        {
            let mut inner = self.lock();
            if inner.close_worker.is_some() || !inner.close_work_resolved {
                return;
            }
            inner.close_work_resolved = false;
        }
        let lifecycle = Arc::clone(self);
        let worker = tauri::async_runtime::spawn_blocking(move || {
            eprintln!(r#"event="application_shutdown" outcome="close_attempted""#);
            let failure = close_operational(owner);
            {
                let mut inner = lifecycle.lock();
                inner.state.finish_close(failure);
                inner.close_work_resolved = true;
            }
            if lifecycle.status() == StartupStatus::ShutdownIncomplete {
                eprintln!(r#"event="application_shutdown" outcome="close_failed""#);
            } else {
                eprintln!(r#"event="application_shutdown" outcome="close_succeeded""#);
                app.exit(0);
            }
        });
        self.lock().close_worker = Some(worker);
    }

    pub(crate) fn may_exit(&self) -> bool {
        let inner = self.lock();
        inner.startup_work_resolved
            && inner.close_work_resolved
            && matches!(inner.state, LifecycleState::Failed(_))
    }

    pub(crate) fn join_workers(&self) {
        let (startup, close) = {
            let mut inner = self.lock();
            (inner.startup_worker.take(), inner.close_worker.take())
        };
        if let Some(worker) = startup {
            let _ = tauri::async_runtime::block_on(worker);
        }
        if let Some(worker) = close {
            let _ = tauri::async_runtime::block_on(worker);
        }
    }
}

#[cfg(windows)]
fn close_operational(owner: OperationalProductionDatabase) -> Option<RetainedCloseFailure> {
    match owner.close() {
        ProductionDatabaseConnectionCloseOutcome::Closed => None,
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            Some(RetainedCloseFailure::Operational(failure))
        }
    }
}

#[cfg(not(windows))]
fn close_operational(_: OperationalProductionDatabase) -> Option<RetainedCloseFailure> {
    None
}

#[cfg(windows)]
fn run_production_startup(
    app: &AppHandle,
    lifecycle: &ApplicationLifecycle,
) -> StartupWorkerResult<OperationalProductionDatabase, RetainedCloseFailure> {
    let unavailable = || StartupWorkerResult::Failed(CoarseStartupFailure::StartupUnavailable);
    let interrupted = || StartupWorkerResult::Failed(CoarseStartupFailure::StartupInterrupted);

    let paths = match StartupPaths::from_app(app) {
        Ok(paths) => paths,
        Err(_) => return unavailable(),
    };
    let StartupPaths {
        evidence: evidence_paths,
        database_key: key_paths,
        freshness_anchor: anchor_paths,
        database: database_path,
        #[cfg(debug_assertions)]
            pause_before_final_installation_observation: pause_requested,
    } = paths;
    if lifecycle.shutdown_pending() {
        return interrupted();
    }

    let early_installation_evidence = observe_production_installation_evidence(&evidence_paths);
    if lifecycle.shutdown_pending() {
        return interrupted();
    }
    if !is_initialized_with_expected_storage(&early_installation_evidence) {
        return unavailable();
    }

    let trusted_assessment =
        match load_trusted_current_installation_evidence_assessment(&evidence_paths) {
            Ok(assessment) => assessment,
            Err(_) => return unavailable(),
        };
    let anchor_observation = observe_normalized_current_freshness_anchor(
        &anchor_paths,
        trusted_assessment.trusted_identity(),
    );
    let key_presence = inspect_database_key_active_presence(&key_paths);
    let loaded_key = match load_active_database_key_wrapper(&key_paths, key_presence) {
        Ok(key) => key,
        Err(_) => return unavailable(),
    };
    let key_candidate = match recover_database_key_candidate_from_loaded_wrapper(&loaded_key) {
        Ok(candidate) => candidate,
        Err(_) => return unavailable(),
    };
    let key = match bind_database_key_candidate_to_trusted_installation_evidence(
        key_candidate,
        &trusted_assessment,
    ) {
        Ok(key) => key,
        Err(_) => return unavailable(),
    };
    if lifecycle.shutdown_pending() {
        return interrupted();
    }

    let inspected = match inspect_production_database_file(&database_path) {
        ProductionDatabaseInspection::Present(inspected) => inspected,
        ProductionDatabaseInspection::Missing
        | ProductionDatabaseInspection::Unavailable
        | ProductionDatabaseInspection::Invalid => return unavailable(),
    };
    let opened = match open_keyed_production_database_read_only(database_path, inspected, key) {
        Ok(opened) => opened,
        Err(crate::production_database_connection_handoff::ProductionDatabaseConnectionOpenError::Failed) => {
            return unavailable();
        }
        Err(crate::production_database_connection_handoff::ProductionDatabaseConnectionOpenError::CloseFailed(failure)) => {
            return StartupWorkerResult::CloseRetryRequired(RetainedCloseFailure::Construction(failure));
        }
    };
    if lifecycle.shutdown_pending() {
        return close_interrupted_owner(opened);
    }

    let validated = match validate_production_database_readability_and_integrity(opened) {
        ProductionDatabaseValidationOutcome::Validated(owner) => owner,
        ProductionDatabaseValidationOutcome::Failed(_) => return unavailable(),
        ProductionDatabaseValidationOutcome::CloseFailed(failure) => {
            return StartupWorkerResult::CloseRetryRequired(RetainedCloseFailure::Validation(
                failure,
            ));
        }
    };
    if lifecycle.shutdown_pending() {
        return close_interrupted_owner(validated);
    }

    let metadata = match validate_production_database_live_metadata_and_headers(validated) {
        LiveMetadataAndHeaderValidationOutcome::Validated(owner) => owner,
        LiveMetadataAndHeaderValidationOutcome::Failed(_) => return unavailable(),
        LiveMetadataAndHeaderValidationOutcome::CloseFailed(failure) => {
            return StartupWorkerResult::CloseRetryRequired(RetainedCloseFailure::Metadata(
                failure,
            ));
        }
    };
    if lifecycle.shutdown_pending() {
        return close_interrupted_owner(metadata);
    }

    let correspondence =
        match validate_production_database_evidence_correspondence(metadata, trusted_assessment) {
            DatabaseEvidenceCorrespondenceValidationOutcome::Validated(owner) => owner,
            DatabaseEvidenceCorrespondenceValidationOutcome::Mismatch(_) => return unavailable(),
            DatabaseEvidenceCorrespondenceValidationOutcome::CloseFailed(failure) => {
                return StartupWorkerResult::CloseRetryRequired(
                    RetainedCloseFailure::Correspondence(failure),
                );
            }
        };
    if lifecycle.shutdown_pending() {
        return close_interrupted_owner(correspondence);
    }

    let fresh = match validate_production_database_freshness(correspondence, anchor_observation) {
        ProductionDatabaseFreshnessValidationOutcome::Validated(owner) => owner,
        ProductionDatabaseFreshnessValidationOutcome::Failed(_) => return unavailable(),
        ProductionDatabaseFreshnessValidationOutcome::CloseFailed(failure) => {
            return StartupWorkerResult::CloseRetryRequired(RetainedCloseFailure::Freshness(
                failure,
            ));
        }
    };
    if lifecycle.shutdown_pending() {
        return close_interrupted_owner(fresh);
    }

    #[cfg(debug_assertions)]
    if pause_requested {
        if pause_before_final_installation_observation() != ManualStartupPauseOutcome::Resumed {
            return close_unavailable_owner(fresh);
        }
        if lifecycle.shutdown_pending() {
            return close_interrupted_owner(fresh);
        }
    }

    let final_installation_evidence = observe_production_installation_evidence(&evidence_paths);
    if lifecycle.shutdown_pending() {
        return close_interrupted_owner(fresh);
    }
    if !is_initialized_with_expected_storage(&final_installation_evidence) {
        return close_unavailable_owner(fresh);
    }

    let authorized = match authorize_production_database_startup(fresh, final_installation_evidence)
    {
        ProductionDatabaseStartupAuthorizationOutcome::Authorized(owner) => owner,
        ProductionDatabaseStartupAuthorizationOutcome::Failed(_) => return unavailable(),
        ProductionDatabaseStartupAuthorizationOutcome::CloseFailed(failure) => {
            return StartupWorkerResult::CloseRetryRequired(RetainedCloseFailure::Authorization(
                failure,
            ));
        }
    };
    if lifecycle.shutdown_pending() {
        return close_interrupted_owner(authorized);
    }

    StartupWorkerResult::Ready(activate_production_database_for_operational_use(authorized))
}

#[cfg(windows)]
struct StartupPaths {
    evidence: InstallationEvidencePersistencePaths,
    database_key: DatabaseKeyPersistencePaths,
    freshness_anchor: FreshnessAnchorPersistencePaths,
    database: ProductionDatabasePath,
    #[cfg(debug_assertions)]
    pause_before_final_installation_observation: bool,
}

#[cfg(windows)]
impl StartupPaths {
    fn from_app(app: &AppHandle) -> Result<Self, ()> {
        let canonical_root = app.path().app_local_data_dir().map_err(|_| ())?;
        #[cfg(debug_assertions)]
        {
            let selection = select_startup_root(canonical_root).map_err(|_| ())?;
            Ok(Self::from_root(
                selection.root(),
                selection.pause_before_final_installation_observation(),
            ))
        }
        #[cfg(not(debug_assertions))]
        {
            Ok(Self::from_root(&canonical_root))
        }
    }

    #[cfg(debug_assertions)]
    fn from_root(
        root: &std::path::Path,
        pause_before_final_installation_observation: bool,
    ) -> Self {
        Self {
            evidence: installation_evidence_persistence_paths(root),
            database_key: database_key_persistence_paths(root),
            freshness_anchor: freshness_anchor_persistence_paths(root),
            database: production_database_path(root.to_path_buf()),
            pause_before_final_installation_observation,
        }
    }

    #[cfg(not(debug_assertions))]
    fn from_root(root: &std::path::Path) -> Self {
        Self {
            evidence: installation_evidence_persistence_paths(root),
            database_key: database_key_persistence_paths(root),
            freshness_anchor: freshness_anchor_persistence_paths(root),
            database: production_database_path(root.to_path_buf()),
        }
    }
}

#[cfg(windows)]
fn is_initialized_with_expected_storage(evidence: &InstallationEvidence) -> bool {
    matches!(
        evidence,
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Present)
    )
}

#[cfg(windows)]
fn close_unavailable_owner<T>(
    owner: T,
) -> StartupWorkerResult<OperationalProductionDatabase, RetainedCloseFailure>
where
    T: CanonicallyClosable,
{
    match owner.close_canonically() {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            StartupWorkerResult::Failed(CoarseStartupFailure::StartupUnavailable)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            StartupWorkerResult::CloseRetryRequired(RetainedCloseFailure::Operational(failure))
        }
    }
}

#[cfg(windows)]
fn close_interrupted_owner<T>(
    owner: T,
) -> StartupWorkerResult<OperationalProductionDatabase, RetainedCloseFailure>
where
    T: CanonicallyClosable,
{
    match owner.close_canonically() {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            StartupWorkerResult::Failed(CoarseStartupFailure::StartupInterrupted)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            StartupWorkerResult::CloseRetryRequired(RetainedCloseFailure::Operational(failure))
        }
    }
}

#[cfg(windows)]
trait CanonicallyClosable {
    fn close_canonically(self) -> ProductionDatabaseConnectionCloseOutcome;
}

#[cfg(windows)]
macro_rules! canonical_close {
    ($($owner:ty),+ $(,)?) => {
        $(impl CanonicallyClosable for $owner {
            fn close_canonically(self) -> ProductionDatabaseConnectionCloseOutcome { self.close() }
        })+
    };
}

#[cfg(windows)]
canonical_close!(
    crate::production_database_connection_handoff::ProductionReadOnlyDatabaseConnection,
    crate::production_database_connection_handoff::ReadabilityAndIntegrityValidatedProductionDatabaseConnection,
    crate::production_database_connection_handoff::LiveMetadataAndHeaderValidatedProductionDatabaseConnection,
    crate::production_database_connection_handoff::DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection,
    crate::production_database_connection_handoff::DatabaseFreshnessValidatedProductionDatabaseConnection,
    crate::production_database_connection_handoff::StartupAuthorizedProductionDatabaseConnection,
);

#[cfg(not(windows))]
fn run_production_startup(
    _: &AppHandle,
    _: &ApplicationLifecycle,
) -> StartupWorkerResult<OperationalProductionDatabase, RetainedCloseFailure> {
    StartupWorkerResult::Failed(CoarseStartupFailure::StartupUnavailable)
}

#[tauri::command]
pub(crate) fn startup_status(state: tauri::State<'_, Arc<ApplicationLifecycle>>) -> StartupStatus {
    state.status()
}

pub(crate) fn lifecycle_from_app(app: &AppHandle) -> Arc<ApplicationLifecycle> {
    Arc::clone(app.state::<Arc<ApplicationLifecycle>>().inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct TestOwner(u8);

    #[derive(Debug, Eq, PartialEq)]
    struct TestCloseFailure(u8);

    #[cfg(windows)]
    #[test]
    fn only_initialized_present_may_enter_or_complete_the_production_trust_chain() {
        let present = InstallationEvidence::Initialized(ExpectedStorageEvidence::Present);
        assert!(is_initialized_with_expected_storage(&present));

        for blocked in [
            InstallationEvidence::NeverInitialized,
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing),
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable),
            InstallationEvidence::Inconsistent,
            InstallationEvidence::Unavailable,
        ] {
            assert!(!is_initialized_with_expected_storage(&blocked));
        }
    }

    #[cfg(windows)]
    #[test]
    fn every_final_change_away_from_present_blocks_authorization_including_staging() {
        let early = InstallationEvidence::Initialized(ExpectedStorageEvidence::Present);
        assert!(is_initialized_with_expected_storage(&early));

        for final_observation in [
            InstallationEvidence::NeverInitialized,
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing),
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable),
            InstallationEvidence::Inconsistent,
            InstallationEvidence::Unavailable,
        ] {
            assert!(!is_initialized_with_expected_storage(&final_observation));
        }

        let staging_appearance = InstallationEvidence::Inconsistent;
        assert!(!is_initialized_with_expected_storage(&staging_appearance));
    }

    #[cfg(windows)]
    #[test]
    fn production_worker_observes_twice_and_passes_the_second_value_without_reconstruction() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let worker = SOURCE
            .split_once("fn run_production_startup(")
            .unwrap()
            .1
            .split_once("#[cfg(windows)]\nfn is_initialized_with_expected_storage")
            .unwrap()
            .0;
        let compact: String = worker
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();

        assert_eq!(
            worker
                .matches("observe_production_installation_evidence(&evidence_paths)")
                .count(),
            2
        );

        let early_observation = worker.find("let early_installation_evidence").unwrap();
        let early_gate = worker
            .find("is_initialized_with_expected_storage(&early_installation_evidence)")
            .unwrap();
        let trust_chain = worker
            .find("load_trusted_current_installation_evidence_assessment")
            .unwrap();
        let freshness = worker
            .find("validate_production_database_freshness")
            .unwrap();
        let final_observation = worker.find("let final_installation_evidence").unwrap();
        let final_gate = worker
            .find("is_initialized_with_expected_storage(&final_installation_evidence)")
            .unwrap();
        let authorization = worker
            .find("authorize_production_database_startup")
            .unwrap();

        assert!(early_observation < early_gate);
        assert!(early_gate < trust_chain);
        assert!(freshness < final_observation);
        assert!(final_observation < final_gate);
        assert!(final_gate < authorization);
        assert!(
            compact.contains(
                "authorize_production_database_startup(fresh,final_installation_evidence)"
            )
        );
        assert!(!compact.contains(
            "authorize_production_database_startup(fresh,InstallationEvidence::Initialized("
        ));
        for forbidden in [
            "authorize_first_time_setup(",
            "decide_storage(",
            "SetupAuthorizationState",
            "recovery(",
            "repair(",
            "retry(",
        ] {
            assert!(!worker.contains(forbidden));
        }
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    fn all_startup_path_groups_derive_from_one_exact_selected_root() {
        use crate::storage_foundation::{
            ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME, ACTIVE_AUTHENTICATION_KEY_FILENAME,
            ACTIVE_DATABASE_KEY_FILENAME, DATABASE_KEY_DIRECTORY_NAME,
            FRESHNESS_ANCHOR_DIRECTORY_NAME, INSTALLATION_EVIDENCE_DIRECTORY_NAME,
            PRODUCTION_DATABASE_FILENAME,
        };

        let root = std::path::PathBuf::from(r"C:\synthetic-selected-root");
        let paths = StartupPaths::from_root(&root, true);

        assert_eq!(
            paths.evidence.active_database.as_path(),
            root.join(PRODUCTION_DATABASE_FILENAME)
        );
        assert_eq!(
            paths.evidence.active_authentication_key.as_path(),
            root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME)
                .join(ACTIVE_AUTHENTICATION_KEY_FILENAME)
        );
        assert_eq!(
            paths.database_key.active_database_key.as_path(),
            root.join(DATABASE_KEY_DIRECTORY_NAME)
                .join(ACTIVE_DATABASE_KEY_FILENAME)
        );
        assert_eq!(
            paths
                .freshness_anchor
                .active_anchor_authentication_key
                .as_path(),
            root.join(FRESHNESS_ANCHOR_DIRECTORY_NAME)
                .join(ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME)
        );
        assert_eq!(
            paths.database.as_path(),
            root.join(PRODUCTION_DATABASE_FILENAME)
        );
        assert!(paths.pause_before_final_installation_observation);
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    fn pause_is_single_and_immediately_precedes_final_observation_with_shutdown_recheck() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let worker = SOURCE
            .split_once("fn run_production_startup(")
            .unwrap()
            .1
            .split_once("#[cfg(windows)]\nstruct StartupPaths")
            .unwrap()
            .0;

        assert_eq!(
            worker
                .matches("pause_before_final_installation_observation()")
                .count(),
            1
        );
        let freshness = worker
            .find("validate_production_database_freshness")
            .unwrap();
        let pause = worker
            .find("if pause_requested")
            .expect("pause seam should be present");
        let final_observation = worker.find("let final_installation_evidence").unwrap();
        let authorization = worker
            .find("authorize_production_database_startup")
            .unwrap();
        let ready = worker
            .find("StartupWorkerResult::Ready(activate_production_database_for_operational_use")
            .unwrap();

        assert!(freshness < pause);
        assert!(pause < final_observation);
        assert!(final_observation < authorization);
        assert!(authorization < ready);
        let pause_to_observation = &worker[pause..final_observation];
        assert_eq!(
            pause_to_observation.matches("shutdown_pending()").count(),
            1
        );
        assert!(pause_to_observation.contains("return close_interrupted_owner(fresh)"));
        assert!(!pause_to_observation.contains("observe_production_installation_evidence"));
        assert!(!pause_to_observation.contains("authorize_production_database_startup"));
        assert!(!pause_to_observation.contains("StartupWorkerResult::Ready"));
    }

    #[test]
    fn debug_support_is_compile_time_gated_and_has_no_frontend_or_command_surface() {
        let bootstrap = include_str!("lib.rs");
        assert!(
            bootstrap.contains(
                "#[cfg(all(windows, debug_assertions))]\nmod manual_startup_debug_support;"
            )
        );
        assert!(!bootstrap.contains("generate_handler![manual_startup"));
        assert!(!bootstrap.contains("generate_handler![pause"));

        for frontend_source in [
            include_str!("../../src/App.tsx"),
            include_str!("../../src/App.test.tsx"),
            include_str!("../../src/lib/startup.ts"),
        ] {
            assert!(!frontend_source.contains("CHURCH_APP_MANUAL_STARTUP_ROOT"));
            assert!(!frontend_source.contains("CHURCH_APP_MANUAL_STARTUP_PAUSE"));
            assert!(!frontend_source.contains("manual_startup_pause"));
        }
    }

    #[test]
    fn exactly_one_not_started_to_starting_reservation_succeeds() {
        let mut state: LifecycleState<TestOwner, TestCloseFailure> = LifecycleState::NotStarted;
        assert!(state.reserve_startup());
        assert!(!state.reserve_startup());
        assert_eq!(state.status(), StartupStatus::Starting);
    }

    #[test]
    fn exactly_one_owner_installs_and_stale_completion_cannot_replace_it() {
        let mut state: LifecycleState<TestOwner, TestCloseFailure> = LifecycleState::NotStarted;
        assert!(state.reserve_startup());
        assert!(matches!(
            state.finish_startup(StartupWorkerResult::Ready(TestOwner(1))),
            StartupCompletion::ReadyInstalled
        ));
        let StartupCompletion::CloseLateOwner(stale) =
            state.finish_startup(StartupWorkerResult::Ready(TestOwner(2)))
        else {
            panic!("stale owner must be returned for close");
        };
        assert_eq!(stale, TestOwner(2));
        assert!(matches!(state, LifecycleState::Ready(TestOwner(1))));
    }

    #[test]
    fn shutdown_intent_prevents_late_ready_installation() {
        let mut state: LifecycleState<TestOwner, TestCloseFailure> = LifecycleState::NotStarted;
        assert!(state.reserve_startup());
        assert!(matches!(
            state.begin_shutdown(),
            ShutdownAction::WaitForStartup
        ));
        let StartupCompletion::CloseLateOwner(owner) =
            state.finish_startup(StartupWorkerResult::Ready(TestOwner(7)))
        else {
            panic!("late owner must be closed");
        };
        assert_eq!(owner, TestOwner(7));
        assert_eq!(state.status(), StartupStatus::Stopping);
    }

    #[test]
    fn exactly_one_ready_close_can_begin() {
        let mut state = LifecycleState::<TestOwner, TestCloseFailure>::Ready(TestOwner(3));
        let ShutdownAction::Close(owner) = state.begin_shutdown() else {
            panic!("ready owner must be removed for close");
        };
        assert_eq!(owner, TestOwner(3));
        assert!(matches!(
            state.begin_shutdown(),
            ShutdownAction::WaitForStartup
        ));
    }

    #[test]
    fn failed_never_retains_owner_and_close_failure_does() {
        let failed: LifecycleState<TestOwner, TestCloseFailure> =
            LifecycleState::Failed(CoarseStartupFailure::StartupUnavailable);
        assert_eq!(failed.status(), StartupStatus::Unavailable);

        let retained: LifecycleState<TestOwner, TestCloseFailure> =
            LifecycleState::CloseRetryRequired(TestCloseFailure(9));
        assert_eq!(retained.status(), StartupStatus::ShutdownIncomplete);
        assert!(matches!(
            retained,
            LifecycleState::CloseRetryRequired(TestCloseFailure(9))
        ));
    }

    #[test]
    fn ready_close_failure_transitions_to_retained_shutdown_incomplete() {
        let mut state = LifecycleState::<TestOwner, TestCloseFailure>::Ready(TestOwner(4));
        assert!(matches!(
            state.begin_shutdown(),
            ShutdownAction::Close(TestOwner(4))
        ));
        state.finish_close(Some(TestCloseFailure(11)));
        assert_eq!(state.status(), StartupStatus::ShutdownIncomplete);
        assert!(matches!(
            state,
            LifecycleState::CloseRetryRequired(TestCloseFailure(11))
        ));
    }

    #[test]
    fn status_reads_do_not_mutate_authority() {
        let state = LifecycleState::<TestOwner, TestCloseFailure>::Ready(TestOwner(5));
        assert_eq!(state.status(), StartupStatus::Ready);
        assert_eq!(state.status(), StartupStatus::Ready);
        assert!(matches!(state, LifecycleState::Ready(TestOwner(5))));
    }

    #[test]
    fn status_command_has_no_frontend_arguments_or_startup_authority() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let signature = "pub(crate) fn startup_status(state: tauri::State<'_, Arc<ApplicationLifecycle>>) -> StartupStatus";
        assert!(SOURCE.contains(signature));
        let command = SOURCE.split_once("#[tauri::command]").unwrap().1;
        let command = command.split_once("\n}").unwrap().0;
        assert!(command.contains("state.status()"));
        for forbidden in [
            ".start(",
            "request_shutdown(",
            "activate_production_database_for_operational_use(",
            "retry_close(",
        ] {
            assert!(!command.contains(forbidden));
        }

        let bootstrap = include_str!("lib.rs");
        assert!(
            bootstrap.contains(
                ".invoke_handler(tauri::generate_handler![health_check, startup_status])"
            )
        );
        assert!(bootstrap.contains("lifecycle.start(app.handle().clone())"));
        assert!(!bootstrap.contains("generate_handler![activate_production_database"));
        assert!(!bootstrap.contains("generate_handler![retry"));
    }
}
