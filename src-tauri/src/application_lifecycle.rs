//! Rust-owned application startup and orderly-shutdown orchestration.
//!
//! The frontend can observe only [`StartupStatus`]. All database authority and
//! ownership-bearing failures remain in this module.

use std::{
    fmt,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    thread,
};

use serde::Serialize;
use tauri::{AppHandle, Manager};

mod production_database_migration_confirmation;

use production_database_migration_confirmation::ProductionDatabaseMigrationConfirmation;

#[cfg(windows)]
use crate::{
    database_key_active_wrapper_loader::load_active_database_key_wrapper,
    database_key_presence::inspect_database_key_active_presence,
    first_time_setup_exclusivity::{
        FirstTimeSetupCrossProcessExclusivity, FirstTimeSetupCrossProcessExclusivityOutcome,
        acquire_first_time_setup_cross_process_exclusivity,
    },
    first_time_setup_orchestration::{
        FirstTimeSetupOrchestrationOutcome, FirstTimeSetupTerminalFailure, run_first_time_setup,
    },
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
    SetupInProgress,
    SetupRestartRequired,
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
    SetupInProgress,
    SetupRestartRequired,
    Stopping,
    CloseRetryRequired(CloseFailure),
    StartupCloseRetryRequired,
    SetupCloseRetryRequired,
}

impl<Operational, CloseFailure> LifecycleState<Operational, CloseFailure> {
    fn status(&self) -> StartupStatus {
        match self {
            Self::NotStarted | Self::Starting => StartupStatus::Starting,
            Self::Ready(_) => StartupStatus::Ready,
            Self::Failed(_) => StartupStatus::Unavailable,
            Self::SetupInProgress => StartupStatus::SetupInProgress,
            Self::SetupRestartRequired => StartupStatus::SetupRestartRequired,
            Self::Stopping => StartupStatus::Stopping,
            Self::CloseRetryRequired(_)
            | Self::StartupCloseRetryRequired
            | Self::SetupCloseRetryRequired => StartupStatus::ShutdownIncomplete,
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

    fn reserve_setup(&mut self) -> FirstTimeSetupRequestOutcome {
        match self {
            Self::Failed(_) => {
                *self = Self::SetupInProgress;
                FirstTimeSetupRequestOutcome::Started
            }
            Self::NotStarted | Self::Starting => FirstTimeSetupRequestOutcome::StartupInProgress,
            Self::Ready(_)
            | Self::Stopping
            | Self::CloseRetryRequired(_)
            | Self::StartupCloseRetryRequired => FirstTimeSetupRequestOutcome::NotAllowed,
            Self::SetupInProgress => FirstTimeSetupRequestOutcome::AlreadyInProgress,
            Self::SetupRestartRequired => FirstTimeSetupRequestOutcome::RestartRequired,
            Self::SetupCloseRetryRequired => FirstTimeSetupRequestOutcome::NotAllowed,
        }
    }

    fn rollback_setup_reservation(&mut self) {
        if matches!(self, Self::SetupInProgress) {
            *self = Self::Failed(CoarseStartupFailure::StartupUnavailable);
        }
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
            Self::SetupInProgress => ShutdownAction::WaitForSetup,
            Self::SetupRestartRequired => {
                *self = Self::Failed(CoarseStartupFailure::StartupInterrupted);
                ShutdownAction::Exit
            }
            Self::Stopping => ShutdownAction::WaitForStartup,
            Self::CloseRetryRequired(failure) => {
                *self = Self::CloseRetryRequired(failure);
                ShutdownAction::Blocked
            }
            Self::StartupCloseRetryRequired => {
                *self = Self::StartupCloseRetryRequired;
                ShutdownAction::Blocked
            }
            Self::SetupCloseRetryRequired => {
                *self = Self::SetupCloseRetryRequired;
                ShutdownAction::Blocked
            }
        }
    }

    fn finish_setup(&mut self, result: SetupWorkerResult) -> SetupCompletion {
        match (&self, result) {
            (Self::SetupInProgress, SetupWorkerResult::Completed) => {
                *self = Self::SetupRestartRequired;
                SetupCompletion::RestartRequired
            }
            (Self::SetupInProgress, SetupWorkerResult::Failed) => {
                *self = Self::Failed(CoarseStartupFailure::StartupUnavailable);
                SetupCompletion::FinishedWithoutOwner {
                    shutdown_requested: false,
                }
            }
            (Self::SetupInProgress, SetupWorkerResult::CloseRetryRequired) => {
                *self = Self::SetupCloseRetryRequired;
                SetupCompletion::ShutdownIncomplete
            }
            (Self::Stopping, SetupWorkerResult::Completed | SetupWorkerResult::Failed) => {
                *self = Self::Failed(CoarseStartupFailure::StartupInterrupted);
                SetupCompletion::FinishedWithoutOwner {
                    shutdown_requested: true,
                }
            }
            (Self::Stopping, SetupWorkerResult::CloseRetryRequired) => {
                *self = Self::SetupCloseRetryRequired;
                SetupCompletion::ShutdownIncomplete
            }
            (_, SetupWorkerResult::CloseRetryRequired) => {
                *self = Self::SetupCloseRetryRequired;
                SetupCompletion::ShutdownIncomplete
            }
            _ => SetupCompletion::StaleResultIgnored,
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
    WaitForSetup,
    Close(Operational),
    Blocked,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupRequestOutcome {
    Started,
    AlreadyInProgress,
    StartupInProgress,
    NotAllowed,
    RestartRequired,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum FirstTimeSetupRequestResult {
    Started,
    AlreadyInProgress,
    StartupInProgress,
    NotAllowed,
    RestartRequired,
    Unavailable,
}

impl From<FirstTimeSetupRequestOutcome> for FirstTimeSetupRequestResult {
    fn from(outcome: FirstTimeSetupRequestOutcome) -> Self {
        match outcome {
            FirstTimeSetupRequestOutcome::Started => Self::Started,
            FirstTimeSetupRequestOutcome::AlreadyInProgress => Self::AlreadyInProgress,
            FirstTimeSetupRequestOutcome::StartupInProgress => Self::StartupInProgress,
            FirstTimeSetupRequestOutcome::NotAllowed => Self::NotAllowed,
            FirstTimeSetupRequestOutcome::RestartRequired => Self::RestartRequired,
            FirstTimeSetupRequestOutcome::Unavailable => Self::Unavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SetupWorkerResult {
    Completed,
    Failed,
    CloseRetryRequired,
}

#[cfg(all(windows, debug_assertions))]
fn first_time_setup_terminal_failure_phase(failure: FirstTimeSetupTerminalFailure) -> &'static str {
    match failure {
        FirstTimeSetupTerminalFailure::Authorization => "authorization",
        FirstTimeSetupTerminalFailure::RootPreparation => "root_preparation",
        FirstTimeSetupTerminalFailure::Generation => "generation",
        FirstTimeSetupTerminalFailure::TimestampUnavailable => "timestamp_unavailable",
        FirstTimeSetupTerminalFailure::DatabaseCreation => "database_creation",
        FirstTimeSetupTerminalFailure::DatabaseInitialization => "database_initialization",
        FirstTimeSetupTerminalFailure::DatabaseValidation => "database_validation",
        FirstTimeSetupTerminalFailure::PublicationMaterialPreparation => {
            "publication_material_preparation"
        }
        FirstTimeSetupTerminalFailure::ProtectedDirectoryPreparation => {
            "protected_directory_preparation"
        }
        FirstTimeSetupTerminalFailure::Staging => "staging",
        FirstTimeSetupTerminalFailure::StagedVerification => "staged_verification",
        FirstTimeSetupTerminalFailure::Publication => "publication",
        FirstTimeSetupTerminalFailure::FinalActiveVerification => "final_active_verification",
        FirstTimeSetupTerminalFailure::FinalObservation => "final_observation",
        FirstTimeSetupTerminalFailure::Completion => "completion",
    }
}

#[cfg(all(windows, debug_assertions))]
fn setup_worker_result_for_terminal_failure(
    failure: FirstTimeSetupTerminalFailure,
) -> SetupWorkerResult {
    let phase = first_time_setup_terminal_failure_phase(failure);
    eprintln!(r#"event="first_time_setup" outcome="terminal_failure" phase="{phase}""#);
    SetupWorkerResult::Failed
}

#[cfg(all(windows, not(debug_assertions)))]
fn setup_worker_result_for_terminal_failure(
    _failure: FirstTimeSetupTerminalFailure,
) -> SetupWorkerResult {
    SetupWorkerResult::Failed
}

enum SetupCompletion {
    RestartRequired,
    FinishedWithoutOwner { shutdown_requested: bool },
    ShutdownIncomplete,
    StaleResultIgnored,
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
    migration_confirmation: ProductionDatabaseMigrationConfirmation,
    startup_worker: Option<tauri::async_runtime::JoinHandle<()>>,
    close_worker: Option<tauri::async_runtime::JoinHandle<()>>,
    setup_worker: Option<thread::JoinHandle<()>>,
    startup_work_resolved: bool,
    close_work_resolved: bool,
    setup_work_resolved: bool,
    setup_shutdown_app: Option<AppHandle>,
}

impl LifecycleInner {
    fn begin_shutdown(&mut self) -> ShutdownAction<OperationalProductionDatabase> {
        self.migration_confirmation.invalidate_for_shutdown();
        self.state.begin_shutdown()
    }
}

pub(crate) struct ApplicationLifecycle {
    inner: Mutex<LifecycleInner>,
}

impl ApplicationLifecycle {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(LifecycleInner {
                state: LifecycleState::NotStarted,
                migration_confirmation: ProductionDatabaseMigrationConfirmation::new(),
                startup_worker: None,
                close_worker: None,
                setup_worker: None,
                startup_work_resolved: false,
                close_work_resolved: true,
                setup_work_resolved: true,
                setup_shutdown_app: None,
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

    #[cfg(windows)]
    #[allow(dead_code)]
    pub(crate) fn request_first_time_setup(
        self: &Arc<Self>,
        canonical_root: PathBuf,
    ) -> FirstTimeSetupRequestOutcome {
        self.request_first_time_setup_with(canonical_root, run_first_time_setup, spawn_setup_thread)
    }

    #[cfg(windows)]
    fn request_first_time_setup_with<Run, Spawn>(
        self: &Arc<Self>,
        canonical_root: PathBuf,
        run: Run,
        spawn: Spawn,
    ) -> FirstTimeSetupRequestOutcome
    where
        Run: FnOnce(PathBuf) -> FirstTimeSetupOrchestrationOutcome + Send + 'static,
        Spawn: FnOnce(SetupThreadTask) -> std::io::Result<thread::JoinHandle<()>>,
    {
        let prior_worker = {
            let mut inner = self.lock();
            if matches!(inner.state, LifecycleState::Failed(_)) && inner.setup_work_resolved {
                inner.setup_worker.take()
            } else {
                None
            }
        };
        if let Some(worker) = prior_worker {
            let _ = worker.join();
        }

        let (start_sender, start_receiver) = std::sync::mpsc::sync_channel(0);
        let lifecycle = Arc::clone(self);
        let task: SetupThreadTask = Box::new(move || {
            if start_receiver.recv().is_err() {
                lifecycle.complete_setup(SetupWorkerResult::Failed);
                return;
            }
            eprintln!(r#"event="first_time_setup" outcome="worker_started""#);
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(canonical_root)));
            match outcome {
                Ok(FirstTimeSetupOrchestrationOutcome::Completed) => {
                    lifecycle.complete_setup(SetupWorkerResult::Completed);
                }
                Ok(FirstTimeSetupOrchestrationOutcome::CloseRetryRequired(owner)) => {
                    lifecycle.complete_setup(SetupWorkerResult::CloseRetryRequired);
                    retain_setup_close_owner(owner);
                }
                Ok(FirstTimeSetupOrchestrationOutcome::TerminalFailure(phase)) => {
                    lifecycle.complete_setup(setup_worker_result_for_terminal_failure(phase));
                }
                Ok(
                    FirstTimeSetupOrchestrationOutcome::AlreadyInProgress
                    | FirstTimeSetupOrchestrationOutcome::Unavailable
                    | FirstTimeSetupOrchestrationOutcome::NotEligible(_),
                )
                | Err(_) => lifecycle.complete_setup(SetupWorkerResult::Failed),
            }
        });

        let mut inner = self.lock();
        let reservation = inner.state.reserve_setup();
        if reservation != FirstTimeSetupRequestOutcome::Started {
            return reservation;
        }
        inner.setup_work_resolved = false;
        eprintln!(r#"event="first_time_setup" outcome="reserved""#);
        let worker = match spawn(task) {
            Ok(worker) => worker,
            Err(_) => {
                inner.state.rollback_setup_reservation();
                inner.setup_work_resolved = true;
                return FirstTimeSetupRequestOutcome::Unavailable;
            }
        };
        inner.setup_worker = Some(worker);
        drop(inner);
        if start_sender.send(()).is_err() {
            self.complete_setup(SetupWorkerResult::Failed);
            FirstTimeSetupRequestOutcome::Unavailable
        } else {
            FirstTimeSetupRequestOutcome::Started
        }
    }

    fn complete_setup(&self, result: SetupWorkerResult) {
        let (completion, shutdown_app) = {
            let mut inner = self.lock();
            let completion = inner.state.finish_setup(result);
            if !matches!(completion, SetupCompletion::ShutdownIncomplete) {
                inner.setup_work_resolved = true;
            }
            let shutdown_app = if matches!(
                completion,
                SetupCompletion::FinishedWithoutOwner {
                    shutdown_requested: true
                }
            ) {
                inner.setup_shutdown_app.take()
            } else {
                None
            };
            (completion, shutdown_app)
        };
        eprintln!(r#"event="first_time_setup" outcome="worker_completed""#);
        match completion {
            SetupCompletion::RestartRequired => {
                eprintln!(r#"event="first_time_setup" outcome="restart_required""#);
            }
            SetupCompletion::FinishedWithoutOwner { shutdown_requested } => {
                eprintln!(r#"event="first_time_setup" outcome="unavailable""#);
                if let (true, Some(app)) = (shutdown_requested, shutdown_app) {
                    app.exit(0);
                }
            }
            SetupCompletion::ShutdownIncomplete => {
                eprintln!(r#"event="application_shutdown" outcome="close_failed""#);
            }
            SetupCompletion::StaleResultIgnored => {}
        }
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

    #[cfg(windows)]
    fn retain_startup_close_failure(&self) {
        let mut inner = self.lock();
        inner.state = LifecycleState::StartupCloseRetryRequired;
    }

    pub(crate) fn request_shutdown(self: &Arc<Self>, app: AppHandle) {
        let action = {
            let mut inner = self.lock();
            let action = inner.begin_shutdown();
            if matches!(action, ShutdownAction::WaitForSetup) {
                inner.setup_shutdown_app = Some(app.clone());
            }
            action
        };
        eprintln!(r#"event="application_shutdown" outcome="requested""#);
        match action {
            ShutdownAction::Exit => app.exit(0),
            ShutdownAction::WaitForStartup => {
                eprintln!(r#"event="application_shutdown" outcome="pending""#);
            }
            ShutdownAction::WaitForSetup => {
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
            && inner.setup_work_resolved
            && matches!(inner.state, LifecycleState::Failed(_))
    }

    pub(crate) fn join_workers(&self) {
        let (startup, close, setup) = {
            let mut inner = self.lock();
            let startup = (!matches!(inner.state, LifecycleState::StartupCloseRetryRequired))
                .then(|| inner.startup_worker.take())
                .flatten();
            let setup = inner
                .setup_work_resolved
                .then(|| inner.setup_worker.take())
                .flatten();
            (startup, inner.close_worker.take(), setup)
        };
        if let Some(worker) = startup {
            let _ = tauri::async_runtime::block_on(worker);
        }
        if let Some(worker) = close {
            let _ = tauri::async_runtime::block_on(worker);
        }
        if let Some(worker) = setup {
            let _ = worker.join();
        }
    }
}

#[cfg(windows)]
type SetupThreadTask = Box<dyn FnOnce() + Send + 'static>;

#[cfg(windows)]
fn spawn_setup_thread(task: SetupThreadTask) -> std::io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("first-time-setup".to_owned())
        .spawn(task)
}

#[cfg(windows)]
fn retain_setup_close_owner(
    owner: crate::first_time_setup_orchestration::FirstTimeSetupCloseRetryRequired,
) -> ! {
    let _owner = owner;
    loop {
        thread::park();
    }
}

#[cfg(windows)]
fn retain_startup_close_owner<T>(
    lifecycle: &ApplicationLifecycle,
    failure: T,
    exclusivity: FirstTimeSetupCrossProcessExclusivity,
) -> ! {
    lifecycle.retain_startup_close_failure();
    let _failure = failure;
    let _exclusivity = exclusivity;
    loop {
        thread::park();
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

    let exclusivity = match acquire_first_time_setup_cross_process_exclusivity() {
        FirstTimeSetupCrossProcessExclusivityOutcome::Acquired(owner) => owner,
        FirstTimeSetupCrossProcessExclusivityOutcome::AlreadyHeld
        | FirstTimeSetupCrossProcessExclusivityOutcome::Unavailable => return unavailable(),
    };

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
            retain_startup_close_owner(
                lifecycle,
                RetainedCloseFailure::Construction(failure),
                exclusivity,
            )
        }
    };
    if lifecycle.shutdown_pending() {
        return close_protected_interrupted_owner(opened, lifecycle, exclusivity);
    }

    let validated = match validate_production_database_readability_and_integrity(opened) {
        ProductionDatabaseValidationOutcome::Validated(owner) => owner,
        ProductionDatabaseValidationOutcome::Failed(_) => return unavailable(),
        ProductionDatabaseValidationOutcome::CloseFailed(failure) => retain_startup_close_owner(
            lifecycle,
            RetainedCloseFailure::Validation(failure),
            exclusivity,
        ),
    };
    if lifecycle.shutdown_pending() {
        return close_protected_interrupted_owner(validated, lifecycle, exclusivity);
    }

    let metadata = match validate_production_database_live_metadata_and_headers(validated) {
        LiveMetadataAndHeaderValidationOutcome::Validated(owner) => owner,
        LiveMetadataAndHeaderValidationOutcome::Failed(_) => return unavailable(),
        LiveMetadataAndHeaderValidationOutcome::CloseFailed(failure) => retain_startup_close_owner(
            lifecycle,
            RetainedCloseFailure::Metadata(failure),
            exclusivity,
        ),
    };
    if lifecycle.shutdown_pending() {
        return close_protected_interrupted_owner(metadata, lifecycle, exclusivity);
    }

    let correspondence =
        match validate_production_database_evidence_correspondence(metadata, trusted_assessment) {
            DatabaseEvidenceCorrespondenceValidationOutcome::Validated(owner) => owner,
            DatabaseEvidenceCorrespondenceValidationOutcome::Mismatch(_) => return unavailable(),
            DatabaseEvidenceCorrespondenceValidationOutcome::CloseFailed(failure) => {
                retain_startup_close_owner(
                    lifecycle,
                    RetainedCloseFailure::Correspondence(failure),
                    exclusivity,
                )
            }
        };
    if lifecycle.shutdown_pending() {
        return close_protected_interrupted_owner(correspondence, lifecycle, exclusivity);
    }

    let fresh = match validate_production_database_freshness(correspondence, anchor_observation) {
        ProductionDatabaseFreshnessValidationOutcome::Validated(owner) => owner,
        ProductionDatabaseFreshnessValidationOutcome::Failed(_) => return unavailable(),
        ProductionDatabaseFreshnessValidationOutcome::CloseFailed(failure) => {
            retain_startup_close_owner(
                lifecycle,
                RetainedCloseFailure::Freshness(failure),
                exclusivity,
            )
        }
    };
    if lifecycle.shutdown_pending() {
        return close_protected_interrupted_owner(fresh, lifecycle, exclusivity);
    }

    #[cfg(debug_assertions)]
    if pause_requested {
        if pause_before_final_installation_observation() != ManualStartupPauseOutcome::Resumed {
            return close_protected_unavailable_owner(fresh, lifecycle, exclusivity);
        }
        if lifecycle.shutdown_pending() {
            return close_protected_interrupted_owner(fresh, lifecycle, exclusivity);
        }
    }

    let final_installation_evidence = observe_production_installation_evidence(&evidence_paths);
    if lifecycle.shutdown_pending() {
        return close_protected_interrupted_owner(fresh, lifecycle, exclusivity);
    }
    if !is_initialized_with_expected_storage(&final_installation_evidence) {
        return close_protected_unavailable_owner(fresh, lifecycle, exclusivity);
    }

    let authorized = match authorize_production_database_startup(fresh, final_installation_evidence)
    {
        ProductionDatabaseStartupAuthorizationOutcome::Authorized(owner) => owner,
        ProductionDatabaseStartupAuthorizationOutcome::Failed(_) => return unavailable(),
        ProductionDatabaseStartupAuthorizationOutcome::CloseFailed(failure) => {
            retain_startup_close_owner(
                lifecycle,
                RetainedCloseFailure::Authorization(failure),
                exclusivity,
            )
        }
    };
    drop(exclusivity);
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
fn close_protected_unavailable_owner<T>(
    owner: T,
    lifecycle: &ApplicationLifecycle,
    exclusivity: FirstTimeSetupCrossProcessExclusivity,
) -> StartupWorkerResult<OperationalProductionDatabase, RetainedCloseFailure>
where
    T: CanonicallyClosable,
{
    match owner.close_canonically() {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            drop(exclusivity);
            StartupWorkerResult::Failed(CoarseStartupFailure::StartupUnavailable)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => retain_startup_close_owner(
            lifecycle,
            RetainedCloseFailure::Operational(failure),
            exclusivity,
        ),
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
fn close_protected_interrupted_owner<T>(
    owner: T,
    lifecycle: &ApplicationLifecycle,
    exclusivity: FirstTimeSetupCrossProcessExclusivity,
) -> StartupWorkerResult<OperationalProductionDatabase, RetainedCloseFailure>
where
    T: CanonicallyClosable,
{
    match owner.close_canonically() {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            drop(exclusivity);
            StartupWorkerResult::Failed(CoarseStartupFailure::StartupInterrupted)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => retain_startup_close_owner(
            lifecycle,
            RetainedCloseFailure::Operational(failure),
            exclusivity,
        ),
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

#[tauri::command]
pub(crate) fn request_first_time_setup(app: AppHandle) -> FirstTimeSetupRequestResult {
    #[cfg(windows)]
    return request_first_time_setup_with(
        || app.path().app_local_data_dir().map_err(|_| ()),
        select_setup_root,
        |selected_root| lifecycle_from_app(&app).request_first_time_setup(selected_root),
    );

    #[cfg(not(windows))]
    {
        let _ = app;
        FirstTimeSetupRequestResult::Unavailable
    }
}

#[cfg(all(windows, debug_assertions))]
fn select_setup_root(canonical_root: PathBuf) -> Result<PathBuf, ()> {
    let selection = select_startup_root(canonical_root).map_err(|_| ())?;
    Ok(selection.root().to_path_buf())
}

#[cfg(all(windows, not(debug_assertions)))]
fn select_setup_root(canonical_root: PathBuf) -> Result<PathBuf, ()> {
    Ok(canonical_root)
}

#[cfg(windows)]
fn request_first_time_setup_with<Resolve, Select, Request>(
    resolve_canonical_root: Resolve,
    select_root: Select,
    request: Request,
) -> FirstTimeSetupRequestResult
where
    Resolve: FnOnce() -> Result<PathBuf, ()>,
    Select: FnOnce(PathBuf) -> Result<PathBuf, ()>,
    Request: FnOnce(PathBuf) -> FirstTimeSetupRequestOutcome,
{
    let canonical_root = match resolve_canonical_root() {
        Ok(canonical_root) => canonical_root,
        Err(()) => return FirstTimeSetupRequestResult::Unavailable,
    };
    let selected_root = match select_root(canonical_root) {
        Ok(selected_root) => selected_root,
        Err(()) => return FirstTimeSetupRequestResult::Unavailable,
    };
    request(selected_root).into()
}

pub(crate) fn lifecycle_from_app(app: &AppHandle) -> Arc<ApplicationLifecycle> {
    Arc::clone(app.state::<Arc<ApplicationLifecycle>>().inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    use std::{rc::Rc, sync::mpsc, time::Duration};

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
        assert!(
            pause_to_observation.contains(
                "return close_protected_interrupted_owner(fresh, lifecycle, exclusivity)"
            )
        );
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

    #[cfg(windows)]
    #[test]
    fn startup_exclusivity_wraps_every_decisive_observation_and_authorization_only() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let worker = SOURCE
            .split_once("fn run_production_startup(")
            .unwrap()
            .1
            .split_once("#[cfg(windows)]\nstruct StartupPaths")
            .unwrap()
            .0;

        let paths = worker
            .find("let paths = match StartupPaths::from_app(app)")
            .unwrap();
        let initial_shutdown = worker.find("if lifecycle.shutdown_pending()").unwrap();
        let acquire = worker
            .find("let exclusivity = match acquire_first_time_setup_cross_process_exclusivity()")
            .unwrap();
        let early_observation = worker.find("let early_installation_evidence").unwrap();
        let final_observation = worker.find("let final_installation_evidence").unwrap();
        let authorization = worker
            .find("authorize_production_database_startup(fresh, final_installation_evidence)")
            .unwrap();
        let release = worker.find("drop(exclusivity)").unwrap();
        let post_authorization_shutdown = worker[release..]
            .find("if lifecycle.shutdown_pending()")
            .unwrap()
            + release;
        let activation = worker
            .find("activate_production_database_for_operational_use(authorized)")
            .unwrap();

        assert!(paths < initial_shutdown);
        assert!(initial_shutdown < acquire);
        assert!(acquire < early_observation);
        assert!(early_observation < final_observation);
        assert!(final_observation < authorization);
        assert!(authorization < release);
        assert!(release < post_authorization_shutdown);
        assert!(post_authorization_shutdown < activation);
        assert_eq!(worker.matches("drop(exclusivity)").count(), 1);
        assert_eq!(
            worker
                .matches("acquire_first_time_setup_cross_process_exclusivity()")
                .count(),
            1
        );
    }

    #[cfg(windows)]
    #[test]
    fn startup_exclusivity_acquisition_maps_contention_and_unavailability_before_observation() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let worker = SOURCE
            .split_once("fn run_production_startup(")
            .unwrap()
            .1
            .split_once("#[cfg(windows)]\nstruct StartupPaths")
            .unwrap()
            .0;
        let acquisition = worker
            .split_once("let exclusivity = match")
            .unwrap()
            .1
            .split_once("let early_installation_evidence")
            .unwrap()
            .0;

        assert!(
            acquisition
                .contains("FirstTimeSetupCrossProcessExclusivityOutcome::Acquired(owner) => owner")
        );
        assert!(acquisition.contains(
            "FirstTimeSetupCrossProcessExclusivityOutcome::AlreadyHeld\n        | FirstTimeSetupCrossProcessExclusivityOutcome::Unavailable => return unavailable()"
        ));
        assert!(!acquisition.contains("observe_production_installation_evidence"));
        assert!(!acquisition.contains("loop"));
        assert!(!acquisition.contains("while"));
    }

    #[cfg(windows)]
    #[test]
    fn abandoned_mutex_ownership_uses_the_same_acquired_startup_path() {
        const EXCLUSIVITY_SOURCE: &str = include_str!("first_time_setup_exclusivity.rs");
        let finish = EXCLUSIVITY_SOURCE
            .split_once("fn finish_acquisition(")
            .unwrap()
            .1
            .split_once("#[cfg(test)]")
            .unwrap()
            .0;
        assert!(
            finish
                .contains("WaitDisposition::Acquired | WaitDisposition::AbandonedAndAcquired => (")
        );
        assert_eq!(
            finish
                .matches("FirstTimeSetupCrossProcessExclusivityOutcome::Acquired(")
                .count(),
            1
        );
    }

    #[cfg(windows)]
    #[test]
    fn startup_mutex_owner_blocks_a_setup_side_acquisition_until_drop() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        const EXCLUSIVITY_SOURCE: &str = include_str!("first_time_setup_exclusivity.rs");
        let worker = SOURCE
            .split_once("fn run_production_startup(")
            .unwrap()
            .1
            .split_once("#[cfg(windows)]\nstruct StartupPaths")
            .unwrap()
            .0;
        assert!(
            worker
                .contains("FirstTimeSetupCrossProcessExclusivityOutcome::Acquired(owner) => owner")
        );
        assert!(worker.contains("let exclusivity = match"));
        assert!(worker.contains("drop(exclusivity)"));

        let primitive_regression = EXCLUSIVITY_SOURCE
            .split_once(
                "fn first_acquisition_succeeds_second_is_non_reentrant_and_drop_permits_later_acquisition()",
            )
            .unwrap()
            .1
            .split_once("#[test]")
            .unwrap()
            .0;
        assert!(
            primitive_regression
                .contains("FirstTimeSetupCrossProcessExclusivityOutcome::AlreadyHeld")
        );
        assert_eq!(
            primitive_regression
                .matches("acquire_first_time_setup_cross_process_exclusivity()")
                .count(),
            3
        );
        assert!(primitive_regression.contains("drop(first)"));
    }

    #[test]
    fn startup_close_retry_marker_is_payload_free_blocked_and_not_setup_eligible() {
        let mut state: LifecycleState<TestOwner, TestCloseFailure> =
            LifecycleState::StartupCloseRetryRequired;
        assert_eq!(state.status(), StartupStatus::ShutdownIncomplete);
        assert_eq!(
            state.reserve_setup(),
            FirstTimeSetupRequestOutcome::NotAllowed
        );
        assert!(matches!(state.begin_shutdown(), ShutdownAction::Blocked));
        assert!(matches!(state, LifecycleState::StartupCloseRetryRequired));

        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let definition = SOURCE
            .split_once("enum LifecycleState<Operational, CloseFailure> {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(definition.contains("StartupCloseRetryRequired,"));
        assert!(!definition.contains("StartupCloseRetryRequired("));
    }

    #[test]
    fn startup_close_retry_marker_keeps_may_exit_false() {
        let lifecycle = ApplicationLifecycle::new();
        {
            let mut inner = lifecycle.lock();
            inner.state = LifecycleState::StartupCloseRetryRequired;
            inner.startup_work_resolved = true;
            inner.close_work_resolved = true;
            inner.setup_work_resolved = true;
        }
        assert!(!lifecycle.may_exit());
    }

    #[cfg(windows)]
    #[test]
    fn join_workers_does_not_join_an_intentionally_retained_startup_worker() {
        let lifecycle = ApplicationLifecycle::new();
        let (release_sender, release_receiver) = mpsc::channel();
        let worker = tauri::async_runtime::spawn_blocking(move || {
            release_receiver.recv().expect("release synthetic worker");
        });
        {
            let mut inner = lifecycle.lock();
            inner.state = LifecycleState::StartupCloseRetryRequired;
            inner.startup_worker = Some(worker);
            inner.startup_work_resolved = false;
        }

        lifecycle.join_workers();
        assert!(lifecycle.lock().startup_worker.is_some());

        release_sender.send(()).expect("release synthetic worker");
        {
            let mut inner = lifecycle.lock();
            inner.state = LifecycleState::Failed(CoarseStartupFailure::StartupInterrupted);
            inner.startup_work_resolved = true;
        }
        lifecycle.join_workers();
        assert!(lifecycle.lock().startup_worker.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn mutex_coupled_close_ownership_is_retained_only_on_the_startup_worker() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let inner = SOURCE
            .split_once("struct LifecycleInner {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(!inner.contains("FirstTimeSetupCrossProcessExclusivity"));
        assert!(!inner.contains("StartupClose"));

        let retention = SOURCE
            .split_once("fn retain_startup_close_owner<T>(")
            .unwrap()
            .1
            .split_once("#[cfg(windows)]\nfn close_operational")
            .unwrap()
            .0;
        assert!(retention.contains("failure: T"));
        assert!(retention.contains("exclusivity: FirstTimeSetupCrossProcessExclusivity"));
        assert!(retention.contains("lifecycle.retain_startup_close_failure()"));
        assert!(retention.contains("let _failure = failure"));
        assert!(retention.contains("let _exclusivity = exclusivity"));
        assert!(retention.contains("thread::park()"));
        assert!(!retention.contains("retry_close"));
        assert!(!retention.contains("Arc<"));
        assert!(!retention.contains("Mutex<"));
        assert!(!retention.contains("send("));

        let startup_spawn = SOURCE
            .split_once("let worker = tauri::async_runtime::spawn_blocking(move || {")
            .unwrap()
            .1
            .split_once("self.lock().startup_worker = Some(worker)")
            .unwrap()
            .0;
        assert!(startup_spawn.contains("let result = run_production_startup"));
        assert!(startup_spawn.contains("lifecycle.complete_startup(result"));
        assert!(!startup_spawn.contains("return result"));
    }

    #[cfg(windows)]
    #[test]
    fn protected_close_paths_retain_on_failure_and_release_only_after_success() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        for helper_name in [
            "fn close_protected_unavailable_owner<T>(",
            "fn close_protected_interrupted_owner<T>(",
        ] {
            let helper = SOURCE
                .split_once(helper_name)
                .unwrap()
                .1
                .split_once("\n}\n")
                .unwrap()
                .0;
            let close = helper.find("owner.close_canonically()").unwrap();
            let release = helper.find("drop(exclusivity)").unwrap();
            let retain = helper.find("retain_startup_close_owner(").unwrap();
            assert!(close < release);
            assert!(close < retain);
            assert!(!helper[retain..].contains("drop(exclusivity)"));
        }

        let worker = SOURCE
            .split_once("fn run_production_startup(")
            .unwrap()
            .1
            .split_once("#[cfg(windows)]\nstruct StartupPaths")
            .unwrap()
            .0;
        for failure in [
            "RetainedCloseFailure::Construction(failure)",
            "RetainedCloseFailure::Validation(failure)",
            "RetainedCloseFailure::Metadata(failure)",
            "RetainedCloseFailure::Correspondence(failure)",
            "RetainedCloseFailure::Freshness(failure)",
            "RetainedCloseFailure::Authorization(failure)",
        ] {
            assert!(worker.contains(failure));
        }
        assert_eq!(worker.matches("retain_startup_close_owner(").count(), 6);
    }

    #[cfg(windows)]
    #[test]
    fn post_authorization_shutdown_keeps_existing_movable_operational_close_path() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let worker = SOURCE
            .split_once("fn run_production_startup(")
            .unwrap()
            .1
            .split_once("#[cfg(windows)]\nstruct StartupPaths")
            .unwrap()
            .0;
        let release = worker.find("drop(exclusivity)").unwrap();
        let after_release = &worker[release..];
        assert!(after_release.contains("return close_interrupted_owner(authorized)"));
        assert!(!after_release.contains("close_protected_interrupted_owner"));

        let ordinary_close = SOURCE
            .split_once("fn close_interrupted_owner<T>(")
            .unwrap()
            .1
            .split_once("#[cfg(windows)]\nfn close_protected_interrupted_owner")
            .unwrap()
            .0;
        assert!(ordinary_close.contains(
            "StartupWorkerResult::CloseRetryRequired(RetainedCloseFailure::Operational(failure))"
        ));
    }

    #[test]
    fn exactly_one_not_started_to_starting_reservation_succeeds() {
        let mut state: LifecycleState<TestOwner, TestCloseFailure> = LifecycleState::NotStarted;
        assert!(state.reserve_startup());
        assert!(!state.reserve_startup());
        assert_eq!(state.status(), StartupStatus::Starting);
    }

    #[test]
    fn setup_reservation_accepts_only_failed_and_rejects_every_locked_state() {
        let mut failed = LifecycleState::<TestOwner, TestCloseFailure>::Failed(
            CoarseStartupFailure::StartupUnavailable,
        );
        assert_eq!(
            failed.reserve_setup(),
            FirstTimeSetupRequestOutcome::Started
        );
        assert_eq!(failed.status(), StartupStatus::SetupInProgress);
        assert_eq!(
            failed.reserve_setup(),
            FirstTimeSetupRequestOutcome::AlreadyInProgress
        );

        let cases = [
            (
                LifecycleState::NotStarted,
                FirstTimeSetupRequestOutcome::StartupInProgress,
            ),
            (
                LifecycleState::Starting,
                FirstTimeSetupRequestOutcome::StartupInProgress,
            ),
            (
                LifecycleState::Ready(TestOwner(1)),
                FirstTimeSetupRequestOutcome::NotAllowed,
            ),
            (
                LifecycleState::Stopping,
                FirstTimeSetupRequestOutcome::NotAllowed,
            ),
            (
                LifecycleState::CloseRetryRequired(TestCloseFailure(2)),
                FirstTimeSetupRequestOutcome::NotAllowed,
            ),
            (
                LifecycleState::SetupRestartRequired,
                FirstTimeSetupRequestOutcome::RestartRequired,
            ),
            (
                LifecycleState::SetupCloseRetryRequired,
                FirstTimeSetupRequestOutcome::NotAllowed,
            ),
        ];
        for (mut state, expected) in cases {
            assert_eq!(state.reserve_setup(), expected);
        }
    }

    #[test]
    fn setup_completion_is_restart_only_and_never_operational() {
        let mut state: LifecycleState<TestOwner, TestCloseFailure> =
            LifecycleState::SetupInProgress;
        assert!(matches!(
            state.finish_setup(SetupWorkerResult::Completed),
            SetupCompletion::RestartRequired
        ));
        assert_eq!(state.status(), StartupStatus::SetupRestartRequired);
        assert!(!matches!(state, LifecycleState::Ready(_)));
    }

    #[test]
    fn setup_failure_returns_to_unavailable_without_an_owner() {
        let mut state: LifecycleState<TestOwner, TestCloseFailure> =
            LifecycleState::SetupInProgress;
        assert!(matches!(
            state.finish_setup(SetupWorkerResult::Failed),
            SetupCompletion::FinishedWithoutOwner {
                shutdown_requested: false
            }
        ));
        assert!(matches!(state, LifecycleState::Failed(_)));
        assert_eq!(state.status(), StartupStatus::Unavailable);
    }

    #[test]
    fn setup_close_retention_is_payload_free_and_blocks_exit() {
        let mut state: LifecycleState<TestOwner, TestCloseFailure> =
            LifecycleState::SetupInProgress;
        assert!(matches!(
            state.finish_setup(SetupWorkerResult::CloseRetryRequired),
            SetupCompletion::ShutdownIncomplete
        ));
        assert!(matches!(state, LifecycleState::SetupCloseRetryRequired));
        assert_eq!(state.status(), StartupStatus::ShutdownIncomplete);

        let lifecycle = ApplicationLifecycle::new();
        {
            let mut inner = lifecycle.lock();
            inner.state = LifecycleState::SetupCloseRetryRequired;
            inner.startup_work_resolved = true;
            inner.setup_work_resolved = false;
        }
        assert!(!lifecycle.may_exit());
    }

    #[test]
    fn shutdown_during_setup_drains_without_installing_restart_required() {
        for result in [SetupWorkerResult::Completed, SetupWorkerResult::Failed] {
            let mut state: LifecycleState<TestOwner, TestCloseFailure> =
                LifecycleState::SetupInProgress;
            assert!(matches!(
                state.begin_shutdown(),
                ShutdownAction::WaitForSetup
            ));
            assert_eq!(state.status(), StartupStatus::Stopping);
            assert!(matches!(
                state.finish_setup(result),
                SetupCompletion::FinishedWithoutOwner {
                    shutdown_requested: true
                }
            ));
            assert!(matches!(state, LifecycleState::Failed(_)));
            assert_ne!(state.status(), StartupStatus::SetupRestartRequired);
        }
    }

    #[test]
    fn setup_close_failure_after_shutdown_remains_blocked() {
        let mut state: LifecycleState<TestOwner, TestCloseFailure> =
            LifecycleState::SetupInProgress;
        assert!(matches!(
            state.begin_shutdown(),
            ShutdownAction::WaitForSetup
        ));
        assert!(matches!(
            state.finish_setup(SetupWorkerResult::CloseRetryRequired),
            SetupCompletion::ShutdownIncomplete
        ));
        assert!(matches!(state.begin_shutdown(), ShutdownAction::Blocked));
        assert_eq!(state.status(), StartupStatus::ShutdownIncomplete);
    }

    #[test]
    fn setup_restart_required_shuts_down_without_database_close_work() {
        let mut state: LifecycleState<TestOwner, TestCloseFailure> =
            LifecycleState::SetupRestartRequired;
        assert!(matches!(state.begin_shutdown(), ShutdownAction::Exit));
        assert!(matches!(state, LifecycleState::Failed(_)));
    }

    #[cfg(windows)]
    fn lifecycle_failed_and_resolved() -> Arc<ApplicationLifecycle> {
        let lifecycle = ApplicationLifecycle::new();
        {
            let mut inner = lifecycle.lock();
            inner.state = LifecycleState::Failed(CoarseStartupFailure::StartupUnavailable);
            inner.startup_work_resolved = true;
        }
        lifecycle
    }

    #[cfg(windows)]
    fn wait_for_setup_status(lifecycle: &ApplicationLifecycle, expected: StartupStatus) {
        for _ in 0..200 {
            if lifecycle.status() == expected {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("setup worker did not reach {expected:?}");
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    fn every_terminal_failure_has_one_fixed_safe_phase() {
        let cases = [
            (
                FirstTimeSetupTerminalFailure::Authorization,
                "authorization",
            ),
            (
                FirstTimeSetupTerminalFailure::RootPreparation,
                "root_preparation",
            ),
            (FirstTimeSetupTerminalFailure::Generation, "generation"),
            (
                FirstTimeSetupTerminalFailure::TimestampUnavailable,
                "timestamp_unavailable",
            ),
            (
                FirstTimeSetupTerminalFailure::DatabaseCreation,
                "database_creation",
            ),
            (
                FirstTimeSetupTerminalFailure::DatabaseInitialization,
                "database_initialization",
            ),
            (
                FirstTimeSetupTerminalFailure::DatabaseValidation,
                "database_validation",
            ),
            (
                FirstTimeSetupTerminalFailure::PublicationMaterialPreparation,
                "publication_material_preparation",
            ),
            (
                FirstTimeSetupTerminalFailure::ProtectedDirectoryPreparation,
                "protected_directory_preparation",
            ),
            (FirstTimeSetupTerminalFailure::Staging, "staging"),
            (
                FirstTimeSetupTerminalFailure::StagedVerification,
                "staged_verification",
            ),
            (FirstTimeSetupTerminalFailure::Publication, "publication"),
            (
                FirstTimeSetupTerminalFailure::FinalActiveVerification,
                "final_active_verification",
            ),
            (
                FirstTimeSetupTerminalFailure::FinalObservation,
                "final_observation",
            ),
            (FirstTimeSetupTerminalFailure::Completion, "completion"),
        ];

        let mut distinct = std::collections::BTreeSet::new();
        for (failure, expected) in cases {
            let phase = first_time_setup_terminal_failure_phase(failure);
            assert_eq!(phase, expected);
            assert!(distinct.insert(phase), "duplicate phase: {phase}");
            for forbidden in ['/', '\\', ':'] {
                assert!(!phase.contains(forbidden));
            }
            assert!(
                phase
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
        assert_eq!(distinct.len(), 15);

        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let mapping = SOURCE
            .split_once("fn first_time_setup_terminal_failure_phase(")
            .unwrap()
            .1
            .split_once("fn setup_worker_result_for_terminal_failure(")
            .unwrap()
            .0;
        assert_eq!(
            mapping.matches("FirstTimeSetupTerminalFailure::").count(),
            cases.len()
        );
        assert!(!mapping.contains("_ =>"));
        assert!(!mapping.contains("Debug"));
        assert!(!mapping.contains("format!"));
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    fn terminal_failure_diagnostic_precedes_the_existing_failed_mapping() {
        assert_eq!(
            setup_worker_result_for_terminal_failure(
                FirstTimeSetupTerminalFailure::DatabaseCreation
            ),
            SetupWorkerResult::Failed
        );

        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let production = SOURCE.split_once("#[cfg(test)]").unwrap().0;
        let debug_helper = production
            .split_once(
                "#[cfg(all(windows, debug_assertions))]\nfn setup_worker_result_for_terminal_failure",
            )
            .unwrap()
            .1
            .split_once("#[cfg(all(windows, not(debug_assertions)))]")
            .unwrap()
            .0;
        let emission = debug_helper
            .find(
                r##"eprintln!(r#"event="first_time_setup" outcome="terminal_failure" phase="{phase}""#);"##,
            )
            .unwrap();
        let failed = debug_helper.find("SetupWorkerResult::Failed").unwrap();
        assert!(emission < failed);
        assert_eq!(debug_helper.matches("eprintln!").count(), 1);

        let setup_worker = production
            .split_once("fn request_first_time_setup_with")
            .unwrap()
            .1
            .split_once("fn complete_setup")
            .unwrap()
            .0;
        assert_eq!(
            setup_worker
                .matches("FirstTimeSetupOrchestrationOutcome::TerminalFailure(phase)")
                .count(),
            1
        );
        assert!(setup_worker.contains(
            "lifecycle.complete_setup(setup_worker_result_for_terminal_failure(phase));"
        ));
    }

    #[test]
    fn release_setup_path_has_no_terminal_failure_diagnostic_emission() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let production = SOURCE.split_once("#[cfg(test)]").unwrap().0;
        let release_helper = production
            .split_once(
                "#[cfg(all(windows, not(debug_assertions)))]\nfn setup_worker_result_for_terminal_failure",
            )
            .unwrap()
            .1
            .split_once("enum SetupCompletion")
            .unwrap()
            .0;
        assert!(release_helper.contains("SetupWorkerResult::Failed"));
        assert!(!release_helper.contains("eprintln!"));
        assert!(!release_helper.contains("outcome=\"terminal_failure\""));
        assert!(!release_helper.contains("first_time_setup_terminal_failure_phase"));
    }

    #[test]
    fn terminal_failure_diagnostic_adds_no_lifecycle_or_ipc_status() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let startup_status = SOURCE
            .split_once("pub(crate) enum StartupStatus {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(
            startup_status,
            "\n    Starting,\n    Ready,\n    Unavailable,\n    SetupInProgress,\n    SetupRestartRequired,\n    Stopping,\n    ShutdownIncomplete,"
        );

        let request_result = SOURCE
            .split_once("pub(crate) enum FirstTimeSetupRequestResult {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(
            request_result,
            "\n    Started,\n    AlreadyInProgress,\n    StartupInProgress,\n    NotAllowed,\n    RestartRequired,\n    Unavailable,"
        );

        let setup_worker_result = SOURCE
            .split_once("enum SetupWorkerResult {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(
            setup_worker_result,
            "\n    Completed,\n    Failed,\n    CloseRetryRequired,"
        );
    }

    #[cfg(windows)]
    #[test]
    fn setup_worker_spawn_failure_rolls_back_the_reservation() {
        let lifecycle = lifecycle_failed_and_resolved();
        let result = lifecycle.request_first_time_setup_with(
            PathBuf::from(r"C:\synthetic-root"),
            |_| FirstTimeSetupOrchestrationOutcome::Completed,
            |task| {
                drop(task);
                Err(std::io::Error::other("synthetic spawn failure"))
            },
        );
        assert_eq!(result, FirstTimeSetupRequestOutcome::Unavailable);
        let inner = lifecycle.lock();
        assert_eq!(inner.state.status(), StartupStatus::Unavailable);
        assert!(inner.setup_worker.is_none());
        assert!(inner.setup_work_resolved);
    }

    #[cfg(windows)]
    #[test]
    fn startup_in_progress_rejects_setup_without_invoking_the_spawner() {
        let lifecycle = ApplicationLifecycle::new();
        let result = lifecycle.request_first_time_setup_with(
            PathBuf::from(r"C:\synthetic-root"),
            |_| FirstTimeSetupOrchestrationOutcome::Completed,
            |_| panic!("setup spawner must not run"),
        );
        assert_eq!(result, FirstTimeSetupRequestOutcome::StartupInProgress);
        assert!(lifecycle.lock().setup_worker.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn dedicated_setup_worker_completes_to_restart_required() {
        let lifecycle = lifecycle_failed_and_resolved();
        assert_eq!(
            lifecycle.request_first_time_setup_with(
                PathBuf::from(r"C:\synthetic-root"),
                |_| FirstTimeSetupOrchestrationOutcome::Completed,
                spawn_setup_thread,
            ),
            FirstTimeSetupRequestOutcome::Started
        );
        wait_for_setup_status(&lifecycle, StartupStatus::SetupRestartRequired);
        assert_ne!(lifecycle.status(), StartupStatus::Ready);
        lifecycle.join_workers();
    }

    #[cfg(windows)]
    #[test]
    fn setup_worker_failure_and_panic_fail_closed_to_unavailable() {
        for panics in [false, true] {
            let lifecycle = lifecycle_failed_and_resolved();
            assert_eq!(
                lifecycle.request_first_time_setup_with(
                    PathBuf::from(r"C:\synthetic-root"),
                    move |_| {
                        if panics {
                            panic!("synthetic setup worker panic");
                        }
                        FirstTimeSetupOrchestrationOutcome::Unavailable
                    },
                    spawn_setup_thread,
                ),
                FirstTimeSetupRequestOutcome::Started
            );
            wait_for_setup_status(&lifecycle, StartupStatus::Unavailable);
            assert_ne!(lifecycle.status(), StartupStatus::Ready);
            lifecycle.join_workers();
        }
    }

    #[cfg(windows)]
    #[test]
    fn active_setup_reservation_prevents_a_second_worker() {
        let lifecycle = lifecycle_failed_and_resolved();
        let (release_sender, release_receiver) = mpsc::channel();
        assert_eq!(
            lifecycle.request_first_time_setup_with(
                PathBuf::from(r"C:\synthetic-root"),
                move |_| {
                    release_receiver.recv().expect("release setup worker");
                    FirstTimeSetupOrchestrationOutcome::Unavailable
                },
                spawn_setup_thread,
            ),
            FirstTimeSetupRequestOutcome::Started
        );
        assert_eq!(
            lifecycle.request_first_time_setup_with(
                PathBuf::from(r"C:\second-synthetic-root"),
                |_| FirstTimeSetupOrchestrationOutcome::Completed,
                spawn_setup_thread,
            ),
            FirstTimeSetupRequestOutcome::AlreadyInProgress
        );
        release_sender.send(()).expect("release first setup worker");
        wait_for_setup_status(&lifecycle, StartupStatus::Unavailable);
        lifecycle.join_workers();
    }

    #[cfg(windows)]
    #[test]
    fn synthetic_non_send_owner_is_created_retained_and_dropped_on_one_os_thread() {
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let owner = Rc::new(());
            let created_on = thread::current().id();
            sender.send(created_on).expect("report creation thread");
            thread::park_timeout(Duration::from_millis(5));
            assert_eq!(Rc::strong_count(&owner), 1);
            sender
                .send(thread::current().id())
                .expect("report retention thread");
            drop(owner);
            sender
                .send(thread::current().id())
                .expect("report drop thread");
        });
        let created_on = receiver.recv().expect("creation thread");
        worker.thread().unpark();
        assert_eq!(receiver.recv().expect("retention thread"), created_on);
        assert_eq!(receiver.recv().expect("drop thread"), created_on);
        worker.join().expect("synthetic owner worker");
    }

    #[cfg(windows)]
    #[test]
    fn real_setup_close_owner_is_matched_and_retained_only_inside_worker() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let inner = SOURCE
            .split_once("struct LifecycleInner {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(!inner.contains("FirstTimeSetupCloseRetryRequired"));
        assert!(SOURCE.contains("FirstTimeSetupOrchestrationOutcome::CloseRetryRequired(owner)"));
        assert!(SOURCE.contains("retain_setup_close_owner(owner)"));
        let retention = SOURCE
            .split_once("fn retain_setup_close_owner(")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(retention.contains("let _owner = owner;"));
        assert!(retention.contains("thread::park()"));
        assert!(!retention.contains("retry_close"));
    }

    #[test]
    fn setup_integration_adds_no_startup_reentry() {
        let bootstrap = include_str!("lib.rs");
        assert!(!bootstrap.contains("run_first_time_setup"));
        assert!(
            bootstrap.contains(
                ".invoke_handler(tauri::generate_handler![\n            health_check,\n            startup_status,\n            request_first_time_setup\n        ])"
            )
        );

        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let setup_request = SOURCE
            .split_once("fn request_first_time_setup_with")
            .unwrap()
            .1
            .split_once("fn complete_setup")
            .unwrap()
            .0;
        assert!(!setup_request.contains("run_production_startup"));
        assert!(!setup_request.contains("activate_production_database_for_operational_use"));
        assert!(!setup_request.contains("OperationalProductionDatabase"));
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
    fn lifecycle_shutdown_revokes_migration_confirmation_under_the_same_lock() {
        use production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest;

        let lifecycle = ApplicationLifecycle::new();
        let mut inner = lifecycle.lock();
        assert!(inner.migration_confirmation.establish_pending_for_test());
        assert!(matches!(inner.begin_shutdown(), ShutdownAction::Exit));
        assert_eq!(
            inner.migration_confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );

        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let helper = SOURCE
            .split_once("impl LifecycleInner {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let revocation = helper
            .find("self.migration_confirmation.invalidate_for_shutdown()")
            .unwrap();
        let stopping = helper.find("self.state.begin_shutdown()").unwrap();
        assert!(revocation < stopping);
    }

    #[test]
    fn migration_confirmation_has_no_ipc_frontend_or_startup_status_surface() {
        const LIFECYCLE: &str = include_str!("application_lifecycle.rs");
        const BOOTSTRAP: &str = include_str!("lib.rs");
        const FRONTEND: &str = include_str!("../../src/App.tsx");

        for forbidden in [
            concat!("confirm_production_", "database_migration"),
            concat!("cancel_production_", "database_migration_confirmation"),
        ] {
            assert!(!LIFECYCLE.contains(forbidden));
            assert!(!BOOTSTRAP.contains(forbidden));
            assert!(!FRONTEND.contains(forbidden));
        }
        let startup_status = LIFECYCLE
            .split_once("pub(crate) enum StartupStatus {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(!startup_status.contains("Migration"));
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
                ".invoke_handler(tauri::generate_handler![\n            health_check,\n            startup_status,\n            request_first_time_setup\n        ])"
            )
        );
        assert!(bootstrap.contains("lifecycle.start(app.handle().clone())"));
        assert!(!bootstrap.contains("generate_handler![activate_production_database"));
        assert!(!bootstrap.contains("generate_handler![retry"));
    }

    #[test]
    fn setup_request_outcomes_map_exactly_to_coarse_ipc_results() {
        for (outcome, result) in [
            (
                FirstTimeSetupRequestOutcome::Started,
                FirstTimeSetupRequestResult::Started,
            ),
            (
                FirstTimeSetupRequestOutcome::AlreadyInProgress,
                FirstTimeSetupRequestResult::AlreadyInProgress,
            ),
            (
                FirstTimeSetupRequestOutcome::StartupInProgress,
                FirstTimeSetupRequestResult::StartupInProgress,
            ),
            (
                FirstTimeSetupRequestOutcome::NotAllowed,
                FirstTimeSetupRequestResult::NotAllowed,
            ),
            (
                FirstTimeSetupRequestOutcome::RestartRequired,
                FirstTimeSetupRequestResult::RestartRequired,
            ),
            (
                FirstTimeSetupRequestOutcome::Unavailable,
                FirstTimeSetupRequestResult::Unavailable,
            ),
        ] {
            assert_eq!(FirstTimeSetupRequestResult::from(outcome), result);
        }
    }

    #[cfg(windows)]
    #[test]
    fn setup_request_path_resolution_failure_is_unavailable_without_requesting_setup() {
        let result = request_first_time_setup_with(
            || Err(()),
            |_| panic!("root selection must not run when canonical path resolution fails"),
            |_| panic!("setup must not be requested when canonical path resolution fails"),
        );
        assert_eq!(result, FirstTimeSetupRequestResult::Unavailable);
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    fn setup_request_forwards_the_validated_debug_selection_instead_of_the_canonical_root() {
        let canonical_root = PathBuf::from(r"C:\synthetic-canonical-root");
        let selected_root = PathBuf::from(r"C:\synthetic-validated-manual-root");
        let result = request_first_time_setup_with(
            || Ok(canonical_root.clone()),
            |received| {
                assert_eq!(received, canonical_root);
                Ok(selected_root.clone())
            },
            |received| {
                assert_eq!(received, selected_root);
                FirstTimeSetupRequestOutcome::Started
            },
        );
        assert_eq!(result, FirstTimeSetupRequestResult::Started);
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    fn setup_request_without_a_debug_override_forwards_the_canonical_root() {
        let canonical_root = PathBuf::from(r"C:\synthetic-canonical-root");
        let result = request_first_time_setup_with(
            || Ok(canonical_root.clone()),
            Ok,
            |received| {
                assert_eq!(received, canonical_root);
                FirstTimeSetupRequestOutcome::Started
            },
        );
        assert_eq!(result, FirstTimeSetupRequestResult::Started);
    }

    #[cfg(all(windows, debug_assertions))]
    #[test]
    fn invalid_debug_root_selection_is_unavailable_without_requesting_setup() {
        let result = request_first_time_setup_with(
            || Ok(PathBuf::from(r"C:\synthetic-canonical-root")),
            |_| Err(()),
            |_| panic!("setup must not be requested when root selection fails"),
        );
        assert_eq!(result, FirstTimeSetupRequestResult::Unavailable);
    }

    #[test]
    fn setup_root_selection_is_debug_only_and_reuses_the_startup_selector() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let production_source = SOURCE.split_once("#[cfg(test)]").unwrap().0;
        let debug_selection = production_source
            .split_once("#[cfg(all(windows, debug_assertions))]\nfn select_setup_root")
            .unwrap()
            .1
            .split_once("#[cfg(all(windows, not(debug_assertions)))]")
            .unwrap()
            .0;
        assert!(debug_selection.contains("select_startup_root(canonical_root)"));
        assert!(debug_selection.contains("selection.root().to_path_buf()"));

        let release_selection = production_source
            .split_once("#[cfg(all(windows, not(debug_assertions)))]\nfn select_setup_root")
            .unwrap()
            .1
            .split_once("#[cfg(windows)]\nfn request_first_time_setup_with")
            .unwrap()
            .0;
        assert!(release_selection.contains("Ok(canonical_root)"));
        assert!(!release_selection.contains("select_startup_root"));
    }

    #[cfg(windows)]
    #[test]
    fn setup_request_command_is_argument_free_path_owned_and_reservation_only() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let signature =
            "pub(crate) fn request_first_time_setup(app: AppHandle) -> FirstTimeSetupRequestResult";
        assert!(SOURCE.contains(signature));

        let command = SOURCE
            .split_once(signature)
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(command.contains("app.path().app_local_data_dir().map_err(|_| ())"));
        assert!(command.contains("select_setup_root"));
        assert!(command.contains("lifecycle_from_app(&app)"));
        assert!(command.contains(".request_first_time_setup(selected_root)"));
        for forbidden in [
            "run_first_time_setup(",
            "run_production_startup(",
            "activate_production_database_for_operational_use(",
            "FirstTimeSetupAuthorization",
            "OperationalProductionDatabase",
            "PathBuf",
            "String",
        ] {
            assert!(!command.contains(forbidden));
        }

        let result_definition = SOURCE
            .split_once("pub(crate) enum FirstTimeSetupRequestResult")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        for forbidden in [
            "Path",
            "Authorization",
            "Owner",
            "Error",
            "Phase",
            "Metadata",
        ] {
            assert!(!result_definition.contains(forbidden));
        }
    }
}
