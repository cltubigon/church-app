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

use production_database_migration_confirmation::{
    AuthorizedProductionDatabaseMigrationHandoff, ProductionDatabaseMigrationConfirmation,
    ProductionDatabaseMigrationCrossProcessExclusivity,
    ProductionDatabaseMigrationCrossProcessExclusivityOutcome,
    ProductionDatabaseMigrationDiscoveryCloseFailure, ProductionDatabaseMigrationPendingContext,
    ProductionDatabaseMigrationPreparationFailure, ProductionDatabaseMigrationPreparationOutcome,
    ProductionDatabaseMigrationRevalidationCompletion,
    ProductionDatabaseMigrationShutdownOwnership,
    acquire_production_database_migration_cross_process_exclusivity,
    prepare_authorized_production_database_migration,
};

#[cfg(windows)]
use production_database_migration_confirmation::production_database_migration_backup_stage::{
    PreparedUndisclosedMigrationRecoveryKeyCustody,
    ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome,
    ProductionDatabaseMigrationBackupStageVerifierCloseRetryOutcome,
    ProductionDatabaseMigrationBackupStageWriterCloseRetryOutcome,
    ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome,
    ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseRetryOutcome,
    UndisclosedMigrationRecoveryKeyCustodyShutdown,
    UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome,
};

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
        DatabaseEvidenceCorrespondenceValidationOutcome, FullIntegrityValidationCloseRetryOutcome,
        LiveMetadataAndHeaderValidationCloseFailure, LiveMetadataAndHeaderValidationOutcome,
        OperationalProductionDatabase, ProductionDatabaseConnectionCloseOutcome,
        ProductionDatabaseConnectionConstructionCloseFailure,
        ProductionDatabaseFreshnessValidationCloseFailure,
        ProductionDatabaseFreshnessValidationOutcome,
        ProductionDatabaseMigrationOpportunityOutcome,
        ProductionDatabaseMigrationRevalidationContext,
        ProductionDatabaseStartupAuthorizationCloseFailure,
        ProductionDatabaseStartupAuthorizationOutcome, ProductionDatabaseValidationCloseFailure,
        ProductionDatabaseValidationOutcome, activate_production_database_for_operational_use,
        authorize_production_database_startup, offer_production_database_migration_opportunity,
        open_keyed_production_database_read_only,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionDatabaseMigrationRevalidationRequestOutcome {
    Started,
    NotPending,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionDatabaseMigrationDiscoveryRequestOutcome {
    Started,
    NotReady,
    AlreadyAttempted,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionDatabaseMigrationDiscoveryState {
    NotAttempted,
    InProgress,
    Finished,
}

#[allow(clippy::large_enum_variant)]
enum ProductionDatabaseMigrationDiscoveryWorkerResult {
    Candidate(ProductionDatabaseMigrationPendingContext),
    Unavailable,
    CloseRetryRequired(ProductionDatabaseMigrationDiscoveryCloseFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MigrationPreparationState {
    Inactive,
    Preparing,
    CustodyPrepared,
    CloseRetryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MigrationWorkerCommand {
    Shutdown,
}

#[cfg(windows)]
#[allow(clippy::large_enum_variant)]
enum MigrationWorkerParkedOwnership {
    OperationalClose(
        crate::production_database_connection_handoff::ProductionDatabaseConnectionCloseFailure,
    ),
    PreparationClose(ProductionDatabaseMigrationPreparationFailure),
    Prepared(PreparedUndisclosedMigrationRecoveryKeyCustody),
    PreparedShutdown(UndisclosedMigrationRecoveryKeyCustodyShutdown),
}

#[cfg(windows)]
#[allow(clippy::large_enum_variant)]
enum MigrationWorkerRetryOutcome {
    Resolved,
    Retained(MigrationWorkerParkedOwnership),
}

#[cfg(windows)]
enum MigrationPreparationClaim {
    NoWork,
    Ready(OperationalProductionDatabase),
    ShutdownWon(AuthorizedProductionDatabaseMigrationHandoff),
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
    migration_discovery: ProductionDatabaseMigrationDiscoveryState,
    startup_worker: Option<tauri::async_runtime::JoinHandle<()>>,
    close_worker: Option<tauri::async_runtime::JoinHandle<()>>,
    setup_worker: Option<thread::JoinHandle<()>>,
    migration_worker: Option<thread::JoinHandle<()>>,
    migration_control: Option<std::sync::mpsc::SyncSender<MigrationWorkerCommand>>,
    migration_preparation: MigrationPreparationState,
    startup_work_resolved: bool,
    close_work_resolved: bool,
    setup_work_resolved: bool,
    migration_work_resolved: bool,
    setup_shutdown_app: Option<AppHandle>,
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
                migration_discovery: ProductionDatabaseMigrationDiscoveryState::NotAttempted,
                startup_worker: None,
                close_worker: None,
                setup_worker: None,
                migration_worker: None,
                migration_control: None,
                migration_preparation: MigrationPreparationState::Inactive,
                startup_work_resolved: false,
                close_work_resolved: true,
                setup_work_resolved: true,
                migration_work_resolved: true,
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
        let inner = self.lock();
        if inner.migration_confirmation.has_retained_close_failure() {
            StartupStatus::ShutdownIncomplete
        } else {
            inner.state.status()
        }
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

    #[cfg(windows)]
    #[allow(dead_code)]
    fn request_production_database_migration_discovery(
        self: &Arc<Self>,
        app: AppHandle,
    ) -> ProductionDatabaseMigrationDiscoveryRequestOutcome {
        let worker_app = app.clone();
        self.request_production_database_migration_discovery_with(
            Some(app),
            move || run_production_database_migration_discovery(&worker_app),
            spawn_migration_thread,
        )
    }

    #[cfg(windows)]
    fn request_production_database_migration_discovery_with<Run, Spawn>(
        self: &Arc<Self>,
        app: Option<AppHandle>,
        run: Run,
        spawn: Spawn,
    ) -> ProductionDatabaseMigrationDiscoveryRequestOutcome
    where
        Run: FnOnce() -> ProductionDatabaseMigrationDiscoveryWorkerResult + Send + 'static,
        Spawn: FnOnce(MigrationThreadTask) -> std::io::Result<thread::JoinHandle<()>>,
    {
        let prior_worker = {
            let mut inner = self.lock();
            inner
                .migration_work_resolved
                .then(|| inner.migration_worker.take())
                .flatten()
        };
        if let Some(worker) = prior_worker {
            let _ = worker.join();
        }

        let (start_sender, start_receiver) = std::sync::mpsc::sync_channel(0);
        let lifecycle = Arc::clone(self);
        let worker_app = app.clone();
        let task: MigrationThreadTask = Box::new(move || {
            if start_receiver.recv().is_err() {
                lifecycle.complete_migration_discovery(
                    ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable,
                    worker_app.as_ref(),
                );
                return;
            }
            lifecycle.complete_migration_discovery(run(), worker_app.as_ref());
        });

        let mut inner = self.lock();
        if !matches!(inner.state, LifecycleState::Ready(_)) {
            return ProductionDatabaseMigrationDiscoveryRequestOutcome::NotReady;
        }
        if inner.migration_discovery != ProductionDatabaseMigrationDiscoveryState::NotAttempted {
            return ProductionDatabaseMigrationDiscoveryRequestOutcome::AlreadyAttempted;
        }
        if inner.migration_worker.is_some()
            || !inner.migration_work_resolved
            || !inner.migration_confirmation.is_not_offered()
        {
            return ProductionDatabaseMigrationDiscoveryRequestOutcome::Unavailable;
        }

        inner.migration_discovery = ProductionDatabaseMigrationDiscoveryState::InProgress;
        inner.migration_work_resolved = false;
        let worker = match spawn(task) {
            Ok(worker) => worker,
            Err(_) => {
                inner.migration_discovery = ProductionDatabaseMigrationDiscoveryState::Finished;
                inner.migration_work_resolved = true;
                return ProductionDatabaseMigrationDiscoveryRequestOutcome::Unavailable;
            }
        };
        inner.migration_worker = Some(worker);
        drop(inner);

        if start_sender.send(()).is_err() {
            let mut inner = self.lock();
            inner.migration_discovery = ProductionDatabaseMigrationDiscoveryState::Finished;
            inner.migration_work_resolved = true;
            ProductionDatabaseMigrationDiscoveryRequestOutcome::Unavailable
        } else {
            ProductionDatabaseMigrationDiscoveryRequestOutcome::Started
        }
    }

    #[cfg(windows)]
    fn complete_migration_discovery(
        &self,
        outcome: ProductionDatabaseMigrationDiscoveryWorkerResult,
        app: Option<&AppHandle>,
    ) {
        match outcome {
            ProductionDatabaseMigrationDiscoveryWorkerResult::Candidate(candidate) => {
                let candidate = {
                    let mut inner = self.lock();
                    let may_install = matches!(inner.state, LifecycleState::Ready(_))
                        && inner.migration_discovery
                            == ProductionDatabaseMigrationDiscoveryState::InProgress
                        && inner.migration_confirmation.is_not_offered();
                    inner.migration_discovery = ProductionDatabaseMigrationDiscoveryState::Finished;
                    if may_install {
                        match inner.migration_confirmation.establish_pending(candidate) {
                            Ok(()) => {
                                inner.migration_work_resolved = true;
                                None
                            }
                            Err(candidate) => Some(candidate),
                        }
                    } else {
                        Some(candidate)
                    }
                };
                if let Some(candidate) = candidate {
                    self.complete_migration_discovery_candidate_close(candidate.close(), app);
                }
            }
            ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable => {
                let mut inner = self.lock();
                inner.migration_discovery = ProductionDatabaseMigrationDiscoveryState::Finished;
                inner.migration_work_resolved = true;
            }
            ProductionDatabaseMigrationDiscoveryWorkerResult::CloseRetryRequired(failure) => {
                let mut inner = self.lock();
                inner.migration_discovery = ProductionDatabaseMigrationDiscoveryState::Finished;
                inner
                    .migration_confirmation
                    .retain_discovery_close_failure(failure);
            }
        }
        if self.may_exit()
            && let Some(app) = app
        {
            app.exit(0);
        }
    }

    #[cfg(windows)]
    fn complete_migration_discovery_candidate_close(
        &self,
        outcome: ProductionDatabaseConnectionCloseOutcome,
        app: Option<&AppHandle>,
    ) {
        let mut inner = self.lock();
        match outcome {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                inner.migration_work_resolved = true;
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                inner.migration_confirmation.retain_discovery_close_failure(
                    ProductionDatabaseMigrationDiscoveryCloseFailure::Candidate(failure),
                );
            }
        }
        drop(inner);
        if self.may_exit()
            && let Some(app) = app
        {
            app.exit(0);
        }
    }

    #[cfg(windows)]
    #[allow(dead_code)]
    fn begin_production_database_migration_revalidation(
        self: &Arc<Self>,
        app: AppHandle,
    ) -> ProductionDatabaseMigrationRevalidationRequestOutcome {
        self.begin_production_database_migration_revalidation_with(
            Some(app),
            spawn_migration_thread,
        )
    }

    #[cfg(windows)]
    fn begin_production_database_migration_revalidation_with<Spawn>(
        self: &Arc<Self>,
        app: Option<AppHandle>,
        spawn: Spawn,
    ) -> ProductionDatabaseMigrationRevalidationRequestOutcome
    where
        Spawn: FnOnce(MigrationThreadTask) -> std::io::Result<thread::JoinHandle<()>>,
    {
        let (start_sender, start_receiver) = std::sync::mpsc::sync_channel(0);
        let (control_sender, control_receiver) = std::sync::mpsc::sync_channel(1);
        let lifecycle = Arc::clone(self);
        let mut inner = self.lock();
        if inner.migration_worker.is_some() || !inner.migration_work_resolved {
            return ProductionDatabaseMigrationRevalidationRequestOutcome::Unavailable;
        }
        let work = match inner.migration_confirmation.begin_revalidation() {
            Ok(work) => work,
            Err(_) => return ProductionDatabaseMigrationRevalidationRequestOutcome::NotPending,
        };
        inner.migration_work_resolved = false;
        let escrow = Arc::new(Mutex::new(Some(work)));
        let worker_escrow = Arc::clone(&escrow);
        let worker_app = app.clone();
        let task: MigrationThreadTask = Box::new(move || {
            if start_receiver.recv().is_err() {
                return;
            }
            let work = worker_escrow
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .expect("migration work escrow must contain exactly one owner");
            let outcome = work.revalidate();
            if lifecycle.complete_migration_revalidation(outcome, worker_app.as_ref()) {
                lifecycle.run_migration_preparation_worker(worker_app, control_receiver);
            }
        });
        let worker = match spawn(task) {
            Ok(worker) => worker,
            Err(_) => {
                inner
                    .migration_confirmation
                    .revoke_revalidation_before_start();
                let work = escrow
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                    .expect("failed migration spawn must return complete escrowed work");
                drop(inner);
                self.complete_migration_source_close(work.close(), app.as_ref());
                return ProductionDatabaseMigrationRevalidationRequestOutcome::Unavailable;
            }
        };
        inner.migration_worker = Some(worker);
        inner.migration_control = Some(control_sender);
        drop(inner);
        if start_sender.send(()).is_err() {
            self.lock().migration_control = None;
            let work = escrow
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            if let Some(work) = work {
                self.lock()
                    .migration_confirmation
                    .revoke_revalidation_before_start();
                self.complete_migration_source_close(work.close(), app.as_ref());
            }
            ProductionDatabaseMigrationRevalidationRequestOutcome::Unavailable
        } else {
            ProductionDatabaseMigrationRevalidationRequestOutcome::Started
        }
    }

    #[cfg(windows)]
    fn complete_migration_revalidation(
        &self,
        outcome: crate::production_database_connection_handoff::ProductionDatabaseMigrationRevalidationOutcome,
        app: Option<&AppHandle>,
    ) -> bool {
        let completion = {
            let mut inner = self.lock();
            let completion = inner
                .migration_confirmation
                .complete_revalidation(outcome)
                .expect("only the reserved migration worker may complete revalidation");
            match completion {
                ProductionDatabaseMigrationRevalidationCompletion::Failed(_) => {
                    inner.migration_work_resolved = true;
                    inner.migration_control = None;
                }
                ProductionDatabaseMigrationRevalidationCompletion::Authorized => {}
                ProductionDatabaseMigrationRevalidationCompletion::CloseRetryRequired
                | ProductionDatabaseMigrationRevalidationCompletion::Revoked(_) => {
                    inner.migration_control = None;
                }
            }
            completion
        };
        let authorized = matches!(
            completion,
            ProductionDatabaseMigrationRevalidationCompletion::Authorized
        );
        if let ProductionDatabaseMigrationRevalidationCompletion::Revoked(source) = completion {
            self.complete_migration_source_close(source.close(), app);
        } else if self.may_exit()
            && let Some(app) = app
        {
            app.exit(0);
        }
        authorized
    }

    #[cfg(windows)]
    fn run_migration_preparation_worker(
        self: &Arc<Self>,
        app: Option<AppHandle>,
        control: std::sync::mpsc::Receiver<MigrationWorkerCommand>,
    ) {
        let Some(app) = app else {
            let mut inner = self.lock();
            inner.migration_work_resolved = true;
            inner.migration_control = None;
            return;
        };
        let exclusivity = match acquire_production_database_migration_cross_process_exclusivity() {
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Acquired(owner) => owner,
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::AlreadyHeld
            | ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Unavailable => {
                let mut inner = self.lock();
                inner.migration_work_resolved = true;
                inner.migration_control = None;
                return;
            }
        };

        let claim = {
            let mut inner = self.lock();
            claim_migration_preparation(&mut inner)
        };
        let operational = match claim {
            MigrationPreparationClaim::NoWork => {
                drop(exclusivity);
                self.finish_migration_preparation_worker(Some(&app));
                return;
            }
            MigrationPreparationClaim::ShutdownWon(authorized) => {
                match close_authorized_migration_for_shutdown(authorized) {
                    MigrationWorkerRetryOutcome::Resolved => {
                        drop(exclusivity);
                        self.finish_migration_preparation_worker(Some(&app));
                    }
                    MigrationWorkerRetryOutcome::Retained(owner) => {
                        self.park_migration_worker(owner, control, exclusivity, &app)
                    }
                }
                return;
            }
            MigrationPreparationClaim::Ready(operational) => operational,
        };

        if let Some(failure) = close_operational(operational) {
            let RetainedCloseFailure::Operational(failure) = failure else {
                unreachable!("operational close returns only its exact failure owner")
            };
            self.park_migration_worker(
                MigrationWorkerParkedOwnership::OperationalClose(failure),
                control,
                exclusivity,
                &app,
            );
            return;
        }

        let authorized = {
            let mut inner = self.lock();
            inner.state = LifecycleState::Failed(CoarseStartupFailure::StartupInterrupted);
            inner
                .migration_confirmation
                .consume_authorization()
                .expect("only the exact lifecycle Authorized state enters preparation")
        };

        if control.try_recv().is_ok() {
            match authorized.close() {
                ProductionDatabaseConnectionCloseOutcome::Closed => {
                    drop(exclusivity);
                    self.finish_migration_preparation_worker(Some(&app));
                }
                ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                    self.park_migration_worker(
                        MigrationWorkerParkedOwnership::PreparationClose(
                            ProductionDatabaseMigrationPreparationFailure::SourceClose(failure),
                        ),
                        control,
                        exclusivity,
                        &app,
                    );
                }
            }
            return;
        }

        match prepare_authorized_production_database_migration(&app, authorized) {
            ProductionDatabaseMigrationPreparationOutcome::Prepared(prepared) => {
                self.lock().migration_preparation = MigrationPreparationState::CustodyPrepared;
                self.park_migration_worker(
                    MigrationWorkerParkedOwnership::Prepared(prepared),
                    control,
                    exclusivity,
                    &app,
                );
            }
            ProductionDatabaseMigrationPreparationOutcome::Failed => {
                drop(exclusivity);
                self.finish_migration_preparation_worker(Some(&app));
            }
            ProductionDatabaseMigrationPreparationOutcome::CloseRetryRequired(failure) => {
                self.park_migration_worker(
                    MigrationWorkerParkedOwnership::PreparationClose(failure),
                    control,
                    exclusivity,
                    &app,
                );
            }
        }
    }

    #[cfg(windows)]
    fn park_migration_worker(
        &self,
        mut owner: MigrationWorkerParkedOwnership,
        control: std::sync::mpsc::Receiver<MigrationWorkerCommand>,
        exclusivity: ProductionDatabaseMigrationCrossProcessExclusivity,
        app: &AppHandle,
    ) {
        self.lock().migration_preparation = match &owner {
            MigrationWorkerParkedOwnership::Prepared(_) => {
                MigrationPreparationState::CustodyPrepared
            }
            _ => MigrationPreparationState::CloseRetryRequired,
        };
        loop {
            let _ = control.recv();
            match retry_migration_worker_ownership(owner, self) {
                MigrationWorkerRetryOutcome::Resolved => {
                    drop(exclusivity);
                    self.finish_migration_preparation_worker(Some(app));
                    return;
                }
                MigrationWorkerRetryOutcome::Retained(retained) => owner = retained,
            }
        }
    }

    #[cfg(windows)]
    fn finish_migration_preparation_worker(&self, app: Option<&AppHandle>) {
        {
            let mut inner = self.lock();
            inner.migration_preparation = MigrationPreparationState::Inactive;
            inner.migration_work_resolved = true;
            inner.migration_control = None;
            if matches!(inner.state, LifecycleState::Stopping) {
                inner.state = LifecycleState::Failed(CoarseStartupFailure::StartupInterrupted);
            }
        }
        if self.may_exit()
            && let Some(app) = app
        {
            app.exit(0);
        }
    }

    #[cfg(windows)]
    fn complete_migration_source_close(
        &self,
        outcome: ProductionDatabaseConnectionCloseOutcome,
        app: Option<&AppHandle>,
    ) {
        {
            let mut inner = self.lock();
            match outcome {
                ProductionDatabaseConnectionCloseOutcome::Closed => {
                    inner.migration_work_resolved = true;
                    inner.migration_control = None;
                }
                ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                    inner
                        .migration_confirmation
                        .retain_source_close_failure(failure);
                }
            }
        }
        if self.may_exit()
            && let Some(app) = app
        {
            app.exit(0);
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
                if let (true, Some(app)) = (shutdown_requested, shutdown_app)
                    && self.may_exit()
                {
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
                if shutdown_requested && self.may_exit() {
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
        let prior_migration_worker = {
            let mut inner = self.lock();
            inner
                .migration_work_resolved
                .then(|| inner.migration_worker.take())
                .flatten()
        };
        if let Some(worker) = prior_migration_worker {
            let _ = worker.join();
        }

        let (migration_start_sender, migration_escrow, migration_control, action) = {
            let (start_sender, start_receiver) = std::sync::mpsc::sync_channel(0);
            let mut inner = self.lock();
            if inner.migration_discovery == ProductionDatabaseMigrationDiscoveryState::InProgress {
                inner.migration_discovery = ProductionDatabaseMigrationDiscoveryState::Finished;
            }
            let migration_control = inner.migration_control.clone();
            let migration_owner = if migration_control.is_some() {
                None
            } else {
                inner.migration_confirmation.invalidate_for_shutdown()
            };
            if migration_owner.is_some() {
                inner.migration_work_resolved = false;
            }
            let action = inner.state.begin_shutdown();
            if matches!(action, ShutdownAction::WaitForSetup) {
                inner.setup_shutdown_app = Some(app.clone());
            }
            let mut migration_start_sender = None;
            let mut migration_escrow = None;
            if let Some(migration_owner) = migration_owner {
                let escrow = Arc::new(Mutex::new(Some(migration_owner)));
                let worker_escrow = Arc::clone(&escrow);
                let lifecycle = Arc::clone(self);
                let worker_app = app.clone();
                let task: MigrationThreadTask = Box::new(move || {
                    if start_receiver.recv().is_err() {
                        return;
                    }
                    let owner = worker_escrow
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .take()
                        .expect("migration shutdown escrow must contain exactly one owner");
                    lifecycle.complete_migration_source_close(
                        close_migration_shutdown_ownership(owner),
                        Some(&worker_app),
                    );
                });
                if let Ok(worker) = spawn_migration_thread(task) {
                    inner.migration_worker = Some(worker);
                    migration_start_sender = Some(start_sender);
                }
                migration_escrow = Some(escrow);
            }
            (
                migration_start_sender,
                migration_escrow,
                migration_control,
                action,
            )
        };

        if let Some(control) = migration_control {
            let _ = control.try_send(MigrationWorkerCommand::Shutdown);
        }

        if let Some(start_sender) = migration_start_sender {
            if start_sender.send(()).is_err()
                && let Some(owner) = migration_escrow.as_ref().and_then(|escrow| {
                    escrow
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .take()
                })
            {
                self.complete_migration_source_close(
                    close_migration_shutdown_ownership(owner),
                    Some(&app),
                );
            }
        } else if let Some(owner) = migration_escrow.and_then(|escrow| {
            escrow
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
        }) {
            self.complete_migration_source_close(
                close_migration_shutdown_ownership(owner),
                Some(&app),
            );
        }
        eprintln!(r#"event="application_shutdown" outcome="requested""#);
        match action {
            ShutdownAction::Exit => {
                if self.may_exit() {
                    app.exit(0);
                }
            }
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
            let close_failed = failure.is_some();
            {
                let mut inner = lifecycle.lock();
                inner.state.finish_close(failure);
                inner.close_work_resolved = true;
            }
            if close_failed {
                eprintln!(r#"event="application_shutdown" outcome="close_failed""#);
            } else {
                eprintln!(r#"event="application_shutdown" outcome="close_succeeded""#);
                if lifecycle.may_exit() {
                    app.exit(0);
                }
            }
        });
        self.lock().close_worker = Some(worker);
    }

    pub(crate) fn may_exit(&self) -> bool {
        let inner = self.lock();
        inner.startup_work_resolved
            && inner.close_work_resolved
            && inner.setup_work_resolved
            && inner.migration_work_resolved
            && matches!(inner.state, LifecycleState::Failed(_))
            && inner.migration_confirmation.ownership_resolved_for_exit()
    }

    pub(crate) fn join_workers(&self) {
        let (startup, close, setup, migration) = {
            let mut inner = self.lock();
            let startup = (!matches!(inner.state, LifecycleState::StartupCloseRetryRequired))
                .then(|| inner.startup_worker.take())
                .flatten();
            let setup = inner
                .setup_work_resolved
                .then(|| inner.setup_worker.take())
                .flatten();
            let migration = (inner.migration_work_resolved
                && inner.migration_confirmation.ownership_resolved_for_exit())
            .then(|| inner.migration_worker.take())
            .flatten();
            (startup, inner.close_worker.take(), setup, migration)
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
        if let Some(worker) = migration {
            let _ = worker.join();
        }
    }
}

#[cfg(windows)]
fn claim_migration_preparation(inner: &mut LifecycleInner) -> MigrationPreparationClaim {
    if !inner.migration_confirmation.is_authorized() {
        return MigrationPreparationClaim::NoWork;
    }
    if !matches!(inner.state, LifecycleState::Ready(_)) {
        return MigrationPreparationClaim::ShutdownWon(
            inner
                .migration_confirmation
                .consume_authorization()
                .expect("only the exact lifecycle Authorized state is consumed after shutdown"),
        );
    }
    inner.migration_preparation = MigrationPreparationState::Preparing;
    let LifecycleState::Ready(operational) =
        std::mem::replace(&mut inner.state, LifecycleState::Stopping)
    else {
        unreachable!("Ready state was checked before migration ownership transfer")
    };
    MigrationPreparationClaim::Ready(operational)
}

#[cfg(windows)]
fn close_authorized_migration_for_shutdown(
    authorized: AuthorizedProductionDatabaseMigrationHandoff,
) -> MigrationWorkerRetryOutcome {
    match authorized.close() {
        ProductionDatabaseConnectionCloseOutcome::Closed => MigrationWorkerRetryOutcome::Resolved,
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            MigrationWorkerRetryOutcome::Retained(MigrationWorkerParkedOwnership::PreparationClose(
                ProductionDatabaseMigrationPreparationFailure::SourceClose(failure),
            ))
        }
    }
}

#[cfg(windows)]
fn retry_migration_worker_ownership(
    owner: MigrationWorkerParkedOwnership,
    lifecycle: &ApplicationLifecycle,
) -> MigrationWorkerRetryOutcome {
    match owner {
        MigrationWorkerParkedOwnership::OperationalClose(failure) => match failure.retry_close() {
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                MigrationWorkerRetryOutcome::Retained(
                    MigrationWorkerParkedOwnership::OperationalClose(failure),
                )
            }
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                let authorized = {
                    let mut inner = lifecycle.lock();
                    inner.state = LifecycleState::Failed(CoarseStartupFailure::StartupInterrupted);
                    inner
                        .migration_confirmation
                        .consume_authorization()
                        .expect("shutdown consumes the retained exact Authorized migration")
                };
                match authorized.close() {
                    ProductionDatabaseConnectionCloseOutcome::Closed => {
                        MigrationWorkerRetryOutcome::Resolved
                    }
                    ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                        MigrationWorkerRetryOutcome::Retained(
                            MigrationWorkerParkedOwnership::PreparationClose(
                                ProductionDatabaseMigrationPreparationFailure::SourceClose(failure),
                            ),
                        )
                    }
                }
            }
        },
        MigrationWorkerParkedOwnership::PreparationClose(failure) => {
            retry_migration_preparation_failure(failure)
        }
        MigrationWorkerParkedOwnership::Prepared(prepared) => {
            let shutdown = prepared.abort_before_exposure_for_shutdown();
            match shutdown.retry_source_close() {
                UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome::Closed(
                    shutdown,
                ) => {
                    drop(shutdown);
                    MigrationWorkerRetryOutcome::Resolved
                }
                UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome::Failed(
                    shutdown,
                ) => MigrationWorkerRetryOutcome::Retained(
                    MigrationWorkerParkedOwnership::PreparedShutdown(shutdown),
                ),
            }
        }
        MigrationWorkerParkedOwnership::PreparedShutdown(shutdown) => {
            match shutdown.retry_source_close() {
                UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome::Closed(
                    shutdown,
                ) => {
                    drop(shutdown);
                    MigrationWorkerRetryOutcome::Resolved
                }
                UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome::Failed(
                    shutdown,
                ) => MigrationWorkerRetryOutcome::Retained(
                    MigrationWorkerParkedOwnership::PreparedShutdown(shutdown),
                ),
            }
        }
    }
}

#[cfg(windows)]
fn retry_migration_preparation_failure(
    failure: ProductionDatabaseMigrationPreparationFailure,
) -> MigrationWorkerRetryOutcome {
    use ProductionDatabaseMigrationPreparationFailure as Failure;

    match failure {
        Failure::FullIntegrityClose(failure) => match failure.retry_close() {
            FullIntegrityValidationCloseRetryOutcome::Closed(_) => {
                MigrationWorkerRetryOutcome::Resolved
            }
            FullIntegrityValidationCloseRetryOutcome::Failed(failure) => {
                MigrationWorkerRetryOutcome::Retained(
                    MigrationWorkerParkedOwnership::PreparationClose(
                        Failure::FullIntegrityClose(failure),
                    ),
                )
            }
        },
        Failure::SourceClose(failure) => match failure.retry_close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                MigrationWorkerRetryOutcome::Resolved
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                MigrationWorkerRetryOutcome::Retained(
                    MigrationWorkerParkedOwnership::PreparationClose(Failure::SourceClose(failure)),
                )
            }
        },
        Failure::BackupStage(failure) => match failure.retry_source_close() {
            ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Closed(failure) => {
                drop(failure);
                MigrationWorkerRetryOutcome::Resolved
            }
            ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Failed(failure) => {
                MigrationWorkerRetryOutcome::Retained(
                    MigrationWorkerParkedOwnership::PreparationClose(Failure::BackupStage(failure)),
                )
            }
        },
        Failure::BackupStageWriterClose(failure) => match failure.retry_source_close() {
            ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Failed(failure) => {
                MigrationWorkerRetryOutcome::Retained(
                    MigrationWorkerParkedOwnership::PreparationClose(
                        Failure::BackupStageWriterClose(failure),
                    ),
                )
            }
            ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Closed(failure) => {
                match failure.retry_close() {
                    ProductionDatabaseMigrationBackupStageWriterCloseRetryOutcome::Closed(
                        failure,
                    ) => {
                        drop(failure);
                        MigrationWorkerRetryOutcome::Resolved
                    }
                    ProductionDatabaseMigrationBackupStageWriterCloseRetryOutcome::Failed(
                        failure,
                    ) => MigrationWorkerRetryOutcome::Retained(
                        MigrationWorkerParkedOwnership::PreparationClose(
                            Failure::BackupStageWriterClose(failure),
                        ),
                    ),
                }
            }
        },
        Failure::BackupStageVerifierClose(failure) => match failure.retry_source_close() {
            ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Failed(failure) => {
                MigrationWorkerRetryOutcome::Retained(
                    MigrationWorkerParkedOwnership::PreparationClose(
                        Failure::BackupStageVerifierClose(failure),
                    ),
                )
            }
            ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Closed(failure) => {
                match failure.retry_close() {
                    ProductionDatabaseMigrationBackupStageVerifierCloseRetryOutcome::Closed(
                        failure,
                    ) => {
                        drop(failure);
                        MigrationWorkerRetryOutcome::Resolved
                    }
                    ProductionDatabaseMigrationBackupStageVerifierCloseRetryOutcome::Failed(
                        failure,
                    ) => MigrationWorkerRetryOutcome::Retained(
                        MigrationWorkerParkedOwnership::PreparationClose(
                            Failure::BackupStageVerifierClose(failure),
                        ),
                    ),
                }
            }
        },
        Failure::RecoveryEnvelope(failure) => match failure.retry_source_close() {
            ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome::Closed(failure) => {
                drop(failure);
                MigrationWorkerRetryOutcome::Resolved
            }
            ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome::Failed(failure) => {
                MigrationWorkerRetryOutcome::Retained(
                    MigrationWorkerParkedOwnership::PreparationClose(
                        Failure::RecoveryEnvelope(failure),
                    ),
                )
            }
        },
        Failure::RecoveryEnvelopeVerifierClose(failure) => {
            match failure.retry_source_close() {
                ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome::Failed(
                    failure,
                ) => MigrationWorkerRetryOutcome::Retained(
                    MigrationWorkerParkedOwnership::PreparationClose(
                        Failure::RecoveryEnvelopeVerifierClose(failure),
                    ),
                ),
                ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome::Closed(
                    failure,
                ) => match failure.retry_close() {
                    ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseRetryOutcome::Closed(
                        failure,
                    ) => {
                        drop(failure);
                        MigrationWorkerRetryOutcome::Resolved
                    }
                    ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseRetryOutcome::Failed(
                        failure,
                    ) => MigrationWorkerRetryOutcome::Retained(
                        MigrationWorkerParkedOwnership::PreparationClose(
                            Failure::RecoveryEnvelopeVerifierClose(failure),
                        ),
                    ),
                },
            }
        }
    }
}

#[cfg(windows)]
type SetupThreadTask = Box<dyn FnOnce() + Send + 'static>;

#[cfg(windows)]
type MigrationThreadTask = Box<dyn FnOnce() + Send + 'static>;

#[cfg(windows)]
fn spawn_setup_thread(task: SetupThreadTask) -> std::io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("first-time-setup".to_owned())
        .spawn(task)
}

#[cfg(windows)]
fn spawn_migration_thread(task: MigrationThreadTask) -> std::io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("production-database-migration".to_owned())
        .spawn(task)
}

#[cfg(windows)]
fn close_migration_shutdown_ownership(
    owner: ProductionDatabaseMigrationShutdownOwnership,
) -> ProductionDatabaseConnectionCloseOutcome {
    match owner {
        ProductionDatabaseMigrationShutdownOwnership::Pending(pending) => pending.close(),
        ProductionDatabaseMigrationShutdownOwnership::Authorized(source) => source.close(),
    }
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
fn run_production_database_migration_discovery(
    app: &AppHandle,
) -> ProductionDatabaseMigrationDiscoveryWorkerResult {
    let paths = match StartupPaths::from_app(app) {
        Ok(paths) => paths,
        Err(_) => return ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable,
    };
    let StartupPaths {
        evidence: evidence_paths,
        database_key: key_paths,
        freshness_anchor: anchor_paths,
        database: database_path,
        ..
    } = paths;

    let early_installation_evidence = observe_production_installation_evidence(&evidence_paths);
    if !is_initialized_with_expected_storage(&early_installation_evidence) {
        return ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable;
    }

    let trusted_assessment =
        match load_trusted_current_installation_evidence_assessment(&evidence_paths) {
            Ok(assessment) => assessment,
            Err(_) => return ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable,
        };
    let anchor_observation = observe_normalized_current_freshness_anchor(
        &anchor_paths,
        trusted_assessment.trusted_identity(),
    );
    let key_presence = inspect_database_key_active_presence(&key_paths);
    let loaded_key = match load_active_database_key_wrapper(&key_paths, key_presence) {
        Ok(key) => key,
        Err(_) => return ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable,
    };
    let key_candidate = match recover_database_key_candidate_from_loaded_wrapper(&loaded_key) {
        Ok(candidate) => candidate,
        Err(_) => return ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable,
    };
    let key = match bind_database_key_candidate_to_trusted_installation_evidence(
        key_candidate,
        &trusted_assessment,
    ) {
        Ok(key) => key,
        Err(_) => return ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable,
    };

    let inspected = match inspect_production_database_file(&database_path) {
        ProductionDatabaseInspection::Present(inspected) => inspected,
        ProductionDatabaseInspection::Missing
        | ProductionDatabaseInspection::Unavailable
        | ProductionDatabaseInspection::Invalid => {
            return ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable;
        }
    };
    let opened = match open_keyed_production_database_read_only(database_path, inspected, key) {
        Ok(opened) => opened,
        Err(crate::production_database_connection_handoff::ProductionDatabaseConnectionOpenError::Failed) => {
            return ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable;
        }
        Err(crate::production_database_connection_handoff::ProductionDatabaseConnectionOpenError::CloseFailed(failure)) => {
            return ProductionDatabaseMigrationDiscoveryWorkerResult::CloseRetryRequired(
                ProductionDatabaseMigrationDiscoveryCloseFailure::Construction(failure),
            );
        }
    };

    let validated = match validate_production_database_readability_and_integrity(opened) {
        ProductionDatabaseValidationOutcome::Validated(owner) => owner,
        ProductionDatabaseValidationOutcome::Failed(_) => {
            return ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable;
        }
        ProductionDatabaseValidationOutcome::CloseFailed(failure) => {
            return ProductionDatabaseMigrationDiscoveryWorkerResult::CloseRetryRequired(
                ProductionDatabaseMigrationDiscoveryCloseFailure::Validation(failure),
            );
        }
    };
    let metadata = match validate_production_database_live_metadata_and_headers(validated) {
        LiveMetadataAndHeaderValidationOutcome::Validated(owner) => owner,
        LiveMetadataAndHeaderValidationOutcome::Failed(_) => {
            return ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable;
        }
        LiveMetadataAndHeaderValidationOutcome::CloseFailed(failure) => {
            return ProductionDatabaseMigrationDiscoveryWorkerResult::CloseRetryRequired(
                ProductionDatabaseMigrationDiscoveryCloseFailure::Metadata(failure),
            );
        }
    };
    let correspondence =
        match validate_production_database_evidence_correspondence(metadata, trusted_assessment) {
            DatabaseEvidenceCorrespondenceValidationOutcome::Validated(owner) => owner,
            DatabaseEvidenceCorrespondenceValidationOutcome::Mismatch(_) => {
                return ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable;
            }
            DatabaseEvidenceCorrespondenceValidationOutcome::CloseFailed(failure) => {
                return ProductionDatabaseMigrationDiscoveryWorkerResult::CloseRetryRequired(
                    ProductionDatabaseMigrationDiscoveryCloseFailure::Correspondence(failure),
                );
            }
        };
    let fresh = match validate_production_database_freshness(correspondence, anchor_observation) {
        ProductionDatabaseFreshnessValidationOutcome::Validated(owner) => owner,
        ProductionDatabaseFreshnessValidationOutcome::Failed(_) => {
            return ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable;
        }
        ProductionDatabaseFreshnessValidationOutcome::CloseFailed(failure) => {
            return ProductionDatabaseMigrationDiscoveryWorkerResult::CloseRetryRequired(
                ProductionDatabaseMigrationDiscoveryCloseFailure::Freshness(failure),
            );
        }
    };

    // This is intentionally the final external observation before the fixed offer transition.
    let final_installation_evidence = observe_production_installation_evidence(&evidence_paths);
    if !is_initialized_with_expected_storage(&final_installation_evidence) {
        return match fresh.close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                ProductionDatabaseMigrationDiscoveryWorkerResult::CloseRetryRequired(
                    ProductionDatabaseMigrationDiscoveryCloseFailure::Candidate(failure),
                )
            }
        };
    }

    match offer_production_database_migration_opportunity(fresh, final_installation_evidence) {
        ProductionDatabaseMigrationOpportunityOutcome::Offered(opportunity) => {
            ProductionDatabaseMigrationDiscoveryWorkerResult::Candidate(
                ProductionDatabaseMigrationPendingContext::new(
                    opportunity,
                    ProductionDatabaseMigrationRevalidationContext::new(
                        evidence_paths,
                        anchor_paths,
                    ),
                ),
            )
        }
        ProductionDatabaseMigrationOpportunityOutcome::Failed(_) => {
            ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable
        }
        ProductionDatabaseMigrationOpportunityOutcome::CloseFailed(failure) => {
            ProductionDatabaseMigrationDiscoveryWorkerResult::CloseRetryRequired(
                ProductionDatabaseMigrationDiscoveryCloseFailure::Opportunity(failure),
            )
        }
    }
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
    use std::{
        rc::Rc,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        time::Duration,
    };

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

    #[cfg(windows)]
    fn establish_migration_pending(
        lifecycle: &ApplicationLifecycle,
        root: &std::path::Path,
        opportunity: crate::production_database_connection_handoff::ProductionDatabaseMigrationOpportunity,
    ) {
        use production_database_migration_confirmation::ProductionDatabaseMigrationPendingContext;

        lifecycle
            .lock()
            .migration_confirmation
            .establish_pending(ProductionDatabaseMigrationPendingContext::new(
                opportunity,
                crate::production_database_connection_handoff::genuine_production_database_migration_revalidation_context_for_test(root),
            ))
            .expect("test must establish one genuine pending opportunity");
    }

    #[cfg(windows)]
    fn authorize_migration(lifecycle: &ApplicationLifecycle) {
        let work = lifecycle
            .lock()
            .migration_confirmation
            .begin_revalidation()
            .expect("test must begin genuine pending revalidation");
        assert!(matches!(
            lifecycle
                .lock()
                .migration_confirmation
                .complete_revalidation(work.revalidate()),
            Ok(ProductionDatabaseMigrationRevalidationCompletion::Authorized)
        ));
    }

    #[cfg(windows)]
    fn wait_for_migration_state(
        lifecycle: &ApplicationLifecycle,
        expected: production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest,
    ) {
        for _ in 0..200 {
            if lifecycle.lock().migration_confirmation.state_for_test() == expected {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("migration worker did not reach the expected state");
    }

    #[cfg(windows)]
    fn install_ready_owner_for_migration_discovery(
        lifecycle: &ApplicationLifecycle,
    ) -> crate::production_database_connection_handoff::MigrationDiscoveryTestRoot {
        let (root, owner) = crate::production_database_connection_handoff::genuine_operational_production_database_for_test();
        lifecycle.lock().state = LifecycleState::Ready(owner);
        root
    }

    #[cfg(windows)]
    fn close_ready_owner_for_migration_discovery(lifecycle: &ApplicationLifecycle) {
        let owner = {
            let mut inner = lifecycle.lock();
            let LifecycleState::Ready(owner) = std::mem::replace(
                &mut inner.state,
                LifecycleState::Failed(CoarseStartupFailure::StartupInterrupted),
            ) else {
                panic!("test lifecycle must still own the operational database in Ready");
            };
            owner
        };
        assert!(close_operational(owner).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn migration_discovery_non_ready_does_not_consume_not_attempted() {
        let lifecycle = ApplicationLifecycle::new();
        for _ in 0..2 {
            assert_eq!(
                lifecycle.request_production_database_migration_discovery_with(
                    None,
                    || panic!("non-Ready discovery must not run"),
                    |_| panic!("non-Ready discovery must not spawn"),
                ),
                ProductionDatabaseMigrationDiscoveryRequestOutcome::NotReady
            );
            assert_eq!(
                lifecycle.lock().migration_discovery,
                ProductionDatabaseMigrationDiscoveryState::NotAttempted
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn migration_discovery_ready_is_one_shot_and_keeps_operational_owner_installed() {
        let lifecycle = ApplicationLifecycle::new();
        let operational_root = install_ready_owner_for_migration_discovery(&lifecycle);
        let (candidate_root, opportunity) = crate::production_database_connection_handoff::genuine_production_database_migration_opportunity_for_test();
        let context = crate::production_database_connection_handoff::genuine_production_database_migration_revalidation_context_for_test(candidate_root.path());

        assert_eq!(
            lifecycle.request_production_database_migration_discovery_with(
                None,
                move || {
                    ProductionDatabaseMigrationDiscoveryWorkerResult::Candidate(
                        ProductionDatabaseMigrationPendingContext::new(opportunity, context),
                    )
                },
                spawn_migration_thread,
            ),
            ProductionDatabaseMigrationDiscoveryRequestOutcome::Started
        );
        lifecycle.join_workers();
        {
            let inner = lifecycle.lock();
            assert!(matches!(inner.state, LifecycleState::Ready(_)));
            assert_eq!(
                inner.migration_discovery,
                ProductionDatabaseMigrationDiscoveryState::Finished
            );
            assert_eq!(
                inner.migration_confirmation.state_for_test(),
                production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest::Pending
            );
            assert!(inner.migration_work_resolved);
        }
        assert_eq!(
            lifecycle.request_production_database_migration_discovery_with(
                None,
                || panic!("finished discovery must not run again"),
                |_| panic!("finished discovery must not spawn again"),
            ),
            ProductionDatabaseMigrationDiscoveryRequestOutcome::AlreadyAttempted
        );

        let pending = lifecycle
            .lock()
            .migration_confirmation
            .invalidate_for_shutdown()
            .expect("pending discovery candidate must remain lifecycle-owned");
        assert!(matches!(
            close_migration_shutdown_ownership(pending),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        close_ready_owner_for_migration_discovery(&lifecycle);
        candidate_root.assert_exact_cleanup();
        operational_root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn migration_discovery_spawn_failure_consumes_attempt_without_retry() {
        let lifecycle = ApplicationLifecycle::new();
        let operational_root = install_ready_owner_for_migration_discovery(&lifecycle);
        assert_eq!(
            lifecycle.request_production_database_migration_discovery_with(
                None,
                || ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable,
                |_| Err(std::io::Error::other("synthetic spawn failure")),
            ),
            ProductionDatabaseMigrationDiscoveryRequestOutcome::Unavailable
        );
        {
            let inner = lifecycle.lock();
            assert_eq!(
                inner.migration_discovery,
                ProductionDatabaseMigrationDiscoveryState::Finished
            );
            assert!(inner.migration_work_resolved);
            assert!(inner.migration_worker.is_none());
        }
        assert_eq!(
            lifecycle.request_production_database_migration_discovery_with(
                None,
                || panic!("spawn failure must consume discovery"),
                |_| panic!("spawn failure must prevent retry"),
            ),
            ProductionDatabaseMigrationDiscoveryRequestOutcome::AlreadyAttempted
        );
        close_ready_owner_for_migration_discovery(&lifecycle);
        operational_root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn migration_discovery_start_failure_consumes_attempt_and_resolves_accounting() {
        let lifecycle = ApplicationLifecycle::new();
        let operational_root = install_ready_owner_for_migration_discovery(&lifecycle);
        assert_eq!(
            lifecycle.request_production_database_migration_discovery_with(
                None,
                || panic!("discarded start-gated work must not run"),
                |task| {
                    drop(task);
                    Ok(thread::spawn(|| {}))
                },
            ),
            ProductionDatabaseMigrationDiscoveryRequestOutcome::Unavailable
        );
        {
            let inner = lifecycle.lock();
            assert_eq!(
                inner.migration_discovery,
                ProductionDatabaseMigrationDiscoveryState::Finished
            );
            assert!(inner.migration_work_resolved);
            assert!(inner.migration_worker.is_some());
        }
        assert_eq!(
            lifecycle.request_production_database_migration_discovery_with(
                None,
                || panic!("start failure must consume discovery"),
                |_| panic!("start failure must prevent retry"),
            ),
            ProductionDatabaseMigrationDiscoveryRequestOutcome::AlreadyAttempted
        );
        lifecycle.join_workers();
        close_ready_owner_for_migration_discovery(&lifecycle);
        operational_root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn migration_discovery_start_gate_precedes_trust_work_and_blocks_concurrent_request() {
        let lifecycle = ApplicationLifecycle::new();
        let operational_root = install_ready_owner_for_migration_discovery(&lifecycle);
        let ran = Arc::new(AtomicBool::new(false));
        let worker_ran = Arc::clone(&ran);
        let (wrapper_ready_sender, wrapper_ready_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let request_lifecycle = Arc::clone(&lifecycle);
        let request = thread::spawn(move || {
            request_lifecycle.request_production_database_migration_discovery_with(
                None,
                move || {
                    worker_ran.store(true, Ordering::SeqCst);
                    ProductionDatabaseMigrationDiscoveryWorkerResult::Unavailable
                },
                move |task| {
                    Ok(thread::spawn(move || {
                        wrapper_ready_sender.send(()).unwrap();
                        release_receiver.recv().unwrap();
                        task();
                    }))
                },
            )
        });
        wrapper_ready_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        {
            let inner = lifecycle.lock();
            assert_eq!(
                inner.migration_discovery,
                ProductionDatabaseMigrationDiscoveryState::InProgress
            );
            assert!(!inner.migration_work_resolved);
            assert!(inner.migration_worker.is_some());
        }
        assert!(!ran.load(Ordering::SeqCst));
        assert_eq!(
            lifecycle.request_production_database_migration_discovery_with(
                None,
                || panic!("concurrent discovery must not run"),
                |_| panic!("concurrent discovery must not spawn"),
            ),
            ProductionDatabaseMigrationDiscoveryRequestOutcome::AlreadyAttempted
        );
        release_sender.send(()).unwrap();
        assert_eq!(
            request.join().unwrap(),
            ProductionDatabaseMigrationDiscoveryRequestOutcome::Started
        );
        lifecycle.join_workers();
        assert!(ran.load(Ordering::SeqCst));
        assert_eq!(
            lifecycle.lock().migration_discovery,
            ProductionDatabaseMigrationDiscoveryState::Finished
        );
        assert_eq!(
            lifecycle.request_production_database_migration_discovery_with(
                None,
                || panic!("completed unavailable discovery must not retry"),
                |_| panic!("completed unavailable discovery must not respawn"),
            ),
            ProductionDatabaseMigrationDiscoveryRequestOutcome::AlreadyAttempted
        );
        close_ready_owner_for_migration_discovery(&lifecycle);
        operational_root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn migration_discovery_late_candidate_after_shutdown_is_closed_without_pending() {
        let lifecycle = ApplicationLifecycle::new();
        let operational_root = install_ready_owner_for_migration_discovery(&lifecycle);
        let (candidate_root, opportunity) = crate::production_database_connection_handoff::genuine_production_database_migration_opportunity_for_test();
        let context = crate::production_database_connection_handoff::genuine_production_database_migration_revalidation_context_for_test(candidate_root.path());
        let operational_owner = {
            let mut inner = lifecycle.lock();
            inner.migration_discovery = ProductionDatabaseMigrationDiscoveryState::InProgress;
            inner.migration_work_resolved = false;
            let ShutdownAction::Close(owner) = inner.state.begin_shutdown() else {
                panic!("Ready shutdown must return the ordinary operational owner");
            };
            inner.migration_discovery = ProductionDatabaseMigrationDiscoveryState::Finished;
            owner
        };
        assert!(close_operational(operational_owner).is_none());
        lifecycle.lock().state.finish_close(None);

        lifecycle.complete_migration_discovery(
            ProductionDatabaseMigrationDiscoveryWorkerResult::Candidate(
                ProductionDatabaseMigrationPendingContext::new(opportunity, context),
            ),
            None,
        );
        {
            let inner = lifecycle.lock();
            assert_eq!(
                inner.migration_confirmation.state_for_test(),
                production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest::NotOffered
            );
            assert_eq!(
                inner.migration_discovery,
                ProductionDatabaseMigrationDiscoveryState::Finished
            );
            assert!(inner.migration_work_resolved);
        }
        candidate_root.assert_exact_cleanup();
        operational_root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn migration_discovery_late_candidate_close_failure_is_retained_and_blocks_exit() {
        let lifecycle = ApplicationLifecycle::new();
        let (candidate_root, opportunity) = crate::production_database_connection_handoff::genuine_production_database_migration_opportunity_for_test();
        let context = crate::production_database_connection_handoff::genuine_production_database_migration_revalidation_context_for_test(candidate_root.path());
        {
            let mut inner = lifecycle.lock();
            inner.state = LifecycleState::Failed(CoarseStartupFailure::StartupInterrupted);
            inner.startup_work_resolved = true;
            inner.migration_discovery = ProductionDatabaseMigrationDiscoveryState::Finished;
            inner.migration_work_resolved = false;
        }
        crate::production_database_connection_handoff::with_production_database_close_failure_injected(
            || {
                lifecycle.complete_migration_discovery(
                    ProductionDatabaseMigrationDiscoveryWorkerResult::Candidate(
                        ProductionDatabaseMigrationPendingContext::new(opportunity, context),
                    ),
                    None,
                );
            },
        );
        {
            let inner = lifecycle.lock();
            assert_eq!(
                inner.migration_confirmation.state_for_test(),
                production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest::DiscoveryCloseRetryRequired
            );
            assert!(!inner.migration_work_resolved);
        }
        assert!(!lifecycle.may_exit());
        assert!(
            lifecycle
                .lock()
                .migration_confirmation
                .retry_discovery_candidate_close_for_test()
        );
        candidate_root.assert_exact_cleanup();
    }

    #[test]
    fn migration_discovery_producer_is_private_fresh_ordered_and_stops_at_pending() {
        const SOURCE: &str = include_str!("application_lifecycle.rs");
        const BOOTSTRAP: &str = include_str!("lib.rs");
        const FRONTEND: &str = include_str!("../../src/App.tsx");
        let production = SOURCE.split_once("#[cfg(test)]\nmod tests").unwrap().0;
        let worker = production
            .split_once("fn run_production_database_migration_discovery(")
            .unwrap()
            .1
            .split_once("#[cfg(windows)]\nfn run_production_startup(")
            .unwrap()
            .0;
        let ordered = [
            "StartupPaths::from_app(app)",
            "let early_installation_evidence",
            "load_trusted_current_installation_evidence_assessment",
            "observe_normalized_current_freshness_anchor",
            "inspect_database_key_active_presence",
            "load_active_database_key_wrapper",
            "recover_database_key_candidate_from_loaded_wrapper",
            "bind_database_key_candidate_to_trusted_installation_evidence",
            "inspect_production_database_file",
            "open_keyed_production_database_read_only",
            "validate_production_database_readability_and_integrity",
            "validate_production_database_live_metadata_and_headers",
            "validate_production_database_evidence_correspondence",
            "validate_production_database_freshness",
            "let final_installation_evidence",
            "offer_production_database_migration_opportunity",
            "ProductionDatabaseMigrationPendingContext::new",
        ];
        let mut prior = 0;
        for marker in ordered {
            let position = worker
                .find(marker)
                .unwrap_or_else(|| panic!("missing {marker}"));
            assert!(position >= prior, "out-of-order {marker}");
            prior = position;
        }
        assert_eq!(
            worker
                .matches("observe_production_installation_evidence(&evidence_paths)")
                .count(),
            2
        );
        for forbidden in [
            "begin_production_database_migration_revalidation",
            "spawn_blocking",
            "integrity_check",
            "backup",
            "MigrationPlan",
        ] {
            assert!(!worker.contains(forbidden));
        }
        let request_name = "request_production_database_migration_discovery(";
        assert_eq!(production.matches(request_name).count(), 1);
        assert!(!BOOTSTRAP.contains(request_name));
        assert!(!FRONTEND.contains(request_name));
        let shutdown = production
            .split_once("pub(crate) fn request_shutdown")
            .unwrap()
            .1
            .split_once("fn close_on_worker")
            .unwrap()
            .0;
        let discovery_finished = shutdown
            .find("ProductionDatabaseMigrationDiscoveryState::Finished")
            .unwrap();
        let stopping = shutdown.find("state.begin_shutdown()").unwrap();
        assert!(discovery_finished < stopping);
    }

    #[cfg(windows)]
    #[test]
    fn migration_worker_start_gate_installs_handle_and_accounting_before_execution() {
        use crate::production_database_connection_handoff::genuine_production_database_migration_opportunity_for_test;
        use production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest;

        let lifecycle = ApplicationLifecycle::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        establish_migration_pending(&lifecycle, root.path(), opportunity);
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::clone(&finished);
        let result =
            lifecycle.begin_production_database_migration_revalidation_with(None, |task| {
                let handle = thread::Builder::new()
                    .name("migration-start-gate-test".to_owned())
                    .spawn(move || {
                        task();
                        worker_finished.store(true, Ordering::SeqCst);
                    })?;
                thread::sleep(Duration::from_millis(50));
                assert!(!finished.load(Ordering::SeqCst));
                Ok(handle)
            });
        assert_eq!(
            result,
            ProductionDatabaseMigrationRevalidationRequestOutcome::Started
        );
        assert_eq!(
            lifecycle.begin_production_database_migration_revalidation_with(None, |_| {
                unreachable!("occupied migration worker lane must not spawn again")
            }),
            ProductionDatabaseMigrationRevalidationRequestOutcome::Unavailable
        );
        {
            let inner = lifecycle.lock();
            assert!(inner.migration_worker.is_some());
        }
        wait_for_migration_state(
            &lifecycle,
            ProductionDatabaseMigrationConfirmationStateForTest::Authorized,
        );
        assert!(lifecycle.lock().migration_work_resolved);
        let source = lifecycle
            .lock()
            .migration_confirmation
            .invalidate_for_shutdown()
            .expect("authorized source must remain owned");
        assert!(matches!(
            close_migration_shutdown_ownership(source),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn migration_request_is_exactly_once_and_non_pending_does_not_spawn() {
        let lifecycle = ApplicationLifecycle::new();
        let spawned = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&spawned);
        let result =
            lifecycle.begin_production_database_migration_revalidation_with(None, move |_| {
                observed.store(true, Ordering::SeqCst);
                unreachable!("non-pending request must not spawn")
            });
        assert_eq!(
            result,
            ProductionDatabaseMigrationRevalidationRequestOutcome::NotPending
        );
        assert!(!spawned.load(Ordering::SeqCst));
    }

    #[cfg(windows)]
    #[test]
    fn migration_spawn_failure_recovers_closes_and_terminally_revokes_work() {
        use crate::production_database_connection_handoff::genuine_production_database_migration_opportunity_for_test;
        use production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest;

        let lifecycle = ApplicationLifecycle::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        establish_migration_pending(&lifecycle, root.path(), opportunity);
        let result =
            lifecycle.begin_production_database_migration_revalidation_with(None, |task| {
                drop(task);
                Err(std::io::Error::other("synthetic spawn refusal"))
            });
        assert_eq!(
            result,
            ProductionDatabaseMigrationRevalidationRequestOutcome::Unavailable
        );
        let inner = lifecycle.lock();
        assert!(inner.migration_work_resolved);
        assert!(inner.migration_worker.is_none());
        assert_eq!(
            inner.migration_confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
        drop(inner);
        root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn migration_spawn_failure_close_failure_retains_owner_and_blocks_exit() {
        use crate::production_database_connection_handoff::{
            genuine_production_database_migration_opportunity_for_test,
            with_production_database_close_failure_injected,
        };
        use production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest;

        let lifecycle = ApplicationLifecycle::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        establish_migration_pending(&lifecycle, root.path(), opportunity);
        let result = with_production_database_close_failure_injected(|| {
            lifecycle.begin_production_database_migration_revalidation_with(None, |task| {
                drop(task);
                Err(std::io::Error::other("synthetic spawn refusal"))
            })
        });
        assert_eq!(
            result,
            ProductionDatabaseMigrationRevalidationRequestOutcome::Unavailable
        );
        let inner = lifecycle.lock();
        assert!(!inner.migration_work_resolved);
        assert_eq!(
            inner.migration_confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::RevokedSourceCloseRetryRequired
        );
        drop(inner);
        assert!(!lifecycle.may_exit());
        assert_eq!(lifecycle.status(), StartupStatus::ShutdownIncomplete);
        assert!(
            lifecycle
                .lock()
                .migration_confirmation
                .retry_retained_close_for_test()
        );
        root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn primary_migration_revalidation_failure_resolves_without_double_close() {
        use crate::{
            production_database_connection_handoff::genuine_production_database_migration_opportunity_for_test,
            storage_foundation::installation_evidence_persistence_paths,
        };
        use production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest;

        let lifecycle = ApplicationLifecycle::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        establish_migration_pending(&lifecycle, root.path(), opportunity);
        std::fs::remove_file(
            installation_evidence_persistence_paths(root.path())
                .active_authenticated_evidence
                .as_path(),
        )
        .unwrap();
        assert_eq!(
            lifecycle.begin_production_database_migration_revalidation_with(
                None,
                spawn_migration_thread,
            ),
            ProductionDatabaseMigrationRevalidationRequestOutcome::Started
        );
        wait_for_migration_state(
            &lifecycle,
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked,
        );
        assert!(lifecycle.lock().migration_work_resolved);
        lifecycle.join_workers();
        assert!(lifecycle.lock().migration_worker.is_none());
        root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn revalidation_close_failure_remains_owned_and_unresolved() {
        use crate::{
            production_database_connection_handoff::{
                genuine_production_database_migration_opportunity_for_test,
                with_production_database_close_failure_injected,
            },
            storage_foundation::installation_evidence_persistence_paths,
        };
        use production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest;

        let lifecycle = ApplicationLifecycle::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        establish_migration_pending(&lifecycle, root.path(), opportunity);
        std::fs::remove_file(
            installation_evidence_persistence_paths(root.path())
                .active_authenticated_evidence
                .as_path(),
        )
        .unwrap();
        assert_eq!(
            lifecycle.begin_production_database_migration_revalidation_with(None, |task| {
                thread::Builder::new()
                    .name("migration-close-failure-test".to_owned())
                    .spawn(move || with_production_database_close_failure_injected(task))
            }),
            ProductionDatabaseMigrationRevalidationRequestOutcome::Started
        );
        wait_for_migration_state(
            &lifecycle,
            ProductionDatabaseMigrationConfirmationStateForTest::RevokedCloseRetryRequired,
        );
        assert!(!lifecycle.lock().migration_work_resolved);
        assert!(!lifecycle.may_exit());
        assert!(
            lifecycle
                .lock()
                .migration_confirmation
                .retry_retained_close_for_test()
        );
        root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn shutdown_revocation_wins_over_late_success_and_worker_closes_source() {
        use crate::production_database_connection_handoff::genuine_production_database_migration_opportunity_for_test;
        use production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest;

        let lifecycle = ApplicationLifecycle::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        establish_migration_pending(&lifecycle, root.path(), opportunity);
        let (wrapper_ready_sender, wrapper_ready_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let request_lifecycle = Arc::clone(&lifecycle);
        let request = thread::spawn(move || {
            request_lifecycle.begin_production_database_migration_revalidation_with(
                None,
                move |task| {
                    thread::Builder::new()
                        .name("migration-late-revocation-test".to_owned())
                        .spawn(move || {
                            wrapper_ready_sender.send(()).unwrap();
                            release_receiver.recv().unwrap();
                            task();
                        })
                },
            )
        });
        wrapper_ready_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        {
            let mut inner = lifecycle.lock();
            assert!(
                inner
                    .migration_confirmation
                    .invalidate_for_shutdown()
                    .is_none()
            );
            assert_eq!(
                inner.migration_confirmation.state_for_test(),
                ProductionDatabaseMigrationConfirmationStateForTest::RevalidatingRevokeRequested
            );
        }
        release_sender.send(()).unwrap();
        assert_eq!(
            request.join().unwrap(),
            ProductionDatabaseMigrationRevalidationRequestOutcome::Started
        );
        wait_for_migration_state(
            &lifecycle,
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked,
        );
        assert!(lifecycle.lock().migration_work_resolved);
        lifecycle.join_workers();
        root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn migration_shutdown_won_race_consumes_and_closes_authorized_source() {
        use crate::production_database_connection_handoff::genuine_production_database_migration_opportunity_for_test;
        use production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest;

        let lifecycle = ApplicationLifecycle::new();
        let operational_root = install_ready_owner_for_migration_discovery(&lifecycle);
        let (source_root, opportunity) =
            genuine_production_database_migration_opportunity_for_test();
        establish_migration_pending(&lifecycle, source_root.path(), opportunity);
        authorize_migration(&lifecycle);
        let (control, _receiver) = std::sync::mpsc::sync_channel(1);
        {
            let mut inner = lifecycle.lock();
            inner.startup_work_resolved = true;
            inner.migration_work_resolved = false;
            inner.migration_control = Some(control);
        }
        let exclusivity = match acquire_production_database_migration_cross_process_exclusivity() {
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Acquired(owner) => owner,
            _ => panic!("test must acquire migration exclusivity"),
        };
        let operational = {
            let mut inner = lifecycle.lock();
            let ShutdownAction::Close(operational) = inner.state.begin_shutdown() else {
                panic!("shutdown must win the Ready operational owner");
            };
            inner.close_work_resolved = false;
            assert_eq!(
                inner.migration_confirmation.state_for_test(),
                ProductionDatabaseMigrationConfirmationStateForTest::Authorized
            );
            operational
        };

        let authorized = {
            let mut inner = lifecycle.lock();
            let MigrationPreparationClaim::ShutdownWon(authorized) =
                claim_migration_preparation(&mut inner)
            else {
                panic!("authorized non-Ready worker must claim shutdown-only ownership");
            };
            assert_eq!(
                inner.migration_confirmation.state_for_test(),
                ProductionDatabaseMigrationConfirmationStateForTest::Consumed
            );
            assert!(
                inner
                    .migration_confirmation
                    .consume_authorization()
                    .is_err()
            );
            assert_eq!(
                inner.migration_preparation,
                MigrationPreparationState::Inactive
            );
            authorized
        };
        assert!(matches!(
            close_authorized_migration_for_shutdown(authorized),
            MigrationWorkerRetryOutcome::Resolved
        ));
        assert!(matches!(
            acquire_production_database_migration_cross_process_exclusivity(),
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::AlreadyHeld
        ));
        assert!(!lifecycle.lock().migration_work_resolved);
        drop(exclusivity);
        lifecycle.finish_migration_preparation_worker(None);
        assert!(lifecycle.lock().migration_work_resolved);
        assert!(!lifecycle.may_exit());

        assert!(close_operational(operational).is_none());
        {
            let mut inner = lifecycle.lock();
            inner.close_work_resolved = true;
            inner.state.finish_close(None);
        }
        assert!(lifecycle.may_exit());
        source_root.assert_exact_cleanup();
        operational_root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn migration_shutdown_won_source_close_failure_retries_only_close() {
        use crate::production_database_connection_handoff::{
            genuine_production_database_migration_opportunity_for_test,
            with_production_database_close_failure_injected,
        };
        use production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest;

        let lifecycle = ApplicationLifecycle::new();
        let operational_root = install_ready_owner_for_migration_discovery(&lifecycle);
        let (source_root, opportunity) =
            genuine_production_database_migration_opportunity_for_test();
        establish_migration_pending(&lifecycle, source_root.path(), opportunity);
        authorize_migration(&lifecycle);
        let (control, _receiver) = std::sync::mpsc::sync_channel(1);
        {
            let mut inner = lifecycle.lock();
            inner.startup_work_resolved = true;
            inner.migration_work_resolved = false;
            inner.migration_control = Some(control);
        }
        let exclusivity = match acquire_production_database_migration_cross_process_exclusivity() {
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Acquired(owner) => owner,
            _ => panic!("test must acquire migration exclusivity"),
        };
        let operational = {
            let mut inner = lifecycle.lock();
            let ShutdownAction::Close(operational) = inner.state.begin_shutdown() else {
                panic!("shutdown must win the Ready operational owner");
            };
            inner.close_work_resolved = false;
            operational
        };
        let authorized = {
            let mut inner = lifecycle.lock();
            let MigrationPreparationClaim::ShutdownWon(authorized) =
                claim_migration_preparation(&mut inner)
            else {
                panic!("authorized non-Ready worker must claim shutdown-only ownership");
            };
            authorized
        };
        let retained = with_production_database_close_failure_injected(|| {
            close_authorized_migration_for_shutdown(authorized)
        });
        let MigrationWorkerRetryOutcome::Retained(
            MigrationWorkerParkedOwnership::PreparationClose(failure),
        ) = retained
        else {
            panic!("injected source close failure must remain worker-owned");
        };
        assert!(matches!(
            &failure,
            ProductionDatabaseMigrationPreparationFailure::SourceClose(_)
        ));
        lifecycle.lock().migration_preparation = MigrationPreparationState::CloseRetryRequired;
        assert!(!lifecycle.lock().migration_work_resolved);
        assert!(!lifecycle.may_exit());
        assert!(matches!(
            acquire_production_database_migration_cross_process_exclusivity(),
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::AlreadyHeld
        ));

        let retained = with_production_database_close_failure_injected(|| {
            retry_migration_preparation_failure(failure)
        });
        let MigrationWorkerRetryOutcome::Retained(
            MigrationWorkerParkedOwnership::PreparationClose(failure),
        ) = retained
        else {
            panic!("repeated failure must retain only preparation source-close ownership");
        };
        assert!(matches!(
            &failure,
            ProductionDatabaseMigrationPreparationFailure::SourceClose(_)
        ));
        assert!(!lifecycle.lock().migration_work_resolved);
        assert!(matches!(
            acquire_production_database_migration_cross_process_exclusivity(),
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::AlreadyHeld
        ));
        assert!(matches!(
            retry_migration_preparation_failure(failure),
            MigrationWorkerRetryOutcome::Resolved
        ));
        assert!(!lifecycle.lock().migration_work_resolved);
        drop(exclusivity);
        lifecycle.finish_migration_preparation_worker(None);
        let released = match acquire_production_database_migration_cross_process_exclusivity() {
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Acquired(owner) => owner,
            _ => panic!("resolved migration worker must release exclusivity"),
        };
        drop(released);
        assert_eq!(
            lifecycle.lock().migration_confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Consumed
        );
        assert!(lifecycle.lock().migration_work_resolved);

        assert!(close_operational(operational).is_none());
        {
            let mut inner = lifecycle.lock();
            inner.close_work_resolved = true;
            inner.state.finish_close(None);
        }
        assert!(lifecycle.may_exit());
        source_root.assert_exact_cleanup();
        operational_root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn migration_authorized_ready_claim_preserves_preparation_transfer() {
        use crate::production_database_connection_handoff::{
            ProductionDatabaseConnectionCloseOutcome,
            genuine_production_database_migration_opportunity_for_test,
        };
        use production_database_migration_confirmation::ProductionDatabaseMigrationConfirmationStateForTest;

        let lifecycle = ApplicationLifecycle::new();
        let operational_root = install_ready_owner_for_migration_discovery(&lifecycle);
        let (source_root, opportunity) =
            genuine_production_database_migration_opportunity_for_test();
        establish_migration_pending(&lifecycle, source_root.path(), opportunity);
        authorize_migration(&lifecycle);

        let operational = {
            let mut inner = lifecycle.lock();
            let MigrationPreparationClaim::Ready(operational) =
                claim_migration_preparation(&mut inner)
            else {
                panic!("authorized Ready worker must transfer the operational owner");
            };
            assert_eq!(
                inner.migration_preparation,
                MigrationPreparationState::Preparing
            );
            assert_eq!(
                inner.migration_confirmation.state_for_test(),
                ProductionDatabaseMigrationConfirmationStateForTest::Authorized
            );
            operational
        };
        assert!(close_operational(operational).is_none());
        let authorized = lifecycle
            .lock()
            .migration_confirmation
            .consume_authorization()
            .expect("normal preparation path must retain exact authorization until transfer");
        assert!(matches!(
            authorized.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        source_root.assert_exact_cleanup();
        operational_root.assert_exact_cleanup();
    }

    #[cfg(windows)]
    #[test]
    fn migration_non_authorized_claim_remains_no_work() {
        let lifecycle = ApplicationLifecycle::new();
        let operational_root = install_ready_owner_for_migration_discovery(&lifecycle);
        {
            let mut inner = lifecycle.lock();
            assert!(matches!(
                claim_migration_preparation(&mut inner),
                MigrationPreparationClaim::NoWork
            ));
            assert!(matches!(inner.state, LifecycleState::Ready(_)));
            assert_eq!(
                inner.migration_preparation,
                MigrationPreparationState::Inactive
            );
            assert!(inner.migration_confirmation.is_not_offered());
        }
        close_ready_owner_for_migration_discovery(&lifecycle);
        operational_root.assert_exact_cleanup();
    }

    #[test]
    fn migration_worker_surface_remains_private_and_non_executing() {
        const LIFECYCLE: &str = include_str!("application_lifecycle.rs");
        const BOOTSTRAP: &str = include_str!("lib.rs");
        const FRONTEND: &str = include_str!("../../src/App.tsx");
        let production = LIFECYCLE.split_once("#[cfg(test)]\nmod tests").unwrap().0;
        let request_name = "begin_production_database_migration_revalidation(";
        assert_eq!(production.matches(request_name).count(), 1);
        assert!(!BOOTSTRAP.contains(request_name));
        assert!(!FRONTEND.contains(request_name));
        assert!(production.contains("std::sync::mpsc::sync_channel(0)"));
        assert!(production.contains("name(\"production-database-migration\".to_owned())"));
        let request = production
            .split_once("fn begin_production_database_migration_revalidation_with")
            .unwrap()
            .1
            .split_once("fn complete_migration_revalidation")
            .unwrap()
            .0;
        assert!(!request.contains("spawn_blocking"));
        assert!(!request.contains("catch_unwind"));
        assert!(!request.contains(".establish_pending("));
        for forbidden in [
            "#[tauri::command]\nfn begin_production_database_migration",
            "ProductionDatabaseMigrationRevalidationRequestResult",
            "migration SQL",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
    }

    #[test]
    fn migration_preparation_order_and_worker_retention_are_explicit_and_private() {
        const LIFECYCLE: &str = include_str!("application_lifecycle.rs");
        const CONFIRMATION: &str =
            include_str!("application_lifecycle/production_database_migration_confirmation.rs");
        let production = LIFECYCLE.split_once("#[cfg(test)]\nmod tests").unwrap().0;
        let worker = production
            .split_once("fn run_migration_preparation_worker")
            .unwrap()
            .1
            .split_once("fn park_migration_worker")
            .unwrap()
            .0;
        let exclusivity = worker
            .find("acquire_production_database_migration_cross_process_exclusivity()")
            .unwrap();
        let operational_close = worker.find("close_operational(operational)").unwrap();
        let consume = worker.find(".consume_authorization()").unwrap();
        let preparation = worker
            .find("prepare_authorized_production_database_migration(&app, authorized)")
            .unwrap();
        assert!(exclusivity < operational_close);
        assert!(operational_close < consume);
        assert!(consume < preparation);

        let shutdown_won = worker
            .split_once("MigrationPreparationClaim::ShutdownWon(authorized)")
            .unwrap()
            .1
            .split_once("MigrationPreparationClaim::Ready(operational)")
            .unwrap()
            .0;
        assert!(shutdown_won.contains("close_authorized_migration_for_shutdown(authorized)"));
        assert!(shutdown_won.contains("MigrationWorkerRetryOutcome::Retained(owner)"));
        let shutdown_close = production
            .split_once("fn close_authorized_migration_for_shutdown")
            .unwrap()
            .1
            .split_once("fn retry_migration_worker_ownership")
            .unwrap()
            .0;
        assert!(shutdown_close.contains("authorized.close()"));
        assert!(shutdown_close.contains("MigrationWorkerParkedOwnership::PreparationClose"));
        assert!(
            shutdown_close.contains("ProductionDatabaseMigrationPreparationFailure::SourceClose")
        );
        for forbidden in [
            "prepare_authorized_production_database_migration",
            "validate_full_integrity",
            "stage_encrypted_production_database_migration_backup",
            "verify_production_database_migration_recovery_envelope",
            "prepare_migration_recovery_key_custody",
        ] {
            assert!(!shutdown_won.contains(forbidden));
            assert!(!shutdown_close.contains(forbidden));
        }

        let orchestration = CONFIRMATION
            .split_once("pub(super) fn prepare_authorized_production_database_migration")
            .unwrap()
            .1
            .split_once("impl FullIntegrityValidatedProductionDatabaseMigrationHandoff")
            .unwrap()
            .0;
        let full_integrity = orchestration.find("validate_full_integrity()").unwrap();
        let stage_prepare = orchestration
            .find("prepare_production_database_migration_backup_stage(app)")
            .unwrap();
        let encrypted_stage = orchestration
            .find("stage_encrypted_production_database_migration_backup")
            .unwrap();
        let envelope = orchestration
            .find("verify_production_database_migration_recovery_envelope")
            .unwrap();
        let custody = orchestration
            .find("prepare_migration_recovery_key_custody")
            .unwrap();
        assert!(full_integrity < stage_prepare);
        assert!(stage_prepare < encrypted_stage);
        assert!(encrypted_stage < envelope);
        assert!(envelope < custody);

        let lifecycle_inner = production
            .split_once("struct LifecycleInner {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(!lifecycle_inner.contains("PreparedUndisclosedMigrationRecoveryKeyCustody"));
        assert!(!lifecycle_inner.contains("ProductionDatabaseMigrationCrossProcessExclusivity"));
        assert!(production.contains("MigrationPreparationState::CustodyPrepared"));
        assert!(production.contains("control.recv()"));
        assert!(production.contains("drop(exclusivity)"));

        for forbidden in [
            "run_migration_recovery_key_custody_native_ceremony",
            "get_webview_window(\"main\")",
            "run_on_main_thread",
            "DialogBoxIndirectParamW",
            ".hwnd()",
            "#[tauri::command]",
            "publish",
            "CREATE TABLE",
            "user_version",
        ] {
            assert!(
                !worker.contains(forbidden) && !orchestration.contains(forbidden),
                "forbidden orchestration surface: {forbidden}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn migration_accounting_independently_blocks_exit_and_completed_worker_joins() {
        let lifecycle = ApplicationLifecycle::new();
        let joined = Arc::new(AtomicBool::new(false));
        let worker_joined = Arc::clone(&joined);
        let worker = thread::spawn(move || worker_joined.store(true, Ordering::SeqCst));
        {
            let mut inner = lifecycle.lock();
            inner.state = LifecycleState::Failed(CoarseStartupFailure::StartupInterrupted);
            inner.startup_work_resolved = true;
            inner.close_work_resolved = false;
            inner.setup_work_resolved = true;
            inner.migration_work_resolved = false;
            inner.migration_worker = Some(worker);
        }
        assert!(!lifecycle.may_exit());
        lifecycle.lock().close_work_resolved = true;
        assert!(!lifecycle.may_exit());
        lifecycle.lock().migration_work_resolved = true;
        assert!(lifecycle.may_exit());
        lifecycle.join_workers();
        assert!(joined.load(Ordering::SeqCst));
        assert!(lifecycle.lock().migration_worker.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn pending_migration_owner_blocks_exit_even_if_resolution_bit_is_incorrectly_true() {
        use crate::production_database_connection_handoff::genuine_production_database_migration_opportunity_for_test;

        let lifecycle = ApplicationLifecycle::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        establish_migration_pending(&lifecycle, root.path(), opportunity);
        {
            let mut inner = lifecycle.lock();
            inner.state = LifecycleState::Failed(CoarseStartupFailure::StartupInterrupted);
            inner.startup_work_resolved = true;
            inner.close_work_resolved = true;
            inner.setup_work_resolved = true;
            inner.migration_work_resolved = true;
        }
        assert!(!lifecycle.may_exit());
        let owner = lifecycle
            .lock()
            .migration_confirmation
            .invalidate_for_shutdown()
            .unwrap();
        assert!(matches!(
            close_migration_shutdown_ownership(owner),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn lifecycle_shutdown_revokes_migration_confirmation_under_the_same_lock() {
        use crate::production_database_connection_handoff::{
            ProductionDatabaseConnectionCloseOutcome,
            genuine_production_database_migration_opportunity_for_test,
            genuine_production_database_migration_revalidation_context_for_test,
        };
        use production_database_migration_confirmation::{
            ProductionDatabaseMigrationConfirmationStateForTest,
            ProductionDatabaseMigrationPendingContext,
        };

        let lifecycle = ApplicationLifecycle::new();
        let mut inner = lifecycle.lock();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        assert!(
            inner
                .migration_confirmation
                .establish_pending(ProductionDatabaseMigrationPendingContext::new(
                    opportunity,
                    genuine_production_database_migration_revalidation_context_for_test(
                        root.path()
                    ),
                ))
                .is_ok()
        );
        let pending_migration = inner.migration_confirmation.invalidate_for_shutdown();
        inner.migration_work_resolved = false;
        let action = inner.state.begin_shutdown();
        assert!(matches!(action, ShutdownAction::Exit));
        assert_eq!(
            inner.migration_confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
        drop(inner);
        let Some(ProductionDatabaseMigrationShutdownOwnership::Pending(pending_migration)) =
            pending_migration
        else {
            panic!("lifecycle shutdown must return pending ownership");
        };
        assert!(matches!(
            pending_migration.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();

        const SOURCE: &str = include_str!("application_lifecycle.rs");
        let helper = SOURCE
            .split_once("pub(crate) fn request_shutdown")
            .unwrap()
            .1
            .split_once("fn close_on_worker")
            .unwrap()
            .0;
        let revocation = helper
            .find("migration_confirmation.invalidate_for_shutdown()")
            .unwrap();
        let stopping = helper.find("state.begin_shutdown()").unwrap();
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
