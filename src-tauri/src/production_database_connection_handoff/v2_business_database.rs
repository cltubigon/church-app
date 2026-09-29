//! Exact-V2-only normal business database activation and dedicated worker.
//!
//! Later state-changing business commands must be sealed variants implemented
//! here and use `BEGIN IMMEDIATE` for read-check-write atomicity. No connection,
//! arbitrary SQL, callback, path, key, or raw database error crosses this boundary.

use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender, SyncSender, sync_channel},
    },
    thread::{self, JoinHandle},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, config::DbConfig,
    params,
};

use crate::{
    database_key_active_wrapper_loader::load_active_database_key_wrapper,
    database_key_presence::inspect_database_key_active_presence,
    database_restart_version_classification::ProductionDatabaseRestartClassification,
    installation_evidence_protection::{
        bind_database_key_candidate_to_trusted_installation_evidence,
        recover_database_key_candidate_from_loaded_wrapper,
    },
    production_database_file::{
        ProductionDatabaseInspection, inspect_production_database_file_for_writable_migration,
        inspected_production_database_file_matches_identity,
    },
    storage_foundation::{DatabaseKeyPersistencePaths, ProductionDatabasePath},
};

use super::{
    ClosedExactV2OperationalProductionDatabase, ConnectionLifetimeOwner,
    ProductionDatabaseConnectionCloseOutcome, acquire_guarded_inspection_for_writable_migration,
    apply_key_once, close_lifetime_owner,
    full_integrity_validation::validate_production_database_full_integrity_on_borrowed_connection,
    live_metadata_and_header_validation::observe_and_classify_restart_state,
    revalidate_connection_identity, run_cipher_integrity_check, run_sqlite_quick_check,
    set_and_verify,
};

pub(crate) const BUSINESS_DATABASE_COMMAND_CAPACITY: usize = 8;
const WIN32_VFS_NAME: &str = "win32";
const MAIN_DATABASE_NAME: &str = "main";
const WRITABLE_BUSINESS_OPEN_FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE
    .union(OpenFlags::SQLITE_OPEN_FULL_MUTEX)
    .union(OpenFlags::SQLITE_OPEN_PRIVATE_CACHE)
    .union(OpenFlags::SQLITE_OPEN_NOFOLLOW);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum V2BusinessDatabaseActivationError {
    DatabaseUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BusinessFailure {
    InvalidInput,
    NotFound,
    InvalidState,
    PendingCancellationAlreadyExists,
    ScheduleConflict,
    ConcurrentChange,
    DatabaseUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ServiceRequestId(i64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ScheduleOccurrenceId(i64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CancellationReviewId(i64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServiceCategory {
    Baptism,
    Confirmation,
    WeddingMarriage,
    BurialFuneral,
    FirstCommunion,
}

impl ServiceCategory {
    fn code(self) -> &'static str {
        match self {
            Self::Baptism => "baptism",
            Self::Confirmation => "confirmation",
            Self::WeddingMarriage => "wedding_marriage",
            Self::BurialFuneral => "burial_funeral",
            Self::FirstCommunion => "first_communion",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        match code {
            "baptism" => Some(Self::Baptism),
            "confirmation" => Some(Self::Confirmation),
            "wedding_marriage" => Some(Self::WeddingMarriage),
            "burial_funeral" => Some(Self::BurialFuneral),
            "first_communion" => Some(Self::FirstCommunion),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestStatus {
    Pending,
    Scheduled,
    Completed,
    Cancelled,
}

impl RequestStatus {
    fn from_code(code: &str) -> Option<Self> {
        match code {
            "pending" => Some(Self::Pending),
            "scheduled" => Some(Self::Scheduled),
            "completed" => Some(Self::Completed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CancellationDisposition {
    Pending,
    Approved,
    Rejected,
}

impl CancellationDisposition {
    fn from_code(code: &str) -> Option<Self> {
        match code {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OccurrenceKind {
    Primary,
    Funeral,
    Burial,
}

impl OccurrenceKind {
    fn code(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Funeral => "funeral",
            Self::Burial => "burial",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        match code {
            "primary" => Some(Self::Primary),
            "funeral" => Some(Self::Funeral),
            "burial" => Some(Self::Burial),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CreateServiceRequest {
    pub(crate) service_category: ServiceCategory,
    pub(crate) requester_full_name: String,
    pub(crate) requester_phone: String,
    pub(crate) requester_email: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequesterSnapshot {
    pub(crate) full_name: String,
    pub(crate) phone: String,
    pub(crate) email: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServiceRequestSummary {
    pub(crate) id: ServiceRequestId,
    pub(crate) service_category: ServiceCategory,
    pub(crate) status: RequestStatus,
    pub(crate) requester: RequesterSnapshot,
    pub(crate) created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScheduleOccurrence {
    pub(crate) id: ScheduleOccurrenceId,
    pub(crate) kind: OccurrenceKind,
    pub(crate) local_date: String,
    pub(crate) local_time: String,
    pub(crate) location: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CancellationReview {
    pub(crate) id: CancellationReviewId,
    pub(crate) disposition: CancellationDisposition,
    pub(crate) requested_at: i64,
    pub(crate) resolved_at: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServiceRequestDetail {
    pub(crate) request: ServiceRequestSummary,
    pub(crate) occurrences: Vec<ScheduleOccurrence>,
    pub(crate) cancellation_reviews: Vec<CancellationReview>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OccurrenceInput {
    pub(crate) kind: OccurrenceKind,
    pub(crate) local_date: String,
    pub(crate) local_time: String,
    pub(crate) location: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RescheduleOccurrenceInput {
    pub(crate) local_date: String,
    pub(crate) local_time: String,
    pub(crate) location: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScheduleOccupancyItem {
    pub(crate) request_id: ServiceRequestId,
    pub(crate) service_category: ServiceCategory,
    pub(crate) occurrence: ScheduleOccurrence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingCancellationReview {
    pub(crate) review_id: CancellationReviewId,
    pub(crate) request_id: ServiceRequestId,
    pub(crate) service_category: ServiceCategory,
    pub(crate) request_status: RequestStatus,
    pub(crate) requester_display_name: String,
    pub(crate) requested_at: i64,
}

#[must_use = "the V2 business database activation outcome must be handled"]
pub(crate) enum V2BusinessDatabaseActivationOutcome {
    Ready(OperationalV2BusinessDatabase),
    Failed(V2BusinessDatabaseActivationError),
    CloseFailed(super::ProductionDatabaseConnectionCloseFailure),
}

struct BusinessWorkerControl {
    accepting: bool,
    sender: Option<SyncSender<BusinessDatabaseCommand>>,
}

/// Opaque Rust-only proof that one dedicated worker owns the sole normal
/// writable Exact-V2 connection.
pub(crate) struct OperationalV2BusinessDatabase {
    control: Arc<Mutex<BusinessWorkerControl>>,
    shutdown_requested: Arc<AtomicBool>,
    #[cfg(test)]
    inject_close_failure: Arc<AtomicBool>,
    worker: Option<JoinHandle<ProductionDatabaseConnectionCloseOutcome>>,
}

#[allow(dead_code)] // Rust-only service calls are intentionally not wired to IPC yet.
enum BusinessDatabaseCommand {
    CreateRequest {
        input: CreateServiceRequest,
        reply: Sender<Result<ServiceRequestSummary, BusinessFailure>>,
    },
    GetRequest {
        request_id: ServiceRequestId,
        reply: Sender<Result<ServiceRequestDetail, BusinessFailure>>,
    },
    ListRequests(Sender<Result<Vec<ServiceRequestSummary>, BusinessFailure>>),
    CreatePendingOccurrence {
        request_id: ServiceRequestId,
        input: OccurrenceInput,
        reply: Sender<Result<ScheduleOccurrence, BusinessFailure>>,
    },
    UpdatePendingOccurrence {
        request_id: ServiceRequestId,
        occurrence_id: ScheduleOccurrenceId,
        input: OccurrenceInput,
        reply: Sender<Result<ScheduleOccurrence, BusinessFailure>>,
    },
    DeletePendingOccurrence {
        request_id: ServiceRequestId,
        occurrence_id: ScheduleOccurrenceId,
        reply: Sender<Result<(), BusinessFailure>>,
    },
    ScheduleRequest {
        request_id: ServiceRequestId,
        reply: Sender<Result<(), BusinessFailure>>,
    },
    RescheduleOccurrence {
        request_id: ServiceRequestId,
        occurrence_id: ScheduleOccurrenceId,
        input: RescheduleOccurrenceInput,
        reply: Sender<Result<ScheduleOccurrence, BusinessFailure>>,
    },
    CompleteRequest {
        request_id: ServiceRequestId,
        reply: Sender<Result<(), BusinessFailure>>,
    },
    ListScheduleOccupancy(Sender<Result<Vec<ScheduleOccupancyItem>, BusinessFailure>>),
    RequestCancellation {
        request_id: ServiceRequestId,
        reply: Sender<Result<CancellationReview, BusinessFailure>>,
    },
    ApproveCancellationReview {
        review_id: CancellationReviewId,
        reply: Sender<Result<(), BusinessFailure>>,
    },
    RejectCancellationReview {
        review_id: CancellationReviewId,
        reply: Sender<Result<(), BusinessFailure>>,
    },
    ListPendingCancellationReviews(Sender<Result<Vec<PendingCancellationReview>, BusinessFailure>>),
    ListRequestsWithPendingCancellationReview(
        Sender<Result<Vec<ServiceRequestSummary>, BusinessFailure>>,
    ),
    #[cfg(test)]
    Probe(std::sync::mpsc::Sender<Result<(), V2BusinessDatabaseActivationError>>),
    #[cfg(test)]
    Block {
        started: std::sync::mpsc::Sender<()>,
        release: Receiver<()>,
        completed: std::sync::mpsc::Sender<()>,
    },
    #[cfg(test)]
    VerifyForeignKeyViolation(std::sync::mpsc::Sender<bool>),
}

impl fmt::Debug for OperationalV2BusinessDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperationalV2BusinessDatabase([REDACTED])")
    }
}

#[allow(dead_code)] // The next IPC slice will consume this sealed crate-private surface.
impl OperationalV2BusinessDatabase {
    fn request<T>(
        &self,
        build: impl FnOnce(Sender<Result<T, BusinessFailure>>) -> BusinessDatabaseCommand,
    ) -> Result<T, BusinessFailure> {
        let (reply, response) = std::sync::mpsc::channel();
        let control = self
            .control
            .lock()
            .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
        if !control.accepting {
            return Err(BusinessFailure::DatabaseUnavailable);
        }
        control
            .sender
            .as_ref()
            .ok_or(BusinessFailure::DatabaseUnavailable)?
            .try_send(build(reply))
            .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
        drop(control);
        response
            .recv()
            .unwrap_or(Err(BusinessFailure::DatabaseUnavailable))
    }

    pub(crate) fn create_request(
        &self,
        input: CreateServiceRequest,
    ) -> Result<ServiceRequestSummary, BusinessFailure> {
        self.request(|reply| BusinessDatabaseCommand::CreateRequest { input, reply })
    }

    pub(crate) fn get_request(
        &self,
        request_id: ServiceRequestId,
    ) -> Result<ServiceRequestDetail, BusinessFailure> {
        self.request(|reply| BusinessDatabaseCommand::GetRequest { request_id, reply })
    }

    pub(crate) fn list_requests(&self) -> Result<Vec<ServiceRequestSummary>, BusinessFailure> {
        self.request(BusinessDatabaseCommand::ListRequests)
    }

    pub(crate) fn create_pending_occurrence(
        &self,
        request_id: ServiceRequestId,
        input: OccurrenceInput,
    ) -> Result<ScheduleOccurrence, BusinessFailure> {
        self.request(|reply| BusinessDatabaseCommand::CreatePendingOccurrence {
            request_id,
            input,
            reply,
        })
    }

    pub(crate) fn update_pending_occurrence(
        &self,
        request_id: ServiceRequestId,
        occurrence_id: ScheduleOccurrenceId,
        input: OccurrenceInput,
    ) -> Result<ScheduleOccurrence, BusinessFailure> {
        self.request(|reply| BusinessDatabaseCommand::UpdatePendingOccurrence {
            request_id,
            occurrence_id,
            input,
            reply,
        })
    }

    pub(crate) fn delete_pending_occurrence(
        &self,
        request_id: ServiceRequestId,
        occurrence_id: ScheduleOccurrenceId,
    ) -> Result<(), BusinessFailure> {
        self.request(|reply| BusinessDatabaseCommand::DeletePendingOccurrence {
            request_id,
            occurrence_id,
            reply,
        })
    }

    pub(crate) fn schedule_request(
        &self,
        request_id: ServiceRequestId,
    ) -> Result<(), BusinessFailure> {
        self.request(|reply| BusinessDatabaseCommand::ScheduleRequest { request_id, reply })
    }

    pub(crate) fn reschedule_occurrence(
        &self,
        request_id: ServiceRequestId,
        occurrence_id: ScheduleOccurrenceId,
        input: RescheduleOccurrenceInput,
    ) -> Result<ScheduleOccurrence, BusinessFailure> {
        self.request(|reply| BusinessDatabaseCommand::RescheduleOccurrence {
            request_id,
            occurrence_id,
            input,
            reply,
        })
    }

    pub(crate) fn complete_request(
        &self,
        request_id: ServiceRequestId,
    ) -> Result<(), BusinessFailure> {
        self.request(|reply| BusinessDatabaseCommand::CompleteRequest { request_id, reply })
    }

    pub(crate) fn list_schedule_occupancy(
        &self,
    ) -> Result<Vec<ScheduleOccupancyItem>, BusinessFailure> {
        self.request(BusinessDatabaseCommand::ListScheduleOccupancy)
    }

    pub(crate) fn request_cancellation(
        &self,
        request_id: ServiceRequestId,
    ) -> Result<CancellationReview, BusinessFailure> {
        self.request(|reply| BusinessDatabaseCommand::RequestCancellation { request_id, reply })
    }

    pub(crate) fn approve_cancellation_review(
        &self,
        review_id: CancellationReviewId,
    ) -> Result<(), BusinessFailure> {
        self.request(|reply| BusinessDatabaseCommand::ApproveCancellationReview {
            review_id,
            reply,
        })
    }

    pub(crate) fn reject_cancellation_review(
        &self,
        review_id: CancellationReviewId,
    ) -> Result<(), BusinessFailure> {
        self.request(|reply| BusinessDatabaseCommand::RejectCancellationReview { review_id, reply })
    }

    pub(crate) fn list_pending_cancellation_reviews(
        &self,
    ) -> Result<Vec<PendingCancellationReview>, BusinessFailure> {
        self.request(BusinessDatabaseCommand::ListPendingCancellationReviews)
    }

    pub(crate) fn list_requests_with_pending_cancellation_review(
        &self,
    ) -> Result<Vec<ServiceRequestSummary>, BusinessFailure> {
        self.request(BusinessDatabaseCommand::ListRequestsWithPendingCancellationReview)
    }

    pub(crate) fn shutdown(self) -> ProductionDatabaseConnectionCloseOutcome {
        self.begin_shutdown();
        self.finish_shutdown()
    }

    fn begin_shutdown(&self) {
        {
            let mut control = self
                .control
                .lock()
                .unwrap_or_else(|_| std::process::abort());
            control.accepting = false;
            self.shutdown_requested.store(true, Ordering::Release);
            drop(control.sender.take());
        }
    }

    fn finish_shutdown(mut self) -> ProductionDatabaseConnectionCloseOutcome {
        self.worker
            .take()
            .unwrap_or_else(|| std::process::abort())
            .join()
            .unwrap_or_else(|_| std::process::abort())
    }

    #[cfg(test)]
    fn inject_close_failure_for_test(&self) {
        self.inject_close_failure.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn send_for_test(&self, command: BusinessDatabaseCommand) -> Result<(), ()> {
        let control = self.control.lock().map_err(|_| ())?;
        if !control.accepting {
            return Err(());
        }
        control
            .sender
            .as_ref()
            .ok_or(())?
            .try_send(command)
            .map_err(|_| ())
    }
}

impl Drop for OperationalV2BusinessDatabase {
    fn drop(&mut self) {
        self.begin_shutdown();
        let Some(worker) = self.worker.take() else {
            return;
        };
        match worker.join().unwrap_or_else(|_| std::process::abort()) {
            ProductionDatabaseConnectionCloseOutcome::Closed => {}
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                std::mem::forget(failure);
                std::process::abort();
            }
        }
    }
}

fn configure_writable_business_policy(connection: &Connection) -> Result<(), ()> {
    connection
        .busy_timeout(super::BUSY_TIMEOUT)
        .map_err(|_| ())?;
    // SAFETY: the live handle is borrowed synchronously and does not escape.
    let status = unsafe { rusqlite::ffi::sqlite3_enable_load_extension(connection.handle(), 0) };
    if status != rusqlite::ffi::SQLITE_OK {
        return Err(());
    }
    for (config, expected) in [
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, false),
    ] {
        set_and_verify(connection, config, expected).map_err(|_| ())?;
    }
    if connection.is_readonly(MAIN_DATABASE_NAME) != Ok(false) {
        return Err(());
    }
    Ok(())
}

fn enable_and_verify_foreign_keys(connection: &Connection) -> Result<(), ()> {
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| ())?;
    let enabled = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
        .map_err(|_| ())?;
    if enabled != 1 {
        return Err(());
    }
    Ok(())
}

fn close_activation_failure(owner: ConnectionLifetimeOwner) -> V2BusinessDatabaseActivationOutcome {
    match close_lifetime_owner(owner) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            V2BusinessDatabaseActivationOutcome::Failed(
                V2BusinessDatabaseActivationError::DatabaseUnavailable,
            )
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            V2BusinessDatabaseActivationOutcome::CloseFailed(failure)
        }
    }
}

pub(crate) fn activate_exact_v2_business_database(
    closed_exact_v2: ClosedExactV2OperationalProductionDatabase,
    path: ProductionDatabasePath,
    key_paths: &DatabaseKeyPersistencePaths,
) -> V2BusinessDatabaseActivationOutcome {
    let (expected_file_identity, expected_metadata, trusted_assessment) =
        closed_exact_v2.into_parts();
    let key_presence = inspect_database_key_active_presence(key_paths);
    let key = load_active_database_key_wrapper(key_paths, key_presence)
        .map_err(|_| ())
        .and_then(|loaded| {
            recover_database_key_candidate_from_loaded_wrapper(&loaded).map_err(|_| ())
        })
        .and_then(|candidate| {
            bind_database_key_candidate_to_trusted_installation_evidence(
                candidate,
                &trusted_assessment,
            )
            .map_err(|_| ())
        });
    let _ = trusted_assessment;
    let Ok(key) = key else {
        return V2BusinessDatabaseActivationOutcome::Failed(
            V2BusinessDatabaseActivationError::DatabaseUnavailable,
        );
    };

    let inspected = match inspect_production_database_file_for_writable_migration(&path) {
        ProductionDatabaseInspection::Present(inspected)
            if inspected_production_database_file_matches_identity(
                &inspected,
                expected_file_identity,
            ) =>
        {
            inspected
        }
        _ => {
            return V2BusinessDatabaseActivationOutcome::Failed(
                V2BusinessDatabaseActivationError::DatabaseUnavailable,
            );
        }
    };
    let guarded = match acquire_guarded_inspection_for_writable_migration(&path, inspected) {
        Ok(guarded) => guarded,
        Err(_) => {
            return V2BusinessDatabaseActivationOutcome::Failed(
                V2BusinessDatabaseActivationError::DatabaseUnavailable,
            );
        }
    };
    let connection = match Connection::open_with_flags_and_vfs(
        path.as_path(),
        WRITABLE_BUSINESS_OPEN_FLAGS,
        WIN32_VFS_NAME,
    ) {
        Ok(connection) => connection,
        Err(_) => {
            return V2BusinessDatabaseActivationOutcome::Failed(
                V2BusinessDatabaseActivationError::DatabaseUnavailable,
            );
        }
    };
    let owner = ConnectionLifetimeOwner {
        connection,
        guard: guarded.guard,
        inspected: guarded.inspected,
    };
    if revalidate_connection_identity(&owner.connection, &owner.inspected).is_err()
        || configure_writable_business_policy(&owner.connection).is_err()
        || apply_key_once(&owner.connection, &key).is_err()
    {
        return close_activation_failure(owner);
    }
    drop(key);
    if run_cipher_integrity_check(&owner.connection).is_err()
        || run_sqlite_quick_check(&owner.connection).is_err()
        || validate_production_database_full_integrity_on_borrowed_connection(&owner.connection)
            .is_err()
    {
        return close_activation_failure(owner);
    }
    match observe_and_classify_restart_state(&owner.connection) {
        Ok((metadata, ProductionDatabaseRestartClassification::ExactV2))
            if metadata == expected_metadata => {}
        _ => return close_activation_failure(owner),
    }
    if enable_and_verify_foreign_keys(&owner.connection).is_err() {
        return close_activation_failure(owner);
    }

    start_worker(owner)
}

fn start_worker(owner: ConnectionLifetimeOwner) -> V2BusinessDatabaseActivationOutcome {
    let (sender, receiver) = sync_channel(BUSINESS_DATABASE_COMMAND_CAPACITY);
    let control = Arc::new(Mutex::new(BusinessWorkerControl {
        accepting: true,
        sender: Some(sender),
    }));
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let launch_owner = Arc::new(Mutex::new(Some(owner)));
    let worker_owner = Arc::clone(&launch_owner);
    let worker_shutdown = Arc::clone(&shutdown_requested);
    #[cfg(test)]
    let inject_close_failure = Arc::new(AtomicBool::new(false));
    #[cfg(test)]
    let worker_close_failure = Arc::clone(&inject_close_failure);
    let worker = thread::Builder::new()
        .name("church-app-v2-business-database".to_owned())
        .spawn(move || {
            let owner = worker_owner
                .lock()
                .unwrap_or_else(|_| std::process::abort())
                .take()
                .unwrap_or_else(|| std::process::abort());
            run_worker(
                owner,
                receiver,
                &worker_shutdown,
                #[cfg(test)]
                &worker_close_failure,
            )
        });
    match worker {
        Ok(worker) => V2BusinessDatabaseActivationOutcome::Ready(OperationalV2BusinessDatabase {
            control,
            shutdown_requested,
            #[cfg(test)]
            inject_close_failure,
            worker: Some(worker),
        }),
        Err(_) => {
            let owner = launch_owner
                .lock()
                .unwrap_or_else(|_| std::process::abort())
                .take()
                .unwrap_or_else(|| std::process::abort());
            close_activation_failure(owner)
        }
    }
}

fn run_worker(
    mut owner: ConnectionLifetimeOwner,
    receiver: Receiver<BusinessDatabaseCommand>,
    shutdown_requested: &AtomicBool,
    #[cfg(test)] inject_close_failure: &AtomicBool,
) -> ProductionDatabaseConnectionCloseOutcome {
    while let Ok(command) = receiver.recv() {
        if shutdown_requested.load(Ordering::Acquire) {
            reject_command(command);
        } else {
            process_command(&mut owner.connection, command);
        }
    }
    #[cfg(test)]
    if inject_close_failure.load(Ordering::Acquire) {
        return ProductionDatabaseConnectionCloseOutcome::Failed(
            super::ProductionDatabaseConnectionCloseFailure { owner },
        );
    }
    close_lifetime_owner(owner)
}

fn reject_command(command: BusinessDatabaseCommand) {
    match command {
        BusinessDatabaseCommand::CreateRequest { reply, .. } => {
            let _ = reply.send(Err(BusinessFailure::DatabaseUnavailable));
        }
        BusinessDatabaseCommand::GetRequest { reply, .. } => {
            let _ = reply.send(Err(BusinessFailure::DatabaseUnavailable));
        }
        BusinessDatabaseCommand::ListRequests(reply) => {
            let _ = reply.send(Err(BusinessFailure::DatabaseUnavailable));
        }
        BusinessDatabaseCommand::CreatePendingOccurrence { reply, .. }
        | BusinessDatabaseCommand::UpdatePendingOccurrence { reply, .. }
        | BusinessDatabaseCommand::RescheduleOccurrence { reply, .. } => {
            let _ = reply.send(Err(BusinessFailure::DatabaseUnavailable));
        }
        BusinessDatabaseCommand::DeletePendingOccurrence { reply, .. }
        | BusinessDatabaseCommand::ScheduleRequest { reply, .. }
        | BusinessDatabaseCommand::CompleteRequest { reply, .. } => {
            let _ = reply.send(Err(BusinessFailure::DatabaseUnavailable));
        }
        BusinessDatabaseCommand::ListScheduleOccupancy(reply) => {
            let _ = reply.send(Err(BusinessFailure::DatabaseUnavailable));
        }
        BusinessDatabaseCommand::RequestCancellation { reply, .. } => {
            let _ = reply.send(Err(BusinessFailure::DatabaseUnavailable));
        }
        BusinessDatabaseCommand::ApproveCancellationReview { reply, .. }
        | BusinessDatabaseCommand::RejectCancellationReview { reply, .. } => {
            let _ = reply.send(Err(BusinessFailure::DatabaseUnavailable));
        }
        BusinessDatabaseCommand::ListPendingCancellationReviews(reply) => {
            let _ = reply.send(Err(BusinessFailure::DatabaseUnavailable));
        }
        BusinessDatabaseCommand::ListRequestsWithPendingCancellationReview(reply) => {
            let _ = reply.send(Err(BusinessFailure::DatabaseUnavailable));
        }
        #[cfg(test)]
        BusinessDatabaseCommand::Probe(reply) => {
            let _ = reply.send(Err(V2BusinessDatabaseActivationError::DatabaseUnavailable));
        }
        #[cfg(test)]
        BusinessDatabaseCommand::Block { .. } => {}
        #[cfg(test)]
        BusinessDatabaseCommand::VerifyForeignKeyViolation(reply) => {
            let _ = reply.send(false);
        }
    }
}

fn process_command(connection: &mut Connection, command: BusinessDatabaseCommand) {
    match command {
        BusinessDatabaseCommand::CreateRequest { input, reply } => {
            let _ = reply.send(create_request_on_connection(connection, input));
        }
        BusinessDatabaseCommand::GetRequest { request_id, reply } => {
            let _ = reply.send(get_request_on_connection(connection, request_id));
        }
        BusinessDatabaseCommand::ListRequests(reply) => {
            let _ = reply.send(list_requests_on_connection(connection));
        }
        BusinessDatabaseCommand::CreatePendingOccurrence {
            request_id,
            input,
            reply,
        } => {
            let _ = reply.send(create_pending_occurrence_on_connection(
                connection, request_id, input,
            ));
        }
        BusinessDatabaseCommand::UpdatePendingOccurrence {
            request_id,
            occurrence_id,
            input,
            reply,
        } => {
            let _ = reply.send(update_pending_occurrence_on_connection(
                connection,
                request_id,
                occurrence_id,
                input,
            ));
        }
        BusinessDatabaseCommand::DeletePendingOccurrence {
            request_id,
            occurrence_id,
            reply,
        } => {
            let _ = reply.send(delete_pending_occurrence_on_connection(
                connection,
                request_id,
                occurrence_id,
            ));
        }
        BusinessDatabaseCommand::ScheduleRequest { request_id, reply } => {
            let _ = reply.send(schedule_request_on_connection(connection, request_id));
        }
        BusinessDatabaseCommand::RescheduleOccurrence {
            request_id,
            occurrence_id,
            input,
            reply,
        } => {
            let _ = reply.send(reschedule_occurrence_on_connection(
                connection,
                request_id,
                occurrence_id,
                input,
            ));
        }
        BusinessDatabaseCommand::CompleteRequest { request_id, reply } => {
            let _ = reply.send(complete_request_on_connection(connection, request_id));
        }
        BusinessDatabaseCommand::ListScheduleOccupancy(reply) => {
            let _ = reply.send(list_schedule_occupancy_on_connection(connection));
        }
        BusinessDatabaseCommand::RequestCancellation { request_id, reply } => {
            let _ = reply.send(request_cancellation_on_connection(connection, request_id));
        }
        BusinessDatabaseCommand::ApproveCancellationReview { review_id, reply } => {
            let _ = reply.send(approve_cancellation_review_on_connection(
                connection, review_id,
            ));
        }
        BusinessDatabaseCommand::RejectCancellationReview { review_id, reply } => {
            let _ = reply.send(reject_cancellation_review_on_connection(
                connection, review_id,
            ));
        }
        BusinessDatabaseCommand::ListPendingCancellationReviews(reply) => {
            let _ = reply.send(list_pending_cancellation_reviews_on_connection(connection));
        }
        BusinessDatabaseCommand::ListRequestsWithPendingCancellationReview(reply) => {
            let _ = reply
                .send(list_requests_with_pending_cancellation_review_on_connection(connection));
        }
        #[cfg(test)]
        BusinessDatabaseCommand::Probe(reply) => {
            let _ = reply.send(Ok(()));
        }
        #[cfg(test)]
        BusinessDatabaseCommand::Block {
            started,
            release,
            completed,
        } => {
            let _ = started.send(());
            let _ = release.recv();
            let _ = completed.send(());
        }
        #[cfg(test)]
        BusinessDatabaseCommand::VerifyForeignKeyViolation(reply) => {
            let rejected = connection
                .execute(
                    "INSERT INTO request_schedule_occurrences(\
                        service_request_id, occurrence_kind, scheduled_local_date, scheduled_local_time\
                     ) VALUES (999, 'primary', '2030-01-01', '09:00')",
                    [],
                )
                .is_err();
            let _ = reply.send(rejected);
        }
    }
}

fn trusted_created_at() -> Result<i64, BusinessFailure> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?
        .as_millis();
    i64::try_from(milliseconds).map_err(|_| BusinessFailure::DatabaseUnavailable)
}

fn normalize_required(value: String, maximum: usize) -> Result<String, BusinessFailure> {
    if value.chars().any(char::is_control) {
        return Err(BusinessFailure::InvalidInput);
    }
    let normalized = value.trim().to_owned();
    if normalized.is_empty() || normalized.chars().count() > maximum {
        return Err(BusinessFailure::InvalidInput);
    }
    Ok(normalized)
}

fn normalize_optional(
    value: Option<String>,
    maximum: usize,
) -> Result<Option<String>, BusinessFailure> {
    value
        .map(|value| normalize_required(value, maximum))
        .transpose()
}

fn normalize_occurrence(input: OccurrenceInput) -> Result<OccurrenceInput, BusinessFailure> {
    if !valid_local_date(&input.local_date) || !valid_local_time(&input.local_time) {
        return Err(BusinessFailure::InvalidInput);
    }
    Ok(OccurrenceInput {
        kind: input.kind,
        local_date: input.local_date,
        local_time: input.local_time,
        location: normalize_optional(input.location, 256)?,
    })
}

fn valid_local_date(value: &str) -> bool {
    if value.len() != 10
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || value
            .bytes()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(year) = value[0..4].parse::<u32>() else {
        return false;
    };
    let Ok(month) = value[5..7].parse::<u32>() else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u32>() else {
        return false;
    };
    if year == 0 || !(1..=12).contains(&month) {
        return false;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=maximum).contains(&day)
}

fn valid_local_time(value: &str) -> bool {
    value.len() == 5
        && value.as_bytes()[2] == b':'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 2 || byte.is_ascii_digit())
        && value[0..2].parse::<u8>().is_ok_and(|hour| hour < 24)
        && value[3..5].parse::<u8>().is_ok_and(|minute| minute < 60)
}

fn kind_is_compatible(service: ServiceCategory, kind: OccurrenceKind) -> bool {
    match service {
        ServiceCategory::BurialFuneral => {
            matches!(kind, OccurrenceKind::Funeral | OccurrenceKind::Burial)
        }
        _ => kind == OccurrenceKind::Primary,
    }
}

fn begin_immediate(connection: &mut Connection) -> Result<Transaction<'_>, BusinessFailure> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| BusinessFailure::DatabaseUnavailable)
}

fn constraint_or_database_failure(error: rusqlite::Error) -> BusinessFailure {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
        BusinessFailure::InvalidInput
    } else {
        BusinessFailure::DatabaseUnavailable
    }
}

fn parent_state(
    transaction: &Transaction<'_>,
    request_id: ServiceRequestId,
) -> Result<(ServiceCategory, RequestStatus), BusinessFailure> {
    let row = transaction
        .query_row(
            "SELECT service_category, status FROM service_requests WHERE id = ?1",
            [request_id.0],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?
        .ok_or(BusinessFailure::NotFound)?;
    Ok((
        ServiceCategory::from_code(&row.0).ok_or(BusinessFailure::DatabaseUnavailable)?,
        RequestStatus::from_code(&row.1).ok_or(BusinessFailure::DatabaseUnavailable)?,
    ))
}

fn create_request_on_connection(
    connection: &mut Connection,
    input: CreateServiceRequest,
) -> Result<ServiceRequestSummary, BusinessFailure> {
    let requester = RequesterSnapshot {
        full_name: normalize_required(input.requester_full_name, 200)?,
        phone: normalize_required(input.requester_phone, 32)?,
        email: normalize_optional(input.requester_email, 254)?,
    };
    let created_at = trusted_created_at()?;
    let transaction = begin_immediate(connection)?;
    transaction
        .execute(
            "INSERT INTO service_requests(\
                service_category, status, requester_full_name, requester_phone, requester_email, created_at\
             ) VALUES (?1, 'pending', ?2, ?3, ?4, ?5)",
            params![
                input.service_category.code(),
                &requester.full_name,
                &requester.phone,
                &requester.email,
                created_at
            ],
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    let id = ServiceRequestId(transaction.last_insert_rowid());
    transaction
        .commit()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    Ok(ServiceRequestSummary {
        id,
        service_category: input.service_category,
        status: RequestStatus::Pending,
        requester,
        created_at,
    })
}

fn decode_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<ServiceRequestSummary> {
    let service_code: String = row.get(1)?;
    let status_code: String = row.get(2)?;
    let Some(service_category) = ServiceCategory::from_code(&service_code) else {
        return Err(rusqlite::Error::InvalidQuery);
    };
    let Some(status) = RequestStatus::from_code(&status_code) else {
        return Err(rusqlite::Error::InvalidQuery);
    };
    Ok(ServiceRequestSummary {
        id: ServiceRequestId(row.get(0)?),
        service_category,
        status,
        requester: RequesterSnapshot {
            full_name: row.get(3)?,
            phone: row.get(4)?,
            email: row.get(5)?,
        },
        created_at: row.get(6)?,
    })
}

const REQUEST_COLUMNS: &str = "id, service_category, status, requester_full_name, requester_phone, requester_email, created_at";

fn get_request_on_connection(
    connection: &Connection,
    request_id: ServiceRequestId,
) -> Result<ServiceRequestDetail, BusinessFailure> {
    let request = connection
        .query_row(
            &format!("SELECT {REQUEST_COLUMNS} FROM service_requests WHERE id = ?1"),
            [request_id.0],
            decode_summary,
        )
        .optional()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?
        .ok_or(BusinessFailure::NotFound)?;
    let mut statement = connection
        .prepare(
            "SELECT id, occurrence_kind, scheduled_local_date, scheduled_local_time, location \
             FROM request_schedule_occurrences WHERE service_request_id = ?1 ORDER BY id ASC",
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    let rows = statement
        .query_map([request_id.0], decode_occurrence)
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    let occurrences = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    let mut review_statement = connection
        .prepare(
            "SELECT id, disposition, requested_at, resolved_at \
             FROM request_cancellation_reviews WHERE service_request_id = ?1 \
             ORDER BY requested_at ASC, id ASC",
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    let review_rows = review_statement
        .query_map([request_id.0], decode_cancellation_review)
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    let cancellation_reviews = review_rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    Ok(ServiceRequestDetail {
        request,
        occurrences,
        cancellation_reviews,
    })
}

fn list_requests_on_connection(
    connection: &Connection,
) -> Result<Vec<ServiceRequestSummary>, BusinessFailure> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {REQUEST_COLUMNS} FROM service_requests ORDER BY created_at DESC, id DESC"
        ))
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    statement
        .query_map([], decode_summary)
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)
}

fn decode_occurrence(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScheduleOccurrence> {
    let kind_code: String = row.get(1)?;
    let Some(kind) = OccurrenceKind::from_code(&kind_code) else {
        return Err(rusqlite::Error::InvalidQuery);
    };
    Ok(ScheduleOccurrence {
        id: ScheduleOccurrenceId(row.get(0)?),
        kind,
        local_date: row.get(2)?,
        local_time: row.get(3)?,
        location: row.get(4)?,
    })
}

fn decode_cancellation_review(row: &rusqlite::Row<'_>) -> rusqlite::Result<CancellationReview> {
    let disposition_code: String = row.get(1)?;
    let Some(disposition) = CancellationDisposition::from_code(&disposition_code) else {
        return Err(rusqlite::Error::InvalidQuery);
    };
    Ok(CancellationReview {
        id: CancellationReviewId(row.get(0)?),
        disposition,
        requested_at: row.get(2)?,
        resolved_at: row.get(3)?,
    })
}

fn create_pending_occurrence_on_connection(
    connection: &mut Connection,
    request_id: ServiceRequestId,
    input: OccurrenceInput,
) -> Result<ScheduleOccurrence, BusinessFailure> {
    let input = normalize_occurrence(input)?;
    let transaction = begin_immediate(connection)?;
    let (service, status) = parent_state(&transaction, request_id)?;
    if status != RequestStatus::Pending {
        return Err(BusinessFailure::InvalidState);
    }
    if !kind_is_compatible(service, input.kind) {
        return Err(BusinessFailure::InvalidInput);
    }
    transaction
        .execute(
            "INSERT INTO request_schedule_occurrences(\
            service_request_id, occurrence_kind, scheduled_local_date, scheduled_local_time, location\
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                request_id.0,
                input.kind.code(),
                &input.local_date,
                &input.local_time,
                &input.location
            ],
        )
        .map_err(constraint_or_database_failure)?;
    let occurrence = ScheduleOccurrence {
        id: ScheduleOccurrenceId(transaction.last_insert_rowid()),
        kind: input.kind,
        local_date: input.local_date,
        local_time: input.local_time,
        location: input.location,
    };
    transaction
        .commit()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    Ok(occurrence)
}

fn occurrence_exists_for_parent(
    transaction: &Transaction<'_>,
    request_id: ServiceRequestId,
    occurrence_id: ScheduleOccurrenceId,
) -> Result<bool, BusinessFailure> {
    transaction
        .query_row(
            "SELECT 1 FROM request_schedule_occurrences WHERE id = ?1 AND service_request_id = ?2",
            params![occurrence_id.0, request_id.0],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|_| BusinessFailure::DatabaseUnavailable)
}

fn update_pending_occurrence_on_connection(
    connection: &mut Connection,
    request_id: ServiceRequestId,
    occurrence_id: ScheduleOccurrenceId,
    input: OccurrenceInput,
) -> Result<ScheduleOccurrence, BusinessFailure> {
    let input = normalize_occurrence(input)?;
    let transaction = begin_immediate(connection)?;
    let (service, status) = parent_state(&transaction, request_id)?;
    if status != RequestStatus::Pending {
        return Err(BusinessFailure::InvalidState);
    }
    if !occurrence_exists_for_parent(&transaction, request_id, occurrence_id)? {
        return Err(BusinessFailure::NotFound);
    }
    if !kind_is_compatible(service, input.kind) {
        return Err(BusinessFailure::InvalidInput);
    }
    let changed = transaction
        .execute(
            "UPDATE request_schedule_occurrences SET occurrence_kind = ?1,\
                scheduled_local_date = ?2, scheduled_local_time = ?3, location = ?4 \
             WHERE id = ?5 AND service_request_id = ?6",
            params![
                input.kind.code(),
                &input.local_date,
                &input.local_time,
                &input.location,
                occurrence_id.0,
                request_id.0
            ],
        )
        .map_err(constraint_or_database_failure)?;
    if changed != 1 {
        return Err(BusinessFailure::ConcurrentChange);
    }
    transaction
        .commit()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    Ok(ScheduleOccurrence {
        id: occurrence_id,
        kind: input.kind,
        local_date: input.local_date,
        local_time: input.local_time,
        location: input.location,
    })
}

fn delete_pending_occurrence_on_connection(
    connection: &mut Connection,
    request_id: ServiceRequestId,
    occurrence_id: ScheduleOccurrenceId,
) -> Result<(), BusinessFailure> {
    let transaction = begin_immediate(connection)?;
    let (_, status) = parent_state(&transaction, request_id)?;
    if status != RequestStatus::Pending {
        return Err(BusinessFailure::InvalidState);
    }
    if !occurrence_exists_for_parent(&transaction, request_id, occurrence_id)? {
        return Err(BusinessFailure::NotFound);
    }
    let changed = transaction
        .execute(
            "DELETE FROM request_schedule_occurrences WHERE id = ?1 AND service_request_id = ?2",
            params![occurrence_id.0, request_id.0],
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    if changed != 1 {
        return Err(BusinessFailure::ConcurrentChange);
    }
    transaction
        .commit()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)
}

fn occurrences_for_request(
    transaction: &Transaction<'_>,
    request_id: ServiceRequestId,
) -> Result<Vec<ScheduleOccurrence>, BusinessFailure> {
    let mut statement = transaction
        .prepare(
            "SELECT id, occurrence_kind, scheduled_local_date, scheduled_local_time, location \
             FROM request_schedule_occurrences WHERE service_request_id = ?1 ORDER BY id ASC",
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    statement
        .query_map([request_id.0], decode_occurrence)
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)
}

fn validate_schedule_shape(
    service: ServiceCategory,
    occurrences: &[ScheduleOccurrence],
) -> Result<(), BusinessFailure> {
    match service {
        ServiceCategory::BurialFuneral => {
            if occurrences.is_empty()
                || occurrences.len() > 2
                || occurrences.iter().any(|item| {
                    !matches!(item.kind, OccurrenceKind::Funeral | OccurrenceKind::Burial)
                })
            {
                return Err(BusinessFailure::InvalidInput);
            }
            if occurrences.len() == 2
                && occurrences[0].local_date == occurrences[1].local_date
                && occurrences[0].local_time == occurrences[1].local_time
            {
                return Err(BusinessFailure::ScheduleConflict);
            }
        }
        _ => {
            if occurrences.len() != 1 || occurrences[0].kind != OccurrenceKind::Primary {
                return Err(BusinessFailure::InvalidInput);
            }
            if matches!(
                service,
                ServiceCategory::WeddingMarriage | ServiceCategory::FirstCommunion
            ) && occurrences[0].location.is_none()
            {
                return Err(BusinessFailure::InvalidInput);
            }
        }
    }
    Ok(())
}

fn external_slot_is_occupied(
    transaction: &Transaction<'_>,
    excluded_occurrence: Option<ScheduleOccurrenceId>,
    date: &str,
    time: &str,
) -> Result<bool, BusinessFailure> {
    let count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM request_schedule_occurrences occurrence \
             JOIN service_requests request ON request.id = occurrence.service_request_id \
             WHERE request.status = 'scheduled' \
               AND (?1 IS NULL OR occurrence.id <> ?1) \
               AND occurrence.scheduled_local_date = ?2 \
               AND occurrence.scheduled_local_time = ?3",
            params![excluded_occurrence.map(|value| value.0), date, time],
            |row| row.get(0),
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    Ok(count != 0)
}

fn schedule_request_on_connection(
    connection: &mut Connection,
    request_id: ServiceRequestId,
) -> Result<(), BusinessFailure> {
    let transaction = begin_immediate(connection)?;
    let (service, status) = parent_state(&transaction, request_id)?;
    if status != RequestStatus::Pending {
        return Err(BusinessFailure::InvalidState);
    }
    let occurrences = occurrences_for_request(&transaction, request_id)?;
    validate_schedule_shape(service, &occurrences)?;
    for occurrence in &occurrences {
        if external_slot_is_occupied(
            &transaction,
            None,
            &occurrence.local_date,
            &occurrence.local_time,
        )? {
            return Err(BusinessFailure::ScheduleConflict);
        }
    }
    let changed = transaction
        .execute(
            "UPDATE service_requests SET status = 'scheduled' WHERE id = ?1 AND status = 'pending'",
            [request_id.0],
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    if changed != 1 {
        return Err(BusinessFailure::ConcurrentChange);
    }
    transaction
        .commit()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)
}

fn reschedule_occurrence_on_connection(
    connection: &mut Connection,
    request_id: ServiceRequestId,
    occurrence_id: ScheduleOccurrenceId,
    input: RescheduleOccurrenceInput,
) -> Result<ScheduleOccurrence, BusinessFailure> {
    let normalized = normalize_occurrence(OccurrenceInput {
        kind: OccurrenceKind::Primary,
        local_date: input.local_date,
        local_time: input.local_time,
        location: input.location,
    })?;
    let transaction = begin_immediate(connection)?;
    let (service, status) = parent_state(&transaction, request_id)?;
    if status != RequestStatus::Scheduled {
        return Err(BusinessFailure::InvalidState);
    }
    let existing = transaction
        .query_row(
            "SELECT id, occurrence_kind, scheduled_local_date, scheduled_local_time, location \
             FROM request_schedule_occurrences WHERE id = ?1 AND service_request_id = ?2",
            params![occurrence_id.0, request_id.0],
            decode_occurrence,
        )
        .optional()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?
        .ok_or(BusinessFailure::NotFound)?;
    if matches!(
        service,
        ServiceCategory::WeddingMarriage | ServiceCategory::FirstCommunion
    ) && normalized.location.is_none()
    {
        return Err(BusinessFailure::InvalidInput);
    }
    if external_slot_is_occupied(
        &transaction,
        Some(occurrence_id),
        &normalized.local_date,
        &normalized.local_time,
    )? {
        return Err(BusinessFailure::ScheduleConflict);
    }
    if service == ServiceCategory::BurialFuneral {
        let sibling_conflict: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM request_schedule_occurrences \
                 WHERE service_request_id = ?1 AND id <> ?2 \
                   AND scheduled_local_date = ?3 AND scheduled_local_time = ?4",
                params![
                    request_id.0,
                    occurrence_id.0,
                    &normalized.local_date,
                    &normalized.local_time
                ],
                |row| row.get(0),
            )
            .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
        if sibling_conflict != 0 {
            return Err(BusinessFailure::ScheduleConflict);
        }
    }
    let changed = transaction
        .execute(
            "UPDATE request_schedule_occurrences \
             SET scheduled_local_date = ?1, scheduled_local_time = ?2, location = ?3 \
             WHERE id = ?4 AND service_request_id = ?5",
            params![
                &normalized.local_date,
                &normalized.local_time,
                &normalized.location,
                occurrence_id.0,
                request_id.0
            ],
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    if changed != 1 {
        return Err(BusinessFailure::ConcurrentChange);
    }
    transaction
        .commit()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    Ok(ScheduleOccurrence {
        id: occurrence_id,
        kind: existing.kind,
        local_date: normalized.local_date,
        local_time: normalized.local_time,
        location: normalized.location,
    })
}

fn complete_request_on_connection(
    connection: &mut Connection,
    request_id: ServiceRequestId,
) -> Result<(), BusinessFailure> {
    let transaction = begin_immediate(connection)?;
    let (_, status) = parent_state(&transaction, request_id)?;
    if status != RequestStatus::Scheduled {
        return Err(BusinessFailure::InvalidState);
    }
    let changed = transaction
        .execute(
            "UPDATE service_requests SET status = 'completed' WHERE id = ?1 AND status = 'scheduled'",
            [request_id.0],
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    if changed != 1 {
        return Err(BusinessFailure::ConcurrentChange);
    }
    transaction
        .commit()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)
}

fn request_cancellation_on_connection(
    connection: &mut Connection,
    request_id: ServiceRequestId,
) -> Result<CancellationReview, BusinessFailure> {
    let requested_at = trusted_created_at()?;
    let transaction = begin_immediate(connection)?;
    let (_, status) = parent_state(&transaction, request_id)?;
    if !matches!(status, RequestStatus::Pending | RequestStatus::Scheduled) {
        return Err(BusinessFailure::InvalidState);
    }
    let pending_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM request_cancellation_reviews \
             WHERE service_request_id = ?1 AND disposition = 'pending'",
            [request_id.0],
            |row| row.get(0),
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    if pending_count != 0 {
        return Err(BusinessFailure::PendingCancellationAlreadyExists);
    }
    transaction
        .execute(
            "INSERT INTO request_cancellation_reviews(\
                service_request_id, disposition, requested_at, resolved_at\
             ) VALUES (?1, 'pending', ?2, NULL)",
            params![request_id.0, requested_at],
        )
        .map_err(|error| {
            if matches!(
                &error,
                rusqlite::Error::SqliteFailure(code, _)
                    if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
            ) {
                BusinessFailure::PendingCancellationAlreadyExists
            } else {
                BusinessFailure::DatabaseUnavailable
            }
        })?;
    let review = CancellationReview {
        id: CancellationReviewId(transaction.last_insert_rowid()),
        disposition: CancellationDisposition::Pending,
        requested_at,
        resolved_at: None,
    };
    transaction
        .commit()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    Ok(review)
}

fn cancellation_review_parent_state(
    transaction: &Transaction<'_>,
    review_id: CancellationReviewId,
) -> Result<(ServiceRequestId, CancellationDisposition, RequestStatus), BusinessFailure> {
    let row = transaction
        .query_row(
            "SELECT review.service_request_id, review.disposition, request.status \
             FROM request_cancellation_reviews review \
             JOIN service_requests request ON request.id = review.service_request_id \
             WHERE review.id = ?1",
            [review_id.0],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?
        .ok_or(BusinessFailure::NotFound)?;
    Ok((
        ServiceRequestId(row.0),
        CancellationDisposition::from_code(&row.1).ok_or(BusinessFailure::DatabaseUnavailable)?,
        RequestStatus::from_code(&row.2).ok_or(BusinessFailure::DatabaseUnavailable)?,
    ))
}

fn approve_cancellation_review_on_connection(
    connection: &mut Connection,
    review_id: CancellationReviewId,
) -> Result<(), BusinessFailure> {
    approve_cancellation_review_transaction(connection, review_id, false)
}

fn approve_cancellation_review_transaction(
    connection: &mut Connection,
    review_id: CancellationReviewId,
    #[cfg_attr(not(test), allow(unused_variables))] fail_after_parent_update: bool,
) -> Result<(), BusinessFailure> {
    let resolved_at = trusted_created_at()?;
    let transaction = begin_immediate(connection)?;
    let (request_id, disposition, status) =
        cancellation_review_parent_state(&transaction, review_id)?;
    if disposition != CancellationDisposition::Pending
        || !matches!(status, RequestStatus::Pending | RequestStatus::Scheduled)
    {
        return Err(BusinessFailure::InvalidState);
    }
    let request_changed = transaction
        .execute(
            "UPDATE service_requests SET status = 'cancelled' \
             WHERE id = ?1 AND status IN ('pending', 'scheduled')",
            [request_id.0],
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    if request_changed != 1 {
        return Err(BusinessFailure::ConcurrentChange);
    }
    #[cfg(test)]
    if fail_after_parent_update {
        return Err(BusinessFailure::ConcurrentChange);
    }
    let review_changed = transaction
        .execute(
            "UPDATE request_cancellation_reviews \
             SET disposition = 'approved', resolved_at = ?1 \
             WHERE id = ?2 AND disposition = 'pending'",
            params![resolved_at, review_id.0],
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    if review_changed != 1 {
        return Err(BusinessFailure::ConcurrentChange);
    }
    transaction
        .commit()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)
}

fn reject_cancellation_review_on_connection(
    connection: &mut Connection,
    review_id: CancellationReviewId,
) -> Result<(), BusinessFailure> {
    let resolved_at = trusted_created_at()?;
    let transaction = begin_immediate(connection)?;
    let (_, disposition, _) = cancellation_review_parent_state(&transaction, review_id)?;
    if disposition != CancellationDisposition::Pending {
        return Err(BusinessFailure::InvalidState);
    }
    let changed = transaction
        .execute(
            "UPDATE request_cancellation_reviews \
             SET disposition = 'rejected', resolved_at = ?1 \
             WHERE id = ?2 AND disposition = 'pending'",
            params![resolved_at, review_id.0],
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    if changed != 1 {
        return Err(BusinessFailure::ConcurrentChange);
    }
    transaction
        .commit()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)
}

fn list_pending_cancellation_reviews_on_connection(
    connection: &Connection,
) -> Result<Vec<PendingCancellationReview>, BusinessFailure> {
    let mut statement = connection
        .prepare(
            "SELECT review.id, request.id, request.service_category, request.status, \
                    request.requester_full_name, review.requested_at \
             FROM request_cancellation_reviews review \
             JOIN service_requests request ON request.id = review.service_request_id \
             WHERE review.disposition = 'pending' \
             ORDER BY review.requested_at ASC, review.id ASC",
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    statement
        .query_map([], |row| {
            let service_code: String = row.get(2)?;
            let status_code: String = row.get(3)?;
            let Some(service_category) = ServiceCategory::from_code(&service_code) else {
                return Err(rusqlite::Error::InvalidQuery);
            };
            let Some(request_status) = RequestStatus::from_code(&status_code) else {
                return Err(rusqlite::Error::InvalidQuery);
            };
            Ok(PendingCancellationReview {
                review_id: CancellationReviewId(row.get(0)?),
                request_id: ServiceRequestId(row.get(1)?),
                service_category,
                request_status,
                requester_display_name: row.get(4)?,
                requested_at: row.get(5)?,
            })
        })
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)
}

fn list_requests_with_pending_cancellation_review_on_connection(
    connection: &Connection,
) -> Result<Vec<ServiceRequestSummary>, BusinessFailure> {
    let mut statement = connection
        .prepare(
            "SELECT request.id, request.service_category, request.status, \
                    request.requester_full_name, request.requester_phone, \
                    request.requester_email, request.created_at \
             FROM request_cancellation_reviews review \
             JOIN service_requests request ON request.id = review.service_request_id \
             WHERE review.disposition = 'pending' \
             ORDER BY review.requested_at ASC, review.id ASC",
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    statement
        .query_map([], decode_summary)
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)
}

fn list_schedule_occupancy_on_connection(
    connection: &Connection,
) -> Result<Vec<ScheduleOccupancyItem>, BusinessFailure> {
    let mut statement = connection
        .prepare(
            "SELECT request.id, request.service_category, occurrence.id, occurrence.occurrence_kind, \
                    occurrence.scheduled_local_date, occurrence.scheduled_local_time, occurrence.location \
             FROM request_schedule_occurrences occurrence \
             JOIN service_requests request ON request.id = occurrence.service_request_id \
             WHERE request.status = 'scheduled' \
             ORDER BY occurrence.scheduled_local_date ASC, occurrence.scheduled_local_time ASC, \
                      occurrence.id ASC, request.id ASC",
        )
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    let rows = statement
        .query_map([], |row| {
            let service_code: String = row.get(1)?;
            let kind_code: String = row.get(3)?;
            let Some(service_category) = ServiceCategory::from_code(&service_code) else {
                return Err(rusqlite::Error::InvalidQuery);
            };
            let Some(kind) = OccurrenceKind::from_code(&kind_code) else {
                return Err(rusqlite::Error::InvalidQuery);
            };
            Ok(ScheduleOccupancyItem {
                request_id: ServiceRequestId(row.get(0)?),
                service_category,
                occurrence: ScheduleOccurrence {
                    id: ScheduleOccurrenceId(row.get(2)?),
                    kind,
                    local_date: row.get(4)?,
                    local_time: row.get(5)?,
                    location: row.get(6)?,
                },
            })
        })
        .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| BusinessFailure::DatabaseUnavailable)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use rusqlite::{params_from_iter, types::Value};

    use super::*;
    use crate::{
        database_key::DatabaseKey,
        database_key_protected_payload::{DecodedDatabaseKeyCandidate, EncodedDatabaseKeyPayload},
        database_schema_v2_contract::V2_SCHEMA_DDL,
        installation_evidence_contract::{
            DatabaseKeyGenerationIdentifier, PERMANENT_APPLICATION_IDENTIFIER,
            UnvalidatedInstallationEvidenceContract,
        },
        installation_evidence_protection::{
            GenerationBoundDatabaseKey, protect_database_key,
            trusted_current_installation_evidence_assessment_for_test,
        },
        production_database_file::{
            ProductionDatabaseInspection, inspect_production_database_file,
        },
        storage_foundation::{
            APPLICATION_DATABASE_FORMAT_IDENTITY, PRODUCTION_DATABASE_FILENAME,
            database_key_persistence_paths, production_database_path,
        },
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const DATABASE_KEY_BYTES: [u8; 32] = [0x74; 32];
    const DATABASE_KEY_GENERATION: [u8; 16] = [0x43; 16];
    const INSTALLATION: [u8; 16] = [0x21; 16];
    const PUBLICATION: [u8; 16] = [0x65; 16];
    const CREATE_METADATA_RELATION: &str = "CREATE TABLE church_app_database_metadata (
        singleton_id,
        metadata_contract_version,
        database_schema_version,
        permanent_application_identifier,
        database_format_identity,
        parish_identifier,
        installation_identifier,
        installation_generation,
        recovery_replacement_generation,
        database_key_generation_identifier,
        setup_publication_identifier,
        database_created_at
    )";
    const INSERT_METADATA_ROW: &str = "INSERT INTO church_app_database_metadata VALUES
        (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

    #[derive(Clone, Copy)]
    enum FixtureSchema {
        ExactV1,
        ExactV2,
        MalformedV2,
    }

    struct ActivationFixture {
        root: PathBuf,
        path: ProductionDatabasePath,
        key_paths: DatabaseKeyPersistencePaths,
        metadata: crate::database_metadata_contract::DatabaseMetadataContractV1,
    }

    impl ActivationFixture {
        fn create(schema: FixtureSchema) -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "church-app-v2-business-database-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            let path = production_database_path(root.clone());
            let key_paths = database_key_persistence_paths(&root);
            fs::create_dir_all(key_paths.database_key_directory.as_path()).unwrap();
            let key = DatabaseKey::from_bytes(DATABASE_KEY_BYTES);
            let wrapper = protect_database_key(&key, key_generation()).unwrap();
            fs::write(key_paths.active_database_key.as_path(), wrapper.as_bytes()).unwrap();

            let connection = Connection::open(root.join(PRODUCTION_DATABASE_FILENAME)).unwrap();
            apply_key_once(&connection, &generation_bound_key()).unwrap();
            let schema_version = match schema {
                FixtureSchema::ExactV1 => 1,
                FixtureSchema::ExactV2 | FixtureSchema::MalformedV2 => 2,
            };
            connection
                .execute_batch(&format!(
                    "PRAGMA application_id = 1128808784; PRAGMA user_version = {schema_version};"
                ))
                .unwrap();
            connection.execute_batch(CREATE_METADATA_RELATION).unwrap();
            connection
                .execute(
                    INSERT_METADATA_ROW,
                    params_from_iter(metadata_values(schema_version).iter()),
                )
                .unwrap();
            if !matches!(schema, FixtureSchema::ExactV1) {
                for statement in V2_SCHEMA_DDL {
                    connection.execute_batch(statement).unwrap();
                }
            }
            let (metadata, _) = observe_and_classify_restart_state(&connection).unwrap();
            if matches!(schema, FixtureSchema::MalformedV2) {
                connection
                    .execute_batch(
                        "DROP INDEX idx_request_schedule_occurrences_schedule;
                         CREATE INDEX idx_request_schedule_occurrences_schedule
                         ON request_schedule_occurrences(scheduled_local_time, scheduled_local_date, id);",
                    )
                    .unwrap();
            }
            connection.close().map_err(|(_, error)| error).unwrap();
            Self {
                root,
                path,
                key_paths,
                metadata,
            }
        }

        fn closed_handoff(&self) -> ClosedExactV2OperationalProductionDatabase {
            let ProductionDatabaseInspection::Present(inspected) =
                inspect_production_database_file(&self.path)
            else {
                panic!("synthetic database must pass canonical inspection");
            };
            ClosedExactV2OperationalProductionDatabase::for_test(
                inspected.identity(),
                self.metadata,
                trusted_current_installation_evidence_assessment_for_test(installation_evidence()),
            )
        }

        fn database_bytes(&self) -> Vec<u8> {
            fs::read(self.root.join(PRODUCTION_DATABASE_FILENAME)).unwrap()
        }

        fn replace_active_key(&self, bytes: [u8; 32]) {
            let wrapper =
                protect_database_key(&DatabaseKey::from_bytes(bytes), key_generation()).unwrap();
            fs::write(
                self.key_paths.active_database_key.as_path(),
                wrapper.as_bytes(),
            )
            .unwrap();
        }

        fn assert_exact_cleanup(self) {
            fs::remove_dir_all(&self.root).unwrap();
            assert!(!self.root.exists());
        }
    }

    impl Drop for ActivationFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn key_generation() -> DatabaseKeyGenerationIdentifier {
        DatabaseKeyGenerationIdentifier::from_bytes(DATABASE_KEY_GENERATION).unwrap()
    }

    fn installation_evidence()
    -> crate::installation_evidence_contract::StructurallyValidatedInstallationEvidence {
        UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            "11111111111111111111111111111111",
            INSTALLATION,
            7,
            11,
            DATABASE_KEY_GENERATION,
            PUBLICATION,
            1_798_000_000,
        )
        .validate()
        .unwrap()
    }

    fn generation_bound_key() -> GenerationBoundDatabaseKey {
        let payload = EncodedDatabaseKeyPayload::encode(
            &DatabaseKey::from_bytes(DATABASE_KEY_BYTES),
            key_generation(),
        );
        bind_database_key_candidate_to_trusted_installation_evidence(
            DecodedDatabaseKeyCandidate::parse(payload.as_bytes()).unwrap(),
            &trusted_current_installation_evidence_assessment_for_test(installation_evidence()),
        )
        .unwrap()
    }

    fn metadata_values(schema_version: i64) -> [Value; 12] {
        [
            Value::Integer(1),
            Value::Integer(1),
            Value::Integer(schema_version),
            Value::Text(PERMANENT_APPLICATION_IDENTIFIER.to_owned()),
            Value::Blob(APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes().to_vec()),
            Value::Blob(vec![0x11; 16]),
            Value::Blob(INSTALLATION.to_vec()),
            Value::Blob(7_u64.to_be_bytes().to_vec()),
            Value::Blob(11_u64.to_be_bytes().to_vec()),
            Value::Blob(DATABASE_KEY_GENERATION.to_vec()),
            Value::Blob(PUBLICATION.to_vec()),
            Value::Integer(1_798_000_000_123),
        ]
    }

    #[test]
    fn foreign_keys_are_explicitly_enabled_and_read_back() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        enable_and_verify_foreign_keys(&connection).unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn inability_to_enable_foreign_keys_prevents_readiness() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        connection.execute_batch("BEGIN").unwrap();
        assert_eq!(enable_and_verify_foreign_keys(&connection), Err(()));
        connection.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn enabled_foreign_keys_reject_a_synthetic_violation() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        connection
            .execute_batch(
                "CREATE TABLE parent (id INTEGER PRIMARY KEY);\
                 CREATE TABLE child (parent_id INTEGER NOT NULL REFERENCES parent(id));",
            )
            .unwrap();
        enable_and_verify_foreign_keys(&connection).unwrap();
        assert!(
            connection
                .execute("INSERT INTO child(parent_id) VALUES (1)", [])
                .is_err()
        );
    }

    #[test]
    fn canonical_exact_v2_activation_preserves_database_and_enforces_foreign_keys() {
        let fixture = ActivationFixture::create(FixtureSchema::ExactV2);
        let before = fixture.database_bytes();
        let V2BusinessDatabaseActivationOutcome::Ready(worker) =
            activate_exact_v2_business_database(
                fixture.closed_handoff(),
                fixture.path.clone(),
                &fixture.key_paths,
            )
        else {
            panic!("canonical synthetic Exact V2 must activate the business worker");
        };
        let (reply, result) = std::sync::mpsc::channel();
        worker
            .send_for_test(BusinessDatabaseCommand::VerifyForeignKeyViolation(reply))
            .unwrap();
        assert!(result.recv().unwrap());
        assert!(matches!(
            worker.shutdown(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert_eq!(fixture.database_bytes(), before);
        fixture.assert_exact_cleanup();
    }

    #[test]
    fn sealed_business_surface_executes_end_to_end_on_the_single_worker() {
        let fixture = ActivationFixture::create(FixtureSchema::ExactV2);
        let V2BusinessDatabaseActivationOutcome::Ready(worker) =
            activate_exact_v2_business_database(
                fixture.closed_handoff(),
                fixture.path.clone(),
                &fixture.key_paths,
            )
        else {
            panic!("canonical synthetic Exact V2 must activate the business worker");
        };
        let request = worker
            .create_request(request_input(ServiceCategory::WeddingMarriage))
            .unwrap();
        let occurrence = worker
            .create_pending_occurrence(
                request.id,
                occurrence_input(
                    OccurrenceKind::Primary,
                    "2037-09-10",
                    "16:30",
                    Some("Parish Church"),
                ),
            )
            .unwrap();
        let occurrence = worker
            .update_pending_occurrence(
                request.id,
                occurrence.id,
                occurrence_input(
                    OccurrenceKind::Primary,
                    "2037-09-10",
                    "16:45",
                    Some("Parish Church"),
                ),
            )
            .unwrap();
        worker.schedule_request(request.id).unwrap();
        let occurrence = worker
            .reschedule_occurrence(
                request.id,
                occurrence.id,
                RescheduleOccurrenceInput {
                    local_date: "2037-09-11".to_owned(),
                    local_time: "17:00".to_owned(),
                    location: Some("Parish Church".to_owned()),
                },
            )
            .unwrap();
        assert_eq!(worker.list_requests().unwrap().len(), 1);
        assert_eq!(
            worker.get_request(request.id).unwrap().occurrences[0],
            occurrence
        );
        assert_eq!(worker.list_schedule_occupancy().unwrap().len(), 1);
        let rejected = worker.request_cancellation(request.id).unwrap();
        assert_eq!(worker.list_pending_cancellation_reviews().unwrap().len(), 1);
        assert_eq!(
            worker
                .list_requests_with_pending_cancellation_review()
                .unwrap()[0]
                .status,
            RequestStatus::Scheduled
        );
        worker.reject_cancellation_review(rejected.id).unwrap();
        assert_eq!(worker.list_schedule_occupancy().unwrap().len(), 1);
        let approved = worker.request_cancellation(request.id).unwrap();
        worker.approve_cancellation_review(approved.id).unwrap();
        assert!(worker.list_schedule_occupancy().unwrap().is_empty());
        let detail = worker.get_request(request.id).unwrap();
        assert_eq!(detail.request.status, RequestStatus::Cancelled);
        assert_eq!(detail.cancellation_reviews.len(), 2);
        assert!(matches!(
            worker.shutdown(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        fixture.assert_exact_cleanup();
    }

    #[test]
    fn wrong_key_v1_and_malformed_v2_fail_closed_before_worker_readiness() {
        let wrong_key = ActivationFixture::create(FixtureSchema::ExactV2);
        wrong_key.replace_active_key([0x91; 32]);
        assert!(matches!(
            activate_exact_v2_business_database(
                wrong_key.closed_handoff(),
                wrong_key.path.clone(),
                &wrong_key.key_paths,
            ),
            V2BusinessDatabaseActivationOutcome::Failed(
                V2BusinessDatabaseActivationError::DatabaseUnavailable
            )
        ));
        wrong_key.assert_exact_cleanup();

        for schema in [FixtureSchema::ExactV1, FixtureSchema::MalformedV2] {
            let fixture = ActivationFixture::create(schema);
            assert!(matches!(
                activate_exact_v2_business_database(
                    fixture.closed_handoff(),
                    fixture.path.clone(),
                    &fixture.key_paths,
                ),
                V2BusinessDatabaseActivationOutcome::Failed(
                    V2BusinessDatabaseActivationError::DatabaseUnavailable
                )
            ));
            fixture.assert_exact_cleanup();
        }
    }

    #[test]
    fn production_surface_is_bounded_fixed_and_operation_closed() {
        let source = include_str!("v2_business_database.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        assert!(production.contains("sync_channel(BUSINESS_DATABASE_COMMAND_CAPACITY)"));
        assert!(production.contains("BUSINESS_DATABASE_COMMAND_CAPACITY: usize = 8"));
        assert!(production.contains("ProductionDatabaseRestartClassification::ExactV2"));
        assert!(production.contains("pragma_update(None, \"foreign_keys\", \"ON\")"));
        assert!(production.contains("pragma_query_value(None, \"foreign_keys\""));
        assert!(production.contains("recover_database_key_candidate_from_loaded_wrapper"));
        assert!(production.contains("apply_key_once(&owner.connection, &key)"));
        assert!(production.contains("drop(key)"));
        for forbidden in [
            "FnOnce(Connection",
            "with_connection",
            "tauri::command",
            "SQLITE_OPEN_CREATE",
            "pub(crate) fn foreign_keys",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
    }

    #[test]
    fn worker_serializes_in_flight_work_rejects_queued_work_and_checked_closes() {
        let root = super::super::tests::TestRoot::create();
        root.create_empty_database();
        let owner = super::super::tests::test_lifetime_owner(&root);
        let V2BusinessDatabaseActivationOutcome::Ready(worker) = start_worker(owner) else {
            panic!("synthetic worker should start");
        };

        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let (completed_sender, completed_receiver) = std::sync::mpsc::channel();
        worker
            .send_for_test(BusinessDatabaseCommand::Block {
                started: started_sender,
                release: release_receiver,
                completed: completed_sender,
            })
            .unwrap();
        started_receiver.recv().unwrap();

        let (queued_sender, queued_receiver) = std::sync::mpsc::channel();
        worker
            .send_for_test(BusinessDatabaseCommand::Probe(queued_sender))
            .unwrap();
        worker.begin_shutdown();
        release_sender.send(()).unwrap();
        completed_receiver.recv().unwrap();
        assert_eq!(
            queued_receiver.recv().unwrap(),
            Err(V2BusinessDatabaseActivationError::DatabaseUnavailable)
        );
        assert!(matches!(
            worker.finish_shutdown(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn worker_close_failure_retains_exact_owner_for_close_only_retry() {
        let root = super::super::tests::TestRoot::create();
        root.create_empty_database();
        let owner = super::super::tests::test_lifetime_owner(&root);
        let V2BusinessDatabaseActivationOutcome::Ready(worker) = start_worker(owner) else {
            panic!("synthetic worker should start");
        };
        worker.inject_close_failure_for_test();
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) = worker.shutdown() else {
            panic!("injected close failure must retain exact ownership");
        };
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    fn business_connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        for statement in V2_SCHEMA_DDL {
            connection.execute_batch(statement).unwrap();
        }
        enable_and_verify_foreign_keys(&connection).unwrap();
        connection
    }

    fn request_input(service_category: ServiceCategory) -> CreateServiceRequest {
        CreateServiceRequest {
            service_category,
            requester_full_name: "  Synthetic Requester  ".to_owned(),
            requester_phone: "  +63 900 000 0000  ".to_owned(),
            requester_email: Some("  synthetic@example.test  ".to_owned()),
        }
    }

    fn occurrence_input(
        kind: OccurrenceKind,
        date: &str,
        time: &str,
        location: Option<&str>,
    ) -> OccurrenceInput {
        OccurrenceInput {
            kind,
            local_date: date.to_owned(),
            local_time: time.to_owned(),
            location: location.map(str::to_owned),
        }
    }

    fn create_request(
        connection: &mut Connection,
        service: ServiceCategory,
    ) -> ServiceRequestSummary {
        create_request_on_connection(connection, request_input(service)).unwrap()
    }

    fn create_occurrence(
        connection: &mut Connection,
        request_id: ServiceRequestId,
        kind: OccurrenceKind,
        date: &str,
        time: &str,
        location: Option<&str>,
    ) -> ScheduleOccurrence {
        create_pending_occurrence_on_connection(
            connection,
            request_id,
            occurrence_input(kind, date, time, location),
        )
        .unwrap()
    }

    #[test]
    fn request_creation_owns_pending_status_timestamp_normalization_and_all_service_codes() {
        let mut connection = business_connection();
        let before = trusted_created_at().unwrap();
        let services = [
            ServiceCategory::Baptism,
            ServiceCategory::Confirmation,
            ServiceCategory::WeddingMarriage,
            ServiceCategory::BurialFuneral,
            ServiceCategory::FirstCommunion,
        ];
        for service in services {
            let created = create_request(&mut connection, service);
            assert_eq!(created.service_category, service);
            assert_eq!(created.status, RequestStatus::Pending);
            assert_eq!(created.requester.full_name, "Synthetic Requester");
            assert_eq!(created.requester.phone, "+63 900 000 0000");
            assert_eq!(
                created.requester.email.as_deref(),
                Some("synthetic@example.test")
            );
            assert!(created.created_at >= before);
        }
        let stored: Vec<(String, String)> = connection
            .prepare("SELECT service_category, status FROM service_requests ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            stored,
            vec![
                ("baptism".to_owned(), "pending".to_owned()),
                ("confirmation".to_owned(), "pending".to_owned()),
                ("wedding_marriage".to_owned(), "pending".to_owned()),
                ("burial_funeral".to_owned(), "pending".to_owned()),
                ("first_communion".to_owned(), "pending".to_owned()),
            ]
        );
        assert!(
            !include_str!("v2_business_database.rs")
                .split("struct CreateServiceRequest")
                .nth(1)
                .unwrap()
                .split('}')
                .next()
                .unwrap()
                .contains("status")
        );
    }

    #[test]
    fn requester_validation_enforces_required_optional_controls_and_schema_bounds() {
        let mut connection = business_connection();
        let mut absent_email = request_input(ServiceCategory::Baptism);
        absent_email.requester_email = None;
        let id = create_request_on_connection(&mut connection, absent_email)
            .unwrap()
            .id;
        assert_eq!(
            connection
                .query_row(
                    "SELECT requester_email FROM service_requests WHERE id = ?1",
                    [id.0],
                    |row| row.get::<_, Option<String>>(0),
                )
                .unwrap(),
            None
        );

        for mutate in [
            |input: &mut CreateServiceRequest| input.requester_full_name = "   ".to_owned(),
            |input: &mut CreateServiceRequest| input.requester_phone = "".to_owned(),
            |input: &mut CreateServiceRequest| input.requester_email = Some("  ".to_owned()),
            |input: &mut CreateServiceRequest| input.requester_full_name = "Bad\0Name".to_owned(),
            |input: &mut CreateServiceRequest| input.requester_phone = "Bad\nPhone".to_owned(),
            |input: &mut CreateServiceRequest| input.requester_full_name = "x".repeat(201),
            |input: &mut CreateServiceRequest| input.requester_phone = "x".repeat(33),
            |input: &mut CreateServiceRequest| input.requester_email = Some("x".repeat(255)),
        ] {
            let mut input = request_input(ServiceCategory::Baptism);
            mutate(&mut input);
            assert_eq!(
                create_request_on_connection(&mut connection, input),
                Err(BusinessFailure::InvalidInput)
            );
        }
        assert_eq!(list_requests_on_connection(&connection).unwrap().len(), 1);
    }

    #[test]
    fn pending_drafts_validate_kind_calendar_time_uniqueness_and_mutate_in_place() {
        let mut connection = business_connection();
        let baptism = create_request(&mut connection, ServiceCategory::Baptism);
        assert_eq!(
            create_pending_occurrence_on_connection(
                &mut connection,
                baptism.id,
                occurrence_input(OccurrenceKind::Funeral, "2026-02-28", "09:00", None),
            ),
            Err(BusinessFailure::InvalidInput)
        );
        for (date, time) in [
            ("2026-02-30", "09:00"),
            ("2025-02-29", "09:00"),
            ("2026-13-01", "09:00"),
            ("2026-01-01", "24:00"),
            ("2026-01-01", "09:60"),
            ("2026-1-01", "09:00"),
            ("2026-01-01", "9:00"),
        ] {
            assert_eq!(
                create_pending_occurrence_on_connection(
                    &mut connection,
                    baptism.id,
                    occurrence_input(OccurrenceKind::Primary, date, time, None),
                ),
                Err(BusinessFailure::InvalidInput)
            );
        }
        let draft = create_occurrence(
            &mut connection,
            baptism.id,
            OccurrenceKind::Primary,
            "2028-02-29",
            "09:00",
            None,
        );
        assert_eq!(
            create_pending_occurrence_on_connection(
                &mut connection,
                baptism.id,
                occurrence_input(OccurrenceKind::Primary, "2028-03-01", "10:00", None),
            ),
            Err(BusinessFailure::InvalidInput)
        );
        let updated = update_pending_occurrence_on_connection(
            &mut connection,
            baptism.id,
            draft.id,
            occurrence_input(
                OccurrenceKind::Primary,
                "2028-03-02",
                "10:15",
                Some("  Chapel  "),
            ),
        )
        .unwrap();
        assert_eq!(updated.id, draft.id);
        assert_eq!(updated.location.as_deref(), Some("Chapel"));
        delete_pending_occurrence_on_connection(&mut connection, baptism.id, draft.id).unwrap();
        assert!(
            get_request_on_connection(&connection, baptism.id)
                .unwrap()
                .occurrences
                .is_empty()
        );
    }

    #[test]
    fn service_scheduling_cardinality_and_required_location_rules_are_enforced() {
        let mut connection = business_connection();
        for service in [
            ServiceCategory::Baptism,
            ServiceCategory::Confirmation,
            ServiceCategory::WeddingMarriage,
            ServiceCategory::FirstCommunion,
        ] {
            let request = create_request(&mut connection, service);
            assert_eq!(
                schedule_request_on_connection(&mut connection, request.id),
                Err(BusinessFailure::InvalidInput)
            );
            create_occurrence(
                &mut connection,
                request.id,
                OccurrenceKind::Primary,
                "2030-01-01",
                match service {
                    ServiceCategory::Baptism => "08:00",
                    ServiceCategory::Confirmation => "09:00",
                    ServiceCategory::WeddingMarriage => "10:00",
                    _ => "11:00",
                },
                None,
            );
            if matches!(
                service,
                ServiceCategory::WeddingMarriage | ServiceCategory::FirstCommunion
            ) {
                assert_eq!(
                    schedule_request_on_connection(&mut connection, request.id),
                    Err(BusinessFailure::InvalidInput)
                );
                let occurrence = get_request_on_connection(&connection, request.id)
                    .unwrap()
                    .occurrences[0]
                    .clone();
                update_pending_occurrence_on_connection(
                    &mut connection,
                    request.id,
                    occurrence.id,
                    occurrence_input(
                        OccurrenceKind::Primary,
                        &occurrence.local_date,
                        &occurrence.local_time,
                        Some("Parish Church"),
                    ),
                )
                .unwrap();
            }
            schedule_request_on_connection(&mut connection, request.id).unwrap();
            assert_eq!(
                schedule_request_on_connection(&mut connection, request.id),
                Err(BusinessFailure::InvalidState)
            );
        }
    }

    #[test]
    fn burial_funeral_accepts_either_or_both_but_rejects_same_internal_slot() {
        let mut connection = business_connection();
        for (day, kinds) in [
            vec![OccurrenceKind::Funeral],
            vec![OccurrenceKind::Burial],
            vec![OccurrenceKind::Funeral, OccurrenceKind::Burial],
        ]
        .into_iter()
        .enumerate()
        {
            let request = create_request(&mut connection, ServiceCategory::BurialFuneral);
            for (offset, kind) in kinds.into_iter().enumerate() {
                create_occurrence(
                    &mut connection,
                    request.id,
                    kind,
                    &format!("2031-02-{:02}", day + 3),
                    if offset == 0 { "08:00" } else { "09:00" },
                    None,
                );
            }
            schedule_request_on_connection(&mut connection, request.id).unwrap();
        }
        let neither = create_request(&mut connection, ServiceCategory::BurialFuneral);
        assert_eq!(
            schedule_request_on_connection(&mut connection, neither.id),
            Err(BusinessFailure::InvalidInput)
        );
        let conflict = create_request(&mut connection, ServiceCategory::BurialFuneral);
        create_occurrence(
            &mut connection,
            conflict.id,
            OccurrenceKind::Funeral,
            "2031-03-04",
            "12:00",
            None,
        );
        create_occurrence(
            &mut connection,
            conflict.id,
            OccurrenceKind::Burial,
            "2031-03-04",
            "12:00",
            None,
        );
        assert_eq!(
            schedule_request_on_connection(&mut connection, conflict.id),
            Err(BusinessFailure::ScheduleConflict)
        );
    }

    #[test]
    fn exact_slot_conflicts_only_with_scheduled_parents_and_location_is_irrelevant() {
        let mut connection = business_connection();
        let active = create_request(&mut connection, ServiceCategory::Baptism);
        create_occurrence(
            &mut connection,
            active.id,
            OccurrenceKind::Primary,
            "2032-04-05",
            "13:30",
            Some("Church"),
        );
        schedule_request_on_connection(&mut connection, active.id).unwrap();
        assert_eq!(
            create_pending_occurrence_on_connection(
                &mut connection,
                active.id,
                occurrence_input(OccurrenceKind::Primary, "2032-04-07", "13:30", None),
            ),
            Err(BusinessFailure::InvalidState)
        );

        let pending = create_request(&mut connection, ServiceCategory::Confirmation);
        create_occurrence(
            &mut connection,
            pending.id,
            OccurrenceKind::Primary,
            "2032-04-05",
            "13:30",
            Some("Hall"),
        );
        assert_eq!(
            schedule_request_on_connection(&mut connection, pending.id),
            Err(BusinessFailure::ScheduleConflict)
        );
        assert_eq!(
            get_request_on_connection(&connection, pending.id)
                .unwrap()
                .request
                .status,
            RequestStatus::Pending
        );

        complete_request_on_connection(&mut connection, active.id).unwrap();
        schedule_request_on_connection(&mut connection, pending.id).unwrap();

        let cancelled = create_request(&mut connection, ServiceCategory::Baptism);
        create_occurrence(
            &mut connection,
            cancelled.id,
            OccurrenceKind::Primary,
            "2032-04-10",
            "10:00",
            None,
        );
        connection
            .execute(
                "UPDATE service_requests SET status = 'cancelled' WHERE id = ?1",
                [cancelled.id.0],
            )
            .unwrap();
        let after_cancel = create_request(&mut connection, ServiceCategory::Baptism);
        create_occurrence(
            &mut connection,
            after_cancel.id,
            OccurrenceKind::Primary,
            "2032-04-10",
            "10:00",
            None,
        );
        schedule_request_on_connection(&mut connection, after_cancel.id).unwrap();

        for (date, time) in [("2032-04-05", "13:31"), ("2032-04-06", "13:30")] {
            let request = create_request(&mut connection, ServiceCategory::Baptism);
            create_occurrence(
                &mut connection,
                request.id,
                OccurrenceKind::Primary,
                date,
                time,
                None,
            );
            schedule_request_on_connection(&mut connection, request.id).unwrap();
        }
    }

    #[test]
    fn rescheduling_is_atomic_in_place_and_releases_the_old_slot() {
        let mut connection = business_connection();
        let first = create_request(&mut connection, ServiceCategory::WeddingMarriage);
        let occurrence = create_occurrence(
            &mut connection,
            first.id,
            OccurrenceKind::Primary,
            "2033-05-01",
            "09:00",
            Some("Church"),
        );
        schedule_request_on_connection(&mut connection, first.id).unwrap();
        let unchanged_self = reschedule_occurrence_on_connection(
            &mut connection,
            first.id,
            occurrence.id,
            RescheduleOccurrenceInput {
                local_date: "2033-05-01".to_owned(),
                local_time: "09:00".to_owned(),
                location: Some("Church".to_owned()),
            },
        )
        .unwrap();
        assert_eq!(unchanged_self.id, occurrence.id);
        let blocker = create_request(&mut connection, ServiceCategory::Baptism);
        let blocker_occurrence = create_occurrence(
            &mut connection,
            blocker.id,
            OccurrenceKind::Primary,
            "2033-05-02",
            "10:00",
            None,
        );
        assert_eq!(
            reschedule_occurrence_on_connection(
                &mut connection,
                blocker.id,
                blocker_occurrence.id,
                RescheduleOccurrenceInput {
                    local_date: "2033-05-02".to_owned(),
                    local_time: "10:30".to_owned(),
                    location: None,
                },
            ),
            Err(BusinessFailure::InvalidState)
        );
        schedule_request_on_connection(&mut connection, blocker.id).unwrap();

        assert_eq!(
            reschedule_occurrence_on_connection(
                &mut connection,
                first.id,
                occurrence.id,
                RescheduleOccurrenceInput {
                    local_date: "2033-05-02".to_owned(),
                    local_time: "10:00".to_owned(),
                    location: Some("Other".to_owned()),
                },
            ),
            Err(BusinessFailure::ScheduleConflict)
        );
        let unchanged = get_request_on_connection(&connection, first.id).unwrap();
        assert_eq!(unchanged.occurrences[0].local_date, "2033-05-01");
        assert_eq!(
            reschedule_occurrence_on_connection(
                &mut connection,
                first.id,
                occurrence.id,
                RescheduleOccurrenceInput {
                    local_date: "2033-05-03".to_owned(),
                    local_time: "11:00".to_owned(),
                    location: None,
                },
            ),
            Err(BusinessFailure::InvalidInput)
        );
        let moved = reschedule_occurrence_on_connection(
            &mut connection,
            first.id,
            occurrence.id,
            RescheduleOccurrenceInput {
                local_date: "2033-05-03".to_owned(),
                local_time: "11:00".to_owned(),
                location: Some("Church".to_owned()),
            },
        )
        .unwrap();
        assert_eq!(moved.id, occurrence.id);
        assert_eq!(
            get_request_on_connection(&connection, first.id)
                .unwrap()
                .request
                .status,
            RequestStatus::Scheduled
        );

        let old_slot = create_request(&mut connection, ServiceCategory::Baptism);
        create_occurrence(
            &mut connection,
            old_slot.id,
            OccurrenceKind::Primary,
            "2033-05-01",
            "09:00",
            None,
        );
        schedule_request_on_connection(&mut connection, old_slot.id).unwrap();
    }

    #[test]
    fn completion_retains_occurrences_and_removes_only_live_occupancy() {
        let mut connection = business_connection();
        let pending = create_request(&mut connection, ServiceCategory::Baptism);
        assert_eq!(
            complete_request_on_connection(&mut connection, pending.id),
            Err(BusinessFailure::InvalidState)
        );
        let occurrence = create_occurrence(
            &mut connection,
            pending.id,
            OccurrenceKind::Primary,
            "2034-06-07",
            "07:45",
            None,
        );
        schedule_request_on_connection(&mut connection, pending.id).unwrap();
        assert_eq!(
            list_schedule_occupancy_on_connection(&connection)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            delete_pending_occurrence_on_connection(&mut connection, pending.id, occurrence.id),
            Err(BusinessFailure::InvalidState)
        );
        complete_request_on_connection(&mut connection, pending.id).unwrap();
        assert_eq!(
            complete_request_on_connection(&mut connection, pending.id),
            Err(BusinessFailure::InvalidState)
        );
        let detail = get_request_on_connection(&connection, pending.id).unwrap();
        assert_eq!(detail.request.status, RequestStatus::Completed);
        assert_eq!(detail.occurrences[0].id, occurrence.id);
        assert!(
            list_schedule_occupancy_on_connection(&connection)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            delete_pending_occurrence_on_connection(&mut connection, pending.id, occurrence.id),
            Err(BusinessFailure::InvalidState)
        );

        let cancelled = create_request(&mut connection, ServiceCategory::Confirmation);
        let cancelled_occurrence = create_occurrence(
            &mut connection,
            cancelled.id,
            OccurrenceKind::Primary,
            "2034-06-08",
            "08:45",
            None,
        );
        connection
            .execute(
                "UPDATE service_requests SET status = 'cancelled' WHERE id = ?1",
                [cancelled.id.0],
            )
            .unwrap();
        assert_eq!(
            delete_pending_occurrence_on_connection(
                &mut connection,
                cancelled.id,
                cancelled_occurrence.id,
            ),
            Err(BusinessFailure::InvalidState)
        );
    }

    #[test]
    fn reads_and_occupancy_have_stable_deterministic_ordering() {
        let mut connection = business_connection();
        let first = create_request(&mut connection, ServiceCategory::Baptism);
        let second = create_request(&mut connection, ServiceCategory::Confirmation);
        connection
            .execute(
                "UPDATE service_requests SET created_at = 42 WHERE id IN (?1, ?2)",
                params![first.id.0, second.id.0],
            )
            .unwrap();
        assert_eq!(
            list_requests_on_connection(&connection)
                .unwrap()
                .iter()
                .map(|item| item.id)
                .collect::<Vec<_>>(),
            vec![second.id, first.id]
        );
        create_occurrence(
            &mut connection,
            first.id,
            OccurrenceKind::Primary,
            "2035-07-08",
            "12:00",
            None,
        );
        create_occurrence(
            &mut connection,
            second.id,
            OccurrenceKind::Primary,
            "2035-07-08",
            "11:00",
            None,
        );
        schedule_request_on_connection(&mut connection, first.id).unwrap();
        schedule_request_on_connection(&mut connection, second.id).unwrap();
        let occupancy = list_schedule_occupancy_on_connection(&connection).unwrap();
        assert_eq!(occupancy[0].request_id, second.id);
        assert_eq!(occupancy[1].request_id, first.id);
        let detail = get_request_on_connection(&connection, first.id).unwrap();
        assert_eq!(detail.request.requester.full_name, "Synthetic Requester");
        assert_eq!(detail.occurrences.len(), 1);
    }

    #[test]
    fn cancellation_requests_preserve_primary_status_enforce_eligibility_and_retain_history() {
        let mut connection = business_connection();
        let pending = create_request(&mut connection, ServiceCategory::Baptism);
        let before = trusted_created_at().unwrap();
        let first = request_cancellation_on_connection(&mut connection, pending.id).unwrap();
        assert_eq!(first.disposition, CancellationDisposition::Pending);
        assert!(first.requested_at >= before);
        assert_eq!(first.resolved_at, None);
        assert_eq!(
            get_request_on_connection(&connection, pending.id)
                .unwrap()
                .request
                .status,
            RequestStatus::Pending
        );
        assert_eq!(
            request_cancellation_on_connection(&mut connection, pending.id),
            Err(BusinessFailure::PendingCancellationAlreadyExists)
        );

        reject_cancellation_review_on_connection(&mut connection, first.id).unwrap();
        let second = request_cancellation_on_connection(&mut connection, pending.id).unwrap();
        assert_ne!(second.id, first.id);
        approve_cancellation_review_on_connection(&mut connection, second.id).unwrap();
        connection
            .execute(
                "UPDATE request_cancellation_reviews SET requested_at = 42 WHERE id IN (?1, ?2)",
                params![first.id.0, second.id.0],
            )
            .unwrap();
        assert_eq!(
            request_cancellation_on_connection(&mut connection, pending.id),
            Err(BusinessFailure::InvalidState)
        );
        assert_eq!(
            approve_cancellation_review_on_connection(&mut connection, second.id),
            Err(BusinessFailure::InvalidState)
        );
        let history = get_request_on_connection(&connection, pending.id)
            .unwrap()
            .cancellation_reviews;
        assert_eq!(history.len(), 2);
        assert_eq!(
            history.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![first.id, second.id]
        );
        assert_eq!(history[0].disposition, CancellationDisposition::Rejected);
        assert!(history[0].resolved_at.is_some());
        assert_eq!(history[1].disposition, CancellationDisposition::Approved);
        assert!(history[1].resolved_at.is_some());

        let completed = create_request(&mut connection, ServiceCategory::Confirmation);
        connection
            .execute(
                "UPDATE service_requests SET status = 'completed' WHERE id = ?1",
                [completed.id.0],
            )
            .unwrap();
        assert_eq!(
            request_cancellation_on_connection(&mut connection, completed.id),
            Err(BusinessFailure::InvalidState)
        );
        let cancelled = create_request(&mut connection, ServiceCategory::Confirmation);
        connection
            .execute(
                "UPDATE service_requests SET status = 'cancelled' WHERE id = ?1",
                [cancelled.id.0],
            )
            .unwrap();
        assert_eq!(
            request_cancellation_on_connection(&mut connection, cancelled.id),
            Err(BusinessFailure::InvalidState)
        );
    }

    #[test]
    fn cancellation_resolution_preserves_or_releases_schedule_occupancy_as_locked() {
        let mut connection = business_connection();
        let scheduled = create_request(&mut connection, ServiceCategory::Baptism);
        let occurrence = create_occurrence(
            &mut connection,
            scheduled.id,
            OccurrenceKind::Primary,
            "2037-09-10",
            "09:00",
            None,
        );
        schedule_request_on_connection(&mut connection, scheduled.id).unwrap();

        let rejected = request_cancellation_on_connection(&mut connection, scheduled.id).unwrap();
        assert_eq!(
            list_schedule_occupancy_on_connection(&connection)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            get_request_on_connection(&connection, scheduled.id)
                .unwrap()
                .request
                .status,
            RequestStatus::Scheduled
        );
        reject_cancellation_review_on_connection(&mut connection, rejected.id).unwrap();
        assert_eq!(
            get_request_on_connection(&connection, scheduled.id)
                .unwrap()
                .request
                .status,
            RequestStatus::Scheduled
        );
        assert_eq!(
            list_schedule_occupancy_on_connection(&connection)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            reject_cancellation_review_on_connection(&mut connection, rejected.id),
            Err(BusinessFailure::InvalidState)
        );

        let approved = request_cancellation_on_connection(&mut connection, scheduled.id).unwrap();
        approve_cancellation_review_on_connection(&mut connection, approved.id).unwrap();
        assert!(
            list_schedule_occupancy_on_connection(&connection)
                .unwrap()
                .is_empty()
        );
        let detail = get_request_on_connection(&connection, scheduled.id).unwrap();
        assert_eq!(detail.request.status, RequestStatus::Cancelled);
        assert_eq!(detail.occurrences[0].id, occurrence.id);
        assert_eq!(detail.cancellation_reviews.len(), 2);
        assert_eq!(
            detail.cancellation_reviews[1].disposition,
            CancellationDisposition::Approved
        );
        assert!(detail.cancellation_reviews[1].resolved_at.is_some());
    }

    #[test]
    fn cancellation_approval_rechecks_parent_and_rolls_back_both_mutations() {
        let mut connection = business_connection();
        let changed_parent = create_request(&mut connection, ServiceCategory::Baptism);
        let review =
            request_cancellation_on_connection(&mut connection, changed_parent.id).unwrap();
        connection
            .execute(
                "UPDATE service_requests SET status = 'completed' WHERE id = ?1",
                [changed_parent.id.0],
            )
            .unwrap();
        assert_eq!(
            approve_cancellation_review_on_connection(&mut connection, review.id),
            Err(BusinessFailure::InvalidState)
        );
        assert_eq!(
            get_request_on_connection(&connection, changed_parent.id)
                .unwrap()
                .cancellation_reviews[0]
                .disposition,
            CancellationDisposition::Pending
        );

        let rollback_parent = create_request(&mut connection, ServiceCategory::Confirmation);
        let rollback_review =
            request_cancellation_on_connection(&mut connection, rollback_parent.id).unwrap();
        assert_eq!(
            approve_cancellation_review_transaction(&mut connection, rollback_review.id, true),
            Err(BusinessFailure::ConcurrentChange)
        );
        let detail = get_request_on_connection(&connection, rollback_parent.id).unwrap();
        assert_eq!(detail.request.status, RequestStatus::Pending);
        assert_eq!(
            detail.cancellation_reviews[0].disposition,
            CancellationDisposition::Pending
        );
        assert_eq!(detail.cancellation_reviews[0].resolved_at, None);
    }

    #[test]
    fn pending_cancellation_discovery_filter_and_detail_are_deterministic_and_dedicated() {
        let mut connection = business_connection();
        let pending = create_request(&mut connection, ServiceCategory::Baptism);
        let scheduled = create_request(&mut connection, ServiceCategory::Confirmation);
        create_occurrence(
            &mut connection,
            scheduled.id,
            OccurrenceKind::Primary,
            "2038-10-11",
            "10:00",
            None,
        );
        schedule_request_on_connection(&mut connection, scheduled.id).unwrap();
        let resolved = create_request(&mut connection, ServiceCategory::FirstCommunion);

        let first = request_cancellation_on_connection(&mut connection, pending.id).unwrap();
        let second = request_cancellation_on_connection(&mut connection, scheduled.id).unwrap();
        let excluded = request_cancellation_on_connection(&mut connection, resolved.id).unwrap();
        reject_cancellation_review_on_connection(&mut connection, excluded.id).unwrap();
        connection
            .execute(
                "UPDATE request_cancellation_reviews SET requested_at = 42 WHERE id IN (?1, ?2)",
                params![first.id.0, second.id.0],
            )
            .unwrap();

        let reviews = list_pending_cancellation_reviews_on_connection(&connection).unwrap();
        assert_eq!(
            reviews
                .iter()
                .map(|item| item.review_id)
                .collect::<Vec<_>>(),
            vec![first.id, second.id]
        );
        assert_eq!(reviews[0].request_status, RequestStatus::Pending);
        assert_eq!(reviews[1].request_status, RequestStatus::Scheduled);
        assert_eq!(reviews[0].requester_display_name, "Synthetic Requester");
        let filtered =
            list_requests_with_pending_cancellation_review_on_connection(&connection).unwrap();
        assert_eq!(
            filtered.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![pending.id, scheduled.id]
        );
        assert_eq!(filtered[0].status, RequestStatus::Pending);
        assert_eq!(filtered[1].status, RequestStatus::Scheduled);
        assert!(
            list_requests_on_connection(&connection)
                .unwrap()
                .iter()
                .all(|item| matches!(
                    item.status,
                    RequestStatus::Pending | RequestStatus::Scheduled
                ))
        );
        let detail = get_request_on_connection(&connection, resolved.id).unwrap();
        assert_eq!(detail.cancellation_reviews.len(), 1);
        assert_eq!(
            detail.cancellation_reviews[0].disposition,
            CancellationDisposition::Rejected
        );
    }

    #[test]
    fn cancellation_surface_uses_immediate_transactions_and_has_no_direct_cancel_command() {
        let source = include_str!("v2_business_database.rs");
        let commands = source
            .split("enum BusinessDatabaseCommand")
            .nth(1)
            .unwrap()
            .split("impl fmt::Debug")
            .next()
            .unwrap();
        assert!(source.contains("BusinessDatabaseCommand::RequestCancellation"));
        assert!(source.contains("BusinessDatabaseCommand::ApproveCancellationReview"));
        assert!(source.contains("BusinessDatabaseCommand::RejectCancellationReview"));
        assert!(source.contains("BusinessDatabaseCommand::ListPendingCancellationReviews"));
        assert!(!commands.contains("CancelRequest"));
        for function in [
            "fn request_cancellation_on_connection",
            "fn approve_cancellation_review_transaction",
            "fn reject_cancellation_review_on_connection",
        ] {
            let body = source.split(function).nth(1).unwrap();
            let body = body.split("\nfn ").next().unwrap();
            assert!(body.contains("begin_immediate(connection)"));
        }
    }

    #[test]
    fn invalid_operations_roll_back_and_foreign_keys_remain_enforced() {
        let mut connection = business_connection();
        let funeral = create_request(&mut connection, ServiceCategory::BurialFuneral);
        let first = create_occurrence(
            &mut connection,
            funeral.id,
            OccurrenceKind::Funeral,
            "2036-08-09",
            "14:00",
            None,
        );
        let second = create_occurrence(
            &mut connection,
            funeral.id,
            OccurrenceKind::Burial,
            "2036-08-09",
            "15:00",
            None,
        );
        schedule_request_on_connection(&mut connection, funeral.id).unwrap();
        assert_eq!(
            reschedule_occurrence_on_connection(
                &mut connection,
                funeral.id,
                second.id,
                RescheduleOccurrenceInput {
                    local_date: "2036-08-09".to_owned(),
                    local_time: "14:00".to_owned(),
                    location: None,
                },
            ),
            Err(BusinessFailure::ScheduleConflict)
        );
        let detail = get_request_on_connection(&connection, funeral.id).unwrap();
        assert_eq!(detail.occurrences[0].id, first.id);
        assert_eq!(detail.occurrences[1].local_time, "15:00");
        assert_eq!(
            connection
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(
            connection
                .execute(
                    "INSERT INTO request_schedule_occurrences(\
                    service_request_id, occurrence_kind, scheduled_local_date, scheduled_local_time\
                 ) VALUES (999999, 'primary', '2036-01-01', '01:00')",
                    [],
                )
                .is_err()
        );
    }
}
