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
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    thread::{self, JoinHandle},
};

use rusqlite::{Connection, OpenFlags, config::DbConfig};

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

enum BusinessDatabaseCommand {
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

impl OperationalV2BusinessDatabase {
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
    owner: ConnectionLifetimeOwner,
    receiver: Receiver<BusinessDatabaseCommand>,
    shutdown_requested: &AtomicBool,
    #[cfg(test)] inject_close_failure: &AtomicBool,
) -> ProductionDatabaseConnectionCloseOutcome {
    while let Ok(command) = receiver.recv() {
        if shutdown_requested.load(Ordering::Acquire) {
            reject_command(command);
        } else {
            process_command(&owner.connection, command);
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
    #[cfg(test)]
    match command {
        BusinessDatabaseCommand::Probe(reply) => {
            let _ = reply.send(Err(V2BusinessDatabaseActivationError::DatabaseUnavailable));
        }
        BusinessDatabaseCommand::Block { .. } => {}
        BusinessDatabaseCommand::VerifyForeignKeyViolation(reply) => {
            let _ = reply.send(false);
        }
    }
    #[cfg(not(test))]
    match command {}
}

fn process_command(_connection: &Connection, command: BusinessDatabaseCommand) {
    #[cfg(test)]
    match command {
        BusinessDatabaseCommand::Probe(reply) => {
            let _ = reply.send(Ok(()));
        }
        BusinessDatabaseCommand::Block {
            started,
            release,
            completed,
        } => {
            let _ = started.send(());
            let _ = release.recv();
            let _ = completed.send(());
        }
        BusinessDatabaseCommand::VerifyForeignKeyViolation(reply) => {
            let rejected = _connection
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
    #[cfg(not(test))]
    match command {}
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
}
