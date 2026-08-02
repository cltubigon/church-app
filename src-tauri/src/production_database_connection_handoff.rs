//! Windows production read-only SQLCipher connection handoff.
//!
//! Success yields only an identity-matched, policy-configured connection to
//! which the generation-bound key was submitted once and on which query-only
//! mode was enabled. The key and database remain unvalidated: no database
//! page, schema, metadata, integrity, correspondence, or freshness check is
//! performed here, and no startup or operational authority is granted.

#![cfg_attr(not(test), allow(dead_code))]

use std::{
    ffi::{OsStr, c_void},
    fmt,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, config::DbConfig};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, FILE_SHARE_MODE, FILE_SHARE_READ, OPEN_EXISTING,
    },
};

use crate::{
    installation_evidence_protection::GenerationBoundDatabaseKey,
    production_database_file::{
        InspectedProductionDatabaseFile, revalidate_borrowed_production_database_file_handle,
    },
    sqlcipher_database_key_application::apply_generation_bound_database_key_to_handle,
    storage_foundation::ProductionDatabasePath,
};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAIN_DATABASE_NAME: &str = "main";
const WIN32_VFS_NAME: &str = "win32";
const GUARD_ACCESS: u32 = FILE_READ_ATTRIBUTES | FILE_READ_DATA;
const GUARD_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ;
const GUARD_DISPOSITION: u32 = OPEN_EXISTING;
const GUARD_FLAGS: FILE_FLAGS_AND_ATTRIBUTES = FILE_FLAG_OPEN_REPARSE_POINT;
const OPEN_FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_ONLY
    .union(OpenFlags::SQLITE_OPEN_FULL_MUTEX)
    .union(OpenFlags::SQLITE_OPEN_PRIVATE_CACHE)
    .union(OpenFlags::SQLITE_OPEN_NOFOLLOW);

pub(crate) enum ProductionDatabaseConnectionOpenError {
    Failed,
    CloseFailed(ProductionDatabaseConnectionConstructionCloseFailure),
}

impl fmt::Debug for ProductionDatabaseConnectionOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed => formatter.write_str("Failed"),
            Self::CloseFailed(_) => formatter.write_str("CloseFailed([REDACTED])"),
        }
    }
}

/// Private native write-exclusion owner. Its data-read access is intentional,
/// but no content or native-handle capability crosses this module boundary.
struct ConnectionLifetimeWriteGuard {
    handle: OwnedHandle,
}

impl fmt::Debug for ConnectionLifetimeWriteGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionLifetimeWriteGuard([REDACTED])")
    }
}

struct GuardedInspection {
    guard: ConnectionLifetimeWriteGuard,
    inspected: InspectedProductionDatabaseFile,
}

struct ConnectionLifetimeOwner {
    connection: Connection,
    guard: ConnectionLifetimeWriteGuard,
    inspected: InspectedProductionDatabaseFile,
}

/// Opaque owner of a keyed-but-unvalidated production connection and the
/// inspection proof retained for its complete lifetime.
pub(crate) struct ProductionReadOnlyDatabaseConnection {
    owner: ConnectionLifetimeOwner,
}

impl fmt::Debug for ProductionReadOnlyDatabaseConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionReadOnlyDatabaseConnection([REDACTED])")
    }
}

#[must_use = "the explicit production database close outcome must be handled"]
pub(crate) enum ProductionDatabaseConnectionCloseOutcome {
    Closed,
    Failed(ProductionDatabaseConnectionCloseFailure),
}

impl fmt::Debug for ProductionDatabaseConnectionCloseOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("Closed"),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

pub(crate) struct ProductionDatabaseConnectionCloseFailure {
    owner: ConnectionLifetimeOwner,
}

impl fmt::Debug for ProductionDatabaseConnectionCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseConnectionCloseFailure([REDACTED])")
    }
}

#[must_use = "a failed construction close retains the connection and its lifetime guards"]
pub(crate) struct ProductionDatabaseConnectionConstructionCloseFailure {
    owner: ConnectionLifetimeOwner,
}

impl fmt::Debug for ProductionDatabaseConnectionConstructionCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseConnectionConstructionCloseFailure([REDACTED])")
    }
}

impl ProductionDatabaseConnectionConstructionCloseFailure {
    /// Consumes the retained failure and retries only explicit SQLite close.
    pub(crate) fn retry_close(self) -> ProductionDatabaseConnectionCloseOutcome {
        close_lifetime_owner(self.owner)
    }
}

impl ProductionDatabaseConnectionCloseFailure {
    /// Consumes the retained failure and retries only explicit SQLite close.
    pub(crate) fn retry_close(self) -> ProductionDatabaseConnectionCloseOutcome {
        close_lifetime_owner(self.owner)
    }
}

impl ProductionReadOnlyDatabaseConnection {
    /// Consumes the owner and reports whether SQLite explicitly closed it.
    /// A failed close remains owned by an opaque, capability-free failure.
    pub(crate) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        close_lifetime_owner(self.owner)
    }

    #[cfg(test)]
    fn close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
    ) -> ProductionDatabaseConnectionCloseOutcome {
        close_lifetime_owner_using(self.owner, close)
    }
}

fn close_lifetime_owner(
    owner: ConnectionLifetimeOwner,
) -> ProductionDatabaseConnectionCloseOutcome {
    close_lifetime_owner_using(owner, |connection| {
        connection
            .close()
            .map_err(|(returned_connection, _)| returned_connection)
    })
}

fn close_lifetime_owner_using(
    owner: ConnectionLifetimeOwner,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> ProductionDatabaseConnectionCloseOutcome {
    let ConnectionLifetimeOwner {
        connection,
        guard,
        inspected,
    } = owner;
    match close(connection) {
        Ok(()) => {
            drop(guard);
            drop(inspected);
            ProductionDatabaseConnectionCloseOutcome::Closed
        }
        Err(connection) => ProductionDatabaseConnectionCloseOutcome::Failed(
            ProductionDatabaseConnectionCloseFailure {
                owner: ConnectionLifetimeOwner {
                    connection,
                    guard,
                    inspected,
                },
            },
        ),
    }
}

fn encode_guard_path(path: &OsStr) -> Result<Vec<u16>, ProductionDatabaseConnectionOpenError> {
    let mut encoded: Vec<u16> = path.encode_wide().collect();
    if encoded.is_empty() || encoded.contains(&0) {
        return Err(ProductionDatabaseConnectionOpenError::Failed);
    }
    encoded.push(0);
    Ok(encoded)
}

fn acquire_guarded_inspection(
    path: &ProductionDatabasePath,
    inspected: InspectedProductionDatabaseFile,
) -> Result<GuardedInspection, ProductionDatabaseConnectionOpenError> {
    let encoded = encode_guard_path(path.as_path().as_os_str())?;
    // SAFETY: the path is NUL-terminated and live for the call. Security
    // attributes and the template handle are null, so the new handle is not
    // inheritable and no caller-owned pointer is retained.
    let raw_handle = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            GUARD_ACCESS,
            GUARD_SHARE,
            std::ptr::null(),
            GUARD_DISPOSITION,
            GUARD_FLAGS,
            std::ptr::null_mut(),
        )
    };
    if raw_handle.is_null() || raw_handle == INVALID_HANDLE_VALUE {
        return Err(ProductionDatabaseConnectionOpenError::Failed);
    }
    // SAFETY: CreateFileW returned one fresh owned handle, transferred exactly
    // once into OwnedHandle for deterministic lifetime ownership.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw_handle) };
    let guard = ConnectionLifetimeWriteGuard { handle };
    revalidate_borrowed_production_database_file_handle(&inspected, guard.handle.as_raw_handle())
        .map_err(|_| ProductionDatabaseConnectionOpenError::Failed)?;
    Ok(GuardedInspection { guard, inspected })
}

/// Opens exactly one path-based read-only connection through the win32 VFS.
#[allow(dead_code)]
pub(crate) fn open_keyed_production_database_read_only(
    path: ProductionDatabasePath,
    inspected: InspectedProductionDatabaseFile,
    key: GenerationBoundDatabaseKey,
) -> Result<ProductionReadOnlyDatabaseConnection, ProductionDatabaseConnectionOpenError> {
    let GuardedInspection { guard, inspected } = acquire_guarded_inspection(&path, inspected)?;
    let connection = open_connection_once(&path)?;
    let owner = ConnectionLifetimeOwner {
        connection,
        guard,
        inspected,
    };

    finish_opened_connection(
        owner,
        revalidate_connection_identity,
        configure_pre_key_policy,
        move |connection| apply_key_once(connection, &key),
        enable_and_verify_query_only,
    )
}

fn open_connection_once(
    path: &ProductionDatabasePath,
) -> Result<Connection, ProductionDatabaseConnectionOpenError> {
    Connection::open_with_flags_and_vfs(path.as_path(), OPEN_FLAGS, WIN32_VFS_NAME)
        .map_err(|_| ProductionDatabaseConnectionOpenError::Failed)
}

fn finish_opened_connection(
    owner: ConnectionLifetimeOwner,
    revalidate_identity: impl FnOnce(
        &Connection,
        &InspectedProductionDatabaseFile,
    ) -> Result<(), ProductionDatabaseConnectionOpenError>,
    configure_policy: impl FnOnce(&Connection) -> Result<(), ProductionDatabaseConnectionOpenError>,
    apply_key: impl FnOnce(&Connection) -> Result<(), ProductionDatabaseConnectionOpenError>,
    enable_query_only: impl FnOnce(&Connection) -> Result<(), ProductionDatabaseConnectionOpenError>,
) -> Result<ProductionReadOnlyDatabaseConnection, ProductionDatabaseConnectionOpenError> {
    finish_opened_connection_using_close(
        owner,
        revalidate_identity,
        configure_policy,
        apply_key,
        enable_query_only,
        |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        },
    )
}

fn finish_opened_connection_using_close(
    owner: ConnectionLifetimeOwner,
    revalidate_identity: impl FnOnce(
        &Connection,
        &InspectedProductionDatabaseFile,
    ) -> Result<(), ProductionDatabaseConnectionOpenError>,
    configure_policy: impl FnOnce(&Connection) -> Result<(), ProductionDatabaseConnectionOpenError>,
    apply_key: impl FnOnce(&Connection) -> Result<(), ProductionDatabaseConnectionOpenError>,
    enable_query_only: impl FnOnce(&Connection) -> Result<(), ProductionDatabaseConnectionOpenError>,
    close_on_failure: impl FnOnce(Connection) -> Result<(), Connection>,
) -> Result<ProductionReadOnlyDatabaseConnection, ProductionDatabaseConnectionOpenError> {
    let result = revalidate_identity(&owner.connection, &owner.inspected)
        .and_then(|_| configure_policy(&owner.connection))
        .and_then(|_| apply_key(&owner.connection))
        .and_then(|_| enable_query_only(&owner.connection));
    if result.is_err() {
        return match close_lifetime_owner_using(owner, close_on_failure) {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                Err(ProductionDatabaseConnectionOpenError::Failed)
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                Err(ProductionDatabaseConnectionOpenError::CloseFailed(
                    ProductionDatabaseConnectionConstructionCloseFailure {
                        owner: failure.owner,
                    },
                ))
            }
        };
    }
    Ok(ProductionReadOnlyDatabaseConnection { owner })
}

fn classify_file_control_handle(
    status: i32,
    handle: HANDLE,
) -> Result<HANDLE, ProductionDatabaseConnectionOpenError> {
    if status != rusqlite::ffi::SQLITE_OK || handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(ProductionDatabaseConnectionOpenError::Failed)
    } else {
        Ok(handle)
    }
}

fn sqlite_main_database_handle(
    connection: &Connection,
) -> Result<HANDLE, ProductionDatabaseConnectionOpenError> {
    let mut borrowed_handle: HANDLE = std::ptr::null_mut();
    // SAFETY: the connection remains exclusively structurally owned for this
    // synchronous file-control call. The raw sqlite pointer does not escape,
    // the database name is a fixed NUL-terminated string, and SQLite writes a
    // borrowed HANDLE into correctly typed live storage.
    let status = unsafe {
        let sqlite = connection.handle();
        if sqlite.is_null() {
            return Err(ProductionDatabaseConnectionOpenError::Failed);
        }
        rusqlite::ffi::sqlite3_file_control(
            sqlite,
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
            (&raw mut borrowed_handle).cast::<c_void>(),
        )
    };
    classify_file_control_handle(status, borrowed_handle)
}

fn revalidate_connection_identity(
    connection: &Connection,
    inspected: &InspectedProductionDatabaseFile,
) -> Result<(), ProductionDatabaseConnectionOpenError> {
    let borrowed_handle = sqlite_main_database_handle(connection)?;
    revalidate_borrowed_production_database_file_handle(inspected, borrowed_handle)
        .map_err(|_| ProductionDatabaseConnectionOpenError::Failed)
}

fn set_and_verify(
    connection: &Connection,
    config: DbConfig,
    expected: bool,
) -> Result<(), ProductionDatabaseConnectionOpenError> {
    if connection.set_db_config(config, expected).ok() != Some(expected)
        || connection.db_config(config).ok() != Some(expected)
    {
        return Err(ProductionDatabaseConnectionOpenError::Failed);
    }
    Ok(())
}

fn configure_pre_key_policy(
    connection: &Connection,
) -> Result<(), ProductionDatabaseConnectionOpenError> {
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(|_| ProductionDatabaseConnectionOpenError::Failed)?;

    // SAFETY: the raw pointer is obtained and consumed synchronously while the
    // exclusively owned Connection is live; it does not escape this block.
    let extension_result = unsafe {
        let sqlite = connection.handle();
        if sqlite.is_null() {
            return Err(ProductionDatabaseConnectionOpenError::Failed);
        }
        rusqlite::ffi::sqlite3_enable_load_extension(sqlite, 0)
    };
    if extension_result != rusqlite::ffi::SQLITE_OK {
        return Err(ProductionDatabaseConnectionOpenError::Failed);
    }

    set_and_verify(connection, DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    set_and_verify(connection, DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    set_and_verify(connection, DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    set_and_verify(
        connection,
        DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE,
        false,
    )?;
    set_and_verify(
        connection,
        DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE,
        false,
    )?;
    if connection.is_readonly(MAIN_DATABASE_NAME).ok() != Some(true) {
        return Err(ProductionDatabaseConnectionOpenError::Failed);
    }
    Ok(())
}

#[allow(dead_code)]
fn apply_key_once(
    connection: &Connection,
    key: &GenerationBoundDatabaseKey,
) -> Result<(), ProductionDatabaseConnectionOpenError> {
    // SAFETY: the pointer is used synchronously by the accepted one-call key
    // primitive while Connection remains live and exclusively structurally
    // owned. The raw pointer does not escape.
    unsafe {
        apply_generation_bound_database_key_to_handle(connection.handle(), key)
            .map_err(|_| ProductionDatabaseConnectionOpenError::Failed)
    }
}

fn enable_and_verify_query_only(
    connection: &Connection,
) -> Result<(), ProductionDatabaseConnectionOpenError> {
    connection
        .pragma_update(None, "query_only", true)
        .map_err(|_| ProductionDatabaseConnectionOpenError::Failed)?;
    let enabled = connection
        .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
        .map_err(|_| ProductionDatabaseConnectionOpenError::Failed)?;
    if !enabled {
        return Err(ProductionDatabaseConnectionOpenError::Failed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        fs::{self, OpenOptions},
        mem::{needs_drop, size_of},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::{
        production_database_file::{
            ProductionDatabaseInspection, inspect_production_database_file,
            synthetic_inspected_file_with_file_id_mismatch,
            synthetic_inspected_file_with_volume_mismatch,
        },
        storage_foundation::{PRODUCTION_DATABASE_FILENAME, production_database_path},
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn create() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "church-app-connection-handoff-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("synthetic root creation should succeed");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn typed_path(&self) -> ProductionDatabasePath {
            production_database_path(self.0.clone())
        }

        fn create_empty_database(&self) {
            let connection = Connection::open(self.0.join(PRODUCTION_DATABASE_FILENAME))
                .expect("synthetic SQLite file creation should succeed");
            connection
                .close()
                .map_err(|(_, error)| error)
                .expect("synthetic creation connection should close");
        }

        fn inspected(&self) -> InspectedProductionDatabaseFile {
            let ProductionDatabaseInspection::Present(inspected) =
                inspect_production_database_file(&self.typed_path())
            else {
                panic!("synthetic database should pass filesystem inspection");
            };
            inspected
        }

        fn open_read_only(&self) -> Connection {
            open_connection_once(&self.typed_path())
                .expect("synthetic read-only open should succeed")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn finish_with_successful_test_key(
        root: &TestRoot,
        key_calls: &Cell<usize>,
    ) -> Result<ProductionReadOnlyDatabaseConnection, ProductionDatabaseConnectionOpenError> {
        let guarded = acquire_guarded_inspection(&root.typed_path(), root.inspected())?;
        let owner = ConnectionLifetimeOwner {
            connection: root.open_read_only(),
            guard: guarded.guard,
            inspected: guarded.inspected,
        };
        finish_opened_connection(
            owner,
            revalidate_connection_identity,
            configure_pre_key_policy,
            |_| {
                key_calls.set(key_calls.get() + 1);
                Ok(())
            },
            enable_and_verify_query_only,
        )
    }

    fn test_lifetime_owner(root: &TestRoot) -> ConnectionLifetimeOwner {
        let guarded = acquire_guarded_inspection(&root.typed_path(), root.inspected())
            .expect("guard acquisition should succeed");
        ConnectionLifetimeOwner {
            connection: root.open_read_only(),
            guard: guarded.guard,
            inspected: guarded.inspected,
        }
    }

    #[test]
    fn production_source_locks_one_open_exact_flags_vfs_and_sealed_surface() {
        const SOURCE: &str = include_str!("production_database_connection_handoff.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert_eq!(
            production
                .matches(&["Connection::open_with_flags_", "and_vfs("].concat())
                .count(),
            1
        );
        assert_eq!(production.matches("CreateFileW(").count(), 1);
        for required in [
            "OpenFlags::SQLITE_OPEN_READ_ONLY",
            "OpenFlags::SQLITE_OPEN_FULL_MUTEX",
            "OpenFlags::SQLITE_OPEN_PRIVATE_CACHE",
            "OpenFlags::SQLITE_OPEN_NOFOLLOW",
            "WIN32_VFS_NAME: &str = \"win32\"",
            "SQLITE_FCNTL_WIN32_GET_HANDLE",
            "sqlite3_enable_load_extension(sqlite, 0)",
            "const GUARD_ACCESS: u32 = FILE_READ_ATTRIBUTES | FILE_READ_DATA;",
            "const GUARD_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ;",
            "const GUARD_DISPOSITION: u32 = OPEN_EXISTING;",
            "const GUARD_FLAGS: FILE_FLAGS_AND_ATTRIBUTES = FILE_FLAG_OPEN_REPARSE_POINT;",
        ] {
            assert!(
                production.contains(required),
                "missing contract: {required}"
            );
        }
        for forbidden in [
            "SQLITE_OPEN_READ_WRITE",
            "SQLITE_OPEN_CREATE",
            "SQLITE_OPEN_SHARED_CACHE",
            "SQLITE_OPEN_NO_MUTEX",
            "SQLITE_OPEN_MEMORY",
            "SQLITE_OPEN_URI",
            "impl Clone for ProductionReadOnlyDatabaseConnection",
            "impl Copy for ProductionReadOnlyDatabaseConnection",
            "impl Deref",
            "AsRef<Connection>",
            "pub connection:",
            "pub(crate) connection:",
            "sqlite3_close",
            "CloseHandle",
            "integrity_check",
            "cipher_integrity_check",
            "sqlite_master",
            "ATTACH DATABASE",
            "tauri::command",
            "GENERIC_READ",
            "FILE_SHARE_WRITE",
            "FILE_SHARE_DELETE",
            "FILE_WRITE_DATA",
            "FILE_APPEND_DATA",
            "FILE_WRITE_ATTRIBUTES",
            "FILE_WRITE_EA",
            "WRITE_DAC",
            "WRITE_OWNER",
            "DELETE",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
        assert_eq!(
            production.matches("apply_key(&owner.connection)").count(),
            1
        );
        assert!(
            production.find("apply_key(&owner.connection)").unwrap()
                < production
                    .find("enable_query_only(&owner.connection)")
                    .unwrap()
        );
        assert!(
            production
                .find("acquire_guarded_inspection(&path, inspected)")
                .unwrap()
                < production.find("open_connection_once(&path)").unwrap()
        );
        let guard = production
            .split_once("struct ConnectionLifetimeWriteGuard {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(guard.contains("handle: OwnedHandle"));
        for forbidden in [
            "pub",
            "File",
            "HANDLE",
            "RawHandle",
            "path",
            "identity",
            "read",
            "seek",
            "map",
            "duplicate",
        ] {
            assert!(!guard.contains(forbidden));
        }
        assert!(needs_drop::<ConnectionLifetimeWriteGuard>());
        assert_eq!(
            size_of::<ConnectionLifetimeWriteGuard>(),
            size_of::<OwnedHandle>()
        );
        let lifetime_owner = production
            .split_once("struct ConnectionLifetimeOwner {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        for required in [
            "connection: Connection",
            "guard: ConnectionLifetimeWriteGuard",
            "inspected: InspectedProductionDatabaseFile",
        ] {
            assert!(lifetime_owner.contains(required));
        }
    }

    #[test]
    fn missing_main_database_fails_without_creation() {
        let root = TestRoot::create();
        let result = open_connection_once(&root.typed_path());
        assert!(result.is_err());
        assert!(!root.path().join(PRODUCTION_DATABASE_FILENAME).exists());
    }

    #[test]
    fn file_control_status_null_and_invalid_handles_fail_closed() {
        let valid = 1_isize as HANDLE;
        assert!(matches!(
            classify_file_control_handle(rusqlite::ffi::SQLITE_ERROR, valid),
            Err(ProductionDatabaseConnectionOpenError::Failed)
        ));
        assert!(matches!(
            classify_file_control_handle(rusqlite::ffi::SQLITE_OK, std::ptr::null_mut()),
            Err(ProductionDatabaseConnectionOpenError::Failed)
        ));
        assert!(matches!(
            classify_file_control_handle(rusqlite::ffi::SQLITE_OK, INVALID_HANDLE_VALUE),
            Err(ProductionDatabaseConnectionOpenError::Failed)
        ));
        assert!(matches!(
            classify_file_control_handle(rusqlite::ffi::SQLITE_OK, valid),
            Ok(handle) if handle == valid
        ));
    }

    #[test]
    fn actual_sqlite_handle_identity_matches_before_one_key_application() {
        let root = TestRoot::create();
        root.create_empty_database();
        let key_calls = Cell::new(0);
        let owner = finish_with_successful_test_key(&root, &key_calls)
            .expect("identity-matched handoff should succeed");
        assert_eq!(key_calls.get(), 1);
        assert_eq!(
            format!("{owner:?}"),
            "ProductionReadOnlyDatabaseConnection([REDACTED])"
        );
        assert!(matches!(
            owner.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
    }

    #[test]
    fn identity_and_policy_failures_prevent_key_application() {
        for fail_identity in [true, false] {
            let root = TestRoot::create();
            root.create_empty_database();
            let key_calls = Cell::new(0);
            let owner = test_lifetime_owner(&root);
            let result = finish_opened_connection(
                owner,
                |_, _| {
                    if fail_identity {
                        Err(ProductionDatabaseConnectionOpenError::Failed)
                    } else {
                        Ok(())
                    }
                },
                |_| {
                    if fail_identity {
                        Ok(())
                    } else {
                        Err(ProductionDatabaseConnectionOpenError::Failed)
                    }
                },
                |_| {
                    key_calls.set(key_calls.get() + 1);
                    Ok(())
                },
                |_| Ok(()),
            );
            assert!(result.is_err());
            assert_eq!(key_calls.get(), 0);
        }
    }

    #[test]
    fn sqlite_identity_mismatch_after_guard_acquisition_prevents_key_application() {
        let guarded_root = TestRoot::create();
        guarded_root.create_empty_database();
        let other_root = TestRoot::create();
        other_root.create_empty_database();
        let guarded =
            acquire_guarded_inspection(&guarded_root.typed_path(), guarded_root.inspected())
                .unwrap();
        let owner = ConnectionLifetimeOwner {
            connection: other_root.open_read_only(),
            guard: guarded.guard,
            inspected: guarded.inspected,
        };
        let key_calls = Cell::new(0);
        let result = finish_opened_connection(
            owner,
            revalidate_connection_identity,
            configure_pre_key_policy,
            |_| {
                key_calls.set(key_calls.get() + 1);
                Ok(())
            },
            enable_and_verify_query_only,
        );
        assert!(matches!(
            result,
            Err(ProductionDatabaseConnectionOpenError::Failed)
        ));
        assert_eq!(key_calls.get(), 0);
    }

    #[test]
    fn exact_volume_and_file_id_mismatches_prevent_key_application() {
        for offset in 0..=16 {
            let root = TestRoot::create();
            root.create_empty_database();
            let key_calls = Cell::new(0);
            let inspected = if offset == 16 {
                synthetic_inspected_file_with_volume_mismatch(root.inspected())
            } else {
                synthetic_inspected_file_with_file_id_mismatch(root.inspected(), offset)
            };
            let result = acquire_guarded_inspection(&root.typed_path(), inspected);
            assert!(result.is_err());
            assert_eq!(key_calls.get(), 0);
        }
    }

    #[test]
    fn policy_states_read_only_query_only_and_controlled_write_failure_are_exact() {
        let root = TestRoot::create();
        root.create_empty_database();
        let key_calls = Cell::new(0);
        let owner = finish_with_successful_test_key(&root, &key_calls).unwrap();
        assert_eq!(key_calls.get(), 1);
        assert_eq!(BUSY_TIMEOUT, Duration::from_secs(5));
        assert_eq!(
            owner.owner.connection.is_readonly(MAIN_DATABASE_NAME),
            Ok(true)
        );
        for (config, expected) in [
            (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
            (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
            (DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true),
            (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, false),
            (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, false),
        ] {
            assert_eq!(owner.owner.connection.db_config(config), Ok(expected));
        }
        assert_eq!(
            owner
                .owner
                .connection
                .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0)),
            Ok(true)
        );
        assert!(
            owner
                .owner
                .connection
                .execute_batch("BEGIN IMMEDIATE")
                .is_err()
        );
        assert!(matches!(
            owner.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
    }

    #[test]
    fn separate_guard_blocks_ordinary_path_mutations_and_new_write_access() {
        let root = TestRoot::create();
        root.create_empty_database();
        let guarded = acquire_guarded_inspection(&root.typed_path(), root.inspected()).unwrap();
        let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
        let moved = root.path().join("moved.synthetic");
        let replacement = root.path().join("replacement.synthetic");
        fs::write(&replacement, b"synthetic replacement").unwrap();

        assert!(fs::rename(&database, &moved).is_err());
        assert!(fs::remove_file(&database).is_err());
        assert!(fs::rename(&replacement, &database).is_err());
        assert!(OpenOptions::new().write(true).open(&database).is_err());
        assert!(database.exists());

        drop(guarded);
        assert!(OpenOptions::new().write(true).open(&database).is_ok());
    }

    #[test]
    fn substitution_between_inspection_and_guard_acquisition_fails() {
        let root = TestRoot::create();
        root.create_empty_database();
        let inspected = root.inspected();
        let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
        let displaced = root.path().join("displaced.synthetic");
        fs::rename(&database, &displaced).unwrap();
        root.create_empty_database();

        assert!(acquire_guarded_inspection(&root.typed_path(), inspected).is_err());
    }

    #[test]
    fn sqlite_key_success_is_not_misclassified_as_key_validation() {
        let root = TestRoot::create();
        root.create_empty_database();
        let key_calls = Cell::new(0);
        let owner = finish_with_successful_test_key(&root, &key_calls)
            .expect("a key-call success alone must remain an accepted unvalidated handoff");
        assert_eq!(key_calls.get(), 1);
        assert!(matches!(
            owner.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
    }

    #[test]
    fn explicit_close_failure_preserves_opaque_redacted_ownership() {
        let root = TestRoot::create();
        root.create_empty_database();
        let key_calls = Cell::new(0);
        let owner = finish_with_successful_test_key(&root, &key_calls).unwrap();
        let outcome = owner.close_using(Err);
        assert_eq!(format!("{outcome:?}"), "Failed([REDACTED])");
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) = outcome else {
            panic!("injected close failure must retain ownership");
        };
        assert_eq!(
            format!("{failure:?}"),
            "ProductionDatabaseConnectionCloseFailure([REDACTED])"
        );
        let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
        assert!(OpenOptions::new().write(true).open(&database).is_err());
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(OpenOptions::new().write(true).open(&database).is_ok());
    }

    #[test]
    fn construction_failure_with_successful_close_returns_coarse_failure() {
        let root = TestRoot::create();
        root.create_empty_database();
        let result = finish_opened_connection(
            test_lifetime_owner(&root),
            |_, _| Err(ProductionDatabaseConnectionOpenError::Failed),
            |_| Ok(()),
            |_| Ok(()),
            |_| Ok(()),
        );
        assert!(matches!(
            result,
            Err(ProductionDatabaseConnectionOpenError::Failed)
        ));
        assert!(
            OpenOptions::new()
                .write(true)
                .open(root.path().join(PRODUCTION_DATABASE_FILENAME))
                .is_ok()
        );
    }

    #[test]
    fn construction_close_failure_retains_connection_guard_and_proof() {
        let root = TestRoot::create();
        root.create_empty_database();
        let result = finish_opened_connection_using_close(
            test_lifetime_owner(&root),
            |_, _| Err(ProductionDatabaseConnectionOpenError::Failed),
            |_| Ok(()),
            |_| Ok(()),
            |_| Ok(()),
            Err,
        );
        assert_eq!(
            format!("{:?}", result.as_ref().err().unwrap()),
            "CloseFailed([REDACTED])"
        );
        let Err(ProductionDatabaseConnectionOpenError::CloseFailed(failure)) = result else {
            panic!("injected construction close failure must retain ownership");
        };
        assert_eq!(
            format!("{failure:?}"),
            "ProductionDatabaseConnectionConstructionCloseFailure([REDACTED])"
        );
        let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
        assert!(OpenOptions::new().write(true).open(&database).is_err());
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(OpenOptions::new().write(true).open(&database).is_ok());
    }

    #[test]
    fn all_errors_and_owner_debug_are_coarse_and_redacted() {
        let error = ProductionDatabaseConnectionOpenError::Failed;
        assert_eq!(format!("{error:?}"), "Failed");
        for sensitive in [
            "path",
            "sqlite",
            "SQLITE",
            "win32",
            "query_only",
            "key",
            "identity",
        ] {
            assert!(!format!("{error:?}").contains(sensitive));
        }
        let root = TestRoot::create();
        root.create_empty_database();
        let guard = acquire_guarded_inspection(&root.typed_path(), root.inspected())
            .unwrap()
            .guard;
        assert_eq!(
            format!("{guard:?}"),
            "ConnectionLifetimeWriteGuard([REDACTED])"
        );
    }
}
