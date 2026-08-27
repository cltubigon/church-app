//! Explicit-authority Windows production database create-new handoff.
//!
//! Success owns the exact atomically created leaf, its hardened parent, and one
//! writable SQLCipher connection after native identity matching and one key
//! application. It performs no database initialization or validation.

#![cfg_attr(not(test), allow(dead_code))]

use std::{
    ffi::{OsStr, c_void},
    fmt, fs,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    },
    path::Path,
};

use rusqlite::{Connection, OpenFlags, config::DbConfig};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_OFFLINE,
        FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_TAG_INFO,
        FILE_CREATION_DISPOSITION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAGS_AND_ATTRIBUTES, FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
        FILE_TYPE_DISK, FileAttributeTagInfo, FileIdInfo, FileStandardInfo,
        GETFINALPATHNAMEBYHANDLE_FLAGS, GetDriveTypeW, GetFileInformationByHandle,
        GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW,
        GetVolumeInformationByHandleW, OPEN_EXISTING, VOLUME_NAME_GUID,
    },
};

use crate::{
    installation_evidence_protection::GenerationBoundDatabaseKey,
    installation_state::FirstTimeSetupAuthorization,
    sqlcipher_database_key_application::apply_generation_bound_database_key_to_handle,
    storage_foundation::{PRODUCTION_DATABASE_FILENAME, ProductionDatabasePath},
};

use super::sqlite_main_database_handle;

const MAIN_DATABASE_NAME: &str = "main";
const WIN32_VFS_NAME: &str = "win32";
const PARENT_ACCESS: u32 = FILE_READ_ATTRIBUTES;
const PARENT_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ | FILE_SHARE_WRITE;
const PARENT_DISPOSITION: FILE_CREATION_DISPOSITION = OPEN_EXISTING;
const PARENT_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
const LEAF_ACCESS: u32 = FILE_READ_ATTRIBUTES | FILE_READ_DATA;
const LEAF_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ | FILE_SHARE_WRITE;
const LEAF_DISPOSITION: FILE_CREATION_DISPOSITION = CREATE_NEW;
const LEAF_FLAGS: FILE_FLAGS_AND_ATTRIBUTES = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
const SQLITE_FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE
    .union(OpenFlags::SQLITE_OPEN_FULL_MUTEX)
    .union(OpenFlags::SQLITE_OPEN_PRIVATE_CACHE)
    .union(OpenFlags::SQLITE_OPEN_NOFOLLOW);
const FINAL_PATH_FLAGS: GETFINALPATHNAMEBYHANDLE_FLAGS = FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;
const MAXIMUM_FINAL_PATH_UNITS: usize = 32_767;
const VOLUME_GUID_PREFIX_UNITS: usize = 49;
const DOCUMENTED_FIXED_DRIVE_CATEGORY: u32 = 3;
const FILESYSTEM_NAME_CAPACITY: usize = 32;
const DISALLOWED_LEAF_ATTRIBUTES: u32 = FILE_ATTRIBUTE_REPARSE_POINT
    | FILE_ATTRIBUTE_SPARSE_FILE
    | FILE_ATTRIBUTE_OFFLINE
    | FILE_ATTRIBUTE_ENCRYPTED
    | FILE_ATTRIBUTE_RECALL_ON_OPEN
    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

#[derive(Clone, Eq, PartialEq)]
struct RetainedObservation {
    identity: FileIdentity,
    disk_entry: bool,
    attributes: u32,
    reparse_tag: u32,
    delete_pending: bool,
    directory: bool,
    link_count: u32,
    size: u64,
    final_path: Vec<u16>,
}

struct RetainedEntry {
    handle: OwnedHandle,
    initial: RetainedObservation,
}

struct RetainedCreatedDatabase {
    parent: RetainedEntry,
    leaf: RetainedEntry,
}

struct NewlyCreatedConnectionLifetimeOwner {
    connection: Connection,
    retained: RetainedCreatedDatabase,
}

/// Opaque keyed-but-uninitialized owner of the exact newly created leaf.
pub(crate) struct NewlyCreatedKeyedProductionDatabaseConnection {
    owner: NewlyCreatedConnectionLifetimeOwner,
}

impl fmt::Debug for NewlyCreatedKeyedProductionDatabaseConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NewlyCreatedKeyedProductionDatabaseConnection([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PostCreateConstructionFailure {
    ConstructionFailedAfterCreation,
    DatabaseKeyApplicationFailedAfterCreation,
}

impl fmt::Debug for PostCreateConstructionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConstructionFailedAfterCreation => "ConstructionFailedAfterCreation",
            Self::DatabaseKeyApplicationFailedAfterCreation => {
                "DatabaseKeyApplicationFailedAfterCreation"
            }
        })
    }
}

#[must_use = "the production database creation result must be handled"]
pub(crate) enum NewProductionDatabaseCreationError {
    TargetAlreadyExists,
    TargetCreationUnavailable,
    SQLiteOpenFailedAfterCreation,
    ConstructionFailedAfterCreation,
    DatabaseKeyApplicationFailedAfterCreation,
    ConstructionCloseFailed(Box<NewProductionDatabaseConnectionConstructionCloseFailure>),
}

impl fmt::Debug for NewProductionDatabaseCreationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TargetAlreadyExists => "TargetAlreadyExists",
            Self::TargetCreationUnavailable => "TargetCreationUnavailable",
            Self::SQLiteOpenFailedAfterCreation => "SQLiteOpenFailedAfterCreation",
            Self::ConstructionFailedAfterCreation => "ConstructionFailedAfterCreation",
            Self::DatabaseKeyApplicationFailedAfterCreation => {
                "DatabaseKeyApplicationFailedAfterCreation"
            }
            Self::ConstructionCloseFailed(_) => "ConstructionCloseFailed([REDACTED])",
        })
    }
}

#[must_use = "the explicit new production database close outcome must be handled"]
pub(crate) enum NewProductionDatabaseConnectionCloseOutcome {
    Closed,
    Failed(NewProductionDatabaseConnectionCloseFailure),
}

impl fmt::Debug for NewProductionDatabaseConnectionCloseOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("Closed"),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

pub(crate) struct NewProductionDatabaseConnectionCloseFailure {
    owner: NewlyCreatedConnectionLifetimeOwner,
}

impl fmt::Debug for NewProductionDatabaseConnectionCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NewProductionDatabaseConnectionCloseFailure([REDACTED])")
    }
}

pub(crate) struct NewProductionDatabaseConnectionConstructionCloseFailure {
    category: PostCreateConstructionFailure,
    owner: NewlyCreatedConnectionLifetimeOwner,
}

impl fmt::Debug for NewProductionDatabaseConnectionConstructionCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NewProductionDatabaseConnectionConstructionCloseFailure([REDACTED])")
    }
}

#[must_use = "a construction close retry outcome must be handled"]
pub(crate) enum NewProductionDatabaseConnectionConstructionCloseRetryOutcome {
    Closed(NewProductionDatabaseCreationError),
    Failed(NewProductionDatabaseConnectionConstructionCloseFailure),
}

impl fmt::Debug for NewProductionDatabaseConnectionConstructionCloseRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(category) => formatter.debug_tuple("Closed").field(category).finish(),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

impl NewlyCreatedKeyedProductionDatabaseConnection {
    pub(crate) fn close(self) -> NewProductionDatabaseConnectionCloseOutcome {
        close_new_lifetime_owner(self.owner)
    }

    #[cfg(test)]
    fn close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
    ) -> NewProductionDatabaseConnectionCloseOutcome {
        close_new_lifetime_owner_using(self.owner, close)
    }
}

impl NewProductionDatabaseConnectionCloseFailure {
    pub(crate) fn retry_close(self) -> NewProductionDatabaseConnectionCloseOutcome {
        close_new_lifetime_owner(self.owner)
    }

    #[cfg(test)]
    fn retry_close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
    ) -> NewProductionDatabaseConnectionCloseOutcome {
        close_new_lifetime_owner_using(self.owner, close)
    }
}

impl NewProductionDatabaseConnectionConstructionCloseFailure {
    pub(crate) fn retry_close(
        self,
    ) -> NewProductionDatabaseConnectionConstructionCloseRetryOutcome {
        retry_construction_close_using(self, |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        })
    }

    #[cfg(test)]
    fn retry_close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
    ) -> NewProductionDatabaseConnectionConstructionCloseRetryOutcome {
        retry_construction_close_using(self, close)
    }
}

/// Consumes first-time setup authority, the canonical typed path, and one
/// generation-bound key to create and key exactly one uninitialized database.
pub(crate) fn create_new_keyed_production_database(
    authorization: FirstTimeSetupAuthorization,
    path: ProductionDatabasePath,
    key: GenerationBoundDatabaseKey,
) -> Result<NewlyCreatedKeyedProductionDatabaseConnection, NewProductionDatabaseCreationError> {
    create_new_keyed_production_database_using(authorization, path, key, |path| {
        Connection::open_with_flags_and_vfs(path, SQLITE_FLAGS, WIN32_VFS_NAME).map_err(|_| ())
    })
}

fn create_new_keyed_production_database_using(
    authorization: FirstTimeSetupAuthorization,
    path: ProductionDatabasePath,
    key: GenerationBoundDatabaseKey,
    open_connection: impl FnOnce(&Path) -> Result<Connection, ()>,
) -> Result<NewlyCreatedKeyedProductionDatabaseConnection, NewProductionDatabaseCreationError> {
    let _authorization = authorization;
    let parent_path = validate_typed_path_contract(&path)?;
    let parent = open_retained_parent(parent_path)?;
    validate_local_ntfs(&parent)
        .map_err(|_| NewProductionDatabaseCreationError::TargetCreationUnavailable)?;
    verify_pre_create_namespace(parent_path, &parent)?;
    let leaf = create_retained_leaf(path.as_path())?;
    let retained = finish_retained_creation(parent, leaf)?;

    let connection = match open_connection(path.as_path()) {
        Ok(connection) => connection,
        Err(()) => {
            drop(retained);
            return Err(NewProductionDatabaseCreationError::SQLiteOpenFailedAfterCreation);
        }
    };
    let owner = NewlyCreatedConnectionLifetimeOwner {
        connection,
        retained,
    };
    finish_opened_created_connection(
        owner,
        key,
        verify_identity_and_configure_writable_pre_key_policy,
        apply_key_once,
    )
}

fn validate_typed_path_contract(
    path: &ProductionDatabasePath,
) -> Result<&Path, NewProductionDatabaseCreationError> {
    let database = path.as_path();
    let parent = database
        .parent()
        .ok_or(NewProductionDatabaseCreationError::TargetCreationUnavailable)?;
    if database != parent.join(PRODUCTION_DATABASE_FILENAME)
        || database.file_name() != Some(OsStr::new(PRODUCTION_DATABASE_FILENAME))
    {
        return Err(NewProductionDatabaseCreationError::TargetCreationUnavailable);
    }
    Ok(parent)
}

fn encode_path(path: &Path) -> Result<Vec<u16>, NewProductionDatabaseCreationError> {
    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.is_empty() || encoded.contains(&0) {
        return Err(NewProductionDatabaseCreationError::TargetCreationUnavailable);
    }
    encoded.push(0);
    Ok(encoded)
}

fn open_native_handle(
    path: &Path,
    access: u32,
    share: FILE_SHARE_MODE,
    disposition: FILE_CREATION_DISPOSITION,
    flags: FILE_FLAGS_AND_ATTRIBUTES,
) -> Result<OwnedHandle, u32> {
    let encoded = encode_path(path).map_err(|_| 0_u32)?;
    // SAFETY: the path is NUL-terminated and live for the synchronous call;
    // optional pointers are null and a successful fresh handle is transferred
    // exactly once into OwnedHandle.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            access,
            share,
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            disposition,
            flags,
            std::ptr::null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        // SAFETY: this immediately follows the failed native call.
        return Err(unsafe { GetLastError() });
    }
    // SAFETY: ownership of this successful fresh handle transfers once.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
}

fn open_retained_parent(path: &Path) -> Result<RetainedEntry, NewProductionDatabaseCreationError> {
    let handle = open_native_handle(
        path,
        PARENT_ACCESS,
        PARENT_SHARE,
        PARENT_DISPOSITION,
        PARENT_FLAGS,
    )
    .map_err(|_| NewProductionDatabaseCreationError::TargetCreationUnavailable)?;
    let initial = query_observation(&handle)
        .and_then(|observation| validate_parent(&observation).map(|_| observation))
        .map_err(|_| NewProductionDatabaseCreationError::TargetCreationUnavailable)?;
    Ok(RetainedEntry { handle, initial })
}

fn create_retained_leaf(path: &Path) -> Result<OwnedHandle, NewProductionDatabaseCreationError> {
    open_native_handle(path, LEAF_ACCESS, LEAF_SHARE, LEAF_DISPOSITION, LEAF_FLAGS).map_err(
        |code| {
            if matches!(code, ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS) {
                NewProductionDatabaseCreationError::TargetAlreadyExists
            } else {
                NewProductionDatabaseCreationError::TargetCreationUnavailable
            }
        },
    )
}

fn finish_retained_creation(
    parent: RetainedEntry,
    leaf_handle: OwnedHandle,
) -> Result<RetainedCreatedDatabase, NewProductionDatabaseCreationError> {
    let leaf_initial = query_observation(&leaf_handle)
        .and_then(|observation| validate_created_leaf(&observation).map(|_| observation))
        .map_err(|_| NewProductionDatabaseCreationError::ConstructionFailedAfterCreation)?;
    exact_child(&parent.initial, &leaf_initial)
        .map_err(|_| NewProductionDatabaseCreationError::ConstructionFailedAfterCreation)?;
    stable_parent(&parent)
        .map_err(|_| NewProductionDatabaseCreationError::ConstructionFailedAfterCreation)?;
    Ok(RetainedCreatedDatabase {
        parent,
        leaf: RetainedEntry {
            handle: leaf_handle,
            initial: leaf_initial,
        },
    })
}

fn exact_name(name: &OsStr, expected: &str) -> bool {
    name.encode_wide().eq(expected.encode_utf16())
}

fn ascii_case_insensitive_prefix(name: &OsStr, prefix: &str) -> bool {
    let units: Vec<u16> = name.encode_wide().collect();
    let prefix: Vec<u16> = prefix.encode_utf16().collect();
    units.len() >= prefix.len()
        && units
            .iter()
            .take(prefix.len())
            .zip(prefix)
            .all(|(left, right)| fold_ascii(*left) == fold_ascii(right))
}

fn verify_pre_create_namespace(
    parent_path: &Path,
    parent: &RetainedEntry,
) -> Result<(), NewProductionDatabaseCreationError> {
    let mut canonical_exists = false;
    let mut suspicious_name_exists = false;
    for entry in fs::read_dir(parent_path)
        .map_err(|_| NewProductionDatabaseCreationError::TargetCreationUnavailable)?
    {
        let name = entry
            .map_err(|_| NewProductionDatabaseCreationError::TargetCreationUnavailable)?
            .file_name();
        if exact_name(&name, PRODUCTION_DATABASE_FILENAME) {
            canonical_exists = true;
        } else if ascii_case_insensitive_prefix(&name, PRODUCTION_DATABASE_FILENAME) {
            suspicious_name_exists = true;
        }
    }
    if suspicious_name_exists {
        return Err(NewProductionDatabaseCreationError::TargetCreationUnavailable);
    }
    if canonical_exists {
        return Err(NewProductionDatabaseCreationError::TargetAlreadyExists);
    }
    stable_parent(parent).map_err(|_| NewProductionDatabaseCreationError::TargetCreationUnavailable)
}

fn checked_size(value: usize) -> Result<u32, ()> {
    u32::try_from(value).map_err(|_| ())
}

fn query_observation(handle: &OwnedHandle) -> Result<RetainedObservation, ()> {
    let raw = handle.as_raw_handle() as HANDLE;
    let mut standard = FILE_STANDARD_INFO::default();
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    let mut identity = FILE_ID_INFO::default();
    for (class, output, size) in [
        (
            FileStandardInfo,
            (&raw mut standard).cast::<c_void>(),
            std::mem::size_of::<FILE_STANDARD_INFO>(),
        ),
        (
            FileAttributeTagInfo,
            (&raw mut attributes).cast::<c_void>(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>(),
        ),
        (
            FileIdInfo,
            (&raw mut identity).cast::<c_void>(),
            std::mem::size_of::<FILE_ID_INFO>(),
        ),
    ] {
        // SAFETY: each output names initialized writable storage matching the
        // requested information class while the borrowed handle remains live.
        if unsafe { GetFileInformationByHandleEx(raw, class, output, checked_size(size)?) } == 0 {
            return Err(());
        }
    }
    let mut legacy = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the initialized output and borrowed handle remain live.
    if unsafe { GetFileInformationByHandle(raw, &raw mut legacy) } == 0 {
        return Err(());
    }
    Ok(RetainedObservation {
        identity: FileIdentity {
            volume_serial: identity.VolumeSerialNumber,
            file_id: identity.FileId.Identifier,
        },
        // SAFETY: synchronous type query on the live borrowed handle.
        disk_entry: unsafe { GetFileType(raw) } == FILE_TYPE_DISK,
        attributes: attributes.FileAttributes,
        reparse_tag: attributes.ReparseTag,
        delete_pending: standard.DeletePending,
        directory: standard.Directory,
        link_count: legacy.nNumberOfLinks,
        size: u64::try_from(standard.EndOfFile).map_err(|_| ())?,
        final_path: query_final_path(raw)?,
    })
}

fn query_final_path(handle: HANDLE) -> Result<Vec<u16>, ()> {
    // SAFETY: documented size query on a live borrowed handle.
    let required =
        unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, FINAL_PATH_FLAGS) };
    let capacity = usize::try_from(required).map_err(|_| ())?;
    if capacity == 0 || capacity > MAXIMUM_FINAL_PATH_UNITS {
        return Err(());
    }
    let mut output = vec![0_u16; capacity];
    // SAFETY: output is writable for the checked capacity.
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, output.as_mut_ptr(), required, FINAL_PATH_FLAGS)
    };
    let written = usize::try_from(written).map_err(|_| ())?;
    if written == 0 || written >= output.len() {
        return Err(());
    }
    output.truncate(written);
    Ok(output)
}

fn ascii_units(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn fold_ascii(unit: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&unit) {
        unit + 32
    } else {
        unit
    }
}

fn is_ascii_hex(unit: u16) -> bool {
    (b'0' as u16..=b'9' as u16).contains(&unit)
        || (b'a' as u16..=b'f' as u16).contains(&unit)
        || (b'A' as u16..=b'F' as u16).contains(&unit)
}

fn volume_prefix(path: &[u16]) -> Result<&[u16], ()> {
    let prefix = ascii_units(r"\\?\Volume{");
    if path.len() < VOLUME_GUID_PREFIX_UNITS
        || path.len() > MAXIMUM_FINAL_PATH_UNITS
        || path.contains(&0)
        || path.get(..prefix.len()) != Some(prefix.as_slice())
        || path[47] != b'}' as u16
        || path[48] != b'\\' as u16
    {
        return Err(());
    }
    for (offset, unit) in path[11..47].iter().copied().enumerate() {
        let valid = if matches!(offset, 8 | 13 | 18 | 23) {
            unit == b'-' as u16
        } else {
            is_ascii_hex(unit)
        };
        if !valid {
            return Err(());
        }
    }
    Ok(&path[..VOLUME_GUID_PREFIX_UNITS])
}

fn validate_parent(observation: &RetainedObservation) -> Result<(), ()> {
    if !observation.disk_entry
        || observation.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || observation.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || observation.reparse_tag != 0
        || !observation.directory
        || observation.delete_pending
    {
        return Err(());
    }
    volume_prefix(&observation.final_path)?;
    Ok(())
}

fn validate_created_leaf(observation: &RetainedObservation) -> Result<(), ()> {
    if !observation.disk_entry
        || observation.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || observation.attributes & DISALLOWED_LEAF_ATTRIBUTES != 0
        || observation.reparse_tag != 0
        || observation.directory
        || observation.delete_pending
        || observation.link_count != 1
        || observation.size != 0
    {
        return Err(());
    }
    volume_prefix(&observation.final_path)?;
    Ok(())
}

fn exact_child(parent: &RetainedObservation, leaf: &RetainedObservation) -> Result<(), ()> {
    let parent_volume = volume_prefix(&parent.final_path)?;
    let leaf_volume = volume_prefix(&leaf.final_path)?;
    if parent.identity.volume_serial != leaf.identity.volume_serial
        || !parent_volume
            .iter()
            .zip(leaf_volume)
            .all(|(left, right)| fold_ascii(*left) == fold_ascii(*right))
    {
        return Err(());
    }
    let mut expected = parent.final_path.clone();
    if expected.last() != Some(&(b'\\' as u16)) {
        expected.push(b'\\' as u16);
    }
    expected.extend(PRODUCTION_DATABASE_FILENAME.encode_utf16());
    if expected.len() != leaf.final_path.len()
        || expected[..11] != leaf.final_path[..11]
        || expected[47..] != leaf.final_path[47..]
        || !expected[11..47]
            .iter()
            .zip(&leaf.final_path[11..47])
            .all(|(left, right)| fold_ascii(*left) == fold_ascii(*right))
    {
        return Err(());
    }
    Ok(())
}

fn validate_local_ntfs(parent: &RetainedEntry) -> Result<(), ()> {
    let mut root = volume_prefix(&parent.initial.final_path)?.to_vec();
    root.push(0);
    // SAFETY: root is the validated NUL-terminated volume-GUID root.
    let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
    if drive_type != DOCUMENTED_FIXED_DRIVE_CATEGORY {
        return Err(());
    }
    let mut filesystem_name = [0_u16; FILESYSTEM_NAME_CAPACITY];
    // SAFETY: the retained parent handle is live and the output buffer has the
    // exact supplied fixed capacity.
    if unsafe {
        GetVolumeInformationByHandleW(
            parent.handle.as_raw_handle() as HANDLE,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            filesystem_name.as_mut_ptr(),
            FILESYSTEM_NAME_CAPACITY as u32,
        )
    } == 0
    {
        return Err(());
    }
    let length = filesystem_name
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(())?;
    let expected: Vec<u16> = "NTFS".encode_utf16().collect();
    if filesystem_name[..length].len() != expected.len()
        || !filesystem_name[..length]
            .iter()
            .zip(expected)
            .all(|(left, right)| fold_ascii(*left) == fold_ascii(right))
    {
        return Err(());
    }
    Ok(())
}

fn stable_parent(parent: &RetainedEntry) -> Result<(), ()> {
    let current = query_observation(&parent.handle)?;
    validate_parent(&current)?;
    if current != parent.initial {
        return Err(());
    }
    Ok(())
}

fn revalidate_retained_creation(retained: &RetainedCreatedDatabase) -> Result<(), ()> {
    let parent = query_observation(&retained.parent.handle)?;
    let leaf = query_observation(&retained.leaf.handle)?;
    validate_parent(&parent)?;
    validate_created_leaf(&leaf)?;
    exact_child(&parent, &leaf)?;
    if parent != retained.parent.initial || leaf != retained.leaf.initial {
        return Err(());
    }
    Ok(())
}

fn borrowed_handle_matches_created_leaf(
    connection: &Connection,
    retained: &RetainedCreatedDatabase,
) -> Result<(), ()> {
    let borrowed = sqlite_main_database_handle(connection).map_err(|_| ())?;
    let identity = identity_from_borrowed_handle(borrowed)?;
    if identity != retained.leaf.initial.identity {
        return Err(());
    }
    Ok(())
}

fn identity_from_borrowed_handle(handle: HANDLE) -> Result<FileIdentity, ()> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(());
    }
    let mut identity = FILE_ID_INFO::default();
    // SAFETY: the borrowed SQLite handle remains live for the synchronous
    // query and the output exactly matches FileIdInfo.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut identity).cast::<c_void>(),
            checked_size(std::mem::size_of::<FILE_ID_INFO>())?,
        )
    } == 0
    {
        return Err(());
    }
    Ok(FileIdentity {
        volume_serial: identity.VolumeSerialNumber,
        file_id: identity.FileId.Identifier,
    })
}

fn verify_identity_and_configure_writable_pre_key_policy(
    owner: &NewlyCreatedConnectionLifetimeOwner,
) -> Result<(), ()> {
    if owner.connection.is_readonly(MAIN_DATABASE_NAME).ok() != Some(false) {
        return Err(());
    }
    borrowed_handle_matches_created_leaf(&owner.connection, &owner.retained)?;
    revalidate_retained_creation(&owner.retained)?;
    configure_writable_pre_key_policy(&owner.connection)
}

fn set_and_verify(connection: &Connection, config: DbConfig, expected: bool) -> Result<(), ()> {
    if connection.set_db_config(config, expected).ok() != Some(expected)
        || connection.db_config(config).ok() != Some(expected)
    {
        return Err(());
    }
    Ok(())
}

fn configure_writable_pre_key_policy(connection: &Connection) -> Result<(), ()> {
    connection
        .busy_timeout(super::BUSY_TIMEOUT)
        .map_err(|_| ())?;
    // SAFETY: the raw pointer is obtained and consumed synchronously while the
    // exclusively owned Connection remains live and does not escape.
    let extension_result = unsafe {
        let sqlite = connection.handle();
        if sqlite.is_null() {
            return Err(());
        }
        rusqlite::ffi::sqlite3_enable_load_extension(sqlite, 0)
    };
    if extension_result != rusqlite::ffi::SQLITE_OK {
        return Err(());
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
    )
}

fn apply_key_once(connection: &Connection, key: &GenerationBoundDatabaseKey) -> Result<(), ()> {
    // SAFETY: identity and policy checks completed first; the live connection
    // is exclusively structurally owned and the raw pointer does not escape.
    unsafe { apply_generation_bound_database_key_to_handle(connection.handle(), key) }
        .map_err(|_| ())
}

fn finish_opened_created_connection(
    owner: NewlyCreatedConnectionLifetimeOwner,
    key: GenerationBoundDatabaseKey,
    validate_and_configure: impl FnOnce(&NewlyCreatedConnectionLifetimeOwner) -> Result<(), ()>,
    apply_key: impl FnOnce(&Connection, &GenerationBoundDatabaseKey) -> Result<(), ()>,
) -> Result<NewlyCreatedKeyedProductionDatabaseConnection, NewProductionDatabaseCreationError> {
    finish_opened_created_connection_using_close(
        owner,
        key,
        validate_and_configure,
        apply_key,
        |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        },
    )
}

fn finish_opened_created_connection_using_close(
    owner: NewlyCreatedConnectionLifetimeOwner,
    key: GenerationBoundDatabaseKey,
    validate_and_configure: impl FnOnce(&NewlyCreatedConnectionLifetimeOwner) -> Result<(), ()>,
    apply_key: impl FnOnce(&Connection, &GenerationBoundDatabaseKey) -> Result<(), ()>,
    close_on_failure: impl FnOnce(Connection) -> Result<(), Connection>,
) -> Result<NewlyCreatedKeyedProductionDatabaseConnection, NewProductionDatabaseCreationError> {
    let category = if validate_and_configure(&owner).is_err() {
        Some(PostCreateConstructionFailure::ConstructionFailedAfterCreation)
    } else if apply_key(&owner.connection, &key).is_err() {
        Some(PostCreateConstructionFailure::DatabaseKeyApplicationFailedAfterCreation)
    } else {
        None
    };
    drop(key);
    let Some(category) = category else {
        return Ok(NewlyCreatedKeyedProductionDatabaseConnection { owner });
    };
    match close_new_lifetime_owner_using(owner, close_on_failure) {
        NewProductionDatabaseConnectionCloseOutcome::Closed => Err(match category {
            PostCreateConstructionFailure::ConstructionFailedAfterCreation => {
                NewProductionDatabaseCreationError::ConstructionFailedAfterCreation
            }
            PostCreateConstructionFailure::DatabaseKeyApplicationFailedAfterCreation => {
                NewProductionDatabaseCreationError::DatabaseKeyApplicationFailedAfterCreation
            }
        }),
        NewProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            Err(NewProductionDatabaseCreationError::ConstructionCloseFailed(
                Box::new(NewProductionDatabaseConnectionConstructionCloseFailure {
                    category,
                    owner: failure.owner,
                }),
            ))
        }
    }
}

fn close_new_lifetime_owner(
    owner: NewlyCreatedConnectionLifetimeOwner,
) -> NewProductionDatabaseConnectionCloseOutcome {
    close_new_lifetime_owner_using(owner, |connection| {
        connection
            .close()
            .map_err(|(returned_connection, _)| returned_connection)
    })
}

fn close_new_lifetime_owner_using(
    owner: NewlyCreatedConnectionLifetimeOwner,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> NewProductionDatabaseConnectionCloseOutcome {
    let NewlyCreatedConnectionLifetimeOwner {
        connection,
        retained,
    } = owner;
    match close(connection) {
        Ok(()) => {
            drop(retained);
            NewProductionDatabaseConnectionCloseOutcome::Closed
        }
        Err(connection) => NewProductionDatabaseConnectionCloseOutcome::Failed(
            NewProductionDatabaseConnectionCloseFailure {
                owner: NewlyCreatedConnectionLifetimeOwner {
                    connection,
                    retained,
                },
            },
        ),
    }
}

fn retry_construction_close_using(
    failure: NewProductionDatabaseConnectionConstructionCloseFailure,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> NewProductionDatabaseConnectionConstructionCloseRetryOutcome {
    let NewProductionDatabaseConnectionConstructionCloseFailure { category, owner } = failure;
    match close_new_lifetime_owner_using(owner, close) {
        NewProductionDatabaseConnectionCloseOutcome::Closed => {
            NewProductionDatabaseConnectionConstructionCloseRetryOutcome::Closed(match category {
                PostCreateConstructionFailure::ConstructionFailedAfterCreation => {
                    NewProductionDatabaseCreationError::ConstructionFailedAfterCreation
                }
                PostCreateConstructionFailure::DatabaseKeyApplicationFailedAfterCreation => {
                    NewProductionDatabaseCreationError::DatabaseKeyApplicationFailedAfterCreation
                }
            })
        }
        NewProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            NewProductionDatabaseConnectionConstructionCloseRetryOutcome::Failed(
                NewProductionDatabaseConnectionConstructionCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        fs,
        io::Write,
        mem::{needs_drop, size_of},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{
        database_key_generation::generate_database_key_material,
        installation_evidence_protection::bind_generated_database_key_for_first_time_setup,
        installation_identifier_generation::generate_installation_identifier,
        installation_state::{
            InstallationEvidence, SetupAuthorizationState, authorize_first_time_setup,
        },
        storage_foundation::production_database_path,
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn create() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock should be after the Unix epoch")
                .as_nanos();
            let temporary_directory = std::env::temp_dir();
            let path = temporary_directory.join(format!(
                "church-app-create-new-database-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            assert!(path.starts_with(&temporary_directory));
            assert!(!path.exists());
            fs::create_dir(&path).expect("isolated test root creation should succeed");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn database_path(&self) -> ProductionDatabasePath {
            production_database_path(self.0.clone())
        }

        fn assert_exact_cleanup(self) {
            fs::remove_dir_all(&self.0).expect("exact test root cleanup should succeed");
            assert!(!self.0.exists());
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn authorization() -> FirstTimeSetupAuthorization {
        match authorize_first_time_setup(InstallationEvidence::NeverInitialized)
            .expect("NeverInitialized should authorize first-time setup")
        {
            SetupAuthorizationState::Authorized(authorization) => authorization,
            SetupAuthorizationState::NotAuthorized => panic!("authorization must carry proof"),
        }
    }

    fn setup_key(authorization: &FirstTimeSetupAuthorization) -> GenerationBoundDatabaseKey {
        let binding = bind_generated_database_key_for_first_time_setup(
            authorization,
            generate_database_key_material().expect("OS key randomness should be available"),
            generate_installation_identifier()
                .expect("OS installation identifier randomness should be available"),
        );
        let (key, _, _) = binding.into_parts();
        key
    }

    fn real_owner(root: &TestRoot) -> NewlyCreatedKeyedProductionDatabaseConnection {
        let authorization = authorization();
        let key = setup_key(&authorization);
        create_new_keyed_production_database(authorization, root.database_path(), key)
            .expect("real create-new handoff should succeed")
    }

    fn unkeyed_open_owner(root: &TestRoot) -> NewlyCreatedConnectionLifetimeOwner {
        let database_path = root.database_path();
        let parent_path = validate_typed_path_contract(&database_path).unwrap();
        let parent = open_retained_parent(parent_path).unwrap();
        validate_local_ntfs(&parent).unwrap();
        verify_pre_create_namespace(parent_path, &parent).unwrap();
        let leaf = create_retained_leaf(root.database_path().as_path()).unwrap();
        let retained = finish_retained_creation(parent, leaf).unwrap();
        let connection = Connection::open_with_flags_and_vfs(
            root.database_path().as_path(),
            SQLITE_FLAGS,
            WIN32_VFS_NAME,
        )
        .unwrap();
        NewlyCreatedConnectionLifetimeOwner {
            connection,
            retained,
        }
    }

    #[test]
    fn source_and_api_surface_are_exact_typed_sealed_and_uninitialized() {
        const SOURCE: &str = include_str!("create_new_database.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        let signature = "pub(crate) fn create_new_keyed_production_database(\n    authorization: FirstTimeSetupAuthorization,\n    path: ProductionDatabasePath,\n    key: GenerationBoundDatabaseKey,\n) -> Result<NewlyCreatedKeyedProductionDatabaseConnection, NewProductionDatabaseCreationError>";
        assert!(production.contains(signature));
        assert!(needs_drop::<NewlyCreatedKeyedProductionDatabaseConnection>());
        assert!(
            size_of::<NewlyCreatedKeyedProductionDatabaseConnection>() > size_of::<Connection>()
        );
        let owner = production
            .split_once("pub(crate) struct NewlyCreatedKeyedProductionDatabaseConnection {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(owner.lines().filter(|line| line.contains(':')).count(), 1);
        assert!(owner.contains("owner: NewlyCreatedConnectionLifetimeOwner"));
        assert!(!owner.contains("pub"));
        for forbidden in [
            "impl Clone for NewlyCreatedKeyedProductionDatabaseConnection",
            "impl Copy for NewlyCreatedKeyedProductionDatabaseConnection",
            "Serialize",
            "Deserialize",
            "impl Deref",
            "AsRef<Connection>",
            "pub connection:",
            "pub(crate) connection:",
            "with_connection",
            "application_id",
            "user_version",
            "CREATE TABLE",
            "INSERT",
            "UPDATE",
            "DELETE",
            "VACUUM",
            "cipher_integrity_check",
            "quick_check",
            "pragma_update",
            "pragma_query",
            "query_only",
            "remove_file",
            "rename(",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
    }

    #[test]
    fn locked_native_and_sqlite_parameters_and_order_are_present() {
        const SOURCE: &str = include_str!("create_new_database.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        for required in [
            "const PARENT_ACCESS: u32 = FILE_READ_ATTRIBUTES;",
            "const PARENT_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ | FILE_SHARE_WRITE;",
            "const PARENT_DISPOSITION: FILE_CREATION_DISPOSITION = OPEN_EXISTING;",
            "FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT",
            "const LEAF_ACCESS: u32 = FILE_READ_ATTRIBUTES | FILE_READ_DATA;",
            "const LEAF_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ | FILE_SHARE_WRITE;",
            "const LEAF_DISPOSITION: FILE_CREATION_DISPOSITION = CREATE_NEW;",
            "FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT",
            "OpenFlags::SQLITE_OPEN_READ_WRITE",
            "OpenFlags::SQLITE_OPEN_FULL_MUTEX",
            "OpenFlags::SQLITE_OPEN_PRIVATE_CACHE",
            "OpenFlags::SQLITE_OPEN_NOFOLLOW",
            "const WIN32_VFS_NAME: &str = \"win32\";",
            "owner.connection.is_readonly(MAIN_DATABASE_NAME).ok() != Some(false)",
            "apply_generation_bound_database_key_to_handle(connection.handle(), key)",
        ] {
            assert!(
                production.contains(required),
                "missing contract: {required}"
            );
        }
        assert!(!production.contains("SQLITE_OPEN_CREATE"));
        assert_eq!(
            production
                .matches("Connection::open_with_flags_and_vfs")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches("apply_generation_bound_database_key_to_handle(")
                .count(),
            1
        );
        let finish = production
            .split_once("fn finish_opened_created_connection_using_close(")
            .unwrap()
            .1;
        assert!(
            finish.find("validate_and_configure(&owner)").unwrap()
                < finish.find("apply_key(&owner.connection, &key)").unwrap()
        );
        let validation = production
            .split_once("fn verify_identity_and_configure_writable_pre_key_policy(")
            .unwrap()
            .1
            .split_once("fn set_and_verify(")
            .unwrap()
            .0;
        assert!(
            validation.find("is_readonly").unwrap()
                < validation
                    .find("borrowed_handle_matches_created_leaf")
                    .unwrap()
        );
        assert!(
            validation
                .find("borrowed_handle_matches_created_leaf")
                .unwrap()
                < validation.find("revalidate_retained_creation").unwrap()
        );
        assert!(
            validation.find("revalidate_retained_creation").unwrap()
                < validation
                    .find("configure_writable_pre_key_policy")
                    .unwrap()
        );
    }

    #[test]
    fn existing_target_is_refused_without_content_or_identity_change() {
        let root = TestRoot::create();
        let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
        let original = b"synthetic-existing-target";
        fs::write(&database, original).unwrap();
        let before = fs::metadata(&database).unwrap();
        let authorization = authorization();
        let key = setup_key(&authorization);
        let open_calls = Cell::new(0);
        let result = create_new_keyed_production_database_using(
            authorization,
            root.database_path(),
            key,
            |_| {
                open_calls.set(open_calls.get() + 1);
                Err(())
            },
        );
        assert!(matches!(
            result,
            Err(NewProductionDatabaseCreationError::TargetAlreadyExists)
        ));
        assert_eq!(open_calls.get(), 0);
        assert_eq!(fs::read(&database).unwrap(), original);
        let after = fs::metadata(&database).unwrap();
        assert_eq!(before.len(), after.len());
        root.assert_exact_cleanup();
    }

    #[test]
    fn suspicious_case_variants_and_sidecars_fail_before_creation() {
        for name in [
            "PARISH-DATA.DB",
            "parish-data.db-journal",
            "parish-data.db-wal",
            "parish-data.db-shm",
            "parish-data.db.stage",
        ] {
            let root = TestRoot::create();
            fs::write(root.path().join(name), b"synthetic").unwrap();
            let authorization = authorization();
            let key = setup_key(&authorization);
            let result =
                create_new_keyed_production_database(authorization, root.database_path(), key);
            assert!(matches!(
                result,
                Err(NewProductionDatabaseCreationError::TargetCreationUnavailable)
            ));
            let canonical = root.path().join(PRODUCTION_DATABASE_FILENAME);
            if name.eq_ignore_ascii_case(PRODUCTION_DATABASE_FILENAME) {
                assert_eq!(fs::read(canonical).unwrap(), b"synthetic");
            } else {
                assert!(!canonical.exists());
            }
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn real_windows_create_key_redact_close_and_leave_file_succeeds() {
        let root = TestRoot::create();
        let owner = real_owner(&root);
        assert_eq!(
            format!("{owner:?}"),
            "NewlyCreatedKeyedProductionDatabaseConnection([REDACTED])"
        );
        assert_eq!(
            owner.owner.connection.is_readonly(MAIN_DATABASE_NAME),
            Ok(false)
        );
        assert!(matches!(
            owner.close(),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn sqlite_open_failure_after_create_leaves_the_exact_file() {
        let root = TestRoot::create();
        let authorization = authorization();
        let key = setup_key(&authorization);
        let open_calls = Cell::new(0);
        let result = create_new_keyed_production_database_using(
            authorization,
            root.database_path(),
            key,
            |_| {
                open_calls.set(open_calls.get() + 1);
                Err(())
            },
        );
        assert!(matches!(
            result,
            Err(NewProductionDatabaseCreationError::SQLiteOpenFailedAfterCreation)
        ));
        assert_eq!(open_calls.get(), 1);
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn identity_or_policy_failure_prevents_keying_and_leaves_file() {
        let root = TestRoot::create();
        let owner = unkeyed_open_owner(&root);
        let authorization = authorization();
        let key = setup_key(&authorization);
        let _authorization = authorization;
        let key_calls = Cell::new(0);
        let result = finish_opened_created_connection(
            owner,
            key,
            |_| Err(()),
            |_, _| {
                key_calls.set(key_calls.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(NewProductionDatabaseCreationError::ConstructionFailedAfterCreation)
        ));
        assert_eq!(key_calls.get(), 0);
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn successful_injected_path_applies_key_stage_exactly_once() {
        let root = TestRoot::create();
        let owner = unkeyed_open_owner(&root);
        let authorization = authorization();
        let key = setup_key(&authorization);
        let _authorization = authorization;
        let key_calls = Cell::new(0);
        let owner = finish_opened_created_connection(
            owner,
            key,
            verify_identity_and_configure_writable_pre_key_policy,
            |_, _| {
                key_calls.set(key_calls.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(key_calls.get(), 1);
        assert!(matches!(
            owner.close(),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn explicit_close_failure_retains_exclusion_and_retry_closes_only() {
        let root = TestRoot::create();
        let owner = real_owner(&root);
        let NewProductionDatabaseConnectionCloseOutcome::Failed(failure) = owner.close_using(Err)
        else {
            panic!("injected close failure must retain the owner");
        };
        assert_eq!(
            format!("{failure:?}"),
            "NewProductionDatabaseConnectionCloseFailure([REDACTED])"
        );
        let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
        assert!(fs::remove_file(&database).is_err());
        let NewProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            failure.retry_close_using(Err)
        else {
            panic!("repeated failure must retain the owner");
        };
        assert!(matches!(
            failure.retry_close(),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(database.is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn construction_close_failure_retains_category_and_lifetime_for_retry() {
        let root = TestRoot::create();
        let owner = unkeyed_open_owner(&root);
        let authorization = authorization();
        let key = setup_key(&authorization);
        let _authorization = authorization;
        let result = finish_opened_created_connection_using_close(
            owner,
            key,
            |_| Err(()),
            |_, _| panic!("key stage must not run"),
            Err,
        );
        let Err(NewProductionDatabaseCreationError::ConstructionCloseFailed(failure)) = result
        else {
            panic!("injected close failure must retain construction ownership");
        };
        assert_eq!(
            format!("{failure:?}"),
            "NewProductionDatabaseConnectionConstructionCloseFailure([REDACTED])"
        );
        let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
        assert!(fs::remove_file(&database).is_err());
        let NewProductionDatabaseConnectionConstructionCloseRetryOutcome::Failed(failure) =
            failure.retry_close_using(Err)
        else {
            panic!("repeated close failure must retain construction ownership");
        };
        assert!(matches!(
            failure.retry_close(),
            NewProductionDatabaseConnectionConstructionCloseRetryOutcome::Closed(
                NewProductionDatabaseCreationError::ConstructionFailedAfterCreation
            )
        ));
        assert!(database.is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn created_leaf_is_continuously_retained_and_identity_matched() {
        let root = TestRoot::create();
        let owner = unkeyed_open_owner(&root);
        assert!(!owner.retained.parent.handle.as_raw_handle().is_null());
        assert!(!owner.retained.leaf.handle.as_raw_handle().is_null());
        assert_eq!(owner.retained.leaf.initial.size, 0);
        assert_eq!(owner.retained.leaf.initial.link_count, 1);
        assert!(borrowed_handle_matches_created_leaf(&owner.connection, &owner.retained).is_ok());
        assert!(revalidate_retained_creation(&owner.retained).is_ok());
        assert!(matches!(
            close_new_lifetime_owner(owner),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn writable_pre_key_policy_is_exact_and_does_not_enable_query_only() {
        let root = TestRoot::create();
        let owner = unkeyed_open_owner(&root);
        verify_identity_and_configure_writable_pre_key_policy(&owner).unwrap();
        assert_eq!(owner.connection.is_readonly(MAIN_DATABASE_NAME), Ok(false));
        for (config, expected) in [
            (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
            (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
            (DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true),
            (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, false),
            (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, false),
        ] {
            assert_eq!(owner.connection.db_config(config), Ok(expected));
        }
        assert!(matches!(
            close_new_lifetime_owner(owner),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn errors_are_payload_free_and_redacted() {
        for (error, expected) in [
            (
                NewProductionDatabaseCreationError::TargetAlreadyExists,
                "TargetAlreadyExists",
            ),
            (
                NewProductionDatabaseCreationError::TargetCreationUnavailable,
                "TargetCreationUnavailable",
            ),
            (
                NewProductionDatabaseCreationError::SQLiteOpenFailedAfterCreation,
                "SQLiteOpenFailedAfterCreation",
            ),
            (
                NewProductionDatabaseCreationError::ConstructionFailedAfterCreation,
                "ConstructionFailedAfterCreation",
            ),
            (
                NewProductionDatabaseCreationError::DatabaseKeyApplicationFailedAfterCreation,
                "DatabaseKeyApplicationFailedAfterCreation",
            ),
        ] {
            assert_eq!(format!("{error:?}"), expected);
        }
    }

    #[test]
    fn parent_registration_is_private_and_read_only_source_remains_locked() {
        const PARENT: &str = include_str!("../production_database_connection_handoff.rs");
        let read_only_production = PARENT.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(PARENT.contains("mod create_new_database;"));
        assert!(!PARENT.contains("pub mod create_new_database;"));
        assert!(
            read_only_production
                .contains("const OPEN_FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_ONLY")
        );
        assert!(read_only_production.contains("struct ConnectionLifetimeWriteGuard"));
        assert!(
            read_only_production
                .contains("pub(crate) fn open_keyed_production_database_read_only(")
        );
        assert!(!read_only_production.contains("create_new_keyed_production_database("));
    }

    #[test]
    fn existing_target_identity_is_unchanged_by_refusal() {
        let root = TestRoot::create();
        let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
        let mut file = fs::File::create(&database).unwrap();
        file.write_all(b"identity-sentinel").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let before_handle = open_native_handle(
            &database,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
        .unwrap();
        let before = query_observation(&before_handle).unwrap().identity;
        drop(before_handle);
        let authorization = authorization();
        let key = setup_key(&authorization);
        assert!(matches!(
            create_new_keyed_production_database(authorization, root.database_path(), key),
            Err(NewProductionDatabaseCreationError::TargetAlreadyExists)
        ));
        let after_handle = open_native_handle(
            &database,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
        .unwrap();
        let after = query_observation(&after_handle).unwrap().identity;
        drop(after_handle);
        assert!(before == after);
        assert_eq!(fs::read(&database).unwrap(), b"identity-sentinel");
        root.assert_exact_cleanup();
    }
}
