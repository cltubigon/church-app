//! Explicit-authority Windows production database create-new handoff.
//!
//! The CREATE-NEW transition returns ownership of the exact atomically created
//! leaf, its hardened parent, and a keyed-but-uninitialized writable SQLCipher
//! connection; it performs no initialization or validation. This private module
//! also contains a separate consuming initialization transition that establishes
//! only the approved initial policy, headers, minimal metadata relation, and
//! canonical row, while granting no validation authority.

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

use rusqlite::{Connection, OpenFlags, Transaction, config::DbConfig, params};
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
    database_metadata_contract::{DatabaseCreationTimestamp, DatabaseMetadataContractV1},
    installation_evidence_contract::{
        DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
        PermanentApplicationIdentifier, RecoveryOrReplacementGeneration,
        SetupPublicationIdentifier,
    },
    installation_evidence_protection::GenerationBoundDatabaseKey,
    installation_state::FirstTimeSetupAuthorization,
    sqlcipher_database_key_application::apply_generation_bound_database_key_to_handle,
    storage_foundation::{PRODUCTION_DATABASE_FILENAME, ParishIdentifier, ProductionDatabasePath},
};

use super::{
    PRODUCTION_DATABASE_APPLICATION_ID, ProductionDatabaseValidationError,
    fixed_metadata_and_header_observation::{
        FixedMetadataAndHeaderObservationError, observe_fixed_metadata_and_headers,
    },
    sqlite_main_database_handle,
};

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

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

pub(crate) struct SetupDatabaseIdentityProof {
    created_leaf_identity: FileIdentity,
}

impl fmt::Debug for SetupDatabaseIdentityProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SetupDatabaseIdentityProof([REDACTED])")
    }
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

/// Opaque initialized-but-unvalidated owner of the exact newly created leaf.
pub(crate) struct InitializedNewProductionDatabaseConnection {
    owner: NewlyCreatedConnectionLifetimeOwner,
    expected_metadata_contract: DatabaseMetadataContractV1,
}

/// Opaque owner proving only immediate read-back of the initialized database.
pub(crate) struct ValidatedInitializedNewProductionDatabaseConnection {
    owner: NewlyCreatedConnectionLifetimeOwner,
    observed_metadata_contract: DatabaseMetadataContractV1,
}

/// Opaque owner proving the fixed cipher and SQLite integrity checks completed
/// on the same immediately validated new-database connection.
pub(crate) struct IntegrityValidatedInitializedNewProductionDatabaseConnection {
    owner: NewlyCreatedConnectionLifetimeOwner,
    observed_metadata_contract: DatabaseMetadataContractV1,
}

/// Setup-only non-live predecessor retaining only the exact validated metadata
/// and historical native identity provenance for the created leaf.
pub(crate) struct ClosedIntegrityValidatedInitializedNewProductionDatabase {
    observed_metadata_contract: DatabaseMetadataContractV1,
    identity_proof: SetupDatabaseIdentityProof,
}

impl fmt::Debug for NewlyCreatedKeyedProductionDatabaseConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NewlyCreatedKeyedProductionDatabaseConnection([REDACTED])")
    }
}

impl fmt::Debug for InitializedNewProductionDatabaseConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitializedNewProductionDatabaseConnection([REDACTED])")
    }
}

impl fmt::Debug for ValidatedInitializedNewProductionDatabaseConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedInitializedNewProductionDatabaseConnection([REDACTED])")
    }
}

impl fmt::Debug for IntegrityValidatedInitializedNewProductionDatabaseConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("IntegrityValidatedInitializedNewProductionDatabaseConnection([REDACTED])")
    }
}

impl fmt::Debug for ClosedIntegrityValidatedInitializedNewProductionDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClosedIntegrityValidatedInitializedNewProductionDatabase([REDACTED])")
    }
}

impl ClosedIntegrityValidatedInitializedNewProductionDatabase {
    pub(crate) fn into_parts(self) -> (DatabaseMetadataContractV1, SetupDatabaseIdentityProof) {
        (self.observed_metadata_contract, self.identity_proof)
    }
}

#[must_use = "the new production database integrity validation result must be handled"]
pub(crate) enum NewProductionDatabaseIntegrityValidationError {
    EncryptedDatabaseAuthenticationOrCipherIntegrityFailed,
    SQLiteReadabilityOrIntegrityFailed,
    ValidationUnavailable,
    ValidationInterruptedOrIncomplete,
    IntegrityValidationCloseFailed(Box<NewProductionDatabaseIntegrityValidationCloseFailure>),
}

impl fmt::Debug for NewProductionDatabaseIntegrityValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EncryptedDatabaseAuthenticationOrCipherIntegrityFailed => {
                "EncryptedDatabaseAuthenticationOrCipherIntegrityFailed"
            }
            Self::SQLiteReadabilityOrIntegrityFailed => "SQLiteReadabilityOrIntegrityFailed",
            Self::ValidationUnavailable => "ValidationUnavailable",
            Self::ValidationInterruptedOrIncomplete => "ValidationInterruptedOrIncomplete",
            Self::IntegrityValidationCloseFailed(_) => "IntegrityValidationCloseFailed([REDACTED])",
        })
    }
}

pub(crate) struct NewProductionDatabaseIntegrityValidationCloseFailure {
    category: NewProductionDatabaseIntegrityValidationFailure,
    owner: NewlyCreatedConnectionLifetimeOwner,
}

impl fmt::Debug for NewProductionDatabaseIntegrityValidationCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NewProductionDatabaseIntegrityValidationCloseFailure([REDACTED])")
    }
}

#[must_use = "an integrity validation close retry outcome must be handled"]
pub(crate) enum NewProductionDatabaseIntegrityValidationCloseRetryOutcome {
    Closed(NewProductionDatabaseIntegrityValidationError),
    Failed(NewProductionDatabaseIntegrityValidationCloseFailure),
}

impl fmt::Debug for NewProductionDatabaseIntegrityValidationCloseRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(category) => formatter.debug_tuple("Closed").field(category).finish(),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum NewProductionDatabaseIntegrityValidationFailure {
    EncryptedDatabaseAuthenticationOrCipherIntegrityFailed,
    SQLiteReadabilityOrIntegrityFailed,
    ValidationUnavailable,
    ValidationInterruptedOrIncomplete,
}

pub(crate) enum NewProductionDatabaseImmediateValidationError {
    ValidationTransactionFailed,
    HeaderObservationFailed,
    HeaderMismatch,
    MetadataObservationFailed,
    MetadataMalformed,
    MetadataMismatch,
    ValidationCloseFailed(Box<NewProductionDatabaseImmediateValidationCloseFailure>),
}

impl fmt::Debug for NewProductionDatabaseImmediateValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ValidationTransactionFailed => "ValidationTransactionFailed",
            Self::HeaderObservationFailed => "HeaderObservationFailed",
            Self::HeaderMismatch => "HeaderMismatch",
            Self::MetadataObservationFailed => "MetadataObservationFailed",
            Self::MetadataMalformed => "MetadataMalformed",
            Self::MetadataMismatch => "MetadataMismatch",
            Self::ValidationCloseFailed(_) => "ValidationCloseFailed([REDACTED])",
        })
    }
}

pub(crate) struct NewProductionDatabaseImmediateValidationCloseFailure {
    category: NewProductionDatabaseImmediateValidationFailure,
    owner: NewlyCreatedConnectionLifetimeOwner,
}

impl fmt::Debug for NewProductionDatabaseImmediateValidationCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NewProductionDatabaseImmediateValidationCloseFailure([REDACTED])")
    }
}

#[must_use = "an immediate validation close retry outcome must be handled"]
pub(crate) enum NewProductionDatabaseImmediateValidationCloseRetryOutcome {
    Closed(NewProductionDatabaseImmediateValidationError),
    Failed(NewProductionDatabaseImmediateValidationCloseFailure),
}

impl fmt::Debug for NewProductionDatabaseImmediateValidationCloseRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(category) => formatter.debug_tuple("Closed").field(category).finish(),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum NewProductionDatabaseImmediateValidationFailure {
    ValidationTransactionFailed,
    HeaderObservationFailed,
    HeaderMismatch,
    MetadataObservationFailed,
    MetadataMalformed,
    MetadataMismatch,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
enum NewProductionDatabaseInitializationFailure {
    MetadataRepresentationFailed,
    InitializationPolicyFailed,
    InitializationTransactionStartFailed,
    HeaderInitializationFailed,
    MetadataSchemaCreationFailed,
    MetadataInsertionFailed,
    InitializationCommitFailed,
}

impl fmt::Debug for NewProductionDatabaseInitializationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MetadataRepresentationFailed => "MetadataRepresentationFailed",
            Self::InitializationPolicyFailed => "InitializationPolicyFailed",
            Self::InitializationTransactionStartFailed => "InitializationTransactionStartFailed",
            Self::HeaderInitializationFailed => "HeaderInitializationFailed",
            Self::MetadataSchemaCreationFailed => "MetadataSchemaCreationFailed",
            Self::MetadataInsertionFailed => "MetadataInsertionFailed",
            Self::InitializationCommitFailed => "InitializationCommitFailed",
        })
    }
}

#[must_use = "the new production database initialization result must be handled"]
#[allow(clippy::enum_variant_names)]
pub(crate) enum NewProductionDatabaseInitializationError {
    MetadataRepresentationFailed,
    InitializationPolicyFailed,
    InitializationTransactionStartFailed,
    HeaderInitializationFailed,
    MetadataSchemaCreationFailed,
    MetadataInsertionFailed,
    InitializationCommitFailed,
    InitializationCloseFailed(Box<NewProductionDatabaseInitializationCloseFailure>),
}

impl fmt::Debug for NewProductionDatabaseInitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitializationCloseFailed(_) => {
                formatter.write_str("InitializationCloseFailed([REDACTED])")
            }
            _ => formatter.write_str(match self {
                Self::MetadataRepresentationFailed => "MetadataRepresentationFailed",
                Self::InitializationPolicyFailed => "InitializationPolicyFailed",
                Self::InitializationTransactionStartFailed => {
                    "InitializationTransactionStartFailed"
                }
                Self::HeaderInitializationFailed => "HeaderInitializationFailed",
                Self::MetadataSchemaCreationFailed => "MetadataSchemaCreationFailed",
                Self::MetadataInsertionFailed => "MetadataInsertionFailed",
                Self::InitializationCommitFailed => "InitializationCommitFailed",
                Self::InitializationCloseFailed(_) => unreachable!(),
            }),
        }
    }
}

pub(crate) struct NewProductionDatabaseInitializationCloseFailure {
    category: NewProductionDatabaseInitializationFailure,
    owner: NewlyCreatedConnectionLifetimeOwner,
}

impl fmt::Debug for NewProductionDatabaseInitializationCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NewProductionDatabaseInitializationCloseFailure([REDACTED])")
    }
}

#[must_use = "an initialization close retry outcome must be handled"]
pub(crate) enum NewProductionDatabaseInitializationCloseRetryOutcome {
    Closed(NewProductionDatabaseInitializationError),
    Failed(NewProductionDatabaseInitializationCloseFailure),
}

impl fmt::Debug for NewProductionDatabaseInitializationCloseRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(category) => formatter.debug_tuple("Closed").field(category).finish(),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
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

#[must_use = "the setup database close-and-preserve outcome must be handled"]
pub(crate) enum NewProductionDatabaseCloseAndPreserveOutcome {
    Closed(ClosedIntegrityValidatedInitializedNewProductionDatabase),
    Failed(NewProductionDatabaseCloseAndPreserveFailure),
}

impl fmt::Debug for NewProductionDatabaseCloseAndPreserveOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(_) => formatter.write_str("Closed([REDACTED])"),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

pub(crate) struct NewProductionDatabaseCloseAndPreserveFailure {
    owner: NewlyCreatedConnectionLifetimeOwner,
    observed_metadata_contract: DatabaseMetadataContractV1,
    identity_proof: SetupDatabaseIdentityProof,
}

impl fmt::Debug for NewProductionDatabaseCloseAndPreserveFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NewProductionDatabaseCloseAndPreserveFailure([REDACTED])")
    }
}

#[must_use = "the setup database close-and-preserve retry outcome must be handled"]
pub(crate) enum NewProductionDatabaseCloseAndPreserveRetryOutcome {
    Closed(ClosedIntegrityValidatedInitializedNewProductionDatabase),
    Failed(NewProductionDatabaseCloseAndPreserveFailure),
}

impl fmt::Debug for NewProductionDatabaseCloseAndPreserveRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(_) => formatter.write_str("Closed([REDACTED])"),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
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

impl InitializedNewProductionDatabaseConnection {
    pub(crate) fn close(self) -> NewProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            expected_metadata_contract,
        } = self;
        let _ = expected_metadata_contract;
        close_new_lifetime_owner(owner)
    }

    #[cfg(test)]
    fn close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
    ) -> NewProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            expected_metadata_contract,
        } = self;
        let _ = expected_metadata_contract;
        close_new_lifetime_owner_using(owner, close)
    }
}

impl ValidatedInitializedNewProductionDatabaseConnection {
    pub(crate) fn close(self) -> NewProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            observed_metadata_contract,
        } = self;
        close_validated_initialized_owner_using(owner, observed_metadata_contract, |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        })
    }

    #[cfg(test)]
    fn close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
    ) -> NewProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            observed_metadata_contract,
        } = self;
        close_validated_initialized_owner_using(owner, observed_metadata_contract, close)
    }
}

impl IntegrityValidatedInitializedNewProductionDatabaseConnection {
    /// Discards the retained metadata contract, then explicitly closes the
    /// unchanged new-database lifetime owner.
    pub(crate) fn close(self) -> NewProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            observed_metadata_contract,
        } = self;
        close_integrity_validated_initialized_owner_using(
            owner,
            observed_metadata_contract,
            |connection| {
                connection
                    .close()
                    .map_err(|(returned_connection, _)| returned_connection)
            },
        )
    }

    #[cfg(test)]
    fn close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
    ) -> NewProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            observed_metadata_contract,
        } = self;
        close_integrity_validated_initialized_owner_using(owner, observed_metadata_contract, close)
    }
}

fn close_integrity_validated_initialized_owner_using<T>(
    owner: NewlyCreatedConnectionLifetimeOwner,
    observed_metadata_contract: T,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> NewProductionDatabaseConnectionCloseOutcome {
    drop(observed_metadata_contract);
    close_new_lifetime_owner_using(owner, close)
}

fn close_validated_initialized_owner_using<T>(
    owner: NewlyCreatedConnectionLifetimeOwner,
    observed_metadata_contract: T,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> NewProductionDatabaseConnectionCloseOutcome {
    drop(observed_metadata_contract);
    close_new_lifetime_owner_using(owner, close)
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

impl NewProductionDatabaseCloseAndPreserveFailure {
    pub(crate) fn retry_close(self) -> NewProductionDatabaseCloseAndPreserveRetryOutcome {
        retry_close_and_preserve_using(
            self,
            |connection| {
                connection
                    .close()
                    .map_err(|(returned_connection, _)| returned_connection)
            },
            drop,
            drop,
        )
    }

    #[cfg(test)]
    fn retry_close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
        release_leaf: impl FnOnce(RetainedEntry),
        release_parent: impl FnOnce(RetainedEntry),
    ) -> NewProductionDatabaseCloseAndPreserveRetryOutcome {
        retry_close_and_preserve_using(self, close, release_leaf, release_parent)
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

impl NewProductionDatabaseInitializationCloseFailure {
    /// Consumes the complete retained lifetime unit and retries only close.
    pub(crate) fn retry_close(self) -> NewProductionDatabaseInitializationCloseRetryOutcome {
        retry_initialization_close_using(self, |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        })
    }

    #[cfg(test)]
    fn retry_close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
    ) -> NewProductionDatabaseInitializationCloseRetryOutcome {
        retry_initialization_close_using(self, close)
    }
}

impl NewProductionDatabaseImmediateValidationCloseFailure {
    /// Consumes the complete retained lifetime unit and retries only close.
    pub(crate) fn retry_close(self) -> NewProductionDatabaseImmediateValidationCloseRetryOutcome {
        retry_immediate_validation_close_using(self, |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        })
    }

    #[cfg(test)]
    fn retry_close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
    ) -> NewProductionDatabaseImmediateValidationCloseRetryOutcome {
        retry_immediate_validation_close_using(self, close)
    }
}

impl NewProductionDatabaseIntegrityValidationCloseFailure {
    /// Consumes the complete retained lifetime unit and retries only close.
    pub(crate) fn retry_close(self) -> NewProductionDatabaseIntegrityValidationCloseRetryOutcome {
        retry_integrity_validation_close_using(self, |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        })
    }

    #[cfg(test)]
    fn retry_close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
    ) -> NewProductionDatabaseIntegrityValidationCloseRetryOutcome {
        retry_integrity_validation_close_using(self, close)
    }
}

/// Consumes the keyed-new owner and establishes only the approved version-1
/// policy, headers, minimal metadata relation, and one canonical metadata row.
#[allow(clippy::too_many_arguments)]
pub(crate) fn initialize_new_production_database(
    connection: NewlyCreatedKeyedProductionDatabaseConnection,
    parish_identifier: ParishIdentifier,
    installation_identifier: InstallationIdentifier,
    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
    setup_publication_identifier: SetupPublicationIdentifier,
    database_created_at: DatabaseCreationTimestamp,
) -> Result<InitializedNewProductionDatabaseConnection, NewProductionDatabaseInitializationError> {
    initialize_new_production_database_using(
        connection,
        parish_identifier,
        installation_identifier,
        database_key_generation_identifier,
        setup_publication_identifier,
        database_created_at,
        |_| Ok(()),
        |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        },
    )
}

/// Consumes the initialized-new owner and validates only its committed headers
/// and canonical metadata against the exact initialization expectation.
pub(crate) fn validate_initialized_new_production_database(
    connection: InitializedNewProductionDatabaseConnection,
) -> Result<
    ValidatedInitializedNewProductionDatabaseConnection,
    NewProductionDatabaseImmediateValidationError,
> {
    validate_initialized_new_production_database_using(
        connection,
        |_| Ok(()),
        |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        },
    )
}

/// Consumes the immediately validated owner and runs only the existing fixed
/// cipher-integrity and SQLite quick-check helper on its same writable keyed
/// connection, outside an explicit transaction.
pub(crate) fn validate_initialized_new_production_database_integrity(
    connection: ValidatedInitializedNewProductionDatabaseConnection,
) -> Result<
    IntegrityValidatedInitializedNewProductionDatabaseConnection,
    NewProductionDatabaseIntegrityValidationError,
> {
    validate_initialized_new_production_database_integrity_using(
        connection,
        super::validate_fixed_readability_and_integrity,
        |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        },
    )
}

/// Consumes the completed create-new validation chain, captures only its
/// historical created-leaf identity, explicitly closes SQLite, and then
/// releases the retained leaf before its retained parent.
pub(crate) fn close_and_preserve_integrity_validated_initialized_new_production_database(
    database: IntegrityValidatedInitializedNewProductionDatabaseConnection,
) -> NewProductionDatabaseCloseAndPreserveOutcome {
    close_and_preserve_integrity_validated_initialized_new_production_database_using(
        database,
        |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        },
        drop,
        drop,
    )
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

#[derive(Clone, Copy, Eq, PartialEq)]
enum InitializationCheckpoint {
    Policy,
    TransactionStart,
    ApplicationId,
    UserVersion,
    MetadataSchema,
    MetadataInsert,
    Commit,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ImmediateValidationCheckpoint {
    TransactionStart,
    TransactionCompletion,
}

#[allow(clippy::too_many_arguments)]
fn initialize_new_production_database_using(
    connection: NewlyCreatedKeyedProductionDatabaseConnection,
    parish_identifier: ParishIdentifier,
    installation_identifier: InstallationIdentifier,
    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
    setup_publication_identifier: SetupPublicationIdentifier,
    database_created_at: DatabaseCreationTimestamp,
    mut checkpoint: impl FnMut(InitializationCheckpoint) -> Result<(), ()>,
    close_on_failure: impl FnOnce(Connection) -> Result<(), Connection>,
) -> Result<InitializedNewProductionDatabaseConnection, NewProductionDatabaseInitializationError> {
    let metadata_contract = DatabaseMetadataContractV1::new(
        PermanentApplicationIdentifier::canonical(),
        parish_identifier,
        installation_identifier,
        InstallationGeneration::INITIAL,
        RecoveryOrReplacementGeneration::INITIAL,
        database_key_generation_identifier,
        setup_publication_identifier,
        database_created_at,
    );
    let database_created_at = match i64::try_from(database_created_at.unix_milliseconds()) {
        Ok(value) => value,
        Err(_) => {
            return finish_initialization_failure(
                connection.owner,
                NewProductionDatabaseInitializationFailure::MetadataRepresentationFailed,
                close_on_failure,
            );
        }
    };

    let mut owner = connection.owner;
    if checkpoint(InitializationCheckpoint::Policy).is_err()
        || establish_and_verify_initialization_policy(&owner.connection).is_err()
    {
        return finish_initialization_failure(
            owner,
            NewProductionDatabaseInitializationFailure::InitializationPolicyFailed,
            close_on_failure,
        );
    }

    let initialization_result = initialize_in_one_transaction(
        &mut owner.connection,
        &metadata_contract,
        database_created_at,
        &mut checkpoint,
    );
    match initialization_result {
        Ok(()) => Ok(InitializedNewProductionDatabaseConnection {
            owner,
            expected_metadata_contract: metadata_contract,
        }),
        Err(category) => finish_initialization_failure(owner, category, close_on_failure),
    }
}

fn validate_initialized_new_production_database_using(
    connection: InitializedNewProductionDatabaseConnection,
    mut checkpoint: impl FnMut(ImmediateValidationCheckpoint) -> Result<(), ()>,
    close_on_failure: impl FnOnce(Connection) -> Result<(), Connection>,
) -> Result<
    ValidatedInitializedNewProductionDatabaseConnection,
    NewProductionDatabaseImmediateValidationError,
> {
    let InitializedNewProductionDatabaseConnection {
        mut owner,
        expected_metadata_contract,
    } = connection;

    let validation_result = validate_initialized_in_one_read_transaction(
        &mut owner.connection,
        &expected_metadata_contract,
        &mut checkpoint,
    );
    match validation_result {
        Ok(observed_metadata_contract) => {
            let _ = expected_metadata_contract;
            Ok(ValidatedInitializedNewProductionDatabaseConnection {
                owner,
                observed_metadata_contract,
            })
        }
        Err(category) => finish_immediate_validation_failure_after_discard_using(
            owner,
            expected_metadata_contract,
            category,
            close_on_failure,
        ),
    }
}

fn validate_initialized_new_production_database_integrity_using(
    connection: ValidatedInitializedNewProductionDatabaseConnection,
    validate: impl FnOnce(&Connection) -> Result<(), ProductionDatabaseValidationError>,
    close_on_failure: impl FnOnce(Connection) -> Result<(), Connection>,
) -> Result<
    IntegrityValidatedInitializedNewProductionDatabaseConnection,
    NewProductionDatabaseIntegrityValidationError,
> {
    let ValidatedInitializedNewProductionDatabaseConnection {
        owner,
        observed_metadata_contract,
    } = connection;
    match validate(&owner.connection) {
        Ok(()) => Ok(
            IntegrityValidatedInitializedNewProductionDatabaseConnection {
                owner,
                observed_metadata_contract,
            },
        ),
        Err(error) => {
            let category = map_integrity_validation_error(error);
            finish_integrity_validation_failure_after_discard_using(
                owner,
                observed_metadata_contract,
                category,
                close_on_failure,
            )
        }
    }
}

fn map_integrity_validation_error(
    error: ProductionDatabaseValidationError,
) -> NewProductionDatabaseIntegrityValidationFailure {
    match error {
        ProductionDatabaseValidationError::EncryptedDatabaseAuthenticationOrCipherIntegrityFailed => {
            NewProductionDatabaseIntegrityValidationFailure::EncryptedDatabaseAuthenticationOrCipherIntegrityFailed
        }
        ProductionDatabaseValidationError::SQLiteReadabilityOrIntegrityFailed => {
            NewProductionDatabaseIntegrityValidationFailure::SQLiteReadabilityOrIntegrityFailed
        }
        ProductionDatabaseValidationError::ValidationUnavailable => {
            NewProductionDatabaseIntegrityValidationFailure::ValidationUnavailable
        }
        ProductionDatabaseValidationError::ValidationInterruptedOrIncomplete => {
            NewProductionDatabaseIntegrityValidationFailure::ValidationInterruptedOrIncomplete
        }
    }
}

fn primary_integrity_validation_error(
    category: NewProductionDatabaseIntegrityValidationFailure,
) -> NewProductionDatabaseIntegrityValidationError {
    match category {
        NewProductionDatabaseIntegrityValidationFailure::EncryptedDatabaseAuthenticationOrCipherIntegrityFailed => {
            NewProductionDatabaseIntegrityValidationError::EncryptedDatabaseAuthenticationOrCipherIntegrityFailed
        }
        NewProductionDatabaseIntegrityValidationFailure::SQLiteReadabilityOrIntegrityFailed => {
            NewProductionDatabaseIntegrityValidationError::SQLiteReadabilityOrIntegrityFailed
        }
        NewProductionDatabaseIntegrityValidationFailure::ValidationUnavailable => {
            NewProductionDatabaseIntegrityValidationError::ValidationUnavailable
        }
        NewProductionDatabaseIntegrityValidationFailure::ValidationInterruptedOrIncomplete => {
            NewProductionDatabaseIntegrityValidationError::ValidationInterruptedOrIncomplete
        }
    }
}

fn validate_initialized_in_one_read_transaction(
    connection: &mut Connection,
    expected_metadata_contract: &DatabaseMetadataContractV1,
    checkpoint: &mut impl FnMut(ImmediateValidationCheckpoint) -> Result<(), ()>,
) -> Result<DatabaseMetadataContractV1, NewProductionDatabaseImmediateValidationFailure> {
    checkpoint(ImmediateValidationCheckpoint::TransactionStart).map_err(|_| {
        NewProductionDatabaseImmediateValidationFailure::ValidationTransactionFailed
    })?;
    let transaction = connection.transaction().map_err(|_| {
        NewProductionDatabaseImmediateValidationFailure::ValidationTransactionFailed
    })?;

    let expected_user_version =
        i32::from(expected_metadata_contract.database_schema_version().get());
    let observed_metadata_contract =
        observe_fixed_metadata_and_headers(&transaction, Some(expected_user_version))
            .map_err(map_immediate_observation_failure)?;
    if observed_metadata_contract != *expected_metadata_contract {
        return Err(NewProductionDatabaseImmediateValidationFailure::MetadataMismatch);
    }

    checkpoint(ImmediateValidationCheckpoint::TransactionCompletion).map_err(|_| {
        NewProductionDatabaseImmediateValidationFailure::ValidationTransactionFailed
    })?;
    transaction.commit().map_err(|_| {
        NewProductionDatabaseImmediateValidationFailure::ValidationTransactionFailed
    })?;
    Ok(observed_metadata_contract)
}

fn map_immediate_observation_failure(
    error: FixedMetadataAndHeaderObservationError,
) -> NewProductionDatabaseImmediateValidationFailure {
    match error {
        FixedMetadataAndHeaderObservationError::HeaderObservationUnavailable => {
            NewProductionDatabaseImmediateValidationFailure::HeaderObservationFailed
        }
        FixedMetadataAndHeaderObservationError::WrongApplicationId
        | FixedMetadataAndHeaderObservationError::UnexpectedUserVersion
        | FixedMetadataAndHeaderObservationError::UserVersionMismatch => {
            NewProductionDatabaseImmediateValidationFailure::HeaderMismatch
        }
        FixedMetadataAndHeaderObservationError::MetadataObservationUnavailable
        | FixedMetadataAndHeaderObservationError::MetadataObservationInterruptedOrIncomplete
        | FixedMetadataAndHeaderObservationError::MetadataRowMissing
        | FixedMetadataAndHeaderObservationError::DuplicateMetadataRows => {
            NewProductionDatabaseImmediateValidationFailure::MetadataObservationFailed
        }
        FixedMetadataAndHeaderObservationError::MalformedMetadata
        | FixedMetadataAndHeaderObservationError::UnsupportedMetadataContractVersion
        | FixedMetadataAndHeaderObservationError::UnsupportedDatabaseSchemaVersion => {
            NewProductionDatabaseImmediateValidationFailure::MetadataMalformed
        }
    }
}

fn establish_and_verify_initialization_policy(connection: &Connection) -> Result<(), ()> {
    connection
        .pragma_update(Some(MAIN_DATABASE_NAME), "journal_mode", "DELETE")
        .map_err(|_| ())?;
    let journal_mode: String = connection
        .pragma_query_value(Some(MAIN_DATABASE_NAME), "journal_mode", |row| row.get(0))
        .map_err(|_| ())?;
    if !journal_mode.eq_ignore_ascii_case("DELETE") {
        return Err(());
    }

    for (name, value) in [
        ("synchronous", 2_i64),
        ("secure_delete", 1),
        ("auto_vacuum", 0),
    ] {
        connection
            .pragma_update(Some(MAIN_DATABASE_NAME), name, value)
            .map_err(|_| ())?;
        let observed: i64 = connection
            .pragma_query_value(Some(MAIN_DATABASE_NAME), name, |row| row.get(0))
            .map_err(|_| ())?;
        if observed != value {
            return Err(());
        }
    }
    Ok(())
}

fn initialize_in_one_transaction(
    connection: &mut Connection,
    metadata_contract: &DatabaseMetadataContractV1,
    database_created_at: i64,
    checkpoint: &mut impl FnMut(InitializationCheckpoint) -> Result<(), ()>,
) -> Result<(), NewProductionDatabaseInitializationFailure> {
    checkpoint(InitializationCheckpoint::TransactionStart).map_err(|_| {
        NewProductionDatabaseInitializationFailure::InitializationTransactionStartFailed
    })?;
    let transaction = connection.transaction().map_err(|_| {
        NewProductionDatabaseInitializationFailure::InitializationTransactionStartFailed
    })?;

    checkpoint(InitializationCheckpoint::ApplicationId)
        .map_err(|_| NewProductionDatabaseInitializationFailure::HeaderInitializationFailed)?;
    transaction
        .pragma_update(
            Some(MAIN_DATABASE_NAME),
            "application_id",
            PRODUCTION_DATABASE_APPLICATION_ID,
        )
        .map_err(|_| NewProductionDatabaseInitializationFailure::HeaderInitializationFailed)?;

    checkpoint(InitializationCheckpoint::UserVersion)
        .map_err(|_| NewProductionDatabaseInitializationFailure::HeaderInitializationFailed)?;
    transaction
        .pragma_update(
            Some(MAIN_DATABASE_NAME),
            "user_version",
            i64::from(metadata_contract.database_schema_version().get()),
        )
        .map_err(|_| NewProductionDatabaseInitializationFailure::HeaderInitializationFailed)?;

    checkpoint(InitializationCheckpoint::MetadataSchema)
        .map_err(|_| NewProductionDatabaseInitializationFailure::MetadataSchemaCreationFailed)?;
    transaction
        .execute(CREATE_METADATA_RELATION, [])
        .map_err(|_| NewProductionDatabaseInitializationFailure::MetadataSchemaCreationFailed)?;

    checkpoint(InitializationCheckpoint::MetadataInsert)
        .map_err(|_| NewProductionDatabaseInitializationFailure::MetadataInsertionFailed)?;
    insert_canonical_metadata_row(&transaction, metadata_contract, database_created_at)?;

    checkpoint(InitializationCheckpoint::Commit)
        .map_err(|_| NewProductionDatabaseInitializationFailure::InitializationCommitFailed)?;
    transaction
        .commit()
        .map_err(|_| NewProductionDatabaseInitializationFailure::InitializationCommitFailed)
}

fn insert_canonical_metadata_row(
    transaction: &Transaction<'_>,
    metadata: &DatabaseMetadataContractV1,
    database_created_at: i64,
) -> Result<(), NewProductionDatabaseInitializationFailure> {
    let mut installation_identifier = [0_u8; 16];
    metadata
        .installation_identifier()
        .write_bytes_into(&mut installation_identifier);
    let mut database_key_generation_identifier = [0_u8; 16];
    metadata
        .database_key_generation_identifier()
        .write_bytes_into(&mut database_key_generation_identifier);
    let mut setup_publication_identifier = [0_u8; 16];
    metadata
        .setup_publication_identifier()
        .write_bytes_into(&mut setup_publication_identifier);
    let installation_generation = metadata.installation_generation().get().to_be_bytes();
    let recovery_replacement_generation = metadata
        .recovery_replacement_generation()
        .get()
        .to_be_bytes();

    let inserted = transaction
        .execute(
            INSERT_METADATA_ROW,
            params![
                i64::from(metadata.singleton_id().get()),
                i64::from(metadata.metadata_contract_version().get()),
                i64::from(metadata.database_schema_version().get()),
                metadata.permanent_application_identifier().as_str(),
                &metadata.database_format_identity().as_bytes()[..],
                &metadata.parish_identifier().as_bytes()[..],
                &installation_identifier[..],
                &installation_generation[..],
                &recovery_replacement_generation[..],
                &database_key_generation_identifier[..],
                &setup_publication_identifier[..],
                database_created_at,
            ],
        )
        .map_err(|_| NewProductionDatabaseInitializationFailure::MetadataInsertionFailed)?;
    if inserted != 1 {
        return Err(NewProductionDatabaseInitializationFailure::MetadataInsertionFailed);
    }
    Ok(())
}

fn primary_initialization_error(
    category: NewProductionDatabaseInitializationFailure,
) -> NewProductionDatabaseInitializationError {
    match category {
        NewProductionDatabaseInitializationFailure::MetadataRepresentationFailed => {
            NewProductionDatabaseInitializationError::MetadataRepresentationFailed
        }
        NewProductionDatabaseInitializationFailure::InitializationPolicyFailed => {
            NewProductionDatabaseInitializationError::InitializationPolicyFailed
        }
        NewProductionDatabaseInitializationFailure::InitializationTransactionStartFailed => {
            NewProductionDatabaseInitializationError::InitializationTransactionStartFailed
        }
        NewProductionDatabaseInitializationFailure::HeaderInitializationFailed => {
            NewProductionDatabaseInitializationError::HeaderInitializationFailed
        }
        NewProductionDatabaseInitializationFailure::MetadataSchemaCreationFailed => {
            NewProductionDatabaseInitializationError::MetadataSchemaCreationFailed
        }
        NewProductionDatabaseInitializationFailure::MetadataInsertionFailed => {
            NewProductionDatabaseInitializationError::MetadataInsertionFailed
        }
        NewProductionDatabaseInitializationFailure::InitializationCommitFailed => {
            NewProductionDatabaseInitializationError::InitializationCommitFailed
        }
    }
}

fn primary_immediate_validation_error(
    category: NewProductionDatabaseImmediateValidationFailure,
) -> NewProductionDatabaseImmediateValidationError {
    match category {
        NewProductionDatabaseImmediateValidationFailure::ValidationTransactionFailed => {
            NewProductionDatabaseImmediateValidationError::ValidationTransactionFailed
        }
        NewProductionDatabaseImmediateValidationFailure::HeaderObservationFailed => {
            NewProductionDatabaseImmediateValidationError::HeaderObservationFailed
        }
        NewProductionDatabaseImmediateValidationFailure::HeaderMismatch => {
            NewProductionDatabaseImmediateValidationError::HeaderMismatch
        }
        NewProductionDatabaseImmediateValidationFailure::MetadataObservationFailed => {
            NewProductionDatabaseImmediateValidationError::MetadataObservationFailed
        }
        NewProductionDatabaseImmediateValidationFailure::MetadataMalformed => {
            NewProductionDatabaseImmediateValidationError::MetadataMalformed
        }
        NewProductionDatabaseImmediateValidationFailure::MetadataMismatch => {
            NewProductionDatabaseImmediateValidationError::MetadataMismatch
        }
    }
}

fn finish_immediate_validation_failure(
    owner: NewlyCreatedConnectionLifetimeOwner,
    category: NewProductionDatabaseImmediateValidationFailure,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> Result<
    ValidatedInitializedNewProductionDatabaseConnection,
    NewProductionDatabaseImmediateValidationError,
> {
    match close_new_lifetime_owner_using(owner, close) {
        NewProductionDatabaseConnectionCloseOutcome::Closed => {
            Err(primary_immediate_validation_error(category))
        }
        NewProductionDatabaseConnectionCloseOutcome::Failed(failure) => Err(
            NewProductionDatabaseImmediateValidationError::ValidationCloseFailed(Box::new(
                NewProductionDatabaseImmediateValidationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )),
        ),
    }
}

fn finish_immediate_validation_failure_after_discard_using<T>(
    owner: NewlyCreatedConnectionLifetimeOwner,
    expected_metadata_contract: T,
    category: NewProductionDatabaseImmediateValidationFailure,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> Result<
    ValidatedInitializedNewProductionDatabaseConnection,
    NewProductionDatabaseImmediateValidationError,
> {
    drop(expected_metadata_contract);
    finish_immediate_validation_failure(owner, category, close)
}

fn retry_immediate_validation_close_using(
    failure: NewProductionDatabaseImmediateValidationCloseFailure,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> NewProductionDatabaseImmediateValidationCloseRetryOutcome {
    let NewProductionDatabaseImmediateValidationCloseFailure { category, owner } = failure;
    match close_new_lifetime_owner_using(owner, close) {
        NewProductionDatabaseConnectionCloseOutcome::Closed => {
            NewProductionDatabaseImmediateValidationCloseRetryOutcome::Closed(
                primary_immediate_validation_error(category),
            )
        }
        NewProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            NewProductionDatabaseImmediateValidationCloseRetryOutcome::Failed(
                NewProductionDatabaseImmediateValidationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

fn finish_integrity_validation_failure(
    owner: NewlyCreatedConnectionLifetimeOwner,
    category: NewProductionDatabaseIntegrityValidationFailure,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> Result<
    IntegrityValidatedInitializedNewProductionDatabaseConnection,
    NewProductionDatabaseIntegrityValidationError,
> {
    match close_new_lifetime_owner_using(owner, close) {
        NewProductionDatabaseConnectionCloseOutcome::Closed => {
            Err(primary_integrity_validation_error(category))
        }
        NewProductionDatabaseConnectionCloseOutcome::Failed(failure) => Err(
            NewProductionDatabaseIntegrityValidationError::IntegrityValidationCloseFailed(
                Box::new(NewProductionDatabaseIntegrityValidationCloseFailure {
                    category,
                    owner: failure.owner,
                }),
            ),
        ),
    }
}

fn finish_integrity_validation_failure_after_discard_using<T>(
    owner: NewlyCreatedConnectionLifetimeOwner,
    observed_metadata_contract: T,
    category: NewProductionDatabaseIntegrityValidationFailure,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> Result<
    IntegrityValidatedInitializedNewProductionDatabaseConnection,
    NewProductionDatabaseIntegrityValidationError,
> {
    drop(observed_metadata_contract);
    finish_integrity_validation_failure(owner, category, close)
}

fn retry_integrity_validation_close_using(
    failure: NewProductionDatabaseIntegrityValidationCloseFailure,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> NewProductionDatabaseIntegrityValidationCloseRetryOutcome {
    let NewProductionDatabaseIntegrityValidationCloseFailure { category, owner } = failure;
    match close_new_lifetime_owner_using(owner, close) {
        NewProductionDatabaseConnectionCloseOutcome::Closed => {
            NewProductionDatabaseIntegrityValidationCloseRetryOutcome::Closed(
                primary_integrity_validation_error(category),
            )
        }
        NewProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            NewProductionDatabaseIntegrityValidationCloseRetryOutcome::Failed(
                NewProductionDatabaseIntegrityValidationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

fn finish_initialization_failure(
    owner: NewlyCreatedConnectionLifetimeOwner,
    category: NewProductionDatabaseInitializationFailure,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> Result<InitializedNewProductionDatabaseConnection, NewProductionDatabaseInitializationError> {
    match close_new_lifetime_owner_using(owner, close) {
        NewProductionDatabaseConnectionCloseOutcome::Closed => {
            Err(primary_initialization_error(category))
        }
        NewProductionDatabaseConnectionCloseOutcome::Failed(failure) => Err(
            NewProductionDatabaseInitializationError::InitializationCloseFailed(Box::new(
                NewProductionDatabaseInitializationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )),
        ),
    }
}

fn retry_initialization_close_using(
    failure: NewProductionDatabaseInitializationCloseFailure,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> NewProductionDatabaseInitializationCloseRetryOutcome {
    let NewProductionDatabaseInitializationCloseFailure { category, owner } = failure;
    match close_new_lifetime_owner_using(owner, close) {
        NewProductionDatabaseConnectionCloseOutcome::Closed => {
            NewProductionDatabaseInitializationCloseRetryOutcome::Closed(
                primary_initialization_error(category),
            )
        }
        NewProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            NewProductionDatabaseInitializationCloseRetryOutcome::Failed(
                NewProductionDatabaseInitializationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
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

fn close_and_preserve_integrity_validated_initialized_new_production_database_using(
    database: IntegrityValidatedInitializedNewProductionDatabaseConnection,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
    release_leaf: impl FnOnce(RetainedEntry),
    release_parent: impl FnOnce(RetainedEntry),
) -> NewProductionDatabaseCloseAndPreserveOutcome {
    let IntegrityValidatedInitializedNewProductionDatabaseConnection {
        owner,
        observed_metadata_contract,
    } = database;
    let identity_proof = SetupDatabaseIdentityProof {
        created_leaf_identity: owner.retained.leaf.initial.identity,
    };
    finish_close_and_preserve_using(
        owner,
        observed_metadata_contract,
        identity_proof,
        close,
        release_leaf,
        release_parent,
    )
}

fn finish_close_and_preserve_using(
    owner: NewlyCreatedConnectionLifetimeOwner,
    observed_metadata_contract: DatabaseMetadataContractV1,
    identity_proof: SetupDatabaseIdentityProof,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
    release_leaf: impl FnOnce(RetainedEntry),
    release_parent: impl FnOnce(RetainedEntry),
) -> NewProductionDatabaseCloseAndPreserveOutcome {
    let NewlyCreatedConnectionLifetimeOwner {
        connection,
        retained,
    } = owner;
    match close(connection) {
        Ok(()) => {
            let RetainedCreatedDatabase { parent, leaf } = retained;
            release_leaf(leaf);
            release_parent(parent);
            NewProductionDatabaseCloseAndPreserveOutcome::Closed(
                ClosedIntegrityValidatedInitializedNewProductionDatabase {
                    observed_metadata_contract,
                    identity_proof,
                },
            )
        }
        Err(connection) => NewProductionDatabaseCloseAndPreserveOutcome::Failed(
            NewProductionDatabaseCloseAndPreserveFailure {
                owner: NewlyCreatedConnectionLifetimeOwner {
                    connection,
                    retained,
                },
                observed_metadata_contract,
                identity_proof,
            },
        ),
    }
}

fn retry_close_and_preserve_using(
    failure: NewProductionDatabaseCloseAndPreserveFailure,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
    release_leaf: impl FnOnce(RetainedEntry),
    release_parent: impl FnOnce(RetainedEntry),
) -> NewProductionDatabaseCloseAndPreserveRetryOutcome {
    let NewProductionDatabaseCloseAndPreserveFailure {
        owner,
        observed_metadata_contract,
        identity_proof,
    } = failure;
    match finish_close_and_preserve_using(
        owner,
        observed_metadata_contract,
        identity_proof,
        close,
        release_leaf,
        release_parent,
    ) {
        NewProductionDatabaseCloseAndPreserveOutcome::Closed(closed) => {
            NewProductionDatabaseCloseAndPreserveRetryOutcome::Closed(closed)
        }
        NewProductionDatabaseCloseAndPreserveOutcome::Failed(failure) => {
            NewProductionDatabaseCloseAndPreserveRetryOutcome::Failed(failure)
        }
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
        cell::{Cell, RefCell},
        fs,
        io::Write,
        mem::{needs_drop, size_of},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{
        database_key_active_wrapper_loader::LoadedActiveDatabaseKeyWrapper,
        database_key_generation::generate_database_key_material,
        database_metadata_decoding::{RawDatabaseMetadataRow, RawDatabaseMetadataValue},
        installation_evidence_contract::{
            PERMANENT_APPLICATION_IDENTIFIER, StructurallyValidatedInstallationEvidence,
            UnvalidatedInstallationEvidenceContract,
        },
        installation_evidence_protection::{
            bind_database_key_candidate_to_trusted_installation_evidence,
            bind_generated_database_key_for_first_time_setup, protect_database_key,
            protect_first_time_setup_database_key_binding,
            recover_database_key_candidate_from_loaded_wrapper,
            trusted_current_installation_evidence_assessment_for_test,
        },
        installation_identifier_generation::generate_installation_identifier,
        installation_state::{
            InstallationEvidence, SetupAuthorizationState, authorize_first_time_setup,
        },
        parish_identifier_generation::generate_parish_identifier,
        production_database_file::{
            ProductionDatabaseInspection, inspect_production_database_file,
        },
        setup_publication_identifier_generation::generate_setup_publication_identifier,
        storage_foundation::{APPLICATION_DATABASE_FORMAT_IDENTITY, production_database_path},
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

    struct RealInitializationFixture {
        owner: NewlyCreatedKeyedProductionDatabaseConnection,
        parish_identifier: ParishIdentifier,
        installation_identifier: InstallationIdentifier,
        database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
        setup_publication_identifier: SetupPublicationIdentifier,
        protected_database_key_wrapper: Vec<u8>,
    }

    fn real_initialization_fixture(root: &TestRoot) -> RealInitializationFixture {
        let authorization = authorization();
        let binding = bind_generated_database_key_for_first_time_setup(
            &authorization,
            generate_database_key_material().expect("OS key randomness should be available"),
            generate_installation_identifier()
                .expect("OS installation identifier randomness should be available"),
        );
        let (key, installation_identifier, database_key_generation_identifier) =
            binding.into_parts();
        let protected_database_key_wrapper = key
            .expose_key(|database_key| {
                protect_database_key(database_key, database_key_generation_identifier)
            })
            .expect("test-owned database key protection should succeed")
            .as_bytes()
            .to_vec();
        let parish_identifier = generate_parish_identifier()
            .expect("OS parish identifier randomness should be available")
            .into_parish_identifier();
        let setup_publication_identifier = generate_setup_publication_identifier()
            .expect("OS setup publication randomness should be available")
            .into_setup_publication_identifier();
        let owner = create_new_keyed_production_database(authorization, root.database_path(), key)
            .expect("real create-new handoff should succeed");
        RealInitializationFixture {
            owner,
            parish_identifier,
            installation_identifier,
            database_key_generation_identifier,
            setup_publication_identifier,
            protected_database_key_wrapper,
        }
    }

    fn initialize_fixture(
        fixture: RealInitializationFixture,
        timestamp: u64,
    ) -> Result<InitializedNewProductionDatabaseConnection, NewProductionDatabaseInitializationError>
    {
        initialize_new_production_database(
            fixture.owner,
            fixture.parish_identifier,
            fixture.installation_identifier,
            fixture.database_key_generation_identifier,
            fixture.setup_publication_identifier,
            DatabaseCreationTimestamp::from_unix_milliseconds(timestamp),
        )
    }

    fn initialized_fixture(root: &TestRoot) -> InitializedNewProductionDatabaseConnection {
        initialize_fixture(real_initialization_fixture(root), 1_798_000_000_123)
            .expect("real initialization should succeed")
    }

    fn validated_initialized_fixture(
        root: &TestRoot,
    ) -> ValidatedInitializedNewProductionDatabaseConnection {
        validate_initialized_new_production_database(initialized_fixture(root))
            .expect("real immediate validation should succeed")
    }

    fn bytes_from_installation_identifier(identifier: InstallationIdentifier) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        identifier.write_bytes_into(&mut bytes);
        bytes
    }

    fn bytes_from_key_generation_identifier(
        identifier: DatabaseKeyGenerationIdentifier,
    ) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        identifier.write_bytes_into(&mut bytes);
        bytes
    }

    fn bytes_from_setup_publication_identifier(identifier: SetupPublicationIdentifier) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        identifier.write_bytes_into(&mut bytes);
        bytes
    }

    fn parish_text(identifier: ParishIdentifier) -> String {
        identifier
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn validated_evidence_for_fixture(
        fixture: &RealInitializationFixture,
    ) -> StructurallyValidatedInstallationEvidence {
        UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            &parish_text(fixture.parish_identifier),
            bytes_from_installation_identifier(fixture.installation_identifier),
            InstallationGeneration::INITIAL.get(),
            RecoveryOrReplacementGeneration::INITIAL.get(),
            bytes_from_key_generation_identifier(fixture.database_key_generation_identifier),
            bytes_from_setup_publication_identifier(fixture.setup_publication_identifier),
            1_798_000_000,
        )
        .validate()
        .expect("matching synthetic evidence should validate")
    }

    fn observed_metadata_contract(connection: &Connection) -> DatabaseMetadataContractV1 {
        use rusqlite::types::Value;

        let values: [Value; 12] = connection
            .query_row(
                "SELECT singleton_id, metadata_contract_version, database_schema_version, permanent_application_identifier, database_format_identity, parish_identifier, installation_identifier, installation_generation, recovery_replacement_generation, database_key_generation_identifier, setup_publication_identifier, database_created_at FROM church_app_database_metadata",
                [],
                |row| Ok(std::array::from_fn(|index| row.get(index).unwrap())),
            )
            .expect("exact metadata row should be readable in the test");
        fn raw(value: &Value) -> RawDatabaseMetadataValue<'_> {
            match value {
                Value::Null => RawDatabaseMetadataValue::Null,
                Value::Integer(value) => RawDatabaseMetadataValue::Integer(*value),
                Value::Real(_) => panic!("canonical metadata never stores REAL values"),
                Value::Text(value) => RawDatabaseMetadataValue::Text(value),
                Value::Blob(value) => RawDatabaseMetadataValue::Blob(value),
            }
        }
        RawDatabaseMetadataRow::new(
            raw(&values[0]),
            raw(&values[1]),
            raw(&values[2]),
            raw(&values[3]),
            raw(&values[4]),
            raw(&values[5]),
            raw(&values[6]),
            raw(&values[7]),
            raw(&values[8]),
            raw(&values[9]),
            raw(&values[10]),
            raw(&values[11]),
        )
        .parse()
        .expect("stored row should use the canonical parse representation")
        .validate_structure()
        .expect("stored row should satisfy the existing structural validator")
    }

    fn assert_no_committed_initialization(connection: &Connection) {
        assert_eq!(
            connection
                .pragma_query_value::<i64, _>(Some(MAIN_DATABASE_NAME), "application_id", |row| {
                    row.get(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .pragma_query_value::<i64, _>(Some(MAIN_DATABASE_NAME), "user_version", |row| {
                    row.get(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name = 'church_app_database_metadata'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
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
            "cipher_integrity_check",
            "quick_check",
            "remove_file",
            "rename(",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
        let create_transition = production
            .split_once("pub(crate) fn create_new_keyed_production_database(")
            .unwrap()
            .1
            .split_once("#[derive(Clone, Copy, Eq, PartialEq)]\nenum InitializationCheckpoint")
            .unwrap()
            .0;
        for forbidden in [
            "application_id",
            "user_version",
            "CREATE TABLE",
            "INSERT",
            "UPDATE",
            "DELETE",
            "VACUUM",
            "pragma_update",
            "pragma_query",
            "query_only",
        ] {
            assert!(
                !create_transition.contains(forbidden),
                "create-new transition unexpectedly initializes: {forbidden}"
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

    #[test]
    fn initialize_new_production_database_api_owner_and_source_scope_are_locked() {
        const SOURCE: &str = include_str!("create_new_database.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        let signature = "pub(crate) fn initialize_new_production_database(\n    connection: NewlyCreatedKeyedProductionDatabaseConnection,\n    parish_identifier: ParishIdentifier,\n    installation_identifier: InstallationIdentifier,\n    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,\n    setup_publication_identifier: SetupPublicationIdentifier,\n    database_created_at: DatabaseCreationTimestamp,\n) -> Result<InitializedNewProductionDatabaseConnection, NewProductionDatabaseInitializationError>";
        assert!(production.contains(signature));
        assert!(needs_drop::<InitializedNewProductionDatabaseConnection>());
        assert!(size_of::<InitializedNewProductionDatabaseConnection>() > size_of::<Connection>());
        let owner = production
            .split_once("pub(crate) struct InitializedNewProductionDatabaseConnection {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(owner.lines().filter(|line| line.contains(':')).count(), 2);
        assert!(owner.contains("owner: NewlyCreatedConnectionLifetimeOwner"));
        assert!(owner.contains("expected_metadata_contract: DatabaseMetadataContractV1"));
        assert!(!owner.contains("pub"));
        for forbidden in [
            "impl Clone for InitializedNewProductionDatabaseConnection",
            "impl Copy for InitializedNewProductionDatabaseConnection",
            "Serialize",
            "Deserialize",
            "impl Deref",
            "AsRef<Connection>",
            "pub connection:",
            "pub(crate) connection:",
            "with_connection",
            "unchecked_transaction",
            "cipher_integrity_check",
            "quick_check",
            "remove_file",
            "rename(",
            "CREATE INDEX",
            "CREATE TRIGGER",
            "CREATE VIEW",
            "migrations",
            "tauri::command",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden initializer capability: {forbidden}"
            );
        }
        assert_eq!(
            production.matches("const CREATE_METADATA_RELATION").count(),
            1
        );
        assert_eq!(production.matches("const INSERT_METADATA_ROW").count(), 1);
        for forbidden in [
            " NOT NULL",
            " PRIMARY KEY",
            " UNIQUE",
            " CHECK",
            " STRICT",
            " WITHOUT ROWID",
        ] {
            assert!(!CREATE_METADATA_RELATION.contains(forbidden));
        }
        assert_eq!(CREATE_METADATA_RELATION.matches(',').count(), 11);
        assert_eq!(INSERT_METADATA_ROW.matches('?').count(), 12);
        assert_eq!(INSERT_METADATA_ROW.matches("INSERT INTO").count(), 1);
    }

    #[test]
    fn initialize_new_production_database_timestamp_bounds_precede_sql_mutation() {
        let root = TestRoot::create();
        let fixture = real_initialization_fixture(&root);
        let result = initialize_new_production_database_using(
            fixture.owner,
            fixture.parish_identifier,
            fixture.installation_identifier,
            fixture.database_key_generation_identifier,
            fixture.setup_publication_identifier,
            DatabaseCreationTimestamp::from_unix_milliseconds(i64::MAX as u64 + 1),
            |_| panic!("no SQL checkpoint may run after failed representation conversion"),
            Err,
        );
        let Err(NewProductionDatabaseInitializationError::InitializationCloseFailed(failure)) =
            result
        else {
            panic!("injected close failure must retain the representation failure owner")
        };
        assert_no_committed_initialization(&failure.owner.connection);
        assert!(matches!(
            failure.retry_close(),
            NewProductionDatabaseInitializationCloseRetryOutcome::Closed(
                NewProductionDatabaseInitializationError::MetadataRepresentationFailed
            )
        ));
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();

        let root = TestRoot::create();
        let initialized = initialize_fixture(real_initialization_fixture(&root), i64::MAX as u64)
            .expect("largest SQLite-compatible timestamp should initialize");
        assert_eq!(
            observed_metadata_contract(&initialized.owner.connection)
                .database_created_at()
                .unix_milliseconds(),
            i64::MAX as u64
        );
        assert!(matches!(
            initialized.close(),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn initialize_new_production_database_policy_contract_storage_and_headers_are_exact() {
        let root = TestRoot::create();
        let fixture = real_initialization_fixture(&root);
        let expected = DatabaseMetadataContractV1::new(
            PermanentApplicationIdentifier::canonical(),
            fixture.parish_identifier,
            fixture.installation_identifier,
            InstallationGeneration::INITIAL,
            RecoveryOrReplacementGeneration::INITIAL,
            fixture.database_key_generation_identifier,
            fixture.setup_publication_identifier,
            DatabaseCreationTimestamp::from_unix_milliseconds(1_798_000_000_123),
        );
        let initialized = initialize_fixture(fixture, 1_798_000_000_123)
            .expect("real SQLCipher initialization should succeed");
        let connection = &initialized.owner.connection;
        let journal_mode: String = connection
            .pragma_query_value(Some(MAIN_DATABASE_NAME), "journal_mode", |row| row.get(0))
            .unwrap();
        assert!(journal_mode.eq_ignore_ascii_case("DELETE"));
        for (name, expected) in [
            ("synchronous", 2_i64),
            ("secure_delete", 1),
            ("auto_vacuum", 0),
            ("query_only", 0),
        ] {
            assert_eq!(
                connection
                    .pragma_query_value::<i64, _>(Some(MAIN_DATABASE_NAME), name, |row| row.get(0))
                    .unwrap(),
                expected
            );
        }
        assert_eq!(
            connection
                .pragma_query_value::<i64, _>(Some(MAIN_DATABASE_NAME), "application_id", |row| row
                    .get(0))
                .unwrap(),
            i64::from(PRODUCTION_DATABASE_APPLICATION_ID)
        );
        assert_eq!(
            connection
                .pragma_query_value::<i64, _>(Some(MAIN_DATABASE_NAME), "user_version", |row| row
                    .get(0))
                .unwrap(),
            1
        );
        assert_eq!(observed_metadata_contract(connection), expected);
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM church_app_database_metadata",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM sqlite_master", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let storage: (String, String, String, String, i64, i64, i64, i64, i64, i64, i64, i64) = connection
            .query_row(
                "SELECT typeof(singleton_id), typeof(permanent_application_identifier), typeof(database_format_identity), typeof(installation_generation), length(database_format_identity), length(parish_identifier), length(installation_identifier), length(installation_generation), length(recovery_replacement_generation), length(database_key_generation_identifier), length(setup_publication_identifier), database_created_at FROM church_app_database_metadata",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?)),
            )
            .unwrap();
        assert_eq!(&storage.0, "integer");
        assert_eq!(&storage.1, "text");
        assert_eq!(&storage.2, "blob");
        assert_eq!(&storage.3, "blob");
        assert_eq!((storage.4, storage.5, storage.6), (16, 16, 16));
        assert_eq!((storage.7, storage.8), (8, 8));
        assert_eq!((storage.9, storage.10), (16, 16));
        assert_eq!(storage.11, 1_798_000_000_123_i64);
        let generations: (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT installation_generation, recovery_replacement_generation FROM church_app_database_metadata",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            generations.0,
            InstallationGeneration::INITIAL.get().to_be_bytes()
        );
        assert_eq!(
            generations.1,
            RecoveryOrReplacementGeneration::INITIAL.get().to_be_bytes()
        );
        assert_eq!(
            format!("{initialized:?}"),
            "InitializedNewProductionDatabaseConnection([REDACTED])"
        );
        assert!(matches!(
            initialized.close(),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn initialize_new_production_database_transaction_failures_roll_back_and_close() {
        for checkpoint in [
            InitializationCheckpoint::TransactionStart,
            InitializationCheckpoint::ApplicationId,
            InitializationCheckpoint::UserVersion,
            InitializationCheckpoint::MetadataSchema,
            InitializationCheckpoint::MetadataInsert,
            InitializationCheckpoint::Commit,
        ] {
            let root = TestRoot::create();
            let fixture = real_initialization_fixture(&root);
            let result = initialize_new_production_database_using(
                fixture.owner,
                fixture.parish_identifier,
                fixture.installation_identifier,
                fixture.database_key_generation_identifier,
                fixture.setup_publication_identifier,
                DatabaseCreationTimestamp::from_unix_milliseconds(1_798_000_000_123),
                |observed| {
                    if observed == checkpoint {
                        Err(())
                    } else {
                        Ok(())
                    }
                },
                Err,
            );
            let Err(NewProductionDatabaseInitializationError::InitializationCloseFailed(failure)) =
                result
            else {
                panic!("injected stage and close failure must retain ownership")
            };
            assert_no_committed_initialization(&failure.owner.connection);
            let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
            assert!(database.is_file());
            assert!(fs::remove_file(&database).is_err());
            assert!(matches!(
                failure.retry_close(),
                NewProductionDatabaseInitializationCloseRetryOutcome::Closed(_)
            ));
            assert!(database.is_file());
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn initialize_new_production_database_failure_close_retry_is_close_only() {
        let root = TestRoot::create();
        let fixture = real_initialization_fixture(&root);
        let checkpoint_calls = Cell::new(0);
        let result = initialize_new_production_database_using(
            fixture.owner,
            fixture.parish_identifier,
            fixture.installation_identifier,
            fixture.database_key_generation_identifier,
            fixture.setup_publication_identifier,
            DatabaseCreationTimestamp::from_unix_milliseconds(1_798_000_000_123),
            |checkpoint| {
                checkpoint_calls.set(checkpoint_calls.get() + 1);
                if checkpoint == InitializationCheckpoint::MetadataInsert {
                    Err(())
                } else {
                    Ok(())
                }
            },
            Err,
        );
        let Err(NewProductionDatabaseInitializationError::InitializationCloseFailed(failure)) =
            result
        else {
            panic!("injected close failure should retain initialization ownership")
        };
        let calls_after_initialization = checkpoint_calls.get();
        assert_eq!(
            format!("{failure:?}"),
            "NewProductionDatabaseInitializationCloseFailure([REDACTED])"
        );
        let NewProductionDatabaseInitializationCloseRetryOutcome::Failed(failure) =
            failure.retry_close_using(Err)
        else {
            panic!("repeated close failure should retain ownership")
        };
        assert_eq!(checkpoint_calls.get(), calls_after_initialization);
        assert!(matches!(
            failure.retry_close(),
            NewProductionDatabaseInitializationCloseRetryOutcome::Closed(
                NewProductionDatabaseInitializationError::MetadataInsertionFailed
            )
        ));
        assert_eq!(checkpoint_calls.get(), calls_after_initialization);
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn initialize_new_production_database_success_owner_close_retry_is_close_only() {
        let root = TestRoot::create();
        let initialized = initialize_fixture(real_initialization_fixture(&root), 1_798_000_000_123)
            .expect("initialization should succeed");
        let NewProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            initialized.close_using(Err)
        else {
            panic!("injected success-owner close failure should retain ownership")
        };
        let NewProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            failure.retry_close_using(Err)
        else {
            panic!("repeated close failure should remain retryable")
        };
        assert!(matches!(
            failure.retry_close(),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn initialize_new_production_database_real_reopen_wrong_key_and_encryption_regression() {
        let root = TestRoot::create();
        let fixture = real_initialization_fixture(&root);
        let evidence = validated_evidence_for_fixture(&fixture);
        let protected_wrapper = fixture.protected_database_key_wrapper.clone();
        let initialized = initialize_new_production_database(
            fixture.owner,
            fixture.parish_identifier,
            fixture.installation_identifier,
            fixture.database_key_generation_identifier,
            fixture.setup_publication_identifier,
            DatabaseCreationTimestamp::from_unix_milliseconds(1_798_000_000_123),
        )
        .expect("create-to-initialize production transition should succeed");
        assert!(matches!(
            initialized.close(),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
        assert!(database.is_file());
        for entry in fs::read_dir(root.path()).unwrap() {
            let entry = entry.unwrap();
            let bytes = fs::read(entry.path()).unwrap();
            assert!(
                !bytes
                    .windows(b"SQLite format 3\0".len())
                    .any(|window| window == b"SQLite format 3\0")
            );
            assert!(
                !bytes
                    .windows(PERMANENT_APPLICATION_IDENTIFIER.len())
                    .any(|window| window == PERMANENT_APPLICATION_IDENTIFIER.as_bytes())
            );
        }

        let loaded =
            LoadedActiveDatabaseKeyWrapper::from_synthetic_wrapper_bytes(protected_wrapper);
        let candidate = recover_database_key_candidate_from_loaded_wrapper(&loaded).unwrap();
        let assessment = trusted_current_installation_evidence_assessment_for_test(evidence);
        let correct_key =
            bind_database_key_candidate_to_trusted_installation_evidence(candidate, &assessment)
                .unwrap();
        let inspected = match inspect_production_database_file(&root.database_path()) {
            ProductionDatabaseInspection::Present(inspected) => inspected,
            other => panic!("initialized test database should inspect as present: {other:?}"),
        };
        let read_only = super::super::open_keyed_production_database_read_only(
            root.database_path(),
            inspected,
            correct_key,
        )
        .expect("correct-key guarded read-only open should succeed");
        let validated =
            match super::super::validate_production_database_readability_and_integrity(read_only) {
                super::super::ProductionDatabaseValidationOutcome::Validated(owner) => owner,
                other => panic!("correct key should pass readability validation: {other:?}"),
            };
        let live =
            match super::super::validate_production_database_live_metadata_and_headers(validated) {
                super::super::LiveMetadataAndHeaderValidationOutcome::Validated(owner) => owner,
                other => panic!("initialized headers and metadata should validate: {other:?}"),
            };
        assert!(matches!(
            live.close(),
            super::super::ProductionDatabaseConnectionCloseOutcome::Closed
        ));

        let wrong_authorization = authorization();
        let wrong_key = setup_key(&wrong_authorization);
        let inspected = match inspect_production_database_file(&root.database_path()) {
            ProductionDatabaseInspection::Present(inspected) => inspected,
            other => panic!("database should remain inspectable: {other:?}"),
        };
        let wrong_read_only = super::super::open_keyed_production_database_read_only(
            root.database_path(),
            inspected,
            wrong_key,
        )
        .expect("key submission alone does not validate correctness");
        assert!(matches!(
            super::super::validate_production_database_readability_and_integrity(wrong_read_only),
            super::super::ProductionDatabaseValidationOutcome::Failed(
                super::super::ProductionDatabaseValidationError::EncryptedDatabaseAuthenticationOrCipherIntegrityFailed
            )
        ));
        assert!(database.is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn immediate_validation_api_owners_authority_and_shared_observer_are_locked() {
        const SOURCE: &str = include_str!("create_new_database.rs");
        const OBSERVER: &str = include_str!("fixed_metadata_and_header_observation.rs");
        const PARENT: &str = include_str!("../production_database_connection_handoff.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        let signature = "pub(crate) fn validate_initialized_new_production_database(\n    connection: InitializedNewProductionDatabaseConnection,\n) -> Result<\n    ValidatedInitializedNewProductionDatabaseConnection,\n    NewProductionDatabaseImmediateValidationError,\n>";
        assert!(production.contains(signature));
        assert!(needs_drop::<
            ValidatedInitializedNewProductionDatabaseConnection,
        >());

        let initialized = production
            .split_once("pub(crate) struct InitializedNewProductionDatabaseConnection {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(
            initialized
                .lines()
                .filter(|line| line.contains(':'))
                .count(),
            2
        );
        assert!(initialized.contains("owner: NewlyCreatedConnectionLifetimeOwner"));
        assert!(initialized.contains("expected_metadata_contract: DatabaseMetadataContractV1"));

        let validated = production
            .split_once("pub(crate) struct ValidatedInitializedNewProductionDatabaseConnection {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(
            validated.lines().filter(|line| line.contains(':')).count(),
            2
        );
        assert!(validated.contains("owner: NewlyCreatedConnectionLifetimeOwner"));
        assert!(validated.contains("observed_metadata_contract: DatabaseMetadataContractV1"));
        assert!(PARENT.contains("mod fixed_metadata_and_header_observation;"));
        assert!(!PARENT.contains("pub mod fixed_metadata_and_header_observation;"));
        assert_eq!(OBSERVER.matches("LIMIT 2").count(), 1);
        assert_eq!(OBSERVER.matches("RawDatabaseMetadataRow::new(").count(), 1);
        assert_eq!(OBSERVER.matches(".parse()").count(), 1);
        assert_eq!(OBSERVER.matches(".validate_structure()").count(), 1);

        for forbidden in [
            "impl Clone for ValidatedInitializedNewProductionDatabaseConnection",
            "impl Copy for ValidatedInitializedNewProductionDatabaseConnection",
            "Serialize",
            "Deserialize",
            "impl Deref",
            "AsRef<Connection>",
            "with_connection",
            "unchecked_transaction",
            "cipher_integrity_check",
            "quick_check",
            "ProductionDatabaseValidationOutcome",
            "validate_production_database_readability_and_integrity",
            "construct_database_metadata_correspondence",
            "classify_database_freshness",
            "publish_setup",
            "complete_setup",
            "authorize_production_database_startup",
            "activate_production_database_for_operational_use",
            "remove_file",
            "rename(",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden setup validation capability: {forbidden}"
            );
        }
    }

    #[test]
    fn immediate_validation_real_windows_sqlcipher_flow_preserves_exact_owner_and_leaves_file() {
        let root = TestRoot::create();
        let initialized = initialized_fixture(&root);
        let expected = initialized.expected_metadata_contract;
        let sqlite_handle = unsafe { initialized.owner.connection.handle() };
        let parent_handle = initialized.owner.retained.parent.handle.as_raw_handle();
        let leaf_handle = initialized.owner.retained.leaf.handle.as_raw_handle();

        let validated = validate_initialized_new_production_database(initialized)
            .expect("immediate validation should succeed");
        assert_eq!(validated.observed_metadata_contract, expected);
        assert_eq!(
            unsafe { validated.owner.connection.handle() },
            sqlite_handle
        );
        assert_eq!(
            validated.owner.retained.parent.handle.as_raw_handle(),
            parent_handle
        );
        assert_eq!(
            validated.owner.retained.leaf.handle.as_raw_handle(),
            leaf_handle
        );
        assert_eq!(
            format!("{validated:?}"),
            "ValidatedInitializedNewProductionDatabaseConnection([REDACTED])"
        );
        assert!(matches!(
            validated.close(),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn immediate_validation_header_failures_are_coarse_and_leave_database() {
        for (sql, expected) in [
            (
                "PRAGMA main.application_id = 1",
                NewProductionDatabaseImmediateValidationError::HeaderMismatch,
            ),
            (
                "PRAGMA main.user_version = 2",
                NewProductionDatabaseImmediateValidationError::HeaderMismatch,
            ),
        ] {
            let root = TestRoot::create();
            let initialized = initialized_fixture(&root);
            initialized.owner.connection.execute_batch(sql).unwrap();
            let error = validate_initialized_new_production_database(initialized).unwrap_err();
            assert_eq!(format!("{error:?}"), format!("{expected:?}"));
            assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
            root.assert_exact_cleanup();
        }

        for (internal, expected) in [
            (
                FixedMetadataAndHeaderObservationError::HeaderObservationUnavailable,
                NewProductionDatabaseImmediateValidationFailure::HeaderObservationFailed,
            ),
            (
                FixedMetadataAndHeaderObservationError::UserVersionMismatch,
                NewProductionDatabaseImmediateValidationFailure::HeaderMismatch,
            ),
        ] {
            assert!(map_immediate_observation_failure(internal) == expected);
        }
    }

    #[test]
    fn immediate_validation_metadata_observation_and_malformed_families_are_coarse() {
        for (sql, expected) in [
            (
                "DROP TABLE church_app_database_metadata",
                "MetadataObservationFailed",
            ),
            (
                "DELETE FROM church_app_database_metadata",
                "MetadataObservationFailed",
            ),
            (
                "INSERT INTO church_app_database_metadata SELECT * FROM church_app_database_metadata",
                "MetadataObservationFailed",
            ),
            (
                "UPDATE church_app_database_metadata SET singleton_id = 1.5",
                "MetadataMalformed",
            ),
            (
                "UPDATE church_app_database_metadata SET permanent_application_identifier = CAST(X'80' AS TEXT)",
                "MetadataMalformed",
            ),
            (
                "UPDATE church_app_database_metadata SET installation_identifier = X'01'",
                "MetadataMalformed",
            ),
            (
                "UPDATE church_app_database_metadata SET database_created_at = -1",
                "MetadataMalformed",
            ),
            (
                "UPDATE church_app_database_metadata SET metadata_contract_version = 2",
                "MetadataMalformed",
            ),
            (
                "UPDATE church_app_database_metadata SET database_schema_version = 2",
                "MetadataMalformed",
            ),
            (
                "UPDATE church_app_database_metadata SET installation_identifier = zeroblob(16)",
                "MetadataMalformed",
            ),
        ] {
            let root = TestRoot::create();
            let initialized = initialized_fixture(&root);
            initialized.owner.connection.execute_batch(sql).unwrap();
            let error = validate_initialized_new_production_database(initialized).unwrap_err();
            assert_eq!(format!("{error:?}"), expected);
            assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn immediate_validation_valid_but_different_metadata_is_exact_mismatch() {
        for sql in [
            "UPDATE church_app_database_metadata SET parish_identifier = X'11111111111111111111111111111111'",
            "UPDATE church_app_database_metadata SET installation_identifier = X'11111111111111111111111111111111'",
            "UPDATE church_app_database_metadata SET installation_generation = X'0000000000000002'",
            "UPDATE church_app_database_metadata SET recovery_replacement_generation = X'0000000000000002'",
            "UPDATE church_app_database_metadata SET database_key_generation_identifier = X'22222222222222222222222222222222'",
            "UPDATE church_app_database_metadata SET setup_publication_identifier = X'33333333333333333333333333333333'",
            "UPDATE church_app_database_metadata SET database_created_at = database_created_at + 1",
        ] {
            let root = TestRoot::create();
            let initialized = initialized_fixture(&root);
            initialized.owner.connection.execute_batch(sql).unwrap();
            assert!(matches!(
                validate_initialized_new_production_database(initialized),
                Err(NewProductionDatabaseImmediateValidationError::MetadataMismatch)
            ));
            assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn immediate_validation_transaction_checkpoints_fail_without_success_authority() {
        for failed_checkpoint in [
            ImmediateValidationCheckpoint::TransactionStart,
            ImmediateValidationCheckpoint::TransactionCompletion,
        ] {
            let root = TestRoot::create();
            let initialized = initialized_fixture(&root);
            let checkpoints = Cell::new(0_u8);
            let result = validate_initialized_new_production_database_using(
                initialized,
                |checkpoint| {
                    checkpoints.set(checkpoints.get() + 1);
                    if checkpoint == failed_checkpoint {
                        Err(())
                    } else {
                        Ok(())
                    }
                },
                |connection| connection.close().map_err(|(connection, _)| connection),
            );
            assert!(matches!(
                result,
                Err(NewProductionDatabaseImmediateValidationError::ValidationTransactionFailed)
            ));
            assert_eq!(
                checkpoints.get(),
                if failed_checkpoint == ImmediateValidationCheckpoint::TransactionStart {
                    1
                } else {
                    2
                }
            );
            assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn immediate_validation_failure_close_retry_preserves_every_category_and_retries_only_close() {
        for category in [
            NewProductionDatabaseImmediateValidationFailure::ValidationTransactionFailed,
            NewProductionDatabaseImmediateValidationFailure::HeaderObservationFailed,
            NewProductionDatabaseImmediateValidationFailure::HeaderMismatch,
            NewProductionDatabaseImmediateValidationFailure::MetadataObservationFailed,
            NewProductionDatabaseImmediateValidationFailure::MetadataMalformed,
            NewProductionDatabaseImmediateValidationFailure::MetadataMismatch,
        ] {
            let root = TestRoot::create();
            let result =
                finish_immediate_validation_failure(unkeyed_open_owner(&root), category, Err);
            let Err(NewProductionDatabaseImmediateValidationError::ValidationCloseFailed(failure)) =
                result
            else {
                panic!("injected close failure must retain validation ownership");
            };
            assert_eq!(
                format!("{failure:?}"),
                "NewProductionDatabaseImmediateValidationCloseFailure([REDACTED])"
            );
            let NewProductionDatabaseImmediateValidationCloseRetryOutcome::Failed(failure) =
                failure.retry_close_using(Err)
            else {
                panic!("repeated close failure must remain retryable");
            };
            let NewProductionDatabaseImmediateValidationCloseRetryOutcome::Closed(error) =
                failure.retry_close()
            else {
                panic!("eventual close must return the original category");
            };
            assert_eq!(
                format!("{error:?}"),
                format!("{:?}", primary_immediate_validation_error(category))
            );
            assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn immediate_validation_every_primary_category_closes_successfully_and_returns_it() {
        for category in [
            NewProductionDatabaseImmediateValidationFailure::ValidationTransactionFailed,
            NewProductionDatabaseImmediateValidationFailure::HeaderObservationFailed,
            NewProductionDatabaseImmediateValidationFailure::HeaderMismatch,
            NewProductionDatabaseImmediateValidationFailure::MetadataObservationFailed,
            NewProductionDatabaseImmediateValidationFailure::MetadataMalformed,
            NewProductionDatabaseImmediateValidationFailure::MetadataMismatch,
        ] {
            let root = TestRoot::create();
            let result = finish_immediate_validation_failure(
                unkeyed_open_owner(&root),
                category,
                |connection| {
                    drop(connection);
                    Ok(())
                },
            );
            let error = result.expect_err("successful close must return the primary category");
            assert_eq!(
                format!("{error:?}"),
                format!("{:?}", primary_immediate_validation_error(category))
            );
            assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn immediate_validation_failure_discards_expected_contract_before_close_attempt() {
        struct DropProbe<'a>(&'a Cell<bool>);
        impl Drop for DropProbe<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let root = TestRoot::create();
        let expected_dropped = Cell::new(false);
        let close_called = Cell::new(false);
        let result = finish_immediate_validation_failure_after_discard_using(
            unkeyed_open_owner(&root),
            DropProbe(&expected_dropped),
            NewProductionDatabaseImmediateValidationFailure::MetadataMismatch,
            |connection| {
                assert!(expected_dropped.get());
                close_called.set(true);
                drop(connection);
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(NewProductionDatabaseImmediateValidationError::MetadataMismatch)
        ));
        assert!(expected_dropped.get());
        assert!(close_called.get());
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn immediate_validation_success_owner_close_failure_retains_only_lifetime_for_retry() {
        let root = TestRoot::create();
        let validated = validate_initialized_new_production_database(initialized_fixture(&root))
            .expect("canonical validation should succeed");
        let NewProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            validated.close_using(Err)
        else {
            panic!("injected validated-owner close must retain lifetime ownership");
        };
        let NewProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            failure.retry_close_using(Err)
        else {
            panic!("repeated close failure must remain retryable");
        };
        assert!(matches!(
            failure.retry_close(),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn immediate_validation_success_owner_discards_metadata_before_close_attempt() {
        struct DropProbe<'a>(&'a Cell<bool>);
        impl Drop for DropProbe<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let root = TestRoot::create();
        let metadata_dropped = Cell::new(false);
        let close_called = Cell::new(false);
        let outcome = close_validated_initialized_owner_using(
            unkeyed_open_owner(&root),
            DropProbe(&metadata_dropped),
            |connection| {
                assert!(metadata_dropped.get());
                close_called.set(true);
                drop(connection);
                Ok(())
            },
        );
        assert!(metadata_dropped.get());
        assert!(close_called.get());
        assert!(matches!(
            outcome,
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn setup_integrity_api_owner_shared_helper_and_authority_surface_are_locked() {
        const SOURCE: &str = include_str!("create_new_database.rs");
        const PARENT: &str = include_str!("../production_database_connection_handoff.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        let parent_production = PARENT.split("#[cfg(test)]\nmod tests").next().unwrap();
        let signature = "pub(crate) fn validate_initialized_new_production_database_integrity(\n    connection: ValidatedInitializedNewProductionDatabaseConnection,\n) -> Result<\n    IntegrityValidatedInitializedNewProductionDatabaseConnection,\n    NewProductionDatabaseIntegrityValidationError,\n>";
        assert!(production.contains(signature));
        assert!(needs_drop::<
            IntegrityValidatedInitializedNewProductionDatabaseConnection,
        >());

        let owner = production
            .split_once(
                "pub(crate) struct IntegrityValidatedInitializedNewProductionDatabaseConnection {",
            )
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(owner.lines().filter(|line| line.contains(':')).count(), 2);
        assert!(owner.contains("owner: NewlyCreatedConnectionLifetimeOwner"));
        assert!(owner.contains("observed_metadata_contract: DatabaseMetadataContractV1"));

        let transition = production
            .split_once(signature)
            .unwrap()
            .1
            .split_once("/// Consumes first-time setup authority")
            .unwrap()
            .0;
        assert!(transition.contains("super::validate_fixed_readability_and_integrity"));
        assert_eq!(
            production.matches("PRAGMA cipher_integrity_check").count(),
            0
        );
        assert_eq!(production.matches("PRAGMA main.quick_check(1)").count(), 0);
        assert_eq!(
            parent_production
                .matches("PRAGMA cipher_integrity_check")
                .count(),
            1
        );
        assert_eq!(
            parent_production
                .matches("PRAGMA main.quick_check(1)")
                .count(),
            1
        );

        for forbidden in [
            "impl Clone for IntegrityValidatedInitializedNewProductionDatabaseConnection",
            "impl Copy for IntegrityValidatedInitializedNewProductionDatabaseConnection",
            "Serialize",
            "Deserialize",
            "impl Deref",
            "AsRef<Connection>",
            "with_connection",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden owner surface: {forbidden}"
            );
        }
        for forbidden in [
            "Connection::open",
            "ProductionDatabasePath",
            "GenerationBoundDatabaseKey",
            ".transaction(",
            "unchecked_transaction",
            "BEGIN",
            "COMMIT",
            "query_only",
            "application_id",
            "user_version",
            "observe_fixed_metadata_and_headers",
            "establish_and_verify_initialization_policy",
            "evidence",
            "freshness",
            "correspondence",
            "publication",
            "complete_setup",
            "authorize_production_database_startup",
            "activate_production_database_for_operational_use",
            "recovery",
            "cleanup",
            "remove_file",
            "rename(",
        ] {
            assert!(
                !transition.contains(forbidden),
                "forbidden integrity-transition capability: {forbidden}"
            );
        }
    }

    #[test]
    fn setup_integrity_real_windows_sqlcipher_flow_preserves_owner_metadata_and_file() {
        let root = TestRoot::create();
        let validated = validated_initialized_fixture(&root);
        let expected = validated.observed_metadata_contract;
        let sqlite_handle = unsafe { validated.owner.connection.handle() };
        let parent_handle = validated.owner.retained.parent.handle.as_raw_handle();
        let leaf_handle = validated.owner.retained.leaf.handle.as_raw_handle();

        let integrity_validated = validate_initialized_new_production_database_integrity(validated)
            .expect("fixed setup integrity validation should succeed");
        assert_eq!(integrity_validated.observed_metadata_contract, expected);
        assert_eq!(
            unsafe { integrity_validated.owner.connection.handle() },
            sqlite_handle
        );
        assert_eq!(
            integrity_validated
                .owner
                .retained
                .parent
                .handle
                .as_raw_handle(),
            parent_handle
        );
        assert_eq!(
            integrity_validated
                .owner
                .retained
                .leaf
                .handle
                .as_raw_handle(),
            leaf_handle
        );
        assert_eq!(
            format!("{integrity_validated:?}"),
            "IntegrityValidatedInitializedNewProductionDatabaseConnection([REDACTED])"
        );
        assert!(matches!(
            integrity_validated.close(),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn setup_integrity_maps_all_four_parent_categories_one_to_one() {
        for (parent, expected) in [
            (
                ProductionDatabaseValidationError::EncryptedDatabaseAuthenticationOrCipherIntegrityFailed,
                "EncryptedDatabaseAuthenticationOrCipherIntegrityFailed",
            ),
            (
                ProductionDatabaseValidationError::SQLiteReadabilityOrIntegrityFailed,
                "SQLiteReadabilityOrIntegrityFailed",
            ),
            (
                ProductionDatabaseValidationError::ValidationUnavailable,
                "ValidationUnavailable",
            ),
            (
                ProductionDatabaseValidationError::ValidationInterruptedOrIncomplete,
                "ValidationInterruptedOrIncomplete",
            ),
        ] {
            let mapped = primary_integrity_validation_error(map_integrity_validation_error(parent));
            assert_eq!(format!("{mapped:?}"), expected);
        }
    }

    #[test]
    fn setup_integrity_failure_close_retry_preserves_every_category_without_rerun() {
        for parent_category in [
            ProductionDatabaseValidationError::EncryptedDatabaseAuthenticationOrCipherIntegrityFailed,
            ProductionDatabaseValidationError::SQLiteReadabilityOrIntegrityFailed,
            ProductionDatabaseValidationError::ValidationUnavailable,
            ProductionDatabaseValidationError::ValidationInterruptedOrIncomplete,
        ] {
            let root = TestRoot::create();
            let calls = Cell::new(0_u8);
            let result = validate_initialized_new_production_database_integrity_using(
                validated_initialized_fixture(&root),
                |_| {
                    calls.set(calls.get() + 1);
                    Err(parent_category)
                },
                Err,
            );
            let Err(
                NewProductionDatabaseIntegrityValidationError::IntegrityValidationCloseFailed(
                    failure,
                ),
            ) = result
            else {
                panic!("injected close failure must retain integrity ownership")
            };
            assert_eq!(calls.get(), 1);
            assert_eq!(
                format!("{failure:?}"),
                "NewProductionDatabaseIntegrityValidationCloseFailure([REDACTED])"
            );
            let NewProductionDatabaseIntegrityValidationCloseRetryOutcome::Failed(failure) =
                failure.retry_close_using(Err)
            else {
                panic!("repeated close failure must remain retryable")
            };
            assert_eq!(calls.get(), 1);
            let NewProductionDatabaseIntegrityValidationCloseRetryOutcome::Closed(error) =
                failure.retry_close()
            else {
                panic!("eventual close must return the original category")
            };
            assert_eq!(
                format!("{error:?}"),
                format!(
                    "{:?}",
                    primary_integrity_validation_error(map_integrity_validation_error(
                        parent_category
                    ))
                )
            );
            assert_eq!(calls.get(), 1);
            assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn setup_integrity_every_primary_failure_closes_and_returns_original_category() {
        for parent_category in [
            ProductionDatabaseValidationError::EncryptedDatabaseAuthenticationOrCipherIntegrityFailed,
            ProductionDatabaseValidationError::SQLiteReadabilityOrIntegrityFailed,
            ProductionDatabaseValidationError::ValidationUnavailable,
            ProductionDatabaseValidationError::ValidationInterruptedOrIncomplete,
        ] {
            let root = TestRoot::create();
            let result = validate_initialized_new_production_database_integrity_using(
                validated_initialized_fixture(&root),
                |_| Err(parent_category),
                |connection| {
                    drop(connection);
                    Ok(())
                },
            );
            let error = result.expect_err("successful close must return the primary category");
            assert_eq!(
                format!("{error:?}"),
                format!(
                    "{:?}",
                    primary_integrity_validation_error(map_integrity_validation_error(
                        parent_category
                    ))
                )
            );
            assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn setup_integrity_success_owner_close_discards_metadata_and_retries_only_close() {
        struct DropProbe<'a>(&'a Cell<bool>);
        impl Drop for DropProbe<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let root = TestRoot::create();
        let metadata_dropped = Cell::new(false);
        let close_called = Cell::new(false);
        let outcome = close_integrity_validated_initialized_owner_using(
            unkeyed_open_owner(&root),
            DropProbe(&metadata_dropped),
            |connection| {
                assert!(metadata_dropped.get());
                close_called.set(true);
                drop(connection);
                Ok(())
            },
        );
        assert!(metadata_dropped.get());
        assert!(close_called.get());
        assert!(matches!(
            outcome,
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();

        let root = TestRoot::create();
        let metadata_dropped = Cell::new(false);
        let close_called = Cell::new(false);
        let result = finish_integrity_validation_failure_after_discard_using(
            unkeyed_open_owner(&root),
            DropProbe(&metadata_dropped),
            NewProductionDatabaseIntegrityValidationFailure::ValidationUnavailable,
            |connection| {
                assert!(metadata_dropped.get());
                close_called.set(true);
                drop(connection);
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(NewProductionDatabaseIntegrityValidationError::ValidationUnavailable)
        ));
        assert!(metadata_dropped.get());
        assert!(close_called.get());
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();

        let root = TestRoot::create();
        let integrity_validated = validate_initialized_new_production_database_integrity(
            validated_initialized_fixture(&root),
        )
        .expect("fixed setup integrity validation should succeed");
        let NewProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            integrity_validated.close_using(Err)
        else {
            panic!("injected success-owner close failure must retain lifetime ownership")
        };
        let NewProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            failure.retry_close_using(Err)
        else {
            panic!("repeated close failure must remain retryable")
        };
        assert!(matches!(
            failure.retry_close(),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(root.path().join(PRODUCTION_DATABASE_FILENAME).is_file());
        root.assert_exact_cleanup();
    }

    #[test]
    fn close_and_preserve_api_representation_and_authority_surface_are_exact() {
        const SOURCE: &str = include_str!("create_new_database.rs");
        const PARENT: &str = include_str!("../production_database_connection_handoff.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        let signature = "pub(crate) fn close_and_preserve_integrity_validated_initialized_new_production_database(\n    database: IntegrityValidatedInitializedNewProductionDatabaseConnection,\n) -> NewProductionDatabaseCloseAndPreserveOutcome";
        assert!(production.contains(signature));
        assert!(PARENT.contains(
            "close_and_preserve_integrity_validated_initialized_new_production_database,"
        ));

        let closed = production
            .split_once(
                "pub(crate) struct ClosedIntegrityValidatedInitializedNewProductionDatabase {",
            )
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(closed.lines().filter(|line| line.contains(':')).count(), 2);
        assert!(closed.contains("observed_metadata_contract: DatabaseMetadataContractV1"));
        assert!(closed.contains("identity_proof: SetupDatabaseIdentityProof"));
        for forbidden in [
            "Connection",
            "OwnedHandle",
            "HANDLE",
            "Path",
            "ProductionDatabasePath",
            "StagedDatabasePath",
            "RetainedObservation",
        ] {
            assert!(
                !closed.contains(forbidden),
                "closed owner retained {forbidden}"
            );
        }

        assert!(production.contains("pub(crate) struct SetupDatabaseIdentityProof {"));
        let proof = production
            .split_once("pub(crate) struct SetupDatabaseIdentityProof {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(proof.lines().filter(|line| line.contains(':')).count(), 1);
        assert!(proof.contains("created_leaf_identity: FileIdentity"));
        assert!(!proof.contains("pub(crate) created_leaf_identity"));
        assert!(!production.contains("impl SetupDatabaseIdentityProof {"));
        assert!(!production.contains("pub(crate) struct FileIdentity {"));
        let file_identity = production
            .split_once("struct FileIdentity {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(
            file_identity
                .lines()
                .filter(|line| line.contains(':'))
                .count(),
            2
        );
        assert!(file_identity.contains("volume_serial: u64"));
        assert!(file_identity.contains("file_id: [u8; 16]"));

        let into_parts = production
            .split_once("impl ClosedIntegrityValidatedInitializedNewProductionDatabase {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let exact_into_parts = "\n    pub(crate) fn into_parts(self) -> (DatabaseMetadataContractV1, SetupDatabaseIdentityProof) {\n        (self.observed_metadata_contract, self.identity_proof)\n    }";
        assert_eq!(into_parts, exact_into_parts);
        for forbidden in [
            "clone",
            "DatabaseMetadataContractV1::new",
            "serialize",
            "parse",
            "query",
            "identity_from",
            "Path",
            "volume_serial",
            "file_id",
            "as_bytes",
            "into_bytes",
            "matches",
        ] {
            assert!(
                !into_parts.contains(forbidden),
                "forbidden consuming decomposition capability: {forbidden}"
            );
        }

        for forbidden in [
            "impl Clone for ClosedIntegrityValidatedInitializedNewProductionDatabase",
            "impl Copy for ClosedIntegrityValidatedInitializedNewProductionDatabase",
            "Serialize for ClosedIntegrityValidatedInitializedNewProductionDatabase",
            "Deserialize for ClosedIntegrityValidatedInitializedNewProductionDatabase",
            "impl Clone for SetupDatabaseIdentityProof",
            "impl Copy for SetupDatabaseIdentityProof",
            "Serialize for SetupDatabaseIdentityProof",
            "Deserialize for SetupDatabaseIdentityProof",
            "ProtectedFirstTimeSetupDatabaseKeyBinding",
            "EncodedProtectedWrapper",
            "database_key_wrapper:",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden close surface: {forbidden}"
            );
        }

        let transition = production
            .split_once(signature)
            .unwrap()
            .1
            .split_once("/// Consumes first-time setup authority")
            .unwrap()
            .0;
        for forbidden in [
            "Connection::open",
            "open_with_flags",
            "ProductionDatabasePath",
            "StagedDatabasePath",
            "production_database_path",
            "inspect_production_database_file",
            "CreateFileW",
            "query_observation",
            "revalidate_retained_creation",
            "borrowed_handle_matches_created_leaf",
            "sqlite_main_database_handle",
            "publication",
            "staging",
            "evidence",
            "freshness",
            "complete_setup",
            "startup_authorization",
            "operational_activation",
            "cleanup",
            "recovery",
            "ProtectedFirstTimeSetupDatabaseKeyBinding",
            "EncodedProtectedWrapper",
        ] {
            assert!(
                !transition.contains(forbidden),
                "forbidden close transition capability: {forbidden}"
            );
        }
    }

    #[test]
    fn close_and_preserve_orders_close_leaf_parent_and_preserves_exact_values() {
        let root = TestRoot::create();
        let integrity_validated = validate_initialized_new_production_database_integrity(
            validated_initialized_fixture(&root),
        )
        .expect("fixed setup integrity validation should succeed");
        let expected_metadata = integrity_validated.observed_metadata_contract;
        let expected_identity = integrity_validated.owner.retained.leaf.initial.identity;
        let events = RefCell::new(Vec::new());

        let outcome =
            close_and_preserve_integrity_validated_initialized_new_production_database_using(
                integrity_validated,
                |connection| {
                    events.borrow_mut().push("sqlite-close");
                    drop(connection);
                    Ok(())
                },
                |leaf| {
                    events.borrow_mut().push("leaf-release");
                    drop(leaf);
                },
                |parent| {
                    events.borrow_mut().push("parent-release");
                    drop(parent);
                },
            );
        let NewProductionDatabaseCloseAndPreserveOutcome::Closed(closed) = outcome else {
            panic!("injected successful close must return the closed predecessor");
        };
        assert_eq!(
            events.into_inner(),
            ["sqlite-close", "leaf-release", "parent-release"]
        );
        assert_eq!(
            format!("{closed:?}"),
            "ClosedIntegrityValidatedInitializedNewProductionDatabase([REDACTED])"
        );
        let parts: (DatabaseMetadataContractV1, SetupDatabaseIdentityProof) = closed.into_parts();
        let (observed_metadata_contract, identity_proof) = parts;
        assert_eq!(observed_metadata_contract, expected_metadata);
        assert!(identity_proof.created_leaf_identity == expected_identity);
        root.assert_exact_cleanup();
    }

    #[test]
    fn close_and_preserve_failure_and_retries_retain_all_state_and_only_close() {
        let root = TestRoot::create();
        let integrity_validated = validate_initialized_new_production_database_integrity(
            validated_initialized_fixture(&root),
        )
        .expect("fixed setup integrity validation should succeed");
        let expected_metadata = integrity_validated.observed_metadata_contract;
        let expected_identity = integrity_validated.owner.retained.leaf.initial.identity;
        let expected_connection = unsafe { integrity_validated.owner.connection.handle() };
        let releases = Cell::new(0_u8);

        let outcome =
            close_and_preserve_integrity_validated_initialized_new_production_database_using(
                integrity_validated,
                Err,
                |_| releases.set(releases.get() + 1),
                |_| releases.set(releases.get() + 1),
            );
        assert_eq!(format!("{outcome:?}"), "Failed([REDACTED])");
        let NewProductionDatabaseCloseAndPreserveOutcome::Failed(failure) = outcome else {
            panic!("injected close failure must retain all close-and-preserve state");
        };
        assert_eq!(releases.get(), 0);
        assert_eq!(failure.observed_metadata_contract, expected_metadata);
        assert!(failure.identity_proof.created_leaf_identity == expected_identity);
        assert_eq!(
            unsafe { failure.owner.connection.handle() },
            expected_connection
        );
        assert_eq!(
            format!("{failure:?}"),
            "NewProductionDatabaseCloseAndPreserveFailure([REDACTED])"
        );

        let NewProductionDatabaseCloseAndPreserveRetryOutcome::Failed(failure) = failure
            .retry_close_using(
                Err,
                |_| releases.set(releases.get() + 1),
                |_| releases.set(releases.get() + 1),
            )
        else {
            panic!("repeated close failure must remain retryable");
        };
        assert_eq!(releases.get(), 0);
        assert_eq!(failure.observed_metadata_contract, expected_metadata);
        assert!(failure.identity_proof.created_leaf_identity == expected_identity);
        assert_eq!(
            unsafe { failure.owner.connection.handle() },
            expected_connection
        );

        let NewProductionDatabaseCloseAndPreserveRetryOutcome::Closed(closed) =
            failure.retry_close()
        else {
            panic!("eventual close success must return the closed predecessor");
        };
        let parts: (DatabaseMetadataContractV1, SetupDatabaseIdentityProof) = closed.into_parts();
        let (observed_metadata_contract, identity_proof) = parts;
        assert_eq!(observed_metadata_contract, expected_metadata);
        assert!(identity_proof.created_leaf_identity == expected_identity);
        root.assert_exact_cleanup();
    }

    #[test]
    fn close_and_preserve_real_windows_setup_flow_matches_fresh_post_close_identity() {
        let root = TestRoot::create();
        let authorization = authorization();
        let binding = bind_generated_database_key_for_first_time_setup(
            &authorization,
            generate_database_key_material().expect("OS key randomness should be available"),
            generate_installation_identifier()
                .expect("OS installation identifier randomness should be available"),
        );
        let protected = protect_first_time_setup_database_key_binding(binding)
            .expect("test-owned database key protection should succeed");
        let (
            key,
            installation_identifier,
            database_key_generation_identifier,
            protected_database_key_wrapper,
        ) = protected.into_parts();
        let parish_identifier = generate_parish_identifier()
            .expect("OS parish identifier randomness should be available")
            .into_parish_identifier();
        let setup_publication_identifier = generate_setup_publication_identifier()
            .expect("OS setup publication randomness should be available")
            .into_setup_publication_identifier();
        let created =
            create_new_keyed_production_database(authorization, root.database_path(), key)
                .expect("real create-new handoff should succeed");
        let initialized = initialize_new_production_database(
            created,
            parish_identifier,
            installation_identifier,
            database_key_generation_identifier,
            setup_publication_identifier,
            DatabaseCreationTimestamp::from_unix_milliseconds(1_798_000_000_123),
        )
        .expect("real initialization should succeed");
        let validated = validate_initialized_new_production_database(initialized)
            .expect("real immediate validation should succeed");
        let expected_metadata = validated.observed_metadata_contract;
        let integrity_validated = validate_initialized_new_production_database_integrity(validated)
            .expect("fixed setup integrity validation should succeed");
        let outcome = close_and_preserve_integrity_validated_initialized_new_production_database(
            integrity_validated,
        );
        let NewProductionDatabaseCloseAndPreserveOutcome::Closed(closed) = outcome else {
            panic!("real SQLite close should return the closed predecessor");
        };
        assert_eq!(
            format!("{closed:?}"),
            "ClosedIntegrityValidatedInitializedNewProductionDatabase([REDACTED])"
        );
        let parts: (DatabaseMetadataContractV1, SetupDatabaseIdentityProof) = closed.into_parts();
        let (observed_metadata_contract, identity_proof) = parts;
        assert_eq!(observed_metadata_contract, expected_metadata);

        let current_handle = open_native_handle(
            &root.path().join(PRODUCTION_DATABASE_FILENAME),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
        .expect("fresh test-only post-close identity handle should open");
        let current_identity = query_observation(&current_handle)
            .expect("fresh test-only post-close identity query should succeed")
            .identity;
        drop(current_handle);
        assert!(identity_proof.created_leaf_identity == current_identity);
        drop(protected_database_key_wrapper);
        root.assert_exact_cleanup();
    }
}
