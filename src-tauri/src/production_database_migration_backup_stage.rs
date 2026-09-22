//! Private, synchronous encrypted migration-backup staging primitive.
//!
//! This module creates and verifies one encrypted SQLCipher stage. It does not
//! publish a backup, establish portable recovery, select a production backup
//! root or final name, restore data, or grant database mutation authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::{
    ffi::c_void,
    fmt,
    fs::{File, OpenOptions},
    io::Read,
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::Path,
    time::Duration,
};

use rusqlite::{
    Connection, OpenFlags,
    backup::{Backup, StepResult},
    config::DbConfig,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_ID_INFO, FILE_SHARE_READ, FileIdInfo, GetFileInformationByHandleEx,
};

use crate::{
    database_key_active_wrapper_loader::load_active_database_key_wrapper,
    database_key_presence::{DatabaseKeyActivePresence, inspect_database_key_active_presence},
    database_metadata_contract::DatabaseMetadataContractV1,
    installation_evidence_protection::{
        GenerationBoundDatabaseKey, TrustedCurrentInstallationEvidenceAssessment,
        bind_database_key_candidate_to_trusted_installation_evidence,
        recover_database_key_candidate_from_loaded_wrapper,
    },
    production_database_connection_handoff::{
        FullIntegrityValidatedProductionDatabaseMigrationSource,
        ProductionDatabaseConnectionCloseFailure, ProductionDatabaseConnectionCloseOutcome,
        observe_production_database_fixed_metadata_and_headers_on_borrowed_connection,
        validate_production_database_cipher_integrity_on_borrowed_connection,
        validate_production_database_full_integrity_on_borrowed_connection,
    },
    sqlcipher_database_key_application::apply_generation_bound_database_key_to_handle,
    storage_foundation::{
        DatabaseKeyPersistencePaths, PRODUCTION_DATABASE_MIGRATION_BACKUP_STAGE_FILENAME,
        ProductionDatabaseMigrationBackupStagePath, resolve_database_key_persistence_paths,
        resolve_production_database_migration_backup_stage_path,
    },
};

use super::{
    FullIntegrityValidatedProductionDatabaseMigrationHandoff,
    ProductionDatabaseMigrationAuthorization, destroy_migration_authorization,
};

#[path = "production_database_migration_backup_stage/recovery_envelope.rs"]
mod recovery_envelope;

#[allow(unused_imports)]
pub(crate) use recovery_envelope::{
    MigrationRecoveryKeyCustodySourceCloseRetryOutcome, NativeMigrationRecoveryKeyCustodyOutcome,
    PossiblyExposedMigrationRecoveryKeyCustodyFailure,
    PreparedUndisclosedMigrationRecoveryKeyCustody,
    ProductionDatabaseMigrationRecoveryEnvelopeFailure,
    ProductionDatabaseMigrationRecoveryEnvelopeOutcome,
    ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome,
    ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseFailure,
    ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseRetryOutcome,
    RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    RecoverySetManifestPreparationError, UndisclosedMigrationRecoveryKeyCustodyInterruption,
    VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup,
    prepare_migration_recovery_key_custody, run_migration_recovery_key_custody_native_ceremony,
    verify_production_database_migration_recovery_envelope,
};

const STAGE_LEAF_NAME: &str = PRODUCTION_DATABASE_MIGRATION_BACKUP_STAGE_FILENAME;
const MAIN_DATABASE_NAME: &str = "main";
const BACKUP_PAGES_PER_STEP: i32 = 16;
const PLAINTEXT_SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

const DESTINATION_OPEN_FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE
    .union(OpenFlags::SQLITE_OPEN_FULL_MUTEX)
    .union(OpenFlags::SQLITE_OPEN_PRIVATE_CACHE)
    .union(OpenFlags::SQLITE_OPEN_NOFOLLOW);
const VERIFIER_OPEN_FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_ONLY
    .union(OpenFlags::SQLITE_OPEN_FULL_MUTEX)
    .union(OpenFlags::SQLITE_OPEN_PRIVATE_CACHE)
    .union(OpenFlags::SQLITE_OPEN_NOFOLLOW);

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

/// Opaque proof that one application-owned stage parent was accepted and the
/// fixed stage leaf was absent. It carries no general path mutation API.
pub(crate) struct PreparedProductionDatabaseMigrationBackupStage {
    path: ProductionDatabaseMigrationBackupStagePath,
    parent: File,
    parent_identity: FileIdentity,
}

/// Narrow canonical-key reload context. It contains only Rust-owned typed
/// database-key paths and is deliberately separate from the stage location.
pub(crate) struct ProductionDatabaseMigrationBackupContext {
    database_key_paths: DatabaseKeyPersistencePaths,
}

struct CreatedProductionDatabaseMigrationBackupStage {
    prepared: PreparedProductionDatabaseMigrationBackupStage,
}

pub(crate) struct VerifiedEncryptedProductionDatabaseMigrationBackupStageProof {
    created: CreatedProductionDatabaseMigrationBackupStage,
    leaf: File,
    leaf_identity: FileIdentity,
}

pub(crate) struct VerifiedEncryptedProductionDatabaseMigrationBackupStage {
    authorization: ProductionDatabaseMigrationAuthorization,
    source: FullIntegrityValidatedProductionDatabaseMigrationSource,
    backup_stage_proof: VerifiedEncryptedProductionDatabaseMigrationBackupStageProof,
    context: ProductionDatabaseMigrationBackupContext,
}

pub(crate) struct UndisclosedMigrationRecoveryKeyCustodyShutdown {
    backup_stage_proof: VerifiedEncryptedProductionDatabaseMigrationBackupStageProof,
    verified_envelope: recovery_envelope::IndependentlyVerifiedMigrationRecoveryEnvelopeV1,
    source_close: SourceCloseState,
}

#[must_use = "a pre-exposure shutdown source-close retry outcome must be handled"]
pub(crate) enum UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome {
    Closed(UndisclosedMigrationRecoveryKeyCustodyShutdown),
    Failed(UndisclosedMigrationRecoveryKeyCustodyShutdown),
}

enum RetainedProductionDatabaseMigrationBackupStage {
    Prepared(PreparedProductionDatabaseMigrationBackupStage),
    Created(CreatedProductionDatabaseMigrationBackupStage),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProductionDatabaseMigrationBackupStageError {
    StageLocationUnavailableOrChanged,
    DestinationAlreadyExists,
    DestinationCreateFailed,
    ActiveDatabaseKeyUnavailable,
    ActiveDatabaseKeyRecoveryFailed,
    ActiveDatabaseKeyBindingFailed,
    DestinationOpenFailed,
    DestinationKeyApplicationFailed,
    DestinationPolicyFailed,
    BackupInitializationFailed,
    BackupBusy,
    BackupLocked,
    BackupStepFailed,
    BackupCompletionIncomplete,
    DestinationWriterCloseFailed,
    DestinationVerifierOpenFailed,
    DestinationVerificationFailed,
    DestinationVerifierCloseFailed,
    CiphertextAtRestNotEstablished,
    SourceInvariantChanged,
}

enum SourceCloseState {
    Closed,
    RetryRequired(ProductionDatabaseConnectionCloseFailure),
}

pub(crate) struct ProductionDatabaseMigrationBackupStageFailure {
    category: ProductionDatabaseMigrationBackupStageError,
    stage: RetainedProductionDatabaseMigrationBackupStage,
    source_close: SourceCloseState,
}

#[allow(dead_code)]
pub(crate) struct ProductionDatabaseMigrationBackupStageWriterCloseFailure {
    category: ProductionDatabaseMigrationBackupStageError,
    stage: CreatedProductionDatabaseMigrationBackupStage,
    writer: Connection,
    source_close: SourceCloseState,
}

#[allow(dead_code)]
pub(crate) struct ProductionDatabaseMigrationBackupStageVerifierCloseFailure {
    category: ProductionDatabaseMigrationBackupStageError,
    stage: CreatedProductionDatabaseMigrationBackupStage,
    verifier: Connection,
    source_close: SourceCloseState,
}

#[must_use = "a source close retry outcome must be handled"]
pub(crate) enum ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome<T> {
    Closed(T),
    Failed(T),
}

#[must_use = "the migration backup-stage outcome must be handled"]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProductionDatabaseMigrationBackupStageOutcome {
    Verified(VerifiedEncryptedProductionDatabaseMigrationBackupStage),
    Failed(ProductionDatabaseMigrationBackupStageFailure),
    WriterCloseFailed(ProductionDatabaseMigrationBackupStageWriterCloseFailure),
    VerifierCloseFailed(ProductionDatabaseMigrationBackupStageVerifierCloseFailure),
}

macro_rules! redacted_debug {
    ($type:ty, $name:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($name, "([REDACTED])"))
            }
        }
    };
}

redacted_debug!(
    PreparedProductionDatabaseMigrationBackupStage,
    "PreparedProductionDatabaseMigrationBackupStage"
);
redacted_debug!(
    ProductionDatabaseMigrationBackupContext,
    "ProductionDatabaseMigrationBackupContext"
);
redacted_debug!(
    VerifiedEncryptedProductionDatabaseMigrationBackupStageProof,
    "VerifiedEncryptedProductionDatabaseMigrationBackupStageProof"
);
redacted_debug!(
    VerifiedEncryptedProductionDatabaseMigrationBackupStage,
    "VerifiedEncryptedProductionDatabaseMigrationBackupStage"
);
redacted_debug!(
    UndisclosedMigrationRecoveryKeyCustodyShutdown,
    "UndisclosedMigrationRecoveryKeyCustodyShutdown"
);
redacted_debug!(
    ProductionDatabaseMigrationBackupStageFailure,
    "ProductionDatabaseMigrationBackupStageFailure"
);
redacted_debug!(
    ProductionDatabaseMigrationBackupStageWriterCloseFailure,
    "ProductionDatabaseMigrationBackupStageWriterCloseFailure"
);
redacted_debug!(
    ProductionDatabaseMigrationBackupStageVerifierCloseFailure,
    "ProductionDatabaseMigrationBackupStageVerifierCloseFailure"
);

impl fmt::Debug for ProductionDatabaseMigrationBackupStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StageLocationUnavailableOrChanged => "StageLocationUnavailableOrChanged",
            Self::DestinationAlreadyExists => "DestinationAlreadyExists",
            Self::DestinationCreateFailed => "DestinationCreateFailed",
            Self::ActiveDatabaseKeyUnavailable => "ActiveDatabaseKeyUnavailable",
            Self::ActiveDatabaseKeyRecoveryFailed => "ActiveDatabaseKeyRecoveryFailed",
            Self::ActiveDatabaseKeyBindingFailed => "ActiveDatabaseKeyBindingFailed",
            Self::DestinationOpenFailed => "DestinationOpenFailed",
            Self::DestinationKeyApplicationFailed => "DestinationKeyApplicationFailed",
            Self::DestinationPolicyFailed => "DestinationPolicyFailed",
            Self::BackupInitializationFailed => "BackupInitializationFailed",
            Self::BackupBusy => "BackupBusy",
            Self::BackupLocked => "BackupLocked",
            Self::BackupStepFailed => "BackupStepFailed",
            Self::BackupCompletionIncomplete => "BackupCompletionIncomplete",
            Self::DestinationWriterCloseFailed => "DestinationWriterCloseFailed",
            Self::DestinationVerifierOpenFailed => "DestinationVerifierOpenFailed",
            Self::DestinationVerificationFailed => "DestinationVerificationFailed",
            Self::DestinationVerifierCloseFailed => "DestinationVerifierCloseFailed",
            Self::CiphertextAtRestNotEstablished => "CiphertextAtRestNotEstablished",
            Self::SourceInvariantChanged => "SourceInvariantChanged",
        })
    }
}

impl fmt::Debug for ProductionDatabaseMigrationBackupStageOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified(_) => formatter.write_str("Verified([REDACTED])"),
            Self::Failed(failure) => formatter
                .debug_tuple("Failed")
                .field(&failure.category)
                .finish(),
            Self::WriterCloseFailed(_) => formatter.write_str("WriterCloseFailed([REDACTED])"),
            Self::VerifierCloseFailed(_) => formatter.write_str("VerifierCloseFailed([REDACTED])"),
        }
    }
}

impl PreparedProductionDatabaseMigrationBackupStage {
    #[cfg(test)]
    pub(crate) fn from_synthetic_temp_root(root: &Path) -> Result<Self, ()> {
        let temporary = std::env::temp_dir();
        if !root.is_absolute() || !root.starts_with(&temporary) || root == temporary {
            return Err(());
        }
        prepare_stage_path(
            crate::storage_foundation::production_database_migration_backup_stage_path(root),
        )
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }

    fn parent_is_unchanged(&self) -> bool {
        file_identity(&self.parent).is_some_and(|identity| identity == self.parent_identity)
            && self
                .path()
                .parent()
                .and_then(|parent| parent_identity(parent).ok())
                == Some(self.parent_identity)
    }
}

impl ProductionDatabaseMigrationBackupContext {
    #[cfg(test)]
    pub(crate) fn from_synthetic_root(root: &Path) -> Self {
        Self {
            database_key_paths: crate::storage_foundation::database_key_persistence_paths(root),
        }
    }
}

pub(crate) fn prepare_production_database_migration_backup_stage(
    app: &tauri::AppHandle,
) -> Result<
    (
        PreparedProductionDatabaseMigrationBackupStage,
        ProductionDatabaseMigrationBackupContext,
    ),
    (),
> {
    let path = resolve_production_database_migration_backup_stage_path(app).map_err(|_| ())?;
    let database_key_paths = resolve_database_key_persistence_paths(app).map_err(|_| ())?;
    let prepared = prepare_stage_path(path)?;
    Ok((
        prepared,
        ProductionDatabaseMigrationBackupContext { database_key_paths },
    ))
}

impl VerifiedEncryptedProductionDatabaseMigrationBackupStage {
    #[cfg(test)]
    fn preservation_evidence_for_test(&self) -> (usize, DatabaseMetadataContractV1) {
        self.source
            .with_migration_backup_source(|connection, metadata, _| {
                (unsafe { connection.handle() as usize }, *metadata)
            })
    }

    #[cfg(test)]
    fn stage_path_for_test(&self) -> &Path {
        self.backup_stage_proof.created.prepared.path()
    }

    #[cfg(test)]
    fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            authorization,
            source,
            backup_stage_proof,
            context,
        } = self;
        destroy_migration_authorization(authorization);
        drop(backup_stage_proof);
        drop(context);
        source.close()
    }
}

impl ProductionDatabaseMigrationBackupStageFailure {
    pub(crate) fn source_close_retry_required(&self) -> bool {
        matches!(self.source_close, SourceCloseState::RetryRequired(_))
    }

    pub(crate) fn retry_source_close(
        self,
    ) -> ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome<Self> {
        let Self {
            category,
            stage,
            source_close,
        } = self;
        let (source_close, closed) = retry_source_close_state(source_close);
        let failure = Self {
            category,
            stage,
            source_close,
        };
        if closed {
            ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Closed(failure)
        } else {
            ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Failed(failure)
        }
    }

    #[cfg(test)]
    fn category(&self) -> ProductionDatabaseMigrationBackupStageError {
        self.category
    }

    #[cfg(test)]
    fn retained_stage_is_created(&self) -> bool {
        match &self.stage {
            RetainedProductionDatabaseMigrationBackupStage::Prepared(prepared) => {
                let _ = prepared.parent_identity;
                false
            }
            RetainedProductionDatabaseMigrationBackupStage::Created(created) => {
                let _ = created.prepared.parent_identity;
                true
            }
        }
    }

    #[cfg(test)]
    fn source_close_was_required(&self) -> bool {
        match &self.source_close {
            SourceCloseState::Closed => false,
            SourceCloseState::RetryRequired(failure) => {
                let _ = std::mem::size_of_val(failure);
                true
            }
        }
    }
}

impl UndisclosedMigrationRecoveryKeyCustodyShutdown {
    pub(crate) fn retry_source_close(
        self,
    ) -> UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome {
        let Self {
            backup_stage_proof,
            verified_envelope,
            source_close,
        } = self;
        let (source_close, closed) = retry_source_close_state(source_close);
        let shutdown = Self {
            backup_stage_proof,
            verified_envelope,
            source_close,
        };
        if closed {
            UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome::Closed(shutdown)
        } else {
            UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome::Failed(shutdown)
        }
    }
}

#[must_use = "a writer close retry outcome must be handled"]
#[allow(dead_code)]
pub(crate) enum ProductionDatabaseMigrationBackupStageWriterCloseRetryOutcome {
    Closed(ProductionDatabaseMigrationBackupStageFailure),
    Failed(ProductionDatabaseMigrationBackupStageWriterCloseFailure),
}

impl ProductionDatabaseMigrationBackupStageWriterCloseFailure {
    pub(crate) fn retry_source_close(
        self,
    ) -> ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome<Self> {
        let Self {
            category,
            stage,
            writer,
            source_close,
        } = self;
        let (source_close, closed) = retry_source_close_state(source_close);
        let failure = Self {
            category,
            stage,
            writer,
            source_close,
        };
        if closed {
            ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Closed(failure)
        } else {
            ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Failed(failure)
        }
    }

    #[allow(dead_code)]
    pub(crate) fn retry_close(
        self,
    ) -> ProductionDatabaseMigrationBackupStageWriterCloseRetryOutcome {
        let Self {
            category,
            stage,
            writer,
            source_close,
        } = self;
        match writer.close() {
            Ok(()) => ProductionDatabaseMigrationBackupStageWriterCloseRetryOutcome::Closed(
                ProductionDatabaseMigrationBackupStageFailure {
                    category,
                    stage: RetainedProductionDatabaseMigrationBackupStage::Created(stage),
                    source_close,
                },
            ),
            Err((writer, _)) => {
                ProductionDatabaseMigrationBackupStageWriterCloseRetryOutcome::Failed(Self {
                    category,
                    stage,
                    writer,
                    source_close,
                })
            }
        }
    }
}

#[must_use = "a verifier close retry outcome must be handled"]
#[allow(dead_code)]
pub(crate) enum ProductionDatabaseMigrationBackupStageVerifierCloseRetryOutcome {
    Closed(ProductionDatabaseMigrationBackupStageFailure),
    Failed(ProductionDatabaseMigrationBackupStageVerifierCloseFailure),
}

impl ProductionDatabaseMigrationBackupStageVerifierCloseFailure {
    pub(crate) fn retry_source_close(
        self,
    ) -> ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome<Self> {
        let Self {
            category,
            stage,
            verifier,
            source_close,
        } = self;
        let (source_close, closed) = retry_source_close_state(source_close);
        let failure = Self {
            category,
            stage,
            verifier,
            source_close,
        };
        if closed {
            ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Closed(failure)
        } else {
            ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Failed(failure)
        }
    }

    #[allow(dead_code)]
    pub(crate) fn retry_close(
        self,
    ) -> ProductionDatabaseMigrationBackupStageVerifierCloseRetryOutcome {
        let Self {
            category,
            stage,
            verifier,
            source_close,
        } = self;
        match verifier.close() {
            Ok(()) => ProductionDatabaseMigrationBackupStageVerifierCloseRetryOutcome::Closed(
                ProductionDatabaseMigrationBackupStageFailure {
                    category,
                    stage: RetainedProductionDatabaseMigrationBackupStage::Created(stage),
                    source_close,
                },
            ),
            Err((verifier, _)) => {
                ProductionDatabaseMigrationBackupStageVerifierCloseRetryOutcome::Failed(Self {
                    category,
                    stage,
                    verifier,
                    source_close,
                })
            }
        }
    }
}

fn prepare_stage_path(
    path: ProductionDatabaseMigrationBackupStagePath,
) -> Result<PreparedProductionDatabaseMigrationBackupStage, ()> {
    let parent_path = path.as_path().parent().ok_or(())?;
    if path.as_path().file_name().and_then(|name| name.to_str()) != Some(STAGE_LEAF_NAME)
        || path.as_path().exists()
    {
        return Err(());
    }
    let parent = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(parent_path)
        .map_err(|_| ())?;
    let metadata = parent.metadata().map_err(|_| ())?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(());
    }
    let retained_parent_identity = file_identity(&parent).ok_or(())?;
    if parent_identity(parent_path)? != retained_parent_identity {
        return Err(());
    }
    Ok(PreparedProductionDatabaseMigrationBackupStage {
        path,
        parent,
        parent_identity: retained_parent_identity,
    })
}

fn file_identity(file: &File) -> Option<FileIdentity> {
    let mut information = FILE_ID_INFO::default();
    // SAFETY: `file` owns a live handle and `information` is initialized,
    // writable output of the exact documented type.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileIdInfo,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).ok()?,
        )
    } == 0
    {
        return None;
    }
    Some(FileIdentity {
        volume_serial: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

fn parent_identity(path: &Path) -> Result<FileIdentity, ()> {
    let parent = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| ())?;
    file_identity(&parent).ok_or(())
}

fn retain_verified_stage_leaf(
    created: CreatedProductionDatabaseMigrationBackupStage,
) -> Result<
    VerifiedEncryptedProductionDatabaseMigrationBackupStageProof,
    CreatedProductionDatabaseMigrationBackupStage,
> {
    if !created.prepared.parent_is_unchanged() {
        return Err(created);
    }
    let leaf = match OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(created.prepared.path())
    {
        Ok(leaf) => leaf,
        Err(_) => return Err(created),
    };
    let metadata = match leaf.metadata() {
        Ok(metadata)
            if metadata.is_file()
                && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 =>
        {
            metadata
        }
        _ => return Err(created),
    };
    let _ = metadata;
    let leaf_identity = match file_identity(&leaf) {
        Some(identity) => identity,
        None => return Err(created),
    };
    let fresh_identity = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(created.prepared.path())
        .ok()
        .and_then(|fresh| file_identity(&fresh));
    if fresh_identity != Some(leaf_identity) || !created.prepared.parent_is_unchanged() {
        return Err(created);
    }
    Ok(
        VerifiedEncryptedProductionDatabaseMigrationBackupStageProof {
            created,
            leaf,
            leaf_identity,
        },
    )
}

impl VerifiedEncryptedProductionDatabaseMigrationBackupStageProof {
    fn identity_is_unchanged(&self) -> bool {
        self.created.prepared.parent_is_unchanged()
            && file_identity(&self.leaf) == Some(self.leaf_identity)
            && OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(self.created.prepared.path())
                .ok()
                .and_then(|fresh| file_identity(&fresh))
                == Some(self.leaf_identity)
    }
}

fn create_stage_file(
    prepared: PreparedProductionDatabaseMigrationBackupStage,
) -> Result<
    CreatedProductionDatabaseMigrationBackupStage,
    (
        ProductionDatabaseMigrationBackupStageError,
        PreparedProductionDatabaseMigrationBackupStage,
    ),
> {
    if !prepared.parent_is_unchanged() {
        return Err((
            ProductionDatabaseMigrationBackupStageError::StageLocationUnavailableOrChanged,
            prepared,
        ));
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(prepared.path())
    {
        Ok(file) => {
            drop(file);
            Ok(CreatedProductionDatabaseMigrationBackupStage { prepared })
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err((
            ProductionDatabaseMigrationBackupStageError::DestinationAlreadyExists,
            prepared,
        )),
        Err(_) => Err((
            ProductionDatabaseMigrationBackupStageError::DestinationCreateFailed,
            prepared,
        )),
    }
}

fn load_fresh_bound_key(
    context: &ProductionDatabaseMigrationBackupContext,
    assessment: &TrustedCurrentInstallationEvidenceAssessment,
) -> Result<GenerationBoundDatabaseKey, ProductionDatabaseMigrationBackupStageError> {
    let presence = inspect_database_key_active_presence(&context.database_key_paths);
    if presence != DatabaseKeyActivePresence::Present {
        return Err(ProductionDatabaseMigrationBackupStageError::ActiveDatabaseKeyUnavailable);
    }
    let loaded = load_active_database_key_wrapper(&context.database_key_paths, presence)
        .map_err(|_| ProductionDatabaseMigrationBackupStageError::ActiveDatabaseKeyUnavailable)?;
    let candidate = recover_database_key_candidate_from_loaded_wrapper(&loaded).map_err(|_| {
        ProductionDatabaseMigrationBackupStageError::ActiveDatabaseKeyRecoveryFailed
    })?;
    bind_database_key_candidate_to_trusted_installation_evidence(candidate, assessment)
        .map_err(|_| ProductionDatabaseMigrationBackupStageError::ActiveDatabaseKeyBindingFailed)
}

fn open_destination(
    path: &Path,
) -> Result<Connection, ProductionDatabaseMigrationBackupStageError> {
    Connection::open_with_flags(path, DESTINATION_OPEN_FLAGS)
        .map_err(|_| ProductionDatabaseMigrationBackupStageError::DestinationOpenFailed)
}

fn apply_key(
    connection: &Connection,
    key: &GenerationBoundDatabaseKey,
    category: ProductionDatabaseMigrationBackupStageError,
) -> Result<(), ProductionDatabaseMigrationBackupStageError> {
    // SAFETY: the connection is live, exclusively controlled by this
    // synchronous primitive, and has not previously had a key applied.
    unsafe { apply_generation_bound_database_key_to_handle(connection.handle(), key) }
        .map_err(|_| category)
}

fn configure_destination(
    connection: &Connection,
) -> Result<(), ProductionDatabaseMigrationBackupStageError> {
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| ProductionDatabaseMigrationBackupStageError::DestinationPolicyFailed)?;
    // SAFETY: the live handle is borrowed only for this synchronous policy call.
    if unsafe { rusqlite::ffi::sqlite3_enable_load_extension(connection.handle(), 0) }
        != rusqlite::ffi::SQLITE_OK
    {
        return Err(ProductionDatabaseMigrationBackupStageError::DestinationPolicyFailed);
    }
    for (config, expected) in [
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, false),
    ] {
        if connection.set_db_config(config, expected).ok() != Some(expected)
            || connection.db_config(config).ok() != Some(expected)
        {
            return Err(ProductionDatabaseMigrationBackupStageError::DestinationPolicyFailed);
        }
    }
    let journal: String = connection
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
        .map_err(|_| ProductionDatabaseMigrationBackupStageError::DestinationPolicyFailed)?;
    if !journal.eq_ignore_ascii_case("delete") {
        return Err(ProductionDatabaseMigrationBackupStageError::DestinationPolicyFailed);
    }
    Ok(())
}

fn run_backup(
    source: &Connection,
    destination: &mut Connection,
) -> Result<(), ProductionDatabaseMigrationBackupStageError> {
    let backup = Backup::new(source, destination)
        .map_err(|_| ProductionDatabaseMigrationBackupStageError::BackupInitializationFailed)?;
    drive_backup_steps(|| {
        let step = backup
            .step(BACKUP_PAGES_PER_STEP)
            .map_err(|_| ProductionDatabaseMigrationBackupStageError::BackupStepFailed)?;
        Ok((step, backup.progress().remaining))
    })
}

fn drive_backup_steps(
    mut step: impl FnMut() -> Result<(StepResult, i32), ProductionDatabaseMigrationBackupStageError>,
) -> Result<(), ProductionDatabaseMigrationBackupStageError> {
    loop {
        let (result, remaining) = step()?;
        match result {
            StepResult::More => {}
            StepResult::Done if remaining == 0 => return Ok(()),
            StepResult::Done => {
                return Err(
                    ProductionDatabaseMigrationBackupStageError::BackupCompletionIncomplete,
                );
            }
            StepResult::Busy => {
                return Err(ProductionDatabaseMigrationBackupStageError::BackupBusy);
            }
            StepResult::Locked => {
                return Err(ProductionDatabaseMigrationBackupStageError::BackupLocked);
            }
            _ => return Err(ProductionDatabaseMigrationBackupStageError::BackupStepFailed),
        }
    }
}

fn source_invariants(
    connection: &Connection,
    expected_metadata: &DatabaseMetadataContractV1,
) -> Result<usize, ProductionDatabaseMigrationBackupStageError> {
    if connection.is_readonly(MAIN_DATABASE_NAME) != Ok(true)
        || connection.pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
            != Ok(true)
        || observe_production_database_fixed_metadata_and_headers_on_borrowed_connection(connection)
            .as_ref()
            != Ok(expected_metadata)
    {
        return Err(ProductionDatabaseMigrationBackupStageError::SourceInvariantChanged);
    }
    // SAFETY: only the opaque value is observed while the owner remains live.
    Ok(unsafe { connection.handle() as usize })
}

fn verify_destination(
    connection: &Connection,
    expected_metadata: &DatabaseMetadataContractV1,
) -> Result<(), ProductionDatabaseMigrationBackupStageError> {
    validate_production_database_cipher_integrity_on_borrowed_connection(connection)
        .map_err(|_| ProductionDatabaseMigrationBackupStageError::DestinationVerificationFailed)?;
    validate_production_database_full_integrity_on_borrowed_connection(connection)
        .map_err(|_| ProductionDatabaseMigrationBackupStageError::DestinationVerificationFailed)?;
    if observe_production_database_fixed_metadata_and_headers_on_borrowed_connection(connection)
        .as_ref()
        != Ok(expected_metadata)
    {
        return Err(ProductionDatabaseMigrationBackupStageError::DestinationVerificationFailed);
    }
    Ok(())
}

fn ciphertext_header_is_non_plaintext(path: &Path) -> bool {
    let mut header = [0_u8; 16];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .is_ok()
        && &header != PLAINTEXT_SQLITE_HEADER
}

enum InternalFailure {
    Primary(
        ProductionDatabaseMigrationBackupStageError,
        RetainedProductionDatabaseMigrationBackupStage,
    ),
    WriterClose(
        ProductionDatabaseMigrationBackupStageError,
        CreatedProductionDatabaseMigrationBackupStage,
        Connection,
    ),
    VerifierClose(
        ProductionDatabaseMigrationBackupStageError,
        CreatedProductionDatabaseMigrationBackupStage,
        Connection,
    ),
}

fn run_stage(
    source: &Connection,
    expected_metadata: &DatabaseMetadataContractV1,
    assessment: &TrustedCurrentInstallationEvidenceAssessment,
    prepared: PreparedProductionDatabaseMigrationBackupStage,
    context: &ProductionDatabaseMigrationBackupContext,
) -> Result<VerifiedEncryptedProductionDatabaseMigrationBackupStageProof, InternalFailure> {
    let source_handle = match source_invariants(source, expected_metadata) {
        Ok(handle) => handle,
        Err(category) => {
            return Err(InternalFailure::Primary(
                category,
                RetainedProductionDatabaseMigrationBackupStage::Prepared(prepared),
            ));
        }
    };
    let created = match create_stage_file(prepared) {
        Ok(created) => created,
        Err((category, prepared)) => {
            return Err(InternalFailure::Primary(
                category,
                RetainedProductionDatabaseMigrationBackupStage::Prepared(prepared),
            ));
        }
    };
    let key = match load_fresh_bound_key(context, assessment) {
        Ok(key) => key,
        Err(category) => {
            return Err(InternalFailure::Primary(
                category,
                RetainedProductionDatabaseMigrationBackupStage::Created(created),
            ));
        }
    };
    let mut writer = match open_destination(created.prepared.path()) {
        Ok(writer) => writer,
        Err(category) => {
            return Err(InternalFailure::Primary(
                category,
                RetainedProductionDatabaseMigrationBackupStage::Created(created),
            ));
        }
    };
    if let Err(category) = apply_key(
        &writer,
        &key,
        ProductionDatabaseMigrationBackupStageError::DestinationKeyApplicationFailed,
    )
    .and_then(|_| configure_destination(&writer))
    .and_then(|_| run_backup(source, &mut writer))
    {
        return match writer.close() {
            Ok(()) => Err(InternalFailure::Primary(
                category,
                RetainedProductionDatabaseMigrationBackupStage::Created(created),
            )),
            Err((writer, _)) => Err(InternalFailure::WriterClose(category, created, writer)),
        };
    }
    if let Err((writer, _)) = writer.close() {
        return Err(InternalFailure::WriterClose(
            ProductionDatabaseMigrationBackupStageError::DestinationWriterCloseFailed,
            created,
            writer,
        ));
    }
    let verifier = match Connection::open_with_flags(created.prepared.path(), VERIFIER_OPEN_FLAGS) {
        Ok(verifier) => verifier,
        Err(_) => {
            return Err(InternalFailure::Primary(
                ProductionDatabaseMigrationBackupStageError::DestinationVerifierOpenFailed,
                RetainedProductionDatabaseMigrationBackupStage::Created(created),
            ));
        }
    };
    if let Err(category) = apply_key(
        &verifier,
        &key,
        ProductionDatabaseMigrationBackupStageError::DestinationVerificationFailed,
    )
    .and_then(|_| verify_destination(&verifier, expected_metadata))
    {
        return match verifier.close() {
            Ok(()) => Err(InternalFailure::Primary(
                category,
                RetainedProductionDatabaseMigrationBackupStage::Created(created),
            )),
            Err((verifier, _)) => Err(InternalFailure::VerifierClose(category, created, verifier)),
        };
    }
    if let Err((verifier, _)) = verifier.close() {
        return Err(InternalFailure::VerifierClose(
            ProductionDatabaseMigrationBackupStageError::DestinationVerifierCloseFailed,
            created,
            verifier,
        ));
    }
    drop(key);
    if !ciphertext_header_is_non_plaintext(created.prepared.path()) {
        return Err(InternalFailure::Primary(
            ProductionDatabaseMigrationBackupStageError::CiphertextAtRestNotEstablished,
            RetainedProductionDatabaseMigrationBackupStage::Created(created),
        ));
    }
    let final_handle = match source_invariants(source, expected_metadata) {
        Ok(handle) => handle,
        Err(category) => {
            return Err(InternalFailure::Primary(
                category,
                RetainedProductionDatabaseMigrationBackupStage::Created(created),
            ));
        }
    };
    if final_handle != source_handle || !created.prepared.parent_is_unchanged() {
        return Err(InternalFailure::Primary(
            ProductionDatabaseMigrationBackupStageError::SourceInvariantChanged,
            RetainedProductionDatabaseMigrationBackupStage::Created(created),
        ));
    }
    retain_verified_stage_leaf(created).map_err(|created| {
        InternalFailure::Primary(
            ProductionDatabaseMigrationBackupStageError::StageLocationUnavailableOrChanged,
            RetainedProductionDatabaseMigrationBackupStage::Created(created),
        )
    })
}

fn close_source(
    source: FullIntegrityValidatedProductionDatabaseMigrationSource,
) -> SourceCloseState {
    match source.close() {
        ProductionDatabaseConnectionCloseOutcome::Closed => SourceCloseState::Closed,
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            SourceCloseState::RetryRequired(failure)
        }
    }
}

fn retry_source_close_state(source_close: SourceCloseState) -> (SourceCloseState, bool) {
    match source_close {
        SourceCloseState::Closed => (SourceCloseState::Closed, true),
        SourceCloseState::RetryRequired(failure) => match failure.retry_close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => (SourceCloseState::Closed, true),
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                (SourceCloseState::RetryRequired(failure), false)
            }
        },
    }
}

pub(crate) fn stage_encrypted_production_database_migration_backup(
    handoff: FullIntegrityValidatedProductionDatabaseMigrationHandoff,
    prepared: PreparedProductionDatabaseMigrationBackupStage,
    context: ProductionDatabaseMigrationBackupContext,
) -> ProductionDatabaseMigrationBackupStageOutcome {
    let (authorization, source) = handoff.into_parts();
    let result = source.with_migration_backup_source(|connection, metadata, assessment| {
        run_stage(connection, metadata, assessment, prepared, &context)
    });
    match result {
        Ok(backup_stage_proof) => ProductionDatabaseMigrationBackupStageOutcome::Verified(
            VerifiedEncryptedProductionDatabaseMigrationBackupStage {
                authorization,
                source,
                backup_stage_proof,
                context,
            },
        ),
        Err(failure) => {
            destroy_migration_authorization(authorization);
            let source_close = close_source(source);
            match failure {
                InternalFailure::Primary(category, stage) => {
                    ProductionDatabaseMigrationBackupStageOutcome::Failed(
                        ProductionDatabaseMigrationBackupStageFailure {
                            category,
                            stage,
                            source_close,
                        },
                    )
                }
                InternalFailure::WriterClose(category, stage, writer) => {
                    ProductionDatabaseMigrationBackupStageOutcome::WriterCloseFailed(
                        ProductionDatabaseMigrationBackupStageWriterCloseFailure {
                            category,
                            stage,
                            writer,
                            source_close,
                        },
                    )
                }
                InternalFailure::VerifierClose(category, stage, verifier) => {
                    ProductionDatabaseMigrationBackupStageOutcome::VerifierCloseFailed(
                        ProductionDatabaseMigrationBackupStageVerifierCloseFailure {
                            category,
                            stage,
                            verifier,
                            source_close,
                        },
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        mem::needs_drop,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::{
        database_key::DatabaseKey, installation_evidence_contract::DatabaseKeyGenerationIdentifier,
        installation_evidence_protection::protect_database_key,
        production_database_connection_handoff::with_production_database_close_failure_injected,
        storage_foundation::database_key_persistence_paths,
    };

    use super::super::genuine_full_integrity_validated_migration_handoff_for_test;
    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const KEY_BYTES: [u8; 32] = [0x74; 32];
    const KEY_GENERATION: [u8; 16] = [0x43; 16];

    struct StageRoot(PathBuf);

    impl StageRoot {
        fn create() -> Self {
            let path = std::env::temp_dir().join(format!(
                "church-app-migration-backup-stage-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for StageRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_active_key_wrapper(root: &Path) {
        let paths = database_key_persistence_paths(root);
        fs::create_dir_all(paths.database_key_directory.as_path()).unwrap();
        let key = DatabaseKey::from_bytes(KEY_BYTES);
        let generation = DatabaseKeyGenerationIdentifier::from_bytes(KEY_GENERATION).unwrap();
        let wrapper = protect_database_key(&key, generation).unwrap();
        fs::write(paths.active_database_key.as_path(), wrapper.as_bytes()).unwrap();
    }

    fn prepared(root: &StageRoot) -> PreparedProductionDatabaseMigrationBackupStage {
        PreparedProductionDatabaseMigrationBackupStage::from_synthetic_temp_root(root.path())
            .unwrap()
    }

    #[test]
    fn genuine_full_integrity_source_enters_stage_and_preserves_exact_source() {
        let (source_root, handoff) = genuine_full_integrity_validated_migration_handoff_for_test();
        write_active_key_wrapper(source_root.path());
        let stage_root = StageRoot::create();
        let expected = handoff.source.preservation_evidence_for_test();
        let outcome = stage_encrypted_production_database_migration_backup(
            handoff,
            prepared(&stage_root),
            ProductionDatabaseMigrationBackupContext::from_synthetic_root(source_root.path()),
        );
        let ProductionDatabaseMigrationBackupStageOutcome::Verified(verified) = outcome else {
            panic!("genuine full-integrity source and independently recovered key must stage");
        };
        assert_eq!(
            verified.preservation_evidence_for_test(),
            (expected.0, expected.1)
        );
        assert!(verified.stage_path_for_test().exists());
        let mut header = [0_u8; 16];
        File::open(verified.stage_path_for_test())
            .unwrap()
            .read_exact(&mut header)
            .unwrap();
        assert_ne!(&header, PLAINTEXT_SQLITE_HEADER);
        assert!(matches!(
            verified.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        source_root.assert_exact_cleanup();
    }

    #[test]
    fn existing_destination_is_refused_and_authorization_is_destroyed() {
        let (source_root, handoff) = genuine_full_integrity_validated_migration_handoff_for_test();
        write_active_key_wrapper(source_root.path());
        let stage_root = StageRoot::create();
        let prepared = prepared(&stage_root);
        fs::write(prepared.path(), b"occupied").unwrap();
        let outcome = stage_encrypted_production_database_migration_backup(
            handoff,
            prepared,
            ProductionDatabaseMigrationBackupContext::from_synthetic_root(source_root.path()),
        );
        let ProductionDatabaseMigrationBackupStageOutcome::Failed(failure) = outcome else {
            panic!("existing destination must fail without replacement");
        };
        assert_eq!(
            failure.category(),
            ProductionDatabaseMigrationBackupStageError::DestinationAlreadyExists
        );
        assert!(!failure.retained_stage_is_created());
        assert!(!failure.source_close_was_required());
        assert_eq!(
            fs::read(stage_root.path().join(STAGE_LEAF_NAME)).unwrap(),
            b"occupied"
        );
        source_root.assert_exact_cleanup();
    }

    #[test]
    fn missing_active_key_fails_closed_and_retains_created_stage() {
        let (source_root, handoff) = genuine_full_integrity_validated_migration_handoff_for_test();
        let stage_root = StageRoot::create();
        let outcome = stage_encrypted_production_database_migration_backup(
            handoff,
            prepared(&stage_root),
            ProductionDatabaseMigrationBackupContext::from_synthetic_root(source_root.path()),
        );
        let ProductionDatabaseMigrationBackupStageOutcome::Failed(failure) = outcome else {
            panic!("missing independently loaded key must fail closed");
        };
        assert_eq!(
            failure.category(),
            ProductionDatabaseMigrationBackupStageError::ActiveDatabaseKeyUnavailable
        );
        assert!(failure.retained_stage_is_created());
        assert!(stage_root.path().join(STAGE_LEAF_NAME).exists());
        source_root.assert_exact_cleanup();
    }

    #[test]
    fn primary_failure_source_close_retry_can_only_close() {
        let (source_root, handoff) = genuine_full_integrity_validated_migration_handoff_for_test();
        let stage_root = StageRoot::create();
        let outcome = with_production_database_close_failure_injected(|| {
            stage_encrypted_production_database_migration_backup(
                handoff,
                prepared(&stage_root),
                ProductionDatabaseMigrationBackupContext::from_synthetic_root(source_root.path()),
            )
        });
        let ProductionDatabaseMigrationBackupStageOutcome::Failed(failure) = outcome else {
            panic!("missing key plus injected source close failure must retain both owners");
        };
        assert!(failure.source_close_was_required());
        let ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Closed(failure) =
            failure.retry_source_close()
        else {
            panic!("source close-only retry must close when injection is removed");
        };
        assert!(!failure.source_close_was_required());
        assert!(failure.retained_stage_is_created());
        source_root.assert_exact_cleanup();
    }

    #[test]
    fn backup_completion_rules_are_exact_and_do_not_retry_busy_or_locked() {
        let calls = std::cell::Cell::new(0);
        assert_eq!(
            drive_backup_steps(|| {
                calls.set(calls.get() + 1);
                Ok(if calls.get() == 1 {
                    (StepResult::More, 1)
                } else {
                    (StepResult::Done, 0)
                })
            }),
            Ok(())
        );
        assert_eq!(calls.get(), 2);
        for (step, expected) in [
            (
                StepResult::Busy,
                ProductionDatabaseMigrationBackupStageError::BackupBusy,
            ),
            (
                StepResult::Locked,
                ProductionDatabaseMigrationBackupStageError::BackupLocked,
            ),
            (
                StepResult::Done,
                ProductionDatabaseMigrationBackupStageError::BackupCompletionIncomplete,
            ),
        ] {
            let calls = std::cell::Cell::new(0);
            assert_eq!(
                drive_backup_steps(|| {
                    calls.set(calls.get() + 1);
                    Ok((step, 1))
                }),
                Err(expected)
            );
            assert_eq!(calls.get(), 1);
        }
        assert_eq!(
            drive_backup_steps(|| Err(
                ProductionDatabaseMigrationBackupStageError::BackupStepFailed
            )),
            Err(ProductionDatabaseMigrationBackupStageError::BackupStepFailed)
        );
    }

    #[test]
    fn encrypted_stage_refuses_no_key_and_wrong_key_metadata_observation() {
        let (source_root, handoff) = genuine_full_integrity_validated_migration_handoff_for_test();
        write_active_key_wrapper(source_root.path());
        let stage_root = StageRoot::create();
        let ProductionDatabaseMigrationBackupStageOutcome::Verified(verified) =
            stage_encrypted_production_database_migration_backup(
                handoff,
                prepared(&stage_root),
                ProductionDatabaseMigrationBackupContext::from_synthetic_root(source_root.path()),
            )
        else {
            panic!("stage fixture must verify");
        };
        let no_key =
            Connection::open_with_flags(verified.stage_path_for_test(), VERIFIER_OPEN_FLAGS)
                .unwrap();
        no_key
            .pragma_update(None, "cipher_log_level", "NONE")
            .unwrap();
        assert!(
            observe_production_database_fixed_metadata_and_headers_on_borrowed_connection(&no_key)
                .is_err()
        );
        no_key.close().unwrap();
        let wrong =
            Connection::open_with_flags(verified.stage_path_for_test(), VERIFIER_OPEN_FLAGS)
                .unwrap();
        wrong
            .pragma_update(None, "cipher_log_level", "NONE")
            .unwrap();
        let wrong_candidate =
            crate::database_key_protected_payload::DecodedDatabaseKeyCandidate::parse(
                crate::database_key_protected_payload::EncodedDatabaseKeyPayload::encode(
                    &DatabaseKey::from_bytes([0x91; 32]),
                    DatabaseKeyGenerationIdentifier::from_bytes(KEY_GENERATION).unwrap(),
                )
                .as_bytes(),
            )
            .unwrap();
        verified
            .source
            .with_migration_backup_source(|_, _, assessment| {
                let wrong_key = bind_database_key_candidate_to_trusted_installation_evidence(
                    wrong_candidate,
                    assessment,
                )
                .unwrap();
                apply_key(
                    &wrong,
                    &wrong_key,
                    ProductionDatabaseMigrationBackupStageError::DestinationVerificationFailed,
                )
                .unwrap();
            });
        assert!(
            observe_production_database_fixed_metadata_and_headers_on_borrowed_connection(&wrong)
                .is_err()
        );
        wrong.close().unwrap();
        assert!(matches!(
            verified.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        source_root.assert_exact_cleanup();
    }

    #[test]
    fn writer_and_verifier_close_failures_retain_only_close_owners() {
        let writer_root = StageRoot::create();
        let writer_stage = create_stage_file(prepared(&writer_root)).unwrap();
        let writer =
            Connection::open_with_flags(writer_stage.prepared.path(), DESTINATION_OPEN_FLAGS)
                .unwrap();
        let writer_failure = ProductionDatabaseMigrationBackupStageWriterCloseFailure {
            category: ProductionDatabaseMigrationBackupStageError::DestinationWriterCloseFailed,
            stage: writer_stage,
            writer,
            source_close: SourceCloseState::Closed,
        };
        let ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Closed(writer_failure) =
            writer_failure.retry_source_close()
        else {
            panic!("an already-closed source stays closed");
        };
        let ProductionDatabaseMigrationBackupStageWriterCloseRetryOutcome::Closed(failure) =
            writer_failure.retry_close()
        else {
            panic!("an unborrowed synthetic writer must close on retry");
        };
        assert_eq!(
            failure.category(),
            ProductionDatabaseMigrationBackupStageError::DestinationWriterCloseFailed
        );
        assert!(failure.retained_stage_is_created());

        let verifier_root = StageRoot::create();
        let verifier_stage = create_stage_file(prepared(&verifier_root)).unwrap();
        let verifier =
            Connection::open_with_flags(verifier_stage.prepared.path(), VERIFIER_OPEN_FLAGS)
                .unwrap();
        let verifier_failure = ProductionDatabaseMigrationBackupStageVerifierCloseFailure {
            category: ProductionDatabaseMigrationBackupStageError::DestinationVerifierCloseFailed,
            stage: verifier_stage,
            verifier,
            source_close: SourceCloseState::Closed,
        };
        let ProductionDatabaseMigrationBackupStageSourceCloseRetryOutcome::Closed(verifier_failure) =
            verifier_failure.retry_source_close()
        else {
            panic!("an already-closed source stays closed");
        };
        let ProductionDatabaseMigrationBackupStageVerifierCloseRetryOutcome::Closed(failure) =
            verifier_failure.retry_close()
        else {
            panic!("an unborrowed synthetic verifier must close on retry");
        };
        assert_eq!(
            failure.category(),
            ProductionDatabaseMigrationBackupStageError::DestinationVerifierCloseFailed
        );
        assert!(failure.retained_stage_is_created());
    }

    #[test]
    fn surface_is_opaque_one_shot_and_contains_no_publication_or_restore() {
        assert!(needs_drop::<PreparedProductionDatabaseMigrationBackupStage>());
        assert!(needs_drop::<ProductionDatabaseMigrationBackupContext>());
        assert!(needs_drop::<
            VerifiedEncryptedProductionDatabaseMigrationBackupStage,
        >());
        const SOURCE: &str = include_str!("production_database_migration_backup_stage.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        for duplicated_verification in [
            "PRAGMA cipher_integrity_check",
            "PRAGMA main.integrity_check",
            "church_app_database_metadata",
            "RawDatabaseMetadataRow",
            "OwnedMetadataValue",
            "METADATA_QUERY",
            "METADATA_COLUMN_COUNT",
        ] {
            assert!(!production.contains(duplicated_verification));
        }
        for canonical_seam in [
            "validate_production_database_cipher_integrity_on_borrowed_connection(connection)",
            "validate_production_database_full_integrity_on_borrowed_connection(connection)",
            "observe_production_database_fixed_metadata_and_headers_on_borrowed_connection(connection)",
        ] {
            assert!(production.contains(canonical_seam));
        }
        assert!(production.contains("Backup::new(source, destination)"));
        assert!(production.contains("OpenFlags::SQLITE_OPEN_READ_WRITE"));
        assert!(!production.contains("SQLITE_OPEN_CREATE"));
        assert!(!production.contains("tauri::command"));
        assert!(!production.contains("schema version 2"));
        assert!(!production.contains("CREATE TABLE"));
        assert!(!production.contains("DELETE FROM"));
        assert!(!production.contains("recoverable"));
        for excluded in [
            "publish_stage",
            "delete_stage",
            "restore_stage",
            "RetentionPolicy",
        ] {
            assert!(
                !production.contains(excluded),
                "excluded surface: {excluded}"
            );
        }
        for close_owner in [
            "pub(crate) struct ProductionDatabaseMigrationBackupStageWriterCloseFailure {",
            "pub(crate) struct ProductionDatabaseMigrationBackupStageVerifierCloseFailure {",
        ] {
            let fields = production
                .split_once(close_owner)
                .unwrap()
                .1
                .split_once("\n}")
                .unwrap()
                .0;
            assert!(!fields.contains("authorization"));
            assert!(!fields.contains("source:"));
        }
        assert_eq!(production.matches("Backup::new(").count(), 1);
        assert_eq!(
            production
                .matches("recover_database_key_candidate_from_loaded_wrapper(&loaded)")
                .count(),
            1
        );
    }
}
