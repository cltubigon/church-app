//! Final keyless composition of the two independently verified recovery sets.

use std::fmt;

use super::*;

use crate::{
    application_lifecycle::{
        RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup, WritableMigrationKeyAuthority,
    },
    production_database_connection_handoff::{
        ProductionDatabaseConnectionCloseFailure, ProductionDatabaseConnectionCloseOutcome,
        WritableV1MigrationDatabase, WritableV1MigrationDatabaseCloseFailure,
        WritableV1MigrationDatabaseCloseRetryOutcome, WritableV1MigrationDatabaseOpenError,
        WritableV1MigrationDatabaseOpenOutcome, open_writable_v1_migration_database,
    },
    storage_foundation::ProductionDatabasePath,
};

pub(crate) struct TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup {
    second_complete_set: SecondCompleteRecoverySetVerified,
    _final_layer_d_complete: (),
}

pub(crate) struct MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup
{
    final_recovery_proof: TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
    _fresh_native_confirmation: (),
}

pub(crate) struct WritableV1MigrationPreparedProductionDatabase {
    confirmed_recovery:
        MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
    database: WritableV1MigrationDatabase,
    _transaction_not_started: (),
}

pub(crate) struct WritableV1MigrationPreparationFailure {
    confirmed_recovery:
        MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
    category: WritableV1MigrationPreparationError,
}

pub(crate) struct WritableV1MigrationSourceCloseFailure {
    confirmed_recovery:
        MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
    path: ProductionDatabasePath,
    key_authority: WritableMigrationKeyAuthority,
    close_failure: ProductionDatabaseConnectionCloseFailure,
}

pub(crate) struct WritableV1MigrationOpenedCloseFailure {
    confirmed_recovery:
        MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
    close_failure: WritableV1MigrationDatabaseCloseFailure,
}

pub(crate) struct WritableV1MigrationPreparedShutdownCloseFailure {
    confirmed_recovery:
        MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
    close_failure: ProductionDatabaseConnectionCloseFailure,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum WritableV1MigrationPreparationError {
    FinalRecoverySourceRevalidationFailed,
    DatabaseKeyRecoveryFailed,
    ProductionFileChangedOrUnavailable,
    WritableOpenFailed,
    DatabaseKeyApplicationFailed,
    ExactV1RevalidationFailed,
    IntegrityFailed,
    VersionClassificationMismatch,
}

#[must_use = "the writable V1 migration preparation outcome must be handled"]
#[allow(clippy::large_enum_variant)]
pub(crate) enum WritableV1MigrationPreparationOutcome {
    Prepared(WritableV1MigrationPreparedProductionDatabase),
    Failed(WritableV1MigrationPreparationFailure),
    SourceCloseFailed(WritableV1MigrationSourceCloseFailure),
    WritableCloseFailed(WritableV1MigrationOpenedCloseFailure),
}

#[must_use = "the writable prepared shutdown outcome must be handled"]
#[allow(clippy::large_enum_variant)]
pub(crate) enum WritableV1MigrationPreparedShutdownOutcome {
    Closed(RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup),
    CloseFailed(WritableV1MigrationPreparedShutdownCloseFailure),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FinalTwoSetVerificationError {
    SourceUnavailableOrChanged,
    DestinationChangedOrInconsistent,
    DirectoryLayoutInvalid,
    PriorArtifactChangedOrInvalid,
    SetCorrespondenceFailed,
}

pub(crate) struct FinalTwoSetVerificationFailure {
    second_complete_set: SecondCompleteRecoverySetVerified,
    error: FinalTwoSetVerificationError,
}

#[must_use = "the final two-set verification outcome must be handled"]
pub(crate) enum FinalTwoSetVerificationOutcome {
    Verified(TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup),
    Failed(FinalTwoSetVerificationFailure),
}

impl fmt::Debug for TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup([REDACTED])",
        )
    }
}

impl fmt::Debug
    for MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup([REDACTED])",
        )
    }
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
    WritableV1MigrationPreparedProductionDatabase,
    "WritableV1MigrationPreparedProductionDatabase"
);
redacted_debug!(
    WritableV1MigrationPreparationFailure,
    "WritableV1MigrationPreparationFailure"
);
redacted_debug!(
    WritableV1MigrationSourceCloseFailure,
    "WritableV1MigrationSourceCloseFailure"
);
redacted_debug!(
    WritableV1MigrationOpenedCloseFailure,
    "WritableV1MigrationOpenedCloseFailure"
);
redacted_debug!(
    WritableV1MigrationPreparedShutdownCloseFailure,
    "WritableV1MigrationPreparedShutdownCloseFailure"
);

impl fmt::Debug for WritableV1MigrationPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FinalRecoverySourceRevalidationFailed => "FinalRecoverySourceRevalidationFailed",
            Self::DatabaseKeyRecoveryFailed => "DatabaseKeyRecoveryFailed",
            Self::ProductionFileChangedOrUnavailable => "ProductionFileChangedOrUnavailable",
            Self::WritableOpenFailed => "WritableOpenFailed",
            Self::DatabaseKeyApplicationFailed => "DatabaseKeyApplicationFailed",
            Self::ExactV1RevalidationFailed => "ExactV1RevalidationFailed",
            Self::IntegrityFailed => "IntegrityFailed",
            Self::VersionClassificationMismatch => "VersionClassificationMismatch",
        })
    }
}

impl fmt::Debug for FinalTwoSetVerificationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FinalTwoSetVerificationFailure([REDACTED])")
    }
}

impl fmt::Debug for FinalTwoSetVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceUnavailableOrChanged => "SourceUnavailableOrChanged",
            Self::DestinationChangedOrInconsistent => "DestinationChangedOrInconsistent",
            Self::DirectoryLayoutInvalid => "DirectoryLayoutInvalid",
            Self::PriorArtifactChangedOrInvalid => "PriorArtifactChangedOrInvalid",
            Self::SetCorrespondenceFailed => "SetCorrespondenceFailed",
        })
    }
}

fn fail(
    second_complete_set: SecondCompleteRecoverySetVerified,
    error: FinalTwoSetVerificationError,
) -> FinalTwoSetVerificationOutcome {
    FinalTwoSetVerificationOutcome::Failed(FinalTwoSetVerificationFailure {
        second_complete_set,
        error,
    })
}

fn map_predecessor_error(
    error: SecondRecoveryManifestArtifactPublicationError,
) -> FinalTwoSetVerificationError {
    match error {
        SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged => {
            FinalTwoSetVerificationError::SourceUnavailableOrChanged
        }
        SecondRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent => {
            FinalTwoSetVerificationError::DestinationChangedOrInconsistent
        }
        _ => FinalTwoSetVerificationError::PriorArtifactChangedOrInvalid,
    }
}

fn observe_final_layouts(
    second_complete_set: &SecondCompleteRecoverySetVerified,
) -> Result<
    (
        super::super::super::super::ExactLayoutState,
        super::super::super::super::ExactLayoutState,
    ),
    FinalTwoSetVerificationError,
> {
    let destinations = &second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    let first =
        super::super::super::super::exact_layout(&destinations.first.initial_child.normalized_path)
            .map_err(|_| FinalTwoSetVerificationError::DirectoryLayoutInvalid)?;
    let second = super::super::super::super::exact_layout(
        &destinations.second.initial_child.normalized_path,
    )
    .map_err(|_| FinalTwoSetVerificationError::DirectoryLayoutInvalid)?;
    Ok((first, second))
}

fn retained_recovery_source_mut(
    proof: &mut TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
) -> &mut RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup {
    &mut proof
        .second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
}

fn revalidate_final_recovery_proof_for_writable_preparation(
    proof: &mut TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
) -> Result<(), FinalTwoSetVerificationError> {
    let second_complete_set = &mut proof.second_complete_set;
    let expected_database = second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .observe_recovery_database_source()
        .map_err(|_| FinalTwoSetVerificationError::SourceUnavailableOrChanged)?;
    let expected_envelope = second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .with_verified_recovery_envelope_bytes(|bytes| *bytes)
        .map_err(|_| FinalTwoSetVerificationError::SourceUnavailableOrChanged)?;
    let expected_manifest = second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .prepare_recovery_set_manifest_v1()
        .map_err(|_| FinalTwoSetVerificationError::SourceUnavailableOrChanged)?
        .encode();

    super::super::revalidate_predecessor(
        &mut second_complete_set.published.prior,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &expected_manifest,
    )
    .map_err(map_predecessor_error)?;
    let destinations = &mut second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    second_complete_set
        .published
        .second_manifest
        .revalidate(
            &destinations.second.initial_child.identity,
            &destinations.second.initial_child.normalized_path,
            &expected_manifest,
        )
        .map_err(|_| FinalTwoSetVerificationError::PriorArtifactChangedOrInvalid)?;
    destinations
        .revalidate()
        .map_err(|_| FinalTwoSetVerificationError::DestinationChangedOrInconsistent)?;
    let before_layouts = observe_final_layouts(second_complete_set)?;

    let source = &second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source;
    if source.observe_recovery_database_source().as_ref() != Ok(&expected_database)
        || source
            .with_verified_recovery_envelope_bytes(|bytes| *bytes)
            .as_ref()
            != Ok(&expected_envelope)
        || !source
            .prepare_recovery_set_manifest_v1()
            .is_ok_and(|manifest| manifest.encode() == expected_manifest)
    {
        return Err(FinalTwoSetVerificationError::SourceUnavailableOrChanged);
    }
    let after_layouts = observe_final_layouts(second_complete_set)?;
    if before_layouts != after_layouts {
        return Err(FinalTwoSetVerificationError::DirectoryLayoutInvalid);
    }
    Ok(())
}

pub(crate) fn verify_final_two_recovery_sets(
    mut second_complete_set: SecondCompleteRecoverySetVerified,
) -> FinalTwoSetVerificationOutcome {
    let expected_database = match second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .observe_recovery_database_source()
    {
        Ok(observation) => observation,
        Err(_) => {
            return fail(
                second_complete_set,
                FinalTwoSetVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_envelope = match second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .with_verified_recovery_envelope_bytes(|bytes| *bytes)
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return fail(
                second_complete_set,
                FinalTwoSetVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_manifest = match second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .prepare_recovery_set_manifest_v1()
    {
        Ok(manifest) => manifest.encode(),
        Err(_) => {
            return fail(
                second_complete_set,
                FinalTwoSetVerificationError::SourceUnavailableOrChanged,
            );
        }
    };

    if let Err(error) = super::super::revalidate_predecessor(
        &mut second_complete_set.published.prior,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &expected_manifest,
    ) {
        return fail(second_complete_set, map_predecessor_error(error));
    }

    let destinations = &mut second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    if second_complete_set
        .published
        .second_manifest
        .revalidate(
            &destinations.second.initial_child.identity,
            &destinations.second.initial_child.normalized_path,
            &expected_manifest,
        )
        .is_err()
    {
        return fail(
            second_complete_set,
            FinalTwoSetVerificationError::PriorArtifactChangedOrInvalid,
        );
    }
    if destinations.revalidate().is_err() {
        return fail(
            second_complete_set,
            FinalTwoSetVerificationError::DestinationChangedOrInconsistent,
        );
    }

    let before_layouts = match observe_final_layouts(&second_complete_set) {
        Ok(layouts) => layouts,
        Err(error) => return fail(second_complete_set, error),
    };

    let source = &second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source;
    let source_still_matches = source.observe_recovery_database_source().as_ref()
        == Ok(&expected_database)
        && source
            .with_verified_recovery_envelope_bytes(|bytes| *bytes)
            .as_ref()
            == Ok(&expected_envelope)
        && source
            .prepare_recovery_set_manifest_v1()
            .is_ok_and(|manifest| manifest.encode() == expected_manifest);
    if !source_still_matches {
        return fail(
            second_complete_set,
            FinalTwoSetVerificationError::SourceUnavailableOrChanged,
        );
    }

    if let Err(error) = super::super::revalidate_predecessor(
        &mut second_complete_set.published.prior,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &expected_manifest,
    ) {
        return fail(second_complete_set, map_predecessor_error(error));
    }
    let destinations = &mut second_complete_set
        .published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    if second_complete_set
        .published
        .second_manifest
        .revalidate(
            &destinations.second.initial_child.identity,
            &destinations.second.initial_child.normalized_path,
            &expected_manifest,
        )
        .is_err()
    {
        return fail(
            second_complete_set,
            FinalTwoSetVerificationError::PriorArtifactChangedOrInvalid,
        );
    }
    if destinations.revalidate().is_err() {
        return fail(
            second_complete_set,
            FinalTwoSetVerificationError::DestinationChangedOrInconsistent,
        );
    }
    let after_layouts = match observe_final_layouts(&second_complete_set) {
        Ok(layouts) => layouts,
        Err(error) => return fail(second_complete_set, error),
    };
    if before_layouts != after_layouts {
        return fail(
            second_complete_set,
            FinalTwoSetVerificationError::DirectoryLayoutInvalid,
        );
    }

    FinalTwoSetVerificationOutcome::Verified(
        TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup {
            second_complete_set,
            _final_layer_d_complete: (),
        },
    )
}

impl FinalTwoSetVerificationFailure {
    pub(crate) fn category(&self) -> FinalTwoSetVerificationError {
        self.error
    }

    pub(crate) fn retry(self) -> FinalTwoSetVerificationOutcome {
        verify_final_two_recovery_sets(self.second_complete_set)
    }

    pub(crate) fn abandon_published_destinations_and_retain_source(
        self,
    ) -> crate::application_lifecycle::RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup
    {
        self.second_complete_set
            .abandon_published_destination_and_retain_source()
    }
}

impl TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup {
    pub(crate) fn confirm_migration_execution(
        self,
    ) -> MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup
    {
        MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup {
            final_recovery_proof: self,
            _fresh_native_confirmation: (),
        }
    }

    pub(crate) fn abandon_published_destinations_and_retain_source(
        self,
    ) -> crate::application_lifecycle::RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup
    {
        self.second_complete_set
            .abandon_published_destination_and_retain_source()
    }
}

impl MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup {
    pub(crate) fn prepare_writable_v1_migration(
        mut self,
        path: Option<ProductionDatabasePath>,
    ) -> WritableV1MigrationPreparationOutcome {
        let Some(path) = path else {
            return WritableV1MigrationPreparationOutcome::Failed(
                WritableV1MigrationPreparationFailure {
                    confirmed_recovery: self,
                    category:
                        WritableV1MigrationPreparationError::ProductionFileChangedOrUnavailable,
                },
            );
        };
        if revalidate_final_recovery_proof_for_writable_preparation(&mut self.final_recovery_proof)
            .is_err()
        {
            return WritableV1MigrationPreparationOutcome::Failed(
                WritableV1MigrationPreparationFailure {
                    confirmed_recovery: self,
                    category:
                        WritableV1MigrationPreparationError::FinalRecoverySourceRevalidationFailed,
                },
            );
        }
        let key_authority = match retained_recovery_source_mut(&mut self.final_recovery_proof)
            .recover_writable_migration_key_authority()
        {
            Ok(authority) => authority,
            Err(()) => {
                return WritableV1MigrationPreparationOutcome::Failed(
                    WritableV1MigrationPreparationFailure {
                        confirmed_recovery: self,
                        category: WritableV1MigrationPreparationError::DatabaseKeyRecoveryFailed,
                    },
                );
            }
        };
        let read_only_source = retained_recovery_source_mut(&mut self.final_recovery_proof)
            .detach_read_only_migration_source();
        match read_only_source.close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                continue_writable_v1_migration_open(self, path, key_authority)
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(close_failure) => {
                WritableV1MigrationPreparationOutcome::SourceCloseFailed(
                    WritableV1MigrationSourceCloseFailure {
                        confirmed_recovery: self,
                        path,
                        key_authority,
                        close_failure,
                    },
                )
            }
        }
    }

    pub(crate) fn abandon_published_destinations_and_retain_source(
        self,
    ) -> crate::application_lifecycle::RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup
    {
        self.final_recovery_proof
            .abandon_published_destinations_and_retain_source()
    }
}

fn map_writable_open_error(
    error: WritableV1MigrationDatabaseOpenError,
) -> WritableV1MigrationPreparationError {
    match error {
        WritableV1MigrationDatabaseOpenError::ProductionFileChangedOrUnavailable => {
            WritableV1MigrationPreparationError::ProductionFileChangedOrUnavailable
        }
        WritableV1MigrationDatabaseOpenError::WritableOpenFailed => {
            WritableV1MigrationPreparationError::WritableOpenFailed
        }
        WritableV1MigrationDatabaseOpenError::DatabaseKeyApplicationFailed => {
            WritableV1MigrationPreparationError::DatabaseKeyApplicationFailed
        }
        WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed => {
            WritableV1MigrationPreparationError::ExactV1RevalidationFailed
        }
        WritableV1MigrationDatabaseOpenError::IntegrityFailed => {
            WritableV1MigrationPreparationError::IntegrityFailed
        }
        WritableV1MigrationDatabaseOpenError::VersionClassificationMismatch(_) => {
            WritableV1MigrationPreparationError::VersionClassificationMismatch
        }
    }
}

fn continue_writable_v1_migration_open(
    confirmed_recovery: MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
    path: ProductionDatabasePath,
    key_authority: WritableMigrationKeyAuthority,
) -> WritableV1MigrationPreparationOutcome {
    let (key, expected_metadata, expected_file_identity) = key_authority.into_parts();
    match open_writable_v1_migration_database(path, expected_file_identity, expected_metadata, key)
    {
        WritableV1MigrationDatabaseOpenOutcome::Prepared(database) => {
            WritableV1MigrationPreparationOutcome::Prepared(
                WritableV1MigrationPreparedProductionDatabase {
                    confirmed_recovery,
                    database,
                    _transaction_not_started: (),
                },
            )
        }
        WritableV1MigrationDatabaseOpenOutcome::Failed(category) => {
            WritableV1MigrationPreparationOutcome::Failed(WritableV1MigrationPreparationFailure {
                confirmed_recovery,
                category: map_writable_open_error(category),
            })
        }
        WritableV1MigrationDatabaseOpenOutcome::CloseFailed(close_failure) => {
            WritableV1MigrationPreparationOutcome::WritableCloseFailed(
                WritableV1MigrationOpenedCloseFailure {
                    confirmed_recovery,
                    close_failure,
                },
            )
        }
    }
}

impl WritableV1MigrationPreparationFailure {
    pub(crate) fn category(&self) -> WritableV1MigrationPreparationError {
        self.category
    }

    pub(crate) fn abandon_published_destinations_and_retain_source(
        self,
    ) -> RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup {
        self.confirmed_recovery
            .abandon_published_destinations_and_retain_source()
    }
}

impl WritableV1MigrationSourceCloseFailure {
    pub(crate) fn retry_close(self) -> WritableV1MigrationPreparationOutcome {
        let Self {
            confirmed_recovery,
            path,
            key_authority,
            close_failure,
        } = self;
        match close_failure.retry_close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                continue_writable_v1_migration_open(confirmed_recovery, path, key_authority)
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(close_failure) => {
                WritableV1MigrationPreparationOutcome::SourceCloseFailed(Self {
                    confirmed_recovery,
                    path,
                    key_authority,
                    close_failure,
                })
            }
        }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn retry_close_for_shutdown(
        self,
    ) -> Result<RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup, Self> {
        let Self {
            confirmed_recovery,
            path,
            key_authority,
            close_failure,
        } = self;
        match close_failure.retry_close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                drop(path);
                drop(key_authority);
                Ok(confirmed_recovery.abandon_published_destinations_and_retain_source())
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(close_failure) => Err(Self {
                confirmed_recovery,
                path,
                key_authority,
                close_failure,
            }),
        }
    }
}

impl WritableV1MigrationOpenedCloseFailure {
    #[allow(clippy::result_large_err)]
    pub(crate) fn retry_close_for_shutdown(
        self,
    ) -> Result<RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup, Self> {
        let Self {
            confirmed_recovery,
            close_failure,
        } = self;
        match close_failure.retry_close() {
            WritableV1MigrationDatabaseCloseRetryOutcome::Closed => {
                Ok(confirmed_recovery.abandon_published_destinations_and_retain_source())
            }
            WritableV1MigrationDatabaseCloseRetryOutcome::Failed(close_failure) => Err(Self {
                confirmed_recovery,
                close_failure,
            }),
        }
    }
}

impl WritableV1MigrationPreparedProductionDatabase {
    pub(crate) fn close_for_shutdown(self) -> WritableV1MigrationPreparedShutdownOutcome {
        let Self {
            confirmed_recovery,
            database,
            _transaction_not_started: (),
        } = self;
        match database.close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                WritableV1MigrationPreparedShutdownOutcome::Closed(
                    confirmed_recovery.abandon_published_destinations_and_retain_source(),
                )
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(close_failure) => {
                WritableV1MigrationPreparedShutdownOutcome::CloseFailed(
                    WritableV1MigrationPreparedShutdownCloseFailure {
                        confirmed_recovery,
                        close_failure,
                    },
                )
            }
        }
    }
}

impl WritableV1MigrationPreparedShutdownCloseFailure {
    pub(crate) fn retry_close(self) -> WritableV1MigrationPreparedShutdownOutcome {
        let Self {
            confirmed_recovery,
            close_failure,
        } = self;
        match close_failure.retry_close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                WritableV1MigrationPreparedShutdownOutcome::Closed(
                    confirmed_recovery.abandon_published_destinations_and_retain_source(),
                )
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(close_failure) => {
                WritableV1MigrationPreparedShutdownOutcome::CloseFailed(Self {
                    confirmed_recovery,
                    close_failure,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::needs_drop;

    #[test]
    fn signature_owner_failure_and_redaction_are_narrow_and_keyless() {
        assert!(needs_drop::<
            TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
        >());
        assert!(needs_drop::<FinalTwoSetVerificationFailure>());
        assert!(needs_drop::<
            MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
        >());
        let source = include_str!("final_two.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(production.contains("mut second_complete_set: SecondCompleteRecoverySetVerified,"));
        let success = production
            .split_once(
                "pub(crate) struct TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup {",
            )
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        assert!(success.contains("second_complete_set: SecondCompleteRecoverySetVerified"));
        assert!(success.contains("_final_layer_d_complete: ()"));
        for forbidden in [
            "ReenteredMigrationRecoveryKeyCustodyV1",
            "MigrationRecoveryKey",
            "DatabaseKey",
            "PathBuf",
            "Connection",
            "serde",
            "tauri::command",
            "remove_file",
            "remove_dir",
        ] {
            assert!(
                !success.contains(forbidden),
                "unexpected authority: {forbidden}"
            );
        }
        assert!(production.contains("FinalTwoSetVerificationFailure([REDACTED])"));
        assert!(production.contains("retry(self)"));
    }

    #[test]
    fn execution_confirmation_owner_is_single_use_process_local_and_retains_final_proof() {
        let source = include_str!("final_two.rs");
        let owner = source
            .split_once("pub(crate) struct MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup")
            .unwrap()
            .1
            .split_once("}")
            .unwrap()
            .0;
        assert!(owner.contains(
            "final_recovery_proof: TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup"
        ));
        for forbidden in ["Clone", "Copy", "Serialize", "Connection", "DatabaseKey"] {
            assert!(!owner.contains(forbidden));
        }

        let transition = source
            .split_once("pub(crate) fn confirm_migration_execution(")
            .unwrap()
            .1
            .split_once("pub(crate) fn abandon_published_destinations_and_retain_source")
            .unwrap()
            .0;
        assert!(transition.contains("final_recovery_proof: self"));
        assert!(!transition.contains("clone"));
        assert!(!transition.contains("serialize"));
    }

    #[test]
    fn writable_preparation_consumes_only_confirmed_owner_in_required_order() {
        let source = include_str!("final_two.rs");
        let transition = source
            .split_once(
                "impl MigrationExecutionConfirmedTwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup",
            )
            .unwrap()
            .1
            .split_once("impl WritableV1MigrationPreparationFailure")
            .unwrap()
            .0;
        let revalidate = transition
            .find("revalidate_final_recovery_proof_for_writable_preparation")
            .unwrap();
        let recover = transition
            .find("recover_writable_migration_key_authority")
            .unwrap();
        let detach = transition
            .find("detach_read_only_migration_source")
            .unwrap();
        let close = transition.find("read_only_source.close()").unwrap();
        let open = transition
            .find("continue_writable_v1_migration_open")
            .unwrap();
        assert!(revalidate < recover && recover < detach && detach < close && close < open);
        assert!(!transition.contains("confirm_migration_execution"));
        assert!(!transition.contains("clone"));
    }

    #[test]
    fn writable_prepared_owner_retains_confirmation_and_no_key() {
        let source = include_str!("final_two.rs");
        let owner = source
            .split_once("pub(crate) struct WritableV1MigrationPreparedProductionDatabase")
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        assert!(owner.contains("confirmed_recovery:"));
        assert!(owner.contains("database: WritableV1MigrationDatabase"));
        assert!(owner.contains("_transaction_not_started: ()"));
        for forbidden in ["GenerationBoundDatabaseKey", "Clone", "Copy", "Serialize"] {
            assert!(!owner.contains(forbidden));
        }
    }

    #[test]
    fn source_and_writable_close_failures_are_close_only_and_shutdown_safe() {
        let source = include_str!("final_two.rs");
        let source_retry = source
            .split_once("impl WritableV1MigrationSourceCloseFailure")
            .unwrap()
            .1
            .split_once("impl WritableV1MigrationOpenedCloseFailure")
            .unwrap()
            .0;
        assert!(source_retry.contains("close_failure.retry_close()"));
        assert!(source_retry.contains("drop(key_authority)"));
        assert!(!source_retry.contains("open_writable_v1_migration_database"));

        let shutdown = source
            .split_once("impl WritableV1MigrationPreparedProductionDatabase")
            .unwrap()
            .1
            .split_once("#[cfg(test)]")
            .unwrap()
            .0;
        let close = shutdown.find("database.close()").unwrap();
        let abandon = shutdown
            .find("abandon_published_destinations_and_retain_source")
            .unwrap();
        assert!(close < abandon);
        for forbidden in ["BEGIN", "CREATE TABLE", "UPDATE ", "user_version = 2"] {
            assert!(!shutdown.contains(forbidden));
        }
    }

    #[test]
    fn failure_and_success_abandonment_are_consuming_source_only_and_filesystem_inert() {
        let source = include_str!("final_two.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        for owner in [
            "impl FinalTwoSetVerificationFailure",
            "impl TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup",
        ] {
            let abandonment = production.split_once(owner).unwrap().1;
            assert!(abandonment.contains("abandon_published_destinations_and_retain_source"));
            assert!(abandonment.contains("self.second_complete_set"));
            assert!(abandonment.contains("abandon_published_destination_and_retain_source"));
        }
        for forbidden in [
            "remove_file",
            "remove_dir",
            "rename",
            "truncate",
            "overwrite",
        ] {
            assert!(!production.contains(forbidden));
        }
    }

    #[test]
    fn composition_reuses_canonical_non_secret_revalidation_only() {
        let source = include_str!("final_two.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        for required in [
            "observe_recovery_database_source",
            "with_verified_recovery_envelope_bytes",
            "prepare_recovery_set_manifest_v1",
            "revalidate_predecessor",
            ".second_manifest\n        .revalidate",
            "destinations.revalidate()",
            "exact_layout",
            "destinations.first.initial_child.normalized_path",
            "destinations.second.initial_child.normalized_path",
        ] {
            assert!(
                production.contains(required),
                "missing continuity check: {required}"
            );
        }
        for forbidden in [
            "validate_checksum_and_association",
            "into_recovery_key_material",
            "open_migration_recovery_envelope_v1",
            "bind_recovered_database_key_candidate",
            "open_production_database_migration_backup_stage_verifier",
            "validate_production_database_cipher_integrity",
            "fs::copy",
            "std::fs::copy",
        ] {
            assert!(
                !production.contains(forbidden),
                "repeated or peer authority: {forbidden}"
            );
        }
        assert_eq!(production.matches("observe_final_layouts").count(), 5);
        assert_eq!(production.matches("revalidate_predecessor(").count(), 3);
    }

    #[test]
    fn error_taxonomy_is_fixed_and_redacted() {
        assert_eq!(
            format!(
                "{:?}",
                FinalTwoSetVerificationError::SourceUnavailableOrChanged
            ),
            "SourceUnavailableOrChanged"
        );
        assert_eq!(
            format!(
                "{:?}",
                FinalTwoSetVerificationError::DestinationChangedOrInconsistent
            ),
            "DestinationChangedOrInconsistent"
        );
        assert_eq!(
            format!("{:?}", FinalTwoSetVerificationError::DirectoryLayoutInvalid),
            "DirectoryLayoutInvalid"
        );
        assert_eq!(
            format!(
                "{:?}",
                FinalTwoSetVerificationError::PriorArtifactChangedOrInvalid
            ),
            "PriorArtifactChangedOrInvalid"
        );
        assert_eq!(
            format!(
                "{:?}",
                FinalTwoSetVerificationError::SetCorrespondenceFailed
            ),
            "SetCorrespondenceFailed"
        );
    }
}
