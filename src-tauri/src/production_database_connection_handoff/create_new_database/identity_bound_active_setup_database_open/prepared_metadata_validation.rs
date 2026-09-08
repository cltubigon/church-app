//! Setup-only validation of the identity-bound active canonical database.
//!
//! One database lifetime is preserved across canonical integrity, live
//! header/metadata validation, and exact prepared-metadata equality. This does
//! no correspondence, freshness, publication advancement, observation, setup
//! completion, startup authorization, operational use, reopen, or reload work.

use std::fmt;

use crate::{
    database_freshness_classification::NormalizedFreshnessAnchorObservation,
    database_metadata_contract::DatabaseMetadataContractV1,
    first_time_setup_publication::FirstTimeSetupPublicationStateMachine,
    installation_evidence_protection::TrustedCurrentInstallationEvidenceAssessment,
    production_database_connection_handoff::{
        LiveMetadataAndHeaderValidatedProductionDatabaseConnection,
        LiveMetadataAndHeaderValidationCloseFailure, LiveMetadataAndHeaderValidationError,
        LiveMetadataAndHeaderValidationOutcome, ProductionDatabaseConnectionCloseFailure,
        ProductionDatabaseConnectionCloseOutcome, ProductionDatabaseValidationCloseFailure,
        ProductionDatabaseValidationError, ProductionDatabaseValidationOutcome,
        ReadabilityAndIntegrityValidatedProductionDatabaseConnection,
        validate_production_database_live_metadata_and_headers,
        validate_production_database_readability_and_integrity,
    },
    storage_foundation::{
        DatabaseKeyPersistencePaths, FreshnessAnchorPersistencePaths,
        InstallationEvidencePersistencePaths,
    },
};

use super::{IdentityBoundActiveSetupDatabase, ProtectedArtifactStagingAuthority};

#[path = "prepared_metadata_validation/correspondence_and_freshness_validation.rs"]
mod correspondence_and_freshness_validation;

pub(crate) use correspondence_and_freshness_validation::{
    ActiveSetupCorrespondenceAndFreshnessValidationError,
    CanonicalInstallationObservationAcceptedFirstTimeSetupOperation,
    CorrespondenceAndFreshnessValidatedActiveSetupDatabase,
    CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation,
    FinalActiveArtifactsVerifiedFirstTimeSetupOperation, FinalActiveSetupDatabaseCloseFailure,
    FinalActiveSetupDatabaseCloseOutcome, FinalActiveSetupDatabaseCloseRetryOutcome,
    FirstTimeSetupCanonicalInstallationObservationError,
    FirstTimeSetupFinalActiveArtifactsVerificationStateError,
    FirstTimeSetupReadyForCompletionError, ReadyForSetupCompletionFirstTimeSetupOperation,
    accept_canonical_installation_observation_for_first_time_setup,
    advance_final_active_artifacts_verified_for_first_time_setup,
    advance_ready_for_setup_completion_for_first_time_setup,
    close_and_preserve_correspondence_and_freshness_validated_active_setup_database,
    validate_active_setup_database_correspondence_and_freshness,
};

/// The same validated live database plus every setup branch needed by the next
/// correspondence and freshness slice.
#[must_use = "the validated setup database and retained trust branches must remain owned"]
pub(crate) struct PreparedMetadataValidatedActiveSetupDatabase {
    database: LiveMetadataAndHeaderValidatedProductionDatabaseConnection,
    prepared_database_metadata: DatabaseMetadataContractV1,
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
    trusted_evidence_assessment: TrustedCurrentInstallationEvidenceAssessment,
    normalized_freshness_observation: NormalizedFreshnessAnchorObservation,
    machine: FirstTimeSetupPublicationStateMachine,
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for PreparedMetadataValidatedActiveSetupDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedMetadataValidatedActiveSetupDatabase([REDACTED])")
    }
}

/// Terminal categories for the consumed setup operation. Canonical close
/// failures retain their exact ownership-bearing owners.
#[must_use = "a validation close failure may retain the live database lifetime"]
pub(crate) enum ActiveSetupDatabaseValidationError {
    Integrity(ProductionDatabaseValidationError),
    LiveMetadataAndHeaders(LiveMetadataAndHeaderValidationError),
    PreparedMetadataMismatch,
    IntegrityCloseFailed(ProductionDatabaseValidationCloseFailure),
    LiveMetadataAndHeadersCloseFailed(LiveMetadataAndHeaderValidationCloseFailure),
    PreparedMetadataMismatchCloseFailed(ActiveSetupPreparedMetadataMismatchCloseFailure),
}

impl fmt::Debug for ActiveSetupDatabaseValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integrity(category) => {
                formatter.debug_tuple("Integrity").field(category).finish()
            }
            Self::LiveMetadataAndHeaders(category) => formatter
                .debug_tuple("LiveMetadataAndHeaders")
                .field(category)
                .finish(),
            Self::PreparedMetadataMismatch => formatter.write_str("PreparedMetadataMismatch"),
            Self::IntegrityCloseFailed(_) => {
                formatter.write_str("IntegrityCloseFailed([REDACTED])")
            }
            Self::LiveMetadataAndHeadersCloseFailed(_) => {
                formatter.write_str("LiveMetadataAndHeadersCloseFailed([REDACTED])")
            }
            Self::PreparedMetadataMismatchCloseFailed(_) => {
                formatter.write_str("PreparedMetadataMismatchCloseFailed([REDACTED])")
            }
        }
    }
}

/// The mismatch category is fixed by the type; only lifetime ownership remains.
#[must_use = "the mismatch database lifetime must remain owned until closed"]
pub(crate) struct ActiveSetupPreparedMetadataMismatchCloseFailure {
    failure: ProductionDatabaseConnectionCloseFailure,
}

impl fmt::Debug for ActiveSetupPreparedMetadataMismatchCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveSetupPreparedMetadataMismatchCloseFailure([REDACTED])")
    }
}

impl ActiveSetupPreparedMetadataMismatchCloseFailure {
    /// Retries only canonical close and preserves the original mismatch.
    pub(crate) fn retry_close(self) -> ActiveSetupDatabaseValidationError {
        mismatch_close_result(self.failure.retry_close())
    }
}

/// Consumes the sole identity-bound owner and applies the fixed validation
/// chain to its already-open canonical database.
pub(crate) fn validate_identity_bound_active_setup_database(
    database: IdentityBoundActiveSetupDatabase,
) -> Result<PreparedMetadataValidatedActiveSetupDatabase, ActiveSetupDatabaseValidationError> {
    let IdentityBoundActiveSetupDatabase {
        database,
        database_metadata: prepared_database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        trusted_evidence_assessment,
        normalized_freshness_observation,
        machine,
        authority,
    } = database;

    let integrity = preserve_integrity_outcome(
        validate_production_database_readability_and_integrity(database),
    )?;
    let live = preserve_live_outcome(validate_production_database_live_metadata_and_headers(
        integrity,
    ))?;

    if !live.matches_prepared_metadata(&prepared_database_metadata) {
        let _ = (
            prepared_database_metadata,
            installation_evidence_paths,
            database_key_paths,
            freshness_anchor_paths,
            trusted_evidence_assessment,
            normalized_freshness_observation,
            machine,
            authority,
        );

        #[cfg(test)]
        if tests::FAIL_MISMATCH_CLOSE.with(|fail| fail.replace(false)) {
            return Err(mismatch_close_result(live.close_using(Err)));
        }
        return Err(mismatch_close_result(live.close()));
    }

    Ok(PreparedMetadataValidatedActiveSetupDatabase {
        database: live,
        prepared_database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        trusted_evidence_assessment,
        normalized_freshness_observation,
        machine,
        authority,
    })
}

fn preserve_integrity_outcome(
    outcome: ProductionDatabaseValidationOutcome,
) -> Result<
    ReadabilityAndIntegrityValidatedProductionDatabaseConnection,
    ActiveSetupDatabaseValidationError,
> {
    match outcome {
        ProductionDatabaseValidationOutcome::Validated(database) => Ok(database),
        ProductionDatabaseValidationOutcome::Failed(category) => {
            Err(ActiveSetupDatabaseValidationError::Integrity(category))
        }
        ProductionDatabaseValidationOutcome::CloseFailed(failure) => Err(
            ActiveSetupDatabaseValidationError::IntegrityCloseFailed(failure),
        ),
    }
}

fn preserve_live_outcome(
    outcome: LiveMetadataAndHeaderValidationOutcome,
) -> Result<
    LiveMetadataAndHeaderValidatedProductionDatabaseConnection,
    ActiveSetupDatabaseValidationError,
> {
    match outcome {
        LiveMetadataAndHeaderValidationOutcome::Validated(database) => Ok(database),
        LiveMetadataAndHeaderValidationOutcome::Failed(category) => Err(
            ActiveSetupDatabaseValidationError::LiveMetadataAndHeaders(category),
        ),
        LiveMetadataAndHeaderValidationOutcome::CloseFailed(failure) => {
            Err(ActiveSetupDatabaseValidationError::LiveMetadataAndHeadersCloseFailed(failure))
        }
    }
}

fn mismatch_close_result(
    outcome: ProductionDatabaseConnectionCloseOutcome,
) -> ActiveSetupDatabaseValidationError {
    match outcome {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ActiveSetupDatabaseValidationError::PreparedMetadataMismatch
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ActiveSetupDatabaseValidationError::PreparedMetadataMismatchCloseFailed(
                ActiveSetupPreparedMetadataMismatchCloseFailure { failure },
            )
        }
    }
}

#[cfg(test)]
#[path = "prepared_metadata_validation_tests.rs"]
mod tests;
