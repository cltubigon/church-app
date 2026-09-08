//! Setup-only close and final-active-artifacts ownership transitions.
//!
//! The live correspondence-and-freshness-validated database must close through
//! its canonical close API before the retained publication machine may advance
//! through the protected final-active-artifacts bridge.

use std::fmt;

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    first_time_setup_publication::{
        FirstTimeSetupPublicationStateMachine, FirstTimeSetupPublicationTransitionError,
        protected_artifact_staging,
    },
    production_database_connection_handoff::{
        ProductionDatabaseConnectionCloseFailure, ProductionDatabaseConnectionCloseOutcome,
    },
    storage_foundation::{
        DatabaseKeyPersistencePaths, FreshnessAnchorPersistencePaths,
        InstallationEvidencePersistencePaths,
    },
};

use super::{
    CorrespondenceAndFreshnessValidatedActiveSetupDatabase, ProtectedArtifactStagingAuthority,
};

#[path = "final_active_artifacts_verification/canonical_installation_observation.rs"]
mod canonical_installation_observation;

pub(crate) use canonical_installation_observation::{
    CanonicalInstallationObservationAcceptedFirstTimeSetupOperation,
    CompletedFirstTimeSetupOperation, FirstTimeSetupCanonicalInstallationObservationError,
    FirstTimeSetupReadyForCompletionError, ReadyForSetupCompletionFirstTimeSetupOperation,
    accept_canonical_installation_observation_for_first_time_setup,
    advance_ready_for_setup_completion_for_first_time_setup, complete_first_time_setup,
};

/// The setup provenance retained after the validated active database has
/// explicitly closed and before final-active publication state advances.
#[must_use = "the closed setup operation and retained provenance must remain owned"]
pub(crate) struct CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation {
    prepared_database_metadata: DatabaseMetadataContractV1,
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
    machine: FirstTimeSetupPublicationStateMachine,
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation([REDACTED])",
        )
    }
}

/// Setup-specific ownership retained when canonical database close fails.
#[must_use = "a setup database close failure retains the live database lifetime"]
pub(crate) struct FinalActiveSetupDatabaseCloseFailure {
    close_failure: ProductionDatabaseConnectionCloseFailure,
    prepared_database_metadata: DatabaseMetadataContractV1,
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
    machine: FirstTimeSetupPublicationStateMachine,
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for FinalActiveSetupDatabaseCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FinalActiveSetupDatabaseCloseFailure([REDACTED])")
    }
}

#[must_use = "the setup database close outcome must be handled"]
#[allow(clippy::large_enum_variant)]
pub(crate) enum FinalActiveSetupDatabaseCloseOutcome {
    Closed(CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation),
    Failed(FinalActiveSetupDatabaseCloseFailure),
}

impl fmt::Debug for FinalActiveSetupDatabaseCloseOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(_) => formatter.write_str("Closed([REDACTED])"),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

#[must_use = "the setup database close retry outcome must be handled"]
#[allow(clippy::large_enum_variant)]
pub(crate) enum FinalActiveSetupDatabaseCloseRetryOutcome {
    Closed(CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation),
    Failed(FinalActiveSetupDatabaseCloseFailure),
}

impl fmt::Debug for FinalActiveSetupDatabaseCloseRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(_) => formatter.write_str("Closed([REDACTED])"),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

impl FinalActiveSetupDatabaseCloseFailure {
    /// Consumes the retained failure and delegates only to the canonical
    /// close-only retry while preserving every setup provenance value.
    pub(crate) fn retry_close(self) -> FinalActiveSetupDatabaseCloseRetryOutcome {
        let Self {
            close_failure,
            prepared_database_metadata,
            installation_evidence_paths,
            database_key_paths,
            freshness_anchor_paths,
            machine,
            authority,
        } = self;

        match close_failure.retry_close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                FinalActiveSetupDatabaseCloseRetryOutcome::Closed(
                    CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation {
                        prepared_database_metadata,
                        installation_evidence_paths,
                        database_key_paths,
                        freshness_anchor_paths,
                        machine,
                        authority,
                    },
                )
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(close_failure) => {
                FinalActiveSetupDatabaseCloseRetryOutcome::Failed(Self {
                    close_failure,
                    prepared_database_metadata,
                    installation_evidence_paths,
                    database_key_paths,
                    freshness_anchor_paths,
                    machine,
                    authority,
                })
            }
        }
    }
}

/// Consumes the sole live validated setup owner and performs only its canonical
/// explicit close while preserving the setup provenance on either outcome.
pub(crate) fn close_and_preserve_correspondence_and_freshness_validated_active_setup_database(
    operation: CorrespondenceAndFreshnessValidatedActiveSetupDatabase,
) -> FinalActiveSetupDatabaseCloseOutcome {
    let CorrespondenceAndFreshnessValidatedActiveSetupDatabase {
        database,
        prepared_database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        machine,
        authority,
    } = operation;

    match database.close() {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            FinalActiveSetupDatabaseCloseOutcome::Closed(
                CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation {
                    prepared_database_metadata,
                    installation_evidence_paths,
                    database_key_paths,
                    freshness_anchor_paths,
                    machine,
                    authority,
                },
            )
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(close_failure) => {
            FinalActiveSetupDatabaseCloseOutcome::Failed(FinalActiveSetupDatabaseCloseFailure {
                close_failure,
                prepared_database_metadata,
                installation_evidence_paths,
                database_key_paths,
                freshness_anchor_paths,
                machine,
                authority,
            })
        }
    }
}

/// The same non-live setup provenance after final active artifacts were
/// verified through the protected publication bridge.
#[must_use = "the verified setup operation and retained provenance must remain owned"]
pub(crate) struct FinalActiveArtifactsVerifiedFirstTimeSetupOperation {
    prepared_database_metadata: DatabaseMetadataContractV1,
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
    machine: FirstTimeSetupPublicationStateMachine,
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for FinalActiveArtifactsVerifiedFirstTimeSetupOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FinalActiveArtifactsVerifiedFirstTimeSetupOperation([REDACTED])")
    }
}

/// Coarse terminal failure for an impossible retained-machine ordering error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupFinalActiveArtifactsVerificationStateError {
    InternalState,
}

/// Consumes only the non-live closed setup owner and advances exactly one
/// publication milestone through the existing protected bridge.
pub(crate) fn advance_final_active_artifacts_verified_for_first_time_setup(
    operation: CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation,
) -> Result<
    FinalActiveArtifactsVerifiedFirstTimeSetupOperation,
    FirstTimeSetupFinalActiveArtifactsVerificationStateError,
> {
    let CorrespondenceAndFreshnessValidatedClosedFirstTimeSetupOperation {
        prepared_database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        machine,
        authority,
    } = operation;

    let machine = protected_artifact_staging::advance_final_active_artifacts_verified::<
        FirstTimeSetupPublicationStateMachine,
    >(&authority, machine)
    .map_err(|error| match error {
        FirstTimeSetupPublicationTransitionError::OutOfOrder => {
            FirstTimeSetupFinalActiveArtifactsVerificationStateError::InternalState
        }
    })?;

    Ok(FinalActiveArtifactsVerifiedFirstTimeSetupOperation {
        prepared_database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        machine,
        authority,
    })
}

#[cfg(test)]
#[path = "final_active_artifacts_verification_tests.rs"]
mod tests;
