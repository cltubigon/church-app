//! Setup-only canonical installation-state observation after final-active
//! artifact verification.

use std::fmt;

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    first_time_setup_publication::{
        FirstTimeSetupPublicationStateMachine, FirstTimeSetupPublicationTransitionError,
        protected_artifact_staging,
    },
    installation_evidence_persistence::observe_production_installation_evidence,
    installation_state::{ExpectedStorageEvidence, InstallationEvidence},
    storage_foundation::{
        DatabaseKeyPersistencePaths, FreshnessAnchorPersistencePaths,
        InstallationEvidencePersistencePaths,
    },
};

use super::{
    FinalActiveArtifactsVerifiedFirstTimeSetupOperation, ProtectedArtifactStagingAuthority,
};

#[path = "canonical_installation_observation/ready_for_setup_completion.rs"]
mod ready_for_setup_completion;

pub(crate) use ready_for_setup_completion::{
    CompletedFirstTimeSetupOperation, FirstTimeSetupReadyForCompletionError,
    ReadyForSetupCompletionFirstTimeSetupOperation,
    advance_ready_for_setup_completion_for_first_time_setup, complete_first_time_setup,
};

/// Non-live setup provenance retained after the one canonical installation
/// observation was accepted by the protected publication bridge.
#[must_use = "the accepted setup operation and retained provenance must remain owned"]
pub(crate) struct CanonicalInstallationObservationAcceptedFirstTimeSetupOperation {
    prepared_database_metadata: DatabaseMetadataContractV1,
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
    machine: FirstTimeSetupPublicationStateMachine,
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for CanonicalInstallationObservationAcceptedFirstTimeSetupOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "CanonicalInstallationObservationAcceptedFirstTimeSetupOperation([REDACTED])",
        )
    }
}

/// Coarse setup-local terminal categories for the consumed observation
/// operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupCanonicalInstallationObservationError {
    NeverInitialized,
    ExpectedStorageMissing,
    InstallationStateInconsistent,
    InstallationStateUnavailable,
    InternalState,
}

/// Consumes final-active setup provenance, observes canonical installation
/// evidence exactly once, and advances only on initialized-present evidence.
pub(crate) fn accept_canonical_installation_observation_for_first_time_setup(
    operation: FinalActiveArtifactsVerifiedFirstTimeSetupOperation,
) -> Result<
    CanonicalInstallationObservationAcceptedFirstTimeSetupOperation,
    FirstTimeSetupCanonicalInstallationObservationError,
> {
    let FinalActiveArtifactsVerifiedFirstTimeSetupOperation {
        prepared_database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        machine,
        authority,
    } = operation;

    match observe_production_installation_evidence(&installation_evidence_paths) {
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Present) => {}
        InstallationEvidence::NeverInitialized => {
            return Err(FirstTimeSetupCanonicalInstallationObservationError::NeverInitialized);
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing) => {
            return Err(
                FirstTimeSetupCanonicalInstallationObservationError::ExpectedStorageMissing,
            );
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable)
        | InstallationEvidence::Unavailable => {
            return Err(
                FirstTimeSetupCanonicalInstallationObservationError::InstallationStateUnavailable,
            );
        }
        InstallationEvidence::Inconsistent => {
            return Err(
                FirstTimeSetupCanonicalInstallationObservationError::InstallationStateInconsistent,
            );
        }
    }

    let machine =
        protected_artifact_staging::advance_canonical_installation_observation_accepted::<
            FirstTimeSetupPublicationStateMachine,
        >(&authority, machine)
        .map_err(|error| match error {
            FirstTimeSetupPublicationTransitionError::OutOfOrder => {
                FirstTimeSetupCanonicalInstallationObservationError::InternalState
            }
        })?;

    Ok(
        CanonicalInstallationObservationAcceptedFirstTimeSetupOperation {
            prepared_database_metadata,
            installation_evidence_paths,
            database_key_paths,
            freshness_anchor_paths,
            machine,
            authority,
        },
    )
}

#[cfg(test)]
#[path = "canonical_installation_observation_tests.rs"]
mod tests;
