//! Pure setup-only transition into the existing readiness authority.

use std::fmt;

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    first_time_setup_publication::{
        FirstTimeSetupPublicationStateMachine, FirstTimeSetupPublicationTransitionError,
        ReadyForSetupCompletion, protected_artifact_staging,
    },
    storage_foundation::{
        DatabaseKeyPersistencePaths, FreshnessAnchorPersistencePaths,
        InstallationEvidencePersistencePaths,
    },
};

use super::{
    CanonicalInstallationObservationAcceptedFirstTimeSetupOperation,
    ProtectedArtifactStagingAuthority,
};

/// Sealed non-live setup ownership carrying only the existing readiness proof
/// and retained setup provenance.
#[must_use = "the ready setup operation and retained authority must remain owned"]
pub(crate) struct ReadyForSetupCompletionFirstTimeSetupOperation {
    prepared_database_metadata: DatabaseMetadataContractV1,
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
    readiness: ReadyForSetupCompletion,
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for ReadyForSetupCompletionFirstTimeSetupOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadyForSetupCompletionFirstTimeSetupOperation([REDACTED])")
    }
}

/// Coarse setup-local failure for an impossible retained-machine ordering
/// error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupReadyForCompletionError {
    InternalState,
}

/// Consumes the accepted canonical-observation owner and advances exactly once
/// through the existing protected readiness bridge. It performs no setup
/// completion.
pub(crate) fn advance_ready_for_setup_completion_for_first_time_setup(
    operation: CanonicalInstallationObservationAcceptedFirstTimeSetupOperation,
) -> Result<ReadyForSetupCompletionFirstTimeSetupOperation, FirstTimeSetupReadyForCompletionError> {
    let CanonicalInstallationObservationAcceptedFirstTimeSetupOperation {
        prepared_database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        machine,
        authority,
    } = operation;

    let readiness = protected_artifact_staging::advance_ready_for_setup_completion::<
        FirstTimeSetupPublicationStateMachine,
    >(&authority, machine)
    .map_err(|error| match error {
        FirstTimeSetupPublicationTransitionError::OutOfOrder => {
            FirstTimeSetupReadyForCompletionError::InternalState
        }
    })?;

    Ok(ReadyForSetupCompletionFirstTimeSetupOperation {
        prepared_database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        readiness,
        authority,
    })
}

#[cfg(test)]
#[path = "ready_for_setup_completion_tests.rs"]
mod tests;
