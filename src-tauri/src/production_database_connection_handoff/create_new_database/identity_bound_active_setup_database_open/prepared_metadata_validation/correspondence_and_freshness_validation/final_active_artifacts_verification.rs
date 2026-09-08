//! Setup-only ownership transition for the final-active-artifacts milestone.
//!
//! This consumes the correspondence-and-freshness-validated owner, advances
//! only its retained publication machine through the protected bridge, and
//! preserves the same live database, prepared metadata, paths, and authority.

use std::fmt;

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    first_time_setup_publication::{
        FirstTimeSetupPublicationStateMachine, FirstTimeSetupPublicationTransitionError,
        protected_artifact_staging,
    },
    production_database_connection_handoff::DatabaseFreshnessValidatedProductionDatabaseConnection,
    storage_foundation::{
        DatabaseKeyPersistencePaths, FreshnessAnchorPersistencePaths,
        InstallationEvidencePersistencePaths,
    },
};

use super::{
    CorrespondenceAndFreshnessValidatedActiveSetupDatabase, ProtectedArtifactStagingAuthority,
};

/// The same setup-only operation after final active artifacts were verified.
#[must_use = "the verified setup operation and live database must remain owned"]
pub(crate) struct FinalActiveArtifactsVerifiedFirstTimeSetupOperation {
    database: DatabaseFreshnessValidatedProductionDatabaseConnection,
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

/// Consumes the sole validated setup owner and advances exactly one milestone.
pub(crate) fn advance_final_active_artifacts_verified_for_first_time_setup(
    operation: CorrespondenceAndFreshnessValidatedActiveSetupDatabase,
) -> Result<
    FinalActiveArtifactsVerifiedFirstTimeSetupOperation,
    FirstTimeSetupFinalActiveArtifactsVerificationStateError,
> {
    let CorrespondenceAndFreshnessValidatedActiveSetupDatabase {
        database,
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
        database,
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
