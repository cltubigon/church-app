//! Setup-only identity-bound open of already-prepared active trust material.
//!
//! This transition proves only that one fresh canonical inspection matched the
//! setup-created native identity and that the same inspection and prepared key
//! entered the canonical keyed read-only opener. It performs no validation or
//! publication-state advancement.

use std::fmt;

use crate::{
    database_freshness_classification::NormalizedFreshnessAnchorObservation,
    database_metadata_contract::DatabaseMetadataContractV1,
    first_time_setup_publication::FirstTimeSetupPublicationStateMachine,
    installation_evidence_protection::TrustedCurrentInstallationEvidenceAssessment,
    production_database_file::{ProductionDatabaseInspection, inspect_production_database_file},
    storage_foundation::{
        DatabaseKeyPersistencePaths, FreshnessAnchorPersistencePaths,
        InstallationEvidencePersistencePaths,
    },
};

use super::{
    super::super::super::{
        ProductionDatabaseConnectionCloseOutcome,
        ProductionDatabaseConnectionConstructionCloseFailure,
        ProductionDatabaseConnectionOpenError, ProductionReadOnlyDatabaseConnection,
        SetupDatabaseIdentityProof, open_keyed_production_database_read_only,
    },
    PreparedFinalActiveSetupTrustMaterial, ProtectedArtifactStagingAuthority,
};

#[path = "identity_bound_active_setup_database_open/prepared_metadata_validation.rs"]
mod prepared_metadata_validation;

pub(crate) use prepared_metadata_validation::{
    ActiveSetupDatabaseValidationError, ActiveSetupPreparedMetadataMismatchCloseFailure,
    PreparedMetadataValidatedActiveSetupDatabase, validate_identity_bound_active_setup_database,
};

/// One keyed-but-unvalidated canonical database lifetime plus the remaining
/// prepared setup trust and provenance branches.
#[must_use = "the setup database and retained trust material must remain owned"]
pub(crate) struct IdentityBoundActiveSetupDatabase {
    database: ProductionReadOnlyDatabaseConnection,
    database_metadata: DatabaseMetadataContractV1,
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
    trusted_evidence_assessment: TrustedCurrentInstallationEvidenceAssessment,
    normalized_freshness_observation: NormalizedFreshnessAnchorObservation,
    machine: FirstTimeSetupPublicationStateMachine,
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for IdentityBoundActiveSetupDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityBoundActiveSetupDatabase([REDACTED])")
    }
}

#[must_use = "a construction close failure retains the canonical close-retry owner"]
pub(crate) enum FirstTimeSetupActiveDatabaseOpenError {
    CurrentDatabaseUnavailable,
    CurrentDatabaseUnsafe,
    IdentityMismatch,
    KeyedReadOnlyOpenFailed,
    CloseFailed(ProductionDatabaseConnectionConstructionCloseFailure),
}

impl fmt::Debug for FirstTimeSetupActiveDatabaseOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CurrentDatabaseUnavailable => "CurrentDatabaseUnavailable",
            Self::CurrentDatabaseUnsafe => "CurrentDatabaseUnsafe",
            Self::IdentityMismatch => "IdentityMismatch",
            Self::KeyedReadOnlyOpenFailed => "KeyedReadOnlyOpenFailed",
            Self::CloseFailed(_) => "CloseFailed([REDACTED])",
        })
    }
}

impl FirstTimeSetupActiveDatabaseOpenError {
    /// Only the ownership-bearing construction-close branch can retry, and the
    /// delegated canonical operation retries close alone.
    pub(crate) fn retry_construction_close(
        self,
    ) -> Result<ProductionDatabaseConnectionCloseOutcome, Self> {
        match self {
            Self::CloseFailed(failure) => Ok(failure.retry_close()),
            other => Err(other),
        }
    }
}

fn preserve_open_failure(
    error: ProductionDatabaseConnectionOpenError,
) -> FirstTimeSetupActiveDatabaseOpenError {
    match error {
        ProductionDatabaseConnectionOpenError::Failed => {
            FirstTimeSetupActiveDatabaseOpenError::KeyedReadOnlyOpenFailed
        }
        ProductionDatabaseConnectionOpenError::CloseFailed(failure) => {
            FirstTimeSetupActiveDatabaseOpenError::CloseFailed(failure)
        }
    }
}

/// Consume the sole prepared owner, bind its historical proof to exactly one
/// retained fresh inspection, and move that inspection and key into the
/// canonical keyed-but-unvalidated read-only opener.
pub(crate) fn open_identity_bound_active_setup_database(
    material: PreparedFinalActiveSetupTrustMaterial,
) -> Result<IdentityBoundActiveSetupDatabase, FirstTimeSetupActiveDatabaseOpenError> {
    let PreparedFinalActiveSetupTrustMaterial {
        database_identity_proof,
        database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        trusted_evidence_assessment,
        normalized_freshness_observation,
        generation_bound_database_key,
        machine,
        authority,
    } = material;

    let SetupDatabaseIdentityProof {
        created_leaf_identity,
    } = database_identity_proof;
    let path = installation_evidence_paths.active_database.clone();
    let inspected = match inspect_production_database_file(&path) {
        ProductionDatabaseInspection::Present(inspected) => inspected,
        ProductionDatabaseInspection::Missing | ProductionDatabaseInspection::Unavailable => {
            return Err(FirstTimeSetupActiveDatabaseOpenError::CurrentDatabaseUnavailable);
        }
        ProductionDatabaseInspection::Invalid => {
            return Err(FirstTimeSetupActiveDatabaseOpenError::CurrentDatabaseUnsafe);
        }
    };
    if !inspected.has_native_identity(
        created_leaf_identity.volume_serial,
        created_leaf_identity.file_id,
    ) {
        return Err(FirstTimeSetupActiveDatabaseOpenError::IdentityMismatch);
    }

    let database =
        open_keyed_production_database_read_only(path, inspected, generation_bound_database_key)
            .map_err(preserve_open_failure)?;

    Ok(IdentityBoundActiveSetupDatabase {
        database,
        database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        trusted_evidence_assessment,
        normalized_freshness_observation,
        machine,
        authority,
    })
}

#[cfg(test)]
#[path = "identity_bound_active_setup_database_open_tests.rs"]
mod tests;
