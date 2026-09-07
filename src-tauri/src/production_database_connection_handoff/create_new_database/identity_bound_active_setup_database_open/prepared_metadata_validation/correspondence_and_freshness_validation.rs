//! Setup-only correspondence and freshness validation for the already-open
//! canonical database lifetime.
//!
//! This transition consumes the prepared-metadata-validated setup owner,
//! applies the canonical correspondence validator before the canonical
//! freshness validator, and retains the successful live lifetime plus setup
//! provenance. It does not advance publication state or observe installation
//! state.

use std::fmt;

use crate::{
    database_freshness_classification::DatabaseFreshnessClassification,
    database_metadata_contract::DatabaseMetadataContractV1,
    first_time_setup_publication::FirstTimeSetupPublicationStateMachine,
    production_database_connection_handoff::{
        DatabaseEvidenceCorrespondenceMismatch,
        DatabaseEvidenceCorrespondenceValidationCloseFailure,
        DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome,
        DatabaseEvidenceCorrespondenceValidationOutcome,
        DatabaseFreshnessValidatedProductionDatabaseConnection,
        ProductionDatabaseFreshnessValidationCloseFailure,
        ProductionDatabaseFreshnessValidationCloseRetryOutcome,
        ProductionDatabaseFreshnessValidationOutcome,
        validate_production_database_evidence_correspondence,
        validate_production_database_freshness,
    },
    storage_foundation::{
        DatabaseKeyPersistencePaths, FreshnessAnchorPersistencePaths,
        InstallationEvidencePersistencePaths,
    },
};

use super::{PreparedMetadataValidatedActiveSetupDatabase, ProtectedArtifactStagingAuthority};

/// The same live canonical database after correspondence and freshness have
/// both passed, plus the provenance required by the next setup-only boundary.
#[must_use = "the validated setup database and retained provenance must remain owned"]
pub(crate) struct CorrespondenceAndFreshnessValidatedActiveSetupDatabase {
    database: DatabaseFreshnessValidatedProductionDatabaseConnection,
    prepared_database_metadata: DatabaseMetadataContractV1,
    installation_evidence_paths: InstallationEvidencePersistencePaths,
    database_key_paths: DatabaseKeyPersistencePaths,
    freshness_anchor_paths: FreshnessAnchorPersistencePaths,
    machine: FirstTimeSetupPublicationStateMachine,
    authority: ProtectedArtifactStagingAuthority,
}

impl fmt::Debug for CorrespondenceAndFreshnessValidatedActiveSetupDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CorrespondenceAndFreshnessValidatedActiveSetupDatabase([REDACTED])")
    }
}

/// Terminal categories for the consumed setup operation. Ownership-bearing
/// canonical close failures remain intact for their close-only retries.
#[must_use = "a validation close failure may retain the live database lifetime"]
#[allow(dead_code)]
pub(crate) enum ActiveSetupCorrespondenceAndFreshnessValidationError {
    CorrespondenceMismatch(DatabaseEvidenceCorrespondenceMismatch),
    CorrespondenceCloseFailed(DatabaseEvidenceCorrespondenceValidationCloseFailure),
    Freshness(DatabaseFreshnessClassification),
    FreshnessCloseFailed(ProductionDatabaseFreshnessValidationCloseFailure),
}

impl fmt::Debug for ActiveSetupCorrespondenceAndFreshnessValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorrespondenceMismatch(category) => formatter
                .debug_tuple("CorrespondenceMismatch")
                .field(category)
                .finish(),
            Self::CorrespondenceCloseFailed(_) => {
                formatter.write_str("CorrespondenceCloseFailed([REDACTED])")
            }
            Self::Freshness(category) => {
                formatter.debug_tuple("Freshness").field(category).finish()
            }
            Self::FreshnessCloseFailed(_) => {
                formatter.write_str("FreshnessCloseFailed([REDACTED])")
            }
        }
    }
}

#[allow(dead_code)]
impl ActiveSetupCorrespondenceAndFreshnessValidationError {
    /// Delegates only the canonical correspondence close retry when that exact
    /// ownership-bearing branch is present.
    pub(crate) fn retry_correspondence_close(
        self,
    ) -> Result<DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome, Self> {
        match self {
            Self::CorrespondenceCloseFailed(failure) => Ok(failure.retry_close()),
            other => Err(other),
        }
    }

    /// Delegates only the canonical freshness close retry when that exact
    /// ownership-bearing branch is present.
    pub(crate) fn retry_freshness_close(
        self,
    ) -> Result<ProductionDatabaseFreshnessValidationCloseRetryOutcome, Self> {
        match self {
            Self::FreshnessCloseFailed(failure) => Ok(failure.retry_close()),
            other => Err(other),
        }
    }
}

/// Consumes the sole prepared-metadata-validated setup owner and applies the
/// canonical correspondence-then-freshness chain to its existing lifetime.
pub(crate) fn validate_active_setup_database_correspondence_and_freshness(
    database: PreparedMetadataValidatedActiveSetupDatabase,
) -> Result<
    CorrespondenceAndFreshnessValidatedActiveSetupDatabase,
    ActiveSetupCorrespondenceAndFreshnessValidationError,
> {
    let PreparedMetadataValidatedActiveSetupDatabase {
        database,
        prepared_database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        trusted_evidence_assessment,
        normalized_freshness_observation,
        machine,
        authority,
    } = database;

    let corresponding = match validate_production_database_evidence_correspondence(
        database,
        trusted_evidence_assessment,
    ) {
        DatabaseEvidenceCorrespondenceValidationOutcome::Validated(database) => database,
        DatabaseEvidenceCorrespondenceValidationOutcome::Mismatch(category) => {
            return Err(
                ActiveSetupCorrespondenceAndFreshnessValidationError::CorrespondenceMismatch(
                    category,
                ),
            );
        }
        DatabaseEvidenceCorrespondenceValidationOutcome::CloseFailed(failure) => {
            return Err(
                ActiveSetupCorrespondenceAndFreshnessValidationError::CorrespondenceCloseFailed(
                    failure,
                ),
            );
        }
    };

    let fresh = match validate_production_database_freshness(
        corresponding,
        normalized_freshness_observation,
    ) {
        ProductionDatabaseFreshnessValidationOutcome::Validated(database) => database,
        ProductionDatabaseFreshnessValidationOutcome::Failed(category) => {
            return Err(ActiveSetupCorrespondenceAndFreshnessValidationError::Freshness(category));
        }
        ProductionDatabaseFreshnessValidationOutcome::CloseFailed(failure) => {
            return Err(
                ActiveSetupCorrespondenceAndFreshnessValidationError::FreshnessCloseFailed(failure),
            );
        }
    };

    Ok(CorrespondenceAndFreshnessValidatedActiveSetupDatabase {
        database: fresh,
        prepared_database_metadata,
        installation_evidence_paths,
        database_key_paths,
        freshness_anchor_paths,
        machine,
        authority,
    })
}

#[cfg(test)]
#[path = "correspondence_and_freshness_validation_tests.rs"]
mod tests;
