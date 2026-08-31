//! Setup Slices 2 and 3: preserve the identity-bound staged-key open through canonical
//! integrity, live header/metadata validation, and exact prepared correspondence.
//! This establishes no common context with other staged artifacts, freshness,
//! publication, setup completion, startup authorization, operational trust, or
//! continuing correctness after later mutation. Creation time is equality only.

use std::fmt;

use crate::database_metadata_contract::DatabaseMetadataContractV1;

use super::{
    super::{
        IdentityBoundStagedKeyOpenedProductionDatabaseForSetup,
        ProductionDatabaseConnectionCloseFailure, ProductionDatabaseConnectionCloseOutcome,
        ProductionDatabaseValidationCloseFailure, ProductionDatabaseValidationError,
        ProductionDatabaseValidationOutcome,
        ReadabilityAndIntegrityValidatedProductionDatabaseConnection,
    },
    LiveMetadataAndHeaderValidatedProductionDatabaseConnection,
    LiveMetadataAndHeaderValidationCloseFailure, LiveMetadataAndHeaderValidationError,
    LiveMetadataAndHeaderValidationOutcome, validate_production_database_live_metadata_and_headers,
};

/// Same live lifetime, with all three setup validation stages satisfied.
#[must_use = "the setup database must remain owned until closed"]
pub(crate) struct PreparedMetadataValidatedProductionDatabaseForSetup {
    database: LiveMetadataAndHeaderValidatedProductionDatabaseConnection,
}

impl fmt::Debug for PreparedMetadataValidatedProductionDatabaseForSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedMetadataValidatedProductionDatabaseForSetup([REDACTED])")
    }
}

impl PreparedMetadataValidatedProductionDatabaseForSetup {
    /// Ordinary close discards provenance. It returns no closed validation proof.
    pub(crate) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        self.database.close()
    }
}

/// Canonical payload-free categories are preserved under phase-specific variants.
/// Close-failure variants retain the exact canonical failure owner for that phase.
#[must_use = "a close failure retains the live connection lifetime"]
pub(crate) enum SetupProductionDatabaseRevalidationError {
    Integrity(ProductionDatabaseValidationError),
    LiveMetadataAndHeaders(LiveMetadataAndHeaderValidationError),
    PreparedMetadataMismatch,
    IntegrityCloseFailed(ProductionDatabaseValidationCloseFailure),
    LiveMetadataAndHeadersCloseFailed(LiveMetadataAndHeaderValidationCloseFailure),
    PreparedMetadataMismatchCloseFailed(SetupPreparedMetadataMismatchCloseFailure),
}

impl fmt::Debug for SetupProductionDatabaseRevalidationError {
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

/// The type itself fixes PreparedMetadataMismatch; only lifetime ownership remains.
#[must_use = "the mismatch connection must remain owned until closed"]
pub(crate) struct SetupPreparedMetadataMismatchCloseFailure {
    failure: ProductionDatabaseConnectionCloseFailure,
}

impl fmt::Debug for SetupPreparedMetadataMismatchCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SetupPreparedMetadataMismatchCloseFailure([REDACTED])")
    }
}

impl SetupPreparedMetadataMismatchCloseFailure {
    /// Only close is retried. Returns PreparedMetadataMismatch after close, or
    /// PreparedMetadataMismatchCloseFailed with the retained owner on failure.
    pub(crate) fn retry_close(self) -> SetupProductionDatabaseRevalidationError {
        mismatch_close_result(self.failure.retry_close())
    }
}

/// Consumes setup provenance once, then follows the existing canonical order.
/// The prepared contract is borrowed, not retained or treated as freshness.
pub(crate) fn revalidate_identity_bound_staged_key_production_database_for_setup(
    database: IdentityBoundStagedKeyOpenedProductionDatabaseForSetup,
    prepared_metadata: &DatabaseMetadataContractV1,
) -> Result<
    PreparedMetadataValidatedProductionDatabaseForSetup,
    SetupProductionDatabaseRevalidationError,
> {
    let integrity = preserve_integrity_outcome(database.validate_readability_and_integrity())?;
    let live = preserve_live_outcome(validate_production_database_live_metadata_and_headers(
        integrity,
    ))?;
    compare_prepared_metadata(live, prepared_metadata)
}

fn preserve_integrity_outcome(
    outcome: ProductionDatabaseValidationOutcome,
) -> Result<
    ReadabilityAndIntegrityValidatedProductionDatabaseConnection,
    SetupProductionDatabaseRevalidationError,
> {
    match outcome {
        ProductionDatabaseValidationOutcome::Validated(database) => Ok(database),
        ProductionDatabaseValidationOutcome::Failed(category) => Err(
            SetupProductionDatabaseRevalidationError::Integrity(category),
        ),
        ProductionDatabaseValidationOutcome::CloseFailed(failure) => {
            Err(SetupProductionDatabaseRevalidationError::IntegrityCloseFailed(failure))
        }
    }
}

fn preserve_live_outcome(
    outcome: LiveMetadataAndHeaderValidationOutcome,
) -> Result<
    LiveMetadataAndHeaderValidatedProductionDatabaseConnection,
    SetupProductionDatabaseRevalidationError,
> {
    match outcome {
        LiveMetadataAndHeaderValidationOutcome::Validated(database) => Ok(database),
        LiveMetadataAndHeaderValidationOutcome::Failed(category) => {
            Err(SetupProductionDatabaseRevalidationError::LiveMetadataAndHeaders(category))
        }
        LiveMetadataAndHeaderValidationOutcome::CloseFailed(failure) => Err(
            SetupProductionDatabaseRevalidationError::LiveMetadataAndHeadersCloseFailed(failure),
        ),
    }
}

// Private to this composition: a generic live owner cannot create setup success
// through any caller-accessible transition or metadata accessor.
fn compare_prepared_metadata(
    database: LiveMetadataAndHeaderValidatedProductionDatabaseConnection,
    prepared_metadata: &DatabaseMetadataContractV1,
) -> Result<
    PreparedMetadataValidatedProductionDatabaseForSetup,
    SetupProductionDatabaseRevalidationError,
> {
    if database.metadata_contract == *prepared_metadata {
        Ok(PreparedMetadataValidatedProductionDatabaseForSetup { database })
    } else {
        #[cfg(test)]
        if tests::FAIL_MISMATCH_CLOSE.with(|fail| fail.replace(false)) {
            return Err(mismatch_close_result(database.close_using(Err)));
        }
        Err(mismatch_close_result(database.close()))
    }
}

fn mismatch_close_result(
    outcome: ProductionDatabaseConnectionCloseOutcome,
) -> SetupProductionDatabaseRevalidationError {
    match outcome {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            SetupProductionDatabaseRevalidationError::PreparedMetadataMismatch
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            SetupProductionDatabaseRevalidationError::PreparedMetadataMismatchCloseFailed(
                SetupPreparedMetadataMismatchCloseFailure { failure },
            )
        }
    }
}

/// Resource-free evidence that a Slice-2 success was explicitly closed.
/// Proves neither other staged artifacts nor common context, publication, setup
/// completion, startup authority, operational trust, or correctness after close.
pub(crate) struct ClosedPreparedMetadataValidatedProductionDatabaseForSetup {
    _private: (),
}

impl fmt::Debug for ClosedPreparedMetadataValidatedProductionDatabaseForSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClosedPreparedMetadataValidatedProductionDatabaseForSetup([REDACTED])")
    }
}

#[must_use = "the setup close outcome retains either closed provenance or the live lifetime"]
pub(crate) enum SetupProductionDatabaseRevalidationCloseOutcome {
    Closed(ClosedPreparedMetadataValidatedProductionDatabaseForSetup),
    Failed(SetupProductionDatabaseRevalidationCloseFailure),
}

impl fmt::Debug for SetupProductionDatabaseRevalidationCloseOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(_) => formatter.write_str("Closed([REDACTED])"),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

/// The type preserves already-earned Slice-2 provenance while the canonical
/// failure retains the complete connection/guard/inspection lifetime.
#[must_use = "the validated setup connection must remain owned until closed"]
pub(crate) struct SetupProductionDatabaseRevalidationCloseFailure {
    failure: ProductionDatabaseConnectionCloseFailure,
}

impl fmt::Debug for SetupProductionDatabaseRevalidationCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SetupProductionDatabaseRevalidationCloseFailure([REDACTED])")
    }
}

impl SetupProductionDatabaseRevalidationCloseFailure {
    /// Retries only canonical close, preserving setup provenance on either result.
    pub(crate) fn retry_close(self) -> SetupProductionDatabaseRevalidationCloseOutcome {
        preserve_revalidation_close_result(self.failure.retry_close())
    }
}

/// Consumes Slice-2 success and explicitly closes its exact retained lifetime.
/// Canonical close discards metadata and, only after SQLite close succeeds,
/// releases the write guard and inspection before the closed proof is created.
pub(crate) fn close_and_preserve_prepared_metadata_validated_production_database_for_setup(
    database: PreparedMetadataValidatedProductionDatabaseForSetup,
) -> SetupProductionDatabaseRevalidationCloseOutcome {
    preserve_revalidation_close_result(database.database.close())
}

// Private mapping used only after consuming Slice-2 success or its close failure.
fn preserve_revalidation_close_result(
    outcome: ProductionDatabaseConnectionCloseOutcome,
) -> SetupProductionDatabaseRevalidationCloseOutcome {
    match outcome {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            SetupProductionDatabaseRevalidationCloseOutcome::Closed(
                ClosedPreparedMetadataValidatedProductionDatabaseForSetup { _private: () },
            )
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            SetupProductionDatabaseRevalidationCloseOutcome::Failed(
                SetupProductionDatabaseRevalidationCloseFailure { failure },
            )
        }
    }
}

#[cfg(test)]
#[path = "setup_database_revalidation_tests.rs"]
mod tests;
