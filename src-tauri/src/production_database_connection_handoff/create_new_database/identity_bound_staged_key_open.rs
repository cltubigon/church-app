//! Setup-only composition of historical identity, fresh retained inspection,
//! and independently verified staged-key ownership into the canonical opener.
//!
//! Applying the key is not proof of key correctness. This owner establishes no
//! integrity, live metadata, correspondence, freshness, setup completion,
//! startup authorization, or operational trust. Identity equality does not
//! establish unchanged bytes or any continuing guarantee after close.

use std::fmt;

use crate::{
    installation_evidence_protection::ReloadedStagedGenerationBoundDatabaseKeyForSetup,
    production_database_file::{ProductionDatabaseInspection, inspect_production_database_file},
    storage_foundation::ProductionDatabasePath,
};

use super::{
    super::{
        ProductionDatabaseConnectionCloseOutcome,
        ProductionDatabaseConnectionConstructionCloseFailure,
        ProductionDatabaseConnectionOpenError, ProductionReadOnlyDatabaseConnection,
        open_keyed_production_database_read_only,
    },
    SetupDatabaseIdentityProof,
};

/// Only the provenance of this setup open, retaining the complete read-only owner.
#[must_use = "the setup connection must remain owned until explicitly closed"]
pub(crate) struct IdentityBoundStagedKeyOpenedProductionDatabaseForSetup {
    database: ProductionReadOnlyDatabaseConnection,
}

impl fmt::Debug for IdentityBoundStagedKeyOpenedProductionDatabaseForSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityBoundStagedKeyOpenedProductionDatabaseForSetup([REDACTED])")
    }
}

impl IdentityBoundStagedKeyOpenedProductionDatabaseForSetup {
    /// Ordinary consuming close discards setup provenance; no revalidation proof.
    pub(crate) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        self.database.close()
    }
}

#[must_use = "a construction close failure retains the complete existing close-retry owner"]
pub(crate) enum SetupProductionDatabaseOpenError {
    CurrentDatabaseUnavailable,
    CurrentDatabaseUnsafe,
    IdentityMismatch,
    KeyedReadOnlyOpenFailed,
    CloseFailed(ProductionDatabaseConnectionConstructionCloseFailure),
}

impl fmt::Debug for SetupProductionDatabaseOpenError {
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

fn preserve_open_failure(
    error: ProductionDatabaseConnectionOpenError,
) -> SetupProductionDatabaseOpenError {
    match error {
        ProductionDatabaseConnectionOpenError::Failed => {
            SetupProductionDatabaseOpenError::KeyedReadOnlyOpenFailed
        }
        ProductionDatabaseConnectionOpenError::CloseFailed(failure) => {
            SetupProductionDatabaseOpenError::CloseFailed(failure)
        }
    }
}

/// Match the historical identity against the exact fresh inspection consumed by
/// the existing opener. No earlier identity-observation token participates.
pub(crate) fn open_identity_bound_staged_key_production_database_for_setup(
    proof: &SetupDatabaseIdentityProof,
    path: ProductionDatabasePath,
    staged_key: ReloadedStagedGenerationBoundDatabaseKeyForSetup,
) -> Result<IdentityBoundStagedKeyOpenedProductionDatabaseForSetup, SetupProductionDatabaseOpenError>
{
    let inspected = match inspect_production_database_file(&path) {
        ProductionDatabaseInspection::Present(inspected) => inspected,
        ProductionDatabaseInspection::Missing | ProductionDatabaseInspection::Unavailable => {
            return Err(SetupProductionDatabaseOpenError::CurrentDatabaseUnavailable);
        }
        ProductionDatabaseInspection::Invalid => {
            return Err(SetupProductionDatabaseOpenError::CurrentDatabaseUnsafe);
        }
    };
    if !inspected.has_native_identity(
        proof.created_leaf_identity.volume_serial,
        proof.created_leaf_identity.file_id,
    ) {
        return Err(SetupProductionDatabaseOpenError::IdentityMismatch);
    }
    let key = staged_key.into_generation_bound_database_key();
    let database = open_keyed_production_database_read_only(path, inspected, key)
        .map_err(preserve_open_failure)?;
    Ok(IdentityBoundStagedKeyOpenedProductionDatabaseForSetup { database })
}

#[cfg(test)]
#[path = "identity_bound_staged_key_open_tests.rs"]
mod tests;
