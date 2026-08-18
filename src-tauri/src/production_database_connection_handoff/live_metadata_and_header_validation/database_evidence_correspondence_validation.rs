//! Consuming identity-only correspondence validation over the live metadata
//! and header validated production database owner.

use std::fmt;

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    database_metadata_correspondence::{
        DatabaseMetadataCorrespondence, classify_database_metadata_correspondence,
    },
    installation_evidence_protection::TrustedCurrentInstallationEvidenceAssessment,
};

use super::{
    super::{
        ConnectionLifetimeOwner, ProductionDatabaseConnectionCloseOutcome, close_lifetime_owner,
    },
    LiveMetadataAndHeaderValidatedProductionDatabaseConnection,
};

mod database_freshness_validation;

pub(crate) use database_freshness_validation::{
    DatabaseFreshnessValidatedProductionDatabaseConnection,
    ProductionDatabaseFreshnessValidationCloseFailure,
    ProductionDatabaseFreshnessValidationCloseRetryOutcome,
    ProductionDatabaseFreshnessValidationOutcome,
    ProductionDatabaseStartupAuthorizationCloseFailure,
    ProductionDatabaseStartupAuthorizationCloseRetryOutcome,
    ProductionDatabaseStartupAuthorizationError, ProductionDatabaseStartupAuthorizationOutcome,
    StartupAuthorizedProductionDatabaseConnection, authorize_production_database_startup,
    validate_production_database_freshness,
};

pub(crate) struct DatabaseEvidenceCorrespondenceMismatch;

impl fmt::Debug for DatabaseEvidenceCorrespondenceMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DatabaseEvidenceCorrespondenceMismatch")
    }
}

#[must_use = "the database evidence correspondence validation outcome must be handled"]
// The intentionally opaque success owner retains the complete approved trust
// chain directly; boxing would add an unrelated allocation to this transition.
#[allow(clippy::large_enum_variant)]
pub(crate) enum DatabaseEvidenceCorrespondenceValidationOutcome {
    Validated(DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection),
    Mismatch(DatabaseEvidenceCorrespondenceMismatch),
    CloseFailed(DatabaseEvidenceCorrespondenceValidationCloseFailure),
}

impl fmt::Debug for DatabaseEvidenceCorrespondenceValidationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validated(_) => formatter.write_str("Validated([REDACTED])"),
            Self::Mismatch(category) => formatter.debug_tuple("Mismatch").field(category).finish(),
            Self::CloseFailed(_) => formatter.write_str("CloseFailed([REDACTED])"),
        }
    }
}

pub(crate) struct DatabaseEvidenceCorrespondenceValidationCloseFailure {
    mismatch: DatabaseEvidenceCorrespondenceMismatch,
    owner: ConnectionLifetimeOwner,
}

impl fmt::Debug for DatabaseEvidenceCorrespondenceValidationCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DatabaseEvidenceCorrespondenceValidationCloseFailure([REDACTED])")
    }
}

#[must_use = "a database evidence correspondence close retry outcome must be handled"]
pub(crate) enum DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome {
    Closed(DatabaseEvidenceCorrespondenceMismatch),
    Failed(DatabaseEvidenceCorrespondenceValidationCloseFailure),
}

impl fmt::Debug for DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(category) => formatter.debug_tuple("Closed").field(category).finish(),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

impl DatabaseEvidenceCorrespondenceValidationCloseFailure {
    #[allow(dead_code)]
    pub(crate) fn retry_close(self) -> DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome {
        let Self { mismatch, owner } = self;
        match close_lifetime_owner(owner) {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Closed(mismatch)
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Failed(Self {
                    mismatch,
                    owner: failure.owner,
                })
            }
        }
    }
}

pub(crate) struct DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection {
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
}

impl fmt::Debug for DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection([REDACTED])",
        )
    }
}

impl DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection {
    pub(crate) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            metadata_contract,
            trusted_assessment,
        } = self;
        discard_correspondence_inputs(metadata_contract, trusted_assessment);
        close_lifetime_owner(owner)
    }
}

pub(crate) fn validate_production_database_evidence_correspondence(
    database: LiveMetadataAndHeaderValidatedProductionDatabaseConnection,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
) -> DatabaseEvidenceCorrespondenceValidationOutcome {
    let LiveMetadataAndHeaderValidatedProductionDatabaseConnection {
        owner,
        metadata_contract,
    } = database;

    match classify_database_metadata_correspondence(
        &metadata_contract,
        trusted_assessment.evidence(),
    ) {
        DatabaseMetadataCorrespondence::Corresponds => {
            DatabaseEvidenceCorrespondenceValidationOutcome::Validated(
                DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection {
                    owner,
                    metadata_contract,
                    trusted_assessment,
                },
            )
        }
        DatabaseMetadataCorrespondence::Mismatch => {
            finish_mismatch(owner, metadata_contract, trusted_assessment)
        }
    }
}

fn finish_mismatch(
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
) -> DatabaseEvidenceCorrespondenceValidationOutcome {
    discard_correspondence_inputs(metadata_contract, trusted_assessment);
    let mismatch = DatabaseEvidenceCorrespondenceMismatch;
    match close_lifetime_owner(owner) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            DatabaseEvidenceCorrespondenceValidationOutcome::Mismatch(mismatch)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            DatabaseEvidenceCorrespondenceValidationOutcome::CloseFailed(
                DatabaseEvidenceCorrespondenceValidationCloseFailure {
                    mismatch,
                    owner: failure.owner,
                },
            )
        }
    }
}

fn discard_correspondence_inputs<T, U>(metadata_contract: T, trusted_assessment: U) {
    drop(metadata_contract);
    drop(trusted_assessment);
}

#[cfg(test)]
impl DatabaseEvidenceCorrespondenceValidationCloseFailure {
    pub(super) fn retry_close_using(
        self,
        close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
    ) -> DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome {
        let Self { mismatch, owner } = self;
        match super::super::close_lifetime_owner_using(owner, close) {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Closed(mismatch)
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Failed(Self {
                    mismatch,
                    owner: failure.owner,
                })
            }
        }
    }
}

#[cfg(test)]
impl DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection {
    pub(super) fn close_using(
        self,
        close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
    ) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            metadata_contract,
            trusted_assessment,
        } = self;
        close_correspondence_owner_using(owner, metadata_contract, trusted_assessment, close)
    }
}

#[cfg(test)]
pub(super) fn finish_mismatch_using<T, U>(
    owner: ConnectionLifetimeOwner,
    metadata_contract: T,
    trusted_assessment: U,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> DatabaseEvidenceCorrespondenceValidationOutcome {
    discard_correspondence_inputs(metadata_contract, trusted_assessment);
    let mismatch = DatabaseEvidenceCorrespondenceMismatch;
    match super::super::close_lifetime_owner_using(owner, close) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            DatabaseEvidenceCorrespondenceValidationOutcome::Mismatch(mismatch)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            DatabaseEvidenceCorrespondenceValidationOutcome::CloseFailed(
                DatabaseEvidenceCorrespondenceValidationCloseFailure {
                    mismatch,
                    owner: failure.owner,
                },
            )
        }
    }
}

#[cfg(test)]
pub(super) fn close_correspondence_owner_using<T, U>(
    owner: ConnectionLifetimeOwner,
    metadata_contract: T,
    trusted_assessment: U,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseConnectionCloseOutcome {
    discard_correspondence_inputs(metadata_contract, trusted_assessment);
    super::super::close_lifetime_owner_using(owner, close)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    struct DropProbe<'a>(&'a Cell<bool>);

    impl Drop for DropProbe<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    #[test]
    fn discard_helper_drops_metadata_and_assessment_in_order() {
        let metadata_dropped = Cell::new(false);
        let assessment_dropped = Cell::new(false);
        discard_correspondence_inputs(DropProbe(&metadata_dropped), DropProbe(&assessment_dropped));
        assert!(metadata_dropped.get());
        assert!(assessment_dropped.get());
    }

    #[test]
    fn production_source_invokes_only_the_pure_classifier_once_and_has_no_forbidden_capability() {
        const SOURCE: &str = include_str!("database_evidence_correspondence_validation.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();

        assert_eq!(
            production
                .matches("classify_database_metadata_correspondence(")
                .count(),
            1
        );
        assert!(production.contains("&metadata_contract"));
        assert!(production.contains("trusted_assessment.evidence()"));

        for forbidden in [
            "SELECT ",
            "PRAGMA",
            ".prepare(",
            ".query(",
            ".query_row(",
            ".get_ref(",
            "AsRef<Connection>",
            "with_connection",
            "std::fs",
            "std::path",
            "load_trusted",
            "DPAPI",
            "dpapi",
            "HMAC",
            "hmac",
            "envelope",
            "plaintext",
            "RawDatabaseMetadataRow",
            "installation_generation()",
            "recovery_or_replacement_generation()",
            "database_created_at()",
            "creation_timestamp()",
            "CREATE TABLE",
            "ALTER TABLE",
            "tauri::command",
            "invoke_handler",
            "pub fn",
            "impl Clone",
            "impl Copy",
            "#[derive(",
            "unsafe {",
            "extern \"",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden production capability: {forbidden}"
            );
        }

        let success_body = production
            .split_once(
                "pub(crate) struct DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection {",
            )
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(
            success_body
                .lines()
                .filter(|line| line.contains(':'))
                .count(),
            3
        );
        assert!(success_body.contains("owner: ConnectionLifetimeOwner"));
        assert!(success_body.contains("metadata_contract: DatabaseMetadataContractV1"));
        assert!(
            success_body
                .contains("trusted_assessment: TrustedCurrentInstallationEvidenceAssessment")
        );

        let failure_body = production
            .split_once("pub(crate) struct DatabaseEvidenceCorrespondenceValidationCloseFailure {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(
            failure_body
                .lines()
                .filter(|line| line.contains(':'))
                .count(),
            2
        );
        assert!(failure_body.contains("mismatch: DatabaseEvidenceCorrespondenceMismatch"));
        assert!(failure_body.contains("owner: ConnectionLifetimeOwner"));
        assert!(!failure_body.contains("metadata"));
        assert!(!failure_body.contains("assessment"));
    }

    #[test]
    fn manual_debug_is_coarse_and_redacted() {
        assert_eq!(
            format!("{:?}", DatabaseEvidenceCorrespondenceMismatch),
            "DatabaseEvidenceCorrespondenceMismatch"
        );
        assert_eq!(
            format!(
                "{:?}",
                DatabaseEvidenceCorrespondenceValidationOutcome::Mismatch(
                    DatabaseEvidenceCorrespondenceMismatch
                )
            ),
            "Mismatch(DatabaseEvidenceCorrespondenceMismatch)"
        );
        assert_eq!(
            format!(
                "{:?}",
                DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Closed(
                    DatabaseEvidenceCorrespondenceMismatch
                )
            ),
            "Closed(DatabaseEvidenceCorrespondenceMismatch)"
        );
    }
}
