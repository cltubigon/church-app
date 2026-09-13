//! Private, unwired offer-time ownership boundary for the fixed production
//! database schema-1 to schema-2 migration policy.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    installation_evidence_protection::TrustedCurrentInstallationEvidenceAssessment,
    installation_state::{ExpectedStorageEvidence, InstallationEvidence},
};

use super::{
    ConnectionLifetimeOwner, DatabaseFreshnessValidatedProductionDatabaseConnection,
    ProductionDatabaseConnectionCloseOutcome,
};

/// Opaque ownership proving only that the exact retained fresh source database
/// met the fixed schema-1 to schema-2 opportunity policy at offer time.
pub(crate) struct ProductionDatabaseMigrationOpportunity {
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
}

impl fmt::Debug for ProductionDatabaseMigrationOpportunity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseMigrationOpportunity([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProductionDatabaseMigrationOpportunityError {
    NeverInitialized,
    ExpectedStorageMissing,
    InstallationStateInconsistent,
    InstallationStateUnavailable,
}

impl fmt::Debug for ProductionDatabaseMigrationOpportunityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NeverInitialized => "NeverInitialized",
            Self::ExpectedStorageMissing => "ExpectedStorageMissing",
            Self::InstallationStateInconsistent => "InstallationStateInconsistent",
            Self::InstallationStateUnavailable => "InstallationStateUnavailable",
        })
    }
}

#[must_use = "the production database migration opportunity outcome must be handled"]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProductionDatabaseMigrationOpportunityOutcome {
    Offered(ProductionDatabaseMigrationOpportunity),
    Failed(ProductionDatabaseMigrationOpportunityError),
    CloseFailed(ProductionDatabaseMigrationOpportunityCloseFailure),
}

impl fmt::Debug for ProductionDatabaseMigrationOpportunityOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offered(_) => formatter.write_str("Offered([REDACTED])"),
            Self::Failed(category) => formatter.debug_tuple("Failed").field(category).finish(),
            Self::CloseFailed(_) => formatter.write_str("CloseFailed([REDACTED])"),
        }
    }
}

pub(crate) struct ProductionDatabaseMigrationOpportunityCloseFailure {
    category: ProductionDatabaseMigrationOpportunityError,
    owner: ConnectionLifetimeOwner,
}

impl fmt::Debug for ProductionDatabaseMigrationOpportunityCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseMigrationOpportunityCloseFailure([REDACTED])")
    }
}

#[must_use = "a production database migration opportunity close retry outcome must be handled"]
pub(crate) enum ProductionDatabaseMigrationOpportunityCloseRetryOutcome {
    Closed(ProductionDatabaseMigrationOpportunityError),
    Failed(ProductionDatabaseMigrationOpportunityCloseFailure),
}

impl fmt::Debug for ProductionDatabaseMigrationOpportunityCloseRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(category) => formatter.debug_tuple("Closed").field(category).finish(),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

impl ProductionDatabaseMigrationOpportunityCloseFailure {
    /// Consumes the retained lifetime unit and retries only explicit close.
    pub(crate) fn retry_close(self) -> ProductionDatabaseMigrationOpportunityCloseRetryOutcome {
        retry_failed_offer_close(self)
    }
}

impl ProductionDatabaseMigrationOpportunity {
    /// Discards opportunity-only capability state before explicitly closing the
    /// unchanged guarded database lifetime through the canonical close path.
    pub(crate) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            metadata_contract,
            trusted_assessment,
        } = self;
        close_opportunity_owner(owner, metadata_contract, trusted_assessment)
    }
}

pub(crate) fn offer_production_database_migration_opportunity(
    database: DatabaseFreshnessValidatedProductionDatabaseConnection,
    installation_evidence: InstallationEvidence,
) -> ProductionDatabaseMigrationOpportunityOutcome {
    let DatabaseFreshnessValidatedProductionDatabaseConnection {
        owner,
        metadata_contract,
        trusted_assessment,
    } = database;

    let category = match installation_evidence {
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Present) => {
            discard_installation_evidence(installation_evidence);
            return ProductionDatabaseMigrationOpportunityOutcome::Offered(
                ProductionDatabaseMigrationOpportunity {
                    owner,
                    metadata_contract,
                    trusted_assessment,
                },
            );
        }
        InstallationEvidence::NeverInitialized => {
            ProductionDatabaseMigrationOpportunityError::NeverInitialized
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing) => {
            ProductionDatabaseMigrationOpportunityError::ExpectedStorageMissing
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable)
        | InstallationEvidence::Unavailable => {
            ProductionDatabaseMigrationOpportunityError::InstallationStateUnavailable
        }
        InstallationEvidence::Inconsistent => {
            ProductionDatabaseMigrationOpportunityError::InstallationStateInconsistent
        }
    };

    finish_failed_offer(
        category,
        owner,
        metadata_contract,
        trusted_assessment,
        installation_evidence,
    )
}

fn discard_installation_evidence<T>(installation_evidence: T) {
    drop(installation_evidence);
}

fn finish_failed_offer(
    category: ProductionDatabaseMigrationOpportunityError,
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
    installation_evidence: InstallationEvidence,
) -> ProductionDatabaseMigrationOpportunityOutcome {
    discard_failed_offer_inputs(installation_evidence, metadata_contract, trusted_assessment);
    match super::super::super::super::close_lifetime_owner(owner) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseMigrationOpportunityOutcome::Failed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseMigrationOpportunityOutcome::CloseFailed(
                ProductionDatabaseMigrationOpportunityCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

fn discard_failed_offer_inputs<T, U, V>(
    installation_evidence: T,
    metadata_contract: U,
    trusted_assessment: V,
) {
    drop(installation_evidence);
    drop(metadata_contract);
    drop(trusted_assessment);
}

fn retry_failed_offer_close(
    failure: ProductionDatabaseMigrationOpportunityCloseFailure,
) -> ProductionDatabaseMigrationOpportunityCloseRetryOutcome {
    let ProductionDatabaseMigrationOpportunityCloseFailure { category, owner } = failure;
    match super::super::super::super::close_lifetime_owner(owner) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseMigrationOpportunityCloseRetryOutcome::Closed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseMigrationOpportunityCloseRetryOutcome::Failed(
                ProductionDatabaseMigrationOpportunityCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

fn close_opportunity_owner(
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
) -> ProductionDatabaseConnectionCloseOutcome {
    discard_opportunity_inputs(metadata_contract, trusted_assessment);
    super::super::super::super::close_lifetime_owner(owner)
}

fn discard_opportunity_inputs<T, U>(metadata_contract: T, trusted_assessment: U) {
    drop(metadata_contract);
    drop(trusted_assessment);
}

#[cfg(test)]
pub(crate) fn genuine_production_database_migration_opportunity_for_test() -> (
    super::tests::TestRoot,
    ProductionDatabaseMigrationOpportunity,
) {
    let (root, database) = super::tests::fresh_owner();
    let ProductionDatabaseMigrationOpportunityOutcome::Offered(opportunity) =
        offer_production_database_migration_opportunity(
            database,
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Present),
        )
    else {
        panic!("synthetic source-1 freshness chain should produce a genuine opportunity");
    };
    (root, opportunity)
}

#[cfg(test)]
fn offer_production_database_migration_opportunity_using(
    database: DatabaseFreshnessValidatedProductionDatabaseConnection,
    installation_evidence: InstallationEvidence,
    close_on_failure: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseMigrationOpportunityOutcome {
    let DatabaseFreshnessValidatedProductionDatabaseConnection {
        owner,
        metadata_contract,
        trusted_assessment,
    } = database;

    let category = match installation_evidence {
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Present) => {
            discard_installation_evidence(installation_evidence);
            return ProductionDatabaseMigrationOpportunityOutcome::Offered(
                ProductionDatabaseMigrationOpportunity {
                    owner,
                    metadata_contract,
                    trusted_assessment,
                },
            );
        }
        InstallationEvidence::NeverInitialized => {
            ProductionDatabaseMigrationOpportunityError::NeverInitialized
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing) => {
            ProductionDatabaseMigrationOpportunityError::ExpectedStorageMissing
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable)
        | InstallationEvidence::Unavailable => {
            ProductionDatabaseMigrationOpportunityError::InstallationStateUnavailable
        }
        InstallationEvidence::Inconsistent => {
            ProductionDatabaseMigrationOpportunityError::InstallationStateInconsistent
        }
    };

    finish_failed_offer_using(
        category,
        owner,
        metadata_contract,
        trusted_assessment,
        installation_evidence,
        close_on_failure,
    )
}

#[cfg(test)]
fn finish_failed_offer_using<T, U, V>(
    category: ProductionDatabaseMigrationOpportunityError,
    owner: ConnectionLifetimeOwner,
    metadata_contract: T,
    trusted_assessment: U,
    installation_evidence: V,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseMigrationOpportunityOutcome {
    discard_failed_offer_inputs(installation_evidence, metadata_contract, trusted_assessment);
    match super::super::super::super::close_lifetime_owner_using(owner, close) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseMigrationOpportunityOutcome::Failed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseMigrationOpportunityOutcome::CloseFailed(
                ProductionDatabaseMigrationOpportunityCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

#[cfg(test)]
fn retry_failed_offer_close_using(
    failure: ProductionDatabaseMigrationOpportunityCloseFailure,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseMigrationOpportunityCloseRetryOutcome {
    let ProductionDatabaseMigrationOpportunityCloseFailure { category, owner } = failure;
    match super::super::super::super::close_lifetime_owner_using(owner, close) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseMigrationOpportunityCloseRetryOutcome::Closed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseMigrationOpportunityCloseRetryOutcome::Failed(
                ProductionDatabaseMigrationOpportunityCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

#[cfg(test)]
fn close_opportunity_owner_using<T, U>(
    owner: ConnectionLifetimeOwner,
    metadata_contract: T,
    trusted_assessment: U,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseConnectionCloseOutcome {
    discard_opportunity_inputs(metadata_contract, trusted_assessment);
    super::super::super::super::close_lifetime_owner_using(owner, close)
}

#[cfg(test)]
impl ProductionDatabaseMigrationOpportunityCloseFailure {
    fn retry_close_using(
        self,
        close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
    ) -> ProductionDatabaseMigrationOpportunityCloseRetryOutcome {
        retry_failed_offer_close_using(self, close)
    }
}

#[cfg(test)]
impl ProductionDatabaseMigrationOpportunity {
    fn close_using(
        self,
        close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
    ) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            metadata_contract,
            trusted_assessment,
        } = self;
        close_opportunity_owner_using(owner, metadata_contract, trusted_assessment, close)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    const NON_SUCCESS_CASES: [(
        InstallationEvidence,
        ProductionDatabaseMigrationOpportunityError,
    ); 5] = [
        (
            InstallationEvidence::NeverInitialized,
            ProductionDatabaseMigrationOpportunityError::NeverInitialized,
        ),
        (
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing),
            ProductionDatabaseMigrationOpportunityError::ExpectedStorageMissing,
        ),
        (
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable),
            ProductionDatabaseMigrationOpportunityError::InstallationStateUnavailable,
        ),
        (
            InstallationEvidence::Inconsistent,
            ProductionDatabaseMigrationOpportunityError::InstallationStateInconsistent,
        ),
        (
            InstallationEvidence::Unavailable,
            ProductionDatabaseMigrationOpportunityError::InstallationStateUnavailable,
        ),
    ];

    const PRIMARY_CASES: [(
        InstallationEvidence,
        ProductionDatabaseMigrationOpportunityError,
    ); 4] = [
        (
            InstallationEvidence::NeverInitialized,
            ProductionDatabaseMigrationOpportunityError::NeverInitialized,
        ),
        (
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing),
            ProductionDatabaseMigrationOpportunityError::ExpectedStorageMissing,
        ),
        (
            InstallationEvidence::Inconsistent,
            ProductionDatabaseMigrationOpportunityError::InstallationStateInconsistent,
        ),
        (
            InstallationEvidence::Unavailable,
            ProductionDatabaseMigrationOpportunityError::InstallationStateUnavailable,
        ),
    ];

    struct DropProbe<'a>(&'a Cell<bool>);

    impl Drop for DropProbe<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    #[test]
    fn genuine_source_one_and_initialized_present_offer_redact_retain_and_close() {
        let (root, database) = super::super::tests::fresh_owner();
        assert_eq!(
            database.metadata_contract.database_schema_version().get(),
            1
        );
        let expected_path = database.owner.connection.path().map(str::to_owned);
        let outcome = offer_production_database_migration_opportunity(
            database,
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Present),
        );
        assert_eq!(format!("{outcome:?}"), "Offered([REDACTED])");
        let ProductionDatabaseMigrationOpportunityOutcome::Offered(opportunity) = outcome else {
            panic!("initialized present evidence should offer the fixed opportunity");
        };
        assert_eq!(
            format!("{opportunity:?}"),
            "ProductionDatabaseMigrationOpportunity([REDACTED])"
        );
        assert!(matches!(
            opportunity.close_using(|connection| {
                assert_eq!(connection.path().map(str::to_owned), expected_path);
                connection
                    .close()
                    .map_err(|(returned_connection, _)| returned_connection)
            }),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();

        let (root, database) = super::super::tests::fresh_owner();
        let ProductionDatabaseMigrationOpportunityOutcome::Offered(opportunity) =
            offer_production_database_migration_opportunity(
                database,
                InstallationEvidence::Initialized(ExpectedStorageEvidence::Present),
            )
        else {
            panic!("initialized present evidence should offer the fixed opportunity");
        };
        assert!(matches!(
            opportunity.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn every_other_actual_installation_observation_fails_closed_without_owner() {
        for (evidence, expected) in NON_SUCCESS_CASES {
            let (root, database) = super::super::tests::fresh_owner();
            let outcome = offer_production_database_migration_opportunity(database, evidence);
            assert!(matches!(
                outcome,
                ProductionDatabaseMigrationOpportunityOutcome::Failed(observed)
                    if observed == expected
            ));
            assert_eq!(format!("{outcome:?}"), format!("Failed({expected:?})"));
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn failed_offer_discards_decision_inputs_before_close() {
        let (root, database) = super::super::tests::fresh_owner();
        let DatabaseFreshnessValidatedProductionDatabaseConnection { owner, .. } = database;
        let evidence_dropped = Cell::new(false);
        let metadata_dropped = Cell::new(false);
        let assessment_dropped = Cell::new(false);
        let outcome = finish_failed_offer_using(
            ProductionDatabaseMigrationOpportunityError::NeverInitialized,
            owner,
            DropProbe(&metadata_dropped),
            DropProbe(&assessment_dropped),
            DropProbe(&evidence_dropped),
            |connection| {
                assert!(evidence_dropped.get());
                assert!(metadata_dropped.get());
                assert!(assessment_dropped.get());
                drop(connection);
                Ok(())
            },
        );
        assert!(matches!(
            outcome,
            ProductionDatabaseMigrationOpportunityOutcome::Failed(
                ProductionDatabaseMigrationOpportunityError::NeverInitialized
            )
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn policy_close_failure_preserves_primary_category_and_owner_across_retries() {
        for (evidence, expected) in PRIMARY_CASES {
            let (root, database) = super::super::tests::fresh_owner();
            let outcome =
                offer_production_database_migration_opportunity_using(database, evidence, Err);
            assert_eq!(format!("{outcome:?}"), "CloseFailed([REDACTED])");
            let ProductionDatabaseMigrationOpportunityOutcome::CloseFailed(failure) = outcome
            else {
                panic!("injected failed close should retain lifetime ownership");
            };
            assert_eq!(
                format!("{failure:?}"),
                "ProductionDatabaseMigrationOpportunityCloseFailure([REDACTED])"
            );
            let close_calls = Cell::new(0_u8);
            let retry = failure.retry_close_using(|connection| {
                close_calls.set(close_calls.get() + 1);
                Err(connection)
            });
            assert_eq!(close_calls.get(), 1);
            assert_eq!(format!("{retry:?}"), "Failed([REDACTED])");
            let ProductionDatabaseMigrationOpportunityCloseRetryOutcome::Failed(failure) = retry
            else {
                panic!("repeated failed close should retain lifetime ownership");
            };
            assert!(matches!(
                failure.retry_close(),
                ProductionDatabaseMigrationOpportunityCloseRetryOutcome::Closed(observed)
                    if observed == expected
            ));
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn opportunity_close_failure_retains_the_general_guarded_lifetime() {
        let (root, database) = super::super::tests::fresh_owner();
        let ProductionDatabaseMigrationOpportunityOutcome::Offered(opportunity) =
            offer_production_database_migration_opportunity(
                database,
                InstallationEvidence::Initialized(ExpectedStorageEvidence::Present),
            )
        else {
            panic!("initialized present evidence should offer the fixed opportunity");
        };
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            opportunity.close_using(Err)
        else {
            panic!("injected opportunity close should retain lifetime ownership");
        };
        assert_eq!(
            format!("{failure:?}"),
            "ProductionDatabaseConnectionCloseFailure([REDACTED])"
        );
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn opportunity_is_non_forgeable_non_transferable_and_non_serializable() {
        macro_rules! assert_not_impl {
            ($owner:ty, $bound:path) => {{
                trait AmbiguousIfImpl<A> {
                    fn check() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                struct Implemented;
                impl<T: ?Sized + $bound> AmbiguousIfImpl<Implemented> for T {}
                let _ = <$owner as AmbiguousIfImpl<_>>::check;
            }};
        }

        assert_not_impl!(ProductionDatabaseMigrationOpportunity, Clone);
        assert_not_impl!(ProductionDatabaseMigrationOpportunity, Copy);
        assert_not_impl!(ProductionDatabaseMigrationOpportunity, Default);
        assert_not_impl!(ProductionDatabaseMigrationOpportunity, std::ops::Deref);
        assert_not_impl!(ProductionDatabaseMigrationOpportunity, serde::Serialize);
        assert_not_impl!(
            ProductionDatabaseMigrationOpportunity,
            serde::Deserialize<'static>
        );
    }

    #[test]
    fn debug_exposes_only_payload_free_categories_and_redacted_owners() {
        for (category, expected) in [
            (
                ProductionDatabaseMigrationOpportunityError::NeverInitialized,
                "NeverInitialized",
            ),
            (
                ProductionDatabaseMigrationOpportunityError::ExpectedStorageMissing,
                "ExpectedStorageMissing",
            ),
            (
                ProductionDatabaseMigrationOpportunityError::InstallationStateInconsistent,
                "InstallationStateInconsistent",
            ),
            (
                ProductionDatabaseMigrationOpportunityError::InstallationStateUnavailable,
                "InstallationStateUnavailable",
            ),
        ] {
            assert_eq!(format!("{category:?}"), expected);
            assert_eq!(
                format!(
                    "{:?}",
                    ProductionDatabaseMigrationOpportunityOutcome::Failed(category)
                ),
                format!("Failed({expected})")
            );
            assert_eq!(
                format!(
                    "{:?}",
                    ProductionDatabaseMigrationOpportunityCloseRetryOutcome::Closed(category)
                ),
                format!("Closed({expected})")
            );
        }
    }

    #[test]
    fn production_source_is_exactly_the_private_fixed_offer_time_boundary() {
        const SOURCE: &str = include_str!("production_database_migration_opportunity.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let compact_production: String = production
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();

        assert!(production.contains(
            "pub(crate) fn offer_production_database_migration_opportunity(\n    database: DatabaseFreshnessValidatedProductionDatabaseConnection,\n    installation_evidence: InstallationEvidence,\n) -> ProductionDatabaseMigrationOpportunityOutcome"
        ));
        assert_eq!(
            production
                .matches("InstallationEvidence::Initialized(ExpectedStorageEvidence::Present)")
                .count(),
            1
        );

        let opportunity = production
            .split_once("pub(crate) struct ProductionDatabaseMigrationOpportunity {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(
            opportunity
                .lines()
                .filter(|line| line.contains(':'))
                .count(),
            3
        );
        assert!(opportunity.contains("owner: ConnectionLifetimeOwner"));
        assert!(opportunity.contains("metadata_contract: DatabaseMetadataContractV1"));
        assert!(
            opportunity
                .contains("trusted_assessment: TrustedCurrentInstallationEvidenceAssessment")
        );
        for forbidden_field in [
            "source_version",
            "target_version",
            ": InstallationEvidence",
            "bool",
            "Path",
            "connection: rusqlite::Connection",
        ] {
            assert!(
                !opportunity.contains(forbidden_field),
                "forbidden opportunity field: {forbidden_field}"
            );
        }

        let failure = production
            .split_once("pub(crate) struct ProductionDatabaseMigrationOpportunityCloseFailure {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(failure.lines().filter(|line| line.contains(':')).count(), 2);
        assert!(failure.contains("category: ProductionDatabaseMigrationOpportunityError"));
        assert!(failure.contains("owner: ConnectionLifetimeOwner"));
        assert!(!failure.contains("InstallationEvidence"));
        assert!(!failure.contains("metadata"));
        assert!(!failure.contains("assessment"));

        for forbidden in [
            "source_version",
            "target_version",
            "DatabaseSchemaVersion",
            "MigrationPlan",
            "MaintenanceOperation",
            "impl FnOnce(rusqlite::Connection",
            "FnOnce(rusqlite::Connection",
            "impl FnOnce(Connection",
            "FnOnce(Connection",
            "classify_database_freshness(",
            "classify_database_metadata_correspondence(",
            "validate_production_database_live_metadata",
            "validate_production_database_readability",
            "validate_production_database_full_integrity",
            "inspect_production_database_file",
            "SELECT ",
            "PRAGMA",
            ".prepare(",
            ".query(",
            ".query_row(",
            ".execute(",
            ".execute_batch(",
            "CREATE TABLE",
            "ALTER TABLE",
            "DROP TABLE",
            "std::fs",
            "fs::",
            "std::path",
            "PathBuf",
            "evidence_directory",
            "anchor",
            "load_",
            "backup",
            "writable",
            "exclusive",
            "tauri::command",
            "invoke_handler",
            "serde::Serialize",
            "serde::Deserialize",
            "pub fn",
            "pub(crate) fn new",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden production capability: {forbidden}"
            );
        }
        for forbidden in [
            "implFnOnce(rusqlite::Connection",
            "FnOnce(rusqlite::Connection",
            "implFnOnce(Connection",
            "FnOnce(Connection",
        ] {
            assert!(
                !compact_production.contains(forbidden),
                "formatting-obscured production callback seam: {forbidden}"
            );
        }
    }

    #[test]
    fn opportunity_transition_is_unwired_outside_its_focused_tests() {
        const PARENT: &str = include_str!("../database_freshness_validation.rs");
        const HANDOFF: &str = include_str!("../../../../production_database_connection_handoff.rs");
        const LIFECYCLE: &str = include_str!("../../../../application_lifecycle.rs");
        const CONFIRMATION: &str = include_str!(
            "../../../../application_lifecycle/production_database_migration_confirmation.rs"
        );

        assert_eq!(
            PARENT
                .matches("mod production_database_migration_opportunity;")
                .count(),
            1
        );
        for outside_source in [PARENT, HANDOFF, LIFECYCLE, CONFIRMATION] {
            assert!(!outside_source.contains("offer_production_database_migration_opportunity("));
        }
    }
}
