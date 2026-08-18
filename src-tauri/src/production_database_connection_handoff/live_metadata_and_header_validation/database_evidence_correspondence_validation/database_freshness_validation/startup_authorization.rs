//! Consuming startup authorization over the freshness-validated owner.

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

pub(crate) struct StartupAuthorizedProductionDatabaseConnection {
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
}

impl fmt::Debug for StartupAuthorizedProductionDatabaseConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StartupAuthorizedProductionDatabaseConnection([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProductionDatabaseStartupAuthorizationError {
    NeverInitialized,
    ExpectedStorageMissing,
    InstallationStateInconsistent,
    InstallationStateUnavailable,
}

impl fmt::Debug for ProductionDatabaseStartupAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NeverInitialized => "NeverInitialized",
            Self::ExpectedStorageMissing => "ExpectedStorageMissing",
            Self::InstallationStateInconsistent => "InstallationStateInconsistent",
            Self::InstallationStateUnavailable => "InstallationStateUnavailable",
        })
    }
}

#[must_use = "the production database startup authorization outcome must be handled"]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProductionDatabaseStartupAuthorizationOutcome {
    Authorized(StartupAuthorizedProductionDatabaseConnection),
    Failed(ProductionDatabaseStartupAuthorizationError),
    CloseFailed(ProductionDatabaseStartupAuthorizationCloseFailure),
}

impl fmt::Debug for ProductionDatabaseStartupAuthorizationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorized(_) => formatter.write_str("Authorized([REDACTED])"),
            Self::Failed(category) => formatter.debug_tuple("Failed").field(category).finish(),
            Self::CloseFailed(_) => formatter.write_str("CloseFailed([REDACTED])"),
        }
    }
}

pub(crate) struct ProductionDatabaseStartupAuthorizationCloseFailure {
    category: ProductionDatabaseStartupAuthorizationError,
    owner: ConnectionLifetimeOwner,
}

impl fmt::Debug for ProductionDatabaseStartupAuthorizationCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseStartupAuthorizationCloseFailure([REDACTED])")
    }
}

#[must_use = "a production database startup authorization close retry outcome must be handled"]
pub(crate) enum ProductionDatabaseStartupAuthorizationCloseRetryOutcome {
    Closed(ProductionDatabaseStartupAuthorizationError),
    Failed(ProductionDatabaseStartupAuthorizationCloseFailure),
}

impl fmt::Debug for ProductionDatabaseStartupAuthorizationCloseRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(category) => formatter.debug_tuple("Closed").field(category).finish(),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

impl ProductionDatabaseStartupAuthorizationCloseFailure {
    pub(crate) fn retry_close(self) -> ProductionDatabaseStartupAuthorizationCloseRetryOutcome {
        retry_unauthorized_close(self)
    }
}

impl StartupAuthorizedProductionDatabaseConnection {
    pub(crate) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            metadata_contract,
            trusted_assessment,
        } = self;
        close_authorized_owner(owner, metadata_contract, trusted_assessment)
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use std::cell::Cell;

    use super::*;

    const NON_SUCCESS_CASES: [(
        InstallationEvidence,
        ProductionDatabaseStartupAuthorizationError,
    ); 5] = [
        (
            InstallationEvidence::NeverInitialized,
            ProductionDatabaseStartupAuthorizationError::NeverInitialized,
        ),
        (
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing),
            ProductionDatabaseStartupAuthorizationError::ExpectedStorageMissing,
        ),
        (
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable),
            ProductionDatabaseStartupAuthorizationError::InstallationStateUnavailable,
        ),
        (
            InstallationEvidence::Inconsistent,
            ProductionDatabaseStartupAuthorizationError::InstallationStateInconsistent,
        ),
        (
            InstallationEvidence::Unavailable,
            ProductionDatabaseStartupAuthorizationError::InstallationStateUnavailable,
        ),
    ];

    const PRIMARY_CASES: [(
        InstallationEvidence,
        ProductionDatabaseStartupAuthorizationError,
    ); 4] = [
        (
            InstallationEvidence::NeverInitialized,
            ProductionDatabaseStartupAuthorizationError::NeverInitialized,
        ),
        (
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing),
            ProductionDatabaseStartupAuthorizationError::ExpectedStorageMissing,
        ),
        (
            InstallationEvidence::Inconsistent,
            ProductionDatabaseStartupAuthorizationError::InstallationStateInconsistent,
        ),
        (
            InstallationEvidence::Unavailable,
            ProductionDatabaseStartupAuthorizationError::InstallationStateUnavailable,
        ),
    ];

    struct DropProbe<'a>(&'a Cell<bool>);

    impl Drop for DropProbe<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    #[test]
    fn initialized_present_real_sqlcipher_chain_authorizes_redacts_closes_and_cleans_exactly() {
        let (root, database) = super::super::tests::fresh_owner();
        let outcome = authorize_production_database_startup(
            database,
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Present),
        );
        assert_eq!(format!("{outcome:?}"), "Authorized([REDACTED])");
        let ProductionDatabaseStartupAuthorizationOutcome::Authorized(owner) = outcome else {
            panic!("initialized present evidence should authorize startup");
        };
        assert_eq!(
            format!("{owner:?}"),
            "StartupAuthorizedProductionDatabaseConnection([REDACTED])"
        );
        assert!(matches!(
            owner.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn every_non_success_observation_maps_exactly_never_authorizes_and_closes() {
        for (evidence, expected) in NON_SUCCESS_CASES {
            let (root, database) = super::super::tests::fresh_owner();
            let outcome = authorize_production_database_startup(database, evidence);
            assert!(matches!(
                outcome,
                ProductionDatabaseStartupAuthorizationOutcome::Failed(observed)
                    if observed == expected
            ));
            assert_eq!(format!("{outcome:?}"), format!("Failed({expected:?})"));
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn metadata_and_assessment_drop_before_failure_close() {
        let (root, database) = super::super::tests::fresh_owner();
        let DatabaseFreshnessValidatedProductionDatabaseConnection { owner, .. } = database;
        let metadata_dropped = Cell::new(false);
        let assessment_dropped = Cell::new(false);
        let close_called = Cell::new(false);
        let outcome = finish_unauthorized_using(
            ProductionDatabaseStartupAuthorizationError::NeverInitialized,
            owner,
            DropProbe(&metadata_dropped),
            DropProbe(&assessment_dropped),
            InstallationEvidence::NeverInitialized,
            |connection| {
                assert!(metadata_dropped.get());
                assert!(assessment_dropped.get());
                close_called.set(true);
                drop(connection);
                Ok(())
            },
        );
        assert!(close_called.get());
        assert!(matches!(
            outcome,
            ProductionDatabaseStartupAuthorizationOutcome::Failed(
                ProductionDatabaseStartupAuthorizationError::NeverInitialized
            )
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn every_primary_close_failure_preserves_category_and_owner_across_retry() {
        for (evidence, expected) in PRIMARY_CASES {
            let (root, database) = super::super::tests::fresh_owner();
            let outcome = authorize_production_database_startup_using(database, evidence, Err);
            assert_eq!(format!("{outcome:?}"), "CloseFailed([REDACTED])");
            let ProductionDatabaseStartupAuthorizationOutcome::CloseFailed(failure) = outcome
            else {
                panic!("injected failed close should retain ownership");
            };
            assert_eq!(
                format!("{failure:?}"),
                "ProductionDatabaseStartupAuthorizationCloseFailure([REDACTED])"
            );
            let close_calls = Cell::new(0_u8);
            let retry = failure.retry_close_using(|connection| {
                close_calls.set(close_calls.get() + 1);
                Err(connection)
            });
            assert_eq!(close_calls.get(), 1);
            assert_eq!(format!("{retry:?}"), "Failed([REDACTED])");
            let ProductionDatabaseStartupAuthorizationCloseRetryOutcome::Failed(failure) = retry
            else {
                panic!("repeated failed close should retain ownership");
            };
            assert!(matches!(
                failure.retry_close(),
                ProductionDatabaseStartupAuthorizationCloseRetryOutcome::Closed(observed)
                    if observed == expected
            ));
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn authorized_owner_drops_inputs_before_close_and_reuses_general_failure() {
        let (root, database) = super::super::tests::fresh_owner();
        let outcome = authorize_production_database_startup(
            database,
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Present),
        );
        let ProductionDatabaseStartupAuthorizationOutcome::Authorized(owner) = outcome else {
            panic!("initialized present evidence should authorize startup");
        };
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) = owner.close_using(Err)
        else {
            panic!("injected owner close should retain general lifetime ownership");
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

        let (root, database) = super::super::tests::fresh_owner();
        let DatabaseFreshnessValidatedProductionDatabaseConnection { owner, .. } = database;
        let metadata_dropped = Cell::new(false);
        let assessment_dropped = Cell::new(false);
        let outcome = close_authorized_owner_using(
            owner,
            DropProbe(&metadata_dropped),
            DropProbe(&assessment_dropped),
            |connection| {
                assert!(metadata_dropped.get());
                assert!(assessment_dropped.get());
                drop(connection);
                Ok(())
            },
        );
        assert!(matches!(
            outcome,
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn manual_debug_reveals_only_payload_free_primary_categories() {
        for (category, expected) in [
            (
                ProductionDatabaseStartupAuthorizationError::NeverInitialized,
                "NeverInitialized",
            ),
            (
                ProductionDatabaseStartupAuthorizationError::ExpectedStorageMissing,
                "ExpectedStorageMissing",
            ),
            (
                ProductionDatabaseStartupAuthorizationError::InstallationStateInconsistent,
                "InstallationStateInconsistent",
            ),
            (
                ProductionDatabaseStartupAuthorizationError::InstallationStateUnavailable,
                "InstallationStateUnavailable",
            ),
        ] {
            assert_eq!(format!("{category:?}"), expected);
            assert_eq!(
                format!(
                    "{:?}",
                    ProductionDatabaseStartupAuthorizationOutcome::Failed(category)
                ),
                format!("Failed({expected})")
            );
            assert_eq!(
                format!(
                    "{:?}",
                    ProductionDatabaseStartupAuthorizationCloseRetryOutcome::Closed(category)
                ),
                format!("Closed({expected})")
            );
        }
    }

    #[test]
    fn production_source_is_the_narrow_non_operational_startup_adapter() {
        const SOURCE: &str = include_str!("startup_authorization.rs");
        let declarations = SOURCE.split("#[cfg(test)]").next().unwrap();
        let functions = SOURCE
            .rsplit_once("pub(crate) fn authorize_production_database_startup(")
            .unwrap()
            .1
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let production = format!(
            "{declarations}pub(crate) fn authorize_production_database_startup({functions}"
        );
        let compact_production: String = production
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();

        assert!(production.contains(
            "pub(crate) fn authorize_production_database_startup(\n    database: DatabaseFreshnessValidatedProductionDatabaseConnection,\n    installation_evidence: InstallationEvidence,\n) -> ProductionDatabaseStartupAuthorizationOutcome"
        ));
        assert_eq!(
            production
                .matches("InstallationEvidence::Initialized(ExpectedStorageEvidence::Present)")
                .count(),
            1
        );

        let success = production
            .split_once("pub(crate) struct StartupAuthorizedProductionDatabaseConnection {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(success.lines().filter(|line| line.contains(':')).count(), 3);
        assert!(success.contains("owner: ConnectionLifetimeOwner"));
        assert!(success.contains("metadata_contract: DatabaseMetadataContractV1"));
        assert!(
            success.contains("trusted_assessment: TrustedCurrentInstallationEvidenceAssessment")
        );
        assert!(!success.contains(": InstallationEvidence"));

        let failure = production
            .split_once("pub(crate) struct ProductionDatabaseStartupAuthorizationCloseFailure {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(failure.lines().filter(|line| line.contains(':')).count(), 2);
        assert!(failure.contains("category: ProductionDatabaseStartupAuthorizationError"));
        assert!(failure.contains("owner: ConnectionLifetimeOwner"));
        assert!(!failure.contains(": InstallationEvidence"));
        assert!(!failure.contains("metadata"));
        assert!(!failure.contains("assessment"));

        for forbidden in [
            "impl FnOnce(rusqlite::Connection",
            "FnOnce(rusqlite::Connection",
            "impl FnOnce(Connection",
            "FnOnce(Connection",
        ] {
            assert!(
                !production.contains(forbidden),
                "production Connection callback seam: {forbidden}"
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
                "formatting-obscured production Connection callback seam: {forbidden}"
            );
        }

        for forbidden in [
            "classify_database_freshness(",
            "classify_database_metadata_correspondence(",
            "validate_production_database_live_metadata",
            "validate_production_database_readability",
            "inspect_production_database_file",
            "SELECT ",
            "PRAGMA",
            ".prepare(",
            ".query(",
            ".query_row(",
            ".get_ref(",
            "AsRef<Connection>",
            "with_connection",
            "std::fs",
            "fs::",
            "std::path",
            "PathBuf",
            "sidecar",
            "DPAPI",
            "dpapi",
            "HMAC",
            "hmac",
            "parse(",
            "load_",
            "normalize_",
            "authorize_first_time_setup",
            "FirstTimeSetupAuthorization",
            "SetupAuthorizationState",
            "StorageDecision",
            "decide_storage",
            "decide_ordinary_startup",
            "CREATE TABLE",
            "ALTER TABLE",
            "schema",
            "migration",
            "recovery",
            "replacement",
            "repair",
            "tauri::command",
            "invoke_handler",
            "pub fn",
            "unsafe {",
            "extern \"",
            "impl Clone",
            "impl Copy",
            "pub(crate) fn new",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden production capability: {forbidden}"
            );
        }
    }
}

pub(crate) fn authorize_production_database_startup(
    database: DatabaseFreshnessValidatedProductionDatabaseConnection,
    installation_evidence: InstallationEvidence,
) -> ProductionDatabaseStartupAuthorizationOutcome {
    let DatabaseFreshnessValidatedProductionDatabaseConnection {
        owner,
        metadata_contract,
        trusted_assessment,
    } = database;

    let category = match installation_evidence {
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Present) => {
            discard_installation_evidence(installation_evidence);
            return ProductionDatabaseStartupAuthorizationOutcome::Authorized(
                StartupAuthorizedProductionDatabaseConnection {
                    owner,
                    metadata_contract,
                    trusted_assessment,
                },
            );
        }
        InstallationEvidence::NeverInitialized => {
            ProductionDatabaseStartupAuthorizationError::NeverInitialized
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing) => {
            ProductionDatabaseStartupAuthorizationError::ExpectedStorageMissing
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable)
        | InstallationEvidence::Unavailable => {
            ProductionDatabaseStartupAuthorizationError::InstallationStateUnavailable
        }
        InstallationEvidence::Inconsistent => {
            ProductionDatabaseStartupAuthorizationError::InstallationStateInconsistent
        }
    };

    finish_unauthorized(
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

fn finish_unauthorized(
    category: ProductionDatabaseStartupAuthorizationError,
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
    installation_evidence: InstallationEvidence,
) -> ProductionDatabaseStartupAuthorizationOutcome {
    discard_unauthorized_inputs(installation_evidence, metadata_contract, trusted_assessment);
    match super::super::super::super::close_lifetime_owner(owner) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseStartupAuthorizationOutcome::Failed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseStartupAuthorizationOutcome::CloseFailed(
                ProductionDatabaseStartupAuthorizationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

fn discard_unauthorized_inputs<T, U, V>(
    installation_evidence: T,
    metadata_contract: U,
    trusted_assessment: V,
) {
    drop(installation_evidence);
    drop(metadata_contract);
    drop(trusted_assessment);
}

fn retry_unauthorized_close(
    failure: ProductionDatabaseStartupAuthorizationCloseFailure,
) -> ProductionDatabaseStartupAuthorizationCloseRetryOutcome {
    let ProductionDatabaseStartupAuthorizationCloseFailure { category, owner } = failure;
    match super::super::super::super::close_lifetime_owner(owner) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseStartupAuthorizationCloseRetryOutcome::Closed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseStartupAuthorizationCloseRetryOutcome::Failed(
                ProductionDatabaseStartupAuthorizationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

fn close_authorized_owner(
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
) -> ProductionDatabaseConnectionCloseOutcome {
    discard_authorized_inputs(metadata_contract, trusted_assessment);
    super::super::super::super::close_lifetime_owner(owner)
}

fn discard_authorized_inputs<T, U>(metadata_contract: T, trusted_assessment: U) {
    drop(metadata_contract);
    drop(trusted_assessment);
}

#[cfg(test)]
fn authorize_production_database_startup_using(
    database: DatabaseFreshnessValidatedProductionDatabaseConnection,
    installation_evidence: InstallationEvidence,
    close_on_failure: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseStartupAuthorizationOutcome {
    let DatabaseFreshnessValidatedProductionDatabaseConnection {
        owner,
        metadata_contract,
        trusted_assessment,
    } = database;

    let category = match installation_evidence {
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Present) => {
            discard_installation_evidence(installation_evidence);
            return ProductionDatabaseStartupAuthorizationOutcome::Authorized(
                StartupAuthorizedProductionDatabaseConnection {
                    owner,
                    metadata_contract,
                    trusted_assessment,
                },
            );
        }
        InstallationEvidence::NeverInitialized => {
            ProductionDatabaseStartupAuthorizationError::NeverInitialized
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Missing) => {
            ProductionDatabaseStartupAuthorizationError::ExpectedStorageMissing
        }
        InstallationEvidence::Initialized(ExpectedStorageEvidence::Unavailable)
        | InstallationEvidence::Unavailable => {
            ProductionDatabaseStartupAuthorizationError::InstallationStateUnavailable
        }
        InstallationEvidence::Inconsistent => {
            ProductionDatabaseStartupAuthorizationError::InstallationStateInconsistent
        }
    };

    finish_unauthorized_using(
        category,
        owner,
        metadata_contract,
        trusted_assessment,
        installation_evidence,
        close_on_failure,
    )
}

#[cfg(test)]
fn finish_unauthorized_using<T, U, V>(
    category: ProductionDatabaseStartupAuthorizationError,
    owner: ConnectionLifetimeOwner,
    metadata_contract: T,
    trusted_assessment: U,
    installation_evidence: V,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseStartupAuthorizationOutcome {
    discard_unauthorized_inputs(installation_evidence, metadata_contract, trusted_assessment);
    match super::super::super::super::close_lifetime_owner_using(owner, close) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseStartupAuthorizationOutcome::Failed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseStartupAuthorizationOutcome::CloseFailed(
                ProductionDatabaseStartupAuthorizationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

#[cfg(test)]
fn retry_unauthorized_close_using(
    failure: ProductionDatabaseStartupAuthorizationCloseFailure,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseStartupAuthorizationCloseRetryOutcome {
    let ProductionDatabaseStartupAuthorizationCloseFailure { category, owner } = failure;
    match super::super::super::super::close_lifetime_owner_using(owner, close) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            ProductionDatabaseStartupAuthorizationCloseRetryOutcome::Closed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            ProductionDatabaseStartupAuthorizationCloseRetryOutcome::Failed(
                ProductionDatabaseStartupAuthorizationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

#[cfg(test)]
fn close_authorized_owner_using<T, U>(
    owner: ConnectionLifetimeOwner,
    metadata_contract: T,
    trusted_assessment: U,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseConnectionCloseOutcome {
    discard_authorized_inputs(metadata_contract, trusted_assessment);
    super::super::super::super::close_lifetime_owner_using(owner, close)
}

#[cfg(test)]
impl ProductionDatabaseStartupAuthorizationCloseFailure {
    fn retry_close_using(
        self,
        close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
    ) -> ProductionDatabaseStartupAuthorizationCloseRetryOutcome {
        retry_unauthorized_close_using(self, close)
    }
}

#[cfg(test)]
impl StartupAuthorizedProductionDatabaseConnection {
    fn close_using(
        self,
        close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
    ) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            metadata_contract,
            trusted_assessment,
        } = self;
        close_authorized_owner_using(owner, metadata_contract, trusted_assessment, close)
    }
}
