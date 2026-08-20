//! Infallible consuming activation of the startup-authorized database owner.

use std::fmt;

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    installation_evidence_protection::TrustedCurrentInstallationEvidenceAssessment,
};

use super::{
    ConnectionLifetimeOwner, ProductionDatabaseConnectionCloseOutcome,
    StartupAuthorizedProductionDatabaseConnection,
};

/// Opaque root capability for later separately approved operational services.
pub(crate) struct OperationalProductionDatabase {
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
}

impl fmt::Debug for OperationalProductionDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperationalProductionDatabase([REDACTED])")
    }
}

impl OperationalProductionDatabase {
    /// Discards retained activation inputs before explicitly closing the same
    /// guarded connection lifetime.
    pub(crate) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            metadata_contract,
            trusted_assessment,
        } = self;
        close_operational_owner(owner, metadata_contract, trusted_assessment)
    }
}

/// Consumes startup authorization and moves its unchanged retained ownership
/// into the distinct operational root capability.
pub(crate) fn activate_production_database_for_operational_use(
    database: StartupAuthorizedProductionDatabaseConnection,
) -> OperationalProductionDatabase {
    let StartupAuthorizedProductionDatabaseConnection {
        owner,
        metadata_contract,
        trusted_assessment,
    } = database;

    OperationalProductionDatabase {
        owner,
        metadata_contract,
        trusted_assessment,
    }
}

fn close_operational_owner(
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
) -> ProductionDatabaseConnectionCloseOutcome {
    discard_operational_inputs(metadata_contract, trusted_assessment);
    super::super::super::super::super::close_lifetime_owner(owner)
}

fn discard_operational_inputs<T, U>(metadata_contract: T, trusted_assessment: U) {
    drop(metadata_contract);
    drop(trusted_assessment);
}

#[cfg(test)]
fn close_operational_owner_using<T, U>(
    owner: ConnectionLifetimeOwner,
    metadata_contract: T,
    trusted_assessment: U,
    close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
) -> ProductionDatabaseConnectionCloseOutcome {
    discard_operational_inputs(metadata_contract, trusted_assessment);
    super::super::super::super::super::close_lifetime_owner_using(owner, close)
}

#[cfg(test)]
impl OperationalProductionDatabase {
    fn close_using(
        self,
        close: impl FnOnce(rusqlite::Connection) -> Result<(), rusqlite::Connection>,
    ) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            metadata_contract,
            trusted_assessment,
        } = self;
        close_operational_owner_using(owner, metadata_contract, trusted_assessment, close)
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, os::windows::io::AsRawHandle};

    use crate::installation_state::{ExpectedStorageEvidence, InstallationEvidence};

    use super::*;
    use crate::production_database_connection_handoff::{
        ProductionDatabaseConnectionCloseOutcome, ProductionDatabaseStartupAuthorizationOutcome,
        authorize_production_database_startup,
    };

    struct DropProbe<'a>(&'a Cell<bool>);

    impl Drop for DropProbe<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    fn startup_authorized_owner() -> (
        super::super::super::tests::TestRoot,
        StartupAuthorizedProductionDatabaseConnection,
    ) {
        let (root, database) = super::super::super::tests::fresh_owner();
        let outcome = authorize_production_database_startup(
            database,
            InstallationEvidence::Initialized(ExpectedStorageEvidence::Present),
        );
        let ProductionDatabaseStartupAuthorizationOutcome::Authorized(owner) = outcome else {
            panic!("genuine fresh predecessor should authorize startup");
        };
        (root, owner)
    }

    #[test]
    fn genuine_startup_authorized_owner_activates_once_redacts_closes_and_cleans_exactly() {
        let (root, database) = startup_authorized_owner();
        let operational = activate_production_database_for_operational_use(database);
        assert_eq!(
            format!("{operational:?}"),
            "OperationalProductionDatabase([REDACTED])"
        );
        assert!(matches!(
            operational.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn activation_preserves_the_exact_guarded_lifetime_owner() {
        let (root, database) = startup_authorized_owner();
        let expected_guard = database.owner.guard.handle.as_raw_handle();
        let operational = activate_production_database_for_operational_use(database);
        assert_eq!(
            operational.owner.guard.handle.as_raw_handle(),
            expected_guard
        );
        assert!(matches!(
            operational.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn operational_close_discards_retained_inputs_before_close() {
        let (root, database) = startup_authorized_owner();
        let StartupAuthorizedProductionDatabaseConnection { owner, .. } = database;
        let metadata_dropped = Cell::new(false);
        let assessment_dropped = Cell::new(false);
        let outcome = close_operational_owner_using(
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
    fn operational_close_failure_retains_only_canonical_lifetime_ownership_for_retry() {
        let (root, database) = startup_authorized_owner();
        let operational = activate_production_database_for_operational_use(database);
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            operational.close_using(Err)
        else {
            panic!("injected close failure should retain canonical lifetime ownership");
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
    fn production_source_is_the_narrow_observation_free_activation_boundary() {
        const SOURCE: &str = include_str!("operational_activation.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let compact_production: String = production
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();

        assert!(production.contains(
            "pub(crate) fn activate_production_database_for_operational_use(\n    database: StartupAuthorizedProductionDatabaseConnection,\n) -> OperationalProductionDatabase"
        ));

        let owner = production
            .split_once("pub(crate) struct OperationalProductionDatabase {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(owner.lines().filter(|line| line.contains(':')).count(), 3);
        assert!(owner.contains("owner: ConnectionLifetimeOwner"));
        assert!(owner.contains("metadata_contract: DatabaseMetadataContractV1"));
        assert!(owner.contains("trusted_assessment: TrustedCurrentInstallationEvidenceAssessment"));

        for forbidden in [
            "impl FnOnce(rusqlite::Connection",
            "FnOnce(rusqlite::Connection",
            "impl FnOnce(Connection",
            "FnOnce(Connection",
            "AsRef<Connection>",
            "with_connection",
            "pub(crate) fn new",
            "impl Clone",
            "impl Copy",
            "serde",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden operational capability: {forbidden}"
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
                "formatting-obscured operational callback seam: {forbidden}"
            );
        }
        for forbidden in [
            "classify_database_freshness(",
            "classify_database_metadata_correspondence(",
            "validate_production_database",
            "authorize_production_database_startup(",
            "inspect_production_database_file",
            "Connection::open",
            "open_with_flags",
            "SELECT ",
            "PRAGMA",
            ".prepare(",
            ".query(",
            ".query_row(",
            ".execute(",
            "std::fs",
            "fs::",
            "std::path",
            "Path",
            "sidecar",
            "WAL",
            "SHM",
            "DPAPI",
            "dpapi",
            "HMAC",
            "hmac",
            "evidence()",
            "freshness",
            "correspondence",
            "load_",
            "setup",
            "migration",
            "recovery",
            "replacement",
            "repair",
            "tauri::command",
            "invoke_handler",
            "unsafe {",
            "extern \"",
            "pub fn",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden activation behavior: {forbidden}"
            );
        }
    }
}
