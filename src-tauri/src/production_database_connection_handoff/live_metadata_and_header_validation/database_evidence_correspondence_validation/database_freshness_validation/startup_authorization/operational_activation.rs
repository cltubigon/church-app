//! Infallible consuming activation of the startup-authorized database owner.

use std::fmt;

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    database_restart_version_classification::ProductionDatabaseRestartClassification,
    installation_evidence_protection::TrustedCurrentInstallationEvidenceAssessment,
    production_database_connection_handoff::ProductionDatabaseConnectionCloseFailure,
    production_database_file::ProductionDatabaseFileIdentity,
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
    restart_classification: ProductionDatabaseRestartClassification,
}

pub(crate) struct ClosedExactV2OperationalProductionDatabase {
    file_identity: ProductionDatabaseFileIdentity,
    metadata_contract: DatabaseMetadataContractV1,
    trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
}

impl ClosedExactV2OperationalProductionDatabase {
    pub(crate) fn into_parts(
        self,
    ) -> (
        ProductionDatabaseFileIdentity,
        DatabaseMetadataContractV1,
        TrustedCurrentInstallationEvidenceAssessment,
    ) {
        (
            self.file_identity,
            self.metadata_contract,
            self.trusted_assessment,
        )
    }
}

#[must_use = "the exact-v2 operational handoff outcome must be handled"]
pub(crate) enum ExactV2OperationalHandoffOutcome {
    Closed(ClosedExactV2OperationalProductionDatabase),
    Rejected(OperationalProductionDatabase),
    CloseFailed(ProductionDatabaseConnectionCloseFailure),
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
            restart_classification: _,
        } = self;
        close_operational_owner(owner, metadata_contract, trusted_assessment)
    }

    pub(crate) fn close_for_exact_v2_business_handoff(self) -> ExactV2OperationalHandoffOutcome {
        if self.restart_classification != ProductionDatabaseRestartClassification::ExactV2 {
            return ExactV2OperationalHandoffOutcome::Rejected(self);
        }
        let Self {
            owner,
            metadata_contract,
            trusted_assessment,
            restart_classification: _,
        } = self;
        let file_identity = owner.inspected.identity();
        match super::super::super::super::super::close_lifetime_owner(owner) {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                ExactV2OperationalHandoffOutcome::Closed(
                    ClosedExactV2OperationalProductionDatabase {
                        file_identity,
                        metadata_contract,
                        trusted_assessment,
                    },
                )
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                let _ = metadata_contract;
                let _ = trusted_assessment;
                ExactV2OperationalHandoffOutcome::CloseFailed(failure)
            }
        }
    }
}

/// Consumes startup authorization and moves its unchanged retained ownership
/// into the distinct operational root capability.
pub(crate) fn activate_production_database_for_operational_use(
    database: StartupAuthorizedProductionDatabaseConnection,
) -> OperationalProductionDatabase {
    activate_classified_production_database_for_operational_use(
        database,
        ProductionDatabaseRestartClassification::ExactV1,
    )
}

pub(crate) fn activate_classified_production_database_for_operational_use(
    database: StartupAuthorizedProductionDatabaseConnection,
    restart_classification: ProductionDatabaseRestartClassification,
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
        restart_classification,
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
            restart_classification: _,
        } = self;
        close_operational_owner_using(owner, metadata_contract, trusted_assessment, close)
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, os::windows::io::AsRawHandle};

    use crate::installation_state::{ExpectedStorageEvidence, InstallationEvidence};

    use super::*;

    impl ClosedExactV2OperationalProductionDatabase {
        pub(crate) fn for_test(
            file_identity: ProductionDatabaseFileIdentity,
            metadata_contract: DatabaseMetadataContractV1,
            trusted_assessment: TrustedCurrentInstallationEvidenceAssessment,
        ) -> Self {
            Self {
                file_identity,
                metadata_contract,
                trusted_assessment,
            }
        }
    }
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
    fn only_exact_v2_classification_can_enter_the_business_handoff() {
        for rejected in [
            ProductionDatabaseRestartClassification::ExactV1,
            ProductionDatabaseRestartClassification::Inconsistent,
            ProductionDatabaseRestartClassification::UnsupportedNewer,
        ] {
            let (root, database) = startup_authorized_owner();
            let operational =
                activate_classified_production_database_for_operational_use(database, rejected);
            let ExactV2OperationalHandoffOutcome::Rejected(operational) =
                operational.close_for_exact_v2_business_handoff()
            else {
                panic!("non-V2 classification must be rejected");
            };
            assert!(matches!(
                operational.close(),
                ProductionDatabaseConnectionCloseOutcome::Closed
            ));
            root.assert_exact_cleanup();
        }

        let (root, database) = startup_authorized_owner();
        let operational = activate_classified_production_database_for_operational_use(
            database,
            ProductionDatabaseRestartClassification::ExactV2,
        );
        let ExactV2OperationalHandoffOutcome::Closed(closed) =
            operational.close_for_exact_v2_business_handoff()
        else {
            panic!("Exact V2 must consume and checked-close the read-only owner");
        };
        let _ = closed;
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
        assert_eq!(owner.lines().filter(|line| line.contains(':')).count(), 4);
        assert!(owner.contains("owner: ConnectionLifetimeOwner"));
        assert!(owner.contains("metadata_contract: DatabaseMetadataContractV1"));
        assert!(owner.contains("trusted_assessment: TrustedCurrentInstallationEvidenceAssessment"));
        assert!(owner.contains("restart_classification: ProductionDatabaseRestartClassification"));

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
