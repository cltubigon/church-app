use std::fmt;

use crate::production_database_connection_handoff::ProductionDatabaseMigrationOpportunity;

pub(super) struct ProductionDatabaseMigrationConfirmation {
    state: ProductionDatabaseMigrationConfirmationState,
}

#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
enum ProductionDatabaseMigrationConfirmationState {
    NotOffered,
    Pending(ProductionDatabaseMigrationOpportunity),
    Authorized(ProductionDatabaseMigrationAuthorization),
    Consumed,
    Revoked,
}

struct ProductionDatabaseMigrationAuthorization {
    _private: (),
}

impl fmt::Debug for ProductionDatabaseMigrationAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseMigrationAuthorization([REDACTED])")
    }
}

impl fmt::Debug for ProductionDatabaseMigrationConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseMigrationConfirmation([REDACTED])")
    }
}

impl ProductionDatabaseMigrationConfirmation {
    pub(super) fn new() -> Self {
        Self {
            state: ProductionDatabaseMigrationConfirmationState::NotOffered,
        }
    }

    #[allow(dead_code)]
    #[allow(clippy::result_large_err)]
    pub(super) fn establish_pending(
        &mut self,
        opportunity: ProductionDatabaseMigrationOpportunity,
    ) -> Result<(), ProductionDatabaseMigrationOpportunity> {
        if !matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::NotOffered
        ) {
            return Err(opportunity);
        }
        self.state = ProductionDatabaseMigrationConfirmationState::Pending(opportunity);
        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn cancel(&mut self) -> Option<ProductionDatabaseMigrationOpportunity> {
        self.extract_pending_and_revoke()
    }

    pub(super) fn invalidate_for_shutdown(
        &mut self,
    ) -> Option<ProductionDatabaseMigrationOpportunity> {
        let prior = std::mem::replace(
            &mut self.state,
            ProductionDatabaseMigrationConfirmationState::Revoked,
        );
        match prior {
            ProductionDatabaseMigrationConfirmationState::Pending(opportunity) => Some(opportunity),
            ProductionDatabaseMigrationConfirmationState::NotOffered
            | ProductionDatabaseMigrationConfirmationState::Authorized(_) => None,
            terminal @ (ProductionDatabaseMigrationConfirmationState::Consumed
            | ProductionDatabaseMigrationConfirmationState::Revoked) => {
                self.state = terminal;
                None
            }
        }
    }

    #[allow(dead_code)]
    pub(super) fn consume_authorization(&mut self) -> bool {
        let prior = std::mem::replace(
            &mut self.state,
            ProductionDatabaseMigrationConfirmationState::Consumed,
        );
        match prior {
            ProductionDatabaseMigrationConfirmationState::Authorized(authorization) => {
                let ProductionDatabaseMigrationAuthorization { _private: () } = authorization;
                true
            }
            other => {
                self.state = other;
                false
            }
        }
    }

    fn extract_pending_and_revoke(&mut self) -> Option<ProductionDatabaseMigrationOpportunity> {
        let prior = std::mem::replace(
            &mut self.state,
            ProductionDatabaseMigrationConfirmationState::Revoked,
        );
        match prior {
            ProductionDatabaseMigrationConfirmationState::Pending(opportunity) => Some(opportunity),
            other => {
                self.state = other;
                None
            }
        }
    }

    #[cfg(test)]
    fn confirm_for_test(&mut self) -> ProductionDatabaseMigrationConfirmationForTestOutcome {
        use crate::production_database_connection_handoff::ProductionDatabaseConnectionCloseOutcome;

        let Some(opportunity) = self.extract_pending_and_revoke() else {
            return ProductionDatabaseMigrationConfirmationForTestOutcome::NotPending;
        };
        match opportunity.close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                self.state = ProductionDatabaseMigrationConfirmationState::Authorized(
                    ProductionDatabaseMigrationAuthorization { _private: () },
                );
                ProductionDatabaseMigrationConfirmationForTestOutcome::Authorized
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                ProductionDatabaseMigrationConfirmationForTestOutcome::CloseFailed(failure)
            }
        }
    }

    #[cfg(test)]
    pub(super) fn state_for_test(&self) -> ProductionDatabaseMigrationConfirmationStateForTest {
        match &self.state {
            ProductionDatabaseMigrationConfirmationState::NotOffered => {
                ProductionDatabaseMigrationConfirmationStateForTest::NotOffered
            }
            ProductionDatabaseMigrationConfirmationState::Pending(_) => {
                ProductionDatabaseMigrationConfirmationStateForTest::Pending
            }
            ProductionDatabaseMigrationConfirmationState::Authorized(_) => {
                ProductionDatabaseMigrationConfirmationStateForTest::Authorized
            }
            ProductionDatabaseMigrationConfirmationState::Consumed => {
                ProductionDatabaseMigrationConfirmationStateForTest::Consumed
            }
            ProductionDatabaseMigrationConfirmationState::Revoked => {
                ProductionDatabaseMigrationConfirmationStateForTest::Revoked
            }
        }
    }
}

#[cfg(test)]
enum ProductionDatabaseMigrationConfirmationForTestOutcome {
    Authorized,
    NotPending,
    CloseFailed(
        crate::production_database_connection_handoff::ProductionDatabaseConnectionCloseFailure,
    ),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProductionDatabaseMigrationConfirmationStateForTest {
    NotOffered,
    Pending,
    Authorized,
    Consumed,
    Revoked,
}

#[cfg(test)]
mod ownership_tests {
    use std::sync::{Arc, Barrier, Mutex};

    use crate::production_database_connection_handoff::{
        ProductionDatabaseConnectionCloseOutcome,
        genuine_production_database_migration_opportunity_for_test,
    };

    use super::*;

    fn close(opportunity: ProductionDatabaseMigrationOpportunity) {
        assert!(matches!(
            opportunity.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
    }

    #[test]
    fn genuine_opportunity_is_moved_into_pending_and_second_is_returned_whole() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (first_root, first) = genuine_production_database_migration_opportunity_for_test();
        assert!(confirmation.establish_pending(first).is_ok());
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Pending
        );

        let (second_root, second) = genuine_production_database_migration_opportunity_for_test();
        let returned = confirmation
            .establish_pending(second)
            .expect_err("a second opportunity must be returned unchanged");
        close(returned);
        second_root.assert_exact_cleanup();

        close(
            confirmation
                .cancel()
                .expect("pending owner must be extracted"),
        );
        first_root.assert_exact_cleanup();
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
    }

    #[test]
    fn authorized_consumed_and_revoked_states_reject_and_return_new_opportunities() {
        for target in [
            ProductionDatabaseMigrationConfirmationStateForTest::Authorized,
            ProductionDatabaseMigrationConfirmationStateForTest::Consumed,
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked,
        ] {
            let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
            let (first_root, first) = genuine_production_database_migration_opportunity_for_test();
            confirmation.establish_pending(first).unwrap();
            match target {
                ProductionDatabaseMigrationConfirmationStateForTest::Authorized => {
                    assert!(matches!(
                        confirmation.confirm_for_test(),
                        ProductionDatabaseMigrationConfirmationForTestOutcome::Authorized
                    ));
                }
                ProductionDatabaseMigrationConfirmationStateForTest::Consumed => {
                    assert!(matches!(
                        confirmation.confirm_for_test(),
                        ProductionDatabaseMigrationConfirmationForTestOutcome::Authorized
                    ));
                    assert!(confirmation.consume_authorization());
                }
                ProductionDatabaseMigrationConfirmationStateForTest::Revoked => {
                    close(
                        confirmation
                            .cancel()
                            .expect("pending owner must be extracted"),
                    );
                }
                _ => unreachable!(),
            }
            first_root.assert_exact_cleanup();

            let (rejected_root, rejected) =
                genuine_production_database_migration_opportunity_for_test();
            let returned = confirmation
                .establish_pending(rejected)
                .expect_err("same-process renewal must be rejected");
            close(returned);
            rejected_root.assert_exact_cleanup();
            assert_eq!(confirmation.state_for_test(), target);
        }
    }

    #[test]
    fn cancellation_extracts_before_terminal_revocation_and_never_renews() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        confirmation.establish_pending(opportunity).unwrap();
        let returned = confirmation
            .cancel()
            .expect("pending owner must be returned");
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
        assert!(confirmation.cancel().is_none());
        assert!(matches!(
            confirmation.confirm_for_test(),
            ProductionDatabaseMigrationConfirmationForTestOutcome::NotPending
        ));
        close(returned);
        root.assert_exact_cleanup();
    }

    #[test]
    fn shutdown_extracts_pending_and_revokes_pending_or_not_offered() {
        let mut pending = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        pending.establish_pending(opportunity).unwrap();
        let returned = pending
            .invalidate_for_shutdown()
            .expect("shutdown must return pending ownership");
        assert_eq!(
            pending.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
        close(returned);
        root.assert_exact_cleanup();

        let mut not_offered = ProductionDatabaseMigrationConfirmation::new();
        assert!(not_offered.invalidate_for_shutdown().is_none());
        assert_eq!(
            not_offered.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
    }

    #[test]
    fn extracted_opportunity_close_failure_retains_canonical_guarded_lifetime() {
        use crate::production_database_connection_handoff::with_production_database_close_failure_injected;

        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        confirmation.establish_pending(opportunity).unwrap();
        let returned = confirmation
            .cancel()
            .expect("pending owner must be returned");
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) =
            with_production_database_close_failure_injected(|| returned.close())
        else {
            panic!("injected close failure must retain the guarded lifetime");
        };
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn test_only_confirmation_closes_before_authorizing_and_consumes_once() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        confirmation.establish_pending(opportunity).unwrap();
        assert!(matches!(
            confirmation.confirm_for_test(),
            ProductionDatabaseMigrationConfirmationForTestOutcome::Authorized
        ));
        root.assert_exact_cleanup();
        assert!(confirmation.consume_authorization());
        assert!(!confirmation.consume_authorization());
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Consumed
        );
    }

    #[test]
    fn test_only_confirmation_close_failure_returns_the_canonical_owner() {
        use crate::production_database_connection_handoff::with_production_database_close_failure_injected;

        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
        confirmation.establish_pending(opportunity).unwrap();
        let ProductionDatabaseMigrationConfirmationForTestOutcome::CloseFailed(failure) =
            with_production_database_close_failure_injected(|| confirmation.confirm_for_test())
        else {
            panic!("injected close failure must be returned to the test caller");
        };
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn confirmation_racing_shutdown_cannot_retain_authorization_or_drop_pending() {
        for _ in 0..16 {
            let confirmation = Arc::new(Mutex::new(ProductionDatabaseMigrationConfirmation::new()));
            let (root, opportunity) = genuine_production_database_migration_opportunity_for_test();
            confirmation
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .establish_pending(opportunity)
                .unwrap();
            let barrier = Arc::new(Barrier::new(3));

            let confirming_state = Arc::clone(&confirmation);
            let confirming_barrier = Arc::clone(&barrier);
            let confirming = std::thread::spawn(move || {
                confirming_barrier.wait();
                confirming_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .confirm_for_test()
            });

            let shutdown_state = Arc::clone(&confirmation);
            let shutdown_barrier = Arc::clone(&barrier);
            let shutdown = std::thread::spawn(move || {
                shutdown_barrier.wait();
                shutdown_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .invalidate_for_shutdown()
            });

            barrier.wait();
            let confirmation_outcome = confirming.join().expect("confirmation thread");
            if let Some(opportunity) = shutdown.join().expect("shutdown thread") {
                close(opportunity);
            } else {
                assert!(matches!(
                    confirmation_outcome,
                    ProductionDatabaseMigrationConfirmationForTestOutcome::Authorized
                        | ProductionDatabaseMigrationConfirmationForTestOutcome::NotPending
                ));
            }
            assert_eq!(
                confirmation
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .state_for_test(),
                ProductionDatabaseMigrationConfirmationStateForTest::Revoked
            );
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn authorization_and_confirmation_owner_remain_redacted_and_non_clone() {
        trait AmbiguousIfClone<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        struct Implemented;
        impl<T: Clone> AmbiguousIfClone<Implemented> for T {}
        let _ = <ProductionDatabaseMigrationAuthorization as AmbiguousIfClone<_>>::check;

        assert_eq!(
            format!(
                "{:?}",
                ProductionDatabaseMigrationAuthorization { _private: () }
            ),
            "ProductionDatabaseMigrationAuthorization([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", ProductionDatabaseMigrationConfirmation::new()),
            "ProductionDatabaseMigrationConfirmation([REDACTED])"
        );
    }

    #[test]
    fn production_source_has_only_the_genuine_unwired_pending_boundary() {
        const SOURCE: &str = include_str!("production_database_migration_confirmation.rs");
        let production = SOURCE.split_once("#[cfg(test)]").unwrap().0;
        assert!(production.contains("Pending(ProductionDatabaseMigrationOpportunity)"));
        assert!(production.contains(
            "pub(super) fn establish_pending(\n        &mut self,\n        opportunity: ProductionDatabaseMigrationOpportunity,\n    ) -> Result<(), ProductionDatabaseMigrationOpportunity>"
        ));
        assert!(!production.contains("establish_pending_for_test"));
        assert!(!production.contains("fn confirm"));
        assert!(!production.contains("Pending,"));
        for forbidden in [
            "Revalidating",
            "PendingMigrationContext",
            "RevalidatedProductionDatabaseMigrationOpportunity",
            "AuthorizedMigrationContext",
            "#[tauri::command]",
            "serde::Serialize",
            "serde::Deserialize",
            "MaintenanceOperation",
            "ConfirmedMigrationIntent",
            "rusqlite",
            "Connection",
            "Path",
            "version",
            "backup",
            "integrity",
            "exclusivity",
            "migration SQL",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }

        const LIFECYCLE: &str = include_str!("../application_lifecycle.rs");
        let production_lifecycle = LIFECYCLE.split_once("#[cfg(test)]\nmod tests").unwrap().0;
        assert!(!production_lifecycle.contains(".establish_pending("));
    }
}
