use std::fmt;

pub(super) struct ProductionDatabaseMigrationConfirmation {
    state: ProductionDatabaseMigrationConfirmationState,
}

#[allow(dead_code)]
enum ProductionDatabaseMigrationConfirmationState {
    NotOffered,
    Pending,
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
    pub(super) fn confirm(&mut self) -> bool {
        if !matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::Pending
        ) {
            return false;
        }
        self.state = ProductionDatabaseMigrationConfirmationState::Authorized(
            ProductionDatabaseMigrationAuthorization { _private: () },
        );
        true
    }

    #[allow(dead_code)]
    pub(super) fn cancel(&mut self) -> bool {
        if !matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::Pending
        ) {
            return false;
        }
        self.state = ProductionDatabaseMigrationConfirmationState::Revoked;
        true
    }

    #[allow(dead_code)]
    pub(super) fn revoke_pending(&mut self) -> bool {
        if !matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::Pending
        ) {
            return false;
        }
        self.state = ProductionDatabaseMigrationConfirmationState::Revoked;
        true
    }

    pub(super) fn invalidate_for_shutdown(&mut self) {
        if matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::NotOffered
                | ProductionDatabaseMigrationConfirmationState::Pending
                | ProductionDatabaseMigrationConfirmationState::Authorized(_)
        ) {
            self.state = ProductionDatabaseMigrationConfirmationState::Revoked;
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

    #[cfg(test)]
    pub(super) fn establish_pending_for_test(&mut self) -> bool {
        if !matches!(
            self.state,
            ProductionDatabaseMigrationConfirmationState::NotOffered
        ) {
            return false;
        }
        self.state = ProductionDatabaseMigrationConfirmationState::Pending;
        true
    }

    #[cfg(test)]
    pub(super) fn state_for_test(&self) -> ProductionDatabaseMigrationConfirmationStateForTest {
        match self.state {
            ProductionDatabaseMigrationConfirmationState::NotOffered => {
                ProductionDatabaseMigrationConfirmationStateForTest::NotOffered
            }
            ProductionDatabaseMigrationConfirmationState::Pending => {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProductionDatabaseMigrationConfirmationStateForTest {
    NotOffered,
    Pending,
    Authorized,
    Consumed,
    Revoked,
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier, Mutex};

    use super::*;

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

    #[test]
    fn fresh_state_is_not_offered_and_pending_can_be_established_only_once() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::NotOffered
        );
        assert!(confirmation.establish_pending_for_test());
        assert!(!confirmation.establish_pending_for_test());
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Pending
        );
    }

    #[test]
    fn confirmation_authorizes_once_and_same_process_cannot_renew() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        assert!(confirmation.establish_pending_for_test());
        assert!(confirmation.confirm());
        assert!(!confirmation.confirm());
        assert!(!confirmation.establish_pending_for_test());
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Authorized
        );
    }

    #[test]
    fn cancellation_revokes_without_authorizing_and_prevents_renewal() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        assert!(confirmation.establish_pending_for_test());
        assert!(confirmation.cancel());
        assert!(!confirmation.cancel());
        assert!(!confirmation.confirm());
        assert!(!confirmation.consume_authorization());
        assert!(!confirmation.establish_pending_for_test());
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
    }

    #[test]
    fn invalidation_revokes_pending_without_authorizing() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        assert!(confirmation.establish_pending_for_test());
        assert!(confirmation.revoke_pending());
        assert!(!confirmation.revoke_pending());
        assert!(!confirmation.confirm());
        assert!(!confirmation.consume_authorization());
        assert!(!confirmation.establish_pending_for_test());
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Revoked
        );
    }

    #[test]
    fn authorization_consumption_is_exactly_once_and_terminal() {
        let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
        assert!(confirmation.establish_pending_for_test());
        assert!(confirmation.confirm());
        assert!(confirmation.consume_authorization());
        assert!(!confirmation.consume_authorization());
        assert!(!confirmation.confirm());
        assert!(!confirmation.establish_pending_for_test());
        assert_eq!(
            confirmation.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::Consumed
        );
    }

    #[test]
    fn shutdown_invalidation_revokes_pending_and_unconsumed_authorization() {
        for confirm_first in [false, true] {
            let mut confirmation = ProductionDatabaseMigrationConfirmation::new();
            assert!(confirmation.establish_pending_for_test());
            if confirm_first {
                assert!(confirmation.confirm());
            }
            confirmation.invalidate_for_shutdown();
            assert_eq!(
                confirmation.state_for_test(),
                ProductionDatabaseMigrationConfirmationStateForTest::Revoked
            );
            assert!(!confirmation.confirm());
            assert!(!confirmation.consume_authorization());
            assert!(!confirmation.establish_pending_for_test());
        }
    }

    #[test]
    fn confirmation_racing_shutdown_cannot_retain_authorization() {
        for _ in 0..64 {
            let confirmation = Arc::new(Mutex::new(ProductionDatabaseMigrationConfirmation::new()));
            assert!(
                confirmation
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .establish_pending_for_test()
            );
            let barrier = Arc::new(Barrier::new(3));

            let confirming_state = Arc::clone(&confirmation);
            let confirming_barrier = Arc::clone(&barrier);
            let confirming = std::thread::spawn(move || {
                confirming_barrier.wait();
                confirming_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .confirm()
            });

            let shutdown_state = Arc::clone(&confirmation);
            let shutdown_barrier = Arc::clone(&barrier);
            let shutdown = std::thread::spawn(move || {
                shutdown_barrier.wait();
                shutdown_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .invalidate_for_shutdown();
            });

            barrier.wait();
            let _confirmation_won_race = confirming.join().expect("confirmation thread");
            shutdown.join().expect("shutdown thread");
            assert_eq!(
                confirmation
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .state_for_test(),
                ProductionDatabaseMigrationConfirmationStateForTest::Revoked
            );
        }
    }

    #[test]
    fn a_new_process_local_owner_starts_fresh() {
        let mut prior = ProductionDatabaseMigrationConfirmation::new();
        assert!(prior.establish_pending_for_test());
        assert!(prior.confirm());
        let replacement = ProductionDatabaseMigrationConfirmation::new();
        assert_eq!(
            replacement.state_for_test(),
            ProductionDatabaseMigrationConfirmationStateForTest::NotOffered
        );
    }

    #[test]
    fn capability_and_owner_are_sealed_non_clone_non_copy_non_serde_and_redacted() {
        assert_not_impl!(ProductionDatabaseMigrationAuthorization, Clone);
        assert_not_impl!(ProductionDatabaseMigrationAuthorization, Copy);
        assert_not_impl!(ProductionDatabaseMigrationAuthorization, Default);
        assert_not_impl!(ProductionDatabaseMigrationAuthorization, serde::Serialize);
        assert_not_impl!(
            ProductionDatabaseMigrationAuthorization,
            serde::Deserialize<'static>
        );
        let authorization = ProductionDatabaseMigrationAuthorization { _private: () };
        assert_eq!(
            format!("{authorization:?}"),
            "ProductionDatabaseMigrationAuthorization([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", ProductionDatabaseMigrationConfirmation::new()),
            "ProductionDatabaseMigrationConfirmation([REDACTED])"
        );
    }

    #[test]
    fn production_source_has_no_pending_producer_or_out_of_scope_surface() {
        const SOURCE: &str = include_str!("production_database_migration_confirmation.rs");
        let production = SOURCE.split_once("#[cfg(test)]").unwrap().0;
        assert!(!production.contains("establish_pending"));
        let confirmation_transition = production
            .split_once("pub(super) fn confirm(&mut self) -> bool {")
            .unwrap()
            .1
            .split_once("pub(super) fn cancel(&mut self) -> bool {")
            .unwrap()
            .0;
        assert_eq!(
            confirmation_transition
                .matches("ProductionDatabaseMigrationAuthorization { _private: () }")
                .count(),
            1
        );
        for forbidden in [
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
    }
}
