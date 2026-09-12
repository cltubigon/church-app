//! Private, unwired, consuming full-integrity validation over an already
//! readable guarded production database lifetime.

use std::fmt;

use rusqlite::{Connection, ffi::ErrorCode, types::ValueRef};

use super::{
    ConnectionLifetimeOwner, ProductionDatabaseConnectionCloseOutcome,
    ReadabilityAndIntegrityValidatedProductionDatabaseConnection, close_lifetime_owner_using,
};

const FULL_INTEGRITY_CHECK: &str = "PRAGMA main.integrity_check";

pub(crate) struct FullIntegrityValidatedProductionDatabaseConnection {
    owner: ConnectionLifetimeOwner,
}

impl fmt::Debug for FullIntegrityValidatedProductionDatabaseConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FullIntegrityValidatedProductionDatabaseConnection([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum FullIntegrityValidationError {
    FullIntegrityFailed,
    FullIntegrityUnavailable,
    FullIntegrityInterruptedOrIncomplete,
}

impl fmt::Debug for FullIntegrityValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FullIntegrityFailed => "FullIntegrityFailed",
            Self::FullIntegrityUnavailable => "FullIntegrityUnavailable",
            Self::FullIntegrityInterruptedOrIncomplete => "FullIntegrityInterruptedOrIncomplete",
        })
    }
}

#[must_use = "the full-integrity validation outcome must be handled"]
pub(crate) enum FullIntegrityValidationOutcome {
    Validated(FullIntegrityValidatedProductionDatabaseConnection),
    Failed(FullIntegrityValidationError),
    CloseFailed(FullIntegrityValidationCloseFailure),
}

impl fmt::Debug for FullIntegrityValidationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validated(_) => formatter.write_str("Validated([REDACTED])"),
            Self::Failed(category) => formatter.debug_tuple("Failed").field(category).finish(),
            Self::CloseFailed(_) => formatter.write_str("CloseFailed([REDACTED])"),
        }
    }
}

pub(crate) struct FullIntegrityValidationCloseFailure {
    category: FullIntegrityValidationError,
    owner: ConnectionLifetimeOwner,
}

impl fmt::Debug for FullIntegrityValidationCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FullIntegrityValidationCloseFailure([REDACTED])")
    }
}

#[must_use = "a full-integrity close retry outcome must be handled"]
pub(crate) enum FullIntegrityValidationCloseRetryOutcome {
    Closed(FullIntegrityValidationError),
    Failed(FullIntegrityValidationCloseFailure),
}

impl fmt::Debug for FullIntegrityValidationCloseRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(category) => formatter.debug_tuple("Closed").field(category).finish(),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

impl FullIntegrityValidationCloseFailure {
    /// Consumes the complete retained lifetime unit and retries only close.
    pub(crate) fn retry_close(self) -> FullIntegrityValidationCloseRetryOutcome {
        retry_close_using(self, |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        })
    }

    #[cfg(test)]
    fn retry_close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
    ) -> FullIntegrityValidationCloseRetryOutcome {
        retry_close_using(self, close)
    }
}

impl FullIntegrityValidatedProductionDatabaseConnection {
    /// Consumes the proof owner and explicitly closes its SQLite handle.
    pub(crate) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        close_lifetime_owner_using(self.owner, |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        })
    }

    #[cfg(test)]
    fn close_using(
        self,
        close: impl FnOnce(Connection) -> Result<(), Connection>,
    ) -> ProductionDatabaseConnectionCloseOutcome {
        close_lifetime_owner_using(self.owner, close)
    }
}

/// Consumes only the readability-and-integrity-validated predecessor and runs
/// the one fixed full-integrity operation on its same retained connection.
#[allow(dead_code)]
pub(crate) fn validate_production_database_full_integrity(
    connection: ReadabilityAndIntegrityValidatedProductionDatabaseConnection,
) -> FullIntegrityValidationOutcome {
    finish_validation_using(connection, validate_fixed_full_integrity, |connection| {
        connection
            .close()
            .map_err(|(returned_connection, _)| returned_connection)
    })
}

fn finish_validation_using(
    connection: ReadabilityAndIntegrityValidatedProductionDatabaseConnection,
    validate: impl FnOnce(&Connection) -> Result<(), FullIntegrityValidationError>,
    close_on_failure: impl FnOnce(Connection) -> Result<(), Connection>,
) -> FullIntegrityValidationOutcome {
    let owner = connection.owner;
    // Deliberate scope: Rows, Statement, and all validation temporaries are
    // released before ownership can enter the close path.
    let validation_result = { validate(&owner.connection) };
    match validation_result {
        Ok(()) => FullIntegrityValidationOutcome::Validated(
            FullIntegrityValidatedProductionDatabaseConnection { owner },
        ),
        Err(category) => match close_lifetime_owner_using(owner, close_on_failure) {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                FullIntegrityValidationOutcome::Failed(category)
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                FullIntegrityValidationOutcome::CloseFailed(FullIntegrityValidationCloseFailure {
                    category,
                    owner: failure.owner,
                })
            }
        },
    }
}

fn retry_close_using(
    failure: FullIntegrityValidationCloseFailure,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> FullIntegrityValidationCloseRetryOutcome {
    let FullIntegrityValidationCloseFailure { category, owner } = failure;
    match close_lifetime_owner_using(owner, close) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            FullIntegrityValidationCloseRetryOutcome::Closed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            FullIntegrityValidationCloseRetryOutcome::Failed(FullIntegrityValidationCloseFailure {
                category,
                owner: failure.owner,
            })
        }
    }
}

#[derive(Clone, Copy)]
enum FullIntegrityRow {
    ExactOkText,
    OtherText,
    NonText,
    Malformed,
    End,
}

fn validate_full_integrity_row_stream(
    mut next: impl FnMut() -> Result<FullIntegrityRow, FullIntegrityValidationError>,
) -> Result<(), FullIntegrityValidationError> {
    match next()? {
        FullIntegrityRow::ExactOkText => {}
        FullIntegrityRow::OtherText | FullIntegrityRow::NonText => {
            return Err(FullIntegrityValidationError::FullIntegrityFailed);
        }
        FullIntegrityRow::Malformed | FullIntegrityRow::End => {
            return Err(FullIntegrityValidationError::FullIntegrityInterruptedOrIncomplete);
        }
    }
    match next()? {
        FullIntegrityRow::End => Ok(()),
        FullIntegrityRow::ExactOkText
        | FullIntegrityRow::OtherText
        | FullIntegrityRow::NonText
        | FullIntegrityRow::Malformed => {
            Err(FullIntegrityValidationError::FullIntegrityInterruptedOrIncomplete)
        }
    }
}

#[derive(Clone, Copy)]
enum FullIntegrityOperationBoundary {
    Preparation,
    QueryStartup,
    RowStepping,
}

fn validate_fixed_full_integrity(
    connection: &Connection,
) -> Result<(), FullIntegrityValidationError> {
    let mut statement = connection.prepare(FULL_INTEGRITY_CHECK).map_err(|error| {
        classify_full_integrity_error(&error, FullIntegrityOperationBoundary::Preparation)
    })?;
    if statement.column_count() != 1 {
        return Err(FullIntegrityValidationError::FullIntegrityInterruptedOrIncomplete);
    }
    let mut rows = statement.query([]).map_err(|error| {
        classify_full_integrity_error(&error, FullIntegrityOperationBoundary::QueryStartup)
    })?;
    validate_full_integrity_row_stream(|| {
        rows.next()
            .map(|row| match row {
                None => FullIntegrityRow::End,
                Some(row) => match row.get_ref(0) {
                    Ok(ValueRef::Text(value)) if value == b"ok" => FullIntegrityRow::ExactOkText,
                    Ok(ValueRef::Text(_)) => FullIntegrityRow::OtherText,
                    Ok(_) => FullIntegrityRow::NonText,
                    Err(_) => FullIntegrityRow::Malformed,
                },
            })
            .map_err(|error| {
                classify_full_integrity_error(&error, FullIntegrityOperationBoundary::RowStepping)
            })
    })
}

fn classify_full_integrity_error(
    error: &rusqlite::Error,
    boundary: FullIntegrityOperationBoundary,
) -> FullIntegrityValidationError {
    match error.sqlite_error_code() {
        Some(ErrorCode::OperationInterrupted | ErrorCode::OperationAborted) => {
            FullIntegrityValidationError::FullIntegrityInterruptedOrIncomplete
        }
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => {
            FullIntegrityValidationError::FullIntegrityFailed
        }
        Some(
            ErrorCode::PermissionDenied
            | ErrorCode::DatabaseBusy
            | ErrorCode::DatabaseLocked
            | ErrorCode::OutOfMemory
            | ErrorCode::ReadOnly
            | ErrorCode::SystemIoFailure
            | ErrorCode::DiskFull
            | ErrorCode::CannotOpen
            | ErrorCode::FileLockingProtocolFailed
            | ErrorCode::TooBig
            | ErrorCode::NoLargeFileSupport,
        ) => FullIntegrityValidationError::FullIntegrityUnavailable,
        _ => match boundary {
            FullIntegrityOperationBoundary::Preparation
            | FullIntegrityOperationBoundary::QueryStartup => {
                FullIntegrityValidationError::FullIntegrityUnavailable
            }
            FullIntegrityOperationBoundary::RowStepping => {
                FullIntegrityValidationError::FullIntegrityInterruptedOrIncomplete
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, mem::needs_drop};

    use rusqlite::ffi;

    use super::*;
    use crate::production_database_connection_handoff::{
        ProductionDatabaseValidationOutcome, open_keyed_production_database_read_only,
        tests::{TestRoot, generation_bound_key},
        validate_production_database_readability_and_integrity,
    };

    fn stream(
        values: impl IntoIterator<Item = Result<FullIntegrityRow, FullIntegrityValidationError>>,
    ) -> Result<(), FullIntegrityValidationError> {
        let mut values = values.into_iter();
        validate_full_integrity_row_stream(|| values.next().expect("complete synthetic stream"))
    }

    fn accepted_predecessor(
        root: &TestRoot,
    ) -> ReadabilityAndIntegrityValidatedProductionDatabaseConnection {
        let key_bytes = [0x74; 32];
        root.create_encrypted_database(&generation_bound_key(root, key_bytes), false);
        let keyed = open_keyed_production_database_read_only(
            root.typed_path(),
            root.inspected(),
            generation_bound_key(root, key_bytes),
        )
        .expect("guarded keyed read-only handoff should succeed");
        let ProductionDatabaseValidationOutcome::Validated(predecessor) =
            validate_production_database_readability_and_integrity(keyed)
        else {
            panic!("readability validation should succeed");
        };
        predecessor
    }

    fn synthetic_sqlite_error(code: ErrorCode) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(
            ffi::Error {
                code,
                extended_code: 0,
            },
            None,
        )
    }

    #[test]
    fn full_integrity_row_contract_is_exact_and_fail_closed() {
        assert_eq!(
            stream([Ok(FullIntegrityRow::ExactOkText), Ok(FullIntegrityRow::End)]),
            Ok(())
        );
        for values in [
            vec![Ok(FullIntegrityRow::End)],
            vec![Ok(FullIntegrityRow::Malformed)],
            vec![
                Ok(FullIntegrityRow::ExactOkText),
                Ok(FullIntegrityRow::ExactOkText),
            ],
        ] {
            assert_eq!(
                stream(values),
                Err(FullIntegrityValidationError::FullIntegrityInterruptedOrIncomplete)
            );
        }
        for row in [FullIntegrityRow::NonText, FullIntegrityRow::OtherText] {
            assert_eq!(
                stream([Ok(row)]),
                Err(FullIntegrityValidationError::FullIntegrityFailed)
            );
        }
    }

    #[test]
    fn step_failures_before_and_during_terminal_check_fail_closed() {
        let interrupted = FullIntegrityValidationError::FullIntegrityInterruptedOrIncomplete;
        assert_eq!(stream([Err(interrupted)]), Err(interrupted));
        assert_eq!(
            stream([Ok(FullIntegrityRow::ExactOkText), Err(interrupted)]),
            Err(interrupted)
        );
    }

    #[test]
    fn preparation_query_start_and_step_failures_are_coarsely_classified() {
        let unavailable = synthetic_sqlite_error(ErrorCode::DatabaseBusy);
        let corrupt = synthetic_sqlite_error(ErrorCode::DatabaseCorrupt);
        let interrupted = synthetic_sqlite_error(ErrorCode::OperationInterrupted);
        for boundary in [
            FullIntegrityOperationBoundary::Preparation,
            FullIntegrityOperationBoundary::QueryStartup,
            FullIntegrityOperationBoundary::RowStepping,
        ] {
            assert_eq!(
                classify_full_integrity_error(&unavailable, boundary),
                FullIntegrityValidationError::FullIntegrityUnavailable
            );
            assert_eq!(
                classify_full_integrity_error(&corrupt, boundary),
                FullIntegrityValidationError::FullIntegrityFailed
            );
            assert_eq!(
                classify_full_integrity_error(&interrupted, boundary),
                FullIntegrityValidationError::FullIntegrityInterruptedOrIncomplete
            );
        }
        let opaque = rusqlite::Error::InvalidQuery;
        assert_eq!(
            classify_full_integrity_error(&opaque, FullIntegrityOperationBoundary::Preparation),
            FullIntegrityValidationError::FullIntegrityUnavailable
        );
        assert_eq!(
            classify_full_integrity_error(&opaque, FullIntegrityOperationBoundary::QueryStartup),
            FullIntegrityValidationError::FullIntegrityUnavailable
        );
        assert_eq!(
            classify_full_integrity_error(&opaque, FullIntegrityOperationBoundary::RowStepping),
            FullIntegrityValidationError::FullIntegrityInterruptedOrIncomplete
        );
    }

    #[test]
    fn real_fixed_transition_succeeds_and_success_owner_closes_explicitly() {
        let root = TestRoot::create();
        let outcome = validate_production_database_full_integrity(accepted_predecessor(&root));
        let FullIntegrityValidationOutcome::Validated(owner) = outcome else {
            panic!("fixed full-integrity transition should succeed");
        };
        assert_eq!(
            format!("{owner:?}"),
            "FullIntegrityValidatedProductionDatabaseConnection([REDACTED])"
        );
        assert!(matches!(
            owner.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    struct ReleaseMarker<'a>(&'a RefCell<Vec<&'static str>>);

    impl Drop for ReleaseMarker<'_> {
        fn drop(&mut self) {
            self.0.borrow_mut().push("validation-resources-released");
        }
    }

    #[test]
    fn validation_resources_release_before_close_and_primary_is_preserved() {
        let root = TestRoot::create();
        let events = RefCell::new(Vec::new());
        let result = finish_validation_using(
            accepted_predecessor(&root),
            |_| {
                let _resources = ReleaseMarker(&events);
                Err(FullIntegrityValidationError::FullIntegrityFailed)
            },
            |connection| {
                events.borrow_mut().push("close");
                connection.close().map_err(|(returned, _)| returned)
            },
        );
        assert!(matches!(
            result,
            FullIntegrityValidationOutcome::Failed(
                FullIntegrityValidationError::FullIntegrityFailed
            )
        ));
        assert_eq!(
            events.into_inner(),
            ["validation-resources-released", "close"]
        );
        root.assert_exact_cleanup();
    }

    #[test]
    fn close_failure_retries_only_close_and_preserves_primary() {
        let root = TestRoot::create();
        let calls = RefCell::new(Vec::new());
        let outcome = finish_validation_using(
            accepted_predecessor(&root),
            |_| Err(FullIntegrityValidationError::FullIntegrityFailed),
            |connection| {
                calls.borrow_mut().push("close-failed");
                Err(connection)
            },
        );
        let FullIntegrityValidationOutcome::CloseFailed(failure) = outcome else {
            panic!("close failure must retain ownership");
        };
        assert_eq!(
            format!("{failure:?}"),
            "FullIntegrityValidationCloseFailure([REDACTED])"
        );
        let FullIntegrityValidationCloseRetryOutcome::Failed(failure) =
            failure.retry_close_using(|connection| {
                calls.borrow_mut().push("retry-close-failed");
                Err(connection)
            })
        else {
            panic!("repeated close failure must remain retryable");
        };
        let FullIntegrityValidationCloseRetryOutcome::Closed(category) = failure.retry_close()
        else {
            panic!("eventual close must succeed");
        };
        assert_eq!(category, FullIntegrityValidationError::FullIntegrityFailed);
        assert_eq!(calls.into_inner(), ["close-failed", "retry-close-failed"]);
        root.assert_exact_cleanup();
    }

    #[test]
    fn successful_owner_close_failure_retains_only_lifetime_ownership() {
        let root = TestRoot::create();
        let FullIntegrityValidationOutcome::Validated(owner) =
            validate_production_database_full_integrity(accepted_predecessor(&root))
        else {
            panic!("fixed full-integrity transition should succeed");
        };
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) = owner.close_using(Err)
        else {
            panic!("close failure must retain the lifetime owner");
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
    fn debug_and_source_boundaries_are_coarse_and_capability_limited() {
        assert_eq!(
            format!("{:?}", FullIntegrityValidationError::FullIntegrityFailed),
            "FullIntegrityFailed"
        );
        assert_eq!(
            format!(
                "{:?}",
                FullIntegrityValidationOutcome::Failed(
                    FullIntegrityValidationError::FullIntegrityUnavailable
                )
            ),
            "Failed(FullIntegrityUnavailable)"
        );
        assert!(needs_drop::<
            FullIntegrityValidatedProductionDatabaseConnection,
        >());

        const SOURCE: &str = include_str!("full_integrity_validation.rs");
        const PARENT: &str = include_str!("../production_database_connection_handoff.rs");
        const LIFECYCLE: &str = include_str!("../application_lifecycle.rs");
        const SETUP: &str = include_str!("../first_time_setup_orchestration.rs");
        const LIB: &str = include_str!("../lib.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let fixed_pragma = ["PRAGMA main.", "integrity_check"].concat();
        assert_eq!(SOURCE.matches(&fixed_pragma).count(), 1);
        assert!(!production.contains("cipher_integrity_check"));
        assert!(!production.contains("quick_check"));
        assert!(!production.contains("pub fn"));
        assert!(!production.contains("&Connection) ->"));
        for prohibited in [
            "CREATE ",
            "INSERT ",
            "UPDATE ",
            "DELETE ",
            "user_version",
            "std::fs",
            "Path",
            "File",
            "invoke_handler",
            "tauri::command",
            "callback",
        ] {
            assert!(!production.contains(prohibited), "found {prohibited}");
        }
        for unwired in [LIFECYCLE, SETUP, LIB] {
            assert!(!unwired.contains("validate_production_database_full_integrity"));
        }
        let quick_check = ["PRAGMA main.", "quick_check(1)"].concat();
        let cipher_check = ["PRAGMA cipher_", "integrity_check"].concat();
        let parent_production = PARENT.split_once("mod tests {").unwrap().0;
        assert_eq!(parent_production.matches(&quick_check).count(), 1);
        assert_eq!(parent_production.matches(&cipher_check).count(), 1);
    }
}
