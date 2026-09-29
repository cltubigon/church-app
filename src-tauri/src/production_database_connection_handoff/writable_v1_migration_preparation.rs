//! Narrow writable production connection prepared only for a later V1-to-V2
//! transaction. This module opens no caller-selected path and executes no
//! mutation or transaction SQL.

use std::fmt;

use rusqlite::{Connection, OpenFlags, config::DbConfig, types::ValueRef};

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    database_metadata_decoding::{RawDatabaseMetadataRow, RawDatabaseMetadataValue},
    database_restart_version_classification::{
        ObservedProductionDatabaseRestartState, ProductionDatabaseRestartClassification,
        classify_production_database_restart_state, require_exact_v1_for_writable_migration,
    },
    database_schema_v2_contract::ObservedV2Schema,
    installation_evidence_protection::GenerationBoundDatabaseKey,
    production_database_file::{
        ProductionDatabaseFileIdentity, ProductionDatabaseInspection,
        inspect_production_database_file_for_writable_migration,
        inspected_production_database_file_matches_identity,
    },
    storage_foundation::ProductionDatabasePath,
};

use super::{
    ConnectionLifetimeOwner, ProductionDatabaseConnectionCloseFailure,
    ProductionDatabaseConnectionCloseOutcome, acquire_guarded_inspection_for_writable_migration,
    apply_key_once, close_lifetime_owner_using, fixed_metadata_and_header_observation,
    revalidate_connection_identity, run_cipher_integrity_check, run_sqlite_quick_check,
    set_and_verify,
};

const WRITABLE_MIGRATION_OPEN_FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE
    .union(OpenFlags::SQLITE_OPEN_FULL_MUTEX)
    .union(OpenFlags::SQLITE_OPEN_PRIVATE_CACHE)
    .union(OpenFlags::SQLITE_OPEN_NOFOLLOW);
const WIN32_VFS_NAME: &str = "win32";
const MAIN_DATABASE_NAME: &str = "main";
const EXACT_V1_SCHEMA_OBJECTS: &str = "SELECT type, name, tbl_name
FROM main.sqlite_schema
WHERE name NOT LIKE 'sqlite_%'
ORDER BY type, name";
const EXACT_V1_METADATA_COLUMNS: &str = "PRAGMA main.table_xinfo('church_app_database_metadata')";
const METADATA_COLUMNS: [&str; 12] = [
    "singleton_id",
    "metadata_contract_version",
    "database_schema_version",
    "permanent_application_identifier",
    "database_format_identity",
    "parish_identifier",
    "installation_identifier",
    "installation_generation",
    "recovery_replacement_generation",
    "database_key_generation_identifier",
    "setup_publication_identifier",
    "database_created_at",
];

pub(crate) struct WritableV1MigrationDatabase {
    owner: ConnectionLifetimeOwner,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum WritableV1MigrationDatabaseOpenError {
    ProductionFileChangedOrUnavailable,
    WritableOpenFailed,
    DatabaseKeyApplicationFailed,
    ExactV1RevalidationFailed,
    IntegrityFailed,
    VersionClassificationMismatch(ProductionDatabaseRestartClassification),
}

pub(crate) struct WritableV1MigrationDatabaseCloseFailure {
    category: WritableV1MigrationDatabaseOpenError,
    owner: ConnectionLifetimeOwner,
}

#[must_use = "the writable migration database open outcome must be handled"]
pub(crate) enum WritableV1MigrationDatabaseOpenOutcome {
    Prepared(WritableV1MigrationDatabase),
    Failed(WritableV1MigrationDatabaseOpenError),
    CloseFailed(WritableV1MigrationDatabaseCloseFailure),
}

#[must_use = "the writable migration database close retry outcome must be handled"]
pub(crate) enum WritableV1MigrationDatabaseCloseRetryOutcome {
    Closed,
    Failed(WritableV1MigrationDatabaseCloseFailure),
}

impl fmt::Debug for WritableV1MigrationDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WritableV1MigrationDatabase([REDACTED])")
    }
}

impl fmt::Debug for WritableV1MigrationDatabaseCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WritableV1MigrationDatabaseCloseFailure([REDACTED])")
    }
}

impl fmt::Debug for WritableV1MigrationDatabaseOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionClassificationMismatch(classification) => formatter
                .debug_tuple("VersionClassificationMismatch")
                .field(classification)
                .finish(),
            Self::ProductionFileChangedOrUnavailable => {
                formatter.write_str("ProductionFileChangedOrUnavailable")
            }
            Self::WritableOpenFailed => formatter.write_str("WritableOpenFailed"),
            Self::DatabaseKeyApplicationFailed => {
                formatter.write_str("DatabaseKeyApplicationFailed")
            }
            Self::ExactV1RevalidationFailed => formatter.write_str("ExactV1RevalidationFailed"),
            Self::IntegrityFailed => formatter.write_str("IntegrityFailed"),
        }
    }
}

impl WritableV1MigrationDatabase {
    pub(crate) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        close_lifetime_owner_using(self.owner, |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        })
    }
}

impl WritableV1MigrationDatabaseCloseFailure {
    pub(crate) fn retry_close(self) -> WritableV1MigrationDatabaseCloseRetryOutcome {
        let Self { category, owner } = self;
        match close_lifetime_owner_using(owner, |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        }) {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                let _ = category;
                WritableV1MigrationDatabaseCloseRetryOutcome::Closed
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                WritableV1MigrationDatabaseCloseRetryOutcome::Failed(Self {
                    category,
                    owner: failure.owner,
                })
            }
        }
    }
}

fn configure_writable_migration_policy(
    connection: &Connection,
) -> Result<(), WritableV1MigrationDatabaseOpenError> {
    connection
        .busy_timeout(super::BUSY_TIMEOUT)
        .map_err(|_| WritableV1MigrationDatabaseOpenError::WritableOpenFailed)?;
    // SAFETY: the live handle is borrowed synchronously and does not escape.
    let status = unsafe { rusqlite::ffi::sqlite3_enable_load_extension(connection.handle(), 0) };
    if status != rusqlite::ffi::SQLITE_OK {
        return Err(WritableV1MigrationDatabaseOpenError::WritableOpenFailed);
    }
    for (config, expected) in [
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, false),
    ] {
        set_and_verify(connection, config, expected)
            .map_err(|_| WritableV1MigrationDatabaseOpenError::WritableOpenFailed)?;
    }
    if connection.is_readonly(MAIN_DATABASE_NAME) != Ok(false) {
        return Err(WritableV1MigrationDatabaseOpenError::WritableOpenFailed);
    }
    Ok(())
}

fn validate_exact_v1_physical_schema(
    connection: &Connection,
) -> Result<(), WritableV1MigrationDatabaseOpenError> {
    let mut objects = connection
        .prepare(EXACT_V1_SCHEMA_OBJECTS)
        .map_err(|_| WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed)?;
    if objects.column_count() != 3 {
        return Err(WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed);
    }
    let mut rows = objects
        .query([])
        .map_err(|_| WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed)?;
    let row = rows
        .next()
        .map_err(|_| WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed)?
        .ok_or(WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed)?;
    let exact_metadata_table = matches!(row.get_ref(0), Ok(ValueRef::Text(b"table")))
        && matches!(
            row.get_ref(1),
            Ok(ValueRef::Text(b"church_app_database_metadata"))
        )
        && matches!(
            row.get_ref(2),
            Ok(ValueRef::Text(b"church_app_database_metadata"))
        );
    if !exact_metadata_table
        || rows
            .next()
            .map_err(|_| WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed)?
            .is_some()
    {
        return Err(WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed);
    }
    drop(rows);
    drop(objects);

    let mut columns = connection
        .prepare(EXACT_V1_METADATA_COLUMNS)
        .map_err(|_| WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed)?;
    let mut rows = columns
        .query([])
        .map_err(|_| WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed)?;
    for (expected_cid, expected_name) in METADATA_COLUMNS.iter().enumerate() {
        let row = rows
            .next()
            .map_err(|_| WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed)?
            .ok_or(WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed)?;
        let cid = i64::try_from(expected_cid)
            .map_err(|_| WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed)?;
        let exact = matches!(row.get_ref(0), Ok(ValueRef::Integer(value)) if value == cid)
            && matches!(row.get_ref(1), Ok(ValueRef::Text(value)) if value == expected_name.as_bytes())
            && matches!(row.get_ref(2), Ok(ValueRef::Text(b"")))
            && matches!(row.get_ref(3), Ok(ValueRef::Integer(0)))
            && matches!(row.get_ref(4), Ok(ValueRef::Null))
            && matches!(row.get_ref(5), Ok(ValueRef::Integer(0)))
            && matches!(row.get_ref(6), Ok(ValueRef::Integer(0)));
        if !exact {
            return Err(WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed);
        }
    }
    if rows
        .next()
        .map_err(|_| WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed)?
        .is_some()
    {
        return Err(WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed);
    }
    Ok(())
}

fn classify_validated_v1(
    metadata: &DatabaseMetadataContractV1,
) -> ProductionDatabaseRestartClassification {
    let mut installation_identifier = [0_u8; 16];
    metadata
        .installation_identifier()
        .write_bytes_into(&mut installation_identifier);
    let mut database_key_generation_identifier = [0_u8; 16];
    metadata
        .database_key_generation_identifier()
        .write_bytes_into(&mut database_key_generation_identifier);
    let mut setup_publication_identifier = [0_u8; 16];
    metadata
        .setup_publication_identifier()
        .write_bytes_into(&mut setup_publication_identifier);
    let installation_generation = metadata.installation_generation().get().to_be_bytes();
    let recovery_replacement_generation = metadata
        .recovery_replacement_generation()
        .get()
        .to_be_bytes();
    let created_at =
        i64::try_from(metadata.database_created_at().unix_milliseconds()).unwrap_or(i64::MAX);
    let database_format_identity = metadata.database_format_identity();
    let parish_identifier = metadata.parish_identifier();
    let raw = RawDatabaseMetadataRow::new(
        RawDatabaseMetadataValue::Integer(i64::from(metadata.singleton_id().get())),
        RawDatabaseMetadataValue::Integer(i64::from(metadata.metadata_contract_version().get())),
        RawDatabaseMetadataValue::Integer(i64::from(metadata.database_schema_version().get())),
        RawDatabaseMetadataValue::Text(metadata.permanent_application_identifier().as_str()),
        RawDatabaseMetadataValue::Blob(database_format_identity.as_bytes()),
        RawDatabaseMetadataValue::Blob(parish_identifier.as_bytes()),
        RawDatabaseMetadataValue::Blob(&installation_identifier),
        RawDatabaseMetadataValue::Blob(&installation_generation),
        RawDatabaseMetadataValue::Blob(&recovery_replacement_generation),
        RawDatabaseMetadataValue::Blob(&database_key_generation_identifier),
        RawDatabaseMetadataValue::Blob(&setup_publication_identifier),
        RawDatabaseMetadataValue::Integer(created_at),
    );
    classify_production_database_restart_state(&ObservedProductionDatabaseRestartState {
        application_id: super::PRODUCTION_DATABASE_APPLICATION_ID,
        metadata: raw,
        schema: ObservedV2Schema {
            user_version: 1,
            metadata_contract_version: 1,
            metadata_database_schema_version: 1,
            business_tables: Vec::new(),
            business_indexes: Vec::new(),
            triggers: Vec::new(),
        },
    })
}

fn close_after_failure(
    owner: ConnectionLifetimeOwner,
    category: WritableV1MigrationDatabaseOpenError,
) -> WritableV1MigrationDatabaseOpenOutcome {
    match close_lifetime_owner_using(owner, |connection| {
        connection
            .close()
            .map_err(|(returned_connection, _)| returned_connection)
    }) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            WritableV1MigrationDatabaseOpenOutcome::Failed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(
            ProductionDatabaseConnectionCloseFailure { owner },
        ) => WritableV1MigrationDatabaseOpenOutcome::CloseFailed(
            WritableV1MigrationDatabaseCloseFailure { category, owner },
        ),
    }
}

pub(crate) fn open_writable_v1_migration_database(
    path: ProductionDatabasePath,
    expected_file_identity: ProductionDatabaseFileIdentity,
    expected_metadata: DatabaseMetadataContractV1,
    key: GenerationBoundDatabaseKey,
) -> WritableV1MigrationDatabaseOpenOutcome {
    let inspected = match inspect_production_database_file_for_writable_migration(&path) {
        ProductionDatabaseInspection::Present(inspected)
            if inspected_production_database_file_matches_identity(
                &inspected,
                expected_file_identity,
            ) =>
        {
            inspected
        }
        ProductionDatabaseInspection::Present(_)
        | ProductionDatabaseInspection::Missing
        | ProductionDatabaseInspection::Unavailable
        | ProductionDatabaseInspection::Invalid => {
            return WritableV1MigrationDatabaseOpenOutcome::Failed(
                WritableV1MigrationDatabaseOpenError::ProductionFileChangedOrUnavailable,
            );
        }
    };
    let guarded = match acquire_guarded_inspection_for_writable_migration(&path, inspected) {
        Ok(guarded) => guarded,
        Err(_) => {
            return WritableV1MigrationDatabaseOpenOutcome::Failed(
                WritableV1MigrationDatabaseOpenError::ProductionFileChangedOrUnavailable,
            );
        }
    };
    let connection = match Connection::open_with_flags_and_vfs(
        path.as_path(),
        WRITABLE_MIGRATION_OPEN_FLAGS,
        WIN32_VFS_NAME,
    ) {
        Ok(connection) => connection,
        Err(_) => {
            return WritableV1MigrationDatabaseOpenOutcome::Failed(
                WritableV1MigrationDatabaseOpenError::WritableOpenFailed,
            );
        }
    };
    let owner = ConnectionLifetimeOwner {
        connection,
        guard: guarded.guard,
        inspected: guarded.inspected,
    };

    if revalidate_connection_identity(&owner.connection, &owner.inspected).is_err()
        || configure_writable_migration_policy(&owner.connection).is_err()
    {
        return close_after_failure(
            owner,
            WritableV1MigrationDatabaseOpenError::WritableOpenFailed,
        );
    }
    if apply_key_once(&owner.connection, &key).is_err() {
        return close_after_failure(
            owner,
            WritableV1MigrationDatabaseOpenError::DatabaseKeyApplicationFailed,
        );
    }
    drop(key);

    if run_cipher_integrity_check(&owner.connection).is_err()
        || run_sqlite_quick_check(&owner.connection).is_err()
        || super::full_integrity_validation::validate_production_database_full_integrity_on_borrowed_connection(
            &owner.connection,
        )
        .is_err()
    {
        return close_after_failure(owner, WritableV1MigrationDatabaseOpenError::IntegrityFailed);
    }
    let metadata = match fixed_metadata_and_header_observation::observe_fixed_metadata_and_headers(
        &owner.connection,
        Some(1),
    ) {
        Ok(metadata) if metadata == expected_metadata => metadata,
        Ok(_) | Err(_) => {
            return close_after_failure(
                owner,
                WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed,
            );
        }
    };
    if validate_exact_v1_physical_schema(&owner.connection).is_err() {
        return close_after_failure(
            owner,
            WritableV1MigrationDatabaseOpenError::ExactV1RevalidationFailed,
        );
    }
    let classification = classify_validated_v1(&metadata);
    if let Err(classification) = require_exact_v1_for_writable_migration(classification) {
        return close_after_failure(
            owner,
            WritableV1MigrationDatabaseOpenError::VersionClassificationMismatch(classification),
        );
    }

    WritableV1MigrationDatabaseOpenOutcome::Prepared(WritableV1MigrationDatabase { owner })
}

#[cfg(test)]
mod tests {
    #[test]
    fn production_sql_is_read_only_and_contains_no_transaction_or_mutation() {
        let source = include_str!("writable_v1_migration_preparation.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "BEGIN",
            "CREATE TABLE",
            "CREATE INDEX",
            "UPDATE ",
            "INSERT ",
            "DELETE ",
            "ALTER ",
            "DROP ",
            "user_version = 2",
            ".execute(",
            ".execute_batch(",
            ".pragma_update(",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected mutation: {forbidden}"
            );
        }
    }

    #[test]
    fn writable_open_is_fixed_no_create_and_reuses_canonical_keying() {
        let source = include_str!("writable_v1_migration_preparation.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("OpenFlags::SQLITE_OPEN_READ_WRITE"));
        assert!(production.contains("OpenFlags::SQLITE_OPEN_NOFOLLOW"));
        assert!(!production.contains("SQLITE_OPEN_CREATE"));
        assert_eq!(
            production
                .matches("apply_key_once(&owner.connection, &key)")
                .count(),
            1
        );
        assert!(production.contains("inspect_production_database_file_for_writable_migration"));
        assert!(production.contains("inspected_production_database_file_matches_identity"));
    }

    #[test]
    fn exact_v1_checks_reuse_integrity_metadata_and_restart_classifier() {
        let source = include_str!("writable_v1_migration_preparation.rs");
        for required in [
            "run_cipher_integrity_check",
            "run_sqlite_quick_check",
            "validate_production_database_full_integrity_on_borrowed_connection",
            "observe_fixed_metadata_and_headers",
            "validate_exact_v1_physical_schema",
            "classify_production_database_restart_state",
            "require_exact_v1_for_writable_migration",
        ] {
            assert!(source.contains(required), "missing check: {required}");
        }
    }
}
