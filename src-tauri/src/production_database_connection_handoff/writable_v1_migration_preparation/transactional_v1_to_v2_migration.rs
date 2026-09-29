//! One fixed, consuming, in-place V1-to-V2 migration transaction.

use std::fmt;

use rusqlite::{Connection, types::ValueRef};

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    database_metadata_decoding::{RawDatabaseMetadataRow, RawDatabaseMetadataValue},
    database_restart_version_classification::{
        ObservedProductionDatabaseRestartState, ProductionDatabaseRestartClassification,
        classify_production_database_restart_state,
    },
    database_schema_v2_contract::{
        ObservedColumn, ObservedForeignKey, ObservedIndex, ObservedTable, ObservedUniqueConstraint,
        ObservedV2Schema, V2_DATABASE_SCHEMA_VERSION, V2_INDEXES, V2_METADATA_CONTRACT_VERSION,
        V2_SCHEMA_DDL, V2_TABLES, V2_USER_VERSION, validate_v2_schema,
    },
};

use super::{super::*, WritableV1MigrationDatabase};

const BEGIN_IMMEDIATE: &str = "BEGIN IMMEDIATE";
const COMMIT: &str = "COMMIT";
const ROLLBACK: &str = "ROLLBACK";
const METADATA_VERSION_UPDATE: &str = "UPDATE main.church_app_database_metadata
SET database_schema_version = 2
WHERE singleton_id = 1 AND database_schema_version = 1";
const USER_VERSION_UPDATE: &str = "PRAGMA main.user_version = 2";
const FOREIGN_KEYS_ENABLE: &str = "PRAGMA main.foreign_keys = ON";
const FOREIGN_KEYS_QUERY: &str = "PRAGMA main.foreign_keys";
const SCHEMA_OBJECTS_QUERY: &str = "SELECT type, name, tbl_name, sql
FROM main.sqlite_schema
WHERE name NOT LIKE 'sqlite_%'
ORDER BY type, name";
const BUSINESS_TABLE_COUNT_QUERIES: [&str; 3] = [
    "SELECT COUNT(*) FROM main.service_requests",
    "SELECT COUNT(*) FROM main.request_schedule_occurrences",
    "SELECT COUNT(*) FROM main.request_cancellation_reviews",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WritableV1ToV2MigrationError {
    BeginFailed,
    SchemaCreationFailed,
    MetadataVersionUpdateFailed,
    UserVersionUpdateFailed,
    RollbackFailed,
    CommitAmbiguous,
    PostCommitValidationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WritableV1ToV2MigrationTerminalDisposition {
    CommittedAndValidated,
    RolledBack(WritableV1ToV2MigrationError),
    CommitAmbiguous,
    CommittedButInvalid,
}

pub(crate) struct WritableV1ToV2MigrationCloseFailure {
    disposition: WritableV1ToV2MigrationTerminalDisposition,
    close_failure: ProductionDatabaseConnectionCloseFailure,
}

#[must_use = "the V1-to-V2 migration outcome must be handled"]
pub(crate) enum WritableV1ToV2MigrationOutcome {
    Closed(WritableV1ToV2MigrationTerminalDisposition),
    CloseFailed(WritableV1ToV2MigrationCloseFailure),
}

#[must_use = "the V1-to-V2 close retry outcome must be handled"]
pub(crate) enum WritableV1ToV2MigrationCloseRetryOutcome {
    Closed(WritableV1ToV2MigrationTerminalDisposition),
    Failed(WritableV1ToV2MigrationCloseFailure),
}

impl fmt::Debug for WritableV1ToV2MigrationCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WritableV1ToV2MigrationCloseFailure([REDACTED])")
    }
}

impl WritableV1ToV2MigrationCloseFailure {
    pub(crate) fn retry_close(self) -> WritableV1ToV2MigrationCloseRetryOutcome {
        let Self {
            disposition,
            close_failure,
        } = self;
        match close_failure.retry_close() {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                WritableV1ToV2MigrationCloseRetryOutcome::Closed(disposition)
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(close_failure) => {
                WritableV1ToV2MigrationCloseRetryOutcome::Failed(Self {
                    disposition,
                    close_failure,
                })
            }
        }
    }
}

fn close_with_disposition(
    owner: ConnectionLifetimeOwner,
    disposition: WritableV1ToV2MigrationTerminalDisposition,
) -> WritableV1ToV2MigrationOutcome {
    match close_lifetime_owner_using(owner, |connection| {
        connection
            .close()
            .map_err(|(returned_connection, _)| returned_connection)
    }) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            WritableV1ToV2MigrationOutcome::Closed(disposition)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(close_failure) => {
            WritableV1ToV2MigrationOutcome::CloseFailed(WritableV1ToV2MigrationCloseFailure {
                disposition,
                close_failure,
            })
        }
    }
}

#[derive(Clone, Copy)]
enum MigrationFailureInjection {
    None,
    #[cfg(test)]
    Ddl(usize),
    #[cfg(test)]
    Metadata,
    #[cfg(test)]
    UserVersion,
    #[cfg(test)]
    Commit,
}

impl MigrationFailureInjection {
    fn fails_ddl_at(self, index: usize) -> bool {
        #[cfg(test)]
        {
            matches!(self, Self::Ddl(failed) if failed == index)
        }
        #[cfg(not(test))]
        {
            let _ = (self, index);
            false
        }
    }
}

enum FixedTransactionOutcome {
    Committed,
    Terminal(WritableV1ToV2MigrationTerminalDisposition),
}

fn rollback_transaction(
    connection: &Connection,
    category: WritableV1ToV2MigrationError,
) -> FixedTransactionOutcome {
    if connection.execute_batch(ROLLBACK).is_ok() {
        FixedTransactionOutcome::Terminal(WritableV1ToV2MigrationTerminalDisposition::RolledBack(
            category,
        ))
    } else {
        FixedTransactionOutcome::Terminal(WritableV1ToV2MigrationTerminalDisposition::RolledBack(
            WritableV1ToV2MigrationError::RollbackFailed,
        ))
    }
}

fn execute_fixed_transaction(
    connection: &Connection,
    _failure: MigrationFailureInjection,
) -> FixedTransactionOutcome {
    if connection.execute_batch(FOREIGN_KEYS_ENABLE).is_err()
        || observe_single_i64(connection, FOREIGN_KEYS_QUERY) != Ok(1)
        || connection.execute_batch(BEGIN_IMMEDIATE).is_err()
    {
        return FixedTransactionOutcome::Terminal(
            WritableV1ToV2MigrationTerminalDisposition::RolledBack(
                WritableV1ToV2MigrationError::BeginFailed,
            ),
        );
    }

    for (index, statement) in V2_SCHEMA_DDL.iter().enumerate() {
        if _failure.fails_ddl_at(index) {
            return rollback_transaction(
                connection,
                WritableV1ToV2MigrationError::SchemaCreationFailed,
            );
        }
        if connection.execute_batch(statement).is_err() {
            return rollback_transaction(
                connection,
                WritableV1ToV2MigrationError::SchemaCreationFailed,
            );
        }
    }
    #[cfg(test)]
    if matches!(_failure, MigrationFailureInjection::Metadata) {
        return rollback_transaction(
            connection,
            WritableV1ToV2MigrationError::MetadataVersionUpdateFailed,
        );
    }
    if connection.execute(METADATA_VERSION_UPDATE, []).ok() != Some(1) {
        return rollback_transaction(
            connection,
            WritableV1ToV2MigrationError::MetadataVersionUpdateFailed,
        );
    }
    #[cfg(test)]
    if matches!(_failure, MigrationFailureInjection::UserVersion) {
        return rollback_transaction(
            connection,
            WritableV1ToV2MigrationError::UserVersionUpdateFailed,
        );
    }
    if connection.execute_batch(USER_VERSION_UPDATE).is_err()
        || observe_single_i64(
            connection,
            fixed_metadata_and_header_observation::USER_VERSION_QUERY,
        ) != Ok(i64::from(V2_USER_VERSION))
    {
        return rollback_transaction(
            connection,
            WritableV1ToV2MigrationError::UserVersionUpdateFailed,
        );
    }

    #[cfg(test)]
    if matches!(_failure, MigrationFailureInjection::Commit) {
        return FixedTransactionOutcome::Terminal(
            WritableV1ToV2MigrationTerminalDisposition::CommitAmbiguous,
        );
    }
    if connection.execute_batch(COMMIT).is_err() {
        return FixedTransactionOutcome::Terminal(
            WritableV1ToV2MigrationTerminalDisposition::CommitAmbiguous,
        );
    }
    FixedTransactionOutcome::Committed
}

impl WritableV1MigrationDatabase {
    pub(crate) fn execute_v1_to_v2(self) -> WritableV1ToV2MigrationOutcome {
        let Self {
            owner,
            expected_v1_metadata,
        } = self;
        match execute_fixed_transaction(&owner.connection, MigrationFailureInjection::None) {
            FixedTransactionOutcome::Terminal(disposition) => {
                return close_with_disposition(owner, disposition);
            }
            FixedTransactionOutcome::Committed => {}
        }

        let disposition = if validate_committed_v2(&owner, expected_v1_metadata).is_ok() {
            WritableV1ToV2MigrationTerminalDisposition::CommittedAndValidated
        } else {
            WritableV1ToV2MigrationTerminalDisposition::CommittedButInvalid
        };
        close_with_disposition(owner, disposition)
    }
}

fn observe_single_i64(connection: &Connection, sql: &str) -> Result<i64, ()> {
    let mut statement = connection.prepare(sql).map_err(|_| ())?;
    if statement.column_count() != 1 {
        return Err(());
    }
    let mut rows = statement.query([]).map_err(|_| ())?;
    let row = rows.next().map_err(|_| ())?.ok_or(())?;
    let value = match row.get_ref(0).map_err(|_| ())? {
        ValueRef::Integer(value) => value,
        _ => return Err(()),
    };
    if rows.next().map_err(|_| ())?.is_some() {
        return Err(());
    }
    Ok(value)
}

#[derive(Debug, Eq, PartialEq)]
enum OwnedMetadataValue {
    Integer(i64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
    Other,
}

fn observe_metadata(connection: &Connection) -> Result<Vec<OwnedMetadataValue>, ()> {
    let mut statement = connection
        .prepare(fixed_metadata_and_header_observation::METADATA_QUERY)
        .map_err(|_| ())?;
    if statement.column_count() != fixed_metadata_and_header_observation::METADATA_COLUMN_COUNT {
        return Err(());
    }
    let mut rows = statement.query([]).map_err(|_| ())?;
    let row = rows.next().map_err(|_| ())?.ok_or(())?;
    let mut values =
        Vec::with_capacity(fixed_metadata_and_header_observation::METADATA_COLUMN_COUNT);
    for index in 0..fixed_metadata_and_header_observation::METADATA_COLUMN_COUNT {
        values.push(match row.get_ref(index).map_err(|_| ())? {
            ValueRef::Integer(value) => OwnedMetadataValue::Integer(value),
            ValueRef::Text(value) => OwnedMetadataValue::Text(value.to_vec()),
            ValueRef::Blob(value) => OwnedMetadataValue::Blob(value.to_vec()),
            ValueRef::Null | ValueRef::Real(_) => OwnedMetadataValue::Other,
        });
    }
    if rows.next().map_err(|_| ())?.is_some() {
        return Err(());
    }
    Ok(values)
}

fn expected_metadata_values(
    metadata: DatabaseMetadataContractV1,
    schema_version: i64,
) -> Vec<OwnedMetadataValue> {
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
    vec![
        OwnedMetadataValue::Integer(i64::from(metadata.singleton_id().get())),
        OwnedMetadataValue::Integer(i64::from(metadata.metadata_contract_version().get())),
        OwnedMetadataValue::Integer(schema_version),
        OwnedMetadataValue::Text(
            metadata
                .permanent_application_identifier()
                .as_str()
                .as_bytes()
                .to_vec(),
        ),
        OwnedMetadataValue::Blob(metadata.database_format_identity().as_bytes().to_vec()),
        OwnedMetadataValue::Blob(metadata.parish_identifier().as_bytes().to_vec()),
        OwnedMetadataValue::Blob(installation_identifier.to_vec()),
        OwnedMetadataValue::Blob(
            metadata
                .installation_generation()
                .get()
                .to_be_bytes()
                .to_vec(),
        ),
        OwnedMetadataValue::Blob(
            metadata
                .recovery_replacement_generation()
                .get()
                .to_be_bytes()
                .to_vec(),
        ),
        OwnedMetadataValue::Blob(database_key_generation_identifier.to_vec()),
        OwnedMetadataValue::Blob(setup_publication_identifier.to_vec()),
        OwnedMetadataValue::Integer(
            i64::try_from(metadata.database_created_at().unix_milliseconds()).unwrap_or(i64::MAX),
        ),
    ]
}

fn metadata_raw<'a>(values: &'a [OwnedMetadataValue]) -> Result<RawDatabaseMetadataRow<'a>, ()> {
    let adapt = |value: &'a OwnedMetadataValue| match value {
        OwnedMetadataValue::Integer(value) => Ok(RawDatabaseMetadataValue::Integer(*value)),
        OwnedMetadataValue::Text(value) => std::str::from_utf8(value)
            .map(RawDatabaseMetadataValue::Text)
            .map_err(|_| ()),
        OwnedMetadataValue::Blob(value) => Ok(RawDatabaseMetadataValue::Blob(value)),
        OwnedMetadataValue::Other => Err(()),
    };
    Ok(RawDatabaseMetadataRow::new(
        adapt(&values[0])?,
        adapt(&values[1])?,
        adapt(&values[2])?,
        adapt(&values[3])?,
        adapt(&values[4])?,
        adapt(&values[5])?,
        adapt(&values[6])?,
        adapt(&values[7])?,
        adapt(&values[8])?,
        adapt(&values[9])?,
        adapt(&values[10])?,
        adapt(&values[11])?,
    ))
}

fn exact_schema_observation(connection: &Connection) -> Result<ObservedV2Schema, ()> {
    let mut statement = connection.prepare(SCHEMA_OBJECTS_QUERY).map_err(|_| ())?;
    let mut rows = statement.query([]).map_err(|_| ())?;
    let mut observed = Vec::new();
    while let Some(row) = rows.next().map_err(|_| ())? {
        observed.push((
            row.get::<_, String>(0).map_err(|_| ())?,
            row.get::<_, String>(1).map_err(|_| ())?,
            row.get::<_, String>(2).map_err(|_| ())?,
            row.get::<_, String>(3).map_err(|_| ())?,
        ));
    }
    if observed.len() != 1 + V2_TABLES.len() + V2_INDEXES.len()
        || !observed.iter().any(|(kind, name, table, _)| {
            kind == "table" && name == "church_app_database_metadata" && table == name
        })
    {
        return Err(());
    }
    for (offset, table) in V2_TABLES.iter().enumerate() {
        if !observed.iter().any(|(kind, name, table_name, sql)| {
            kind == "table"
                && name == table.name
                && table_name == table.name
                && sql == V2_SCHEMA_DDL[offset]
        }) {
            return Err(());
        }
    }
    for (offset, index) in V2_INDEXES.iter().enumerate() {
        if !observed.iter().any(|(kind, name, table, sql)| {
            kind == "index"
                && name == index.name
                && table == index.table
                && sql == V2_SCHEMA_DDL[V2_TABLES.len() + offset]
        }) {
            return Err(());
        }
    }

    Ok(ObservedV2Schema {
        user_version: u32::try_from(observe_single_i64(
            connection,
            fixed_metadata_and_header_observation::USER_VERSION_QUERY,
        )?)
        .map_err(|_| ())?,
        metadata_contract_version: V2_METADATA_CONTRACT_VERSION,
        metadata_database_schema_version: V2_DATABASE_SCHEMA_VERSION,
        business_tables: V2_TABLES
            .iter()
            .map(|table| ObservedTable {
                name: table.name.to_owned(),
                columns: table
                    .columns
                    .iter()
                    .map(|column| ObservedColumn {
                        name: column.name.to_owned(),
                        sqlite_type: column.sqlite_type,
                        nullable: column.nullable,
                        primary_key_ordinal: column.primary_key_ordinal,
                        has_default: column.has_default,
                    })
                    .collect(),
                checks: table.checks.to_vec(),
                foreign_keys: table
                    .foreign_keys
                    .iter()
                    .map(|foreign_key| ObservedForeignKey {
                        columns: foreign_key
                            .columns
                            .iter()
                            .map(|column| (*column).to_owned())
                            .collect(),
                        referenced_table: foreign_key.referenced_table.to_owned(),
                        referenced_columns: foreign_key
                            .referenced_columns
                            .iter()
                            .map(|column| (*column).to_owned())
                            .collect(),
                        on_update: foreign_key.on_update,
                        on_delete: foreign_key.on_delete,
                    })
                    .collect(),
                unique_constraints: table
                    .unique_constraints
                    .iter()
                    .map(|unique| ObservedUniqueConstraint {
                        columns: unique
                            .columns
                            .iter()
                            .map(|column| (*column).to_owned())
                            .collect(),
                    })
                    .collect(),
                strict: table.strict,
                without_rowid: table.without_rowid,
            })
            .collect(),
        business_indexes: V2_INDEXES
            .iter()
            .map(|index| ObservedIndex {
                name: index.name.to_owned(),
                table: index.table.to_owned(),
                columns: index
                    .columns
                    .iter()
                    .map(|column| (*column).to_owned())
                    .collect(),
                unique: index.unique,
                predicate: index.predicate,
            })
            .collect(),
        triggers: Vec::new(),
    })
}

fn validate_business_tables_empty(connection: &Connection) -> Result<(), ()> {
    for query in BUSINESS_TABLE_COUNT_QUERIES {
        if observe_single_i64(connection, query)? != 0 {
            return Err(());
        }
    }
    Ok(())
}

fn validate_committed_v2(
    owner: &ConnectionLifetimeOwner,
    expected_v1_metadata: DatabaseMetadataContractV1,
) -> Result<(), ()> {
    revalidate_connection_identity(&owner.connection, &owner.inspected).map_err(|_| ())?;
    if observe_single_i64(&owner.connection, FOREIGN_KEYS_QUERY)? != 1 {
        return Err(());
    }
    run_cipher_integrity_check(&owner.connection).map_err(|_| ())?;
    run_sqlite_quick_check(&owner.connection).map_err(|_| ())?;
    full_integrity_validation::validate_production_database_full_integrity_on_borrowed_connection(
        &owner.connection,
    )
    .map_err(|_| ())?;
    let application_id =
        fixed_metadata_and_header_observation::observe_application_id(&owner.connection)
            .map_err(|_| ())?;
    let metadata = observe_metadata(&owner.connection)?;
    if metadata != expected_metadata_values(expected_v1_metadata, 2) {
        return Err(());
    }
    let schema = exact_schema_observation(&owner.connection)?;
    validate_v2_schema(&schema).map_err(|_| ())?;
    validate_business_tables_empty(&owner.connection)?;
    if classify_production_database_restart_state(&ObservedProductionDatabaseRestartState {
        application_id,
        metadata: metadata_raw(&metadata)?,
        schema,
    }) != ProductionDatabaseRestartClassification::ExactV2
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        installation_evidence_contract::PERMANENT_APPLICATION_IDENTIFIER,
        storage_foundation::APPLICATION_DATABASE_FORMAT_IDENTITY,
    };
    use rusqlite::params;
    use std::{
        ops::Deref,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    const CREATE_METADATA: &str = "CREATE TABLE church_app_database_metadata (
        singleton_id,
        metadata_contract_version,
        database_schema_version,
        permanent_application_identifier,
        database_format_identity,
        parish_identifier,
        installation_identifier,
        installation_generation,
        recovery_replacement_generation,
        database_key_generation_identifier,
        setup_publication_identifier,
        database_created_at
    )";

    struct SyntheticSqlcipherV1 {
        connection: Option<Connection>,
        path: PathBuf,
    }

    impl Deref for SyntheticSqlcipherV1 {
        type Target = Connection;

        fn deref(&self) -> &Self::Target {
            self.connection.as_ref().unwrap()
        }
    }

    impl Drop for SyntheticSqlcipherV1 {
        fn drop(&mut self) {
            if let Some(connection) = self.connection.take() {
                let _ = connection.close();
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn synthetic_sqlcipher_v1() -> SyntheticSqlcipherV1 {
        let path = std::env::temp_dir().join(format!(
            "church-app-v1-v2-migration-{}-{}.db",
            std::process::id(),
            FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "PRAGMA key = \"x'1111111111111111111111111111111111111111111111111111111111111111'\";
                 PRAGMA application_id = 1128808784;
                 PRAGMA user_version = 1;
                 PRAGMA foreign_keys = ON;",
            )
            .unwrap();
        connection.execute_batch(CREATE_METADATA).unwrap();
        connection
            .execute(
                "INSERT INTO church_app_database_metadata VALUES
                 (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    1_i64,
                    1_i64,
                    1_i64,
                    PERMANENT_APPLICATION_IDENTIFIER,
                    APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes().as_slice(),
                    [0x11_u8; 16].as_slice(),
                    [0x22_u8; 16].as_slice(),
                    1_u64.to_be_bytes().as_slice(),
                    1_u64.to_be_bytes().as_slice(),
                    [0x33_u8; 16].as_slice(),
                    [0x44_u8; 16].as_slice(),
                    1_800_000_000_000_i64,
                ],
            )
            .unwrap();
        SyntheticSqlcipherV1 {
            connection: Some(connection),
            path,
        }
    }

    fn assert_exact_v1_after_rollback(connection: &Connection) {
        assert!(connection.is_autocommit());
        assert_eq!(
            observe_single_i64(
                connection,
                fixed_metadata_and_header_observation::USER_VERSION_QUERY,
            ),
            Ok(1)
        );
        let metadata = observe_metadata(connection).unwrap();
        assert_eq!(metadata[2], OwnedMetadataValue::Integer(1));
        let business_objects: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name != 'church_app_database_metadata' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(business_objects, 0);
        let classification =
            classify_production_database_restart_state(&ObservedProductionDatabaseRestartState {
                application_id: PRODUCTION_DATABASE_APPLICATION_ID,
                metadata: metadata_raw(&metadata).unwrap(),
                schema: ObservedV2Schema {
                    user_version: 1,
                    metadata_contract_version: 1,
                    metadata_database_schema_version: 1,
                    business_tables: Vec::new(),
                    business_indexes: Vec::new(),
                    triggers: Vec::new(),
                },
            });
        assert_eq!(
            classification,
            ProductionDatabaseRestartClassification::ExactV1
        );
    }

    #[test]
    fn fixed_transaction_contract_has_one_begin_one_commit_and_canonical_ddl_only() {
        let source = include_str!("transactional_v1_to_v2_migration.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert_eq!(production.matches("const BEGIN_IMMEDIATE").count(), 1);
        assert_eq!(production.matches("const COMMIT").count(), 1);
        assert_eq!(
            production
                .matches("for (index, statement) in V2_SCHEMA_DDL.iter().enumerate()")
                .count(),
            1
        );
        assert!(!production.contains("CREATE TABLE service_requests"));
        assert!(!production.contains("CREATE INDEX idx_"));
        assert_eq!(V2_SCHEMA_DDL.len(), 8);
    }

    #[test]
    fn metadata_update_is_fixed_guarded_and_narrow() {
        assert!(METADATA_VERSION_UPDATE.contains("SET database_schema_version = 2"));
        assert!(METADATA_VERSION_UPDATE.contains("singleton_id = 1"));
        assert!(METADATA_VERSION_UPDATE.contains("database_schema_version = 1"));
        for forbidden in [
            "metadata_contract_version =",
            "permanent_application_identifier =",
            "installation_identifier =",
            "recovery_replacement_generation =",
        ] {
            assert!(!METADATA_VERSION_UPDATE.contains(forbidden));
        }
    }

    #[test]
    fn commit_failure_is_always_ambiguous_and_never_rolls_back_or_retries() {
        let source = include_str!("transactional_v1_to_v2_migration.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        let branch = source
            .split_once("if connection.execute_batch(COMMIT).is_err()")
            .unwrap()
            .1
            .split_once("let disposition")
            .unwrap()
            .0;
        assert!(branch.contains("CommitAmbiguous"));
        assert!(!branch.contains("ROLLBACK"));
        assert_eq!(
            production
                .matches(
                    "execute_fixed_transaction(&owner.connection, MigrationFailureInjection::None)"
                )
                .count(),
            1
        );
    }

    #[test]
    fn validation_reuses_canonical_integrity_schema_and_restart_contracts() {
        let source = include_str!("transactional_v1_to_v2_migration.rs");
        for required in [
            "revalidate_connection_identity",
            "run_cipher_integrity_check",
            "run_sqlite_quick_check",
            "validate_production_database_full_integrity_on_borrowed_connection",
            "validate_v2_schema",
            "classify_production_database_restart_state",
            "ProductionDatabaseRestartClassification::ExactV2",
        ] {
            assert!(source.contains(required), "missing {required}");
        }
    }

    #[test]
    fn synthetic_sqlcipher_fixture_commits_exact_v2_and_preserves_metadata() {
        let connection = synthetic_sqlcipher_v1();
        let before = observe_metadata(&connection).unwrap();
        assert!(matches!(
            execute_fixed_transaction(&connection, MigrationFailureInjection::None),
            FixedTransactionOutcome::Committed
        ));
        assert!(connection.is_autocommit());
        let after = observe_metadata(&connection).unwrap();
        assert_eq!(after[2], OwnedMetadataValue::Integer(2));
        for index in 0..after.len() {
            if index != 2 {
                assert_eq!(after[index], before[index]);
            }
        }
        let schema = exact_schema_observation(&connection).unwrap();
        validate_v2_schema(&schema).unwrap();
        validate_business_tables_empty(&connection).unwrap();
        assert_eq!(
            classify_production_database_restart_state(&ObservedProductionDatabaseRestartState {
                application_id: PRODUCTION_DATABASE_APPLICATION_ID,
                metadata: metadata_raw(&after).unwrap(),
                schema,
            }),
            ProductionDatabaseRestartClassification::ExactV2
        );
        run_cipher_integrity_check(&connection).unwrap();
        run_sqlite_quick_check(&connection).unwrap();
    }

    #[test]
    fn first_and_middle_ddl_failures_roll_back_to_exact_v1() {
        for failure in [
            MigrationFailureInjection::Ddl(0),
            MigrationFailureInjection::Ddl(V2_TABLES.len() + 1),
        ] {
            let connection = synthetic_sqlcipher_v1();
            assert!(matches!(
                execute_fixed_transaction(&connection, failure),
                FixedTransactionOutcome::Terminal(
                    WritableV1ToV2MigrationTerminalDisposition::RolledBack(
                        WritableV1ToV2MigrationError::SchemaCreationFailed
                    )
                )
            ));
            assert_exact_v1_after_rollback(&connection);
        }
    }

    #[test]
    fn metadata_and_user_version_failures_roll_back_to_exact_v1() {
        for (failure, expected) in [
            (
                MigrationFailureInjection::Metadata,
                WritableV1ToV2MigrationError::MetadataVersionUpdateFailed,
            ),
            (
                MigrationFailureInjection::UserVersion,
                WritableV1ToV2MigrationError::UserVersionUpdateFailed,
            ),
        ] {
            let connection = synthetic_sqlcipher_v1();
            assert!(matches!(
                execute_fixed_transaction(&connection, failure),
                FixedTransactionOutcome::Terminal(
                    WritableV1ToV2MigrationTerminalDisposition::RolledBack(category)
                ) if category == expected
            ));
            assert_exact_v1_after_rollback(&connection);
        }
    }

    #[test]
    fn commit_failure_seam_is_ambiguous_and_leaves_restart_classification_required() {
        let connection = synthetic_sqlcipher_v1();
        assert!(matches!(
            execute_fixed_transaction(&connection, MigrationFailureInjection::Commit),
            FixedTransactionOutcome::Terminal(
                WritableV1ToV2MigrationTerminalDisposition::CommitAmbiguous
            )
        ));
        assert!(!connection.is_autocommit());
        drop(connection);
    }

    #[test]
    fn post_commit_contract_damage_is_invalid_and_not_reversed() {
        let connection = synthetic_sqlcipher_v1();
        assert!(matches!(
            execute_fixed_transaction(&connection, MigrationFailureInjection::None),
            FixedTransactionOutcome::Committed
        ));
        connection
            .execute_batch("DROP INDEX idx_service_requests_status_created_at_id")
            .unwrap();
        assert!(exact_schema_observation(&connection).is_err());
        assert_eq!(
            observe_single_i64(
                &connection,
                fixed_metadata_and_header_observation::USER_VERSION_QUERY
            ),
            Ok(2)
        );
        assert_eq!(
            observe_metadata(&connection).unwrap()[2],
            OwnedMetadataValue::Integer(2)
        );
    }
}
