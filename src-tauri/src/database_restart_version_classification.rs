//! Pure restart-time classification of database-neutral production observations.
//!
//! This module opens no database, executes no SQL, mutates no storage, and
//! grants no startup, migration, downgrade, or lifecycle authority.

#![cfg_attr(not(test), allow(dead_code))]

use crate::{
    database_metadata_decoding::RawDatabaseMetadataRow,
    database_schema_v2_contract::{ObservedV2Schema, validate_v2_schema},
    production_database_connection_handoff::PRODUCTION_DATABASE_APPLICATION_ID,
};

const CURRENT_METADATA_CONTRACT_VERSION: u16 = 1;
const CURRENT_DATABASE_SCHEMA_VERSION: u16 = 2;
const V1_DATABASE_SCHEMA_VERSION: u16 = 1;

pub(crate) struct ObservedProductionDatabaseRestartState<'a> {
    pub(crate) application_id: i32,
    pub(crate) metadata: RawDatabaseMetadataRow<'a>,
    pub(crate) schema: ObservedV2Schema,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionDatabaseRestartClassification {
    ExactV1,
    ExactV2,
    Inconsistent,
    UnsupportedNewer,
}

pub(crate) fn classify_production_database_restart_state(
    observed: &ObservedProductionDatabaseRestartState<'_>,
) -> ProductionDatabaseRestartClassification {
    if observed.application_id != PRODUCTION_DATABASE_APPLICATION_ID {
        return ProductionDatabaseRestartClassification::Inconsistent;
    }

    let Ok((metadata_contract_version, metadata_database_schema_version)) =
        observed.metadata.observed_versions()
    else {
        return ProductionDatabaseRestartClassification::Inconsistent;
    };

    if metadata_contract_version > CURRENT_METADATA_CONTRACT_VERSION
        || metadata_database_schema_version > CURRENT_DATABASE_SCHEMA_VERSION
        || observed.schema.user_version > u32::from(CURRENT_DATABASE_SCHEMA_VERSION)
    {
        return ProductionDatabaseRestartClassification::UnsupportedNewer;
    }

    if observed.schema.metadata_contract_version != metadata_contract_version
        || observed.schema.metadata_database_schema_version != metadata_database_schema_version
    {
        return ProductionDatabaseRestartClassification::Inconsistent;
    }

    let Ok(parsed_metadata) = observed.metadata.parse() else {
        return ProductionDatabaseRestartClassification::Inconsistent;
    };

    if observed.schema.user_version == u32::from(V1_DATABASE_SCHEMA_VERSION)
        && metadata_contract_version == CURRENT_METADATA_CONTRACT_VERSION
        && metadata_database_schema_version == V1_DATABASE_SCHEMA_VERSION
        && parsed_metadata.validate_structure().is_ok()
        && observed.schema.business_tables.is_empty()
        && observed.schema.business_indexes.is_empty()
        && observed.schema.triggers.is_empty()
    {
        return ProductionDatabaseRestartClassification::ExactV1;
    }

    if parsed_metadata
        .validate_restart_structure(CURRENT_DATABASE_SCHEMA_VERSION)
        .is_ok()
        && validate_v2_schema(&observed.schema).is_ok()
    {
        return ProductionDatabaseRestartClassification::ExactV2;
    }

    ProductionDatabaseRestartClassification::Inconsistent
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database_metadata_decoding::RawDatabaseMetadataValue,
        database_schema_v2_contract::{
            ObservedColumn, ObservedForeignKey, ObservedIndex, ObservedTable,
            ObservedUniqueConstraint, SqliteType, V2_DATABASE_SCHEMA_VERSION, V2_INDEXES,
            V2_METADATA_CONTRACT_VERSION, V2_TABLES, V2_USER_VERSION,
        },
        installation_evidence_contract::PERMANENT_APPLICATION_IDENTIFIER,
        storage_foundation::APPLICATION_DATABASE_FORMAT_IDENTITY,
    };

    const PARISH_IDENTIFIER: [u8; 16] = [0x11; 16];
    const INSTALLATION_IDENTIFIER: [u8; 16] = [0x22; 16];
    const DATABASE_KEY_GENERATION_IDENTIFIER: [u8; 16] = [0x33; 16];
    const SETUP_PUBLICATION_IDENTIFIER: [u8; 16] = [0x44; 16];
    const INSTALLATION_GENERATION: [u8; 8] = 1_u64.to_be_bytes();
    const RECOVERY_REPLACEMENT_GENERATION: [u8; 8] = 1_u64.to_be_bytes();
    const WRONG_DATABASE_FORMAT_IDENTITY: [u8; 16] = [0x99; 16];

    fn metadata(
        metadata_contract_version: i64,
        database_schema_version: i64,
    ) -> RawDatabaseMetadataRow<'static> {
        metadata_with_identities(
            metadata_contract_version,
            database_schema_version,
            PERMANENT_APPLICATION_IDENTIFIER,
            APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
        )
    }

    fn metadata_with_identities(
        metadata_contract_version: i64,
        database_schema_version: i64,
        application_identifier: &'static str,
        database_format_identity: &'static [u8],
    ) -> RawDatabaseMetadataRow<'static> {
        RawDatabaseMetadataRow::new(
            RawDatabaseMetadataValue::Integer(1),
            RawDatabaseMetadataValue::Integer(metadata_contract_version),
            RawDatabaseMetadataValue::Integer(database_schema_version),
            RawDatabaseMetadataValue::Text(application_identifier),
            RawDatabaseMetadataValue::Blob(database_format_identity),
            RawDatabaseMetadataValue::Blob(&PARISH_IDENTIFIER),
            RawDatabaseMetadataValue::Blob(&INSTALLATION_IDENTIFIER),
            RawDatabaseMetadataValue::Blob(&INSTALLATION_GENERATION),
            RawDatabaseMetadataValue::Blob(&RECOVERY_REPLACEMENT_GENERATION),
            RawDatabaseMetadataValue::Blob(&DATABASE_KEY_GENERATION_IDENTIFIER),
            RawDatabaseMetadataValue::Blob(&SETUP_PUBLICATION_IDENTIFIER),
            RawDatabaseMetadataValue::Integer(1_800_000_000_000),
        )
    }

    fn canonical_v2_schema() -> ObservedV2Schema {
        ObservedV2Schema {
            user_version: V2_USER_VERSION,
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
        }
    }

    fn exact_v1() -> ObservedProductionDatabaseRestartState<'static> {
        ObservedProductionDatabaseRestartState {
            application_id: PRODUCTION_DATABASE_APPLICATION_ID,
            metadata: metadata(1, 1),
            schema: ObservedV2Schema {
                user_version: 1,
                metadata_contract_version: 1,
                metadata_database_schema_version: 1,
                business_tables: Vec::new(),
                business_indexes: Vec::new(),
                triggers: Vec::new(),
            },
        }
    }

    fn exact_v2() -> ObservedProductionDatabaseRestartState<'static> {
        ObservedProductionDatabaseRestartState {
            application_id: PRODUCTION_DATABASE_APPLICATION_ID,
            metadata: metadata(1, 2),
            schema: canonical_v2_schema(),
        }
    }

    fn assert_classification(
        observed: &ObservedProductionDatabaseRestartState<'_>,
        expected: ProductionDatabaseRestartClassification,
    ) {
        assert_eq!(
            classify_production_database_restart_state(observed),
            expected
        );
    }

    #[test]
    fn exact_canonical_versions_classify_exactly() {
        assert_classification(
            &exact_v1(),
            ProductionDatabaseRestartClassification::ExactV1,
        );
        assert_classification(
            &exact_v2(),
            ProductionDatabaseRestartClassification::ExactV2,
        );
    }

    #[test]
    fn mismatched_version_signals_are_inconsistent() {
        let mut v1_user_v2_metadata = exact_v2();
        v1_user_v2_metadata.schema.user_version = 1;
        assert_classification(
            &v1_user_v2_metadata,
            ProductionDatabaseRestartClassification::Inconsistent,
        );

        let mut v2_user_v1_metadata = exact_v1();
        v2_user_v1_metadata.schema.user_version = 2;
        assert_classification(
            &v2_user_v1_metadata,
            ProductionDatabaseRestartClassification::Inconsistent,
        );

        let mut duplicate_version_observation_disagrees = exact_v2();
        duplicate_version_observation_disagrees
            .schema
            .metadata_database_schema_version = 1;
        assert_classification(
            &duplicate_version_observation_disagrees,
            ProductionDatabaseRestartClassification::Inconsistent,
        );
    }

    #[test]
    fn interrupted_v2_physical_and_version_combinations_are_inconsistent() {
        let mut incomplete_v2 = exact_v2();
        incomplete_v2.schema.business_tables.pop();
        assert_classification(
            &incomplete_v2,
            ProductionDatabaseRestartClassification::Inconsistent,
        );

        let mut v2_schema_with_v1_versions = exact_v2();
        v2_schema_with_v1_versions.metadata = metadata(1, 1);
        v2_schema_with_v1_versions.schema.user_version = 1;
        v2_schema_with_v1_versions
            .schema
            .metadata_database_schema_version = 1;
        assert_classification(
            &v2_schema_with_v1_versions,
            ProductionDatabaseRestartClassification::Inconsistent,
        );

        let mut v1_physical_with_v2_versions = exact_v2();
        v1_physical_with_v2_versions.schema.business_tables.clear();
        v1_physical_with_v2_versions.schema.business_indexes.clear();
        assert_classification(
            &v1_physical_with_v2_versions,
            ProductionDatabaseRestartClassification::Inconsistent,
        );
    }

    #[test]
    fn malformed_metadata_never_becomes_exact_v2() {
        let mut observed = exact_v2();
        observed.metadata = RawDatabaseMetadataRow::new(
            RawDatabaseMetadataValue::Integer(2),
            RawDatabaseMetadataValue::Integer(1),
            RawDatabaseMetadataValue::Integer(2),
            RawDatabaseMetadataValue::Text(PERMANENT_APPLICATION_IDENTIFIER),
            RawDatabaseMetadataValue::Blob(APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes()),
            RawDatabaseMetadataValue::Blob(&PARISH_IDENTIFIER),
            RawDatabaseMetadataValue::Blob(&INSTALLATION_IDENTIFIER),
            RawDatabaseMetadataValue::Blob(&INSTALLATION_GENERATION),
            RawDatabaseMetadataValue::Blob(&RECOVERY_REPLACEMENT_GENERATION),
            RawDatabaseMetadataValue::Blob(&DATABASE_KEY_GENERATION_IDENTIFIER),
            RawDatabaseMetadataValue::Blob(&SETUP_PUBLICATION_IDENTIFIER),
            RawDatabaseMetadataValue::Integer(1_800_000_000_000),
        );
        assert_classification(
            &observed,
            ProductionDatabaseRestartClassification::Inconsistent,
        );
    }

    #[test]
    fn unexpected_v2_table_missing_index_and_non_strict_table_are_inconsistent() {
        let mut extra_table = exact_v2();
        extra_table.schema.business_tables.push(ObservedTable {
            name: "unauthorized_business_table".to_owned(),
            columns: vec![ObservedColumn {
                name: "id".to_owned(),
                sqlite_type: SqliteType::Integer,
                nullable: false,
                primary_key_ordinal: Some(1),
                has_default: false,
            }],
            checks: Vec::new(),
            foreign_keys: Vec::new(),
            unique_constraints: Vec::new(),
            strict: true,
            without_rowid: false,
        });
        assert_classification(
            &extra_table,
            ProductionDatabaseRestartClassification::Inconsistent,
        );

        let mut missing_index = exact_v2();
        missing_index.schema.business_indexes.pop();
        assert_classification(
            &missing_index,
            ProductionDatabaseRestartClassification::Inconsistent,
        );

        let mut non_strict = exact_v2();
        non_strict.schema.business_tables[0].strict = false;
        assert_classification(
            &non_strict,
            ProductionDatabaseRestartClassification::Inconsistent,
        );
    }

    #[test]
    fn wrong_application_and_database_format_identities_are_inconsistent() {
        let mut wrong_header_identity = exact_v2();
        wrong_header_identity.application_id = 0;
        assert_classification(
            &wrong_header_identity,
            ProductionDatabaseRestartClassification::Inconsistent,
        );

        let mut wrong_metadata_application_identity = exact_v2();
        wrong_metadata_application_identity.metadata = metadata_with_identities(
            1,
            2,
            "not-the-church-app",
            APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
        );
        assert_classification(
            &wrong_metadata_application_identity,
            ProductionDatabaseRestartClassification::Inconsistent,
        );

        let mut wrong_database_format_identity = exact_v2();
        wrong_database_format_identity.metadata = metadata_with_identities(
            1,
            2,
            PERMANENT_APPLICATION_IDENTIFIER,
            &WRONG_DATABASE_FORMAT_IDENTITY,
        );
        assert_classification(
            &wrong_database_format_identity,
            ProductionDatabaseRestartClassification::Inconsistent,
        );
    }

    #[test]
    fn unsupported_newer_versions_are_distinct_and_never_downgrade() {
        let mut newer_metadata_contract = exact_v2();
        newer_metadata_contract.metadata = metadata(2, 2);
        assert_classification(
            &newer_metadata_contract,
            ProductionDatabaseRestartClassification::UnsupportedNewer,
        );

        let mut newer_schema = exact_v2();
        newer_schema.metadata = metadata(1, 3);
        newer_schema.schema.metadata_database_schema_version = 3;
        assert_classification(
            &newer_schema,
            ProductionDatabaseRestartClassification::UnsupportedNewer,
        );

        let mut newer_user_version = exact_v2();
        newer_user_version.schema.user_version = 3;
        assert_classification(
            &newer_user_version,
            ProductionDatabaseRestartClassification::UnsupportedNewer,
        );
    }

    #[test]
    fn classification_output_is_coarse_and_non_sensitive() {
        for (classification, expected) in [
            (ProductionDatabaseRestartClassification::ExactV1, "ExactV1"),
            (ProductionDatabaseRestartClassification::ExactV2, "ExactV2"),
            (
                ProductionDatabaseRestartClassification::Inconsistent,
                "Inconsistent",
            ),
            (
                ProductionDatabaseRestartClassification::UnsupportedNewer,
                "UnsupportedNewer",
            ),
        ] {
            let debug = format!("{classification:?}");
            assert_eq!(debug, expected);
            for forbidden in ["path", "key", "schema", "table", "SQL", "identifier"] {
                assert!(
                    !debug
                        .to_ascii_lowercase()
                        .contains(&forbidden.to_ascii_lowercase())
                );
            }
        }
    }
}
