//! Pure canonical contract for the approved production database schema V2.
//!
//! This module owns fixed schema material and validates only a database-neutral
//! observation. It opens no database, executes no SQL, and grants no migration,
//! startup, or write authority.

#![cfg_attr(not(test), allow(dead_code))]

pub(crate) const V2_USER_VERSION: u32 = 2;
pub(crate) const V2_METADATA_CONTRACT_VERSION: u16 = 1;
pub(crate) const V2_DATABASE_SCHEMA_VERSION: u16 = 2;

pub(crate) const V2_SCHEMA_DDL: &[&str] = &[
    "CREATE TABLE service_requests (\
        id INTEGER PRIMARY KEY,\
        service_category TEXT NOT NULL CHECK (service_category IN ('baptism', 'confirmation', 'wedding_marriage', 'burial_funeral', 'first_communion')),\
        status TEXT NOT NULL CHECK (status IN ('pending', 'scheduled', 'completed', 'cancelled')),\
        requester_full_name TEXT NOT NULL CHECK (length(requester_full_name) BETWEEN 1 AND 200 AND substr(requester_full_name, 1, 1) <> ' ' AND substr(requester_full_name, -1, 1) <> ' '),\
        requester_phone TEXT NOT NULL CHECK (length(requester_phone) BETWEEN 1 AND 32 AND substr(requester_phone, 1, 1) <> ' ' AND substr(requester_phone, -1, 1) <> ' '),\
        requester_email TEXT CHECK (requester_email IS NULL OR (length(requester_email) BETWEEN 1 AND 254 AND substr(requester_email, 1, 1) <> ' ' AND substr(requester_email, -1, 1) <> ' ')),\
        created_at INTEGER NOT NULL CHECK (created_at >= 0)\
    ) STRICT",
    "CREATE TABLE request_schedule_occurrences (\
        id INTEGER PRIMARY KEY,\
        service_request_id INTEGER NOT NULL REFERENCES service_requests(id) ON UPDATE RESTRICT ON DELETE RESTRICT,\
        occurrence_kind TEXT NOT NULL CHECK (occurrence_kind IN ('primary', 'funeral', 'burial')),\
        scheduled_local_date TEXT NOT NULL CHECK (scheduled_local_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),\
        scheduled_local_time TEXT NOT NULL CHECK (scheduled_local_time GLOB '[0-9][0-9]:[0-9][0-9]' AND substr(scheduled_local_time, 1, 2) BETWEEN '00' AND '23' AND substr(scheduled_local_time, 4, 2) BETWEEN '00' AND '59'),\
        location TEXT CHECK (location IS NULL OR (length(location) BETWEEN 1 AND 256 AND substr(location, 1, 1) <> ' ' AND substr(location, -1, 1) <> ' ')),\
        UNIQUE (service_request_id, occurrence_kind)\
    ) STRICT",
    "CREATE TABLE request_cancellation_reviews (\
        id INTEGER PRIMARY KEY,\
        service_request_id INTEGER NOT NULL REFERENCES service_requests(id) ON UPDATE RESTRICT ON DELETE RESTRICT,\
        disposition TEXT NOT NULL CHECK (disposition IN ('pending', 'approved', 'rejected')),\
        requested_at INTEGER NOT NULL CHECK (requested_at >= 0),\
        resolved_at INTEGER CHECK (resolved_at IS NULL OR resolved_at >= 0),\
        CHECK ((disposition = 'pending' AND resolved_at IS NULL) OR (disposition IN ('approved', 'rejected') AND resolved_at IS NOT NULL))\
    ) STRICT",
    "CREATE INDEX idx_service_requests_status_created_at_id ON service_requests(status, created_at, id)",
    "CREATE INDEX idx_request_schedule_occurrences_schedule ON request_schedule_occurrences(scheduled_local_date, scheduled_local_time, id)",
    "CREATE INDEX idx_request_cancellation_reviews_request_requested ON request_cancellation_reviews(service_request_id, requested_at, id)",
    "CREATE UNIQUE INDEX idx_request_cancellation_reviews_one_pending ON request_cancellation_reviews(service_request_id) WHERE disposition = 'pending'",
    "CREATE INDEX idx_request_cancellation_reviews_pending_requested ON request_cancellation_reviews(requested_at, id) WHERE disposition = 'pending'",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SqliteType {
    Integer,
    Text,
    Real,
    Blob,
    Any,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ColumnContract {
    pub(crate) name: &'static str,
    pub(crate) sqlite_type: SqliteType,
    pub(crate) nullable: bool,
    pub(crate) primary_key_ordinal: Option<u8>,
    pub(crate) has_default: bool,
}

impl ColumnContract {
    const fn required(name: &'static str, sqlite_type: SqliteType) -> Self {
        Self {
            name,
            sqlite_type,
            nullable: false,
            primary_key_ordinal: None,
            has_default: false,
        }
    }

    const fn optional(name: &'static str, sqlite_type: SqliteType) -> Self {
        Self {
            name,
            sqlite_type,
            nullable: true,
            primary_key_ordinal: None,
            has_default: false,
        }
    }

    const fn integer_primary_key() -> Self {
        Self {
            name: "id",
            sqlite_type: SqliteType::Integer,
            nullable: false,
            primary_key_ordinal: Some(1),
            has_default: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CheckConstraint {
    ServiceCategoryCodes,
    RequestStatusCodes,
    RequiredTextBoundsNoEdgeAsciiSpace { column: &'static str, maximum: u16 },
    OptionalTextBoundsNoEdgeAsciiSpace { column: &'static str, maximum: u16 },
    NonNegativeInteger { column: &'static str },
    OccurrenceKindCodes,
    ScheduledLocalDateShape,
    ScheduledLocalTimeShapeAndRange,
    CancellationDispositionCodes,
    ResolvedAtNullabilityByDisposition,
    Unrecognized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForeignKeyAction {
    Restrict,
    NoAction,
    Cascade,
    SetNull,
    SetDefault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ForeignKeyContract {
    pub(crate) columns: &'static [&'static str],
    pub(crate) referenced_table: &'static str,
    pub(crate) referenced_columns: &'static [&'static str],
    pub(crate) on_update: ForeignKeyAction,
    pub(crate) on_delete: ForeignKeyAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UniqueConstraint {
    pub(crate) columns: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TableContract {
    pub(crate) name: &'static str,
    pub(crate) columns: &'static [ColumnContract],
    pub(crate) checks: &'static [CheckConstraint],
    pub(crate) foreign_keys: &'static [ForeignKeyContract],
    pub(crate) unique_constraints: &'static [UniqueConstraint],
    pub(crate) strict: bool,
    pub(crate) without_rowid: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IndexPredicate {
    CancellationDispositionPending,
    Unrecognized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IndexContract {
    pub(crate) name: &'static str,
    pub(crate) table: &'static str,
    pub(crate) columns: &'static [&'static str],
    pub(crate) unique: bool,
    pub(crate) predicate: Option<IndexPredicate>,
}

const SERVICE_REQUEST_COLUMNS: &[ColumnContract] = &[
    ColumnContract::integer_primary_key(),
    ColumnContract::required("service_category", SqliteType::Text),
    ColumnContract::required("status", SqliteType::Text),
    ColumnContract::required("requester_full_name", SqliteType::Text),
    ColumnContract::required("requester_phone", SqliteType::Text),
    ColumnContract::optional("requester_email", SqliteType::Text),
    ColumnContract::required("created_at", SqliteType::Integer),
];

const SERVICE_REQUEST_CHECKS: &[CheckConstraint] = &[
    CheckConstraint::ServiceCategoryCodes,
    CheckConstraint::RequestStatusCodes,
    CheckConstraint::RequiredTextBoundsNoEdgeAsciiSpace {
        column: "requester_full_name",
        maximum: 200,
    },
    CheckConstraint::RequiredTextBoundsNoEdgeAsciiSpace {
        column: "requester_phone",
        maximum: 32,
    },
    CheckConstraint::OptionalTextBoundsNoEdgeAsciiSpace {
        column: "requester_email",
        maximum: 254,
    },
    CheckConstraint::NonNegativeInteger {
        column: "created_at",
    },
];

const OCCURRENCE_COLUMNS: &[ColumnContract] = &[
    ColumnContract::integer_primary_key(),
    ColumnContract::required("service_request_id", SqliteType::Integer),
    ColumnContract::required("occurrence_kind", SqliteType::Text),
    ColumnContract::required("scheduled_local_date", SqliteType::Text),
    ColumnContract::required("scheduled_local_time", SqliteType::Text),
    ColumnContract::optional("location", SqliteType::Text),
];

const OCCURRENCE_CHECKS: &[CheckConstraint] = &[
    CheckConstraint::OccurrenceKindCodes,
    CheckConstraint::ScheduledLocalDateShape,
    CheckConstraint::ScheduledLocalTimeShapeAndRange,
    CheckConstraint::OptionalTextBoundsNoEdgeAsciiSpace {
        column: "location",
        maximum: 256,
    },
];

const SERVICE_REQUEST_FOREIGN_KEY: &[ForeignKeyContract] = &[ForeignKeyContract {
    columns: &["service_request_id"],
    referenced_table: "service_requests",
    referenced_columns: &["id"],
    on_update: ForeignKeyAction::Restrict,
    on_delete: ForeignKeyAction::Restrict,
}];

const OCCURRENCE_UNIQUENESS: &[UniqueConstraint] = &[UniqueConstraint {
    columns: &["service_request_id", "occurrence_kind"],
}];

const CANCELLATION_REVIEW_COLUMNS: &[ColumnContract] = &[
    ColumnContract::integer_primary_key(),
    ColumnContract::required("service_request_id", SqliteType::Integer),
    ColumnContract::required("disposition", SqliteType::Text),
    ColumnContract::required("requested_at", SqliteType::Integer),
    ColumnContract::optional("resolved_at", SqliteType::Integer),
];

const CANCELLATION_REVIEW_CHECKS: &[CheckConstraint] = &[
    CheckConstraint::CancellationDispositionCodes,
    CheckConstraint::NonNegativeInteger {
        column: "requested_at",
    },
    CheckConstraint::NonNegativeInteger {
        column: "resolved_at",
    },
    CheckConstraint::ResolvedAtNullabilityByDisposition,
];

pub(crate) const V2_TABLES: &[TableContract] = &[
    TableContract {
        name: "service_requests",
        columns: SERVICE_REQUEST_COLUMNS,
        checks: SERVICE_REQUEST_CHECKS,
        foreign_keys: &[],
        unique_constraints: &[],
        strict: true,
        without_rowid: false,
    },
    TableContract {
        name: "request_schedule_occurrences",
        columns: OCCURRENCE_COLUMNS,
        checks: OCCURRENCE_CHECKS,
        foreign_keys: SERVICE_REQUEST_FOREIGN_KEY,
        unique_constraints: OCCURRENCE_UNIQUENESS,
        strict: true,
        without_rowid: false,
    },
    TableContract {
        name: "request_cancellation_reviews",
        columns: CANCELLATION_REVIEW_COLUMNS,
        checks: CANCELLATION_REVIEW_CHECKS,
        foreign_keys: SERVICE_REQUEST_FOREIGN_KEY,
        unique_constraints: &[],
        strict: true,
        without_rowid: false,
    },
];

pub(crate) const V2_INDEXES: &[IndexContract] = &[
    IndexContract {
        name: "idx_service_requests_status_created_at_id",
        table: "service_requests",
        columns: &["status", "created_at", "id"],
        unique: false,
        predicate: None,
    },
    IndexContract {
        name: "idx_request_schedule_occurrences_schedule",
        table: "request_schedule_occurrences",
        columns: &["scheduled_local_date", "scheduled_local_time", "id"],
        unique: false,
        predicate: None,
    },
    IndexContract {
        name: "idx_request_cancellation_reviews_request_requested",
        table: "request_cancellation_reviews",
        columns: &["service_request_id", "requested_at", "id"],
        unique: false,
        predicate: None,
    },
    IndexContract {
        name: "idx_request_cancellation_reviews_one_pending",
        table: "request_cancellation_reviews",
        columns: &["service_request_id"],
        unique: true,
        predicate: Some(IndexPredicate::CancellationDispositionPending),
    },
    IndexContract {
        name: "idx_request_cancellation_reviews_pending_requested",
        table: "request_cancellation_reviews",
        columns: &["requested_at", "id"],
        unique: false,
        predicate: Some(IndexPredicate::CancellationDispositionPending),
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedTable {
    pub(crate) name: String,
    pub(crate) columns: Vec<ObservedColumn>,
    pub(crate) checks: Vec<CheckConstraint>,
    pub(crate) foreign_keys: Vec<ObservedForeignKey>,
    pub(crate) unique_constraints: Vec<ObservedUniqueConstraint>,
    pub(crate) strict: bool,
    pub(crate) without_rowid: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedColumn {
    pub(crate) name: String,
    pub(crate) sqlite_type: SqliteType,
    pub(crate) nullable: bool,
    pub(crate) primary_key_ordinal: Option<u8>,
    pub(crate) has_default: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedForeignKey {
    pub(crate) columns: Vec<String>,
    pub(crate) referenced_table: String,
    pub(crate) referenced_columns: Vec<String>,
    pub(crate) on_update: ForeignKeyAction,
    pub(crate) on_delete: ForeignKeyAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedUniqueConstraint {
    pub(crate) columns: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedIndex {
    pub(crate) name: String,
    pub(crate) table: String,
    pub(crate) columns: Vec<String>,
    pub(crate) unique: bool,
    pub(crate) predicate: Option<IndexPredicate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedV2Schema {
    pub(crate) user_version: u32,
    pub(crate) metadata_contract_version: u16,
    pub(crate) metadata_database_schema_version: u16,
    /// Normalized business tables only; the existing metadata relation is
    /// validated by its separate contract.
    pub(crate) business_tables: Vec<ObservedTable>,
    /// Explicit business indexes only; SQLite-owned autoindexes are represented
    /// by the corresponding normalized unique constraints.
    pub(crate) business_indexes: Vec<ObservedIndex>,
    pub(crate) triggers: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum V2SchemaValidationError {
    WrongUserVersion,
    WrongMetadataVersion,
    InvalidSchema,
}

pub(crate) fn validate_v2_schema(
    observed: &ObservedV2Schema,
) -> Result<(), V2SchemaValidationError> {
    if observed.user_version != V2_USER_VERSION {
        return Err(V2SchemaValidationError::WrongUserVersion);
    }
    if observed.metadata_contract_version != V2_METADATA_CONTRACT_VERSION
        || observed.metadata_database_schema_version != V2_DATABASE_SCHEMA_VERSION
    {
        return Err(V2SchemaValidationError::WrongMetadataVersion);
    }
    if !observed.triggers.is_empty()
        || observed.business_tables.len() != V2_TABLES.len()
        || observed.business_indexes.len() != V2_INDEXES.len()
        || !V2_TABLES.iter().all(|expected| {
            observed
                .business_tables
                .iter()
                .any(|actual| table_matches(expected, actual))
        })
        || !V2_INDEXES.iter().all(|expected| {
            observed
                .business_indexes
                .iter()
                .any(|actual| index_matches(expected, actual))
        })
    {
        return Err(V2SchemaValidationError::InvalidSchema);
    }
    Ok(())
}

fn table_matches(expected: &TableContract, actual: &ObservedTable) -> bool {
    actual.name == expected.name
        && actual.columns.len() == expected.columns.len()
        && actual
            .columns
            .iter()
            .zip(expected.columns)
            .all(|(actual, expected)| column_matches(expected, actual))
        && exact_unordered(&actual.checks, expected.checks)
        && actual.foreign_keys.len() == expected.foreign_keys.len()
        && expected.foreign_keys.iter().all(|expected| {
            actual
                .foreign_keys
                .iter()
                .any(|actual| foreign_key_matches(expected, actual))
        })
        && actual.unique_constraints.len() == expected.unique_constraints.len()
        && expected.unique_constraints.iter().all(|expected| {
            actual
                .unique_constraints
                .iter()
                .any(|actual| unique_constraint_matches(expected, actual))
        })
        && actual.strict == expected.strict
        && actual.without_rowid == expected.without_rowid
}

fn column_matches(expected: &ColumnContract, actual: &ObservedColumn) -> bool {
    actual.name == expected.name
        && actual.sqlite_type == expected.sqlite_type
        && actual.nullable == expected.nullable
        && actual.primary_key_ordinal == expected.primary_key_ordinal
        && actual.has_default == expected.has_default
}

fn foreign_key_matches(expected: &ForeignKeyContract, actual: &ObservedForeignKey) -> bool {
    strings_match(&actual.columns, expected.columns)
        && actual.referenced_table == expected.referenced_table
        && strings_match(&actual.referenced_columns, expected.referenced_columns)
        && actual.on_update == expected.on_update
        && actual.on_delete == expected.on_delete
}

fn unique_constraint_matches(
    expected: &UniqueConstraint,
    actual: &ObservedUniqueConstraint,
) -> bool {
    strings_match(&actual.columns, expected.columns)
}

fn index_matches(expected: &IndexContract, actual: &ObservedIndex) -> bool {
    actual.name == expected.name
        && actual.table == expected.table
        && strings_match(&actual.columns, expected.columns)
        && actual.unique == expected.unique
        && actual.predicate == expected.predicate
}

fn strings_match(actual: &[String], expected: &[&str]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected)
}

fn exact_unordered<T: Eq>(actual: &[T], expected: &[T]) -> bool {
    actual.len() == expected.len()
        && expected.iter().all(|expected_item| {
            actual
                .iter()
                .filter(|actual_item| *actual_item == expected_item)
                .count()
                == expected
                    .iter()
                    .filter(|other| *other == expected_item)
                    .count()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_observation() -> ObservedV2Schema {
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

    fn table_mut<'a>(observation: &'a mut ObservedV2Schema, name: &str) -> &'a mut ObservedTable {
        observation
            .business_tables
            .iter_mut()
            .find(|table| table.name == name)
            .expect("canonical table should exist")
    }

    fn assert_invalid(observation: ObservedV2Schema) {
        assert_eq!(
            validate_v2_schema(&observation),
            Err(V2SchemaValidationError::InvalidSchema)
        );
    }

    #[test]
    fn exact_approved_v2_schema_validates() {
        assert_eq!(validate_v2_schema(&canonical_observation()), Ok(()));
    }

    #[test]
    fn contract_has_exactly_the_three_approved_strict_rowid_tables() {
        assert_eq!(
            V2_TABLES.iter().map(|table| table.name).collect::<Vec<_>>(),
            [
                "service_requests",
                "request_schedule_occurrences",
                "request_cancellation_reviews"
            ]
        );
        assert!(V2_TABLES.iter().all(|table| table.strict));
        assert!(V2_TABLES.iter().all(|table| !table.without_rowid));
        assert!(V2_TABLES.iter().all(|table| {
            table.columns.first() == Some(&ColumnContract::integer_primary_key())
                && table
                    .columns
                    .iter()
                    .filter(|column| column.primary_key_ordinal.is_some())
                    .count()
                    == 1
        }));
    }

    #[test]
    fn exact_persisted_code_sets_are_canonical_checks() {
        assert!(SERVICE_REQUEST_CHECKS.contains(&CheckConstraint::ServiceCategoryCodes));
        assert!(SERVICE_REQUEST_CHECKS.contains(&CheckConstraint::RequestStatusCodes));
        assert!(OCCURRENCE_CHECKS.contains(&CheckConstraint::OccurrenceKindCodes));
        assert!(
            CANCELLATION_REVIEW_CHECKS.contains(&CheckConstraint::CancellationDispositionCodes)
        );
        let ddl = V2_SCHEMA_DDL.join("\n");
        for exact_codes in [
            "'baptism', 'confirmation', 'wedding_marriage', 'burial_funeral', 'first_communion'",
            "'pending', 'scheduled', 'completed', 'cancelled'",
            "'primary', 'funeral', 'burial'",
            "'pending', 'approved', 'rejected'",
        ] {
            assert!(ddl.contains(exact_codes));
        }
    }

    #[test]
    fn exact_foreign_keys_and_uniqueness_are_present() {
        for table_name in [
            "request_schedule_occurrences",
            "request_cancellation_reviews",
        ] {
            assert_eq!(
                V2_TABLES
                    .iter()
                    .find(|table| table.name == table_name)
                    .unwrap()
                    .foreign_keys,
                SERVICE_REQUEST_FOREIGN_KEY
            );
        }
        assert_eq!(V2_TABLES[1].unique_constraints, OCCURRENCE_UNIQUENESS);
        assert!(V2_INDEXES.iter().any(|index| {
            index.unique
                && index.columns == ["service_request_id"]
                && index.predicate == Some(IndexPredicate::CancellationDispositionPending)
        }));
    }

    #[test]
    fn exact_nullability_bounds_and_timestamp_checks_are_present() {
        let service = &V2_TABLES[0];
        assert!(!service.columns[3].nullable);
        assert!(!service.columns[4].nullable);
        assert!(service.columns[5].nullable);
        assert!(V2_TABLES[1].columns[5].nullable);
        for check in [
            CheckConstraint::RequiredTextBoundsNoEdgeAsciiSpace {
                column: "requester_full_name",
                maximum: 200,
            },
            CheckConstraint::RequiredTextBoundsNoEdgeAsciiSpace {
                column: "requester_phone",
                maximum: 32,
            },
            CheckConstraint::OptionalTextBoundsNoEdgeAsciiSpace {
                column: "requester_email",
                maximum: 254,
            },
        ] {
            assert!(service.checks.contains(&check));
        }
        assert!(V2_TABLES[1].checks.contains(
            &CheckConstraint::OptionalTextBoundsNoEdgeAsciiSpace {
                column: "location",
                maximum: 256,
            }
        ));
        assert!(
            CANCELLATION_REVIEW_CHECKS
                .contains(&CheckConstraint::ResolvedAtNullabilityByDisposition)
        );
    }

    #[test]
    fn exact_required_indexes_and_partial_rules_are_canonical() {
        assert_eq!(V2_INDEXES.len(), 5);
        assert_eq!(
            V2_INDEXES
                .iter()
                .filter(|index| index.predicate.is_some())
                .count(),
            2
        );
        assert_eq!(V2_INDEXES.iter().filter(|index| index.unique).count(), 1);
    }

    #[test]
    fn missing_or_unexpected_table_rejects() {
        let mut missing = canonical_observation();
        missing.business_tables.pop();
        assert_invalid(missing);

        let mut extra = canonical_observation();
        extra.business_tables.push(ObservedTable {
            name: "request_history".to_owned(),
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
        assert_invalid(extra);
    }

    #[test]
    fn wrong_column_type_nullability_or_primary_key_rejects() {
        let mut wrong_column = canonical_observation();
        table_mut(&mut wrong_column, "service_requests").columns[1].name =
            "service_type".to_owned();
        assert_invalid(wrong_column);

        let mut wrong_type = canonical_observation();
        table_mut(&mut wrong_type, "service_requests").columns[1].sqlite_type = SqliteType::Integer;
        assert_invalid(wrong_type);

        let mut wrong_nullability = canonical_observation();
        table_mut(&mut wrong_nullability, "service_requests").columns[5].nullable = false;
        assert_invalid(wrong_nullability);

        let mut wrong_primary_key = canonical_observation();
        table_mut(&mut wrong_primary_key, "service_requests").columns[0].primary_key_ordinal = None;
        assert_invalid(wrong_primary_key);
    }

    #[test]
    fn every_noncanonical_strict_type_rejects() {
        for sqlite_type in [SqliteType::Real, SqliteType::Blob, SqliteType::Any] {
            let mut observation = canonical_observation();
            table_mut(&mut observation, "service_requests").columns[1].sqlite_type = sqlite_type;
            assert_invalid(observation);
        }
    }

    #[test]
    fn wrong_or_missing_foreign_key_rejects() {
        let mut missing = canonical_observation();
        table_mut(&mut missing, "request_schedule_occurrences")
            .foreign_keys
            .clear();
        assert_invalid(missing);

        let mut wrong = canonical_observation();
        table_mut(&mut wrong, "request_cancellation_reviews").foreign_keys[0].referenced_table =
            "request_schedule_occurrences".to_owned();
        assert_invalid(wrong);

        for action in [
            ForeignKeyAction::NoAction,
            ForeignKeyAction::Cascade,
            ForeignKeyAction::SetNull,
            ForeignKeyAction::SetDefault,
        ] {
            let mut wrong_action = canonical_observation();
            table_mut(&mut wrong_action, "request_schedule_occurrences").foreign_keys[0]
                .on_delete = action;
            assert_invalid(wrong_action);
        }
    }

    #[test]
    fn wrong_missing_or_unexpected_check_rejects() {
        let mut missing = canonical_observation();
        table_mut(&mut missing, "service_requests").checks.pop();
        assert_invalid(missing);

        let mut wrong = canonical_observation();
        table_mut(&mut wrong, "service_requests").checks[0] = CheckConstraint::OccurrenceKindCodes;
        assert_invalid(wrong);

        let mut extra = canonical_observation();
        table_mut(&mut extra, "service_requests")
            .checks
            .push(CheckConstraint::OccurrenceKindCodes);
        assert_invalid(extra);

        let mut unrecognized = canonical_observation();
        table_mut(&mut unrecognized, "service_requests").checks[0] = CheckConstraint::Unrecognized;
        assert_invalid(unrecognized);
    }

    #[test]
    fn wrong_missing_or_speculative_index_rejects() {
        let mut missing = canonical_observation();
        missing.business_indexes.pop();
        assert_invalid(missing);

        let mut wrong = canonical_observation();
        wrong.business_indexes[0].columns.swap(0, 1);
        assert_invalid(wrong);

        let mut extra = canonical_observation();
        extra.business_indexes.push(ObservedIndex {
            name: "idx_speculative_email".to_owned(),
            table: "service_requests".to_owned(),
            columns: vec!["requester_email".to_owned()],
            unique: false,
            predicate: None,
        });
        assert_invalid(extra);

        let mut unrecognized_predicate = canonical_observation();
        unrecognized_predicate.business_indexes[0].predicate = Some(IndexPredicate::Unrecognized);
        assert_invalid(unrecognized_predicate);
    }

    #[test]
    fn non_strict_without_rowid_or_trigger_rejects() {
        let mut non_strict = canonical_observation();
        table_mut(&mut non_strict, "service_requests").strict = false;
        assert_invalid(non_strict);

        let mut without_rowid = canonical_observation();
        table_mut(&mut without_rowid, "request_schedule_occurrences").without_rowid = true;
        assert_invalid(without_rowid);

        let mut trigger = canonical_observation();
        trigger.triggers.push("request_audit".to_owned());
        assert_invalid(trigger);
    }

    #[test]
    fn wrong_user_or_metadata_versions_reject() {
        let mut user = canonical_observation();
        user.user_version = 1;
        assert_eq!(
            validate_v2_schema(&user),
            Err(V2SchemaValidationError::WrongUserVersion)
        );

        let mut schema = canonical_observation();
        schema.metadata_database_schema_version = 1;
        assert_eq!(
            validate_v2_schema(&schema),
            Err(V2SchemaValidationError::WrongMetadataVersion)
        );

        let mut contract = canonical_observation();
        contract.metadata_contract_version = 2;
        assert_eq!(
            validate_v2_schema(&contract),
            Err(V2SchemaValidationError::WrongMetadataVersion)
        );
        assert_eq!(V2_METADATA_CONTRACT_VERSION, 1);
    }

    #[test]
    fn fixed_ddl_is_contract_material_only() {
        assert_eq!(V2_SCHEMA_DDL.len(), 8);
        let production_source = include_str!("database_schema_v2_contract.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "rusqlite",
            "execute_batch",
            "BEGIN IMMEDIATE",
            "ApplicationLifecycle",
            "std::fs",
            "tauri::command",
        ] {
            assert!(!production_source.contains(forbidden));
        }
    }
}
