//! Consuming live SQLite-header and database-metadata validation over the
//! readability-and-integrity-validated production connection owner.

use std::fmt;

use rusqlite::{Connection, Statement, types::ValueRef};

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    database_metadata_decoding::{
        MetadataValidationError, RawDatabaseMetadataRow, RawDatabaseMetadataValue,
    },
};

use super::{
    ConnectionLifetimeOwner, ProductionDatabaseConnectionCloseOutcome,
    ReadabilityAndIntegrityValidatedProductionDatabaseConnection, close_lifetime_owner_using,
};

mod database_evidence_correspondence_validation;

pub(crate) use database_evidence_correspondence_validation::{
    DatabaseEvidenceCorrespondenceMismatch,
    DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection,
    DatabaseEvidenceCorrespondenceValidationCloseFailure,
    DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome,
    DatabaseEvidenceCorrespondenceValidationOutcome,
    validate_production_database_evidence_correspondence,
};

const EXPECTED_APPLICATION_ID: i32 = 0x4348_4150;
const APPLICATION_ID_QUERY: &str = "PRAGMA main.application_id";
const USER_VERSION_QUERY: &str = "PRAGMA main.user_version";
const METADATA_QUERY: &str = "SELECT
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
FROM main.church_app_database_metadata
LIMIT 2";
const METADATA_COLUMN_COUNT: usize = 12;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum LiveMetadataAndHeaderValidationError {
    HeaderObservationUnavailable,
    WrongApplicationId,
    MetadataObservationUnavailable,
    MetadataObservationInterruptedOrIncomplete,
    MetadataRowMissing,
    DuplicateMetadataRows,
    MalformedMetadata,
    UnsupportedMetadataContractVersion,
    UnsupportedDatabaseSchemaVersion,
    UserVersionMismatch,
}

impl fmt::Debug for LiveMetadataAndHeaderValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HeaderObservationUnavailable => "HeaderObservationUnavailable",
            Self::WrongApplicationId => "WrongApplicationId",
            Self::MetadataObservationUnavailable => "MetadataObservationUnavailable",
            Self::MetadataObservationInterruptedOrIncomplete => {
                "MetadataObservationInterruptedOrIncomplete"
            }
            Self::MetadataRowMissing => "MetadataRowMissing",
            Self::DuplicateMetadataRows => "DuplicateMetadataRows",
            Self::MalformedMetadata => "MalformedMetadata",
            Self::UnsupportedMetadataContractVersion => "UnsupportedMetadataContractVersion",
            Self::UnsupportedDatabaseSchemaVersion => "UnsupportedDatabaseSchemaVersion",
            Self::UserVersionMismatch => "UserVersionMismatch",
        })
    }
}

/// Opaque owner proving only the fixed live header and metadata observations.
pub(crate) struct LiveMetadataAndHeaderValidatedProductionDatabaseConnection {
    owner: ConnectionLifetimeOwner,
    metadata_contract: DatabaseMetadataContractV1,
}

impl fmt::Debug for LiveMetadataAndHeaderValidatedProductionDatabaseConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("LiveMetadataAndHeaderValidatedProductionDatabaseConnection([REDACTED])")
    }
}

#[must_use = "the live metadata and header validation outcome must be handled"]
pub(crate) enum LiveMetadataAndHeaderValidationOutcome {
    Validated(LiveMetadataAndHeaderValidatedProductionDatabaseConnection),
    Failed(LiveMetadataAndHeaderValidationError),
    CloseFailed(LiveMetadataAndHeaderValidationCloseFailure),
}

impl fmt::Debug for LiveMetadataAndHeaderValidationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validated(_) => formatter.write_str("Validated([REDACTED])"),
            Self::Failed(category) => formatter.debug_tuple("Failed").field(category).finish(),
            Self::CloseFailed(_) => formatter.write_str("CloseFailed([REDACTED])"),
        }
    }
}

pub(crate) struct LiveMetadataAndHeaderValidationCloseFailure {
    category: LiveMetadataAndHeaderValidationError,
    owner: ConnectionLifetimeOwner,
}

impl fmt::Debug for LiveMetadataAndHeaderValidationCloseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveMetadataAndHeaderValidationCloseFailure([REDACTED])")
    }
}

#[must_use = "a live metadata and header validation close retry outcome must be handled"]
pub(crate) enum LiveMetadataAndHeaderValidationCloseRetryOutcome {
    Closed(LiveMetadataAndHeaderValidationError),
    Failed(LiveMetadataAndHeaderValidationCloseFailure),
}

impl fmt::Debug for LiveMetadataAndHeaderValidationCloseRetryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(category) => formatter.debug_tuple("Closed").field(category).finish(),
            Self::Failed(_) => formatter.write_str("Failed([REDACTED])"),
        }
    }
}

impl LiveMetadataAndHeaderValidationCloseFailure {
    /// Consumes the retained lifetime unit and retries only explicit close.
    pub(crate) fn retry_close(self) -> LiveMetadataAndHeaderValidationCloseRetryOutcome {
        retry_validation_close_using(self, |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        })
    }
}

impl LiveMetadataAndHeaderValidatedProductionDatabaseConnection {
    /// Discards the validated metadata contract, then explicitly closes the
    /// unchanged connection/guard/inspection lifetime unit.
    pub(crate) fn close(self) -> ProductionDatabaseConnectionCloseOutcome {
        let Self {
            owner,
            metadata_contract,
        } = self;
        close_validated_owner_using(owner, metadata_contract, |connection| {
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
        let Self {
            owner,
            metadata_contract,
        } = self;
        close_validated_owner_using(owner, metadata_contract, close)
    }
}

fn close_validated_owner_using<T>(
    owner: ConnectionLifetimeOwner,
    metadata_contract: T,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> ProductionDatabaseConnectionCloseOutcome {
    drop(metadata_contract);
    close_lifetime_owner_using(owner, close)
}

/// Consumes the predecessor owner and runs only the two fixed header reads and
/// one fixed metadata observation on its same privately retained connection.
pub(crate) fn validate_production_database_live_metadata_and_headers(
    connection: ReadabilityAndIntegrityValidatedProductionDatabaseConnection,
) -> LiveMetadataAndHeaderValidationOutcome {
    finish_validation_using(
        connection,
        validate_fixed_live_metadata_and_headers,
        |connection| {
            connection
                .close()
                .map_err(|(returned_connection, _)| returned_connection)
        },
    )
}

fn finish_validation_using(
    connection: ReadabilityAndIntegrityValidatedProductionDatabaseConnection,
    validate: impl FnOnce(
        &Connection,
    )
        -> Result<DatabaseMetadataContractV1, LiveMetadataAndHeaderValidationError>,
    close_on_failure: impl FnOnce(Connection) -> Result<(), Connection>,
) -> LiveMetadataAndHeaderValidationOutcome {
    let owner = connection.owner;
    match validate(&owner.connection) {
        Ok(metadata_contract) => LiveMetadataAndHeaderValidationOutcome::Validated(
            LiveMetadataAndHeaderValidatedProductionDatabaseConnection {
                owner,
                metadata_contract,
            },
        ),
        Err(category) => match close_lifetime_owner_using(owner, close_on_failure) {
            ProductionDatabaseConnectionCloseOutcome::Closed => {
                LiveMetadataAndHeaderValidationOutcome::Failed(category)
            }
            ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
                LiveMetadataAndHeaderValidationOutcome::CloseFailed(
                    LiveMetadataAndHeaderValidationCloseFailure {
                        category,
                        owner: failure.owner,
                    },
                )
            }
        },
    }
}

fn retry_validation_close_using(
    failure: LiveMetadataAndHeaderValidationCloseFailure,
    close: impl FnOnce(Connection) -> Result<(), Connection>,
) -> LiveMetadataAndHeaderValidationCloseRetryOutcome {
    let LiveMetadataAndHeaderValidationCloseFailure { category, owner } = failure;
    match close_lifetime_owner_using(owner, close) {
        ProductionDatabaseConnectionCloseOutcome::Closed => {
            LiveMetadataAndHeaderValidationCloseRetryOutcome::Closed(category)
        }
        ProductionDatabaseConnectionCloseOutcome::Failed(failure) => {
            LiveMetadataAndHeaderValidationCloseRetryOutcome::Failed(
                LiveMetadataAndHeaderValidationCloseFailure {
                    category,
                    owner: failure.owner,
                },
            )
        }
    }
}

fn validate_fixed_live_metadata_and_headers(
    connection: &Connection,
) -> Result<DatabaseMetadataContractV1, LiveMetadataAndHeaderValidationError> {
    let application_id = observe_application_id(connection)?;
    if application_id != EXPECTED_APPLICATION_ID {
        return Err(LiveMetadataAndHeaderValidationError::WrongApplicationId);
    }

    let user_version = observe_user_version(connection)?;
    let metadata_contract = observe_and_validate_metadata(connection)?;
    if i64::from(user_version) != i64::from(metadata_contract.database_schema_version().get()) {
        return Err(LiveMetadataAndHeaderValidationError::UserVersionMismatch);
    }
    Ok(metadata_contract)
}

fn observe_application_id(
    connection: &Connection,
) -> Result<i32, LiveMetadataAndHeaderValidationError> {
    let mut statement = classify_header_operation(connection.prepare(APPLICATION_ID_QUERY))?;
    observe_single_integer_header(&mut statement)
}

fn observe_user_version(
    connection: &Connection,
) -> Result<i32, LiveMetadataAndHeaderValidationError> {
    let mut statement = classify_header_operation(connection.prepare(USER_VERSION_QUERY))?;
    observe_single_integer_header(&mut statement)
}

fn classify_header_operation<T, E>(
    result: Result<T, E>,
) -> Result<T, LiveMetadataAndHeaderValidationError> {
    result.map_err(|_| LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable)
}

enum ObservedHeaderValue {
    Integer(i64),
    Other,
}

fn complete_header_observation(
    first: Result<Option<ObservedHeaderValue>, ()>,
    terminal_step: impl FnOnce() -> Result<bool, ()>,
) -> Result<i32, LiveMetadataAndHeaderValidationError> {
    let value = match classify_header_operation(first)?
        .ok_or(LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable)?
    {
        ObservedHeaderValue::Integer(value) => i32::try_from(value)
            .map_err(|_| LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable)?,
        ObservedHeaderValue::Other => {
            return Err(LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable);
        }
    };
    if classify_header_operation(terminal_step())? {
        return Err(LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable);
    }
    Ok(value)
}

fn observe_single_integer_header(
    statement: &mut Statement<'_>,
) -> Result<i32, LiveMetadataAndHeaderValidationError> {
    if statement.column_count() != 1 {
        return Err(LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable);
    }
    let mut rows = classify_header_operation(statement.query([]))?;
    let first = match classify_header_operation(rows.next())? {
        Some(row) => Some(match classify_header_operation(row.get_ref(0))? {
            ValueRef::Integer(value) => ObservedHeaderValue::Integer(value),
            _ => ObservedHeaderValue::Other,
        }),
        None => None,
    };
    complete_header_observation(Ok(first), || {
        rows.next().map(|row| row.is_some()).map_err(|_| ())
    })
}

enum OwnedRawDatabaseMetadataValue {
    Null,
    Integer(i64),
    Real,
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

impl fmt::Debug for OwnedRawDatabaseMetadataValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedRawDatabaseMetadataValue([REDACTED])")
    }
}

fn observe_and_validate_metadata(
    connection: &Connection,
) -> Result<DatabaseMetadataContractV1, LiveMetadataAndHeaderValidationError> {
    let mut statement = classify_metadata_observation(connection.prepare(METADATA_QUERY))?;
    if statement.column_count() != METADATA_COLUMN_COUNT {
        return Err(LiveMetadataAndHeaderValidationError::MetadataObservationUnavailable);
    }
    let mut rows = classify_metadata_observation(statement.query([]))?;
    let first_row = classify_metadata_step(rows.next())?
        .ok_or(LiveMetadataAndHeaderValidationError::MetadataRowMissing)?;

    let mut observation = Vec::with_capacity(METADATA_COLUMN_COUNT);
    for index in 0..METADATA_COLUMN_COUNT {
        let value = classify_metadata_observation(first_row.get_ref(index))?;
        observation.push(match value {
            ValueRef::Null => OwnedRawDatabaseMetadataValue::Null,
            ValueRef::Integer(value) => OwnedRawDatabaseMetadataValue::Integer(value),
            ValueRef::Real(_) => OwnedRawDatabaseMetadataValue::Real,
            ValueRef::Text(value) => OwnedRawDatabaseMetadataValue::Text(value.to_vec()),
            ValueRef::Blob(value) => OwnedRawDatabaseMetadataValue::Blob(value.to_vec()),
        });
    }

    if classify_metadata_step(rows.next())?.is_some() {
        return Err(LiveMetadataAndHeaderValidationError::DuplicateMetadataRows);
    }
    drop(rows);
    drop(statement);

    validate_owned_metadata_observation(&observation)
}

fn classify_metadata_observation<T, E>(
    result: Result<T, E>,
) -> Result<T, LiveMetadataAndHeaderValidationError> {
    result.map_err(|_| LiveMetadataAndHeaderValidationError::MetadataObservationUnavailable)
}

fn classify_metadata_step<T, E>(
    result: Result<T, E>,
) -> Result<T, LiveMetadataAndHeaderValidationError> {
    result.map_err(|_| {
        LiveMetadataAndHeaderValidationError::MetadataObservationInterruptedOrIncomplete
    })
}

fn adapt_owned_value(
    value: &OwnedRawDatabaseMetadataValue,
) -> Result<RawDatabaseMetadataValue<'_>, LiveMetadataAndHeaderValidationError> {
    match value {
        OwnedRawDatabaseMetadataValue::Null => Ok(RawDatabaseMetadataValue::Null),
        OwnedRawDatabaseMetadataValue::Integer(value) => {
            Ok(RawDatabaseMetadataValue::Integer(*value))
        }
        OwnedRawDatabaseMetadataValue::Real => {
            Err(LiveMetadataAndHeaderValidationError::MalformedMetadata)
        }
        OwnedRawDatabaseMetadataValue::Text(value) => std::str::from_utf8(value)
            .map(RawDatabaseMetadataValue::Text)
            .map_err(|_| LiveMetadataAndHeaderValidationError::MalformedMetadata),
        OwnedRawDatabaseMetadataValue::Blob(value) => Ok(RawDatabaseMetadataValue::Blob(value)),
    }
}

fn validate_owned_metadata_observation(
    observation: &[OwnedRawDatabaseMetadataValue],
) -> Result<DatabaseMetadataContractV1, LiveMetadataAndHeaderValidationError> {
    let values: Vec<_> = observation
        .iter()
        .map(adapt_owned_value)
        .collect::<Result<_, _>>()?;
    let values: [RawDatabaseMetadataValue<'_>; METADATA_COLUMN_COUNT] = values
        .try_into()
        .map_err(|_| LiveMetadataAndHeaderValidationError::MetadataObservationUnavailable)?;
    let [
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
        database_created_at,
    ] = values;

    let parsed = RawDatabaseMetadataRow::new(
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
        database_created_at,
    )
    .parse()
    .map_err(|_| LiveMetadataAndHeaderValidationError::MalformedMetadata)?;

    parsed.validate_structure().map_err(|error| match error {
        MetadataValidationError::UnsupportedMetadataVersion => {
            LiveMetadataAndHeaderValidationError::UnsupportedMetadataContractVersion
        }
        MetadataValidationError::UnsupportedSchemaVersion => {
            LiveMetadataAndHeaderValidationError::UnsupportedDatabaseSchemaVersion
        }
        MetadataValidationError::WrongSingleton
        | MetadataValidationError::WrongApplicationIdentifier
        | MetadataValidationError::WrongDatabaseFormatIdentity
        | MetadataValidationError::InvalidParishIdentifier
        | MetadataValidationError::InvalidInstallationIdentifier
        | MetadataValidationError::InvalidInstallationGeneration
        | MetadataValidationError::InvalidRecoveryReplacementGeneration
        | MetadataValidationError::InvalidDatabaseKeyGenerationIdentifier
        | MetadataValidationError::InvalidSetupPublicationIdentifier => {
            LiveMetadataAndHeaderValidationError::MalformedMetadata
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use rusqlite::{Connection, params_from_iter, types::Value};

    use super::*;
    use crate::{
        database_key::DatabaseKey,
        database_key_protected_payload::{DecodedDatabaseKeyCandidate, EncodedDatabaseKeyPayload},
        installation_evidence_authenticated_envelope::{
            EvidenceAuthenticationKeyGenerationIdentifier, construct_authenticated_envelope_v1,
        },
        installation_evidence_authentication_key::EvidenceAuthenticationKey,
        installation_evidence_contract::{
            DatabaseKeyGenerationIdentifier, PERMANENT_APPLICATION_IDENTIFIER,
            StructurallyValidatedInstallationEvidence, UnvalidatedInstallationEvidenceContract,
        },
        installation_evidence_protection::{
            GenerationBoundDatabaseKey,
            bind_database_key_candidate_to_trusted_installation_evidence,
            load_trusted_current_installation_evidence_assessment, protect_authenticated_evidence,
            protect_authentication_material,
            trusted_current_installation_evidence_assessment_for_test,
        },
        production_database_connection_handoff::{
            ProductionDatabaseValidationOutcome, acquire_guarded_inspection, apply_key_once,
            open_connection_once, open_keyed_production_database_read_only,
            validate_production_database_readability_and_integrity,
        },
        production_database_file::{
            InspectedProductionDatabaseFile, ProductionDatabaseInspection,
            inspect_production_database_file,
        },
        storage_foundation::{
            APPLICATION_DATABASE_FORMAT_IDENTITY, PRODUCTION_DATABASE_FILENAME,
            ProductionDatabasePath, installation_evidence_persistence_paths,
            production_database_path,
        },
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const DATABASE_KEY_GENERATION: [u8; 16] = [0x41; 16];
    const EVIDENCE_KEY_GENERATION: [u8; 16] = [0x52; 16];
    const EVIDENCE_KEY: [u8; 32] = [0x63; 32];
    const DATABASE_KEY_BYTES: [u8; 32] = [0x74; 32];
    const CREATE_METADATA_RELATION: &str = "CREATE TABLE church_app_database_metadata (
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
    const INSERT_METADATA_ROW: &str = "INSERT INTO church_app_database_metadata VALUES
        (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn create() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "church-app-live-metadata-validation-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("synthetic root creation should succeed");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn typed_path(&self) -> ProductionDatabasePath {
            production_database_path(self.0.clone())
        }

        fn inspected(&self) -> InspectedProductionDatabaseFile {
            let ProductionDatabaseInspection::Present(inspected) =
                inspect_production_database_file(&self.typed_path())
            else {
                panic!("synthetic database should pass production inspection");
            };
            inspected
        }

        fn assert_exact_cleanup(self) {
            fs::remove_dir_all(&self.0).expect("exact synthetic root cleanup should succeed");
            assert!(!self.0.exists());
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn generation_bound_key(root: &TestRoot) -> GenerationBoundDatabaseKey {
        let paths = installation_evidence_persistence_paths(root.path());
        fs::create_dir_all(paths.evidence_directory.as_path()).unwrap();
        let evidence = UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            "101112131415161718191a1b1c1d1e1f",
            [0x21; 16],
            1,
            1,
            DATABASE_KEY_GENERATION,
            [0x32; 16],
            1_798_000_000,
        )
        .validate()
        .unwrap();
        let authentication_key = EvidenceAuthenticationKey::from_bytes(EVIDENCE_KEY);
        let authentication_generation =
            EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(EVIDENCE_KEY_GENERATION)
                .unwrap();
        let (envelope, _) = construct_authenticated_envelope_v1(
            &authentication_key,
            authentication_generation,
            &evidence.encode_v1(),
        )
        .unwrap();
        fs::write(
            paths.active_authentication_key.as_path(),
            protect_authentication_material(&authentication_key, authentication_generation)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        fs::write(
            paths.active_authenticated_evidence.as_path(),
            protect_authenticated_evidence(&envelope)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let assessment = load_trusted_current_installation_evidence_assessment(&paths).unwrap();
        let database_key = DatabaseKey::from_bytes(DATABASE_KEY_BYTES);
        let payload = EncodedDatabaseKeyPayload::encode(
            &database_key,
            DatabaseKeyGenerationIdentifier::from_bytes(DATABASE_KEY_GENERATION).unwrap(),
        );
        bind_database_key_candidate_to_trusted_installation_evidence(
            DecodedDatabaseKeyCandidate::parse(payload.as_bytes()).unwrap(),
            &assessment,
        )
        .unwrap()
    }

    fn canonical_values() -> [Value; METADATA_COLUMN_COUNT] {
        [
            Value::Integer(1),
            Value::Integer(1),
            Value::Integer(1),
            Value::Text(PERMANENT_APPLICATION_IDENTIFIER.to_owned()),
            Value::Blob(APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes().to_vec()),
            Value::Blob(vec![0x11; 16]),
            Value::Blob(vec![0x21; 16]),
            Value::Blob(7_u64.to_be_bytes().to_vec()),
            Value::Blob(11_u64.to_be_bytes().to_vec()),
            Value::Blob(vec![0x43; 16]),
            Value::Blob(vec![0x65; 16]),
            Value::Integer(1_798_000_000_123),
        ]
    }

    fn correspondence_evidence(
        parish_identifier: &str,
        installation_identifier: [u8; 16],
        installation_generation: u64,
        recovery_replacement_generation: u64,
        database_key_generation_identifier: [u8; 16],
        setup_publication_identifier: [u8; 16],
        creation_timestamp: u64,
    ) -> StructurallyValidatedInstallationEvidence {
        UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            parish_identifier,
            installation_identifier,
            installation_generation,
            recovery_replacement_generation,
            database_key_generation_identifier,
            setup_publication_identifier,
            creation_timestamp,
        )
        .validate()
        .expect("synthetic correspondence evidence should validate structurally")
    }

    fn matching_correspondence_evidence(
        installation_generation: u64,
        recovery_replacement_generation: u64,
        creation_timestamp: u64,
    ) -> StructurallyValidatedInstallationEvidence {
        correspondence_evidence(
            "11111111111111111111111111111111",
            [0x21; 16],
            installation_generation,
            recovery_replacement_generation,
            [0x43; 16],
            [0x65; 16],
            creation_timestamp,
        )
    }

    fn create_fixture(
        root: &TestRoot,
        application_id: i32,
        user_version: i32,
        relation_sql: Option<&str>,
        rows: &[[Value; METADATA_COLUMN_COUNT]],
        invalid_utf8: bool,
    ) {
        let key = generation_bound_key(root);
        let connection = Connection::open(root.path().join(PRODUCTION_DATABASE_FILENAME)).unwrap();
        apply_key_once(&connection, &key).unwrap();
        connection
            .execute_batch(&format!(
                "PRAGMA application_id = {application_id}; PRAGMA user_version = {user_version};"
            ))
            .unwrap();
        if let Some(schema) = relation_sql {
            connection.execute_batch(schema).unwrap();
            for row in rows {
                connection
                    .execute(INSERT_METADATA_ROW, params_from_iter(row.iter()))
                    .unwrap();
            }
            if invalid_utf8 {
                connection
                    .execute_batch(
                        "UPDATE church_app_database_metadata
                         SET permanent_application_identifier = CAST(x'80' AS TEXT)",
                    )
                    .unwrap();
            }
        }
        connection.close().map_err(|(_, error)| error).unwrap();
    }

    fn accepted_predecessor(
        root: &TestRoot,
    ) -> ReadabilityAndIntegrityValidatedProductionDatabaseConnection {
        let keyed = open_keyed_production_database_read_only(
            root.typed_path(),
            root.inspected(),
            generation_bound_key(root),
        )
        .expect("guarded keyed read-only handoff should succeed");
        let ProductionDatabaseValidationOutcome::Validated(predecessor) =
            validate_production_database_readability_and_integrity(keyed)
        else {
            panic!("readability and integrity validation should succeed");
        };
        predecessor
    }

    fn validate_fixture(
        root: &TestRoot,
    ) -> Result<
        LiveMetadataAndHeaderValidatedProductionDatabaseConnection,
        LiveMetadataAndHeaderValidationError,
    > {
        match validate_production_database_live_metadata_and_headers(accepted_predecessor(root)) {
            LiveMetadataAndHeaderValidationOutcome::Validated(owner) => Ok(owner),
            LiveMetadataAndHeaderValidationOutcome::Failed(category) => Err(category),
            LiveMetadataAndHeaderValidationOutcome::CloseFailed(_) => {
                panic!("synthetic validation failure should explicitly close")
            }
        }
    }

    fn assert_fixture_failure(
        application_id: i32,
        user_version: i32,
        relation_sql: Option<&str>,
        rows: &[[Value; METADATA_COLUMN_COUNT]],
        invalid_utf8: bool,
        expected: LiveMetadataAndHeaderValidationError,
    ) {
        let root = TestRoot::create();
        create_fixture(
            &root,
            application_id,
            user_version,
            relation_sql,
            rows,
            invalid_utf8,
        );
        assert_eq!(validate_fixture(&root).unwrap_err(), expected);
        root.assert_exact_cleanup();
    }

    fn direct_predecessor(
        root: &TestRoot,
    ) -> ReadabilityAndIntegrityValidatedProductionDatabaseConnection {
        let connection = Connection::open(root.path().join(PRODUCTION_DATABASE_FILENAME)).unwrap();
        connection.close().map_err(|(_, error)| error).unwrap();
        let guarded = acquire_guarded_inspection(&root.typed_path(), root.inspected()).unwrap();
        ReadabilityAndIntegrityValidatedProductionDatabaseConnection {
            owner: ConnectionLifetimeOwner {
                connection: open_connection_once(&root.typed_path()).unwrap(),
                guard: guarded.guard,
                inspected: guarded.inspected,
            },
        }
    }

    fn canonical_owned_observation() -> Vec<OwnedRawDatabaseMetadataValue> {
        canonical_values()
            .into_iter()
            .map(|value| match value {
                Value::Null => OwnedRawDatabaseMetadataValue::Null,
                Value::Integer(value) => OwnedRawDatabaseMetadataValue::Integer(value),
                Value::Real(_) => OwnedRawDatabaseMetadataValue::Real,
                Value::Text(value) => OwnedRawDatabaseMetadataValue::Text(value.into_bytes()),
                Value::Blob(value) => OwnedRawDatabaseMetadataValue::Blob(value),
            })
            .collect()
    }

    struct DropProbe<'a>(&'a Cell<bool>);

    impl Drop for DropProbe<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    #[test]
    fn canonical_real_sqlcipher_fixture_succeeds_and_closes_with_exact_cleanup() {
        let root = TestRoot::create();
        create_fixture(
            &root,
            EXPECTED_APPLICATION_ID,
            1,
            Some(CREATE_METADATA_RELATION),
            &[canonical_values()],
            false,
        );
        let owner = validate_fixture(&root).expect("canonical fixture should validate");
        assert_eq!(
            format!("{owner:?}"),
            "LiveMetadataAndHeaderValidatedProductionDatabaseConnection([REDACTED])"
        );
        assert!(matches!(
            owner.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    fn correspondence_fixture(
        evidence: StructurallyValidatedInstallationEvidence,
    ) -> (TestRoot, DatabaseEvidenceCorrespondenceValidationOutcome) {
        let root = TestRoot::create();
        create_fixture(
            &root,
            EXPECTED_APPLICATION_ID,
            1,
            Some(CREATE_METADATA_RELATION),
            &[canonical_values()],
            false,
        );
        let database = validate_fixture(&root).expect("live predecessor should validate");
        let assessment = trusted_current_installation_evidence_assessment_for_test(evidence);
        let outcome = validate_production_database_evidence_correspondence(database, assessment);
        (root, outcome)
    }

    #[test]
    fn database_evidence_correspondence_validation_matching_real_sqlcipher_chain_succeeds_redacts_closes_and_cleans_exactly()
     {
        let (root, outcome) =
            correspondence_fixture(matching_correspondence_evidence(7, 11, 1_798_000_000));
        let DatabaseEvidenceCorrespondenceValidationOutcome::Validated(owner) = outcome else {
            panic!("matching trusted assessment should correspond");
        };
        assert_eq!(
            format!("{owner:?}"),
            "DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection([REDACTED])"
        );
        assert!(matches!(
            owner.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    fn assert_correspondence_mismatch(evidence: StructurallyValidatedInstallationEvidence) {
        let (root, outcome) = correspondence_fixture(evidence);
        assert_eq!(
            format!("{outcome:?}"),
            "Mismatch(DatabaseEvidenceCorrespondenceMismatch)"
        );
        assert!(matches!(
            outcome,
            DatabaseEvidenceCorrespondenceValidationOutcome::Mismatch(
                DatabaseEvidenceCorrespondenceMismatch
            )
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn database_evidence_correspondence_validation_constructible_single_mismatches_are_one_coarse_category()
     {
        for evidence in [
            correspondence_evidence(
                "12121212121212121212121212121212",
                [0x21; 16],
                7,
                11,
                [0x43; 16],
                [0x65; 16],
                1_798_000_000,
            ),
            correspondence_evidence(
                "11111111111111111111111111111111",
                [0x22; 16],
                7,
                11,
                [0x43; 16],
                [0x65; 16],
                1_798_000_000,
            ),
            correspondence_evidence(
                "11111111111111111111111111111111",
                [0x21; 16],
                7,
                11,
                [0x44; 16],
                [0x65; 16],
                1_798_000_000,
            ),
            correspondence_evidence(
                "11111111111111111111111111111111",
                [0x21; 16],
                7,
                11,
                [0x43; 16],
                [0x66; 16],
                1_798_000_000,
            ),
        ] {
            assert_correspondence_mismatch(evidence);
        }
    }

    #[test]
    fn database_evidence_correspondence_validation_multiple_mismatches_remain_the_same_single_category()
     {
        assert_correspondence_mismatch(correspondence_evidence(
            "12121212121212121212121212121212",
            [0x22; 16],
            7,
            11,
            [0x44; 16],
            [0x66; 16],
            1_798_000_000,
        ));
    }

    #[test]
    fn database_evidence_correspondence_validation_ignores_generations_and_database_evidence_timestamps()
     {
        for evidence in [
            matching_correspondence_evidence(8, 11, 1_798_000_000),
            matching_correspondence_evidence(7, 12, 1_798_000_000),
            matching_correspondence_evidence(7, 11, 1_899_000_000),
            matching_correspondence_evidence(71, 111, 1_899_000_000),
        ] {
            let (root, outcome) = correspondence_fixture(evidence);
            let DatabaseEvidenceCorrespondenceValidationOutcome::Validated(owner) = outcome else {
                panic!("excluded generation and timestamp differences must correspond");
            };
            assert!(matches!(
                owner.close(),
                ProductionDatabaseConnectionCloseOutcome::Closed
            ));
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn database_evidence_correspondence_validation_mismatch_discards_inputs_before_close_and_close_success_is_primary()
     {
        let root = TestRoot::create();
        let metadata_dropped = Cell::new(false);
        let assessment_dropped = Cell::new(false);
        let close_called = Cell::new(false);
        let outcome = database_evidence_correspondence_validation::finish_mismatch_using(
            direct_predecessor(&root).owner,
            DropProbe(&metadata_dropped),
            DropProbe(&assessment_dropped),
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
            DatabaseEvidenceCorrespondenceValidationOutcome::Mismatch(
                DatabaseEvidenceCorrespondenceMismatch
            )
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn database_evidence_correspondence_validation_mismatch_close_failure_retries_only_close_and_preserves_ownership()
     {
        let root = TestRoot::create();
        let outcome = database_evidence_correspondence_validation::finish_mismatch_using(
            direct_predecessor(&root).owner,
            (),
            (),
            Err,
        );
        let DatabaseEvidenceCorrespondenceValidationOutcome::CloseFailed(failure) = outcome else {
            panic!("injected mismatch close should fail");
        };
        assert_eq!(
            format!("{failure:?}"),
            "DatabaseEvidenceCorrespondenceValidationCloseFailure([REDACTED])"
        );
        let DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Failed(failure) =
            failure.retry_close_using(Err)
        else {
            panic!("repeated injected close should preserve failure ownership");
        };
        let retry = DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Failed(failure);
        assert_eq!(format!("{retry:?}"), "Failed([REDACTED])");
        let DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Failed(failure) = retry
        else {
            unreachable!();
        };
        assert!(matches!(
            failure.retry_close(),
            DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome::Closed(
                DatabaseEvidenceCorrespondenceMismatch
            )
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn database_evidence_correspondence_validation_success_close_discards_inputs_first_and_failure_uses_general_owner()
     {
        let root = TestRoot::create();
        let metadata_dropped = Cell::new(false);
        let assessment_dropped = Cell::new(false);
        let outcome = database_evidence_correspondence_validation::close_correspondence_owner_using(
            direct_predecessor(&root).owner,
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

        let (root, outcome) =
            correspondence_fixture(matching_correspondence_evidence(7, 11, 1_798_000_000));
        let DatabaseEvidenceCorrespondenceValidationOutcome::Validated(owner) = outcome else {
            panic!("matching correspondence should validate");
        };
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) = owner.close_using(Err)
        else {
            panic!("injected successful-owner close should retain general lifetime ownership");
        };
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn header_and_relation_precedence_is_fail_closed() {
        assert_fixture_failure(
            0,
            1,
            None,
            &[],
            false,
            LiveMetadataAndHeaderValidationError::WrongApplicationId,
        );
        assert_fixture_failure(
            0,
            1,
            Some(CREATE_METADATA_RELATION),
            &[{
                let mut row = canonical_values();
                row[1] = Value::Integer(2);
                row
            }],
            false,
            LiveMetadataAndHeaderValidationError::WrongApplicationId,
        );
        assert_fixture_failure(
            EXPECTED_APPLICATION_ID,
            2,
            Some(CREATE_METADATA_RELATION),
            &[canonical_values()],
            false,
            LiveMetadataAndHeaderValidationError::UserVersionMismatch,
        );
    }

    #[test]
    fn relation_preparation_and_exact_cardinality_are_enforced() {
        assert_fixture_failure(
            EXPECTED_APPLICATION_ID,
            1,
            None,
            &[],
            false,
            LiveMetadataAndHeaderValidationError::MetadataObservationUnavailable,
        );
        assert_fixture_failure(
            EXPECTED_APPLICATION_ID,
            1,
            Some(CREATE_METADATA_RELATION),
            &[],
            false,
            LiveMetadataAndHeaderValidationError::MetadataRowMissing,
        );
        assert_fixture_failure(
            EXPECTED_APPLICATION_ID,
            1,
            Some(CREATE_METADATA_RELATION),
            &[canonical_values(), canonical_values()],
            false,
            LiveMetadataAndHeaderValidationError::DuplicateMetadataRows,
        );
        let missing_column = CREATE_METADATA_RELATION.replace("database_created_at", "other_name");
        assert_fixture_failure(
            EXPECTED_APPLICATION_ID,
            1,
            Some(&missing_column),
            &[],
            false,
            LiveMetadataAndHeaderValidationError::MetadataObservationUnavailable,
        );
    }

    #[test]
    fn representation_family_matrix_maps_to_malformed_metadata() {
        let cases = [
            (0, Value::Null),
            (3, Value::Null),
            (4, Value::Null),
            (7, Value::Null),
            (0, Value::Text("wrong".to_owned())),
            (3, Value::Integer(1)),
            (4, Value::Text("wrong".to_owned())),
            (7, Value::Integer(1)),
            (4, Value::Blob(vec![1; 15])),
            (4, Value::Blob(vec![1; 17])),
            (7, Value::Blob(vec![1; 7])),
            (7, Value::Blob(vec![1; 9])),
        ];
        for (index, value) in cases {
            let mut row = canonical_values();
            row[index] = value;
            assert_fixture_failure(
                EXPECTED_APPLICATION_ID,
                1,
                Some(CREATE_METADATA_RELATION),
                &[row],
                false,
                LiveMetadataAndHeaderValidationError::MalformedMetadata,
            );
        }
        assert_fixture_failure(
            EXPECTED_APPLICATION_ID,
            1,
            Some(CREATE_METADATA_RELATION),
            &[canonical_values()],
            true,
            LiveMetadataAndHeaderValidationError::MalformedMetadata,
        );
    }

    #[test]
    fn version_and_structural_failure_matrix_uses_canonical_categories() {
        let cases = [
            (
                1,
                Value::Integer(2),
                LiveMetadataAndHeaderValidationError::UnsupportedMetadataContractVersion,
            ),
            (
                2,
                Value::Integer(2),
                LiveMetadataAndHeaderValidationError::UnsupportedDatabaseSchemaVersion,
            ),
            (
                3,
                Value::Text("wrong".to_owned()),
                LiveMetadataAndHeaderValidationError::MalformedMetadata,
            ),
            (
                4,
                Value::Blob(vec![0x99; 16]),
                LiveMetadataAndHeaderValidationError::MalformedMetadata,
            ),
            (
                5,
                Value::Blob(vec![0; 16]),
                LiveMetadataAndHeaderValidationError::MalformedMetadata,
            ),
            (
                6,
                Value::Blob(vec![0; 16]),
                LiveMetadataAndHeaderValidationError::MalformedMetadata,
            ),
            (
                7,
                Value::Blob(vec![0; 8]),
                LiveMetadataAndHeaderValidationError::MalformedMetadata,
            ),
            (
                8,
                Value::Blob(vec![0; 8]),
                LiveMetadataAndHeaderValidationError::MalformedMetadata,
            ),
            (
                9,
                Value::Blob(vec![0; 16]),
                LiveMetadataAndHeaderValidationError::MalformedMetadata,
            ),
            (
                10,
                Value::Blob(vec![0; 16]),
                LiveMetadataAndHeaderValidationError::MalformedMetadata,
            ),
            (
                11,
                Value::Integer(-1),
                LiveMetadataAndHeaderValidationError::MalformedMetadata,
            ),
        ];
        for (index, value, expected) in cases {
            let mut row = canonical_values();
            row[index] = value;
            let user_version = if index == 2 { 2 } else { 1 };
            assert_fixture_failure(
                EXPECTED_APPLICATION_ID,
                user_version,
                Some(CREATE_METADATA_RELATION),
                &[row],
                false,
                expected,
            );
        }
    }

    #[test]
    fn owned_adaptation_rejects_real_invalid_utf8_and_unavailable_shape() {
        let mut real = canonical_owned_observation();
        real[0] = OwnedRawDatabaseMetadataValue::Real;
        assert_eq!(
            validate_owned_metadata_observation(&real).unwrap_err(),
            LiveMetadataAndHeaderValidationError::MalformedMetadata
        );
        let mut invalid_utf8 = canonical_owned_observation();
        invalid_utf8[3] = OwnedRawDatabaseMetadataValue::Text(vec![0x80]);
        assert_eq!(
            validate_owned_metadata_observation(&invalid_utf8).unwrap_err(),
            LiveMetadataAndHeaderValidationError::MalformedMetadata
        );
        assert_eq!(
            validate_owned_metadata_observation(&[]).unwrap_err(),
            LiveMetadataAndHeaderValidationError::MetadataObservationUnavailable
        );
        assert_eq!(
            format!("{:?}", OwnedRawDatabaseMetadataValue::Blob(vec![1; 37])),
            "OwnedRawDatabaseMetadataValue([REDACTED])"
        );
    }

    #[test]
    fn every_primary_category_preserves_close_ownership_and_retry_category() {
        let categories = [
            LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable,
            LiveMetadataAndHeaderValidationError::WrongApplicationId,
            LiveMetadataAndHeaderValidationError::MetadataObservationUnavailable,
            LiveMetadataAndHeaderValidationError::MetadataObservationInterruptedOrIncomplete,
            LiveMetadataAndHeaderValidationError::MetadataRowMissing,
            LiveMetadataAndHeaderValidationError::DuplicateMetadataRows,
            LiveMetadataAndHeaderValidationError::MalformedMetadata,
            LiveMetadataAndHeaderValidationError::UnsupportedMetadataContractVersion,
            LiveMetadataAndHeaderValidationError::UnsupportedDatabaseSchemaVersion,
            LiveMetadataAndHeaderValidationError::UserVersionMismatch,
        ];
        for category in categories {
            let root = TestRoot::create();
            let outcome =
                finish_validation_using(direct_predecessor(&root), |_| Err(category), Err);
            let LiveMetadataAndHeaderValidationOutcome::CloseFailed(failure) = outcome else {
                panic!("injected close should fail");
            };
            assert_eq!(
                format!("{failure:?}"),
                "LiveMetadataAndHeaderValidationCloseFailure([REDACTED])"
            );
            let retry = failure.retry_close();
            assert!(matches!(
                retry,
                LiveMetadataAndHeaderValidationCloseRetryOutcome::Closed(observed)
                    if observed == category
            ));
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn every_primary_category_successfully_closes_after_validation_temporaries_are_discarded() {
        let categories = [
            LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable,
            LiveMetadataAndHeaderValidationError::WrongApplicationId,
            LiveMetadataAndHeaderValidationError::MetadataObservationUnavailable,
            LiveMetadataAndHeaderValidationError::MetadataObservationInterruptedOrIncomplete,
            LiveMetadataAndHeaderValidationError::MetadataRowMissing,
            LiveMetadataAndHeaderValidationError::DuplicateMetadataRows,
            LiveMetadataAndHeaderValidationError::MalformedMetadata,
            LiveMetadataAndHeaderValidationError::UnsupportedMetadataContractVersion,
            LiveMetadataAndHeaderValidationError::UnsupportedDatabaseSchemaVersion,
            LiveMetadataAndHeaderValidationError::UserVersionMismatch,
        ];
        for category in categories {
            let root = TestRoot::create();
            let close_called = Cell::new(false);
            let temporary_dropped = Cell::new(false);
            let outcome = finish_validation_using(
                direct_predecessor(&root),
                |_| {
                    let _temporary_observation = DropProbe(&temporary_dropped);
                    Err(category)
                },
                |connection| {
                    assert!(temporary_dropped.get());
                    close_called.set(true);
                    drop(connection);
                    Ok(())
                },
            );
            assert!(close_called.get());
            assert!(matches!(
                outcome,
                LiveMetadataAndHeaderValidationOutcome::Failed(observed)
                    if observed == category
            ));
            root.assert_exact_cleanup();
        }
    }

    #[test]
    fn repeated_close_failure_and_validated_owner_close_failure_retain_lifetime_unit() {
        let root = TestRoot::create();
        let outcome = finish_validation_using(
            direct_predecessor(&root),
            |_| Err(LiveMetadataAndHeaderValidationError::WrongApplicationId),
            Err,
        );
        let LiveMetadataAndHeaderValidationOutcome::CloseFailed(failure) = outcome else {
            panic!("first close should fail");
        };
        let LiveMetadataAndHeaderValidationCloseRetryOutcome::Failed(failure) =
            retry_validation_close_using(failure, Err)
        else {
            panic!("second close should fail");
        };
        assert!(matches!(
            retry_validation_close_using(failure, |_| Ok(())),
            LiveMetadataAndHeaderValidationCloseRetryOutcome::Closed(
                LiveMetadataAndHeaderValidationError::WrongApplicationId
            )
        ));
        root.assert_exact_cleanup();

        let root = TestRoot::create();
        let owner = LiveMetadataAndHeaderValidatedProductionDatabaseConnection {
            owner: direct_predecessor(&root).owner,
            metadata_contract: validate_owned_metadata_observation(&canonical_owned_observation())
                .unwrap(),
        };
        let ProductionDatabaseConnectionCloseOutcome::Failed(failure) = owner.close_using(Err)
        else {
            panic!("injected validated-owner close should fail");
        };
        assert!(matches!(
            failure.retry_close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn validated_owner_metadata_is_dropped_before_injected_close_begins() {
        let root = TestRoot::create();
        let metadata_dropped = Cell::new(false);
        let close_called = Cell::new(false);
        let outcome = close_validated_owner_using(
            direct_predecessor(&root).owner,
            DropProbe(&metadata_dropped),
            |connection| {
                assert!(metadata_dropped.get());
                close_called.set(true);
                drop(connection);
                Ok(())
            },
        );
        assert!(metadata_dropped.get());
        assert!(close_called.get());
        assert!(matches!(
            outcome,
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn debug_and_source_boundaries_are_coarse_fixed_and_sealed() {
        const SOURCE: &str = include_str!("live_metadata_and_header_validation.rs");
        const PARENT: &str = include_str!("../production_database_connection_handoff.rs");
        let production = SOURCE.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        assert_eq!(production.matches("PRAGMA main.application_id").count(), 1);
        assert_eq!(production.matches("PRAGMA main.user_version").count(), 1);
        assert_eq!(
            production
                .matches("FROM main.church_app_database_metadata")
                .count(),
            1
        );
        assert_eq!(production.matches(".parse()").count(), 1);
        assert_eq!(production.matches(".validate_structure()").count(), 1);
        let application = production
            .find("observe_application_id(connection)?")
            .unwrap();
        let user = production
            .find("observe_user_version(connection)?")
            .unwrap();
        let metadata = production
            .find("observe_and_validate_metadata(connection)?")
            .unwrap();
        assert!(application < user && user < metadata);
        for required in ["LIMIT 2", "metadata_contract: DatabaseMetadataContractV1"] {
            assert!(production.contains(required));
        }
        for forbidden in [
            "SELECT *",
            "sqlite_master",
            "typeof(",
            "CAST(",
            " WHERE ",
            "CREATE TABLE",
            "ALTER TABLE",
            "INSERT ",
            "UPDATE ",
            "DELETE ",
            "PRAGMA application_id =",
            "PRAGMA user_version =",
            "impl Deref",
            "AsRef<Connection>",
            "with_connection",
            "tauri::command",
            "unsafe {",
            "sqlite3_",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden production surface: {forbidden}"
            );
        }
        assert!(PARENT.contains("mod live_metadata_and_header_validation;"));
        assert!(!PARENT.contains("pub mod live_metadata_and_header_validation;"));
        let debug = format!(
            "{:?}",
            LiveMetadataAndHeaderValidationOutcome::Failed(
                LiveMetadataAndHeaderValidationError::MalformedMetadata
            )
        );
        assert_eq!(debug, "Failed(MalformedMetadata)");
        assert!(!debug.contains(PERMANENT_APPLICATION_IDENTIFIER));
        let root = TestRoot::create();
        let retry = LiveMetadataAndHeaderValidationCloseRetryOutcome::Failed(
            LiveMetadataAndHeaderValidationCloseFailure {
                category: LiveMetadataAndHeaderValidationError::MalformedMetadata,
                owner: direct_predecessor(&root).owner,
            },
        );
        assert_eq!(format!("{retry:?}"), "Failed([REDACTED])");
        let LiveMetadataAndHeaderValidationCloseRetryOutcome::Failed(failure) = retry else {
            unreachable!();
        };
        assert!(matches!(
            retry_validation_close_using(failure, |_| Ok(())),
            LiveMetadataAndHeaderValidationCloseRetryOutcome::Closed(
                LiveMetadataAndHeaderValidationError::MalformedMetadata
            )
        ));
        root.assert_exact_cleanup();
    }

    #[test]
    fn header_shape_seam_enforces_one_integer_row_i32_range_and_terminal_end() {
        let connection = Connection::open_in_memory().unwrap();
        for (sql, expected) in [
            (
                "SELECT 1, 2",
                Err(LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable),
            ),
            (
                "SELECT 1 WHERE 0",
                Err(LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable),
            ),
            (
                "SELECT '1'",
                Err(LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable),
            ),
            (
                "SELECT 2147483648",
                Err(LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable),
            ),
            (
                "SELECT 1 UNION ALL SELECT 2",
                Err(LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable),
            ),
            ("SELECT 1", Ok(1)),
        ] {
            let mut statement = connection.prepare(sql).unwrap();
            assert_eq!(observe_single_integer_header(&mut statement), expected);
        }
    }

    #[test]
    fn injected_header_operation_failures_are_always_observation_unavailable() {
        let preparation_failure = classify_header_operation::<(), _>(Err(()));
        let query_startup_failure = classify_header_operation::<(), _>(Err(()));
        let terminal_step_failure =
            complete_header_observation(Ok(Some(ObservedHeaderValue::Integer(1))), || Err(()));
        for failure in [
            preparation_failure,
            query_startup_failure,
            terminal_step_failure.map(|_| ()),
        ] {
            assert_eq!(
                failure.unwrap_err(),
                LiveMetadataAndHeaderValidationError::HeaderObservationUnavailable
            );
        }
    }

    #[test]
    fn injected_metadata_operation_failures_use_exact_boundary_categories() {
        let query_startup_failure = classify_metadata_observation::<(), _>(Err(()));
        let first_step_failure = classify_metadata_step::<(), _>(Err(()));
        let second_or_terminal_step_failure = classify_metadata_step::<(), _>(Err(()));
        let expected_column_access_failure = classify_metadata_observation::<(), _>(Err(()));

        assert_eq!(
            query_startup_failure.unwrap_err(),
            LiveMetadataAndHeaderValidationError::MetadataObservationUnavailable
        );
        for failure in [first_step_failure, second_or_terminal_step_failure] {
            assert_eq!(
                failure.unwrap_err(),
                LiveMetadataAndHeaderValidationError::MetadataObservationInterruptedOrIncomplete
            );
        }
        assert_eq!(
            expected_column_access_failure.unwrap_err(),
            LiveMetadataAndHeaderValidationError::MetadataObservationUnavailable
        );
    }

    #[test]
    fn successful_failure_close_discards_temporaries_before_explicit_close() {
        let root = TestRoot::create();
        let close_called = Cell::new(false);
        let outcome = finish_validation_using(
            direct_predecessor(&root),
            |_| Err(LiveMetadataAndHeaderValidationError::MetadataRowMissing),
            |connection| {
                close_called.set(true);
                drop(connection);
                Ok(())
            },
        );
        assert!(close_called.get());
        assert!(matches!(
            outcome,
            LiveMetadataAndHeaderValidationOutcome::Failed(
                LiveMetadataAndHeaderValidationError::MetadataRowMissing
            )
        ));
        root.assert_exact_cleanup();
    }
}
