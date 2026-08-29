//! Fixed production-database header and metadata observation mechanics shared
//! by the setup-time and startup-time consuming validation transitions.

use std::fmt;

use rusqlite::{Connection, Statement, types::ValueRef};

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    database_metadata_decoding::{
        MetadataValidationError, RawDatabaseMetadataRow, RawDatabaseMetadataValue,
    },
};

use super::PRODUCTION_DATABASE_APPLICATION_ID;

pub(super) const APPLICATION_ID_QUERY: &str = "PRAGMA main.application_id";
pub(super) const USER_VERSION_QUERY: &str = "PRAGMA main.user_version";
pub(super) const METADATA_QUERY: &str = "SELECT
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
pub(super) const METADATA_COLUMN_COUNT: usize = 12;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum FixedMetadataAndHeaderObservationError {
    HeaderObservationUnavailable,
    WrongApplicationId,
    UnexpectedUserVersion,
    MetadataObservationUnavailable,
    MetadataObservationInterruptedOrIncomplete,
    MetadataRowMissing,
    DuplicateMetadataRows,
    MalformedMetadata,
    UnsupportedMetadataContractVersion,
    UnsupportedDatabaseSchemaVersion,
    UserVersionMismatch,
}

impl fmt::Debug for FixedMetadataAndHeaderObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HeaderObservationUnavailable => "HeaderObservationUnavailable",
            Self::WrongApplicationId => "WrongApplicationId",
            Self::UnexpectedUserVersion => "UnexpectedUserVersion",
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

/// Runs only the fixed header reads and fixed metadata observation. Supplying an
/// expected user version adds the setup-time early header check without changing
/// the startup adapter's established ordering or taxonomy.
pub(super) fn observe_fixed_metadata_and_headers(
    connection: &Connection,
    expected_user_version: Option<i32>,
) -> Result<DatabaseMetadataContractV1, FixedMetadataAndHeaderObservationError> {
    let application_id = observe_application_id(connection)?;
    if application_id != PRODUCTION_DATABASE_APPLICATION_ID {
        return Err(FixedMetadataAndHeaderObservationError::WrongApplicationId);
    }

    let user_version = observe_user_version(connection)?;
    if expected_user_version.is_some_and(|expected| user_version != expected) {
        return Err(FixedMetadataAndHeaderObservationError::UnexpectedUserVersion);
    }

    let metadata_contract = observe_and_validate_metadata(connection)?;
    if i64::from(user_version) != i64::from(metadata_contract.database_schema_version().get()) {
        return Err(FixedMetadataAndHeaderObservationError::UserVersionMismatch);
    }
    Ok(metadata_contract)
}

pub(super) fn observe_application_id(
    connection: &Connection,
) -> Result<i32, FixedMetadataAndHeaderObservationError> {
    let mut statement = classify_header_operation(connection.prepare(APPLICATION_ID_QUERY))?;
    observe_single_integer_header(&mut statement)
}

pub(super) fn observe_user_version(
    connection: &Connection,
) -> Result<i32, FixedMetadataAndHeaderObservationError> {
    let mut statement = classify_header_operation(connection.prepare(USER_VERSION_QUERY))?;
    observe_single_integer_header(&mut statement)
}

pub(super) fn classify_header_operation<T, E>(
    result: Result<T, E>,
) -> Result<T, FixedMetadataAndHeaderObservationError> {
    result.map_err(|_| FixedMetadataAndHeaderObservationError::HeaderObservationUnavailable)
}

pub(super) enum ObservedHeaderValue {
    Integer(i64),
    Other,
}

pub(super) fn complete_header_observation(
    first: Result<Option<ObservedHeaderValue>, ()>,
    terminal_step: impl FnOnce() -> Result<bool, ()>,
) -> Result<i32, FixedMetadataAndHeaderObservationError> {
    let value = match classify_header_operation(first)?
        .ok_or(FixedMetadataAndHeaderObservationError::HeaderObservationUnavailable)?
    {
        ObservedHeaderValue::Integer(value) => i32::try_from(value)
            .map_err(|_| FixedMetadataAndHeaderObservationError::HeaderObservationUnavailable)?,
        ObservedHeaderValue::Other => {
            return Err(FixedMetadataAndHeaderObservationError::HeaderObservationUnavailable);
        }
    };
    if classify_header_operation(terminal_step())? {
        return Err(FixedMetadataAndHeaderObservationError::HeaderObservationUnavailable);
    }
    Ok(value)
}

pub(super) fn observe_single_integer_header(
    statement: &mut Statement<'_>,
) -> Result<i32, FixedMetadataAndHeaderObservationError> {
    if statement.column_count() != 1 {
        return Err(FixedMetadataAndHeaderObservationError::HeaderObservationUnavailable);
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

pub(super) enum OwnedRawDatabaseMetadataValue {
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
) -> Result<DatabaseMetadataContractV1, FixedMetadataAndHeaderObservationError> {
    let mut statement = classify_metadata_observation(connection.prepare(METADATA_QUERY))?;
    if statement.column_count() != METADATA_COLUMN_COUNT {
        return Err(FixedMetadataAndHeaderObservationError::MetadataObservationUnavailable);
    }
    let mut rows = classify_metadata_observation(statement.query([]))?;
    let first_row = classify_metadata_step(rows.next())?
        .ok_or(FixedMetadataAndHeaderObservationError::MetadataRowMissing)?;

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
        return Err(FixedMetadataAndHeaderObservationError::DuplicateMetadataRows);
    }
    drop(rows);
    drop(statement);

    validate_owned_metadata_observation(&observation)
}

pub(super) fn classify_metadata_observation<T, E>(
    result: Result<T, E>,
) -> Result<T, FixedMetadataAndHeaderObservationError> {
    result.map_err(|_| FixedMetadataAndHeaderObservationError::MetadataObservationUnavailable)
}

pub(super) fn classify_metadata_step<T, E>(
    result: Result<T, E>,
) -> Result<T, FixedMetadataAndHeaderObservationError> {
    result.map_err(|_| {
        FixedMetadataAndHeaderObservationError::MetadataObservationInterruptedOrIncomplete
    })
}

fn adapt_owned_value(
    value: &OwnedRawDatabaseMetadataValue,
) -> Result<RawDatabaseMetadataValue<'_>, FixedMetadataAndHeaderObservationError> {
    match value {
        OwnedRawDatabaseMetadataValue::Null => Ok(RawDatabaseMetadataValue::Null),
        OwnedRawDatabaseMetadataValue::Integer(value) => {
            Ok(RawDatabaseMetadataValue::Integer(*value))
        }
        OwnedRawDatabaseMetadataValue::Real => {
            Err(FixedMetadataAndHeaderObservationError::MalformedMetadata)
        }
        OwnedRawDatabaseMetadataValue::Text(value) => std::str::from_utf8(value)
            .map(RawDatabaseMetadataValue::Text)
            .map_err(|_| FixedMetadataAndHeaderObservationError::MalformedMetadata),
        OwnedRawDatabaseMetadataValue::Blob(value) => Ok(RawDatabaseMetadataValue::Blob(value)),
    }
}

pub(super) fn validate_owned_metadata_observation(
    observation: &[OwnedRawDatabaseMetadataValue],
) -> Result<DatabaseMetadataContractV1, FixedMetadataAndHeaderObservationError> {
    let values: Vec<_> = observation
        .iter()
        .map(adapt_owned_value)
        .collect::<Result<_, _>>()?;
    let values: [RawDatabaseMetadataValue<'_>; METADATA_COLUMN_COUNT] = values
        .try_into()
        .map_err(|_| FixedMetadataAndHeaderObservationError::MetadataObservationUnavailable)?;
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
    .map_err(|_| FixedMetadataAndHeaderObservationError::MalformedMetadata)?;

    parsed.validate_structure().map_err(|error| match error {
        MetadataValidationError::UnsupportedMetadataVersion => {
            FixedMetadataAndHeaderObservationError::UnsupportedMetadataContractVersion
        }
        MetadataValidationError::UnsupportedSchemaVersion => {
            FixedMetadataAndHeaderObservationError::UnsupportedDatabaseSchemaVersion
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
            FixedMetadataAndHeaderObservationError::MalformedMetadata
        }
    })
}
