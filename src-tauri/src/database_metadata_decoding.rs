//! Pure decoding and structural validation for one version-1 metadata observation.
//!
//! The raw boundary preserves storage classes without depending on a database
//! library. Parsing establishes only storage class, width, length, and integer
//! representation. A separate transition applies the approved structural rules.

// This module intentionally has no production caller until a separately approved
// database adapter stage exists.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_metadata_contract::{DatabaseCreationTimestamp, DatabaseMetadataContractV1},
    installation_evidence_contract::{
        DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
        PermanentApplicationIdentifier, RecoveryOrReplacementGeneration,
        SetupPublicationIdentifier,
    },
    storage_foundation::{APPLICATION_DATABASE_FORMAT_IDENTITY, ParishIdentifier},
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RawDatabaseMetadataValue<'a> {
    Integer(i64),
    Text(&'a str),
    Blob(&'a [u8]),
    Null,
}

impl fmt::Debug for RawDatabaseMetadataValue<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let storage_class = match self {
            Self::Integer(_) => "Integer",
            Self::Text(_) => "Text",
            Self::Blob(_) => "Blob",
            Self::Null => "Null",
        };
        write!(
            formatter,
            "RawDatabaseMetadataValue::{storage_class}([REDACTED])"
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RawDatabaseMetadataRow<'a> {
    singleton_id: RawDatabaseMetadataValue<'a>,
    metadata_contract_version: RawDatabaseMetadataValue<'a>,
    database_schema_version: RawDatabaseMetadataValue<'a>,
    permanent_application_identifier: RawDatabaseMetadataValue<'a>,
    database_format_identity: RawDatabaseMetadataValue<'a>,
    parish_identifier: RawDatabaseMetadataValue<'a>,
    installation_identifier: RawDatabaseMetadataValue<'a>,
    installation_generation: RawDatabaseMetadataValue<'a>,
    recovery_replacement_generation: RawDatabaseMetadataValue<'a>,
    database_key_generation_identifier: RawDatabaseMetadataValue<'a>,
    setup_publication_identifier: RawDatabaseMetadataValue<'a>,
    database_created_at: RawDatabaseMetadataValue<'a>,
}

impl<'a> RawDatabaseMetadataRow<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        singleton_id: RawDatabaseMetadataValue<'a>,
        metadata_contract_version: RawDatabaseMetadataValue<'a>,
        database_schema_version: RawDatabaseMetadataValue<'a>,
        permanent_application_identifier: RawDatabaseMetadataValue<'a>,
        database_format_identity: RawDatabaseMetadataValue<'a>,
        parish_identifier: RawDatabaseMetadataValue<'a>,
        installation_identifier: RawDatabaseMetadataValue<'a>,
        installation_generation: RawDatabaseMetadataValue<'a>,
        recovery_replacement_generation: RawDatabaseMetadataValue<'a>,
        database_key_generation_identifier: RawDatabaseMetadataValue<'a>,
        setup_publication_identifier: RawDatabaseMetadataValue<'a>,
        database_created_at: RawDatabaseMetadataValue<'a>,
    ) -> Self {
        Self {
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
        }
    }

    pub(crate) fn parse(self) -> Result<ParsedUntrustedDatabaseMetadataV1<'a>, MetadataParseError> {
        Ok(ParsedUntrustedDatabaseMetadataV1 {
            singleton_id: parse_u8(self.singleton_id)?,
            metadata_contract_version: parse_u16(self.metadata_contract_version)?,
            database_schema_version: parse_u16(self.database_schema_version)?,
            permanent_application_identifier: parse_text(self.permanent_application_identifier)?,
            database_format_identity: parse_blob_16(self.database_format_identity)?,
            parish_identifier: parse_blob_16(self.parish_identifier)?,
            installation_identifier: parse_blob_16(self.installation_identifier)?,
            installation_generation: parse_generation(self.installation_generation)?,
            recovery_replacement_generation: parse_generation(
                self.recovery_replacement_generation,
            )?,
            database_key_generation_identifier: parse_blob_16(
                self.database_key_generation_identifier,
            )?,
            setup_publication_identifier: parse_blob_16(self.setup_publication_identifier)?,
            database_created_at: parse_u64(self.database_created_at)?,
        })
    }
}

impl fmt::Debug for RawDatabaseMetadataRow<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawDatabaseMetadataRow([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ParsedUntrustedDatabaseMetadataV1<'a> {
    singleton_id: u8,
    metadata_contract_version: u16,
    database_schema_version: u16,
    permanent_application_identifier: &'a str,
    database_format_identity: [u8; 16],
    parish_identifier: [u8; 16],
    installation_identifier: [u8; 16],
    installation_generation: u64,
    recovery_replacement_generation: u64,
    database_key_generation_identifier: [u8; 16],
    setup_publication_identifier: [u8; 16],
    database_created_at: u64,
}

impl<'a> ParsedUntrustedDatabaseMetadataV1<'a> {
    pub(crate) fn validate_structure(
        self,
    ) -> Result<DatabaseMetadataContractV1, MetadataValidationError> {
        if self.singleton_id != 1 {
            return Err(MetadataValidationError::WrongSingleton);
        }
        if self.metadata_contract_version != 1 {
            return Err(MetadataValidationError::UnsupportedMetadataVersion);
        }
        if self.database_schema_version != 1 {
            return Err(MetadataValidationError::UnsupportedSchemaVersion);
        }

        let permanent_application_identifier = PermanentApplicationIdentifier::canonical();
        if self.permanent_application_identifier != permanent_application_identifier.as_str() {
            return Err(MetadataValidationError::WrongApplicationIdentifier);
        }
        if self.database_format_identity != *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes() {
            return Err(MetadataValidationError::WrongDatabaseFormatIdentity);
        }

        let parish_identifier = ParishIdentifier::from_bytes(self.parish_identifier)
            .map_err(|_| MetadataValidationError::InvalidParishIdentifier)?;
        let installation_identifier =
            InstallationIdentifier::from_bytes(self.installation_identifier)
                .map_err(|_| MetadataValidationError::InvalidInstallationIdentifier)?;
        let installation_generation = InstallationGeneration::new(self.installation_generation)
            .map_err(|_| MetadataValidationError::InvalidInstallationGeneration)?;
        let recovery_replacement_generation =
            RecoveryOrReplacementGeneration::new(self.recovery_replacement_generation)
                .map_err(|_| MetadataValidationError::InvalidRecoveryReplacementGeneration)?;
        let database_key_generation_identifier =
            DatabaseKeyGenerationIdentifier::from_bytes(self.database_key_generation_identifier)
                .map_err(|_| MetadataValidationError::InvalidDatabaseKeyGenerationIdentifier)?;
        let setup_publication_identifier =
            SetupPublicationIdentifier::from_bytes(self.setup_publication_identifier)
                .map_err(|_| MetadataValidationError::InvalidSetupPublicationIdentifier)?;

        Ok(DatabaseMetadataContractV1::new(
            permanent_application_identifier,
            parish_identifier,
            installation_identifier,
            installation_generation,
            recovery_replacement_generation,
            database_key_generation_identifier,
            setup_publication_identifier,
            DatabaseCreationTimestamp::from_unix_milliseconds(self.database_created_at),
        ))
    }
}

impl fmt::Debug for ParsedUntrustedDatabaseMetadataV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParsedUntrustedDatabaseMetadataV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MetadataParseError {
    WrongStorageClass,
    WrongLength,
    IntegerOutOfRange,
}

impl fmt::Debug for MetadataParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongStorageClass => "MetadataParseError::WrongStorageClass",
            Self::WrongLength => "MetadataParseError::WrongLength",
            Self::IntegerOutOfRange => "MetadataParseError::IntegerOutOfRange",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MetadataValidationError {
    WrongSingleton,
    UnsupportedMetadataVersion,
    UnsupportedSchemaVersion,
    WrongApplicationIdentifier,
    WrongDatabaseFormatIdentity,
    InvalidParishIdentifier,
    InvalidInstallationIdentifier,
    InvalidInstallationGeneration,
    InvalidRecoveryReplacementGeneration,
    InvalidDatabaseKeyGenerationIdentifier,
    InvalidSetupPublicationIdentifier,
}

impl fmt::Debug for MetadataValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongSingleton => "MetadataValidationError::WrongSingleton",
            Self::UnsupportedMetadataVersion => {
                "MetadataValidationError::UnsupportedMetadataVersion"
            }
            Self::UnsupportedSchemaVersion => "MetadataValidationError::UnsupportedSchemaVersion",
            Self::WrongApplicationIdentifier => {
                "MetadataValidationError::WrongApplicationIdentifier"
            }
            Self::WrongDatabaseFormatIdentity => {
                "MetadataValidationError::WrongDatabaseFormatIdentity"
            }
            Self::InvalidParishIdentifier => "MetadataValidationError::InvalidParishIdentifier",
            Self::InvalidInstallationIdentifier => {
                "MetadataValidationError::InvalidInstallationIdentifier"
            }
            Self::InvalidInstallationGeneration => {
                "MetadataValidationError::InvalidInstallationGeneration"
            }
            Self::InvalidRecoveryReplacementGeneration => {
                "MetadataValidationError::InvalidRecoveryReplacementGeneration"
            }
            Self::InvalidDatabaseKeyGenerationIdentifier => {
                "MetadataValidationError::InvalidDatabaseKeyGenerationIdentifier"
            }
            Self::InvalidSetupPublicationIdentifier => {
                "MetadataValidationError::InvalidSetupPublicationIdentifier"
            }
        })
    }
}

fn parse_integer(value: RawDatabaseMetadataValue<'_>) -> Result<i64, MetadataParseError> {
    match value {
        RawDatabaseMetadataValue::Integer(value) => Ok(value),
        _ => Err(MetadataParseError::WrongStorageClass),
    }
}

fn parse_u8(value: RawDatabaseMetadataValue<'_>) -> Result<u8, MetadataParseError> {
    u8::try_from(parse_integer(value)?).map_err(|_| MetadataParseError::IntegerOutOfRange)
}

fn parse_u16(value: RawDatabaseMetadataValue<'_>) -> Result<u16, MetadataParseError> {
    u16::try_from(parse_integer(value)?).map_err(|_| MetadataParseError::IntegerOutOfRange)
}

fn parse_u64(value: RawDatabaseMetadataValue<'_>) -> Result<u64, MetadataParseError> {
    u64::try_from(parse_integer(value)?).map_err(|_| MetadataParseError::IntegerOutOfRange)
}

fn parse_text(value: RawDatabaseMetadataValue<'_>) -> Result<&str, MetadataParseError> {
    match value {
        RawDatabaseMetadataValue::Text(value) => Ok(value),
        _ => Err(MetadataParseError::WrongStorageClass),
    }
}

fn parse_blob_16(value: RawDatabaseMetadataValue<'_>) -> Result<[u8; 16], MetadataParseError> {
    let RawDatabaseMetadataValue::Blob(value) = value else {
        return Err(MetadataParseError::WrongStorageClass);
    };
    value
        .try_into()
        .map_err(|_| MetadataParseError::WrongLength)
}

fn parse_generation(value: RawDatabaseMetadataValue<'_>) -> Result<u64, MetadataParseError> {
    let RawDatabaseMetadataValue::Blob(value) = value else {
        return Err(MetadataParseError::WrongStorageClass);
    };
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| MetadataParseError::WrongLength)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installation_evidence_contract::PERMANENT_APPLICATION_IDENTIFIER;

    const PARISH: [u8; 16] = [0x11; 16];
    const INSTALLATION: [u8; 16] = [0x22; 16];
    const KEY_GENERATION: [u8; 16] = [0x33; 16];
    const PUBLICATION: [u8; 16] = [0x44; 16];
    const INSTALLATION_GENERATION: [u8; 8] = 0x0102_0304_0506_0708_u64.to_be_bytes();
    const REPLACEMENT_GENERATION: [u8; 8] = 0x1112_1314_1516_1718_u64.to_be_bytes();
    const CREATED_AT: i64 = 1_798_000_000_123;
    const SHORT_BLOB: [u8; 15] = [0x55; 15];
    const LONG_BLOB: [u8; 17] = [0x66; 17];
    const SHORT_GENERATION: [u8; 7] = [0x77; 7];
    const LONG_GENERATION: [u8; 9] = [0x88; 9];
    const UNSIGNED_BIG_ENDIAN_GENERATION: [u8; 8] =
        [0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const WRONG_DATABASE_FORMAT: [u8; 16] = [0x99; 16];

    #[derive(Clone, Copy)]
    enum Field {
        Singleton,
        MetadataVersion,
        SchemaVersion,
        ApplicationIdentifier,
        DatabaseFormat,
        Parish,
        Installation,
        InstallationGeneration,
        ReplacementGeneration,
        KeyGeneration,
        Publication,
        CreatedAt,
    }

    const ALL_FIELDS: [Field; 12] = [
        Field::Singleton,
        Field::MetadataVersion,
        Field::SchemaVersion,
        Field::ApplicationIdentifier,
        Field::DatabaseFormat,
        Field::Parish,
        Field::Installation,
        Field::InstallationGeneration,
        Field::ReplacementGeneration,
        Field::KeyGeneration,
        Field::Publication,
        Field::CreatedAt,
    ];

    fn canonical_row() -> RawDatabaseMetadataRow<'static> {
        RawDatabaseMetadataRow::new(
            RawDatabaseMetadataValue::Integer(1),
            RawDatabaseMetadataValue::Integer(1),
            RawDatabaseMetadataValue::Integer(1),
            RawDatabaseMetadataValue::Text(PERMANENT_APPLICATION_IDENTIFIER),
            RawDatabaseMetadataValue::Blob(APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes()),
            RawDatabaseMetadataValue::Blob(&PARISH),
            RawDatabaseMetadataValue::Blob(&INSTALLATION),
            RawDatabaseMetadataValue::Blob(&INSTALLATION_GENERATION),
            RawDatabaseMetadataValue::Blob(&REPLACEMENT_GENERATION),
            RawDatabaseMetadataValue::Blob(&KEY_GENERATION),
            RawDatabaseMetadataValue::Blob(&PUBLICATION),
            RawDatabaseMetadataValue::Integer(CREATED_AT),
        )
    }

    fn replace(
        mut row: RawDatabaseMetadataRow<'static>,
        field: Field,
        value: RawDatabaseMetadataValue<'static>,
    ) -> RawDatabaseMetadataRow<'static> {
        match field {
            Field::Singleton => row.singleton_id = value,
            Field::MetadataVersion => row.metadata_contract_version = value,
            Field::SchemaVersion => row.database_schema_version = value,
            Field::ApplicationIdentifier => row.permanent_application_identifier = value,
            Field::DatabaseFormat => row.database_format_identity = value,
            Field::Parish => row.parish_identifier = value,
            Field::Installation => row.installation_identifier = value,
            Field::InstallationGeneration => row.installation_generation = value,
            Field::ReplacementGeneration => row.recovery_replacement_generation = value,
            Field::KeyGeneration => row.database_key_generation_identifier = value,
            Field::Publication => row.setup_publication_identifier = value,
            Field::CreatedAt => row.database_created_at = value,
        }
        row
    }

    fn parse_error(field: Field, value: RawDatabaseMetadataValue<'static>) -> MetadataParseError {
        replace(canonical_row(), field, value)
            .parse()
            .expect_err("malformed raw observation should fail parsing")
    }

    fn validation_error(
        field: Field,
        value: RawDatabaseMetadataValue<'static>,
    ) -> MetadataValidationError {
        replace(canonical_row(), field, value)
            .parse()
            .expect("structurally invalid value should remain parseable")
            .validate_structure()
            .expect_err("structurally invalid value should fail validation")
    }

    fn require_exact_contract_type(_: DatabaseMetadataContractV1) {}

    #[test]
    fn canonical_observation_parses_and_validates_to_exact_existing_contract() {
        let parsed = canonical_row().parse().expect("canonical row should parse");
        let contract = parsed
            .validate_structure()
            .expect("canonical row should validate");

        require_exact_contract_type(contract);
        assert_eq!(contract.singleton_id().get(), 1);
        assert_eq!(contract.metadata_contract_version().get(), 1);
        assert_eq!(contract.database_schema_version().get(), 1);
        assert_eq!(
            contract.permanent_application_identifier().as_str(),
            PERMANENT_APPLICATION_IDENTIFIER
        );
        assert_eq!(
            contract.database_format_identity(),
            APPLICATION_DATABASE_FORMAT_IDENTITY
        );
        assert_eq!(
            contract.parish_identifier(),
            ParishIdentifier::from_bytes(PARISH).unwrap()
        );
        assert_eq!(
            contract.installation_identifier(),
            InstallationIdentifier::from_bytes(INSTALLATION).unwrap()
        );
        assert_eq!(
            contract.installation_generation().get(),
            u64::from_be_bytes(INSTALLATION_GENERATION)
        );
        assert_eq!(
            contract.recovery_replacement_generation().get(),
            u64::from_be_bytes(REPLACEMENT_GENERATION)
        );
        assert_eq!(
            contract.database_key_generation_identifier(),
            DatabaseKeyGenerationIdentifier::from_bytes(KEY_GENERATION).unwrap()
        );
        assert_eq!(
            contract.setup_publication_identifier(),
            SetupPublicationIdentifier::from_bytes(PUBLICATION).unwrap()
        );
        assert_eq!(
            contract.database_created_at().unix_milliseconds(),
            CREATED_AT as u64
        );
    }

    #[test]
    fn every_field_rejects_every_incorrect_storage_class_and_null() {
        let integer_fields = [
            Field::Singleton,
            Field::MetadataVersion,
            Field::SchemaVersion,
            Field::CreatedAt,
        ];
        for field in integer_fields {
            for wrong in [
                RawDatabaseMetadataValue::Text("1"),
                RawDatabaseMetadataValue::Blob(&INSTALLATION_GENERATION),
                RawDatabaseMetadataValue::Null,
            ] {
                assert_eq!(
                    parse_error(field, wrong),
                    MetadataParseError::WrongStorageClass
                );
            }
        }

        for wrong in [
            RawDatabaseMetadataValue::Integer(1),
            RawDatabaseMetadataValue::Blob(PERMANENT_APPLICATION_IDENTIFIER.as_bytes()),
            RawDatabaseMetadataValue::Null,
        ] {
            assert_eq!(
                parse_error(Field::ApplicationIdentifier, wrong),
                MetadataParseError::WrongStorageClass
            );
        }

        let blob_fields = [
            Field::DatabaseFormat,
            Field::Parish,
            Field::Installation,
            Field::InstallationGeneration,
            Field::ReplacementGeneration,
            Field::KeyGeneration,
            Field::Publication,
        ];
        for field in blob_fields {
            for wrong in [
                RawDatabaseMetadataValue::Integer(1),
                RawDatabaseMetadataValue::Text("opaque"),
                RawDatabaseMetadataValue::Null,
            ] {
                assert_eq!(
                    parse_error(field, wrong),
                    MetadataParseError::WrongStorageClass
                );
            }
        }

        for field in ALL_FIELDS {
            assert_eq!(
                parse_error(field, RawDatabaseMetadataValue::Null),
                MetadataParseError::WrongStorageClass
            );
        }
    }

    #[test]
    fn every_sixteen_byte_field_rejects_fifteen_and_seventeen_bytes() {
        for field in [
            Field::DatabaseFormat,
            Field::Parish,
            Field::Installation,
            Field::KeyGeneration,
            Field::Publication,
        ] {
            assert_eq!(
                parse_error(field, RawDatabaseMetadataValue::Blob(&SHORT_BLOB)),
                MetadataParseError::WrongLength
            );
            assert_eq!(
                parse_error(field, RawDatabaseMetadataValue::Blob(&LONG_BLOB)),
                MetadataParseError::WrongLength
            );
        }
    }

    #[test]
    fn database_format_identity_rejects_all_text_paths() {
        for text in [
            "9c775d4036b14f31a8236ed258970c14",
            "9c775d40-36b1-4f31-a823-6ed258970c14",
            "nHddQDaxtDGoI27SWJcMFA==",
        ] {
            assert_eq!(
                parse_error(Field::DatabaseFormat, RawDatabaseMetadataValue::Text(text)),
                MetadataParseError::WrongStorageClass
            );
        }
    }

    #[test]
    fn generations_require_exact_eight_byte_blobs_and_decode_unsigned_big_endian() {
        for field in [Field::InstallationGeneration, Field::ReplacementGeneration] {
            assert_eq!(
                parse_error(field, RawDatabaseMetadataValue::Blob(&SHORT_GENERATION)),
                MetadataParseError::WrongLength
            );
            assert_eq!(
                parse_error(field, RawDatabaseMetadataValue::Blob(&LONG_GENERATION)),
                MetadataParseError::WrongLength
            );
        }

        let contract = replace(
            canonical_row(),
            Field::InstallationGeneration,
            RawDatabaseMetadataValue::Blob(&UNSIGNED_BIG_ENDIAN_GENERATION),
        )
        .parse()
        .unwrap()
        .validate_structure()
        .unwrap();
        assert_eq!(
            contract.installation_generation().get(),
            0x8001_0203_0405_0607
        );
        assert_ne!(
            contract.installation_generation().get(),
            u64::from_le_bytes(UNSIGNED_BIG_ENDIAN_GENERATION)
        );
    }

    #[test]
    fn negative_and_width_exceeding_integer_values_fail_parsing() {
        for field in [
            Field::Singleton,
            Field::MetadataVersion,
            Field::SchemaVersion,
            Field::CreatedAt,
        ] {
            assert_eq!(
                parse_error(field, RawDatabaseMetadataValue::Integer(-1)),
                MetadataParseError::IntegerOutOfRange
            );
        }
        assert_eq!(
            parse_error(Field::Singleton, RawDatabaseMetadataValue::Integer(256)),
            MetadataParseError::IntegerOutOfRange
        );
        for field in [Field::MetadataVersion, Field::SchemaVersion] {
            assert_eq!(
                parse_error(field, RawDatabaseMetadataValue::Integer(65_536)),
                MetadataParseError::IntegerOutOfRange
            );
        }
    }

    #[test]
    fn unsupported_singleton_and_versions_parse_then_fail_structural_validation() {
        for value in [0, 2, 255] {
            assert_eq!(
                validation_error(Field::Singleton, RawDatabaseMetadataValue::Integer(value)),
                MetadataValidationError::WrongSingleton
            );
        }
        for value in [0, 2, 65_535] {
            assert_eq!(
                validation_error(
                    Field::MetadataVersion,
                    RawDatabaseMetadataValue::Integer(value)
                ),
                MetadataValidationError::UnsupportedMetadataVersion
            );
            assert_eq!(
                validation_error(
                    Field::SchemaVersion,
                    RawDatabaseMetadataValue::Integer(value)
                ),
                MetadataValidationError::UnsupportedSchemaVersion
            );
        }
    }

    #[test]
    fn noncanonical_application_and_database_format_identities_fail_validation() {
        for text in [
            " io.github.cltubigon.churchapp",
            "IO.GITHUB.CLTUBIGON.CHURCHAPP",
            "io.github.cltubigon.churchapp ",
        ] {
            assert_eq!(
                validation_error(
                    Field::ApplicationIdentifier,
                    RawDatabaseMetadataValue::Text(text)
                ),
                MetadataValidationError::WrongApplicationIdentifier
            );
        }
        assert_eq!(
            validation_error(
                Field::DatabaseFormat,
                RawDatabaseMetadataValue::Blob(&WRONG_DATABASE_FORMAT)
            ),
            MetadataValidationError::WrongDatabaseFormatIdentity
        );
    }

    #[test]
    fn zero_identifiers_and_generations_parse_then_fail_validation() {
        const ZERO_16: [u8; 16] = [0; 16];
        const ZERO_8: [u8; 8] = [0; 8];
        for (field, expected) in [
            (
                Field::Parish,
                MetadataValidationError::InvalidParishIdentifier,
            ),
            (
                Field::Installation,
                MetadataValidationError::InvalidInstallationIdentifier,
            ),
            (
                Field::KeyGeneration,
                MetadataValidationError::InvalidDatabaseKeyGenerationIdentifier,
            ),
            (
                Field::Publication,
                MetadataValidationError::InvalidSetupPublicationIdentifier,
            ),
        ] {
            assert_eq!(
                validation_error(field, RawDatabaseMetadataValue::Blob(&ZERO_16)),
                expected
            );
        }
        assert_eq!(
            validation_error(
                Field::InstallationGeneration,
                RawDatabaseMetadataValue::Blob(&ZERO_8)
            ),
            MetadataValidationError::InvalidInstallationGeneration
        );
        assert_eq!(
            validation_error(
                Field::ReplacementGeneration,
                RawDatabaseMetadataValue::Blob(&ZERO_8)
            ),
            MetadataValidationError::InvalidRecoveryReplacementGeneration
        );
    }

    #[test]
    fn creation_timestamp_accepts_zero_and_representative_positive_value() {
        for value in [0, CREATED_AT] {
            let contract = replace(
                canonical_row(),
                Field::CreatedAt,
                RawDatabaseMetadataValue::Integer(value),
            )
            .parse()
            .unwrap()
            .validate_structure()
            .unwrap();
            assert_eq!(
                contract.database_created_at().unix_milliseconds(),
                value as u64
            );
        }
    }

    #[test]
    fn errors_and_untrusted_observations_have_payload_free_redacted_debug() {
        assert_eq!(
            format!("{:?}", MetadataParseError::WrongLength),
            "MetadataParseError::WrongLength"
        );
        assert_eq!(
            format!("{:?}", MetadataValidationError::WrongApplicationIdentifier),
            "MetadataValidationError::WrongApplicationIdentifier"
        );
        for value in [
            RawDatabaseMetadataValue::Integer(CREATED_AT),
            RawDatabaseMetadataValue::Text(PERMANENT_APPLICATION_IDENTIFIER),
            RawDatabaseMetadataValue::Blob(&PARISH),
            RawDatabaseMetadataValue::Null,
        ] {
            let debug = format!("{value:?}");
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains(&CREATED_AT.to_string()));
            assert!(!debug.contains(PERMANENT_APPLICATION_IDENTIFIER));
            assert!(!debug.contains("17, 17, 17"));
        }
        assert_eq!(
            format!("{:?}", canonical_row()),
            "RawDatabaseMetadataRow([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", canonical_row().parse().unwrap()),
            "ParsedUntrustedDatabaseMetadataV1([REDACTED])"
        );
    }

    #[test]
    fn source_boundary_has_exact_types_transitions_and_no_forbidden_capability() {
        const SOURCE: &str = include_str!("database_metadata_decoding.rs");
        const LIB_SOURCE: &str = include_str!("lib.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let raw_row_body = production
            .split_once("pub(crate) struct RawDatabaseMetadataRow<'a> {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let parsed_body = production
            .split_once("pub(crate) struct ParsedUntrustedDatabaseMetadataV1<'a> {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;

        assert_eq!(
            production
                .matches("enum RawDatabaseMetadataValue<'a>")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches("struct RawDatabaseMetadataRow<'a>")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches("struct ParsedUntrustedDatabaseMetadataV1<'a>")
                .count(),
            1
        );
        assert_eq!(production.matches("pub(crate) fn parse(self)").count(), 1);
        assert_eq!(
            production
                .matches("pub(crate) fn validate_structure(")
                .count(),
            1
        );
        assert_eq!(
            raw_row_body
                .lines()
                .filter(|line| line.contains(':'))
                .count(),
            12
        );
        assert_eq!(parsed_body.matches("[u8; 16]").count(), 5);
        assert_eq!(production.matches("u64::from_be_bytes(bytes)").count(), 1);
        assert_eq!(
            LIB_SOURCE
                .matches("mod database_metadata_decoding;")
                .count(),
            1
        );
        assert_eq!(LIB_SOURCE.matches("RawDatabaseMetadataValue").count(), 0);
        assert_eq!(LIB_SOURCE.matches("RawDatabaseMetadataRow").count(), 0);
        assert_eq!(
            LIB_SOURCE
                .matches("ParsedUntrustedDatabaseMetadataV1")
                .count(),
            0
        );

        for forbidden in [
            ["rusq", "lite"].concat(),
            ["sql", "x"].concat(),
            ["std", "::fs"].concat(),
            ["std", "::path"].concat(),
            ["std", "::env"].concat(),
            ["std", "::time"].concat(),
            ["get", "random"].concat(),
            ["rand", "::"].concat(),
            ["windows", "::"].concat(),
            ["tauri", "::"].concat(),
            ["unsafe", " {"].concat(),
            ["Hash", "Map"].concat(),
            ["BTree", "Map"].concat(),
            ["serde", "::"].concat(),
            ["application", "_id ="].concat(),
            ["user", "_version"].concat(),
            ["evidence", "_format"].concat(),
            ["key", "_bytes"].concat(),
        ] {
            assert!(
                !production.contains(&forbidden),
                "unexpected capability in production boundary"
            );
        }
    }
}
