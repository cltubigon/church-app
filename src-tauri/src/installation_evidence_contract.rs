//! Platform-neutral logical installation-evidence contract.
//!
//! Validation in this module is pure and structural. A successful result is not
//! authenticated, loaded from trusted storage, cross-checked against a database,
//! authorized for startup, or converted into operational [`InstallationEvidence`].
//! Encoding is likewise pure and produces only canonical, unauthenticated plaintext.
//! Strict parsing produces a distinct parsed-but-untrusted value; structural
//! validation remains a separate explicit transition.
//! Future authenticated and database-cross-checked boundaries may eventually map
//! their result to that operational model, but this module does not do so.
//!
//! [`InstallationEvidence`]: crate::installation_state::InstallationEvidence

use std::{fmt, num::NonZeroU64};

use crate::storage_foundation::{
    APPLICATION_DATABASE_FORMAT_IDENTITY, ApplicationDatabaseFormatIdentity, ParishIdentifier,
};

pub const PERMANENT_APPLICATION_IDENTIFIER: &str = "io.github.cltubigon.churchapp";
pub const SUPPORTED_EVIDENCE_FORMAT_VERSION: u16 = 1;

pub const ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH: usize = 164;
pub const INSTALLATION_EVIDENCE_V1_PAYLOAD_LENGTH: u16 = 152;

const INSTALLATION_EVIDENCE_ENCODING_MAGIC: [u8; 8] =
    [0x43, 0x48, 0x45, 0x56, 0x49, 0x44, 0x00, 0x01];
const SUPPORTED_INSTALLATION_EVIDENCE_ENCODING_VERSION: u16 = 1;
const ENCODED_APPLICATION_IDENTIFIER: [u8; 29] = *b"io.github.cltubigon.churchapp";
const ENCODED_APPLICATION_IDENTIFIER_LENGTH: u8 = 29;

const ENCODING_MAGIC_OFFSET: usize = 0;
const ENCODING_VERSION_OFFSET: usize = 8;
const PAYLOAD_LENGTH_OFFSET: usize = 10;
const EVIDENCE_FORMAT_IDENTITY_OFFSET: usize = 12;
const EVIDENCE_FORMAT_VERSION_OFFSET: usize = 28;
const APPLICATION_IDENTIFIER_LENGTH_OFFSET: usize = 30;
const APPLICATION_IDENTIFIER_OFFSET: usize = 31;
const APPLICATION_DATABASE_FORMAT_IDENTITY_OFFSET: usize = 60;
const PARISH_IDENTIFIER_OFFSET: usize = 76;
const INSTALLATION_IDENTIFIER_OFFSET: usize = 92;
const INSTALLATION_GENERATION_OFFSET: usize = 108;
const RECOVERY_OR_REPLACEMENT_GENERATION_OFFSET: usize = 116;
const DATABASE_KEY_GENERATION_IDENTIFIER_OFFSET: usize = 124;
const SETUP_PUBLICATION_IDENTIFIER_OFFSET: usize = 140;
const CREATION_TIMESTAMP_OFFSET: usize = 156;

const INSTALLATION_EVIDENCE_FORMAT_IDENTITY_BYTES: [u8; 16] = [
    0x45, 0x56, 0x49, 0x44, 0x45, 0x4e, 0x43, 0x45, 0xa1, 0x57, 0x31, 0xc8, 0x7d, 0x2e, 0x90, 0x04,
];

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EvidenceFormatIdentity([u8; 16]);

pub const INSTALLATION_EVIDENCE_FORMAT_IDENTITY: EvidenceFormatIdentity =
    EvidenceFormatIdentity(INSTALLATION_EVIDENCE_FORMAT_IDENTITY_BYTES);

impl EvidenceFormatIdentity {
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for EvidenceFormatIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EvidenceFormatIdentity(CURRENT)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceFormatVersion(u16);

impl EvidenceFormatVersion {
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermanentApplicationIdentifier(&'static str);

impl PermanentApplicationIdentifier {
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

macro_rules! opaque_identifier {
    ($name:ident, $error_variant:ident, $debug_name:literal) => {
        #[derive(Clone, Copy, Eq, PartialEq)]
        pub struct $name([u8; 16]);

        impl $name {
            pub fn from_bytes(value: [u8; 16]) -> Result<Self, ContractValidationError> {
                if value == [0; 16] {
                    return Err(ContractValidationError::$error_variant);
                }
                Ok(Self(value))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($debug_name, "([REDACTED])"))
            }
        }
    };
}

opaque_identifier!(
    InstallationIdentifier,
    InvalidInstallationIdentifier,
    "InstallationIdentifier"
);
opaque_identifier!(
    DatabaseKeyGenerationIdentifier,
    InvalidDatabaseKeyGenerationIdentifier,
    "DatabaseKeyGenerationIdentifier"
);
opaque_identifier!(
    SetupPublicationIdentifier,
    InvalidSetupPublicationIdentifier,
    "SetupPublicationIdentifier"
);

macro_rules! generation_type {
    ($name:ident, $error_variant:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// The first valid committed generation is 1; zero is invalid.
            pub const INITIAL: Self = Self(NonZeroU64::MIN);

            pub fn new(value: u64) -> Result<Self, ContractValidationError> {
                NonZeroU64::new(value)
                    .map(Self)
                    .ok_or(ContractValidationError::$error_variant)
            }

            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }
    };
}

generation_type!(InstallationGeneration, InvalidInstallationGeneration);
generation_type!(
    RecoveryOrReplacementGeneration,
    InvalidRecoveryOrReplacementGeneration
);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CreationTimestamp(NonZeroU64);

impl CreationTimestamp {
    /// Creates a timestamp represented as whole UTC seconds since the Unix epoch.
    pub fn from_unix_seconds(value: u64) -> Result<Self, ContractValidationError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(ContractValidationError::InvalidCreationTimestamp)
    }

    pub const fn unix_seconds(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractValidationError {
    WrongEvidenceFormatIdentity,
    UnsupportedEvidenceFormatVersion,
    WrongPermanentApplicationIdentifier,
    WrongApplicationDatabaseFormatIdentity,
    InvalidParishIdentifier,
    InvalidInstallationIdentifier,
    InvalidInstallationGeneration,
    InvalidRecoveryOrReplacementGeneration,
    InvalidDatabaseKeyGenerationIdentifier,
    InvalidSetupPublicationIdentifier,
    InvalidCreationTimestamp,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum InstallationEvidenceParseError {
    WrongTotalLength { observed_length: usize },
    WrongEncodingMagic,
    UnsupportedEncodingVersion,
    WrongDeclaredPayloadLength,
    InvalidApplicationIdentifierLength,
    InvalidApplicationIdentifierUtf8,
    InternalFieldBoundaryFailure,
}

impl fmt::Debug for InstallationEvidenceParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongTotalLength { observed_length } => formatter
                .debug_struct("WrongTotalLength")
                .field("observed_length", observed_length)
                .finish(),
            Self::WrongEncodingMagic => formatter.write_str("WrongEncodingMagic"),
            Self::UnsupportedEncodingVersion => formatter.write_str("UnsupportedEncodingVersion"),
            Self::WrongDeclaredPayloadLength => formatter.write_str("WrongDeclaredPayloadLength"),
            Self::InvalidApplicationIdentifierLength => {
                formatter.write_str("InvalidApplicationIdentifierLength")
            }
            Self::InvalidApplicationIdentifierUtf8 => {
                formatter.write_str("InvalidApplicationIdentifierUtf8")
            }
            Self::InternalFieldBoundaryFailure => {
                formatter.write_str("InternalFieldBoundaryFailure")
            }
        }
    }
}

/// Decoded version-1 fields that remain untrusted.
///
/// This type establishes only that the source bytes used the exact supported
/// framing and fixed-width field layout. Its fields are private, its debug
/// representation is redacted, and it has no operational-state conversion.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ParsedUntrustedInstallationEvidenceContract {
    evidence_format_identity: [u8; 16],
    evidence_format_version: u16,
    application_identifier: [u8; 29],
    application_database_format_identity: [u8; 16],
    parish_identifier: [u8; 16],
    installation_identifier: [u8; 16],
    installation_generation: u64,
    recovery_or_replacement_generation: u64,
    database_key_generation_identifier: [u8; 16],
    setup_publication_identifier: [u8; 16],
    creation_timestamp: u64,
}

impl ParsedUntrustedInstallationEvidenceContract {
    /// Strictly parses one exact, untrusted version-1 plaintext record.
    pub fn parse_v1(bytes: &[u8]) -> Result<Self, InstallationEvidenceParseError> {
        if bytes.len() != ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH {
            return Err(InstallationEvidenceParseError::WrongTotalLength {
                observed_length: bytes.len(),
            });
        }

        if read_array::<8>(bytes, ENCODING_MAGIC_OFFSET)? != INSTALLATION_EVIDENCE_ENCODING_MAGIC {
            return Err(InstallationEvidenceParseError::WrongEncodingMagic);
        }
        if read_u16(bytes, ENCODING_VERSION_OFFSET)?
            != SUPPORTED_INSTALLATION_EVIDENCE_ENCODING_VERSION
        {
            return Err(InstallationEvidenceParseError::UnsupportedEncodingVersion);
        }
        if read_u16(bytes, PAYLOAD_LENGTH_OFFSET)? != INSTALLATION_EVIDENCE_V1_PAYLOAD_LENGTH {
            return Err(InstallationEvidenceParseError::WrongDeclaredPayloadLength);
        }
        if bytes[APPLICATION_IDENTIFIER_LENGTH_OFFSET] != ENCODED_APPLICATION_IDENTIFIER_LENGTH {
            return Err(InstallationEvidenceParseError::InvalidApplicationIdentifierLength);
        }

        let application_identifier = read_array::<29>(bytes, APPLICATION_IDENTIFIER_OFFSET)?;
        std::str::from_utf8(&application_identifier)
            .map_err(|_| InstallationEvidenceParseError::InvalidApplicationIdentifierUtf8)?;

        Ok(Self {
            evidence_format_identity: read_array(bytes, EVIDENCE_FORMAT_IDENTITY_OFFSET)?,
            evidence_format_version: read_u16(bytes, EVIDENCE_FORMAT_VERSION_OFFSET)?,
            application_identifier,
            application_database_format_identity: read_array(
                bytes,
                APPLICATION_DATABASE_FORMAT_IDENTITY_OFFSET,
            )?,
            parish_identifier: read_array(bytes, PARISH_IDENTIFIER_OFFSET)?,
            installation_identifier: read_array(bytes, INSTALLATION_IDENTIFIER_OFFSET)?,
            installation_generation: read_u64(bytes, INSTALLATION_GENERATION_OFFSET)?,
            recovery_or_replacement_generation: read_u64(
                bytes,
                RECOVERY_OR_REPLACEMENT_GENERATION_OFFSET,
            )?,
            database_key_generation_identifier: read_array(
                bytes,
                DATABASE_KEY_GENERATION_IDENTIFIER_OFFSET,
            )?,
            setup_publication_identifier: read_array(bytes, SETUP_PUBLICATION_IDENTIFIER_OFFSET)?,
            creation_timestamp: read_u64(bytes, CREATION_TIMESTAMP_OFFSET)?,
        })
    }

    /// Applies the existing logical contract rules to parsed-but-untrusted fields.
    pub fn validate_structure(
        self,
    ) -> Result<StructurallyValidatedInstallationEvidence, ContractValidationError> {
        let application_identifier = std::str::from_utf8(&self.application_identifier)
            .expect("parsed application identifier was UTF-8 validated");
        let parish_identifier_hex = encode_lower_hex(self.parish_identifier);
        let parish_identifier = std::str::from_utf8(&parish_identifier_hex)
            .expect("lowercase hexadecimal is valid UTF-8");

        UnvalidatedInstallationEvidenceContract::new(
            self.evidence_format_identity,
            self.evidence_format_version,
            application_identifier,
            self.application_database_format_identity,
            parish_identifier,
            self.installation_identifier,
            self.installation_generation,
            self.recovery_or_replacement_generation,
            self.database_key_generation_identifier,
            self.setup_publication_identifier,
            self.creation_timestamp,
        )
        .validate()
    }
}

impl fmt::Debug for ParsedUntrustedInstallationEvidenceContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedUntrustedInstallationEvidenceContract")
            .field("evidence_format_identity", &"[REDACTED]")
            .field("evidence_format_version", &self.evidence_format_version)
            .field("application_identifier", &"[REDACTED]")
            .field("application_database_format_identity", &"[REDACTED]")
            .field("parish_identifier", &"[REDACTED]")
            .field("installation_identifier", &"[REDACTED]")
            .field("installation_generation", &self.installation_generation)
            .field(
                "recovery_or_replacement_generation",
                &self.recovery_or_replacement_generation,
            )
            .field("database_key_generation_identifier", &"[REDACTED]")
            .field("setup_publication_identifier", &"[REDACTED]")
            .field("creation_timestamp", &self.creation_timestamp)
            .finish()
    }
}

fn read_array<const LENGTH: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; LENGTH], InstallationEvidenceParseError> {
    bytes
        .get(offset..offset + LENGTH)
        .and_then(|field| field.try_into().ok())
        .ok_or(InstallationEvidenceParseError::InternalFieldBoundaryFailure)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, InstallationEvidenceParseError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, InstallationEvidenceParseError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn encode_lower_hex(bytes: [u8; 16]) -> [u8; 32] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0_u8; 32];
    for (index, byte) in bytes.into_iter().enumerate() {
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    encoded
}

/// Raw logical fields at the untrusted structural-validation boundary.
///
/// The fields are private and have no raw accessors. This type performs no
/// parsing from a serialized representation and has no side effects.
pub struct UnvalidatedInstallationEvidenceContract<'a> {
    evidence_format_identity: [u8; 16],
    evidence_format_version: u16,
    permanent_application_identifier: &'a str,
    application_database_format_identity: [u8; 16],
    parish_identifier: &'a str,
    installation_identifier: [u8; 16],
    installation_generation: u64,
    recovery_or_replacement_generation: u64,
    database_key_generation_identifier: [u8; 16],
    setup_publication_identifier: [u8; 16],
    creation_timestamp_unix_seconds: u64,
}

impl<'a> UnvalidatedInstallationEvidenceContract<'a> {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        evidence_format_identity: [u8; 16],
        evidence_format_version: u16,
        permanent_application_identifier: &'a str,
        application_database_format_identity: [u8; 16],
        parish_identifier: &'a str,
        installation_identifier: [u8; 16],
        installation_generation: u64,
        recovery_or_replacement_generation: u64,
        database_key_generation_identifier: [u8; 16],
        setup_publication_identifier: [u8; 16],
        creation_timestamp_unix_seconds: u64,
    ) -> Self {
        Self {
            evidence_format_identity,
            evidence_format_version,
            permanent_application_identifier,
            application_database_format_identity,
            parish_identifier,
            installation_identifier,
            installation_generation,
            recovery_or_replacement_generation,
            database_key_generation_identifier,
            setup_publication_identifier,
            creation_timestamp_unix_seconds,
        }
    }

    pub fn validate(
        self,
    ) -> Result<StructurallyValidatedInstallationEvidence, ContractValidationError> {
        if self.evidence_format_identity != INSTALLATION_EVIDENCE_FORMAT_IDENTITY_BYTES {
            return Err(ContractValidationError::WrongEvidenceFormatIdentity);
        }
        if self.evidence_format_version != SUPPORTED_EVIDENCE_FORMAT_VERSION {
            return Err(ContractValidationError::UnsupportedEvidenceFormatVersion);
        }
        if self.permanent_application_identifier != PERMANENT_APPLICATION_IDENTIFIER {
            return Err(ContractValidationError::WrongPermanentApplicationIdentifier);
        }
        if self.application_database_format_identity
            != *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes()
        {
            return Err(ContractValidationError::WrongApplicationDatabaseFormatIdentity);
        }

        Ok(StructurallyValidatedInstallationEvidence {
            evidence_format_identity: INSTALLATION_EVIDENCE_FORMAT_IDENTITY,
            evidence_format_version: EvidenceFormatVersion(SUPPORTED_EVIDENCE_FORMAT_VERSION),
            permanent_application_identifier: PermanentApplicationIdentifier(
                PERMANENT_APPLICATION_IDENTIFIER,
            ),
            application_database_format_identity: APPLICATION_DATABASE_FORMAT_IDENTITY,
            parish_identifier: ParishIdentifier::parse(self.parish_identifier)
                .map_err(|_| ContractValidationError::InvalidParishIdentifier)?,
            installation_identifier: InstallationIdentifier::from_bytes(
                self.installation_identifier,
            )?,
            installation_generation: InstallationGeneration::new(self.installation_generation)?,
            recovery_or_replacement_generation: RecoveryOrReplacementGeneration::new(
                self.recovery_or_replacement_generation,
            )?,
            database_key_generation_identifier: DatabaseKeyGenerationIdentifier::from_bytes(
                self.database_key_generation_identifier,
            )?,
            setup_publication_identifier: SetupPublicationIdentifier::from_bytes(
                self.setup_publication_identifier,
            )?,
            creation_timestamp: CreationTimestamp::from_unix_seconds(
                self.creation_timestamp_unix_seconds,
            )?,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StructurallyValidatedInstallationEvidence {
    evidence_format_identity: EvidenceFormatIdentity,
    evidence_format_version: EvidenceFormatVersion,
    permanent_application_identifier: PermanentApplicationIdentifier,
    application_database_format_identity: ApplicationDatabaseFormatIdentity,
    parish_identifier: ParishIdentifier,
    installation_identifier: InstallationIdentifier,
    installation_generation: InstallationGeneration,
    recovery_or_replacement_generation: RecoveryOrReplacementGeneration,
    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
    setup_publication_identifier: SetupPublicationIdentifier,
    creation_timestamp: CreationTimestamp,
}

#[derive(Clone, Eq, PartialEq)]
pub struct EncodedInstallationEvidence {
    bytes: [u8; ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH],
}

impl EncodedInstallationEvidence {
    pub const fn as_bytes(&self) -> &[u8; ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH] {
        &self.bytes
    }
}

impl fmt::Debug for EncodedInstallationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedInstallationEvidence")
            .field("length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl StructurallyValidatedInstallationEvidence {
    /// Produces the canonical, unauthenticated version-1 plaintext encoding.
    pub fn encode_v1(&self) -> EncodedInstallationEvidence {
        let mut bytes = [0_u8; ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH];

        bytes[ENCODING_MAGIC_OFFSET..ENCODING_VERSION_OFFSET]
            .copy_from_slice(&INSTALLATION_EVIDENCE_ENCODING_MAGIC);
        bytes[ENCODING_VERSION_OFFSET..PAYLOAD_LENGTH_OFFSET]
            .copy_from_slice(&SUPPORTED_INSTALLATION_EVIDENCE_ENCODING_VERSION.to_be_bytes());
        bytes[PAYLOAD_LENGTH_OFFSET..EVIDENCE_FORMAT_IDENTITY_OFFSET]
            .copy_from_slice(&INSTALLATION_EVIDENCE_V1_PAYLOAD_LENGTH.to_be_bytes());
        bytes[EVIDENCE_FORMAT_IDENTITY_OFFSET..EVIDENCE_FORMAT_VERSION_OFFSET]
            .copy_from_slice(self.evidence_format_identity.as_bytes());
        bytes[EVIDENCE_FORMAT_VERSION_OFFSET..APPLICATION_IDENTIFIER_LENGTH_OFFSET]
            .copy_from_slice(&self.evidence_format_version.get().to_be_bytes());
        bytes[APPLICATION_IDENTIFIER_LENGTH_OFFSET] = ENCODED_APPLICATION_IDENTIFIER_LENGTH;
        bytes[APPLICATION_IDENTIFIER_OFFSET..APPLICATION_DATABASE_FORMAT_IDENTITY_OFFSET]
            .copy_from_slice(&ENCODED_APPLICATION_IDENTIFIER);
        bytes[APPLICATION_DATABASE_FORMAT_IDENTITY_OFFSET..PARISH_IDENTIFIER_OFFSET]
            .copy_from_slice(self.application_database_format_identity.as_bytes());
        bytes[PARISH_IDENTIFIER_OFFSET..INSTALLATION_IDENTIFIER_OFFSET]
            .copy_from_slice(self.parish_identifier.as_bytes());
        bytes[INSTALLATION_IDENTIFIER_OFFSET..INSTALLATION_GENERATION_OFFSET]
            .copy_from_slice(&self.installation_identifier.0);
        bytes[INSTALLATION_GENERATION_OFFSET..RECOVERY_OR_REPLACEMENT_GENERATION_OFFSET]
            .copy_from_slice(&self.installation_generation.get().to_be_bytes());
        bytes[RECOVERY_OR_REPLACEMENT_GENERATION_OFFSET..DATABASE_KEY_GENERATION_IDENTIFIER_OFFSET]
            .copy_from_slice(&self.recovery_or_replacement_generation.get().to_be_bytes());
        bytes[DATABASE_KEY_GENERATION_IDENTIFIER_OFFSET..SETUP_PUBLICATION_IDENTIFIER_OFFSET]
            .copy_from_slice(&self.database_key_generation_identifier.0);
        bytes[SETUP_PUBLICATION_IDENTIFIER_OFFSET..CREATION_TIMESTAMP_OFFSET]
            .copy_from_slice(&self.setup_publication_identifier.0);
        bytes[CREATION_TIMESTAMP_OFFSET..ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH]
            .copy_from_slice(&self.creation_timestamp.unix_seconds().to_be_bytes());

        EncodedInstallationEvidence { bytes }
    }

    pub const fn evidence_format_identity(&self) -> EvidenceFormatIdentity {
        self.evidence_format_identity
    }

    pub const fn evidence_format_version(&self) -> EvidenceFormatVersion {
        self.evidence_format_version
    }

    pub const fn permanent_application_identifier(&self) -> PermanentApplicationIdentifier {
        self.permanent_application_identifier
    }

    pub const fn application_database_format_identity(&self) -> ApplicationDatabaseFormatIdentity {
        self.application_database_format_identity
    }

    pub const fn parish_identifier(&self) -> ParishIdentifier {
        self.parish_identifier
    }

    pub const fn installation_identifier(&self) -> InstallationIdentifier {
        self.installation_identifier
    }

    pub const fn installation_generation(&self) -> InstallationGeneration {
        self.installation_generation
    }

    pub const fn recovery_or_replacement_generation(&self) -> RecoveryOrReplacementGeneration {
        self.recovery_or_replacement_generation
    }

    pub const fn database_key_generation_identifier(&self) -> DatabaseKeyGenerationIdentifier {
        self.database_key_generation_identifier
    }

    pub const fn setup_publication_identifier(&self) -> SetupPublicationIdentifier {
        self.setup_publication_identifier
    }

    pub const fn creation_timestamp(&self) -> CreationTimestamp {
        self.creation_timestamp
    }
}

impl fmt::Debug for StructurallyValidatedInstallationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StructurallyValidatedInstallationEvidence")
            .field("evidence_format_identity", &self.evidence_format_identity)
            .field("evidence_format_version", &self.evidence_format_version)
            .field(
                "permanent_application_identifier",
                &self.permanent_application_identifier,
            )
            .field("application_database_format_identity", &"[CANONICAL]")
            .field("parish_identifier", &"[REDACTED]")
            .field("installation_identifier", &"[REDACTED]")
            .field("installation_generation", &self.installation_generation)
            .field(
                "recovery_or_replacement_generation",
                &self.recovery_or_replacement_generation,
            )
            .field("database_key_generation_identifier", &"[REDACTED]")
            .field("setup_publication_identifier", &"[REDACTED]")
            .field("creation_timestamp", &self.creation_timestamp)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installation_state::{
        InstallationEvidence, StorageDecision, decide_ordinary_startup,
    };

    const PARISH_IDENTIFIER: &str = "3f6a819cc2044ae3976c5e8b37d29140";
    const INSTALLATION_IDENTIFIER: [u8; 16] = [0x11; 16];
    const DATABASE_KEY_GENERATION_IDENTIFIER: [u8; 16] = [0x22; 16];
    const SETUP_PUBLICATION_IDENTIFIER: [u8; 16] = [0x33; 16];
    const CREATION_TIMESTAMP: u64 = 1_798_000_000;

    const GOLDEN_PARISH_IDENTIFIER: &str = "101112131415161718191a1b1c1d1e1f";
    const GOLDEN_INSTALLATION_IDENTIFIER: [u8; 16] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f,
    ];
    const GOLDEN_DATABASE_KEY_GENERATION_IDENTIFIER: [u8; 16] = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f,
    ];
    const GOLDEN_SETUP_PUBLICATION_IDENTIFIER: [u8; 16] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    const GOLDEN_INSTALLATION_GENERATION: u64 = 0x0102_0304_0506_0708;
    const GOLDEN_RECOVERY_OR_REPLACEMENT_GENERATION: u64 = 0x1112_1314_1516_1718;
    const GOLDEN_CREATION_TIMESTAMP: u64 = 0x2122_2324_2526_2728;

    #[rustfmt::skip]
    const GOLDEN_ENCODING_V1: [u8; ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH] = [
        // Framing: magic, encoding version, payload length.
        0x43, 0x48, 0x45, 0x56, 0x49, 0x44, 0x00, 0x01, 0x00, 0x01, 0x00, 0x98,
        // Evidence-format identity and logical evidence-format version.
        0x45, 0x56, 0x49, 0x44, 0x45, 0x4e, 0x43, 0x45, 0xa1, 0x57, 0x31, 0xc8, 0x7d, 0x2e, 0x90, 0x04,
        0x00, 0x01,
        // Application-identifier length and exact UTF-8 bytes.
        0x1d,
        0x69, 0x6f, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6c, 0x74, 0x75, 0x62, 0x69, 0x67, 0x6f, 0x6e, 0x2e, 0x63, 0x68, 0x75, 0x72, 0x63, 0x68, 0x61, 0x70, 0x70,
        // Application database-format identity.
        0x9c, 0x77, 0x5d, 0x40, 0x36, 0xb1, 0x4f, 0x31, 0xa8, 0x23, 0x6e, 0xd2, 0x58, 0x97, 0x0c, 0x14,
        // Parish identifier.
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        // Installation identifier.
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        // Installation and recovery/replacement generations, big-endian.
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        // Database-key generation and setup publication identifiers.
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        // Creation timestamp, big-endian.
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    ];

    fn candidate() -> UnvalidatedInstallationEvidenceContract<'static> {
        UnvalidatedInstallationEvidenceContract::new(
            *INSTALLATION_EVIDENCE_FORMAT_IDENTITY.as_bytes(),
            SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            PARISH_IDENTIFIER,
            INSTALLATION_IDENTIFIER,
            InstallationGeneration::INITIAL.get(),
            RecoveryOrReplacementGeneration::INITIAL.get(),
            DATABASE_KEY_GENERATION_IDENTIFIER,
            SETUP_PUBLICATION_IDENTIFIER,
            CREATION_TIMESTAMP,
        )
    }

    fn golden_candidate() -> UnvalidatedInstallationEvidenceContract<'static> {
        UnvalidatedInstallationEvidenceContract::new(
            *INSTALLATION_EVIDENCE_FORMAT_IDENTITY.as_bytes(),
            SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            GOLDEN_PARISH_IDENTIFIER,
            GOLDEN_INSTALLATION_IDENTIFIER,
            GOLDEN_INSTALLATION_GENERATION,
            GOLDEN_RECOVERY_OR_REPLACEMENT_GENERATION,
            GOLDEN_DATABASE_KEY_GENERATION_IDENTIFIER,
            GOLDEN_SETUP_PUBLICATION_IDENTIFIER,
            GOLDEN_CREATION_TIMESTAMP,
        )
    }

    fn mutate_golden_byte(index: usize, bit: u8) -> [u8; ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH] {
        let mut mutated = GOLDEN_ENCODING_V1;
        mutated[index] ^= bit;
        assert_ne!(mutated[index], GOLDEN_ENCODING_V1[index]);
        mutated
    }

    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn assert_debug_is_redacted(debug: &str, input: &[u8]) {
        assert!(!debug.contains(PERMANENT_APPLICATION_IDENTIFIER));
        assert!(!debug.contains(GOLDEN_PARISH_IDENTIFIER));
        assert!(!debug.contains(&lower_hex(&GOLDEN_INSTALLATION_IDENTIFIER)));
        assert!(!debug.contains(&lower_hex(&GOLDEN_DATABASE_KEY_GENERATION_IDENTIFIER)));
        assert!(!debug.contains(&lower_hex(&GOLDEN_SETUP_PUBLICATION_IDENTIFIER)));
        assert!(!debug.contains(&format!("{input:?}")));

        if input.len() == ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH {
            for range in [76..92, 92..108, 124..140, 140..156] {
                assert!(!debug.contains(&lower_hex(&input[range.clone()])));
                assert!(!debug.contains(&format!("{:?}", &input[range])));
            }
            if let Ok(application_identifier) = std::str::from_utf8(&input[31..60]) {
                assert!(!debug.contains(application_identifier));
            }
        }
    }

    fn assert_safe_parse_outcome_and_canonicality(input: &[u8]) {
        match ParsedUntrustedInstallationEvidenceContract::parse_v1(input) {
            Ok(parsed) => {
                assert_debug_is_redacted(&format!("{parsed:?}"), input);
                if let Ok(validated) = parsed.validate_structure() {
                    assert_eq!(validated.encode_v1().as_bytes(), input);
                }
            }
            Err(error) => assert_debug_is_redacted(&format!("{error:?}"), input),
        }
    }

    fn deterministic_malformed_input_corpus() -> Vec<Vec<u8>> {
        let mut corpus: Vec<Vec<u8>> = (0..=200).map(|length| vec![0_u8; length]).collect();
        corpus.extend(
            [328, 1024, 4096]
                .into_iter()
                .map(|length| vec![0_u8; length]),
        );
        corpus.push(vec![0_u8; ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH]);
        corpus.push(vec![0xff_u8; ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH]);
        corpus.push(
            (0..ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH)
                .map(|index| if index % 2 == 0 { 0x00 } else { 0xff })
                .collect(),
        );
        corpus.push(
            (0..ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH)
                .map(|index| if index % 2 == 0 { 0xaa } else { 0x55 })
                .collect(),
        );
        corpus.push(GOLDEN_ENCODING_V1.to_vec());
        corpus.extend(
            (0..ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH)
                .map(|index| mutate_golden_byte(index, 0x01).to_vec()),
        );
        corpus.extend((31..60).map(|index| mutate_golden_byte(index, 0x80).to_vec()));

        for (first, second) in [(0, 7), (8, 9), (10, 11), (30, 31)] {
            let mut mutated = GOLDEN_ENCODING_V1;
            mutated[first] ^= 0x01;
            mutated[second] ^= 0x01;
            corpus.push(mutated.to_vec());
        }

        for index in [
            7, 8, 9, 10, 11, 12, 27, 28, 29, 30, 31, 59, 60, 75, 76, 91, 92, 107, 108, 115, 116,
            123, 124, 139, 140, 155, 156, 163,
        ] {
            corpus.push(mutate_golden_byte(index, 0x01).to_vec());
        }
        let mut trailing_byte = GOLDEN_ENCODING_V1.to_vec();
        trailing_byte.push(0x00);
        corpus.push(trailing_byte);

        corpus
    }

    #[test]
    fn malformed_input_hardening_mutates_every_position_and_preserves_boundaries() {
        let golden_validated = golden_candidate()
            .validate()
            .expect("golden contract should be structurally valid");

        for index in 0..ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH {
            let mutated = mutate_golden_byte(index, 0x01);
            let outcome = ParsedUntrustedInstallationEvidenceContract::parse_v1(&mutated);

            match index {
                0..8 => assert_eq!(
                    outcome,
                    Err(InstallationEvidenceParseError::WrongEncodingMagic)
                ),
                8..10 => assert_eq!(
                    outcome,
                    Err(InstallationEvidenceParseError::UnsupportedEncodingVersion)
                ),
                10..12 => assert_eq!(
                    outcome,
                    Err(InstallationEvidenceParseError::WrongDeclaredPayloadLength)
                ),
                30 => assert_eq!(
                    outcome,
                    Err(InstallationEvidenceParseError::InvalidApplicationIdentifierLength)
                ),
                31..60 => {
                    let parsed =
                        outcome.expect("least-significant-bit ASCII mutation should parse");
                    assert_eq!(
                        parsed.validate_structure(),
                        Err(ContractValidationError::WrongPermanentApplicationIdentifier)
                    );
                }
                _ => {
                    let parsed = outcome.expect("logical fixed-width mutation should parse");
                    if let Ok(validated) = parsed.validate_structure() {
                        assert_ne!(validated, golden_validated);
                        assert_eq!(validated.encode_v1().as_bytes(), &mutated);
                    }
                }
            }

            assert_safe_parse_outcome_and_canonicality(&mutated);
        }
    }

    #[test]
    fn malformed_input_hardening_rejects_invalid_utf8_without_identifier_normalization() {
        for index in 31..60 {
            let invalid_utf8 = mutate_golden_byte(index, 0x80);
            let error = ParsedUntrustedInstallationEvidenceContract::parse_v1(&invalid_utf8)
                .expect_err("high-bit application-identifier mutation must fail UTF-8 parsing");
            assert_eq!(
                error,
                InstallationEvidenceParseError::InvalidApplicationIdentifierUtf8
            );
            assert_debug_is_redacted(&format!("{error:?}"), &invalid_utf8);

            let valid_but_different = mutate_golden_byte(index, 0x01);
            let parsed =
                ParsedUntrustedInstallationEvidenceContract::parse_v1(&valid_but_different)
                    .expect("least-significant-bit ASCII mutation should remain valid UTF-8");
            assert_eq!(
                parsed.validate_structure(),
                Err(ContractValidationError::WrongPermanentApplicationIdentifier)
            );
        }
    }

    #[test]
    fn malformed_input_hardening_handles_wrong_lengths_and_patterns_without_panicking() {
        for length in 0..=200 {
            let input = if length == ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH {
                GOLDEN_ENCODING_V1.to_vec()
            } else {
                vec![0_u8; length]
            };
            let outcome = ParsedUntrustedInstallationEvidenceContract::parse_v1(&input);
            if length == ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH {
                assert!(outcome.is_ok());
            } else {
                assert_eq!(
                    outcome,
                    Err(InstallationEvidenceParseError::WrongTotalLength {
                        observed_length: length
                    })
                );
            }
            assert_safe_parse_outcome_and_canonicality(&input);
        }

        for length in [328, 1024, 4096] {
            let input = vec![0_u8; length];
            assert_eq!(
                ParsedUntrustedInstallationEvidenceContract::parse_v1(&input),
                Err(InstallationEvidenceParseError::WrongTotalLength {
                    observed_length: length
                })
            );
            assert_safe_parse_outcome_and_canonicality(&input);
        }

        let patterns = [
            vec![0_u8; ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH],
            vec![0xff_u8; ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH],
            (0..ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH)
                .map(|index| if index % 2 == 0 { 0x00 } else { 0xff })
                .collect(),
            (0..ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH)
                .map(|index| if index % 2 == 0 { 0xaa } else { 0x55 })
                .collect(),
        ];
        for input in patterns {
            assert!(ParsedUntrustedInstallationEvidenceContract::parse_v1(&input).is_err());
            assert_safe_parse_outcome_and_canonicality(&input);
        }
    }

    #[test]
    fn malformed_input_hardening_explicitly_covers_field_boundaries_and_record_end() {
        for index in [
            7, 8, 9, 10, 11, 12, 27, 28, 29, 30, 31, 59, 60, 75, 76, 91, 92, 107, 108, 115, 116,
            123, 124, 139, 140, 155, 156, 163,
        ] {
            let mutated = mutate_golden_byte(index, 0x01);
            assert_ne!(mutated, GOLDEN_ENCODING_V1);
            assert_safe_parse_outcome_and_canonicality(&mutated);
        }

        let mut trailing_byte = GOLDEN_ENCODING_V1.to_vec();
        trailing_byte.push(0x00);
        assert_eq!(
            ParsedUntrustedInstallationEvidenceContract::parse_v1(&trailing_byte),
            Err(InstallationEvidenceParseError::WrongTotalLength {
                observed_length: 165
            })
        );
    }

    #[test]
    fn malformed_input_hardening_rejects_representative_two_byte_framing_mutations() {
        for (first, second, expected) in [
            (0, 7, InstallationEvidenceParseError::WrongEncodingMagic),
            (
                8,
                9,
                InstallationEvidenceParseError::UnsupportedEncodingVersion,
            ),
            (
                10,
                11,
                InstallationEvidenceParseError::WrongDeclaredPayloadLength,
            ),
            (
                30,
                31,
                InstallationEvidenceParseError::InvalidApplicationIdentifierLength,
            ),
        ] {
            let mut mutated = GOLDEN_ENCODING_V1;
            mutated[first] ^= 0x01;
            mutated[second] ^= 0x01;
            let error = ParsedUntrustedInstallationEvidenceContract::parse_v1(&mutated)
                .expect_err("framing mutation must fail at the parse boundary");
            assert_eq!(error, expected);
            assert_debug_is_redacted(&format!("{error:?}"), &mutated);
        }
    }

    #[test]
    fn malformed_input_hardening_corpus_is_safe_redacted_and_canonical() {
        for input in deterministic_malformed_input_corpus() {
            assert_safe_parse_outcome_and_canonicality(&input);
        }
    }

    #[test]
    fn version_1_encoding_matches_exact_layout_and_golden_fixture() {
        let evidence = golden_candidate()
            .validate()
            .expect("golden contract should be structurally valid");
        let encoded = evidence.encode_v1();
        let bytes = encoded.as_bytes();

        assert_eq!(bytes.len(), 164);
        assert_eq!(
            &bytes[0..8],
            &[0x43, 0x48, 0x45, 0x56, 0x49, 0x44, 0x00, 0x01]
        );
        assert_eq!(&bytes[8..10], &1_u16.to_be_bytes());
        assert_eq!(&bytes[10..12], &152_u16.to_be_bytes());
        assert_eq!(
            &bytes[12..28],
            INSTALLATION_EVIDENCE_FORMAT_IDENTITY.as_bytes()
        );
        assert_eq!(&bytes[28..30], &1_u16.to_be_bytes());
        assert_eq!(bytes[30], 29);
        assert_eq!(&bytes[31..60], b"io.github.cltubigon.churchapp");
        assert_eq!(
            &bytes[60..76],
            APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes()
        );
        assert_eq!(&bytes[76..92], &(0x10_u8..=0x1f).collect::<Vec<_>>());
        assert_eq!(&bytes[92..108], &GOLDEN_INSTALLATION_IDENTIFIER);
        assert_eq!(
            &bytes[108..116],
            &GOLDEN_INSTALLATION_GENERATION.to_be_bytes()
        );
        assert_eq!(
            &bytes[116..124],
            &GOLDEN_RECOVERY_OR_REPLACEMENT_GENERATION.to_be_bytes()
        );
        assert_eq!(&bytes[124..140], &GOLDEN_DATABASE_KEY_GENERATION_IDENTIFIER);
        assert_eq!(&bytes[140..156], &GOLDEN_SETUP_PUBLICATION_IDENTIFIER);
        assert_eq!(&bytes[156..164], &GOLDEN_CREATION_TIMESTAMP.to_be_bytes());
        assert_eq!(bytes, &GOLDEN_ENCODING_V1);
    }

    #[test]
    fn version_1_encoding_is_deterministic_and_requires_structural_evidence() {
        let evidence = golden_candidate()
            .validate()
            .expect("golden contract should be structurally valid");
        let encoder: fn(&StructurallyValidatedInstallationEvidence) -> EncodedInstallationEvidence =
            StructurallyValidatedInstallationEvidence::encode_v1;

        assert_eq!(encoder(&evidence), encoder(&evidence));
    }

    #[test]
    fn encoded_debug_reports_only_type_and_length() {
        let encoded = golden_candidate()
            .validate()
            .expect("golden contract should be structurally valid")
            .encode_v1();
        let debug = format!("{encoded:?}");

        assert!(debug.contains("EncodedInstallationEvidence"));
        assert!(debug.contains("164"));
        assert!(!debug.contains("[67, 72, 69, 86"));
        assert!(!debug.contains("101112131415161718191a1b1c1d1e1f"));
        assert!(!debug.contains("32, 33, 34, 35"));
    }

    #[test]
    fn strict_parser_accepts_golden_fixture_and_decodes_every_fixed_offset() {
        let parsed = ParsedUntrustedInstallationEvidenceContract::parse_v1(&GOLDEN_ENCODING_V1)
            .expect("golden bytes should parse");

        assert_eq!(
            parsed.evidence_format_identity,
            *INSTALLATION_EVIDENCE_FORMAT_IDENTITY.as_bytes()
        );
        assert_eq!(parsed.evidence_format_version, 1);
        assert_eq!(
            parsed.application_identifier,
            *b"io.github.cltubigon.churchapp"
        );
        assert_eq!(
            parsed.application_database_format_identity,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes()
        );
        assert_eq!(
            parsed.parish_identifier,
            <[u8; 16]>::try_from(&GOLDEN_ENCODING_V1[76..92]).unwrap()
        );
        assert_eq!(
            parsed.installation_identifier,
            GOLDEN_INSTALLATION_IDENTIFIER
        );
        assert_eq!(
            parsed.installation_generation,
            GOLDEN_INSTALLATION_GENERATION
        );
        assert_eq!(
            parsed.recovery_or_replacement_generation,
            GOLDEN_RECOVERY_OR_REPLACEMENT_GENERATION
        );
        assert_eq!(
            parsed.database_key_generation_identifier,
            GOLDEN_DATABASE_KEY_GENERATION_IDENTIFIER
        );
        assert_eq!(
            parsed.setup_publication_identifier,
            GOLDEN_SETUP_PUBLICATION_IDENTIFIER
        );
        assert_eq!(parsed.creation_timestamp, GOLDEN_CREATION_TIMESTAMP);
    }

    #[test]
    fn golden_parse_structural_validation_and_canonical_round_trip_succeed() {
        let parsed = ParsedUntrustedInstallationEvidenceContract::parse_v1(&GOLDEN_ENCODING_V1)
            .expect("golden bytes should parse");
        let validated = parsed
            .validate_structure()
            .expect("golden parsed fields should validate structurally");

        assert_eq!(validated.encode_v1().as_bytes(), &GOLDEN_ENCODING_V1);
    }

    #[test]
    fn strict_parser_rejects_every_non_exact_total_length() {
        assert_eq!(
            ParsedUntrustedInstallationEvidenceContract::parse_v1(&[]),
            Err(InstallationEvidenceParseError::WrongTotalLength { observed_length: 0 })
        );
        for length in 1..ENCODED_INSTALLATION_EVIDENCE_V1_LENGTH {
            assert_eq!(
                ParsedUntrustedInstallationEvidenceContract::parse_v1(
                    &GOLDEN_ENCODING_V1[..length]
                ),
                Err(InstallationEvidenceParseError::WrongTotalLength {
                    observed_length: length
                })
            );
        }
        for length in [165, 166, 328] {
            let oversized = vec![0_u8; length];
            assert_eq!(
                ParsedUntrustedInstallationEvidenceContract::parse_v1(&oversized),
                Err(InstallationEvidenceParseError::WrongTotalLength {
                    observed_length: length
                })
            );
        }
    }

    #[test]
    fn strict_parser_rejects_wrong_magic_and_each_magic_byte_mutation() {
        let mut wrong_magic = GOLDEN_ENCODING_V1;
        wrong_magic[..8].fill(0);
        assert_eq!(
            ParsedUntrustedInstallationEvidenceContract::parse_v1(&wrong_magic),
            Err(InstallationEvidenceParseError::WrongEncodingMagic)
        );

        for index in 0..8 {
            let mut mutated = GOLDEN_ENCODING_V1;
            mutated[index] ^= 1;
            assert_eq!(
                ParsedUntrustedInstallationEvidenceContract::parse_v1(&mutated),
                Err(InstallationEvidenceParseError::WrongEncodingMagic)
            );
        }
    }

    #[test]
    fn strict_parser_rejects_unsupported_encoding_versions() {
        for version in [0_u16, 2] {
            let mut mutated = GOLDEN_ENCODING_V1;
            mutated[8..10].copy_from_slice(&version.to_be_bytes());
            assert_eq!(
                ParsedUntrustedInstallationEvidenceContract::parse_v1(&mutated),
                Err(InstallationEvidenceParseError::UnsupportedEncodingVersion)
            );
        }
    }

    #[test]
    fn strict_parser_rejects_wrong_declared_payload_lengths() {
        for payload_length in [0_u16, 151, 153] {
            let mut mutated = GOLDEN_ENCODING_V1;
            mutated[10..12].copy_from_slice(&payload_length.to_be_bytes());
            assert_eq!(
                ParsedUntrustedInstallationEvidenceContract::parse_v1(&mutated),
                Err(InstallationEvidenceParseError::WrongDeclaredPayloadLength)
            );
        }
    }

    #[test]
    fn strict_parser_rejects_wrong_application_identifier_lengths_and_invalid_utf8() {
        for identifier_length in [0_u8, 28, 30] {
            let mut mutated = GOLDEN_ENCODING_V1;
            mutated[30] = identifier_length;
            assert_eq!(
                ParsedUntrustedInstallationEvidenceContract::parse_v1(&mutated),
                Err(InstallationEvidenceParseError::InvalidApplicationIdentifierLength)
            );
        }

        let mut invalid_utf8 = GOLDEN_ENCODING_V1;
        invalid_utf8[31] = 0xff;
        assert_eq!(
            ParsedUntrustedInstallationEvidenceContract::parse_v1(&invalid_utf8),
            Err(InstallationEvidenceParseError::InvalidApplicationIdentifierUtf8)
        );
    }

    #[test]
    fn well_framed_logical_mutations_parse_then_fail_structural_validation() {
        let cases: [(usize, usize, ContractValidationError); 9] = [
            (12, 28, ContractValidationError::WrongEvidenceFormatIdentity),
            (
                28,
                30,
                ContractValidationError::UnsupportedEvidenceFormatVersion,
            ),
            (
                31,
                60,
                ContractValidationError::WrongPermanentApplicationIdentifier,
            ),
            (
                60,
                76,
                ContractValidationError::WrongApplicationDatabaseFormatIdentity,
            ),
            (76, 92, ContractValidationError::InvalidParishIdentifier),
            (
                92,
                108,
                ContractValidationError::InvalidInstallationIdentifier,
            ),
            (
                124,
                140,
                ContractValidationError::InvalidDatabaseKeyGenerationIdentifier,
            ),
            (
                140,
                156,
                ContractValidationError::InvalidSetupPublicationIdentifier,
            ),
            (156, 164, ContractValidationError::InvalidCreationTimestamp),
        ];

        for (start, end, expected_error) in cases {
            let mut mutated = GOLDEN_ENCODING_V1;
            mutated[start..end].fill(0);
            if start == 31 {
                mutated[start..end].fill(b'x');
            }
            let parsed = ParsedUntrustedInstallationEvidenceContract::parse_v1(&mutated)
                .expect("logical mutations must retain valid framing");
            assert_eq!(parsed.validate_structure(), Err(expected_error));
        }

        for (start, end, expected_error) in [
            (
                108,
                116,
                ContractValidationError::InvalidInstallationGeneration,
            ),
            (
                116,
                124,
                ContractValidationError::InvalidRecoveryOrReplacementGeneration,
            ),
        ] {
            let mut mutated = GOLDEN_ENCODING_V1;
            mutated[start..end].fill(0);
            let parsed = ParsedUntrustedInstallationEvidenceContract::parse_v1(&mutated)
                .expect("zero generation must parse");
            assert_eq!(parsed.validate_structure(), Err(expected_error));
        }
    }

    #[test]
    fn parsed_and_parse_error_debug_output_do_not_expose_encoded_content() {
        let parsed = ParsedUntrustedInstallationEvidenceContract::parse_v1(&GOLDEN_ENCODING_V1)
            .expect("golden bytes should parse");
        let parsed_debug = format!("{parsed:?}");

        assert!(parsed_debug.contains("ParsedUntrustedInstallationEvidenceContract"));
        assert!(parsed_debug.contains("[REDACTED]"));
        assert!(!parsed_debug.contains("io.github.cltubigon.churchapp"));
        assert!(!parsed_debug.contains("101112131415161718191a1b1c1d1e1f"));
        assert!(!parsed_debug.contains("32, 33, 34, 35"));

        let mut invalid = GOLDEN_ENCODING_V1;
        invalid[0] = 0;
        let error = ParsedUntrustedInstallationEvidenceContract::parse_v1(&invalid)
            .expect_err("wrong magic must fail");
        let error_debug = format!("{error:?}");
        assert_eq!(error_debug, "WrongEncodingMagic");
        assert!(!error_debug.contains("CH EVID"));
        assert!(!error_debug.contains("10111213"));
    }

    #[test]
    fn parser_api_preserves_raw_parsed_structural_and_operational_boundaries() {
        let parser: fn(
            &[u8],
        ) -> Result<
            ParsedUntrustedInstallationEvidenceContract,
            InstallationEvidenceParseError,
        > = ParsedUntrustedInstallationEvidenceContract::parse_v1;
        let structural_transition: fn(
            ParsedUntrustedInstallationEvidenceContract,
        ) -> Result<
            StructurallyValidatedInstallationEvidence,
            ContractValidationError,
        > = ParsedUntrustedInstallationEvidenceContract::validate_structure;
        let operational_boundary: fn(InstallationEvidence) -> StorageDecision =
            decide_ordinary_startup;

        let _ = (parser, structural_transition, operational_boundary);
        // Private parsed fields, the parsed return type, and the separate transition
        // are compile-time API boundaries. No conversion from either parsed or
        // structurally validated evidence to InstallationEvidence exists.
    }

    #[test]
    fn fully_valid_synthetic_contract_is_accepted() {
        let evidence = candidate().validate().expect("contract should be valid");

        assert_eq!(
            evidence.evidence_format_identity(),
            INSTALLATION_EVIDENCE_FORMAT_IDENTITY
        );
        assert_eq!(evidence.evidence_format_version().get(), 1);
        assert_eq!(
            evidence.permanent_application_identifier().as_str(),
            PERMANENT_APPLICATION_IDENTIFIER
        );
        assert_eq!(
            evidence.application_database_format_identity(),
            APPLICATION_DATABASE_FORMAT_IDENTITY
        );
        assert_eq!(evidence.installation_generation().get(), 1);
        assert_eq!(evidence.recovery_or_replacement_generation().get(), 1);
        assert_eq!(
            evidence.creation_timestamp().unix_seconds(),
            CREATION_TIMESTAMP
        );
    }

    #[test]
    fn wrong_permanent_application_identifier_is_rejected() {
        let mut input = candidate();
        input.permanent_application_identifier = "example.invalid.other-app";
        assert_eq!(
            input.validate(),
            Err(ContractValidationError::WrongPermanentApplicationIdentifier)
        );
    }

    #[test]
    fn wrong_application_database_format_identity_is_rejected() {
        let mut input = candidate();
        input.application_database_format_identity = [0x44; 16];
        assert_eq!(
            input.validate(),
            Err(ContractValidationError::WrongApplicationDatabaseFormatIdentity)
        );
    }

    #[test]
    fn wrong_evidence_format_identity_is_rejected() {
        let mut input = candidate();
        input.evidence_format_identity = [0x55; 16];
        assert_eq!(
            input.validate(),
            Err(ContractValidationError::WrongEvidenceFormatIdentity)
        );
    }

    #[test]
    fn zero_and_future_evidence_format_versions_are_rejected() {
        for version in [0, SUPPORTED_EVIDENCE_FORMAT_VERSION + 1] {
            let mut input = candidate();
            input.evidence_format_version = version;
            assert_eq!(
                input.validate(),
                Err(ContractValidationError::UnsupportedEvidenceFormatVersion)
            );
        }
    }

    #[test]
    fn malformed_or_zero_parish_identifier_is_rejected_by_canonical_parser() {
        for parish_identifier in [
            "00000000000000000000000000000000",
            "not-a-parish-identifier",
        ] {
            let mut input = candidate();
            input.parish_identifier = parish_identifier;
            assert_eq!(
                input.validate(),
                Err(ContractValidationError::InvalidParishIdentifier)
            );
        }
    }

    #[test]
    fn zero_opaque_identifiers_are_rejected() {
        let mut installation = candidate();
        installation.installation_identifier = [0; 16];
        assert_eq!(
            installation.validate(),
            Err(ContractValidationError::InvalidInstallationIdentifier)
        );

        let mut database_key = candidate();
        database_key.database_key_generation_identifier = [0; 16];
        assert_eq!(
            database_key.validate(),
            Err(ContractValidationError::InvalidDatabaseKeyGenerationIdentifier)
        );

        let mut publication = candidate();
        publication.setup_publication_identifier = [0; 16];
        assert_eq!(
            publication.validate(),
            Err(ContractValidationError::InvalidSetupPublicationIdentifier)
        );
    }

    #[test]
    fn zero_generations_are_rejected_and_nonzero_generations_are_ordered() {
        let mut installation = candidate();
        installation.installation_generation = 0;
        assert_eq!(
            installation.validate(),
            Err(ContractValidationError::InvalidInstallationGeneration)
        );

        let mut replacement = candidate();
        replacement.recovery_or_replacement_generation = 0;
        assert_eq!(
            replacement.validate(),
            Err(ContractValidationError::InvalidRecoveryOrReplacementGeneration)
        );

        assert!(InstallationGeneration::new(2).unwrap() > InstallationGeneration::INITIAL);
        assert!(
            RecoveryOrReplacementGeneration::new(2).unwrap()
                > RecoveryOrReplacementGeneration::INITIAL
        );
    }

    #[test]
    fn zero_creation_timestamp_is_rejected() {
        let mut input = candidate();
        input.creation_timestamp_unix_seconds = 0;
        assert_eq!(
            input.validate(),
            Err(ContractValidationError::InvalidCreationTimestamp)
        );
    }

    #[test]
    fn structurally_valid_contract_does_not_become_operational_evidence() {
        let structural = candidate().validate().expect("contract should be valid");
        let operational_boundary: fn(InstallationEvidence) -> StorageDecision =
            decide_ordinary_startup;

        let _ = (structural, operational_boundary);
        // There is deliberately no From/TryFrom implementation or function that
        // converts structural evidence into InstallationEvidence. That absence is
        // a compile-time API boundary and cannot be asserted by a runtime call.
    }

    #[test]
    fn debug_output_redacts_sensitive_opaque_identifiers() {
        let evidence = candidate().validate().expect("contract should be valid");
        let debug = format!("{evidence:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(PARISH_IDENTIFIER));
        assert!(!debug.contains("11111111111111111111111111111111"));
        assert!(!debug.contains("22222222222222222222222222222222"));
        assert!(!debug.contains("33333333333333333333333333333333"));
        assert!(!debug.contains("[63, 106, 129"));
        assert!(!debug.contains("[17, 17"));
        assert!(!debug.contains("[34, 34"));
        assert!(!debug.contains("[51, 51"));
        assert_eq!(
            format!("{:?}", evidence.installation_identifier()),
            "InstallationIdentifier([REDACTED])"
        );
    }

    #[test]
    fn validation_is_pure_and_requires_no_external_state() {
        let first = candidate().validate().expect("contract should be valid");
        let second = candidate().validate().expect("contract should be valid");

        assert_eq!(first, second);
    }
}
