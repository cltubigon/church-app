//! Canonical version-1 plaintext encoding for the pure freshness anchor.
//!
//! Parsing establishes framing only. Structural validation is a separate
//! transition into the existing semantic contract.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    freshness_anchor_contract::FreshnessAnchorContractV1,
    installation_evidence_contract::{
        DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
        RecoveryOrReplacementGeneration, SetupPublicationIdentifier,
    },
};

pub(crate) const SEMANTIC_PAYLOAD_LENGTH: usize = 64;
pub(crate) const PLAINTEXT_LENGTH: usize = 76;
const MAGIC: [u8; 8] = [0x43, 0x48, 0x41, 0x4e, 0x43, 0x52, 0x00, 0x01];
const VERSION: u16 = 1;
const DECLARED_PAYLOAD_LENGTH: u16 = 64;

const VERSION_OFFSET: usize = 8;
const PAYLOAD_LENGTH_OFFSET: usize = 10;
const INSTALLATION_IDENTIFIER_OFFSET: usize = 12;
const INSTALLATION_GENERATION_OFFSET: usize = 28;
const RECOVERY_GENERATION_OFFSET: usize = 36;
const DATABASE_KEY_GENERATION_IDENTIFIER_OFFSET: usize = 44;
const SETUP_PUBLICATION_IDENTIFIER_OFFSET: usize = 60;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct EncodedFreshnessAnchorV1 {
    bytes: [u8; PLAINTEXT_LENGTH],
}

impl EncodedFreshnessAnchorV1 {
    pub(crate) fn encode(contract: &FreshnessAnchorContractV1) -> Self {
        let mut bytes = [0_u8; PLAINTEXT_LENGTH];
        bytes[..VERSION_OFFSET].copy_from_slice(&MAGIC);
        bytes[VERSION_OFFSET..PAYLOAD_LENGTH_OFFSET].copy_from_slice(&VERSION.to_be_bytes());
        bytes[PAYLOAD_LENGTH_OFFSET..INSTALLATION_IDENTIFIER_OFFSET]
            .copy_from_slice(&DECLARED_PAYLOAD_LENGTH.to_be_bytes());
        contract.installation_identifier().write_bytes_into(
            bytes[INSTALLATION_IDENTIFIER_OFFSET..INSTALLATION_GENERATION_OFFSET]
                .as_mut()
                .try_into()
                .expect("fixed installation-identifier field has exact length"),
        );
        bytes[INSTALLATION_GENERATION_OFFSET..RECOVERY_GENERATION_OFFSET]
            .copy_from_slice(&contract.installation_generation().get().to_be_bytes());
        bytes[RECOVERY_GENERATION_OFFSET..DATABASE_KEY_GENERATION_IDENTIFIER_OFFSET]
            .copy_from_slice(
                &contract
                    .recovery_or_replacement_generation()
                    .get()
                    .to_be_bytes(),
            );
        contract
            .database_key_generation_identifier()
            .write_bytes_into(
                bytes[DATABASE_KEY_GENERATION_IDENTIFIER_OFFSET
                    ..SETUP_PUBLICATION_IDENTIFIER_OFFSET]
                    .as_mut()
                    .try_into()
                    .expect("fixed database-key-generation field has exact length"),
            );
        contract.setup_publication_identifier().write_bytes_into(
            bytes[SETUP_PUBLICATION_IDENTIFIER_OFFSET..PLAINTEXT_LENGTH]
                .as_mut()
                .try_into()
                .expect("fixed setup-publication field has exact length"),
        );
        Self { bytes }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; PLAINTEXT_LENGTH] {
        &self.bytes
    }
}

impl fmt::Debug for EncodedFreshnessAnchorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncodedFreshnessAnchorV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ParsedUntrustedFreshnessAnchorV1 {
    installation_identifier: [u8; 16],
    installation_generation: u64,
    recovery_or_replacement_generation: u64,
    database_key_generation_identifier: [u8; 16],
    setup_publication_identifier: [u8; 16],
}

impl ParsedUntrustedFreshnessAnchorV1 {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, FreshnessAnchorParseError> {
        if bytes.len() != PLAINTEXT_LENGTH {
            return Err(FreshnessAnchorParseError::WrongTotalLength);
        }
        if read_array::<8>(bytes, 0)? != MAGIC {
            return Err(FreshnessAnchorParseError::WrongMagic);
        }
        if read_u16(bytes, VERSION_OFFSET)? != VERSION {
            return Err(FreshnessAnchorParseError::UnsupportedVersion);
        }
        if read_u16(bytes, PAYLOAD_LENGTH_OFFSET)? != DECLARED_PAYLOAD_LENGTH {
            return Err(FreshnessAnchorParseError::WrongPayloadLength);
        }
        Ok(Self {
            installation_identifier: read_array(bytes, INSTALLATION_IDENTIFIER_OFFSET)?,
            installation_generation: read_u64(bytes, INSTALLATION_GENERATION_OFFSET)?,
            recovery_or_replacement_generation: read_u64(bytes, RECOVERY_GENERATION_OFFSET)?,
            database_key_generation_identifier: read_array(
                bytes,
                DATABASE_KEY_GENERATION_IDENTIFIER_OFFSET,
            )?,
            setup_publication_identifier: read_array(bytes, SETUP_PUBLICATION_IDENTIFIER_OFFSET)?,
        })
    }

    pub(crate) fn validate_structure(
        self,
    ) -> Result<FreshnessAnchorContractV1, FreshnessAnchorStructuralValidationError> {
        let installation_identifier =
            InstallationIdentifier::from_bytes(self.installation_identifier)
                .map_err(|_| FreshnessAnchorStructuralValidationError::InstallationIdentifier)?;
        let installation_generation = InstallationGeneration::new(self.installation_generation)
            .map_err(|_| FreshnessAnchorStructuralValidationError::InstallationGeneration)?;
        let recovery_or_replacement_generation = RecoveryOrReplacementGeneration::new(
            self.recovery_or_replacement_generation,
        )
        .map_err(|_| FreshnessAnchorStructuralValidationError::RecoveryOrReplacementGeneration)?;
        let database_key_generation_identifier =
            DatabaseKeyGenerationIdentifier::from_bytes(self.database_key_generation_identifier)
                .map_err(|_| {
                    FreshnessAnchorStructuralValidationError::DatabaseKeyGenerationIdentifier
                })?;
        let setup_publication_identifier = SetupPublicationIdentifier::from_bytes(
            self.setup_publication_identifier,
        )
        .map_err(|_| FreshnessAnchorStructuralValidationError::SetupPublicationIdentifier)?;

        Ok(FreshnessAnchorContractV1::new(
            installation_identifier,
            installation_generation,
            recovery_or_replacement_generation,
            database_key_generation_identifier,
            setup_publication_identifier,
        ))
    }
}

impl fmt::Debug for ParsedUntrustedFreshnessAnchorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParsedUntrustedFreshnessAnchorV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FreshnessAnchorParseError {
    WrongTotalLength,
    WrongMagic,
    UnsupportedVersion,
    WrongPayloadLength,
    InternalFieldBoundaryFailure,
}

impl fmt::Debug for FreshnessAnchorParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongTotalLength => "WrongTotalLength",
            Self::WrongMagic => "WrongMagic",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::WrongPayloadLength => "WrongPayloadLength",
            Self::InternalFieldBoundaryFailure => "InternalFieldBoundaryFailure",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FreshnessAnchorStructuralValidationError {
    InstallationIdentifier,
    InstallationGeneration,
    RecoveryOrReplacementGeneration,
    DatabaseKeyGenerationIdentifier,
    SetupPublicationIdentifier,
}

impl fmt::Debug for FreshnessAnchorStructuralValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InstallationIdentifier => "InvalidInstallationIdentifier",
            Self::InstallationGeneration => "InvalidInstallationGeneration",
            Self::RecoveryOrReplacementGeneration => "InvalidRecoveryOrReplacementGeneration",
            Self::DatabaseKeyGenerationIdentifier => "InvalidDatabaseKeyGenerationIdentifier",
            Self::SetupPublicationIdentifier => "InvalidSetupPublicationIdentifier",
        })
    }
}

fn read_array<const LENGTH: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; LENGTH], FreshnessAnchorParseError> {
    bytes
        .get(offset..offset + LENGTH)
        .and_then(|field| field.try_into().ok())
        .ok_or(FreshnessAnchorParseError::InternalFieldBoundaryFailure)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FreshnessAnchorParseError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, FreshnessAnchorParseError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTALLATION: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const DATABASE_KEY: [u8; 16] = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f,
    ];
    const PUBLICATION: [u8; 16] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    const GOLDEN: [u8; 76] = [
        0x43, 0x48, 0x41, 0x4e, 0x43, 0x52, 0x00, 0x01, 0x00, 0x01, 0x00, 0x40, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];

    fn contract_with_generations(installation: u64, recovery: u64) -> FreshnessAnchorContractV1 {
        FreshnessAnchorContractV1::new(
            InstallationIdentifier::from_bytes(INSTALLATION).unwrap(),
            InstallationGeneration::new(installation).unwrap(),
            RecoveryOrReplacementGeneration::new(recovery).unwrap(),
            DatabaseKeyGenerationIdentifier::from_bytes(DATABASE_KEY).unwrap(),
            SetupPublicationIdentifier::from_bytes(PUBLICATION).unwrap(),
        )
    }

    fn encoded() -> EncodedFreshnessAnchorV1 {
        EncodedFreshnessAnchorV1::encode(&contract_with_generations(
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
        ))
    }

    #[test]
    fn golden_layout_sizes_offsets_and_big_endian_are_exact() {
        let encoded = encoded();
        assert_eq!(SEMANTIC_PAYLOAD_LENGTH, 64);
        assert_eq!(PLAINTEXT_LENGTH, 76);
        assert_eq!(encoded.as_bytes(), &GOLDEN);
        assert_eq!(&GOLDEN[0..8], &MAGIC);
        assert_eq!(&GOLDEN[8..10], &[0, 1]);
        assert_eq!(&GOLDEN[10..12], &[0, 64]);
        assert_eq!(&GOLDEN[12..28], &INSTALLATION);
        assert_eq!(&GOLDEN[28..36], &0x0102_0304_0506_0708_u64.to_be_bytes());
        assert_eq!(&GOLDEN[36..44], &0x1112_1314_1516_1718_u64.to_be_bytes());
        assert_eq!(&GOLDEN[44..60], &DATABASE_KEY);
        assert_eq!(&GOLDEN[60..76], &PUBLICATION);
    }

    #[test]
    fn encode_parse_validate_reencode_round_trip_is_exact() {
        let parsed = ParsedUntrustedFreshnessAnchorV1::parse(&GOLDEN).unwrap();
        let validated = parsed.validate_structure().unwrap();
        assert_eq!(
            EncodedFreshnessAnchorV1::encode(&validated).as_bytes(),
            &GOLDEN
        );
    }

    #[test]
    fn parser_rejects_all_wrong_lengths_magic_versions_and_payload_lengths() {
        for length in 0..PLAINTEXT_LENGTH {
            assert_eq!(
                ParsedUntrustedFreshnessAnchorV1::parse(&GOLDEN[..length]),
                Err(FreshnessAnchorParseError::WrongTotalLength)
            );
        }
        for length in [77, 100, 512] {
            let mut input = GOLDEN.to_vec();
            input.resize(length, 0);
            assert_eq!(
                ParsedUntrustedFreshnessAnchorV1::parse(&input),
                Err(FreshnessAnchorParseError::WrongTotalLength)
            );
        }
        for offset in 0..8 {
            let mut input = GOLDEN;
            input[offset] ^= 1;
            assert_eq!(
                ParsedUntrustedFreshnessAnchorV1::parse(&input),
                Err(FreshnessAnchorParseError::WrongMagic)
            );
        }
        for value in [[0, 2], [1, 0], [0, 0], [0xff, 0xff]] {
            let mut input = GOLDEN;
            input[8..10].copy_from_slice(&value);
            assert_eq!(
                ParsedUntrustedFreshnessAnchorV1::parse(&input),
                Err(FreshnessAnchorParseError::UnsupportedVersion)
            );
        }
        for value in [[0, 63], [64, 0], [0, 65], [0xff, 0xff]] {
            let mut input = GOLDEN;
            input[10..12].copy_from_slice(&value);
            assert_eq!(
                ParsedUntrustedFreshnessAnchorV1::parse(&input),
                Err(FreshnessAnchorParseError::WrongPayloadLength)
            );
        }
    }

    #[test]
    fn structural_validation_rejects_each_zero_semantic_field_independently() {
        let cases = [
            (
                12,
                28,
                FreshnessAnchorStructuralValidationError::InstallationIdentifier,
            ),
            (
                28,
                36,
                FreshnessAnchorStructuralValidationError::InstallationGeneration,
            ),
            (
                36,
                44,
                FreshnessAnchorStructuralValidationError::RecoveryOrReplacementGeneration,
            ),
            (
                44,
                60,
                FreshnessAnchorStructuralValidationError::DatabaseKeyGenerationIdentifier,
            ),
            (
                60,
                76,
                FreshnessAnchorStructuralValidationError::SetupPublicationIdentifier,
            ),
        ];
        for (start, end, expected) in cases {
            let mut input = GOLDEN;
            input[start..end].fill(0);
            let parsed = ParsedUntrustedFreshnessAnchorV1::parse(&input)
                .expect("semantic invalidity must not be a framing failure");
            assert_eq!(parsed.validate_structure(), Err(expected));
        }
    }

    #[test]
    fn maximum_generations_and_nonzero_semantic_mutations_are_valid() {
        let maximum =
            EncodedFreshnessAnchorV1::encode(&contract_with_generations(u64::MAX, u64::MAX));
        assert_eq!(&maximum.as_bytes()[28..44], &[0xff; 16]);
        assert!(
            ParsedUntrustedFreshnessAnchorV1::parse(maximum.as_bytes())
                .unwrap()
                .validate_structure()
                .is_ok()
        );

        for offset in 12..PLAINTEXT_LENGTH {
            let mut input = GOLDEN;
            input[offset] ^= 0x80;
            let parsed = ParsedUntrustedFreshnessAnchorV1::parse(&input).unwrap();
            assert!(parsed.validate_structure().is_ok(), "offset {offset}");
        }
    }

    #[test]
    fn debug_and_source_boundaries_are_redacted_fixed_binary_and_side_effect_free() {
        let parsed = ParsedUntrustedFreshnessAnchorV1::parse(&GOLDEN).unwrap();
        assert_eq!(
            format!("{:?}", encoded()),
            "EncodedFreshnessAnchorV1([REDACTED])"
        );
        assert_eq!(
            format!("{parsed:?}"),
            "ParsedUntrustedFreshnessAnchorV1([REDACTED])"
        );
        for error in [
            FreshnessAnchorParseError::WrongTotalLength,
            FreshnessAnchorParseError::WrongMagic,
            FreshnessAnchorParseError::UnsupportedVersion,
            FreshnessAnchorParseError::WrongPayloadLength,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains("CHANCR"));
            assert!(!debug.contains("[0,"));
        }
        const SOURCE: &str = include_str!("freshness_anchor_plaintext.rs");
        const IDENTIFIER_SOURCE: &str = include_str!("installation_evidence_contract.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert_eq!(production.matches("write_bytes_into(").count(), 3);
        assert!(IDENTIFIER_SOURCE.contains("pub(crate) fn write_bytes_into"));
        for excluded in [
            "Uuid",
            "UUID",
            "hex::",
            "base64",
            "String",
            "std::fs",
            "std::path",
            "getrandom",
            "windows",
            "dpapi",
            "tauri",
            "unsafe",
            "AssuredFreshnessAnchor",
            "classify",
            "persist",
            "publish",
            "startup",
            "migration",
        ] {
            assert!(
                !production.contains(excluded),
                "unexpected capability: {excluded}"
            );
        }
    }
}
