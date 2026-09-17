//! Pure, fixed-width Recovery Set Manifest Format Version 1 codec.

use std::fmt;

use super::MigrationBackupSetIdentifier;

pub(crate) const RECOVERY_SET_MANIFEST_V1_LENGTH: usize = 98;

const MAGIC: [u8; 8] = *b"CHLDRSM\0";
const FORMAT_VERSION: u16 = 1;
const MINIMUM_DATABASE_BYTE_LENGTH: u64 = 512;
const MAXIMUM_DATABASE_BYTE_LENGTH: u64 = 281_474_976_579_584;

const VERSION_OFFSET: usize = 8;
const BACKUP_SET_IDENTIFIER_OFFSET: usize = 10;
const DATABASE_BYTE_LENGTH_OFFSET: usize = 26;
const DATABASE_DIGEST_OFFSET: usize = 34;
const RECOVERY_ENVELOPE_DIGEST_OFFSET: usize = 66;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RecoverySetManifestV1ParseError {
    WrongTotalLength,
    WrongMagic,
    UnsupportedVersion,
}

impl fmt::Debug for RecoverySetManifestV1ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongTotalLength => "WrongTotalLength",
            Self::WrongMagic => "WrongMagic",
            Self::UnsupportedVersion => "UnsupportedVersion",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RecoverySetManifestV1ValidationError {
    InvalidBackupSetIdentifier,
    InvalidDatabaseByteLength,
}

impl fmt::Debug for RecoverySetManifestV1ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBackupSetIdentifier => "InvalidBackupSetIdentifier",
            Self::InvalidDatabaseByteLength => "InvalidDatabaseByteLength",
        })
    }
}

pub(crate) struct ParsedUntrustedRecoverySetManifestV1 {
    backup_set_identifier: [u8; 16],
    database_byte_length: u64,
    database_sha256: [u8; 32],
    recovery_envelope_sha256: [u8; 32],
}

impl ParsedUntrustedRecoverySetManifestV1 {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, RecoverySetManifestV1ParseError> {
        if bytes.len() != RECOVERY_SET_MANIFEST_V1_LENGTH {
            return Err(RecoverySetManifestV1ParseError::WrongTotalLength);
        }
        if bytes[..VERSION_OFFSET] != MAGIC {
            return Err(RecoverySetManifestV1ParseError::WrongMagic);
        }
        let version = u16::from_be_bytes(
            bytes[VERSION_OFFSET..BACKUP_SET_IDENTIFIER_OFFSET]
                .try_into()
                .expect("exact manifest length fixes the version field width"),
        );
        if version != FORMAT_VERSION {
            return Err(RecoverySetManifestV1ParseError::UnsupportedVersion);
        }

        Ok(Self {
            backup_set_identifier: bytes[BACKUP_SET_IDENTIFIER_OFFSET..DATABASE_BYTE_LENGTH_OFFSET]
                .try_into()
                .expect("exact manifest length fixes the identifier field width"),
            database_byte_length: u64::from_be_bytes(
                bytes[DATABASE_BYTE_LENGTH_OFFSET..DATABASE_DIGEST_OFFSET]
                    .try_into()
                    .expect("exact manifest length fixes the database-length field width"),
            ),
            database_sha256: bytes[DATABASE_DIGEST_OFFSET..RECOVERY_ENVELOPE_DIGEST_OFFSET]
                .try_into()
                .expect("exact manifest length fixes the database-digest field width"),
            recovery_envelope_sha256: bytes
                [RECOVERY_ENVELOPE_DIGEST_OFFSET..RECOVERY_SET_MANIFEST_V1_LENGTH]
                .try_into()
                .expect("exact manifest length fixes the envelope-digest field width"),
        })
    }

    pub(crate) fn validate_structure(
        self,
    ) -> Result<RecoverySetManifestV1, RecoverySetManifestV1ValidationError> {
        let backup_set_identifier =
            MigrationBackupSetIdentifier::from_bytes(self.backup_set_identifier)
                .map_err(|_| RecoverySetManifestV1ValidationError::InvalidBackupSetIdentifier)?;
        if !(MINIMUM_DATABASE_BYTE_LENGTH..=MAXIMUM_DATABASE_BYTE_LENGTH)
            .contains(&self.database_byte_length)
        {
            return Err(RecoverySetManifestV1ValidationError::InvalidDatabaseByteLength);
        }

        Ok(RecoverySetManifestV1 {
            backup_set_identifier,
            database_byte_length: self.database_byte_length,
            database_sha256: self.database_sha256,
            recovery_envelope_sha256: self.recovery_envelope_sha256,
        })
    }
}

impl fmt::Debug for ParsedUntrustedRecoverySetManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParsedUntrustedRecoverySetManifestV1([REDACTED])")
    }
}

pub(crate) struct RecoverySetManifestV1 {
    backup_set_identifier: MigrationBackupSetIdentifier,
    database_byte_length: u64,
    database_sha256: [u8; 32],
    recovery_envelope_sha256: [u8; 32],
}

impl RecoverySetManifestV1 {
    pub(crate) fn from_trusted_internal_facts(
        backup_set_identifier: MigrationBackupSetIdentifier,
        database_byte_length: u64,
        database_sha256: [u8; 32],
        recovery_envelope_sha256: [u8; 32],
    ) -> Result<Self, RecoverySetManifestV1ValidationError> {
        if !(MINIMUM_DATABASE_BYTE_LENGTH..=MAXIMUM_DATABASE_BYTE_LENGTH)
            .contains(&database_byte_length)
        {
            return Err(RecoverySetManifestV1ValidationError::InvalidDatabaseByteLength);
        }

        Ok(Self {
            backup_set_identifier,
            database_byte_length,
            database_sha256,
            recovery_envelope_sha256,
        })
    }

    pub(crate) fn encode(&self) -> [u8; RECOVERY_SET_MANIFEST_V1_LENGTH] {
        let mut encoded = [0_u8; RECOVERY_SET_MANIFEST_V1_LENGTH];
        encoded[..VERSION_OFFSET].copy_from_slice(&MAGIC);
        encoded[VERSION_OFFSET..BACKUP_SET_IDENTIFIER_OFFSET]
            .copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        self.backup_set_identifier.write_bytes_into(
            (&mut encoded[BACKUP_SET_IDENTIFIER_OFFSET..DATABASE_BYTE_LENGTH_OFFSET])
                .try_into()
                .expect("fixed identifier destination has exact length"),
        );
        encoded[DATABASE_BYTE_LENGTH_OFFSET..DATABASE_DIGEST_OFFSET]
            .copy_from_slice(&self.database_byte_length.to_be_bytes());
        encoded[DATABASE_DIGEST_OFFSET..RECOVERY_ENVELOPE_DIGEST_OFFSET]
            .copy_from_slice(&self.database_sha256);
        encoded[RECOVERY_ENVELOPE_DIGEST_OFFSET..].copy_from_slice(&self.recovery_envelope_sha256);
        encoded
    }
}

impl fmt::Debug for RecoverySetManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoverySetManifestV1([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTIFIER: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    const DATABASE_LENGTH: u64 = 0x0000_0102_0304_0506;
    const DATABASE_DIGEST: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    const ENVELOPE_DIGEST: [u8; 32] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
        0xbe, 0xbf,
    ];
    const GOLDEN: [u8; RECOVERY_SET_MANIFEST_V1_LENGTH] = [
        0x43, 0x48, 0x4c, 0x44, 0x52, 0x53, 0x4d, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x00, 0x00, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
        0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    ];

    fn fixture(
        identifier: [u8; 16],
        database_byte_length: u64,
        database_digest: [u8; 32],
        envelope_digest: [u8; 32],
    ) -> [u8; RECOVERY_SET_MANIFEST_V1_LENGTH] {
        let mut bytes = [0_u8; RECOVERY_SET_MANIFEST_V1_LENGTH];
        bytes[..8].copy_from_slice(b"CHLDRSM\0");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10..26].copy_from_slice(&identifier);
        bytes[26..34].copy_from_slice(&database_byte_length.to_be_bytes());
        bytes[34..66].copy_from_slice(&database_digest);
        bytes[66..98].copy_from_slice(&envelope_digest);
        bytes
    }

    fn parse_and_validate(
        bytes: &[u8],
    ) -> Result<RecoverySetManifestV1, RecoverySetManifestV1ValidationError> {
        ParsedUntrustedRecoverySetManifestV1::parse(bytes)
            .expect("fixture framing should parse")
            .validate_structure()
    }

    #[test]
    fn exact_golden_encoding_proves_every_field_and_offset() {
        let encoded = parse_and_validate(&GOLDEN).unwrap().encode();
        assert_eq!(encoded, GOLDEN);
        assert_eq!(encoded.len(), 98);
        assert_eq!(&encoded[0..8], b"CHLDRSM\0");
        assert_eq!(&encoded[8..10], &[0x00, 0x01]);
        assert_eq!(&encoded[10..26], &IDENTIFIER);
        assert_eq!(&encoded[26..34], &DATABASE_LENGTH.to_be_bytes());
        assert_eq!(&encoded[34..66], &DATABASE_DIGEST);
        assert_eq!(&encoded[66..98], &ENVELOPE_DIGEST);
    }

    #[test]
    fn parser_rejects_every_representative_wrong_total_length() {
        for length in [0, 1, 7, 8, 9, 10, 25, 26, 33, 34, 65, 66, 97, 99, 100] {
            let mut bytes = vec![0_u8; length];
            let copied = length.min(GOLDEN.len());
            bytes[..copied].copy_from_slice(&GOLDEN[..copied]);
            assert_eq!(
                ParsedUntrustedRecoverySetManifestV1::parse(&bytes).unwrap_err(),
                RecoverySetManifestV1ParseError::WrongTotalLength,
                "length {length}"
            );
        }

        let mut trailing = GOLDEN.to_vec();
        trailing.extend_from_slice(&[0xde, 0xad]);
        assert_eq!(
            ParsedUntrustedRecoverySetManifestV1::parse(&trailing).unwrap_err(),
            RecoverySetManifestV1ParseError::WrongTotalLength
        );
    }

    #[test]
    fn parser_rejects_mutation_of_each_magic_byte() {
        for index in 0..8 {
            let mut changed = GOLDEN;
            changed[index] ^= 0x01;
            assert_eq!(
                ParsedUntrustedRecoverySetManifestV1::parse(&changed).unwrap_err(),
                RecoverySetManifestV1ParseError::WrongMagic,
                "magic index {index}"
            );
        }
    }

    #[test]
    fn parser_rejects_unsupported_versions_and_each_version_byte_mutation() {
        for version in [0_u16, 2, u16::MAX, 0x0101, 0x0000] {
            let mut changed = GOLDEN;
            changed[8..10].copy_from_slice(&version.to_be_bytes());
            assert_eq!(
                ParsedUntrustedRecoverySetManifestV1::parse(&changed).unwrap_err(),
                RecoverySetManifestV1ParseError::UnsupportedVersion,
                "version {version}"
            );
        }

        for index in 8..10 {
            let mut changed = GOLDEN;
            changed[index] ^= 0x80;
            assert_eq!(
                ParsedUntrustedRecoverySetManifestV1::parse(&changed).unwrap_err(),
                RecoverySetManifestV1ParseError::UnsupportedVersion
            );
        }
    }

    #[test]
    fn parsing_accepts_structurally_invalid_values_and_unrestricted_digests() {
        let cases = [
            fixture([0; 16], DATABASE_LENGTH, [0; 32], [0xff; 32]),
            fixture(IDENTIFIER, 0, [0xff; 32], [0; 32]),
            fixture(IDENTIFIER, 511, [0; 32], [0; 32]),
            fixture(
                IDENTIFIER,
                MAXIMUM_DATABASE_BYTE_LENGTH + 1,
                [0xff; 32],
                [0xff; 32],
            ),
        ];
        for bytes in cases {
            ParsedUntrustedRecoverySetManifestV1::parse(&bytes).unwrap();
        }

        assert_eq!(
            ParsedUntrustedRecoverySetManifestV1::parse(&cases[0])
                .unwrap()
                .validate_structure()
                .unwrap_err(),
            RecoverySetManifestV1ValidationError::InvalidBackupSetIdentifier
        );
        for bytes in &cases[1..] {
            assert_eq!(
                ParsedUntrustedRecoverySetManifestV1::parse(bytes)
                    .unwrap()
                    .validate_structure()
                    .unwrap_err(),
                RecoverySetManifestV1ValidationError::InvalidDatabaseByteLength
            );
        }
    }

    #[test]
    fn identifier_validation_rejects_only_all_zero() {
        let zero = fixture([0; 16], 512, [0; 32], [0; 32]);
        assert_eq!(
            parse_and_validate(&zero).unwrap_err(),
            RecoverySetManifestV1ValidationError::InvalidBackupSetIdentifier
        );

        for identifier in [[1; 16], [0xff; 16], {
            let mut value = [0; 16];
            value[15] = 1;
            value
        }] {
            parse_and_validate(&fixture(identifier, 512, [0; 32], [0; 32])).unwrap();
        }
    }

    #[test]
    fn database_length_validation_enforces_exact_inclusive_boundaries() {
        for accepted in [MINIMUM_DATABASE_BYTE_LENGTH, MAXIMUM_DATABASE_BYTE_LENGTH] {
            parse_and_validate(&fixture(IDENTIFIER, accepted, [0; 32], [0; 32])).unwrap();
        }
        for rejected in [
            0,
            1,
            MINIMUM_DATABASE_BYTE_LENGTH - 1,
            MAXIMUM_DATABASE_BYTE_LENGTH + 1,
            u64::MAX,
        ] {
            assert_eq!(
                parse_and_validate(&fixture(IDENTIFIER, rejected, [0; 32], [0; 32])).unwrap_err(),
                RecoverySetManifestV1ValidationError::InvalidDatabaseByteLength
            );
        }
    }

    #[test]
    fn trusted_internal_construction_enforces_exact_length_boundaries() {
        let identifier = MigrationBackupSetIdentifier::from_bytes(IDENTIFIER).unwrap();
        for accepted in [MINIMUM_DATABASE_BYTE_LENGTH, MAXIMUM_DATABASE_BYTE_LENGTH] {
            assert_eq!(
                RecoverySetManifestV1::from_trusted_internal_facts(
                    identifier,
                    accepted,
                    DATABASE_DIGEST,
                    ENVELOPE_DIGEST,
                )
                .unwrap()
                .encode(),
                fixture(IDENTIFIER, accepted, DATABASE_DIGEST, ENVELOPE_DIGEST)
            );
        }
        for rejected in [
            0,
            1,
            MINIMUM_DATABASE_BYTE_LENGTH - 1,
            MAXIMUM_DATABASE_BYTE_LENGTH + 1,
            u64::MAX,
        ] {
            assert_eq!(
                RecoverySetManifestV1::from_trusted_internal_facts(
                    identifier,
                    rejected,
                    DATABASE_DIGEST,
                    ENVELOPE_DIGEST,
                )
                .unwrap_err(),
                RecoverySetManifestV1ValidationError::InvalidDatabaseByteLength
            );
        }
    }

    #[test]
    fn identifier_validation_precedes_database_length_validation() {
        let both_invalid = fixture([0; 16], 0, [0; 32], [0; 32]);
        assert_eq!(
            parse_and_validate(&both_invalid).unwrap_err(),
            RecoverySetManifestV1ValidationError::InvalidBackupSetIdentifier
        );
        let invalid_length = fixture(IDENTIFIER, 0, [0; 32], [0; 32]);
        assert_eq!(
            parse_and_validate(&invalid_length).unwrap_err(),
            RecoverySetManifestV1ValidationError::InvalidDatabaseByteLength
        );
    }

    #[test]
    fn every_representative_digest_pattern_is_structurally_valid() {
        let mixed_database = std::array::from_fn(|index| index as u8);
        let mixed_envelope = std::array::from_fn(|index| (255 - index) as u8);
        for (database_digest, envelope_digest) in [
            ([0; 32], [0x55; 32]),
            ([0x55; 32], [0; 32]),
            ([0xff; 32], [0xff; 32]),
            (mixed_database, mixed_envelope),
        ] {
            parse_and_validate(&fixture(
                IDENTIFIER,
                DATABASE_LENGTH,
                database_digest,
                envelope_digest,
            ))
            .unwrap();
        }
    }

    #[test]
    fn valid_external_bytes_round_trip_byte_identically_and_encoding_is_deterministic() {
        let fixtures = [
            GOLDEN,
            fixture([0xff; 16], 512, [0; 32], [0xff; 32]),
            fixture(
                [0x7e; 16],
                MAXIMUM_DATABASE_BYTE_LENGTH,
                [0xff; 32],
                [0; 32],
            ),
        ];
        for external in fixtures {
            let validated = parse_and_validate(&external).unwrap();
            assert_eq!(validated.encode(), external);
            assert_eq!(validated.encode(), validated.encode());
            let revalidated = parse_and_validate(&validated.encode()).unwrap();
            assert_eq!(revalidated.encode(), external);
        }
    }

    #[test]
    fn debug_and_errors_expose_only_fixed_type_or_variant_names() {
        let parsed = ParsedUntrustedRecoverySetManifestV1::parse(&GOLDEN).unwrap();
        let parsed_debug = format!("{parsed:?}");
        let validated_debug = format!("{:?}", parse_and_validate(&GOLDEN).unwrap());
        assert_eq!(
            parsed_debug,
            "ParsedUntrustedRecoverySetManifestV1([REDACTED])"
        );
        assert_eq!(validated_debug, "RecoverySetManifestV1([REDACTED])");

        let sensitive_fragments = [
            "0102030405060708090a0b0c0d0e0f10",
            "202122232425262728292a2b2c2d2e2f",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "1108152157446",
            "CHLDRSM",
        ];
        for output in [parsed_debug, validated_debug] {
            for fragment in sensitive_fragments {
                assert!(!output.contains(fragment));
            }
        }
        assert_eq!(
            format!("{:?}", RecoverySetManifestV1ParseError::WrongTotalLength),
            "WrongTotalLength"
        );
        assert_eq!(
            format!("{:?}", RecoverySetManifestV1ParseError::UnsupportedVersion),
            "UnsupportedVersion"
        );
        assert_eq!(
            format!(
                "{:?}",
                RecoverySetManifestV1ValidationError::InvalidDatabaseByteLength
            ),
            "InvalidDatabaseByteLength"
        );
    }

    #[test]
    fn production_module_has_only_the_pure_codec_capability_surface() {
        const SOURCE: &str = include_str!("recovery_set_manifest.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "std::fs",
            "std::path",
            "File::",
            "PathBuf",
            "sha2::",
            "Sha256::",
            "windows_sys",
            "#[tauri::command]",
            "rusqlite",
            "Connection",
            "std::process",
            "Command::",
            "invoke_handler",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected codec capability: {forbidden}"
            );
        }
    }
}
