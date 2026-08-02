//! Pure version-1 plaintext payload for future protection of a database key.
//!
//! Decoding establishes only exact framing, a supported payload version, a
//! nonzero database-key generation identifier, and ownership of 32 key bytes.
//! It does not establish protected-artifact or active provenance, CurrentUser-
//! DPAPI provenance, trusted-evidence generation correspondence, SQLCipher key
//! correctness, database existence or validity, freshness, or operational
//! authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::{fmt, ops::Range};

use zeroize::Zeroize;

use crate::{
    database_key::DatabaseKey, installation_evidence_contract::DatabaseKeyGenerationIdentifier,
};

pub(crate) const DATABASE_KEY_PAYLOAD_LENGTH: usize = 49;
const DATABASE_KEY_PAYLOAD_VERSION: u8 = 1;
const GENERATION_IDENTIFIER_RANGE: Range<usize> = 1..17;
const DATABASE_KEY_RANGE: Range<usize> = 17..49;

pub(crate) struct EncodedDatabaseKeyPayload {
    bytes: [u8; DATABASE_KEY_PAYLOAD_LENGTH],
}

impl EncodedDatabaseKeyPayload {
    pub(crate) fn encode(
        key: &DatabaseKey,
        generation_identifier: DatabaseKeyGenerationIdentifier,
    ) -> Self {
        let mut bytes = [0_u8; DATABASE_KEY_PAYLOAD_LENGTH];
        bytes[0] = DATABASE_KEY_PAYLOAD_VERSION;
        let generation_destination: &mut [u8; 16] = bytes
            .get_mut(GENERATION_IDENTIFIER_RANGE)
            .and_then(|field| field.try_into().ok())
            .expect("locked generation-identifier range has exact length");
        generation_identifier.write_bytes_into(generation_destination);
        let key_destination = bytes
            .get_mut(DATABASE_KEY_RANGE)
            .expect("locked database-key range is within the payload");
        key.expose_bytes(|key_bytes| key_destination.copy_from_slice(key_bytes));
        Self { bytes }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; DATABASE_KEY_PAYLOAD_LENGTH] {
        &self.bytes
    }

    fn zeroize_owned_bytes(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for EncodedDatabaseKeyPayload {
    fn drop(&mut self) {
        self.zeroize_owned_bytes();
    }
}

impl fmt::Debug for EncodedDatabaseKeyPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncodedDatabaseKeyPayload([REDACTED])")
    }
}

pub(crate) struct DecodedDatabaseKeyCandidate {
    key: DatabaseKey,
    generation_identifier: DatabaseKeyGenerationIdentifier,
}

impl DecodedDatabaseKeyCandidate {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, DatabaseKeyPayloadError> {
        if bytes.len() != DATABASE_KEY_PAYLOAD_LENGTH {
            return Err(DatabaseKeyPayloadError::MalformedPayload);
        }
        if bytes.first() != Some(&DATABASE_KEY_PAYLOAD_VERSION) {
            return Err(DatabaseKeyPayloadError::UnsupportedVersion);
        }

        let generation_bytes: [u8; 16] = bytes
            .get(GENERATION_IDENTIFIER_RANGE)
            .ok_or(DatabaseKeyPayloadError::MalformedPayload)?
            .try_into()
            .map_err(|_| DatabaseKeyPayloadError::MalformedPayload)?;
        let generation_identifier =
            DatabaseKeyGenerationIdentifier::from_bytes(generation_bytes)
                .map_err(|_| DatabaseKeyPayloadError::InvalidGenerationIdentifier)?;

        let key_field: &[u8; 32] = bytes
            .get(DATABASE_KEY_RANGE)
            .ok_or(DatabaseKeyPayloadError::MalformedPayload)?
            .try_into()
            .map_err(|_| DatabaseKeyPayloadError::MalformedPayload)?;
        let mut key_source = *key_field;
        let key = DatabaseKey::from_bytes_with_cleared_source(&mut key_source);

        Ok(Self {
            key,
            generation_identifier,
        })
    }

    pub(crate) fn into_parts(self) -> (DatabaseKey, DatabaseKeyGenerationIdentifier) {
        (self.key, self.generation_identifier)
    }
}

impl fmt::Debug for DecodedDatabaseKeyCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecodedDatabaseKeyCandidate([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum DatabaseKeyPayloadError {
    MalformedPayload,
    UnsupportedVersion,
    InvalidGenerationIdentifier,
}

impl fmt::Debug for DatabaseKeyPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MalformedPayload => "MalformedPayload",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::InvalidGenerationIdentifier => "InvalidGenerationIdentifier",
        })
    }
}

#[cfg(test)]
mod tests {
    use std::mem::{needs_drop, size_of};

    use super::*;

    const GENERATION: [u8; 16] = [0x31; 16];
    const ALTERNATE_GENERATION: [u8; 16] = [0x42; 16];
    const KEY: [u8; 32] = [
        0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1,
        0xf2, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef,
        0xf0, 0x01,
    ];
    const ALTERNATE_KEY: [u8; 32] = [
        0x83, 0x94, 0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61,
        0x72, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f,
        0x70, 0x81,
    ];

    fn generation(bytes: [u8; 16]) -> DatabaseKeyGenerationIdentifier {
        DatabaseKeyGenerationIdentifier::from_bytes(bytes)
            .expect("synthetic generation identifier must be nonzero")
    }

    fn encoded(key_bytes: [u8; 32], generation_bytes: [u8; 16]) -> EncodedDatabaseKeyPayload {
        EncodedDatabaseKeyPayload::encode(
            &DatabaseKey::from_bytes(key_bytes),
            generation(generation_bytes),
        )
    }

    #[test]
    fn exact_v1_layout_round_trips_into_database_specific_nominal_types() {
        let payload = encoded(KEY, GENERATION);

        assert_eq!(DATABASE_KEY_PAYLOAD_LENGTH, 49);
        assert_eq!(DATABASE_KEY_PAYLOAD_VERSION, 1);
        assert_eq!(GENERATION_IDENTIFIER_RANGE, 1..17);
        assert_eq!(DATABASE_KEY_RANGE, 17..49);
        assert_eq!(size_of::<EncodedDatabaseKeyPayload>(), 49);
        assert_eq!(payload.as_bytes().len(), 49);
        assert_eq!(payload.as_bytes()[0], 1);
        assert_eq!(&payload.as_bytes()[1..17], &GENERATION);
        assert_eq!(&payload.as_bytes()[17..49], &KEY);
        assert_eq!(payload.as_bytes()[17], KEY[0]);
        assert_eq!(payload.as_bytes()[32], KEY[15]);
        assert_eq!(payload.as_bytes()[48], KEY[31]);

        let candidate = DecodedDatabaseKeyCandidate::parse(payload.as_bytes())
            .expect("canonical payload must decode");
        let (key, decoded_generation) = candidate.into_parts();
        key.expose_bytes(|bytes| assert_eq!(bytes, &KEY));
        assert_eq!(decoded_generation, generation(GENERATION));
    }

    #[test]
    fn generation_and_key_changes_are_confined_to_their_exact_fields() {
        let baseline = encoded(KEY, GENERATION);
        let alternate_generation = encoded(KEY, ALTERNATE_GENERATION);
        let alternate_key = encoded(ALTERNATE_KEY, GENERATION);

        let generation_differences: Vec<_> = baseline
            .as_bytes()
            .iter()
            .zip(alternate_generation.as_bytes())
            .enumerate()
            .filter_map(|(index, (left, right))| (left != right).then_some(index))
            .collect();
        assert_eq!(generation_differences, (1..17).collect::<Vec<_>>());

        let key_differences: Vec<_> = baseline
            .as_bytes()
            .iter()
            .zip(alternate_key.as_bytes())
            .enumerate()
            .filter_map(|(index, (left, right))| (left != right).then_some(index))
            .collect();
        assert_eq!(key_differences, (17..49).collect::<Vec<_>>());
    }

    #[test]
    fn every_shorter_and_representative_longer_length_is_malformed() {
        for length in 0..DATABASE_KEY_PAYLOAD_LENGTH {
            assert_eq!(
                DecodedDatabaseKeyCandidate::parse(&vec![0xa5; length]).unwrap_err(),
                DatabaseKeyPayloadError::MalformedPayload
            );
        }
        for length in [50, 51, 64, 128] {
            assert_eq!(
                DecodedDatabaseKeyCandidate::parse(&vec![0xa5; length]).unwrap_err(),
                DatabaseKeyPayloadError::MalformedPayload
            );
        }
    }

    #[test]
    fn unsupported_version_and_zero_generation_fail_without_a_candidate() {
        let canonical = encoded(KEY, GENERATION);
        let mut unsupported = *canonical.as_bytes();
        unsupported[0] = 2;
        assert_eq!(
            DecodedDatabaseKeyCandidate::parse(&unsupported).unwrap_err(),
            DatabaseKeyPayloadError::UnsupportedVersion
        );

        let mut zero_generation = *canonical.as_bytes();
        zero_generation[1..17].fill(0);
        assert_eq!(
            DecodedDatabaseKeyCandidate::parse(&zero_generation).unwrap_err(),
            DatabaseKeyPayloadError::InvalidGenerationIdentifier
        );
    }

    #[test]
    fn payload_candidate_and_errors_have_exact_redacted_debug_output() {
        let mut payload = encoded(KEY, GENERATION);
        let candidate = DecodedDatabaseKeyCandidate::parse(payload.as_bytes()).unwrap();

        assert_eq!(
            format!("{payload:?}"),
            "EncodedDatabaseKeyPayload([REDACTED])"
        );
        assert_eq!(
            format!("{candidate:?}"),
            "DecodedDatabaseKeyCandidate([REDACTED])"
        );
        for (error, expected) in [
            (
                DatabaseKeyPayloadError::MalformedPayload,
                "MalformedPayload",
            ),
            (
                DatabaseKeyPayloadError::UnsupportedVersion,
                "UnsupportedVersion",
            ),
            (
                DatabaseKeyPayloadError::InvalidGenerationIdentifier,
                "InvalidGenerationIdentifier",
            ),
        ] {
            let debug = format!("{error:?}");
            assert_eq!(debug, expected);
            assert!(!debug.contains("0x"));
            assert!(!debug.contains("["));
        }

        payload.zeroize_owned_bytes();
        assert_eq!(payload.as_bytes(), &[0; DATABASE_KEY_PAYLOAD_LENGTH]);
    }

    #[test]
    fn decoder_uses_the_cleared_source_transition_before_success() {
        const SOURCE: &str = include_str!("database_key_protected_payload.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let parser = production
            .split_once("pub(crate) fn parse(bytes: &[u8])")
            .unwrap()
            .1
            .split_once("pub(crate) fn into_parts")
            .unwrap()
            .0;

        let source_copy = parser.find("let mut key_source = *key_field;").unwrap();
        let cleared_transfer = parser
            .find("DatabaseKey::from_bytes_with_cleared_source(&mut key_source)")
            .unwrap();
        let successful_return = parser.find("Ok(Self {").unwrap();
        assert!(source_copy < cleared_transfer);
        assert!(cleared_transfer < successful_return);
        assert!(!parser.contains("DatabaseKey::from_bytes("));
        assert_eq!(parser.matches("key_source").count(), 2);
    }

    #[test]
    fn source_contract_is_private_nominal_non_authoritative_and_side_effect_free() {
        const SOURCE: &str = include_str!("database_key_protected_payload.rs");
        const LIB_SOURCE: &str = include_str!("lib.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let candidate_body = production
            .split_once("pub(crate) struct DecodedDatabaseKeyCandidate {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let fields: Vec<_> = candidate_body
            .lines()
            .filter(|line| line.contains(':'))
            .collect();

        assert_eq!(
            fields,
            [
                "    key: DatabaseKey,",
                "    generation_identifier: DatabaseKeyGenerationIdentifier,",
            ]
        );
        assert!(needs_drop::<DecodedDatabaseKeyCandidate>());
        assert!(needs_drop::<EncodedDatabaseKeyPayload>());
        assert_eq!(
            LIB_SOURCE
                .matches("mod database_key_protected_payload;")
                .count(),
            1
        );
        assert!(!LIB_SOURCE.contains("pub mod database_key_protected_payload"));

        for forbidden in [
            "EvidenceAuthenticationKey",
            "EvidenceAuthenticationKeyGenerationIdentifier",
            "AnchorAuthenticationKey",
            "AnchorAuthenticationKeyGenerationIdentifier",
            "ProtectedObjectKind",
            "impl Clone for EncodedDatabaseKeyPayload",
            "impl Copy for EncodedDatabaseKeyPayload",
            "impl Clone for DecodedDatabaseKeyCandidate",
            "impl Copy for DecodedDatabaseKeyCandidate",
            "Serialize",
            "Deserialize",
            "impl fmt::Display",
            "impl std::error::Error",
            "impl From<",
            "impl Into<",
            "pub(crate) fn key_bytes",
            "pub(crate) fn as_key",
            "pub(crate) fn new(",
            "std::fs",
            "std::path",
            "std::env",
            "std::net",
            "std::process",
            "windows_sys",
            "CryptProtectData",
            "CryptUnprotectData",
            "rusqlite",
            "sqlx",
            "tauri",
            "tracing",
            "println!",
            "eprintln!",
            "unsafe {",
        ] {
            assert!(
                !production.contains(forbidden),
                "database-key payload unexpectedly contains forbidden surface: {forbidden}"
            );
        }

        assert!(production.contains("does not establish protected-artifact or active provenance"));
        assert!(production.contains("trusted-evidence generation correspondence"));
        assert!(production.contains("operational\n//! authority"));
    }
}
