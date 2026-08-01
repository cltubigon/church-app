//! Strict framing and HMAC-SHA-256 authentication for freshness anchors.
//!
//! Authentication precedes key-generation comparison. Only the matched type
//! can release the authenticated plaintext bytes.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    freshness_anchor_authentication_key::AnchorAuthenticationKey,
    freshness_anchor_plaintext::{EncodedFreshnessAnchorV1, PLAINTEXT_LENGTH},
};

type HmacSha256 = Hmac<Sha256>;

pub(crate) const AUTHENTICATED_PREFIX_LENGTH: usize = 106;
pub(crate) const AUTHENTICATED_ENVELOPE_LENGTH: usize = 138;
const TAG_LENGTH: usize = 32;
const MAGIC: [u8; 8] = *b"CHANAUTH";
const VERSION: u16 = 1;
const HMAC_SHA_256_ALGORITHM_IDENTIFIER: u16 = 1;
const DECLARED_PLAINTEXT_LENGTH: u16 = 76;

const VERSION_OFFSET: usize = 8;
const ALGORITHM_OFFSET: usize = 10;
const KEY_GENERATION_IDENTIFIER_OFFSET: usize = 12;
const PLAINTEXT_LENGTH_OFFSET: usize = 28;
const PLAINTEXT_OFFSET: usize = 30;
const TAG_OFFSET: usize = AUTHENTICATED_PREFIX_LENGTH;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AnchorAuthenticationKeyGenerationIdentifier([u8; 16]);

impl AnchorAuthenticationKeyGenerationIdentifier {
    pub(crate) fn from_bytes(value: [u8; 16]) -> Result<Self, AnchorKeyGenerationIdentifierError> {
        if value == [0; 16] {
            return Err(AnchorKeyGenerationIdentifierError::AllZero);
        }
        Ok(Self(value))
    }

    pub(crate) fn write_bytes_into(&self, destination: &mut [u8; 16]) {
        destination.copy_from_slice(&self.0);
    }

    pub(crate) fn matches(&self, candidate: &Self) -> bool {
        self == candidate
    }
}

impl fmt::Debug for AnchorAuthenticationKeyGenerationIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AnchorAuthenticationKeyGenerationIdentifier([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AnchorKeyGenerationIdentifierError {
    AllZero,
}

impl fmt::Debug for AnchorKeyGenerationIdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AllZero")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct EncodedAuthenticatedFreshnessAnchorV1 {
    bytes: [u8; AUTHENTICATED_ENVELOPE_LENGTH],
}

impl EncodedAuthenticatedFreshnessAnchorV1 {
    pub(crate) const fn as_bytes(&self) -> &[u8; AUTHENTICATED_ENVELOPE_LENGTH] {
        &self.bytes
    }
}

impl fmt::Debug for EncodedAuthenticatedFreshnessAnchorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncodedAuthenticatedFreshnessAnchorV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ParsedUntrustedAuthenticatedFreshnessAnchorV1 {
    key_generation_identifier: AnchorAuthenticationKeyGenerationIdentifier,
    authenticated_prefix: [u8; AUTHENTICATED_PREFIX_LENGTH],
    plaintext: [u8; PLAINTEXT_LENGTH],
    untrusted_tag: [u8; TAG_LENGTH],
}

impl ParsedUntrustedAuthenticatedFreshnessAnchorV1 {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, AuthenticatedAnchorFramingError> {
        if bytes.len() != AUTHENTICATED_ENVELOPE_LENGTH {
            return Err(AuthenticatedAnchorFramingError::WrongTotalLength);
        }
        if read_array::<8>(bytes, 0)? != MAGIC {
            return Err(AuthenticatedAnchorFramingError::WrongMagic);
        }
        if read_u16(bytes, VERSION_OFFSET)? != VERSION {
            return Err(AuthenticatedAnchorFramingError::UnsupportedVersion);
        }
        if read_u16(bytes, ALGORITHM_OFFSET)? != HMAC_SHA_256_ALGORITHM_IDENTIFIER {
            return Err(AuthenticatedAnchorFramingError::UnsupportedAuthenticationAlgorithm);
        }
        let key_generation_identifier = AnchorAuthenticationKeyGenerationIdentifier::from_bytes(
            read_array(bytes, KEY_GENERATION_IDENTIFIER_OFFSET)?,
        )
        .map_err(|_| AuthenticatedAnchorFramingError::InvalidKeyGenerationIdentifier)?;
        if read_u16(bytes, PLAINTEXT_LENGTH_OFFSET)? != DECLARED_PLAINTEXT_LENGTH {
            return Err(AuthenticatedAnchorFramingError::WrongPlaintextLength);
        }
        Ok(Self {
            key_generation_identifier,
            authenticated_prefix: read_array(bytes, 0)?,
            plaintext: read_array(bytes, PLAINTEXT_OFFSET)?,
            untrusted_tag: read_array(bytes, TAG_OFFSET)?,
        })
    }
}

impl fmt::Debug for ParsedUntrustedAuthenticatedFreshnessAnchorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParsedUntrustedAuthenticatedFreshnessAnchorV1([REDACTED])")
    }
}

pub(crate) struct CryptographicallyAuthenticatedFreshnessAnchorV1 {
    key_generation_identifier: AnchorAuthenticationKeyGenerationIdentifier,
    plaintext: [u8; PLAINTEXT_LENGTH],
}

impl CryptographicallyAuthenticatedFreshnessAnchorV1 {
    pub(crate) fn match_generation(
        self,
        recovered_identifier: &AnchorAuthenticationKeyGenerationIdentifier,
    ) -> Result<GenerationMatchedAuthenticatedFreshnessAnchorV1, AnchorGenerationMatchError> {
        if !self.key_generation_identifier.matches(recovered_identifier) {
            return Err(AnchorGenerationMatchError::GenerationMismatch);
        }
        Ok(GenerationMatchedAuthenticatedFreshnessAnchorV1 {
            plaintext: self.plaintext,
        })
    }
}

impl fmt::Debug for CryptographicallyAuthenticatedFreshnessAnchorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CryptographicallyAuthenticatedFreshnessAnchorV1([REDACTED])")
    }
}

pub(crate) struct GenerationMatchedAuthenticatedFreshnessAnchorV1 {
    plaintext: [u8; PLAINTEXT_LENGTH],
}

impl GenerationMatchedAuthenticatedFreshnessAnchorV1 {
    pub(crate) fn into_authenticated_plaintext(self) -> [u8; PLAINTEXT_LENGTH] {
        self.plaintext
    }
}

impl fmt::Debug for GenerationMatchedAuthenticatedFreshnessAnchorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenerationMatchedAuthenticatedFreshnessAnchorV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AnchorGenerationMatchError {
    GenerationMismatch,
}

impl fmt::Debug for AnchorGenerationMatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenerationMismatch")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthenticatedAnchorAuthenticationError {
    AuthenticationFailed,
}

impl fmt::Debug for AuthenticatedAnchorAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticationFailed")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthenticatedAnchorFramingError {
    WrongTotalLength,
    WrongMagic,
    UnsupportedVersion,
    UnsupportedAuthenticationAlgorithm,
    InvalidKeyGenerationIdentifier,
    WrongPlaintextLength,
    InternalFieldBoundaryFailure,
}

impl fmt::Debug for AuthenticatedAnchorFramingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongTotalLength => "WrongTotalLength",
            Self::WrongMagic => "WrongMagic",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::UnsupportedAuthenticationAlgorithm => "UnsupportedAuthenticationAlgorithm",
            Self::InvalidKeyGenerationIdentifier => "InvalidKeyGenerationIdentifier",
            Self::WrongPlaintextLength => "WrongPlaintextLength",
            Self::InternalFieldBoundaryFailure => "InternalFieldBoundaryFailure",
        })
    }
}

pub(crate) fn construct_authenticated_freshness_anchor_v1(
    authentication_key: &AnchorAuthenticationKey,
    key_generation_identifier: AnchorAuthenticationKeyGenerationIdentifier,
    canonical_plaintext: &EncodedFreshnessAnchorV1,
) -> Result<EncodedAuthenticatedFreshnessAnchorV1, AuthenticatedAnchorAuthenticationError> {
    let mut bytes = [0_u8; AUTHENTICATED_ENVELOPE_LENGTH];
    bytes[..VERSION_OFFSET].copy_from_slice(&MAGIC);
    bytes[VERSION_OFFSET..ALGORITHM_OFFSET].copy_from_slice(&VERSION.to_be_bytes());
    bytes[ALGORITHM_OFFSET..KEY_GENERATION_IDENTIFIER_OFFSET]
        .copy_from_slice(&HMAC_SHA_256_ALGORITHM_IDENTIFIER.to_be_bytes());
    key_generation_identifier.write_bytes_into(
        bytes[KEY_GENERATION_IDENTIFIER_OFFSET..PLAINTEXT_LENGTH_OFFSET]
            .as_mut()
            .try_into()
            .expect("fixed key-generation field has exact length"),
    );
    bytes[PLAINTEXT_LENGTH_OFFSET..PLAINTEXT_OFFSET]
        .copy_from_slice(&DECLARED_PLAINTEXT_LENGTH.to_be_bytes());
    bytes[PLAINTEXT_OFFSET..TAG_OFFSET].copy_from_slice(canonical_plaintext.as_bytes());

    let mut hmac = initialize_hmac(authentication_key)?;
    hmac.update(&bytes[..AUTHENTICATED_PREFIX_LENGTH]);
    bytes[TAG_OFFSET..].copy_from_slice(&hmac.finalize().into_bytes());
    Ok(EncodedAuthenticatedFreshnessAnchorV1 { bytes })
}

pub(crate) fn verify_authenticated_freshness_anchor_v1(
    parsed: ParsedUntrustedAuthenticatedFreshnessAnchorV1,
    authentication_key: &AnchorAuthenticationKey,
) -> Result<CryptographicallyAuthenticatedFreshnessAnchorV1, AuthenticatedAnchorAuthenticationError>
{
    let mut hmac = initialize_hmac(authentication_key)?;
    hmac.update(&parsed.authenticated_prefix);
    hmac.verify_slice(&parsed.untrusted_tag)
        .map_err(|_| AuthenticatedAnchorAuthenticationError::AuthenticationFailed)?;
    Ok(CryptographicallyAuthenticatedFreshnessAnchorV1 {
        key_generation_identifier: parsed.key_generation_identifier,
        plaintext: parsed.plaintext,
    })
}

fn initialize_hmac(
    authentication_key: &AnchorAuthenticationKey,
) -> Result<HmacSha256, AuthenticatedAnchorAuthenticationError> {
    authentication_key
        .expose_bytes(|key_bytes| HmacSha256::new_from_slice(key_bytes))
        .map_err(|_| AuthenticatedAnchorAuthenticationError::AuthenticationFailed)
}

fn read_array<const LENGTH: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; LENGTH], AuthenticatedAnchorFramingError> {
    bytes
        .get(offset..offset + LENGTH)
        .and_then(|field| field.try_into().ok())
        .ok_or(AuthenticatedAnchorFramingError::InternalFieldBoundaryFailure)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AuthenticatedAnchorFramingError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        freshness_anchor_contract::FreshnessAnchorContractV1,
        freshness_anchor_plaintext::{
            FreshnessAnchorParseError, FreshnessAnchorStructuralValidationError,
            ParsedUntrustedFreshnessAnchorV1, SEMANTIC_PAYLOAD_LENGTH,
        },
        installation_evidence_contract::{
            DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
            RecoveryOrReplacementGeneration, SetupPublicationIdentifier,
        },
    };

    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const GENERATION: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];
    const EXPECTED_TAG: [u8; 32] = [
        0x5e, 0x75, 0xbf, 0x62, 0x02, 0x64, 0xbe, 0x9d, 0xd0, 0x9e, 0xa2, 0x06, 0xe1, 0xe4, 0x22,
        0xb6, 0xe2, 0x4a, 0x61, 0x16, 0x85, 0x1d, 0x6f, 0xf6, 0xdc, 0x3f, 0xc9, 0x9a, 0x69, 0x49,
        0x6b, 0xda,
    ];

    fn plaintext() -> EncodedFreshnessAnchorV1 {
        EncodedFreshnessAnchorV1::encode(&FreshnessAnchorContractV1::new(
            InstallationIdentifier::from_bytes([
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ])
            .unwrap(),
            InstallationGeneration::new(0x0102_0304_0506_0708).unwrap(),
            RecoveryOrReplacementGeneration::new(0x1112_1314_1516_1718).unwrap(),
            DatabaseKeyGenerationIdentifier::from_bytes([
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
                0x3e, 0x3f,
            ])
            .unwrap(),
            SetupPublicationIdentifier::from_bytes([
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
                0x4e, 0x4f,
            ])
            .unwrap(),
        ))
    }

    fn identifier(bytes: [u8; 16]) -> AnchorAuthenticationKeyGenerationIdentifier {
        AnchorAuthenticationKeyGenerationIdentifier::from_bytes(bytes).unwrap()
    }

    fn envelope_with(
        key_bytes: [u8; 32],
        generation: [u8; 16],
    ) -> EncodedAuthenticatedFreshnessAnchorV1 {
        construct_authenticated_freshness_anchor_v1(
            &AnchorAuthenticationKey::from_bytes(key_bytes),
            identifier(generation),
            &plaintext(),
        )
        .unwrap()
    }

    fn envelope() -> EncodedAuthenticatedFreshnessAnchorV1 {
        envelope_with(KEY, GENERATION)
    }

    fn retag(bytes: &mut [u8; AUTHENTICATED_ENVELOPE_LENGTH], key: &[u8; 32]) {
        let mut hmac = HmacSha256::new_from_slice(key).unwrap();
        hmac.update(&bytes[..AUTHENTICATED_PREFIX_LENGTH]);
        bytes[TAG_OFFSET..].copy_from_slice(&hmac.finalize().into_bytes());
    }

    #[test]
    fn golden_vector_offsets_sizes_determinism_and_independent_tag_are_exact() {
        let first = envelope();
        let second = envelope();
        assert_eq!(SEMANTIC_PAYLOAD_LENGTH, 64);
        assert_eq!(PLAINTEXT_LENGTH, 76);
        assert_eq!(AUTHENTICATED_PREFIX_LENGTH, 106);
        assert_eq!(AUTHENTICATED_ENVELOPE_LENGTH, 138);
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(&first.as_bytes()[0..8], b"CHANAUTH");
        assert_eq!(&first.as_bytes()[8..10], &[0, 1]);
        assert_eq!(&first.as_bytes()[10..12], &[0, 1]);
        assert_eq!(&first.as_bytes()[12..28], &GENERATION);
        assert_eq!(&first.as_bytes()[28..30], &[0, 76]);
        assert_eq!(&first.as_bytes()[30..106], plaintext().as_bytes());
        assert_eq!(&first.as_bytes()[106..138], &EXPECTED_TAG);
        // EXPECTED_TAG was independently computed with .NET HMACSHA256 over bytes 0..106.
    }

    #[test]
    fn strict_parser_rejects_lengths_magic_versions_algorithms_identifiers_and_lengths() {
        let valid = envelope();
        for length in 0..138 {
            assert!(
                ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(&valid.as_bytes()[..length])
                    .is_err()
            );
        }
        for length in [139, 200, 512] {
            let mut input = valid.as_bytes().to_vec();
            input.resize(length, 0);
            assert_eq!(
                ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(&input),
                Err(AuthenticatedAnchorFramingError::WrongTotalLength)
            );
        }
        for offset in 0..8 {
            let mut input = *valid.as_bytes();
            input[offset] ^= 1;
            assert_eq!(
                ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(&input),
                Err(AuthenticatedAnchorFramingError::WrongMagic)
            );
        }
        for (range, values, expected) in [
            (
                8..10,
                [[0, 2], [1, 0], [0xff, 0xff]],
                AuthenticatedAnchorFramingError::UnsupportedVersion,
            ),
            (
                10..12,
                [[0, 2], [1, 0], [0xff, 0xff]],
                AuthenticatedAnchorFramingError::UnsupportedAuthenticationAlgorithm,
            ),
            (
                28..30,
                [[0, 75], [76, 0], [0xff, 0xff]],
                AuthenticatedAnchorFramingError::WrongPlaintextLength,
            ),
        ] {
            for value in values {
                let mut input = *valid.as_bytes();
                input[range.clone()].copy_from_slice(&value);
                assert_eq!(
                    ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(&input),
                    Err(expected)
                );
            }
        }
        let mut input = *valid.as_bytes();
        input[12..28].fill(0);
        assert_eq!(
            ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(&input),
            Err(AuthenticatedAnchorFramingError::InvalidKeyGenerationIdentifier)
        );
    }

    #[test]
    fn every_parseable_prefix_mutation_and_every_tag_mutation_fails_authentication() {
        let valid = envelope();
        let key = AnchorAuthenticationKey::from_bytes(KEY);
        for offset in 0..AUTHENTICATED_PREFIX_LENGTH {
            let mut input = *valid.as_bytes();
            input[offset] ^= 1;
            if let Ok(parsed) = ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(&input) {
                assert!(
                    verify_authenticated_freshness_anchor_v1(parsed, &key).is_err(),
                    "offset {offset}"
                );
            }
        }
        for offset in TAG_OFFSET..AUTHENTICATED_ENVELOPE_LENGTH {
            let mut input = *valid.as_bytes();
            input[offset] ^= 1;
            let parsed = ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(&input).unwrap();
            assert!(
                verify_authenticated_freshness_anchor_v1(parsed, &key).is_err(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn wrong_keys_wrong_tags_and_unretagged_generation_changes_fail_authentication() {
        let valid = envelope();
        let parsed =
            ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(valid.as_bytes()).unwrap();
        assert!(
            verify_authenticated_freshness_anchor_v1(
                parsed,
                &AnchorAuthenticationKey::from_bytes([0x55; 32])
            )
            .is_err()
        );
        let mut wrong_tag = *valid.as_bytes();
        wrong_tag[137] ^= 1;
        assert!(
            verify_authenticated_freshness_anchor_v1(
                ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(&wrong_tag).unwrap(),
                &AnchorAuthenticationKey::from_bytes(KEY)
            )
            .is_err()
        );
        let mut altered_generation = *valid.as_bytes();
        altered_generation[12] ^= 1;
        assert!(
            verify_authenticated_freshness_anchor_v1(
                ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(&altered_generation).unwrap(),
                &AnchorAuthenticationKey::from_bytes(KEY)
            )
            .is_err()
        );
    }

    #[test]
    fn retagged_inner_failures_authenticate_then_fail_at_their_later_boundary() {
        let valid = envelope();
        let key = AnchorAuthenticationKey::from_bytes(KEY);

        let mut malformed = *valid.as_bytes();
        malformed[30] ^= 1;
        retag(&mut malformed, &KEY);
        let authenticated = verify_authenticated_freshness_anchor_v1(
            ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(&malformed).unwrap(),
            &key,
        )
        .unwrap();
        let matched = authenticated
            .match_generation(&identifier(GENERATION))
            .unwrap();
        assert_eq!(
            ParsedUntrustedFreshnessAnchorV1::parse(&matched.into_authenticated_plaintext()),
            Err(FreshnessAnchorParseError::WrongMagic)
        );

        let mut structurally_invalid = *valid.as_bytes();
        structurally_invalid[30 + 12..30 + 28].fill(0);
        retag(&mut structurally_invalid, &KEY);
        let authenticated = verify_authenticated_freshness_anchor_v1(
            ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(&structurally_invalid).unwrap(),
            &key,
        )
        .unwrap();
        let matched = authenticated
            .match_generation(&identifier(GENERATION))
            .unwrap();
        assert_eq!(
            ParsedUntrustedFreshnessAnchorV1::parse(&matched.into_authenticated_plaintext())
                .unwrap()
                .validate_structure(),
            Err(FreshnessAnchorStructuralValidationError::InstallationIdentifier)
        );
    }

    #[test]
    fn generation_matching_is_post_authentication_and_mismatch_is_payload_free() {
        let valid = envelope();
        let key = AnchorAuthenticationKey::from_bytes(KEY);
        let authenticated = verify_authenticated_freshness_anchor_v1(
            ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(valid.as_bytes()).unwrap(),
            &key,
        )
        .unwrap();
        let mismatch = authenticated
            .match_generation(&identifier([0xbb; 16]))
            .unwrap_err();
        assert_eq!(mismatch, AnchorGenerationMatchError::GenerationMismatch);
        assert_eq!(format!("{mismatch:?}"), "GenerationMismatch");

        let mut retagged_generation = *valid.as_bytes();
        retagged_generation[12..28].copy_from_slice(&[0xbb; 16]);
        retag(&mut retagged_generation, &KEY);
        let authenticated = verify_authenticated_freshness_anchor_v1(
            ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(&retagged_generation).unwrap(),
            &key,
        )
        .unwrap();
        let matched = authenticated
            .match_generation(&identifier([0xbb; 16]))
            .unwrap();
        assert_eq!(
            matched.into_authenticated_plaintext(),
            *plaintext().as_bytes()
        );
    }

    #[test]
    fn source_proves_authentication_before_matching_and_matched_only_plaintext_release() {
        const SOURCE: &str = include_str!("freshness_anchor_authenticated_envelope.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let verify = production
            .split_once("pub(crate) fn verify_authenticated_freshness_anchor_v1(")
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(verify.contains("verify_slice"));
        assert!(!verify.contains("match_generation"));
        let match_body = production
            .split_once("pub(crate) fn match_generation(")
            .unwrap()
            .1
            .split_once("\n    }")
            .unwrap()
            .0;
        assert!(match_body.contains("matches(recovered_identifier)"));
        assert_eq!(
            production
                .matches("fn into_authenticated_plaintext(")
                .count(),
            1
        );
        let before_release = production
            .split_once("fn into_authenticated_plaintext(")
            .unwrap()
            .0;
        assert!(
            before_release.ends_with(
                "impl GenerationMatchedAuthenticatedFreshnessAnchorV1 {\n    pub(crate) "
            )
        );
        assert!(production.contains("hmac.update(&bytes[..AUTHENTICATED_PREFIX_LENGTH])"));
        assert!(production.contains("hmac.update(&parsed.authenticated_prefix)"));
        for excluded in [
            "std::fs",
            "std::path",
            "windows",
            "dpapi",
            "getrandom",
            "rusqlite",
            "tauri",
            "unsafe",
            "persist",
            "publish",
            "startup",
            "recovery",
            "replacement",
            "migration",
            "AssuredFreshnessAnchor",
        ] {
            assert!(
                !production.contains(excluded),
                "unexpected capability: {excluded}"
            );
        }
    }

    #[test]
    fn debug_outputs_are_fully_redacted_and_identifier_is_distinct_nonzero() {
        assert_eq!(
            AnchorAuthenticationKeyGenerationIdentifier::from_bytes([0; 16]),
            Err(AnchorKeyGenerationIdentifierError::AllZero)
        );
        let id = identifier(GENERATION);
        assert_eq!(
            format!("{id:?}"),
            "AnchorAuthenticationKeyGenerationIdentifier([REDACTED])"
        );
        let encoded = envelope();
        let parsed =
            ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(encoded.as_bytes()).unwrap();
        assert_eq!(
            format!("{encoded:?}"),
            "EncodedAuthenticatedFreshnessAnchorV1([REDACTED])"
        );
        assert_eq!(
            format!("{parsed:?}"),
            "ParsedUntrustedAuthenticatedFreshnessAnchorV1([REDACTED])"
        );
    }
}
