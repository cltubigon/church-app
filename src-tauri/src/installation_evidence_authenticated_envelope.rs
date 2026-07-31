//! Strict framing and HMAC-SHA-256 authentication for the version-1
//! installation-evidence authenticated envelope.
//!
//! Framing, authentication, inner-plaintext parsing, and structural validation
//! remain separate transitions. Authentication establishes only that a holder
//! of the caller-supplied key authenticated the exact envelope prefix.

// These crate-private contract types intentionally have no production caller
// until a separately approved authentication stage exists.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    installation_evidence_authentication_key::EvidenceAuthenticationKey,
    installation_evidence_contract::{
        EncodedInstallationEvidence, InstallationEvidenceParseError,
        ParsedUntrustedInstallationEvidenceContract,
    },
};

type HmacSha256 = Hmac<Sha256>;

const AUTHENTICATED_ENVELOPE_V1_LENGTH: usize = 226;
const AUTHENTICATION_INPUT_PREFIX_V1_LENGTH: usize = 194;
const AUTHENTICATION_TAG_V1_LENGTH: usize = 32;
const AUTHENTICATED_ENVELOPE_MAGIC: [u8; 8] = *b"CHEVAUTH";
const SUPPORTED_AUTHENTICATED_ENVELOPE_VERSION: u16 = 1;
const SUPPORTED_AUTHENTICATION_ALGORITHM_IDENTIFIER: u16 = 1;
const EVIDENCE_AUTHENTICATION_KEY_GENERATION_IDENTIFIER_LENGTH: usize = 16;
const CANONICAL_INSTALLATION_EVIDENCE_PLAINTEXT_LENGTH: usize = 164;
const DECLARED_CANONICAL_INSTALLATION_EVIDENCE_PLAINTEXT_LENGTH: u16 = 164;

const ENVELOPE_MAGIC_OFFSET: usize = 0;
const ENVELOPE_VERSION_OFFSET: usize = 8;
const AUTHENTICATION_ALGORITHM_IDENTIFIER_OFFSET: usize = 10;
const EVIDENCE_AUTHENTICATION_KEY_GENERATION_IDENTIFIER_OFFSET: usize = 12;
const CANONICAL_PLAINTEXT_LENGTH_OFFSET: usize = 28;
const CANONICAL_PLAINTEXT_OFFSET: usize = 30;
const UNTRUSTED_AUTHENTICATION_TAG_OFFSET: usize = AUTHENTICATION_INPUT_PREFIX_V1_LENGTH;
const AUTHENTICATED_ENVELOPE_END_OFFSET: usize = AUTHENTICATED_ENVELOPE_V1_LENGTH;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct EvidenceAuthenticationKeyGenerationIdentifier([u8; 16]);

impl EvidenceAuthenticationKeyGenerationIdentifier {
    pub(crate) fn from_bytes(value: [u8; 16]) -> Result<Self, AuthenticatedEnvelopeFramingError> {
        if value == [0; 16] {
            return Err(
                AuthenticatedEnvelopeFramingError::InvalidAuthenticationKeyGenerationIdentifier,
            );
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

impl fmt::Debug for EvidenceAuthenticationKeyGenerationIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EvidenceAuthenticationKeyGenerationIdentifier([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct EncodedAuthenticatedEnvelopeV1 {
    bytes: [u8; AUTHENTICATED_ENVELOPE_V1_LENGTH],
}

impl fmt::Debug for EncodedAuthenticatedEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedAuthenticatedEnvelopeV1")
            .field("length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl EncodedAuthenticatedEnvelopeV1 {
    pub(crate) const fn as_bytes(&self) -> &[u8; AUTHENTICATED_ENVELOPE_V1_LENGTH] {
        &self.bytes
    }
}

/// Version-1 envelope fields decoded from correctly framed but untrusted bytes.
///
/// The terminal field remains an untrusted tag pattern. This type has no
/// authentication, inner-plaintext parsing, structural-validation, or
/// operational-state transition.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ParsedUntrustedAuthenticatedEnvelopeV1 {
    key_generation_identifier: EvidenceAuthenticationKeyGenerationIdentifier,
    authenticated_prefix_bytes: [u8; AUTHENTICATION_INPUT_PREFIX_V1_LENGTH],
    plaintext_bytes: [u8; CANONICAL_INSTALLATION_EVIDENCE_PLAINTEXT_LENGTH],
    untrusted_tag_bytes: [u8; AUTHENTICATION_TAG_V1_LENGTH],
}

impl ParsedUntrustedAuthenticatedEnvelopeV1 {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, AuthenticatedEnvelopeFramingError> {
        if bytes.len() != AUTHENTICATED_ENVELOPE_V1_LENGTH {
            return Err(AuthenticatedEnvelopeFramingError::WrongTotalLength {
                observed_length: bytes.len(),
            });
        }

        if read_array::<8>(bytes, ENVELOPE_MAGIC_OFFSET)? != AUTHENTICATED_ENVELOPE_MAGIC {
            return Err(AuthenticatedEnvelopeFramingError::WrongEnvelopeMagic);
        }
        if read_u16(bytes, ENVELOPE_VERSION_OFFSET)? != SUPPORTED_AUTHENTICATED_ENVELOPE_VERSION {
            return Err(AuthenticatedEnvelopeFramingError::UnsupportedEnvelopeVersion);
        }
        if read_u16(bytes, AUTHENTICATION_ALGORITHM_IDENTIFIER_OFFSET)?
            != SUPPORTED_AUTHENTICATION_ALGORITHM_IDENTIFIER
        {
            return Err(AuthenticatedEnvelopeFramingError::UnsupportedAuthenticationAlgorithm);
        }

        let key_generation_identifier =
            EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(read_array::<
                EVIDENCE_AUTHENTICATION_KEY_GENERATION_IDENTIFIER_LENGTH,
            >(
                bytes,
                EVIDENCE_AUTHENTICATION_KEY_GENERATION_IDENTIFIER_OFFSET,
            )?)?;

        if read_u16(bytes, CANONICAL_PLAINTEXT_LENGTH_OFFSET)?
            != DECLARED_CANONICAL_INSTALLATION_EVIDENCE_PLAINTEXT_LENGTH
        {
            return Err(AuthenticatedEnvelopeFramingError::WrongDeclaredPlaintextLength);
        }

        Ok(Self {
            key_generation_identifier,
            authenticated_prefix_bytes: read_array(bytes, ENVELOPE_MAGIC_OFFSET)?,
            plaintext_bytes: read_array(bytes, CANONICAL_PLAINTEXT_OFFSET)?,
            untrusted_tag_bytes: read_array(bytes, UNTRUSTED_AUTHENTICATION_TAG_OFFSET)?,
        })
    }
}

impl fmt::Debug for ParsedUntrustedAuthenticatedEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedUntrustedAuthenticatedEnvelopeV1")
            .field(
                "envelope_version",
                &SUPPORTED_AUTHENTICATED_ENVELOPE_VERSION,
            )
            .field(
                "authentication_algorithm_identifier",
                &SUPPORTED_AUTHENTICATION_ALGORITHM_IDENTIFIER,
            )
            .field("key_generation_identifier", &"[REDACTED]")
            .field("plaintext_length", &self.plaintext_bytes.len())
            .field("plaintext_bytes", &"[REDACTED]")
            .field("untrusted_tag_length", &self.untrusted_tag_bytes.len())
            .field("untrusted_tag_bytes", &"[REDACTED]")
            .finish()
    }
}

/// An envelope whose exact version-1 prefix has passed HMAC-SHA-256
/// authentication, or was produced by the trusted construction boundary.
///
/// This type carries no authentication key and establishes no freshness,
/// rollback protection, database correspondence, startup permission, or
/// operational installation state.
pub(crate) struct CryptographicallyAuthenticatedEnvelopeV1 {
    key_generation_identifier: EvidenceAuthenticationKeyGenerationIdentifier,
    plaintext_bytes: [u8; CANONICAL_INSTALLATION_EVIDENCE_PLAINTEXT_LENGTH],
}

impl CryptographicallyAuthenticatedEnvelopeV1 {
    pub(crate) fn match_generation(
        self,
        recovered_identifier: &EvidenceAuthenticationKeyGenerationIdentifier,
    ) -> Result<GenerationMatchedAuthenticatedEnvelopeV1, GenerationMatchError> {
        if !self.key_generation_identifier.matches(recovered_identifier) {
            return Err(GenerationMatchError::GenerationMismatch);
        }

        Ok(GenerationMatchedAuthenticatedEnvelopeV1 {
            plaintext_bytes: self.plaintext_bytes,
        })
    }
}

impl fmt::Debug for CryptographicallyAuthenticatedEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CryptographicallyAuthenticatedEnvelopeV1([REDACTED])")
    }
}

pub(crate) struct GenerationMatchedAuthenticatedEnvelopeV1 {
    plaintext_bytes: [u8; CANONICAL_INSTALLATION_EVIDENCE_PLAINTEXT_LENGTH],
}

impl GenerationMatchedAuthenticatedEnvelopeV1 {
    pub(crate) fn parse_inner_plaintext(
        &self,
    ) -> Result<ParsedUntrustedInstallationEvidenceContract, InstallationEvidenceParseError> {
        ParsedUntrustedInstallationEvidenceContract::parse_v1(&self.plaintext_bytes)
    }
}

impl fmt::Debug for GenerationMatchedAuthenticatedEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenerationMatchedAuthenticatedEnvelopeV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum GenerationMatchError {
    GenerationMismatch,
}

impl fmt::Debug for GenerationMatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenerationMismatch")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthenticatedEnvelopeAuthenticationError {
    AuthenticationFailed,
}

impl fmt::Debug for AuthenticatedEnvelopeAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => formatter.write_str("AuthenticationFailed"),
        }
    }
}

pub(crate) fn construct_authenticated_envelope_v1(
    authentication_key: &EvidenceAuthenticationKey,
    key_generation_identifier: EvidenceAuthenticationKeyGenerationIdentifier,
    canonical_plaintext: &EncodedInstallationEvidence,
) -> Result<
    (
        EncodedAuthenticatedEnvelopeV1,
        CryptographicallyAuthenticatedEnvelopeV1,
    ),
    AuthenticatedEnvelopeAuthenticationError,
> {
    let mut bytes = [0_u8; AUTHENTICATED_ENVELOPE_V1_LENGTH];
    bytes[ENVELOPE_MAGIC_OFFSET..ENVELOPE_VERSION_OFFSET]
        .copy_from_slice(&AUTHENTICATED_ENVELOPE_MAGIC);
    bytes[ENVELOPE_VERSION_OFFSET..AUTHENTICATION_ALGORITHM_IDENTIFIER_OFFSET]
        .copy_from_slice(&SUPPORTED_AUTHENTICATED_ENVELOPE_VERSION.to_be_bytes());
    bytes[AUTHENTICATION_ALGORITHM_IDENTIFIER_OFFSET
        ..EVIDENCE_AUTHENTICATION_KEY_GENERATION_IDENTIFIER_OFFSET]
        .copy_from_slice(&SUPPORTED_AUTHENTICATION_ALGORITHM_IDENTIFIER.to_be_bytes());
    bytes[EVIDENCE_AUTHENTICATION_KEY_GENERATION_IDENTIFIER_OFFSET
        ..CANONICAL_PLAINTEXT_LENGTH_OFFSET]
        .copy_from_slice(&key_generation_identifier.0);
    bytes[CANONICAL_PLAINTEXT_LENGTH_OFFSET..CANONICAL_PLAINTEXT_OFFSET]
        .copy_from_slice(&DECLARED_CANONICAL_INSTALLATION_EVIDENCE_PLAINTEXT_LENGTH.to_be_bytes());
    bytes[CANONICAL_PLAINTEXT_OFFSET..UNTRUSTED_AUTHENTICATION_TAG_OFFSET]
        .copy_from_slice(canonical_plaintext.as_bytes());

    let mut hmac = initialize_hmac(authentication_key)?;
    hmac.update(&bytes[..AUTHENTICATION_INPUT_PREFIX_V1_LENGTH]);
    let tag = hmac.finalize().into_bytes();
    bytes[UNTRUSTED_AUTHENTICATION_TAG_OFFSET..AUTHENTICATED_ENVELOPE_END_OFFSET]
        .copy_from_slice(&tag);

    Ok((
        EncodedAuthenticatedEnvelopeV1 { bytes },
        CryptographicallyAuthenticatedEnvelopeV1 {
            key_generation_identifier,
            plaintext_bytes: *canonical_plaintext.as_bytes(),
        },
    ))
}

pub(crate) fn verify_authenticated_envelope_v1(
    parsed_untrusted_envelope: ParsedUntrustedAuthenticatedEnvelopeV1,
    authentication_key: &EvidenceAuthenticationKey,
) -> Result<CryptographicallyAuthenticatedEnvelopeV1, AuthenticatedEnvelopeAuthenticationError> {
    let mut hmac = initialize_hmac(authentication_key)?;
    hmac.update(&parsed_untrusted_envelope.authenticated_prefix_bytes);
    hmac.verify_slice(&parsed_untrusted_envelope.untrusted_tag_bytes)
        .map_err(|_| AuthenticatedEnvelopeAuthenticationError::AuthenticationFailed)?;

    Ok(CryptographicallyAuthenticatedEnvelopeV1 {
        key_generation_identifier: parsed_untrusted_envelope.key_generation_identifier,
        plaintext_bytes: parsed_untrusted_envelope.plaintext_bytes,
    })
}

fn initialize_hmac(
    authentication_key: &EvidenceAuthenticationKey,
) -> Result<HmacSha256, AuthenticatedEnvelopeAuthenticationError> {
    authentication_key
        .expose_bytes(|key_bytes| HmacSha256::new_from_slice(key_bytes))
        .map_err(|_| AuthenticatedEnvelopeAuthenticationError::AuthenticationFailed)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthenticatedEnvelopeFramingError {
    WrongTotalLength { observed_length: usize },
    WrongEnvelopeMagic,
    UnsupportedEnvelopeVersion,
    UnsupportedAuthenticationAlgorithm,
    InvalidAuthenticationKeyGenerationIdentifier,
    WrongDeclaredPlaintextLength,
    InternalFieldBoundaryFailure,
}

impl fmt::Debug for AuthenticatedEnvelopeFramingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongTotalLength { observed_length } => formatter
                .debug_struct("WrongTotalLength")
                .field("observed_length", observed_length)
                .finish(),
            Self::WrongEnvelopeMagic => formatter.write_str("WrongEnvelopeMagic"),
            Self::UnsupportedEnvelopeVersion => formatter.write_str("UnsupportedEnvelopeVersion"),
            Self::UnsupportedAuthenticationAlgorithm => {
                formatter.write_str("UnsupportedAuthenticationAlgorithm")
            }
            Self::InvalidAuthenticationKeyGenerationIdentifier => {
                formatter.write_str("InvalidAuthenticationKeyGenerationIdentifier")
            }
            Self::WrongDeclaredPlaintextLength => {
                formatter.write_str("WrongDeclaredPlaintextLength")
            }
            Self::InternalFieldBoundaryFailure => {
                formatter.write_str("InternalFieldBoundaryFailure")
            }
        }
    }
}

fn read_array<const LENGTH: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; LENGTH], AuthenticatedEnvelopeFramingError> {
    bytes
        .get(offset..offset + LENGTH)
        .and_then(|field| field.try_into().ok())
        .ok_or(AuthenticatedEnvelopeFramingError::InternalFieldBoundaryFailure)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AuthenticatedEnvelopeFramingError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        installation_evidence_authentication_key::EvidenceAuthenticationKey,
        installation_evidence_contract::{
            ContractValidationError, EncodedInstallationEvidence,
            INSTALLATION_EVIDENCE_FORMAT_IDENTITY, InstallationGeneration,
            PERMANENT_APPLICATION_IDENTIFIER, RecoveryOrReplacementGeneration,
            SUPPORTED_EVIDENCE_FORMAT_VERSION, UnvalidatedInstallationEvidenceContract,
        },
        installation_state::{InstallationEvidence, StorageDecision, decide_ordinary_startup},
        storage_foundation::APPLICATION_DATABASE_FORMAT_IDENTITY,
    };

    const SYNTHETIC_PARISH_IDENTIFIER: &str = "101112131415161718191a1b1c1d1e1f";
    const SYNTHETIC_INSTALLATION_IDENTIFIER: [u8; 16] = [0x31; 16];
    const SYNTHETIC_DATABASE_KEY_GENERATION_IDENTIFIER: [u8; 16] = [0x42; 16];
    const SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER: [u8; 16] = [0x53; 16];
    const SYNTHETIC_AUTHENTICATION_KEY_GENERATION_IDENTIFIER: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];
    const SYNTHETIC_UNTRUSTED_TAG_PATTERN: [u8; 32] = [
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde,
        0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed,
        0xee, 0xef,
    ];
    const SYNTHETIC_AUTHENTICATION_KEY: [u8; 32] = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1,
        0xf0, 0x01,
    ];

    fn canonical_plaintext() -> EncodedInstallationEvidence {
        UnvalidatedInstallationEvidenceContract::new(
            *INSTALLATION_EVIDENCE_FORMAT_IDENTITY.as_bytes(),
            SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            SYNTHETIC_PARISH_IDENTIFIER,
            SYNTHETIC_INSTALLATION_IDENTIFIER,
            InstallationGeneration::INITIAL.get(),
            RecoveryOrReplacementGeneration::INITIAL.get(),
            SYNTHETIC_DATABASE_KEY_GENERATION_IDENTIFIER,
            SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER,
            1_800_000_000,
        )
        .validate()
        .expect("synthetic plaintext contract should validate")
        .encode_v1()
    }

    fn alternate_canonical_plaintext() -> EncodedInstallationEvidence {
        UnvalidatedInstallationEvidenceContract::new(
            *INSTALLATION_EVIDENCE_FORMAT_IDENTITY.as_bytes(),
            SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            SYNTHETIC_PARISH_IDENTIFIER,
            SYNTHETIC_INSTALLATION_IDENTIFIER,
            InstallationGeneration::INITIAL.get(),
            RecoveryOrReplacementGeneration::INITIAL.get(),
            SYNTHETIC_DATABASE_KEY_GENERATION_IDENTIFIER,
            SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER,
            1_800_000_001,
        )
        .validate()
        .expect("alternate synthetic plaintext contract should validate")
        .encode_v1()
    }

    fn synthetic_framing_fixture() -> EncodedAuthenticatedEnvelopeV1 {
        let plaintext = canonical_plaintext();
        let mut bytes = [0_u8; AUTHENTICATED_ENVELOPE_V1_LENGTH];
        bytes[ENVELOPE_MAGIC_OFFSET..ENVELOPE_VERSION_OFFSET]
            .copy_from_slice(&AUTHENTICATED_ENVELOPE_MAGIC);
        bytes[ENVELOPE_VERSION_OFFSET..AUTHENTICATION_ALGORITHM_IDENTIFIER_OFFSET]
            .copy_from_slice(&SUPPORTED_AUTHENTICATED_ENVELOPE_VERSION.to_be_bytes());
        bytes[AUTHENTICATION_ALGORITHM_IDENTIFIER_OFFSET
            ..EVIDENCE_AUTHENTICATION_KEY_GENERATION_IDENTIFIER_OFFSET]
            .copy_from_slice(&SUPPORTED_AUTHENTICATION_ALGORITHM_IDENTIFIER.to_be_bytes());
        bytes[EVIDENCE_AUTHENTICATION_KEY_GENERATION_IDENTIFIER_OFFSET
            ..CANONICAL_PLAINTEXT_LENGTH_OFFSET]
            .copy_from_slice(&SYNTHETIC_AUTHENTICATION_KEY_GENERATION_IDENTIFIER);
        bytes[CANONICAL_PLAINTEXT_LENGTH_OFFSET..CANONICAL_PLAINTEXT_OFFSET].copy_from_slice(
            &DECLARED_CANONICAL_INSTALLATION_EVIDENCE_PLAINTEXT_LENGTH.to_be_bytes(),
        );
        bytes[CANONICAL_PLAINTEXT_OFFSET..UNTRUSTED_AUTHENTICATION_TAG_OFFSET]
            .copy_from_slice(plaintext.as_bytes());
        bytes[UNTRUSTED_AUTHENTICATION_TAG_OFFSET..AUTHENTICATED_ENVELOPE_END_OFFSET]
            .copy_from_slice(&SYNTHETIC_UNTRUSTED_TAG_PATTERN);

        EncodedAuthenticatedEnvelopeV1 { bytes }
    }

    fn synthetic_key(bytes: [u8; 32]) -> EvidenceAuthenticationKey {
        EvidenceAuthenticationKey::from_bytes(bytes)
    }

    fn synthetic_key_generation_identifier() -> EvidenceAuthenticationKeyGenerationIdentifier {
        EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(
            SYNTHETIC_AUTHENTICATION_KEY_GENERATION_IDENTIFIER,
        )
        .expect("synthetic key-generation identifier should be nonzero")
    }

    fn construct_synthetic_authenticated_envelope() -> (
        EncodedAuthenticatedEnvelopeV1,
        CryptographicallyAuthenticatedEnvelopeV1,
    ) {
        construct_authenticated_envelope_v1(
            &synthetic_key(SYNTHETIC_AUTHENTICATION_KEY),
            synthetic_key_generation_identifier(),
            &canonical_plaintext(),
        )
        .expect("fixed-length HMAC key should construct an envelope")
    }

    fn mutate_envelope_byte(
        bytes: &[u8; AUTHENTICATED_ENVELOPE_V1_LENGTH],
        index: usize,
    ) -> [u8; AUTHENTICATED_ENVELOPE_V1_LENGTH] {
        let mut mutated = *bytes;
        mutated[index] ^= 0x01;
        mutated
    }

    fn retag_synthetic_envelope(
        bytes: &mut [u8; AUTHENTICATED_ENVELOPE_V1_LENGTH],
        key: &EvidenceAuthenticationKey,
    ) {
        let mut hmac = initialize_hmac(key).expect("fixed synthetic key should initialize HMAC");
        hmac.update(&bytes[..AUTHENTICATION_INPUT_PREFIX_V1_LENGTH]);
        let tag = hmac.finalize().into_bytes();
        bytes[UNTRUSTED_AUTHENTICATION_TAG_OFFSET..AUTHENTICATED_ENVELOPE_END_OFFSET]
            .copy_from_slice(&tag);
    }

    fn authenticate_synthetic_bytes(
        bytes: &[u8; AUTHENTICATED_ENVELOPE_V1_LENGTH],
        key: &EvidenceAuthenticationKey,
    ) -> GenerationMatchedAuthenticatedEnvelopeV1 {
        let parsed = ParsedUntrustedAuthenticatedEnvelopeV1::parse(bytes)
            .expect("synthetic outer framing should parse");
        verify_authenticated_envelope_v1(parsed, key)
            .expect("correctly retagged synthetic bytes should authenticate")
            .match_generation(&synthetic_key_generation_identifier())
            .expect("synthetic generation should match")
    }

    fn assert_authentication_error_is_safe(error: AuthenticatedEnvelopeAuthenticationError) {
        assert_eq!(
            error,
            AuthenticatedEnvelopeAuthenticationError::AuthenticationFailed
        );
        assert_eq!(format!("{error:?}"), "AuthenticationFailed");
    }

    fn assert_framing_or_authentication_failure(input: &[u8]) {
        match ParsedUntrustedAuthenticatedEnvelopeV1::parse(input) {
            Err(error) => {
                let debug = format!("{error:?}");
                assert!(!debug.contains("CHEVAUTH"));
                assert!(!debug.contains("[0, 255"));
                assert!(!debug.contains("[170, 85"));
            }
            Ok(parsed) => {
                let parsed_debug = format!("{parsed:?}");
                assert!(parsed_debug.contains("[REDACTED]"));
                assert!(!parsed_debug.contains("CHEVAUTH"));
                let error = verify_authenticated_envelope_v1(
                    parsed,
                    &synthetic_key(SYNTHETIC_AUTHENTICATION_KEY),
                )
                .expect_err("an invalid deterministic input must not authenticate");
                assert_authentication_error_is_safe(error);
            }
        }
    }

    #[test]
    fn version_1_layout_reconciles_without_gaps_or_overlap() {
        assert_eq!(AUTHENTICATED_ENVELOPE_MAGIC.len(), 8);
        assert_eq!(EVIDENCE_AUTHENTICATION_KEY_GENERATION_IDENTIFIER_LENGTH, 16);
        assert_eq!(CANONICAL_INSTALLATION_EVIDENCE_PLAINTEXT_LENGTH, 164);
        assert_eq!(AUTHENTICATION_TAG_V1_LENGTH, 32);
        assert_eq!(
            CANONICAL_PLAINTEXT_OFFSET + 164,
            AUTHENTICATION_INPUT_PREFIX_V1_LENGTH
        );
        assert_eq!(AUTHENTICATION_INPUT_PREFIX_V1_LENGTH + 32, 226);
        assert_eq!(
            AUTHENTICATED_ENVELOPE_END_OFFSET,
            AUTHENTICATED_ENVELOPE_V1_LENGTH
        );
    }

    #[test]
    fn synthetic_canonical_framing_parses_and_fields_occupy_exact_offsets() {
        let fixture = synthetic_framing_fixture();
        let bytes = &fixture.bytes;
        let plaintext = canonical_plaintext();

        assert_eq!(&bytes[0..8], b"CHEVAUTH");
        assert_eq!(&bytes[8..10], &1_u16.to_be_bytes());
        assert_eq!(&bytes[10..12], &1_u16.to_be_bytes());
        assert_eq!(
            &bytes[12..28],
            &SYNTHETIC_AUTHENTICATION_KEY_GENERATION_IDENTIFIER
        );
        assert_eq!(&bytes[28..30], &164_u16.to_be_bytes());
        assert_eq!(&bytes[30..194], plaintext.as_bytes());
        assert_eq!(&bytes[194..226], &SYNTHETIC_UNTRUSTED_TAG_PATTERN);

        let parsed = ParsedUntrustedAuthenticatedEnvelopeV1::parse(bytes)
            .expect("synthetic framing should parse");
        assert_eq!(
            parsed.key_generation_identifier,
            EvidenceAuthenticationKeyGenerationIdentifier(
                SYNTHETIC_AUTHENTICATION_KEY_GENERATION_IDENTIFIER
            )
        );
        assert_eq!(parsed.plaintext_bytes, *plaintext.as_bytes());
        assert_eq!(parsed.untrusted_tag_bytes, SYNTHETIC_UNTRUSTED_TAG_PATTERN);
    }

    #[test]
    fn parser_requires_exact_total_length() {
        let fixture = synthetic_framing_fixture();
        for length in 0..AUTHENTICATED_ENVELOPE_V1_LENGTH {
            assert_eq!(
                ParsedUntrustedAuthenticatedEnvelopeV1::parse(&fixture.bytes[..length]),
                Err(AuthenticatedEnvelopeFramingError::WrongTotalLength {
                    observed_length: length
                })
            );
        }

        for length in [227, 228, 452] {
            let oversized = vec![0_u8; length];
            assert_eq!(
                ParsedUntrustedAuthenticatedEnvelopeV1::parse(&oversized),
                Err(AuthenticatedEnvelopeFramingError::WrongTotalLength {
                    observed_length: length
                })
            );
        }
    }

    #[test]
    fn parser_rejects_wrong_magic_and_every_magic_position_mutation() {
        let fixture = synthetic_framing_fixture();
        let mut wrong_magic = fixture.bytes;
        wrong_magic[0..8].fill(0);
        assert_eq!(
            ParsedUntrustedAuthenticatedEnvelopeV1::parse(&wrong_magic),
            Err(AuthenticatedEnvelopeFramingError::WrongEnvelopeMagic)
        );

        for index in 0..8 {
            let mut mutated = fixture.bytes;
            mutated[index] ^= 1;
            assert_eq!(
                ParsedUntrustedAuthenticatedEnvelopeV1::parse(&mutated),
                Err(AuthenticatedEnvelopeFramingError::WrongEnvelopeMagic)
            );
        }
    }

    #[test]
    fn parser_rejects_unsupported_versions_algorithms_and_plaintext_lengths() {
        let fixture = synthetic_framing_fixture();
        for version in [0_u16, 2] {
            let mut mutated = fixture.bytes;
            mutated[ENVELOPE_VERSION_OFFSET..AUTHENTICATION_ALGORITHM_IDENTIFIER_OFFSET]
                .copy_from_slice(&version.to_be_bytes());
            assert_eq!(
                ParsedUntrustedAuthenticatedEnvelopeV1::parse(&mutated),
                Err(AuthenticatedEnvelopeFramingError::UnsupportedEnvelopeVersion)
            );
        }
        for algorithm in [0_u16, 2] {
            let mut mutated = fixture.bytes;
            mutated[AUTHENTICATION_ALGORITHM_IDENTIFIER_OFFSET
                ..EVIDENCE_AUTHENTICATION_KEY_GENERATION_IDENTIFIER_OFFSET]
                .copy_from_slice(&algorithm.to_be_bytes());
            assert_eq!(
                ParsedUntrustedAuthenticatedEnvelopeV1::parse(&mutated),
                Err(AuthenticatedEnvelopeFramingError::UnsupportedAuthenticationAlgorithm)
            );
        }
        for plaintext_length in [0_u16, 163, 165] {
            let mut mutated = fixture.bytes;
            mutated[CANONICAL_PLAINTEXT_LENGTH_OFFSET..CANONICAL_PLAINTEXT_OFFSET]
                .copy_from_slice(&plaintext_length.to_be_bytes());
            assert_eq!(
                ParsedUntrustedAuthenticatedEnvelopeV1::parse(&mutated),
                Err(AuthenticatedEnvelopeFramingError::WrongDeclaredPlaintextLength)
            );
        }
    }

    #[test]
    fn parser_rejects_an_all_zero_authentication_key_generation_identifier() {
        let mut mutated = synthetic_framing_fixture().bytes;
        mutated[EVIDENCE_AUTHENTICATION_KEY_GENERATION_IDENTIFIER_OFFSET
            ..CANONICAL_PLAINTEXT_LENGTH_OFFSET]
            .fill(0);

        assert_eq!(
            ParsedUntrustedAuthenticatedEnvelopeV1::parse(&mutated),
            Err(AuthenticatedEnvelopeFramingError::InvalidAuthenticationKeyGenerationIdentifier)
        );
    }

    #[test]
    fn debug_output_redacts_envelope_fields_and_errors_retain_no_bytes() {
        let fixture = synthetic_framing_fixture();
        let parsed = ParsedUntrustedAuthenticatedEnvelopeV1::parse(&fixture.bytes)
            .expect("synthetic framing should parse");
        let wrapper_debug = format!("{fixture:?}");
        let identifier_debug = format!("{:?}", parsed.key_generation_identifier);
        let parsed_debug = format!("{parsed:?}");

        assert!(wrapper_debug.contains("EncodedAuthenticatedEnvelopeV1"));
        assert!(wrapper_debug.contains("226"));
        assert_eq!(
            identifier_debug,
            "EvidenceAuthenticationKeyGenerationIdentifier([REDACTED])"
        );
        assert!(parsed_debug.contains("ParsedUntrustedAuthenticatedEnvelopeV1"));
        assert!(parsed_debug.contains("[REDACTED]"));
        for exposed in ["160, 161, 162", "67, 72, 69, 86", "208, 209, 210"] {
            assert!(!wrapper_debug.contains(exposed));
            assert!(!parsed_debug.contains(exposed));
        }

        let mut wrong_magic = fixture.bytes;
        wrong_magic[0] = 0;
        let error = ParsedUntrustedAuthenticatedEnvelopeV1::parse(&wrong_magic)
            .expect_err("wrong magic should fail");
        assert_eq!(format!("{error:?}"), "WrongEnvelopeMagic");

        for safe_error in [
            AuthenticatedEnvelopeFramingError::WrongTotalLength {
                observed_length: 225,
            },
            AuthenticatedEnvelopeFramingError::WrongEnvelopeMagic,
            AuthenticatedEnvelopeFramingError::UnsupportedEnvelopeVersion,
            AuthenticatedEnvelopeFramingError::UnsupportedAuthenticationAlgorithm,
            AuthenticatedEnvelopeFramingError::InvalidAuthenticationKeyGenerationIdentifier,
            AuthenticatedEnvelopeFramingError::WrongDeclaredPlaintextLength,
            AuthenticatedEnvelopeFramingError::InternalFieldBoundaryFailure,
        ] {
            let error_debug = format!("{safe_error:?}");
            assert!(!error_debug.contains("160, 161, 162"));
            assert!(!error_debug.contains("208, 209, 210"));
            assert!(!error_debug.contains("CHEVAUTH"));
        }
    }

    #[test]
    fn correctly_framed_invalid_plaintext_remains_only_parsed_untrusted_framing() {
        let mut fixture = synthetic_framing_fixture();
        fixture.bytes[CANONICAL_PLAINTEXT_OFFSET..UNTRUSTED_AUTHENTICATION_TAG_OFFSET].fill(0xff);

        let parser: fn(
            &[u8],
        ) -> Result<
            ParsedUntrustedAuthenticatedEnvelopeV1,
            AuthenticatedEnvelopeFramingError,
        > = ParsedUntrustedAuthenticatedEnvelopeV1::parse;
        let parsed = parser(&fixture.bytes).expect("inner plaintext is opaque to framing");
        assert_eq!(parsed.plaintext_bytes, [0xff; 164]);

        let operational_boundary: fn(InstallationEvidence) -> StorageDecision =
            decide_ordinary_startup;
        let _ = operational_boundary;
        // Framing alone deliberately performs no inner-plaintext parse,
        // structural validation, tag verification, authenticated transition, or
        // conversion to operational InstallationEvidence.
    }

    #[test]
    fn construction_writes_exact_framing_plaintext_and_full_prefix_tag() {
        let key = synthetic_key(SYNTHETIC_AUTHENTICATION_KEY);
        let plaintext = canonical_plaintext();
        let (encoded, authenticated) = construct_authenticated_envelope_v1(
            &key,
            synthetic_key_generation_identifier(),
            &plaintext,
        )
        .expect("construction should succeed");
        let bytes = encoded.as_bytes();

        assert_eq!(bytes.len(), 226);
        assert_eq!(&bytes[0..8], b"CHEVAUTH");
        assert_eq!(&bytes[8..10], &1_u16.to_be_bytes());
        assert_eq!(&bytes[10..12], &1_u16.to_be_bytes());
        assert_eq!(
            &bytes[12..28],
            &SYNTHETIC_AUTHENTICATION_KEY_GENERATION_IDENTIFIER
        );
        assert_eq!(&bytes[28..30], &164_u16.to_be_bytes());
        assert_eq!(&bytes[30..194], plaintext.as_bytes());
        assert_eq!(bytes[194..226].len(), 32);

        let mut independent_hmac = key
            .expose_bytes(|key_bytes| HmacSha256::new_from_slice(key_bytes))
            .expect("HMAC accepts the fixed synthetic key");
        independent_hmac.update(&bytes[0..194]);
        independent_hmac
            .verify_slice(&bytes[194..226])
            .expect("tag must authenticate exact bytes 0..194");

        authenticated
            .match_generation(&synthetic_key_generation_identifier())
            .expect("trusted construction should retain matching generation")
            .parse_inner_plaintext()
            .expect("trusted construction should release canonical plaintext");
    }

    #[test]
    fn construction_is_deterministic_and_each_authenticated_input_changes_the_tag() {
        let plaintext = canonical_plaintext();
        let first_key = synthetic_key(SYNTHETIC_AUTHENTICATION_KEY);
        let first_identifier = synthetic_key_generation_identifier();
        let (first, _) =
            construct_authenticated_envelope_v1(&first_key, first_identifier, &plaintext)
                .expect("first construction should succeed");
        let (repeated, _) =
            construct_authenticated_envelope_v1(&first_key, first_identifier, &plaintext)
                .expect("repeated construction should succeed");
        assert_eq!(first, repeated);

        let mut different_key_bytes = SYNTHETIC_AUTHENTICATION_KEY;
        different_key_bytes[0] ^= 1;
        let (different_key, _) = construct_authenticated_envelope_v1(
            &synthetic_key(different_key_bytes),
            first_identifier,
            &plaintext,
        )
        .expect("different-key construction should succeed");
        assert_ne!(
            &first.as_bytes()[194..226],
            &different_key.as_bytes()[194..226]
        );

        let mut different_identifier_bytes = SYNTHETIC_AUTHENTICATION_KEY_GENERATION_IDENTIFIER;
        different_identifier_bytes[0] ^= 1;
        let different_identifier =
            EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(different_identifier_bytes)
                .expect("different identifier should remain nonzero");
        let (different_identifier_envelope, _) =
            construct_authenticated_envelope_v1(&first_key, different_identifier, &plaintext)
                .expect("different-identifier construction should succeed");
        assert_ne!(
            &first.as_bytes()[194..226],
            &different_identifier_envelope.as_bytes()[194..226]
        );

        let (different_plaintext, _) = construct_authenticated_envelope_v1(
            &first_key,
            first_identifier,
            &alternate_canonical_plaintext(),
        )
        .expect("different-plaintext construction should succeed");
        assert_ne!(
            &first.as_bytes()[194..226],
            &different_plaintext.as_bytes()[194..226]
        );
    }

    #[test]
    fn verification_succeeds_only_with_the_correct_key() {
        let (encoded, _) = construct_synthetic_authenticated_envelope();
        let parsed = ParsedUntrustedAuthenticatedEnvelopeV1::parse(encoded.as_bytes())
            .expect("constructed framing should parse");
        let authenticated =
            verify_authenticated_envelope_v1(parsed, &synthetic_key(SYNTHETIC_AUTHENTICATION_KEY))
                .expect("correct key should authenticate");
        assert_eq!(
            format!("{authenticated:?}"),
            "CryptographicallyAuthenticatedEnvelopeV1([REDACTED])"
        );

        let mut wrong_key_bytes = SYNTHETIC_AUTHENTICATION_KEY;
        wrong_key_bytes[31] ^= 1;
        let parsed_again = ParsedUntrustedAuthenticatedEnvelopeV1::parse(encoded.as_bytes())
            .expect("constructed framing should parse again");
        assert_eq!(
            verify_authenticated_envelope_v1(parsed_again, &synthetic_key(wrong_key_bytes))
                .expect_err("wrong key must not produce an authenticated type"),
            AuthenticatedEnvelopeAuthenticationError::AuthenticationFailed
        );
    }

    #[test]
    fn malformed_input_hardening_mutates_every_envelope_position_once() {
        let (encoded, _) = construct_synthetic_authenticated_envelope();
        let key = synthetic_key(SYNTHETIC_AUTHENTICATION_KEY);
        let mut framing_failures = 0;
        let mut authentication_failures = 0;

        for index in 0..AUTHENTICATED_ENVELOPE_V1_LENGTH {
            let mutated = mutate_envelope_byte(encoded.as_bytes(), index);
            match ParsedUntrustedAuthenticatedEnvelopeV1::parse(&mutated) {
                Err(error) => {
                    match index {
                        0..8 => {
                            assert_eq!(error, AuthenticatedEnvelopeFramingError::WrongEnvelopeMagic)
                        }
                        8..10 => assert_eq!(
                            error,
                            AuthenticatedEnvelopeFramingError::UnsupportedEnvelopeVersion
                        ),
                        10..12 => assert_eq!(
                            error,
                            AuthenticatedEnvelopeFramingError::UnsupportedAuthenticationAlgorithm
                        ),
                        28..30 => assert_eq!(
                            error,
                            AuthenticatedEnvelopeFramingError::WrongDeclaredPlaintextLength
                        ),
                        _ => panic!("a framing-preserving byte position failed framing"),
                    }
                    framing_failures += 1;
                }
                Ok(parsed) => {
                    assert!(matches!(index, 12..28 | 30..226));
                    let error = verify_authenticated_envelope_v1(parsed, &key)
                        .expect_err("a mutation must not produce an authenticated type");
                    assert_authentication_error_is_safe(error);
                    authentication_failures += 1;
                }
            }
        }

        assert_eq!(framing_failures, 14);
        assert_eq!(authentication_failures, 212);
        assert_eq!(framing_failures + authentication_failures, 226);
    }

    #[test]
    fn malformed_input_hardening_every_terminal_tag_byte_fails_authentication() {
        let (encoded, _) = construct_synthetic_authenticated_envelope();
        let key = synthetic_key(SYNTHETIC_AUTHENTICATION_KEY);

        for index in UNTRUSTED_AUTHENTICATION_TAG_OFFSET..AUTHENTICATED_ENVELOPE_END_OFFSET {
            let mutated = mutate_envelope_byte(encoded.as_bytes(), index);
            let parsed = ParsedUntrustedAuthenticatedEnvelopeV1::parse(&mutated)
                .expect("tag mutation must preserve framing");
            let error = verify_authenticated_envelope_v1(parsed, &key)
                .expect_err("a tag mutation must not produce an authenticated type");
            assert_authentication_error_is_safe(error);
        }
    }

    #[test]
    fn malformed_input_hardening_every_framing_preserving_prefix_mutation_fails_authentication() {
        let (encoded, _) = construct_synthetic_authenticated_envelope();
        let key = synthetic_key(SYNTHETIC_AUTHENTICATION_KEY);

        for index in (12..28).chain(30..AUTHENTICATION_INPUT_PREFIX_V1_LENGTH) {
            let mutated = mutate_envelope_byte(encoded.as_bytes(), index);
            let parsed = ParsedUntrustedAuthenticatedEnvelopeV1::parse(&mutated)
                .expect("identifier or plaintext mutation should preserve outer framing");
            let error = verify_authenticated_envelope_v1(parsed, &key)
                .expect_err("an authenticated-prefix mutation must not authenticate");
            assert_authentication_error_is_safe(error);
        }
    }

    #[test]
    fn malformed_input_hardening_wrong_key_corpus_returns_only_the_coarse_error() {
        let (encoded, _) = construct_synthetic_authenticated_envelope();
        let mut first_byte_difference = SYNTHETIC_AUTHENTICATION_KEY;
        first_byte_difference[0] ^= 0x01;
        let mut last_byte_difference = SYNTHETIC_AUTHENTICATION_KEY;
        last_byte_difference[31] ^= 0x01;
        let alternating = std::array::from_fn(|index| if index % 2 == 0 { 0xaa } else { 0x55 });

        for wrong_key in [
            first_byte_difference,
            last_byte_difference,
            [0x00; 32],
            [0xff; 32],
            alternating,
        ] {
            let parsed = ParsedUntrustedAuthenticatedEnvelopeV1::parse(encoded.as_bytes())
                .expect("constructed envelope framing should parse");
            let error = verify_authenticated_envelope_v1(parsed, &synthetic_key(wrong_key))
                .expect_err("a deterministic wrong key must not authenticate");
            assert_authentication_error_is_safe(error);
        }
    }

    #[test]
    fn malformed_input_hardening_handles_all_required_wrong_lengths_without_verification() {
        let (encoded, _) = construct_synthetic_authenticated_envelope();

        for length in (0..AUTHENTICATED_ENVELOPE_V1_LENGTH)
            .chain(227..=260)
            .chain([452, 1024, 4096])
        {
            let input = if length < AUTHENTICATED_ENVELOPE_V1_LENGTH {
                encoded.as_bytes()[..length].to_vec()
            } else {
                vec![0x5a; length]
            };
            assert_eq!(
                ParsedUntrustedAuthenticatedEnvelopeV1::parse(&input),
                Err(AuthenticatedEnvelopeFramingError::WrongTotalLength {
                    observed_length: length
                })
            );
        }
    }

    #[test]
    fn malformed_input_hardening_handles_required_patterns_without_panicking() {
        let alternating_zero_ff =
            std::array::from_fn(|index| if index % 2 == 0 { 0x00 } else { 0xff });
        let alternating_aa_55 =
            std::array::from_fn(|index| if index % 2 == 0 { 0xaa } else { 0x55 });
        let incrementing = std::array::from_fn(|index| index as u8);
        let repeated_magic = std::array::from_fn(|index| AUTHENTICATED_ENVELOPE_MAGIC[index % 8]);

        for input in [
            [0x00; AUTHENTICATED_ENVELOPE_V1_LENGTH],
            [0xff; AUTHENTICATED_ENVELOPE_V1_LENGTH],
            alternating_zero_ff,
            alternating_aa_55,
            incrementing,
            repeated_magic,
        ] {
            assert_framing_or_authentication_failure(&input);
        }
    }

    #[test]
    fn malformed_input_hardening_covers_boundaries_and_cross_boundary_mutations() {
        let (encoded, _) = construct_synthetic_authenticated_envelope();

        for index in [7, 8, 9, 10, 11, 12, 27, 28, 29, 30, 193, 194, 225] {
            let mutated = mutate_envelope_byte(encoded.as_bytes(), index);
            assert_framing_or_authentication_failure(&mutated);
        }

        for (first, second) in [
            (7, 8),
            (9, 10),
            (11, 12),
            (27, 28),
            (29, 30),
            (193, 194),
            (224, 225),
        ] {
            let mut mutated = mutate_envelope_byte(encoded.as_bytes(), first);
            mutated[second] ^= 0x01;
            assert_framing_or_authentication_failure(&mutated);
        }
    }

    #[test]
    fn authenticated_plaintext_parsing_and_structural_validation_are_explicit_transitions() {
        let (encoded, _) = construct_synthetic_authenticated_envelope();
        let parsed_envelope = ParsedUntrustedAuthenticatedEnvelopeV1::parse(encoded.as_bytes())
            .expect("constructed framing should parse");
        let authenticated = verify_authenticated_envelope_v1(
            parsed_envelope,
            &synthetic_key(SYNTHETIC_AUTHENTICATION_KEY),
        )
        .expect("correct key should authenticate");
        let parsed_plaintext = authenticated
            .match_generation(&synthetic_key_generation_identifier())
            .expect("verified generation should match")
            .parse_inner_plaintext()
            .expect("authenticated canonical plaintext should parse");
        parsed_plaintext
            .validate_structure()
            .expect("structural validation remains a later explicit call");
    }

    #[test]
    fn trusted_and_verified_results_retain_generation_until_explicit_matching() {
        let key = synthetic_key(SYNTHETIC_AUTHENTICATION_KEY);
        let expected_identifier = synthetic_key_generation_identifier();
        let (encoded, constructed) =
            construct_authenticated_envelope_v1(&key, expected_identifier, &canonical_plaintext())
                .expect("trusted construction should succeed");
        assert!(constructed.match_generation(&expected_identifier).is_ok());

        let parsed = ParsedUntrustedAuthenticatedEnvelopeV1::parse(encoded.as_bytes())
            .expect("constructed framing should parse");
        let verified = verify_authenticated_envelope_v1(parsed, &key)
            .expect("correct key should authenticate");
        assert!(verified.match_generation(&expected_identifier).is_ok());
    }

    #[test]
    fn generation_mismatch_is_coarse_and_plaintext_release_belongs_only_to_matched_type() {
        let (_, authenticated) = construct_synthetic_authenticated_envelope();
        let different_identifier =
            EvidenceAuthenticationKeyGenerationIdentifier::from_bytes([0x77; 16]).unwrap();
        assert!(matches!(
            authenticated.match_generation(&different_identifier),
            Err(GenerationMatchError::GenerationMismatch)
        ));
        assert_eq!(
            format!("{:?}", GenerationMatchError::GenerationMismatch),
            "GenerationMismatch"
        );

        const SOURCE: &str = include_str!("installation_evidence_authenticated_envelope.rs");
        let authenticated_impl = SOURCE
            .split("impl CryptographicallyAuthenticatedEnvelopeV1")
            .nth(1)
            .and_then(|suffix| suffix.split("impl fmt::Debug").next())
            .expect("authenticated implementation should remain present");
        assert!(!authenticated_impl.contains("parse_inner_plaintext"));
    }

    #[test]
    fn malformed_input_hardening_retagged_plaintext_fails_only_at_later_logical_boundaries() {
        let (encoded, _) = construct_synthetic_authenticated_envelope();
        let key = synthetic_key(SYNTHETIC_AUTHENTICATION_KEY);

        let mut malformed_magic = *encoded.as_bytes();
        malformed_magic[CANONICAL_PLAINTEXT_OFFSET] ^= 0x01;
        retag_synthetic_envelope(&mut malformed_magic, &key);
        let authenticated = authenticate_synthetic_bytes(&malformed_magic, &key);
        assert_eq!(
            authenticated.parse_inner_plaintext(),
            Err(InstallationEvidenceParseError::WrongEncodingMagic)
        );

        let mut unsupported_encoding = *encoded.as_bytes();
        unsupported_encoding[CANONICAL_PLAINTEXT_OFFSET + 8..CANONICAL_PLAINTEXT_OFFSET + 10]
            .copy_from_slice(&2_u16.to_be_bytes());
        retag_synthetic_envelope(&mut unsupported_encoding, &key);
        let authenticated = authenticate_synthetic_bytes(&unsupported_encoding, &key);
        assert_eq!(
            authenticated.parse_inner_plaintext(),
            Err(InstallationEvidenceParseError::UnsupportedEncodingVersion)
        );

        let mut wrong_application_identifier = *encoded.as_bytes();
        wrong_application_identifier[CANONICAL_PLAINTEXT_OFFSET + 31] ^= 0x01;
        retag_synthetic_envelope(&mut wrong_application_identifier, &key);
        let parsed = authenticate_synthetic_bytes(&wrong_application_identifier, &key)
            .parse_inner_plaintext()
            .expect("different UTF-8 application identifier should parse");
        assert_eq!(
            parsed.validate_structure(),
            Err(ContractValidationError::WrongPermanentApplicationIdentifier)
        );

        let mut zero_installation_generation = *encoded.as_bytes();
        zero_installation_generation
            [CANONICAL_PLAINTEXT_OFFSET + 108..CANONICAL_PLAINTEXT_OFFSET + 116]
            .fill(0);
        retag_synthetic_envelope(&mut zero_installation_generation, &key);
        let parsed = authenticate_synthetic_bytes(&zero_installation_generation, &key)
            .parse_inner_plaintext()
            .expect("zero installation generation should parse structurally untrusted");
        assert_eq!(
            parsed.validate_structure(),
            Err(ContractValidationError::InvalidInstallationGeneration)
        );

        let mut zero_creation_timestamp = *encoded.as_bytes();
        zero_creation_timestamp[CANONICAL_PLAINTEXT_OFFSET + 156..CANONICAL_PLAINTEXT_OFFSET + 164]
            .fill(0);
        retag_synthetic_envelope(&mut zero_creation_timestamp, &key);
        let parsed = authenticate_synthetic_bytes(&zero_creation_timestamp, &key)
            .parse_inner_plaintext()
            .expect("zero creation timestamp should parse structurally untrusted");
        assert_eq!(
            parsed.validate_structure(),
            Err(ContractValidationError::InvalidCreationTimestamp)
        );
    }

    #[test]
    fn malformed_input_hardening_alternate_plaintext_completes_the_nonoperational_chain() {
        let key = synthetic_key(SYNTHETIC_AUTHENTICATION_KEY);
        let alternate_plaintext = alternate_canonical_plaintext();
        let (encoded, _) = construct_authenticated_envelope_v1(
            &key,
            synthetic_key_generation_identifier(),
            &alternate_plaintext,
        )
        .expect("alternate canonical plaintext should construct an envelope");
        let authenticated = authenticate_synthetic_bytes(encoded.as_bytes(), &key);
        let parsed = authenticated
            .parse_inner_plaintext()
            .expect("alternate authenticated plaintext should parse");
        let validated = parsed
            .validate_structure()
            .expect("alternate authenticated plaintext should validate structurally");

        assert_eq!(
            validated.encode_v1().as_bytes(),
            alternate_plaintext.as_bytes()
        );
    }

    #[test]
    fn authenticated_result_retains_no_key_and_debug_and_errors_are_redacted() {
        let authenticated = {
            let key = synthetic_key(SYNTHETIC_AUTHENTICATION_KEY);
            let (_, authenticated) = construct_authenticated_envelope_v1(
                &key,
                synthetic_key_generation_identifier(),
                &canonical_plaintext(),
            )
            .expect("construction should succeed");
            authenticated
        };

        let authenticated_debug = format!("{authenticated:?}");
        assert!(
            authenticated
                .match_generation(&synthetic_key_generation_identifier())
                .expect("trusted construction should retain matching generation")
                .parse_inner_plaintext()
                .is_ok()
        );
        let error_debug = format!(
            "{:?}",
            AuthenticatedEnvelopeAuthenticationError::AuthenticationFailed
        );
        assert_eq!(
            authenticated_debug,
            "CryptographicallyAuthenticatedEnvelopeV1([REDACTED])"
        );
        assert_eq!(error_debug, "AuthenticationFailed");
        for exposed in ["CHEVAUTH", "160, 161, 162", "16, 33, 50", "208, 209, 210"] {
            assert!(!authenticated_debug.contains(exposed));
            assert!(!error_debug.contains(exposed));
        }
    }

    #[test]
    fn rfc_4231_hmac_sha256_vectors() {
        let cases: [(&[u8], &[u8], [u8; 32]); 2] = [
            (
                &[0x0b; 20],
                b"Hi There",
                [
                    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf,
                    0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9,
                    0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
                ],
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                [
                    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08,
                    0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec,
                    0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
                ],
            ),
        ];

        for (key, message, expected_tag) in cases {
            let mut hmac = HmacSha256::new_from_slice(key).expect("RFC key should initialize HMAC");
            hmac.update(message);
            hmac.verify_slice(&expected_tag)
                .expect("RFC 4231 HMAC-SHA-256 vector should match");
        }
    }

    #[test]
    fn authentication_module_uses_library_verification_and_has_no_side_effect_apis() {
        const SOURCE: &str = include_str!("installation_evidence_authenticated_envelope.rs");
        assert!(SOURCE.contains("verify_slice"));
        assert!(!SOURCE.contains(&["untrusted_tag_bytes", " =="].concat()));
        assert!(!SOURCE.contains(&["ct", "_eq"].concat()));

        for fragment in [
            ["get", "random"].concat(),
            ["rand", "::"].concat(),
            ["std", "::fs"].concat(),
            ["std", "::env"].concat(),
            ["std", "::net"].concat(),
            ["rusqlite", "::"].concat(),
            ["windows", "::"].concat(),
            ["tauri", "::command"].concat(),
        ] {
            assert!(
                !SOURCE.contains(&fragment),
                "authentication module unexpectedly contains an excluded API"
            );
        }

        let structural_boundary: fn(
            ParsedUntrustedInstallationEvidenceContract,
        ) -> Result<_, ContractValidationError> =
            ParsedUntrustedInstallationEvidenceContract::validate_structure;
        let operational_boundary: fn(InstallationEvidence) -> StorageDecision =
            decide_ordinary_startup;
        let _ = (structural_boundary, operational_boundary);
    }
}
