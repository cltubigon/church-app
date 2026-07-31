//! In-memory-only protection transitions for installation-evidence material.
//!
//! DPAPI protection, wrapper parsing, HMAC authentication, generation matching,
//! inner parsing, and structural validation remain distinct trust boundaries.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use zeroize::Zeroize;

#[cfg(any(windows, test))]
use crate::installation_evidence_persistence::ProtectedWrapperBytes;
use crate::{
    installation_evidence_authenticated_envelope::{
        EncodedAuthenticatedEnvelopeV1, EvidenceAuthenticationKeyGenerationIdentifier,
        GenerationMatchedAuthenticatedEnvelopeV1, ParsedUntrustedAuthenticatedEnvelopeV1,
        verify_authenticated_envelope_v1,
    },
    installation_evidence_authentication_key::EvidenceAuthenticationKey,
};

mod protected_blob_wrapper;
mod protected_key_payload;
#[cfg(windows)]
mod windows_current_user_dpapi;

pub(crate) use protected_blob_wrapper::EncodedProtectedWrapper;
use protected_blob_wrapper::{ProtectedObjectKind, ValidatedProtectedWrapper};
pub(crate) use protected_key_payload::DecodedProtectedKeyMaterial;
use protected_key_payload::EncodedProtectedKeyPayload;
#[cfg(windows)]
use windows_current_user_dpapi::WindowsCurrentUserDpapi;

const AUTHENTICATED_ENVELOPE_LENGTH: usize = 226;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProtectionStageError {
    WrapperParseFailed,
    UnsupportedWrapperVersion,
    WrongProtectedObjectKind,
    ProtectionUnavailable,
    UnprotectionUnavailable,
    MalformedProtectedKeyPayload,
    UnsupportedProtectedKeyVersion,
    GenerationMismatch,
    AuthenticationFailed,
}

impl fmt::Debug for ProtectionStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrapperParseFailed => "WrapperParseFailed",
            Self::UnsupportedWrapperVersion => "UnsupportedWrapperVersion",
            Self::WrongProtectedObjectKind => "WrongProtectedObjectKind",
            Self::ProtectionUnavailable => "ProtectionUnavailable",
            Self::UnprotectionUnavailable => "UnprotectionUnavailable",
            Self::MalformedProtectedKeyPayload => "MalformedProtectedKeyPayload",
            Self::UnsupportedProtectedKeyVersion => "UnsupportedProtectedKeyVersion",
            Self::GenerationMismatch => "GenerationMismatch",
            Self::AuthenticationFailed => "AuthenticationFailed",
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct ProtectorOperationError;

trait InMemoryProtector {
    fn protect(&self, plaintext: &[u8]) -> Result<OpaqueProtectedBytes, ProtectorOperationError>;
    fn unprotect(&self, protected: &[u8]) -> Result<UnprotectedBytes, ProtectorOperationError>;
}

struct OpaqueProtectedBytes(Vec<u8>);

impl OpaqueProtectedBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for OpaqueProtectedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueProtectedBytes([REDACTED])")
    }
}

struct UnprotectedBytes(Vec<u8>);

impl UnprotectedBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for UnprotectedBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for UnprotectedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnprotectedBytes([REDACTED])")
    }
}

struct RawUntrustedAuthenticatedEnvelopeV1 {
    bytes: [u8; AUTHENTICATED_ENVELOPE_LENGTH],
}

impl RawUntrustedAuthenticatedEnvelopeV1 {
    fn from_unprotected(bytes: &UnprotectedBytes) -> Result<Self, ProtectionStageError> {
        let exact = bytes
            .as_bytes()
            .try_into()
            .map_err(|_| ProtectionStageError::WrapperParseFailed)?;
        Ok(Self { bytes: exact })
    }

    fn parse(&self) -> Result<ParsedUntrustedAuthenticatedEnvelopeV1, ProtectionStageError> {
        ParsedUntrustedAuthenticatedEnvelopeV1::parse(&self.bytes)
            .map_err(|_| ProtectionStageError::AuthenticationFailed)
    }
}

impl Drop for RawUntrustedAuthenticatedEnvelopeV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for RawUntrustedAuthenticatedEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawUntrustedAuthenticatedEnvelopeV1([REDACTED])")
    }
}

#[cfg(windows)]
pub(crate) fn protect_authentication_material(
    key: &EvidenceAuthenticationKey,
    generation_identifier: EvidenceAuthenticationKeyGenerationIdentifier,
) -> Result<EncodedProtectedWrapper, ProtectionStageError> {
    protect_authentication_material_with(&WindowsCurrentUserDpapi, key, generation_identifier)
}

fn protect_authentication_material_with(
    protector: &impl InMemoryProtector,
    key: &EvidenceAuthenticationKey,
    generation_identifier: EvidenceAuthenticationKeyGenerationIdentifier,
) -> Result<EncodedProtectedWrapper, ProtectionStageError> {
    let mut payload = EncodedProtectedKeyPayload::encode(key, generation_identifier);
    let protection_result = protector.protect(payload.as_bytes());
    payload.zeroize_owned_bytes();
    let protected = protection_result.map_err(|_| ProtectionStageError::ProtectionUnavailable)?;
    EncodedProtectedWrapper::encode(ProtectedObjectKind::AuthenticationKey, protected)
}

#[cfg(windows)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn unprotect_authentication_material(
    wrapper_bytes: &[u8],
) -> Result<DecodedProtectedKeyMaterial, ProtectionStageError> {
    unprotect_authentication_material_with(&WindowsCurrentUserDpapi, wrapper_bytes)
}

fn unprotect_authentication_material_with(
    protector: &impl InMemoryProtector,
    wrapper_bytes: &[u8],
) -> Result<DecodedProtectedKeyMaterial, ProtectionStageError> {
    let wrapper =
        ValidatedProtectedWrapper::parse(wrapper_bytes, ProtectedObjectKind::AuthenticationKey)?;
    let plaintext = protector
        .unprotect(wrapper.blob())
        .map_err(|_| ProtectionStageError::UnprotectionUnavailable)?;
    DecodedProtectedKeyMaterial::parse(plaintext.as_bytes())
}

#[cfg(windows)]
pub(crate) fn protect_authenticated_evidence(
    envelope: &EncodedAuthenticatedEnvelopeV1,
) -> Result<EncodedProtectedWrapper, ProtectionStageError> {
    protect_authenticated_evidence_with(&WindowsCurrentUserDpapi, envelope)
}

fn protect_authenticated_evidence_with(
    protector: &impl InMemoryProtector,
    envelope: &EncodedAuthenticatedEnvelopeV1,
) -> Result<EncodedProtectedWrapper, ProtectionStageError> {
    let protected = protector
        .protect(envelope.as_bytes())
        .map_err(|_| ProtectionStageError::ProtectionUnavailable)?;
    EncodedProtectedWrapper::encode(ProtectedObjectKind::AuthenticatedEvidence, protected)
}

#[cfg(windows)]
#[cfg_attr(test, allow(dead_code))]
fn unprotect_authenticated_evidence(
    wrapper_bytes: &[u8],
) -> Result<RawUntrustedAuthenticatedEnvelopeV1, ProtectionStageError> {
    unprotect_authenticated_evidence_with(&WindowsCurrentUserDpapi, wrapper_bytes)
}

fn unprotect_authenticated_evidence_with(
    protector: &impl InMemoryProtector,
    wrapper_bytes: &[u8],
) -> Result<RawUntrustedAuthenticatedEnvelopeV1, ProtectionStageError> {
    let wrapper = ValidatedProtectedWrapper::parse(
        wrapper_bytes,
        ProtectedObjectKind::AuthenticatedEvidence,
    )?;
    let plaintext = protector
        .unprotect(wrapper.blob())
        .map_err(|_| ProtectionStageError::UnprotectionUnavailable)?;
    RawUntrustedAuthenticatedEnvelopeV1::from_unprotected(&plaintext)
}

/// Returns the unprotected authentication-key payload first and the
/// unprotected authenticated-evidence payload second. Success establishes only
/// canonical outer framing, exact outer object kinds, and two successful
/// current-user DPAPI unprotections.
#[cfg(windows)]
#[cfg_attr(test, allow(dead_code))]
fn unprotect_active_installation_evidence_wrappers(
    authentication_key_wrapper: ProtectedWrapperBytes,
    authenticated_evidence_wrapper: ProtectedWrapperBytes,
) -> Result<(UnprotectedBytes, UnprotectedBytes), ProtectionStageError> {
    unprotect_active_installation_evidence_wrappers_with(
        &WindowsCurrentUserDpapi,
        authentication_key_wrapper,
        authenticated_evidence_wrapper,
    )
}

#[cfg(any(windows, test))]
fn unprotect_active_installation_evidence_wrappers_with(
    protector: &impl InMemoryProtector,
    authentication_key_wrapper: ProtectedWrapperBytes,
    authenticated_evidence_wrapper: ProtectedWrapperBytes,
) -> Result<(UnprotectedBytes, UnprotectedBytes), ProtectionStageError> {
    let authentication_key = ValidatedProtectedWrapper::parse(
        authentication_key_wrapper.as_bytes(),
        ProtectedObjectKind::AuthenticationKey,
    )?;
    let unprotected_authentication_key = protector
        .unprotect(authentication_key.blob())
        .map_err(|_| ProtectionStageError::UnprotectionUnavailable)?;

    let authenticated_evidence = ValidatedProtectedWrapper::parse(
        authenticated_evidence_wrapper.as_bytes(),
        ProtectedObjectKind::AuthenticatedEvidence,
    )?;
    let unprotected_authenticated_evidence = protector
        .unprotect(authenticated_evidence.blob())
        .map_err(|_| ProtectionStageError::UnprotectionUnavailable)?;

    Ok((
        unprotected_authentication_key,
        unprotected_authenticated_evidence,
    ))
}

/// Returns decoded authentication-key material first and the original opaque,
/// untrusted authenticated-evidence payload second. Success establishes only
/// canonical supported authentication-key payload framing.
fn decode_unprotected_installation_evidence_key_material(
    unprotected_authentication_key: UnprotectedBytes,
    unprotected_authenticated_evidence: UnprotectedBytes,
) -> Result<(DecodedProtectedKeyMaterial, UnprotectedBytes), ProtectionStageError> {
    let decoded_authentication_key =
        DecodedProtectedKeyMaterial::parse(unprotected_authentication_key.as_bytes())?;

    Ok((
        decoded_authentication_key,
        unprotected_authenticated_evidence,
    ))
}

#[cfg(windows)]
pub(crate) fn recover_and_authenticate_in_memory(
    protected_key_wrapper: &[u8],
    protected_evidence_wrapper: &[u8],
) -> Result<GenerationMatchedAuthenticatedEnvelopeV1, ProtectionStageError> {
    recover_and_authenticate_in_memory_with(
        &WindowsCurrentUserDpapi,
        protected_key_wrapper,
        protected_evidence_wrapper,
    )
}

fn recover_and_authenticate_in_memory_with(
    protector: &impl InMemoryProtector,
    protected_key_wrapper: &[u8],
    protected_evidence_wrapper: &[u8],
) -> Result<GenerationMatchedAuthenticatedEnvelopeV1, ProtectionStageError> {
    let material = unprotect_authentication_material_with(protector, protected_key_wrapper)?;
    let (key, recovered_identifier) = material.into_parts();
    let raw_envelope =
        unprotect_authenticated_evidence_with(protector, protected_evidence_wrapper)?;
    let parsed_envelope = raw_envelope.parse()?;
    let authenticated = verify_authenticated_envelope_v1(parsed_envelope, &key)
        .map_err(|_| ProtectionStageError::AuthenticationFailed)?;
    authenticated
        .match_generation(&recovered_identifier)
        .map_err(|_| ProtectionStageError::GenerationMismatch)
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque, io::Cursor};

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    use super::*;
    use crate::{
        installation_evidence_authenticated_envelope::construct_authenticated_envelope_v1,
        installation_evidence_contract::{
            ContractValidationError, EncodedInstallationEvidence,
            INSTALLATION_EVIDENCE_FORMAT_IDENTITY, InstallationEvidenceParseError,
            InstallationGeneration, PERMANENT_APPLICATION_IDENTIFIER,
            RecoveryOrReplacementGeneration, SUPPORTED_EVIDENCE_FORMAT_VERSION,
            UnvalidatedInstallationEvidenceContract,
        },
        installation_evidence_persistence::read_bounded_protected_wrapper,
        storage_foundation::APPLICATION_DATABASE_FORMAT_IDENTITY,
    };

    const KEY: [u8; 32] = [0x5a; 32];
    const IDENTIFIER: [u8; 16] = [0xa5; 16];

    #[derive(Default)]
    struct FakeProtector {
        protected_plaintexts: RefCell<Vec<Vec<u8>>>,
        protected_results: RefCell<VecDeque<Result<Vec<u8>, ProtectorOperationError>>>,
        unprotected_inputs: RefCell<Vec<Vec<u8>>>,
        unprotected_results: RefCell<VecDeque<Result<Vec<u8>, ProtectorOperationError>>>,
    }

    impl FakeProtector {
        fn with_protected(results: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                protected_results: RefCell::new(results.into_iter().map(Ok).collect()),
                ..Self::default()
            }
        }

        fn with_unprotected(results: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                unprotected_results: RefCell::new(results.into_iter().map(Ok).collect()),
                ..Self::default()
            }
        }

        fn with_unprotected_results(
            results: impl IntoIterator<Item = Result<Vec<u8>, ProtectorOperationError>>,
        ) -> Self {
            Self {
                unprotected_results: RefCell::new(results.into_iter().collect()),
                ..Self::default()
            }
        }
    }

    impl InMemoryProtector for FakeProtector {
        fn protect(
            &self,
            plaintext: &[u8],
        ) -> Result<OpaqueProtectedBytes, ProtectorOperationError> {
            self.protected_plaintexts
                .borrow_mut()
                .push(plaintext.to_vec());
            if let Some(result) = self.protected_results.borrow_mut().pop_front() {
                return result.map(OpaqueProtectedBytes::new);
            }
            let mut protected = vec![0xd0];
            protected.extend_from_slice(plaintext);
            Ok(OpaqueProtectedBytes::new(protected))
        }

        fn unprotect(&self, protected: &[u8]) -> Result<UnprotectedBytes, ProtectorOperationError> {
            self.unprotected_inputs
                .borrow_mut()
                .push(protected.to_vec());
            self.unprotected_results
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(ProtectorOperationError))
                .map(UnprotectedBytes::new)
        }
    }

    fn identifier(bytes: [u8; 16]) -> EvidenceAuthenticationKeyGenerationIdentifier {
        EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(bytes).unwrap()
    }

    fn plaintext() -> EncodedInstallationEvidence {
        UnvalidatedInstallationEvidenceContract::new(
            *INSTALLATION_EVIDENCE_FORMAT_IDENTITY.as_bytes(),
            SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            "101112131415161718191a1b1c1d1e1f",
            [0x31; 16],
            InstallationGeneration::INITIAL.get(),
            RecoveryOrReplacementGeneration::INITIAL.get(),
            [0x42; 16],
            [0x53; 16],
            1_800_000_000,
        )
        .validate()
        .unwrap()
        .encode_v1()
    }

    fn encoded_envelope(key: [u8; 32], generation: [u8; 16]) -> EncodedAuthenticatedEnvelopeV1 {
        construct_authenticated_envelope_v1(
            &EvidenceAuthenticationKey::from_bytes(key),
            identifier(generation),
            &plaintext(),
        )
        .unwrap()
        .0
    }

    fn dummy_wrapper(kind: ProtectedObjectKind) -> EncodedProtectedWrapper {
        EncodedProtectedWrapper::encode(kind, OpaqueProtectedBytes::new(vec![1])).unwrap()
    }

    fn owned_wrapper(kind: ProtectedObjectKind, blob: Vec<u8>) -> ProtectedWrapperBytes {
        let wrapper = EncodedProtectedWrapper::encode(kind, OpaqueProtectedBytes::new(blob))
            .expect("synthetic protected wrapper must encode");
        owned_wrapper_bytes(wrapper.as_bytes())
    }

    fn owned_wrapper_bytes(bytes: &[u8]) -> ProtectedWrapperBytes {
        read_bounded_protected_wrapper(&mut Cursor::new(bytes), bytes.len() as u64)
            .expect("synthetic owned protected-wrapper bytes must satisfy the bounded reader")
    }

    fn key_payload(key: [u8; 32], generation: [u8; 16]) -> Vec<u8> {
        EncodedProtectedKeyPayload::encode(
            &EvidenceAuthenticationKey::from_bytes(key),
            identifier(generation),
        )
        .as_bytes()
        .to_vec()
    }

    fn assert_complete_recovery_failure(
        fake: &FakeProtector,
        key_wrapper: &[u8],
        evidence_wrapper: &[u8],
        expected: ProtectionStageError,
    ) {
        let error = recover_and_authenticate_in_memory_with(fake, key_wrapper, evidence_wrapper)
            .expect_err("malformed protected inputs must not produce matched evidence");
        assert_eq!(error, expected);
        let debug = format!("{error:?}");
        assert!(!debug.contains("CHDPAPI"));
        assert!(!debug.contains("CHEVAUTH"));
    }

    fn retagged_malformed_envelope(plaintext_offset: usize) -> Vec<u8> {
        let mut bytes = *encoded_envelope(KEY, IDENTIFIER).as_bytes();
        bytes[30 + plaintext_offset] ^= 1;
        let mut hmac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        hmac.update(&bytes[..194]);
        bytes[194..226].copy_from_slice(&hmac.finalize().into_bytes());
        bytes.to_vec()
    }

    #[test]
    fn fake_protector_protects_key_payload_and_evidence_separately() {
        let fake = FakeProtector::default();
        let key = EvidenceAuthenticationKey::from_bytes(KEY);
        let key_wrapper =
            protect_authentication_material_with(&fake, &key, identifier(IDENTIFIER)).unwrap();
        let envelope = encoded_envelope(KEY, IDENTIFIER);
        let evidence_wrapper = protect_authenticated_evidence_with(&fake, &envelope).unwrap();
        let calls = fake.protected_plaintexts.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].len(), 49);
        assert_eq!(calls[1].len(), 226);
        assert_eq!(key_wrapper.as_bytes()[9], 1);
        assert_eq!(evidence_wrapper.as_bytes()[9], 2);
    }

    #[test]
    fn paired_wrapper_unprotection_returns_exact_owned_values_in_key_then_evidence_order() {
        let fake = FakeProtector::with_unprotected([vec![0x31, 0x32], vec![0x41, 0x42, 0x43]]);
        let result = unprotect_active_installation_evidence_wrappers_with(
            &fake,
            owned_wrapper(ProtectedObjectKind::AuthenticationKey, vec![0xa1]),
            owned_wrapper(ProtectedObjectKind::AuthenticatedEvidence, vec![0xb2]),
        )
        .expect("both synthetic unprotections must succeed");

        assert_eq!(result.0.as_bytes(), [0x31, 0x32]);
        assert_eq!(result.1.as_bytes(), [0x41, 0x42, 0x43]);
        assert_eq!(format!("{:?}", result.0), "UnprotectedBytes([REDACTED])");
        assert_eq!(format!("{:?}", result.1), "UnprotectedBytes([REDACTED])");
        assert_eq!(
            fake.unprotected_inputs.borrow().as_slice(),
            &[vec![0xa1], vec![0xb2]]
        );
    }

    #[test]
    fn paired_wrapper_unprotection_malformed_key_makes_zero_dpapi_calls() {
        let fake = FakeProtector::with_unprotected([vec![0x31], vec![0x41]]);
        let malformed_key = owned_wrapper_bytes(&[0; 15]);

        assert_eq!(
            unprotect_active_installation_evidence_wrappers_with(
                &fake,
                malformed_key,
                owned_wrapper(ProtectedObjectKind::AuthenticatedEvidence, vec![0xb2]),
            )
            .unwrap_err(),
            ProtectionStageError::WrapperParseFailed
        );
        assert!(fake.unprotected_inputs.borrow().is_empty());
    }

    #[test]
    fn paired_wrapper_unprotection_wrong_key_kind_makes_zero_dpapi_calls() {
        let fake = FakeProtector::with_unprotected([vec![0x31], vec![0x41]]);

        assert_eq!(
            unprotect_active_installation_evidence_wrappers_with(
                &fake,
                owned_wrapper(ProtectedObjectKind::AuthenticatedEvidence, vec![0xa1]),
                owned_wrapper(ProtectedObjectKind::AuthenticatedEvidence, vec![0xb2]),
            )
            .unwrap_err(),
            ProtectionStageError::WrongProtectedObjectKind
        );
        assert!(fake.unprotected_inputs.borrow().is_empty());
    }

    #[test]
    fn paired_wrapper_unprotection_key_dpapi_failure_is_fail_fast() {
        let fake =
            FakeProtector::with_unprotected_results([Err(ProtectorOperationError), Ok(vec![0x41])]);

        assert_eq!(
            unprotect_active_installation_evidence_wrappers_with(
                &fake,
                owned_wrapper(ProtectedObjectKind::AuthenticationKey, vec![0xa1]),
                owned_wrapper(ProtectedObjectKind::AuthenticatedEvidence, vec![0xb2]),
            )
            .unwrap_err(),
            ProtectionStageError::UnprotectionUnavailable
        );
        assert_eq!(fake.unprotected_inputs.borrow().as_slice(), &[vec![0xa1]]);
    }

    #[test]
    fn paired_wrapper_unprotection_malformed_evidence_returns_no_pair_after_key_success() {
        let fake = FakeProtector::with_unprotected([vec![0x31], vec![0x41]]);
        let malformed_evidence = owned_wrapper_bytes(&[0; 15]);

        assert_eq!(
            unprotect_active_installation_evidence_wrappers_with(
                &fake,
                owned_wrapper(ProtectedObjectKind::AuthenticationKey, vec![0xa1]),
                malformed_evidence,
            )
            .unwrap_err(),
            ProtectionStageError::WrapperParseFailed
        );
        assert_eq!(fake.unprotected_inputs.borrow().as_slice(), &[vec![0xa1]]);
    }

    #[test]
    fn paired_wrapper_unprotection_wrong_evidence_kind_returns_no_pair_after_key_success() {
        let fake = FakeProtector::with_unprotected([vec![0x31], vec![0x41]]);

        assert_eq!(
            unprotect_active_installation_evidence_wrappers_with(
                &fake,
                owned_wrapper(ProtectedObjectKind::AuthenticationKey, vec![0xa1]),
                owned_wrapper(ProtectedObjectKind::AuthenticationKey, vec![0xb2]),
            )
            .unwrap_err(),
            ProtectionStageError::WrongProtectedObjectKind
        );
        assert_eq!(fake.unprotected_inputs.borrow().as_slice(), &[vec![0xa1]]);
    }

    #[test]
    fn paired_wrapper_unprotection_evidence_dpapi_failure_returns_no_pair_in_exact_call_order() {
        let fake =
            FakeProtector::with_unprotected_results([Ok(vec![0x31]), Err(ProtectorOperationError)]);

        assert_eq!(
            unprotect_active_installation_evidence_wrappers_with(
                &fake,
                owned_wrapper(ProtectedObjectKind::AuthenticationKey, vec![0xa1]),
                owned_wrapper(ProtectedObjectKind::AuthenticatedEvidence, vec![0xb2]),
            )
            .unwrap_err(),
            ProtectionStageError::UnprotectionUnavailable
        );
        assert_eq!(
            fake.unprotected_inputs.borrow().as_slice(),
            &[vec![0xa1], vec![0xb2]]
        );
    }

    #[test]
    fn paired_wrapper_unprotection_source_proves_private_windows_boundary_and_secure_drop_path() {
        const SOURCE: &str = include_str!("mod.rs");
        let definition_marker =
            ["fn unprotect_active_installation_evidence_", "wrappers("].concat();
        assert_eq!(SOURCE.matches(&definition_marker).count(), 1);
        let before_definition = SOURCE.split_once(&definition_marker).unwrap().0;
        let declaration_attributes = before_definition.rsplit_once("\n\n").unwrap().1;
        assert!(declaration_attributes.contains("#[cfg(windows)]"));
        assert!(declaration_attributes.contains("#[cfg_attr(test, allow(dead_code))]"));
        assert!(!declaration_attributes.contains("pub"));

        let injected_marker = [
            "fn unprotect_active_installation_evidence_",
            "wrappers_with(",
        ]
        .concat();
        let paired_body = SOURCE
            .split_once(&injected_marker)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        let key_validation = paired_body
            .find("ProtectedObjectKind::AuthenticationKey")
            .unwrap();
        let key_unprotection = paired_body
            .find("let unprotected_authentication_key")
            .unwrap();
        let evidence_validation = paired_body
            .find("ProtectedObjectKind::AuthenticatedEvidence")
            .unwrap();
        let evidence_unprotection = paired_body
            .find("let unprotected_authenticated_evidence")
            .unwrap();
        assert!(key_validation < key_unprotection);
        assert!(key_unprotection < evidence_validation);
        assert!(evidence_validation < evidence_unprotection);
        assert!(paired_body.contains("Result<(UnprotectedBytes, UnprotectedBytes)"));
        assert!(!paired_body.contains("Vec<u8>"));

        let secure_drop = SOURCE
            .split_once("impl Drop for UnprotectedBytes")
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(secure_drop.contains("self.0.zeroize();"));
    }

    #[test]
    fn unprotected_key_payload_decode_returns_decoded_first_and_exact_opaque_evidence_second() {
        let key_payload = UnprotectedBytes::new(key_payload(KEY, IDENTIFIER));
        let expected_evidence = vec![0x00, 0xff, 0x43, 0x48, 0x45, 0x56, 0x41, 0x55, 0x54, 0x48];
        let evidence_payload = UnprotectedBytes::new(expected_evidence.clone());

        let result =
            decode_unprotected_installation_evidence_key_material(key_payload, evidence_payload)
                .expect("canonical synthetic key payload must decode");

        assert_eq!(
            format!("{:?}", result.0),
            "DecodedProtectedKeyMaterial([REDACTED])"
        );
        assert_eq!(result.1.as_bytes(), expected_evidence);
        assert_eq!(format!("{:?}", result.1), "UnprotectedBytes([REDACTED])");
    }

    #[test]
    fn unprotected_key_payload_decode_preserves_arbitrary_evidence_without_interpretation() {
        for expected_evidence in [
            Vec::new(),
            vec![0],
            vec![0xff; 225],
            vec![0x42; 226],
            vec![0x53; 227],
            (0..=255).collect(),
        ] {
            let result = decode_unprotected_installation_evidence_key_material(
                UnprotectedBytes::new(key_payload(KEY, IDENTIFIER)),
                UnprotectedBytes::new(expected_evidence.clone()),
            )
            .expect("evidence content and length cannot affect canonical key decoding");

            assert_eq!(result.1.as_bytes(), expected_evidence);
        }
    }

    #[test]
    fn unprotected_key_payload_decode_returns_only_canonical_key_parser_errors() {
        let mut unsupported_version = key_payload(KEY, IDENTIFIER);
        unsupported_version[0] = 2;
        let mut zero_generation = key_payload(KEY, IDENTIFIER);
        zero_generation[1..17].fill(0);

        for (candidate, expected) in [
            (
                vec![0x31; 48],
                ProtectionStageError::MalformedProtectedKeyPayload,
            ),
            (
                vec![0x42; 50],
                ProtectionStageError::MalformedProtectedKeyPayload,
            ),
            (
                unsupported_version,
                ProtectionStageError::UnsupportedProtectedKeyVersion,
            ),
            (
                zero_generation,
                ProtectionStageError::MalformedProtectedKeyPayload,
            ),
        ] {
            let error = decode_unprotected_installation_evidence_key_material(
                UnprotectedBytes::new(candidate),
                UnprotectedBytes::new(vec![0xde, 0xad, 0xbe, 0xef]),
            )
            .expect_err("malformed key payload must return no output tuple");

            assert_eq!(error, expected);
        }
    }

    #[test]
    fn unprotected_key_payload_decode_source_proves_private_non_authoritative_secure_boundary() {
        const SOURCE: &str = include_str!("mod.rs");
        let definition_marker = [
            "fn decode_unprotected_installation_evidence_",
            "key_material(",
        ]
        .concat();
        assert_eq!(SOURCE.matches(&definition_marker).count(), 1);
        let before_definition = SOURCE.split_once(&definition_marker).unwrap().0;
        let declaration_attributes = before_definition.rsplit_once("\n\n").unwrap().1;
        assert!(!declaration_attributes.contains("#[cfg(test)]"));
        assert!(!declaration_attributes.contains("pub"));

        let boundary = SOURCE
            .split_once(&definition_marker)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(boundary.contains("unprotected_authentication_key: UnprotectedBytes"));
        assert!(boundary.contains("unprotected_authenticated_evidence: UnprotectedBytes"));
        assert!(boundary.contains("Result<(DecodedProtectedKeyMaterial, UnprotectedBytes)"));
        assert!(boundary.contains("DecodedProtectedKeyMaterial::parse"));
        assert!(boundary.contains("unprotected_authentication_key.as_bytes()"));
        assert!(!boundary.contains("unprotected_authenticated_evidence.as_bytes()"));
        assert!(!boundary.contains("Vec<u8>"));
        assert!(!boundary.contains("into_parts"));
        assert!(!boundary.contains("ParsedUntrustedAuthenticatedEnvelopeV1"));
        assert!(!boundary.contains("AUTHENTICATED_ENVELOPE_LENGTH"));

        let parse_position = boundary.find("DecodedProtectedKeyMaterial::parse").unwrap();
        let return_position = boundary.find("Ok((").unwrap();
        assert!(parse_position < return_position);

        let secure_drop = SOURCE
            .split_once("impl Drop for UnprotectedBytes")
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(secure_drop.contains("self.0.zeroize();"));
    }

    #[test]
    fn fake_protector_malformed_input_hardening_covers_protection_output_bounds() {
        let key = EvidenceAuthenticationKey::from_bytes(KEY);
        for (protected, expected) in [
            (Vec::new(), Err(ProtectionStageError::ProtectionUnavailable)),
            (vec![0x31; 65_536], Ok(65_550)),
            (
                vec![0x42; 65_537],
                Err(ProtectionStageError::ProtectionUnavailable),
            ),
        ] {
            let fake = FakeProtector::with_protected([protected]);
            let outcome = protect_authentication_material_with(&fake, &key, identifier(IDENTIFIER))
                .map(|wrapper| wrapper.as_bytes().len());
            assert_eq!(outcome, expected);
            assert_eq!(fake.protected_plaintexts.borrow().len(), 1);
        }
    }

    #[test]
    fn full_chain_requires_correct_key_and_generation() {
        let key_payload = EncodedProtectedKeyPayload::encode(
            &EvidenceAuthenticationKey::from_bytes(KEY),
            identifier(IDENTIFIER),
        );
        let envelope = encoded_envelope(KEY, IDENTIFIER);
        let fake = FakeProtector::with_unprotected([
            key_payload.as_bytes().to_vec(),
            envelope.as_bytes().to_vec(),
        ]);
        let matched = recover_and_authenticate_in_memory_with(
            &fake,
            dummy_wrapper(ProtectedObjectKind::AuthenticationKey).as_bytes(),
            dummy_wrapper(ProtectedObjectKind::AuthenticatedEvidence).as_bytes(),
        )
        .unwrap();
        assert!(matched.parse_inner_plaintext().is_ok());
    }

    #[test]
    fn wrong_key_and_wrong_generation_fail_at_distinct_coarse_boundaries() {
        let envelope = encoded_envelope(KEY, IDENTIFIER);
        for (payload_key, payload_identifier, expected) in [
            (
                [0x44; 32],
                IDENTIFIER,
                ProtectionStageError::AuthenticationFailed,
            ),
            (
                [0x44; 32],
                [0x77; 16],
                ProtectionStageError::AuthenticationFailed,
            ),
            (KEY, [0x77; 16], ProtectionStageError::GenerationMismatch),
        ] {
            let payload = EncodedProtectedKeyPayload::encode(
                &EvidenceAuthenticationKey::from_bytes(payload_key),
                identifier(payload_identifier),
            );
            let fake = FakeProtector::with_unprotected([
                payload.as_bytes().to_vec(),
                envelope.as_bytes().to_vec(),
            ]);
            assert_eq!(
                recover_and_authenticate_in_memory_with(
                    &fake,
                    dummy_wrapper(ProtectedObjectKind::AuthenticationKey).as_bytes(),
                    dummy_wrapper(ProtectedObjectKind::AuthenticatedEvidence).as_bytes(),
                )
                .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn fake_failures_malformed_payload_wrong_kind_and_evidence_length_fail_closed() {
        let failing = FakeProtector::default();
        assert_eq!(
            unprotect_authentication_material_with(
                &failing,
                dummy_wrapper(ProtectedObjectKind::AuthenticationKey).as_bytes()
            )
            .unwrap_err(),
            ProtectionStageError::UnprotectionUnavailable
        );
        let malformed = FakeProtector::with_unprotected([vec![0; 48]]);
        assert_eq!(
            unprotect_authentication_material_with(
                &malformed,
                dummy_wrapper(ProtectedObjectKind::AuthenticationKey).as_bytes()
            )
            .unwrap_err(),
            ProtectionStageError::MalformedProtectedKeyPayload
        );
        assert_eq!(
            unprotect_authentication_material_with(
                &malformed,
                dummy_wrapper(ProtectedObjectKind::AuthenticatedEvidence).as_bytes()
            )
            .unwrap_err(),
            ProtectionStageError::WrongProtectedObjectKind
        );
        let wrong_length = FakeProtector::with_unprotected([vec![0; 225]]);
        assert_eq!(
            unprotect_authenticated_evidence_with(
                &wrong_length,
                dummy_wrapper(ProtectedObjectKind::AuthenticatedEvidence).as_bytes()
            )
            .unwrap_err(),
            ProtectionStageError::WrapperParseFailed
        );
    }

    #[test]
    fn fake_protector_malformed_input_hardening_classifies_key_outputs() {
        let key_wrapper = dummy_wrapper(ProtectedObjectKind::AuthenticationKey);
        let evidence_wrapper = dummy_wrapper(ProtectedObjectKind::AuthenticatedEvidence);
        let mut malformed_49 = vec![0; 49];
        malformed_49[0] = 1;
        let mut unsupported_49 = vec![0x31; 49];
        unsupported_49[0] = 2;

        for (candidate, expected) in [
            (
                Vec::new(),
                ProtectionStageError::MalformedProtectedKeyPayload,
            ),
            (
                vec![0x31; 48],
                ProtectionStageError::MalformedProtectedKeyPayload,
            ),
            (
                malformed_49,
                ProtectionStageError::MalformedProtectedKeyPayload,
            ),
            (
                unsupported_49,
                ProtectionStageError::UnsupportedProtectedKeyVersion,
            ),
            (
                vec![0x42; 50],
                ProtectionStageError::MalformedProtectedKeyPayload,
            ),
            (
                vec![0x53; 65_536],
                ProtectionStageError::MalformedProtectedKeyPayload,
            ),
        ] {
            let fake = FakeProtector::with_unprotected([candidate]);
            assert_complete_recovery_failure(
                &fake,
                key_wrapper.as_bytes(),
                evidence_wrapper.as_bytes(),
                expected,
            );
            assert_eq!(fake.unprotected_inputs.borrow().len(), 1);
        }
    }

    #[test]
    fn fake_protector_malformed_input_hardening_classifies_evidence_outputs() {
        let key_wrapper = dummy_wrapper(ProtectedObjectKind::AuthenticationKey);
        let evidence_wrapper = dummy_wrapper(ProtectedObjectKind::AuthenticatedEvidence);

        for (candidate, expected) in [
            (vec![0x31; 225], ProtectionStageError::WrapperParseFailed),
            (vec![0x42; 226], ProtectionStageError::AuthenticationFailed),
            (vec![0x53; 227], ProtectionStageError::WrapperParseFailed),
            (vec![0x64; 65_536], ProtectionStageError::WrapperParseFailed),
        ] {
            let fake = FakeProtector::with_unprotected([key_payload(KEY, IDENTIFIER), candidate]);
            assert_complete_recovery_failure(
                &fake,
                key_wrapper.as_bytes(),
                evidence_wrapper.as_bytes(),
                expected,
            );
            assert_eq!(fake.unprotected_inputs.borrow().len(), 2);
        }
    }

    #[test]
    fn fake_protector_malformed_input_hardening_preserves_kind_and_key_first_boundaries() {
        let key_wrapper = dummy_wrapper(ProtectedObjectKind::AuthenticationKey);
        let evidence_wrapper = dummy_wrapper(ProtectedObjectKind::AuthenticatedEvidence);

        let fake = FakeProtector::default();
        assert_complete_recovery_failure(
            &fake,
            key_wrapper.as_bytes(),
            evidence_wrapper.as_bytes(),
            ProtectionStageError::UnprotectionUnavailable,
        );
        assert_eq!(fake.unprotected_inputs.borrow().len(), 1);

        let fake = FakeProtector::default();
        assert_eq!(
            unprotect_authentication_material_with(&fake, evidence_wrapper.as_bytes()).unwrap_err(),
            ProtectionStageError::WrongProtectedObjectKind
        );
        assert_eq!(fake.unprotected_inputs.borrow().len(), 0);

        let fake = FakeProtector::default();
        assert_eq!(
            unprotect_authenticated_evidence_with(&fake, key_wrapper.as_bytes()).unwrap_err(),
            ProtectionStageError::WrongProtectedObjectKind
        );
        assert_eq!(fake.unprotected_inputs.borrow().len(), 0);
    }

    #[test]
    fn authenticated_malformed_plaintext_reaches_only_later_logical_failures() {
        let key_wrapper = dummy_wrapper(ProtectedObjectKind::AuthenticationKey);
        let evidence_wrapper = dummy_wrapper(ProtectedObjectKind::AuthenticatedEvidence);

        let fake = FakeProtector::with_unprotected([
            key_payload(KEY, IDENTIFIER),
            retagged_malformed_envelope(0),
        ]);
        let matched = recover_and_authenticate_in_memory_with(
            &fake,
            key_wrapper.as_bytes(),
            evidence_wrapper.as_bytes(),
        )
        .expect("valid HMAC and generation should reach the matched boundary");
        assert_eq!(
            matched.parse_inner_plaintext(),
            Err(InstallationEvidenceParseError::WrongEncodingMagic)
        );

        let fake = FakeProtector::with_unprotected([
            key_payload(KEY, IDENTIFIER),
            retagged_malformed_envelope(31),
        ]);
        let matched = recover_and_authenticate_in_memory_with(
            &fake,
            key_wrapper.as_bytes(),
            evidence_wrapper.as_bytes(),
        )
        .expect("valid HMAC and generation should reach the matched boundary");
        let parsed = matched
            .parse_inner_plaintext()
            .expect("mutated UTF-8 application identity should remain parseable");
        assert_eq!(
            parsed.validate_structure(),
            Err(ContractValidationError::WrongPermanentApplicationIdentifier)
        );
    }

    #[test]
    fn protection_errors_remain_coarse_and_redacted() {
        for error in [
            ProtectionStageError::WrapperParseFailed,
            ProtectionStageError::UnsupportedWrapperVersion,
            ProtectionStageError::WrongProtectedObjectKind,
            ProtectionStageError::ProtectionUnavailable,
            ProtectionStageError::UnprotectionUnavailable,
            ProtectionStageError::MalformedProtectedKeyPayload,
            ProtectionStageError::UnsupportedProtectedKeyVersion,
            ProtectionStageError::GenerationMismatch,
            ProtectionStageError::AuthenticationFailed,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains("CHDPAPI"));
            assert!(!debug.contains("CHEVAUTH"));
            assert!(!debug.contains("[0,"));
        }
    }

    #[test]
    fn module_has_no_side_effect_or_frontend_surface() {
        const SOURCE: &str = include_str!("mod.rs");
        for excluded in [
            ["std", "::fs"].concat(),
            ["std", "::env"].concat(),
            ["std", "::net"].concat(),
            ["rusqlite", "::"].concat(),
            ["tauri", "::command"].concat(),
            ["installation", "_state"].concat(),
        ] {
            assert!(!SOURCE.contains(&excluded));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_full_wrapper_dpapi_round_trip_is_same_user_and_in_memory() {
        let key = EvidenceAuthenticationKey::from_bytes(KEY);
        let key_wrapper = protect_authentication_material(&key, identifier(IDENTIFIER)).unwrap();
        let envelope = encoded_envelope(KEY, IDENTIFIER);
        let evidence_wrapper = protect_authenticated_evidence(&envelope).unwrap();
        let matched =
            recover_and_authenticate_in_memory(key_wrapper.as_bytes(), evidence_wrapper.as_bytes())
                .unwrap();
        assert!(matched.parse_inner_plaintext().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn corrupted_dpapi_blobs_cannot_produce_generation_matched_authenticated_evidence() {
        let key = EvidenceAuthenticationKey::from_bytes(KEY);
        let key_wrapper = protect_authentication_material(&key, identifier(IDENTIFIER)).unwrap();
        let envelope = encoded_envelope(KEY, IDENTIFIER);
        let evidence_wrapper = protect_authenticated_evidence(&envelope).unwrap();

        for offset in [
            protected_blob_wrapper::HEADER_LENGTH,
            protected_blob_wrapper::HEADER_LENGTH
                + (key_wrapper.as_bytes().len() - protected_blob_wrapper::HEADER_LENGTH) / 2,
            key_wrapper.as_bytes().len() - 1,
        ] {
            let mut corrupted = key_wrapper.as_bytes().to_vec();
            corrupted[offset] ^= 1;
            assert!(
                recover_and_authenticate_in_memory(&corrupted, evidence_wrapper.as_bytes())
                    .is_err()
            );
        }

        for offset in [
            protected_blob_wrapper::HEADER_LENGTH,
            protected_blob_wrapper::HEADER_LENGTH
                + (evidence_wrapper.as_bytes().len() - protected_blob_wrapper::HEADER_LENGTH) / 2,
            evidence_wrapper.as_bytes().len() - 1,
        ] {
            let mut corrupted = evidence_wrapper.as_bytes().to_vec();
            corrupted[offset] ^= 1;
            assert!(
                recover_and_authenticate_in_memory(key_wrapper.as_bytes(), &corrupted).is_err()
            );
        }
    }
}
