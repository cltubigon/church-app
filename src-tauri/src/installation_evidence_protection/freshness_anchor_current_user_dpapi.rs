//! In-memory CurrentUser-DPAPI composition for freshness-anchor artifacts.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

#[cfg(any(windows, test))]
use crate::freshness_anchor_active_wrapper_loader::LoadedActiveFreshnessAnchorWrapperPair;
use crate::{
    freshness_anchor_authenticated_envelope::{
        AnchorAuthenticationKeyGenerationIdentifier, EncodedAuthenticatedFreshnessAnchorV1,
        ParsedUntrustedAuthenticatedFreshnessAnchorV1, verify_authenticated_freshness_anchor_v1,
    },
    freshness_anchor_authentication_key::AnchorAuthenticationKey,
    freshness_anchor_contract::FreshnessAnchorContractV1,
    freshness_anchor_plaintext::ParsedUntrustedFreshnessAnchorV1,
    freshness_anchor_protected_key_payload::{
        DecodedProtectedAnchorKeyMaterial, EncodedProtectedAnchorKeyPayload,
        ProtectedAnchorKeyPayloadError,
    },
};

#[cfg(windows)]
use super::windows_current_user_dpapi::WindowsCurrentUserDpapi;
use super::{
    AuthenticatedActiveFreshnessAnchor, EncodedProtectedWrapper, InMemoryProtector,
    ProtectionStageError,
    protected_blob_wrapper::{ProtectedObjectKind, ValidatedProtectedWrapper},
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AnchorProtectionError {
    WrapperParseFailed,
    UnsupportedWrapperVersion,
    WrongProtectedObjectKind,
    ProtectionUnavailable,
    UnprotectionUnavailable,
    MalformedAnchorKeyPayload,
    UnsupportedAnchorKeyPayloadVersion,
    AuthenticatedAnchorFramingOrAuthenticationFailed,
    GenerationMismatch,
    AnchorPlaintextParseFailed,
    AnchorStructuralValidationFailed,
}

impl fmt::Debug for AnchorProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrapperParseFailed => "WrapperParseFailed",
            Self::UnsupportedWrapperVersion => "UnsupportedWrapperVersion",
            Self::WrongProtectedObjectKind => "WrongProtectedObjectKind",
            Self::ProtectionUnavailable => "ProtectionUnavailable",
            Self::UnprotectionUnavailable => "UnprotectionUnavailable",
            Self::MalformedAnchorKeyPayload => "MalformedAnchorKeyPayload",
            Self::UnsupportedAnchorKeyPayloadVersion => "UnsupportedAnchorKeyPayloadVersion",
            Self::AuthenticatedAnchorFramingOrAuthenticationFailed => {
                "AuthenticatedAnchorFramingOrAuthenticationFailed"
            }
            Self::GenerationMismatch => "GenerationMismatch",
            Self::AnchorPlaintextParseFailed => "AnchorPlaintextParseFailed",
            Self::AnchorStructuralValidationFailed => "AnchorStructuralValidationFailed",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum LoadedFreshnessAnchorValidationError {
    KeyWrapperProtectionOrPayloadFailed,
    AuthenticatedAnchorWrapperOrProtectionFailed,
    AuthenticatedAnchorFramingOrAuthenticationFailed,
    GenerationMismatch,
    AnchorPlaintextParseFailed,
    AnchorStructuralValidationFailed,
}

impl fmt::Debug for LoadedFreshnessAnchorValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::KeyWrapperProtectionOrPayloadFailed => "KeyWrapperProtectionOrPayloadFailed",
            Self::AuthenticatedAnchorWrapperOrProtectionFailed => {
                "AuthenticatedAnchorWrapperOrProtectionFailed"
            }
            Self::AuthenticatedAnchorFramingOrAuthenticationFailed => {
                "AuthenticatedAnchorFramingOrAuthenticationFailed"
            }
            Self::GenerationMismatch => "GenerationMismatch",
            Self::AnchorPlaintextParseFailed => "AnchorPlaintextParseFailed",
            Self::AnchorStructuralValidationFailed => "AnchorStructuralValidationFailed",
        })
    }
}

fn map_wrapper_error(error: ProtectionStageError) -> AnchorProtectionError {
    match error {
        ProtectionStageError::WrapperParseFailed => AnchorProtectionError::WrapperParseFailed,
        ProtectionStageError::UnsupportedWrapperVersion => {
            AnchorProtectionError::UnsupportedWrapperVersion
        }
        ProtectionStageError::WrongProtectedObjectKind => {
            AnchorProtectionError::WrongProtectedObjectKind
        }
        ProtectionStageError::ProtectionUnavailable => AnchorProtectionError::ProtectionUnavailable,
        ProtectionStageError::UnprotectionUnavailable
        | ProtectionStageError::MalformedProtectedKeyPayload
        | ProtectionStageError::UnsupportedProtectedKeyVersion
        | ProtectionStageError::GenerationMismatch
        | ProtectionStageError::AuthenticationFailed
        | ProtectionStageError::PlaintextParseFailed
        | ProtectionStageError::StructuralValidationFailed => {
            AnchorProtectionError::WrapperParseFailed
        }
    }
}

fn map_key_payload_error(error: ProtectedAnchorKeyPayloadError) -> AnchorProtectionError {
    match error {
        ProtectedAnchorKeyPayloadError::UnsupportedVersion => {
            AnchorProtectionError::UnsupportedAnchorKeyPayloadVersion
        }
        ProtectedAnchorKeyPayloadError::WrongTotalLength
        | ProtectedAnchorKeyPayloadError::InvalidGenerationIdentifier
        | ProtectedAnchorKeyPayloadError::InternalFieldBoundaryFailure => {
            AnchorProtectionError::MalformedAnchorKeyPayload
        }
    }
}

#[cfg(windows)]
pub(crate) fn protect_anchor_authentication_material(
    key: &AnchorAuthenticationKey,
    generation_identifier: AnchorAuthenticationKeyGenerationIdentifier,
) -> Result<EncodedProtectedWrapper, AnchorProtectionError> {
    protect_anchor_authentication_material_with(
        &WindowsCurrentUserDpapi,
        key,
        generation_identifier,
    )
}

fn protect_anchor_authentication_material_with(
    protector: &impl InMemoryProtector,
    key: &AnchorAuthenticationKey,
    generation_identifier: AnchorAuthenticationKeyGenerationIdentifier,
) -> Result<EncodedProtectedWrapper, AnchorProtectionError> {
    let protected = {
        let payload = EncodedProtectedAnchorKeyPayload::encode(key, generation_identifier);
        protector
            .protect(payload.as_bytes())
            .map_err(|_| AnchorProtectionError::ProtectionUnavailable)?
    };
    EncodedProtectedWrapper::encode(ProtectedObjectKind::AnchorAuthenticationKey, protected)
        .map_err(map_wrapper_error)
}

#[cfg(windows)]
pub(crate) fn recover_anchor_authentication_material(
    wrapper_bytes: &[u8],
) -> Result<
    (
        AnchorAuthenticationKey,
        AnchorAuthenticationKeyGenerationIdentifier,
    ),
    AnchorProtectionError,
> {
    recover_anchor_authentication_material_with(&WindowsCurrentUserDpapi, wrapper_bytes)
}

fn recover_anchor_authentication_material_with(
    protector: &impl InMemoryProtector,
    wrapper_bytes: &[u8],
) -> Result<
    (
        AnchorAuthenticationKey,
        AnchorAuthenticationKeyGenerationIdentifier,
    ),
    AnchorProtectionError,
> {
    let wrapper = ValidatedProtectedWrapper::parse(
        wrapper_bytes,
        ProtectedObjectKind::AnchorAuthenticationKey,
    )
    .map_err(map_wrapper_error)?;
    let unprotected = protector
        .unprotect(wrapper.blob())
        .map_err(|_| AnchorProtectionError::UnprotectionUnavailable)?;
    DecodedProtectedAnchorKeyMaterial::parse(unprotected.as_bytes())
        .map_err(map_key_payload_error)
        .map(DecodedProtectedAnchorKeyMaterial::into_parts)
}

#[cfg(windows)]
pub(crate) fn protect_authenticated_freshness_anchor(
    envelope: &EncodedAuthenticatedFreshnessAnchorV1,
) -> Result<EncodedProtectedWrapper, AnchorProtectionError> {
    protect_authenticated_freshness_anchor_with(&WindowsCurrentUserDpapi, envelope)
}

fn protect_authenticated_freshness_anchor_with(
    protector: &impl InMemoryProtector,
    envelope: &EncodedAuthenticatedFreshnessAnchorV1,
) -> Result<EncodedProtectedWrapper, AnchorProtectionError> {
    let protected = protector
        .protect(envelope.as_bytes())
        .map_err(|_| AnchorProtectionError::ProtectionUnavailable)?;
    EncodedProtectedWrapper::encode(ProtectedObjectKind::AuthenticatedFreshnessAnchor, protected)
        .map_err(map_wrapper_error)
}

#[cfg(windows)]
pub(crate) fn recover_and_validate_freshness_anchor(
    wrapper_bytes: &[u8],
    authentication_key: &AnchorAuthenticationKey,
    recovered_generation_identifier: &AnchorAuthenticationKeyGenerationIdentifier,
) -> Result<FreshnessAnchorContractV1, AnchorProtectionError> {
    recover_and_validate_freshness_anchor_with(
        &WindowsCurrentUserDpapi,
        wrapper_bytes,
        authentication_key,
        recovered_generation_identifier,
    )
}

fn recover_and_validate_freshness_anchor_with(
    protector: &impl InMemoryProtector,
    wrapper_bytes: &[u8],
    authentication_key: &AnchorAuthenticationKey,
    recovered_generation_identifier: &AnchorAuthenticationKeyGenerationIdentifier,
) -> Result<FreshnessAnchorContractV1, AnchorProtectionError> {
    let wrapper = ValidatedProtectedWrapper::parse(
        wrapper_bytes,
        ProtectedObjectKind::AuthenticatedFreshnessAnchor,
    )
    .map_err(map_wrapper_error)?;
    let unprotected = protector
        .unprotect(wrapper.blob())
        .map_err(|_| AnchorProtectionError::UnprotectionUnavailable)?;
    let parsed_envelope =
        ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse(unprotected.as_bytes())
            .map_err(|_| AnchorProtectionError::AuthenticatedAnchorFramingOrAuthenticationFailed)?;
    let authenticated =
        verify_authenticated_freshness_anchor_v1(parsed_envelope, authentication_key)
            .map_err(|_| AnchorProtectionError::AuthenticatedAnchorFramingOrAuthenticationFailed)?;
    let matched = authenticated
        .match_generation(recovered_generation_identifier)
        .map_err(|_| AnchorProtectionError::GenerationMismatch)?;
    let plaintext = matched.into_authenticated_plaintext();
    let parsed_plaintext = ParsedUntrustedFreshnessAnchorV1::parse(&plaintext)
        .map_err(|_| AnchorProtectionError::AnchorPlaintextParseFailed)?;
    parsed_plaintext
        .validate_structure()
        .map_err(|_| AnchorProtectionError::AnchorStructuralValidationFailed)
}

#[cfg(windows)]
pub(crate) fn recover_and_validate_loaded_freshness_anchor_pair(
    loaded_pair: LoadedActiveFreshnessAnchorWrapperPair,
) -> Result<AuthenticatedActiveFreshnessAnchor, LoadedFreshnessAnchorValidationError> {
    recover_and_validate_loaded_freshness_anchor_pair_with(&WindowsCurrentUserDpapi, loaded_pair)
}

#[cfg(any(windows, test))]
fn recover_and_validate_loaded_freshness_anchor_pair_with(
    protector: &impl InMemoryProtector,
    loaded_pair: LoadedActiveFreshnessAnchorWrapperPair,
) -> Result<AuthenticatedActiveFreshnessAnchor, LoadedFreshnessAnchorValidationError> {
    let (authentication_key, recovered_generation_identifier) =
        recover_anchor_authentication_material_with(protector, loaded_pair.key_wrapper_bytes())
            .map_err(|_| {
                LoadedFreshnessAnchorValidationError::KeyWrapperProtectionOrPayloadFailed
            })?;

    let contract = recover_and_validate_freshness_anchor_with(
        protector,
        loaded_pair.authenticated_anchor_wrapper_bytes(),
        &authentication_key,
        &recovered_generation_identifier,
    )
    .map_err(|error| match error {
        AnchorProtectionError::AuthenticatedAnchorFramingOrAuthenticationFailed => {
            LoadedFreshnessAnchorValidationError::AuthenticatedAnchorFramingOrAuthenticationFailed
        }
        AnchorProtectionError::GenerationMismatch => {
            LoadedFreshnessAnchorValidationError::GenerationMismatch
        }
        AnchorProtectionError::AnchorPlaintextParseFailed => {
            LoadedFreshnessAnchorValidationError::AnchorPlaintextParseFailed
        }
        AnchorProtectionError::AnchorStructuralValidationFailed => {
            LoadedFreshnessAnchorValidationError::AnchorStructuralValidationFailed
        }
        AnchorProtectionError::WrapperParseFailed
        | AnchorProtectionError::UnsupportedWrapperVersion
        | AnchorProtectionError::WrongProtectedObjectKind
        | AnchorProtectionError::UnprotectionUnavailable
        | AnchorProtectionError::ProtectionUnavailable
        | AnchorProtectionError::MalformedAnchorKeyPayload
        | AnchorProtectionError::UnsupportedAnchorKeyPayloadVersion => {
            LoadedFreshnessAnchorValidationError::AuthenticatedAnchorWrapperOrProtectionFailed
        }
    })?;

    Ok(AuthenticatedActiveFreshnessAnchor::from_authenticated_active_contract(contract))
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque};

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    use super::super::{OpaqueProtectedBytes, ProtectorOperationError, UnprotectedBytes};
    use super::*;
    use crate::{
        freshness_anchor_authenticated_envelope::{
            AUTHENTICATED_PREFIX_LENGTH, construct_authenticated_freshness_anchor_v1,
        },
        freshness_anchor_plaintext::EncodedFreshnessAnchorV1,
        installation_evidence_contract::{
            DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
            RecoveryOrReplacementGeneration, SetupPublicationIdentifier,
        },
    };

    const KEY: [u8; 32] = [0x31; 32];
    const IDENTIFIER: [u8; 16] = [0x42; 16];
    const BLOB: [u8; 4] = [0x53, 0x54, 0x55, 0x56];

    #[derive(Default)]
    struct FakeProtector {
        protected_inputs: RefCell<Vec<Vec<u8>>>,
        unprotected_inputs: RefCell<Vec<Vec<u8>>>,
        protected_output: RefCell<Option<Result<Vec<u8>, ProtectorOperationError>>>,
        unprotected_outputs: RefCell<VecDeque<Result<Vec<u8>, ProtectorOperationError>>>,
    }

    impl FakeProtector {
        fn protecting(output: Vec<u8>) -> Self {
            Self {
                protected_output: RefCell::new(Some(Ok(output))),
                ..Self::default()
            }
        }

        fn protection_failure() -> Self {
            Self {
                protected_output: RefCell::new(Some(Err(ProtectorOperationError))),
                ..Self::default()
            }
        }

        fn unprotecting(output: Vec<u8>) -> Self {
            let mut outputs = VecDeque::new();
            outputs.push_back(Ok(output));
            Self {
                unprotected_outputs: RefCell::new(outputs),
                ..Self::default()
            }
        }

        fn unprotecting_many(
            outputs: impl IntoIterator<Item = Result<Vec<u8>, ProtectorOperationError>>,
        ) -> Self {
            Self {
                unprotected_outputs: RefCell::new(outputs.into_iter().collect()),
                ..Self::default()
            }
        }

        fn unprotection_failure() -> Self {
            let mut outputs = VecDeque::new();
            outputs.push_back(Err(ProtectorOperationError));
            Self {
                unprotected_outputs: RefCell::new(outputs),
                ..Self::default()
            }
        }
    }

    impl InMemoryProtector for FakeProtector {
        fn protect(
            &self,
            plaintext: &[u8],
        ) -> Result<OpaqueProtectedBytes, ProtectorOperationError> {
            self.protected_inputs.borrow_mut().push(plaintext.to_vec());
            self.protected_output
                .borrow_mut()
                .take()
                .expect("one expected protection call")
                .map(OpaqueProtectedBytes::new)
        }

        fn unprotect(&self, protected: &[u8]) -> Result<UnprotectedBytes, ProtectorOperationError> {
            self.unprotected_inputs
                .borrow_mut()
                .push(protected.to_vec());
            self.unprotected_outputs
                .borrow_mut()
                .pop_front()
                .expect("one expected unprotection call")
                .map(UnprotectedBytes::new)
        }
    }

    fn identifier(bytes: [u8; 16]) -> AnchorAuthenticationKeyGenerationIdentifier {
        AnchorAuthenticationKeyGenerationIdentifier::from_bytes(bytes).unwrap()
    }

    fn contract() -> FreshnessAnchorContractV1 {
        FreshnessAnchorContractV1::new(
            InstallationIdentifier::from_bytes([0x11; 16]).unwrap(),
            InstallationGeneration::new(7).unwrap(),
            RecoveryOrReplacementGeneration::new(9).unwrap(),
            DatabaseKeyGenerationIdentifier::from_bytes([0x22; 16]).unwrap(),
            SetupPublicationIdentifier::from_bytes([0x33; 16]).unwrap(),
        )
    }

    fn envelope() -> EncodedAuthenticatedFreshnessAnchorV1 {
        construct_authenticated_freshness_anchor_v1(
            &AnchorAuthenticationKey::from_bytes(KEY),
            identifier(IDENTIFIER),
            &EncodedFreshnessAnchorV1::encode(&contract()),
        )
        .unwrap()
    }

    fn wrapper(kind: ProtectedObjectKind) -> EncodedProtectedWrapper {
        EncodedProtectedWrapper::encode(kind, OpaqueProtectedBytes::new(BLOB.to_vec())).unwrap()
    }

    fn wrapper_with_blob(kind: ProtectedObjectKind, blob: &[u8]) -> EncodedProtectedWrapper {
        EncodedProtectedWrapper::encode(kind, OpaqueProtectedBytes::new(blob.to_vec())).unwrap()
    }

    fn loaded_pair(
        key_wrapper: &EncodedProtectedWrapper,
        anchor_wrapper: &EncodedProtectedWrapper,
    ) -> LoadedActiveFreshnessAnchorWrapperPair {
        LoadedActiveFreshnessAnchorWrapperPair::from_synthetic_wrapper_bytes(
            key_wrapper.as_bytes().to_vec(),
            anchor_wrapper.as_bytes().to_vec(),
        )
    }

    fn canonical_loaded_pair() -> LoadedActiveFreshnessAnchorWrapperPair {
        loaded_pair(
            &wrapper_with_blob(ProtectedObjectKind::AnchorAuthenticationKey, &[0x61]),
            &wrapper_with_blob(ProtectedObjectKind::AuthenticatedFreshnessAnchor, &[0x62]),
        )
    }

    fn encoded_key_payload() -> Vec<u8> {
        EncodedProtectedAnchorKeyPayload::encode(
            &AnchorAuthenticationKey::from_bytes(KEY),
            identifier(IDENTIFIER),
        )
        .as_bytes()
        .to_vec()
    }

    fn retag(bytes: &mut [u8; 138]) {
        let mut hmac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        hmac.update(&bytes[..AUTHENTICATED_PREFIX_LENGTH]);
        bytes[AUTHENTICATED_PREFIX_LENGTH..].copy_from_slice(&hmac.finalize().into_bytes());
    }

    #[test]
    fn key_protection_passes_exact_encoding_and_returns_kind_three_without_generation() {
        let fake = FakeProtector::protecting(BLOB.to_vec());
        let key = AnchorAuthenticationKey::from_bytes(KEY);
        let result =
            protect_anchor_authentication_material_with(&fake, &key, identifier(IDENTIFIER))
                .unwrap();

        assert_eq!(
            fake.protected_inputs.borrow().as_slice(),
            &[encoded_key_payload()]
        );
        assert_eq!(fake.protected_inputs.borrow()[0].len(), 49);
        assert_eq!(result.as_bytes()[9], 0x03);
        assert_eq!(
            ValidatedProtectedWrapper::parse(
                result.as_bytes(),
                ProtectedObjectKind::AuthenticatedFreshnessAnchor,
            )
            .unwrap_err(),
            ProtectionStageError::WrongProtectedObjectKind
        );
        assert_eq!(fake.protected_inputs.borrow().len(), 1);
    }

    #[test]
    fn key_protection_failure_is_coarse_and_payload_zeroization_is_drop_scoped() {
        let error = protect_anchor_authentication_material_with(
            &FakeProtector::protection_failure(),
            &AnchorAuthenticationKey::from_bytes(KEY),
            identifier(IDENTIFIER),
        )
        .unwrap_err();
        assert_eq!(error, AnchorProtectionError::ProtectionUnavailable);

        const SOURCE: &str = include_str!("freshness_anchor_current_user_dpapi.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("let payload = EncodedProtectedAnchorKeyPayload::encode"));
        assert!(production.contains("protector\n            .protect(payload.as_bytes())"));
        assert!(!production.contains("generate_anchor_authentication_material"));
        const PAYLOAD_SOURCE: &str = include_str!("../freshness_anchor_protected_key_payload.rs");
        assert!(PAYLOAD_SOURCE.contains("impl Drop for EncodedProtectedAnchorKeyPayload"));
        assert!(PAYLOAD_SOURCE.contains("self.zeroize_owned_bytes();"));
    }

    #[test]
    fn key_recovery_round_trips_and_rejects_kinds_before_unprotect() {
        let fake = FakeProtector::unprotecting(encoded_key_payload());
        let (key, recovered_identifier) = recover_anchor_authentication_material_with(
            &fake,
            wrapper(ProtectedObjectKind::AnchorAuthenticationKey).as_bytes(),
        )
        .unwrap();
        key.expose_bytes(|bytes| assert_eq!(bytes, &KEY));
        assert!(recovered_identifier.matches(&identifier(IDENTIFIER)));
        assert_eq!(
            fake.unprotected_inputs.borrow().as_slice(),
            &[BLOB.to_vec()]
        );

        for kind in [
            ProtectedObjectKind::AuthenticationKey,
            ProtectedObjectKind::AuthenticatedEvidence,
            ProtectedObjectKind::AuthenticatedFreshnessAnchor,
        ] {
            let fake = FakeProtector::unprotecting(encoded_key_payload());
            assert_eq!(
                recover_anchor_authentication_material_with(&fake, wrapper(kind).as_bytes())
                    .unwrap_err(),
                AnchorProtectionError::WrongProtectedObjectKind
            );
            assert!(fake.unprotected_inputs.borrow().is_empty());
        }
    }

    #[test]
    fn key_recovery_maps_wrapper_unprotect_and_payload_failures() {
        let fake = FakeProtector::unprotecting(encoded_key_payload());
        assert_eq!(
            recover_anchor_authentication_material_with(&fake, b"malformed").unwrap_err(),
            AnchorProtectionError::WrapperParseFailed
        );
        assert!(fake.unprotected_inputs.borrow().is_empty());

        assert_eq!(
            recover_anchor_authentication_material_with(
                &FakeProtector::unprotection_failure(),
                wrapper(ProtectedObjectKind::AnchorAuthenticationKey).as_bytes(),
            )
            .unwrap_err(),
            AnchorProtectionError::UnprotectionUnavailable
        );

        let mut unsupported = encoded_key_payload();
        unsupported[0] = 2;
        let mut zero_identifier = encoded_key_payload();
        zero_identifier[1..17].fill(0);
        for (payload, expected) in [
            (
                vec![0; 48],
                AnchorProtectionError::MalformedAnchorKeyPayload,
            ),
            (
                unsupported,
                AnchorProtectionError::UnsupportedAnchorKeyPayloadVersion,
            ),
            (
                zero_identifier,
                AnchorProtectionError::MalformedAnchorKeyPayload,
            ),
        ] {
            assert_eq!(
                recover_anchor_authentication_material_with(
                    &FakeProtector::unprotecting(payload),
                    wrapper(ProtectedObjectKind::AnchorAuthenticationKey).as_bytes(),
                )
                .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn key_recovery_buffers_and_errors_follow_redacted_zeroizing_paths() {
        const PARENT_SOURCE: &str = include_str!("mod.rs");
        let drop_body = PARENT_SOURCE
            .split_once("impl Drop for UnprotectedBytes")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(drop_body.contains("self.0.zeroize();"));
        for error in [
            AnchorProtectionError::WrapperParseFailed,
            AnchorProtectionError::UnsupportedWrapperVersion,
            AnchorProtectionError::WrongProtectedObjectKind,
            AnchorProtectionError::ProtectionUnavailable,
            AnchorProtectionError::UnprotectionUnavailable,
            AnchorProtectionError::MalformedAnchorKeyPayload,
            AnchorProtectionError::UnsupportedAnchorKeyPayloadVersion,
            AnchorProtectionError::AuthenticatedAnchorFramingOrAuthenticationFailed,
            AnchorProtectionError::GenerationMismatch,
            AnchorProtectionError::AnchorPlaintextParseFailed,
            AnchorProtectionError::AnchorStructuralValidationFailed,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains("CHDPAPI"));
            assert!(!debug.contains("CHANAUTH"));
            assert!(!debug.contains("0x"));
        }
    }

    #[test]
    fn anchor_protection_passes_exact_envelope_unchanged_and_returns_kind_four() {
        let envelope = envelope();
        let fake = FakeProtector::protecting(BLOB.to_vec());
        let result = protect_authenticated_freshness_anchor_with(&fake, &envelope).unwrap();
        assert_eq!(fake.protected_inputs.borrow()[0], envelope.as_bytes());
        assert_eq!(fake.protected_inputs.borrow()[0].len(), 138);
        assert_eq!(result.as_bytes()[9], 0x04);

        let error = protect_authenticated_freshness_anchor_with(
            &FakeProtector::protection_failure(),
            &envelope,
        )
        .unwrap_err();
        assert_eq!(error, AnchorProtectionError::ProtectionUnavailable);
    }

    #[test]
    fn valid_recovery_returns_only_the_exact_structural_contract() {
        let expected = contract();
        let recovered = recover_and_validate_freshness_anchor_with(
            &FakeProtector::unprotecting(envelope().as_bytes().to_vec()),
            wrapper(ProtectedObjectKind::AuthenticatedFreshnessAnchor).as_bytes(),
            &AnchorAuthenticationKey::from_bytes(KEY),
            &identifier(IDENTIFIER),
        )
        .unwrap();
        assert_eq!(recovered, expected);
        fn exact_type(_: &FreshnessAnchorContractV1) {}
        exact_type(&recovered);
    }

    #[test]
    fn anchor_recovery_rejects_wrapper_and_unprotect_failures_before_protocol() {
        for kind in [
            ProtectedObjectKind::AuthenticationKey,
            ProtectedObjectKind::AuthenticatedEvidence,
            ProtectedObjectKind::AnchorAuthenticationKey,
        ] {
            let fake = FakeProtector::unprotecting(envelope().as_bytes().to_vec());
            assert_eq!(
                recover_and_validate_freshness_anchor_with(
                    &fake,
                    wrapper(kind).as_bytes(),
                    &AnchorAuthenticationKey::from_bytes(KEY),
                    &identifier(IDENTIFIER),
                )
                .unwrap_err(),
                AnchorProtectionError::WrongProtectedObjectKind
            );
            assert!(fake.unprotected_inputs.borrow().is_empty());
        }

        assert_eq!(
            recover_and_validate_freshness_anchor_with(
                &FakeProtector::unprotection_failure(),
                wrapper(ProtectedObjectKind::AuthenticatedFreshnessAnchor).as_bytes(),
                &AnchorAuthenticationKey::from_bytes(KEY),
                &identifier(IDENTIFIER),
            )
            .unwrap_err(),
            AnchorProtectionError::UnprotectionUnavailable
        );
    }

    #[test]
    fn framing_hmac_tag_and_generation_fail_closed_in_order() {
        let valid = envelope();
        let mut wrong_framing = valid.as_bytes().to_vec();
        wrong_framing[0] ^= 1;
        let mut altered_tag = valid.as_bytes().to_vec();
        altered_tag[137] ^= 1;

        for (bytes, key, generation, expected) in [
            (
                wrong_framing,
                KEY,
                IDENTIFIER,
                AnchorProtectionError::AuthenticatedAnchorFramingOrAuthenticationFailed,
            ),
            (
                valid.as_bytes().to_vec(),
                [0x77; 32],
                IDENTIFIER,
                AnchorProtectionError::AuthenticatedAnchorFramingOrAuthenticationFailed,
            ),
            (
                altered_tag,
                KEY,
                IDENTIFIER,
                AnchorProtectionError::AuthenticatedAnchorFramingOrAuthenticationFailed,
            ),
            (
                valid.as_bytes().to_vec(),
                KEY,
                [0x88; 16],
                AnchorProtectionError::GenerationMismatch,
            ),
        ] {
            assert_eq!(
                recover_and_validate_freshness_anchor_with(
                    &FakeProtector::unprotecting(bytes),
                    wrapper(ProtectedObjectKind::AuthenticatedFreshnessAnchor).as_bytes(),
                    &AnchorAuthenticationKey::from_bytes(key),
                    &identifier(generation),
                )
                .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn authenticated_malformed_and_structurally_invalid_plaintexts_fail_late() {
        let valid = envelope();
        let mut malformed = *valid.as_bytes();
        malformed[30] ^= 1;
        retag(&mut malformed);
        assert_eq!(
            recover_and_validate_freshness_anchor_with(
                &FakeProtector::unprotecting(malformed.to_vec()),
                wrapper(ProtectedObjectKind::AuthenticatedFreshnessAnchor).as_bytes(),
                &AnchorAuthenticationKey::from_bytes(KEY),
                &identifier(IDENTIFIER),
            )
            .unwrap_err(),
            AnchorProtectionError::AnchorPlaintextParseFailed
        );

        let mut invalid = *valid.as_bytes();
        invalid[30 + 12..30 + 28].fill(0);
        retag(&mut invalid);
        assert_eq!(
            recover_and_validate_freshness_anchor_with(
                &FakeProtector::unprotecting(invalid.to_vec()),
                wrapper(ProtectedObjectKind::AuthenticatedFreshnessAnchor).as_bytes(),
                &AnchorAuthenticationKey::from_bytes(KEY),
                &identifier(IDENTIFIER),
            )
            .unwrap_err(),
            AnchorProtectionError::AnchorStructuralValidationFailed
        );
    }

    #[test]
    fn loaded_pair_composition_consumes_only_the_pair_and_returns_the_exact_proof() {
        let fake = FakeProtector::unprotecting_many([
            Ok(encoded_key_payload()),
            Ok(envelope().as_bytes().to_vec()),
        ]);
        let recovered =
            recover_and_validate_loaded_freshness_anchor_pair_with(&fake, canonical_loaded_pair())
                .unwrap();

        fn require_exact_type(_: AuthenticatedActiveFreshnessAnchor) {}
        assert_eq!(
            recovered.installation_identifier(),
            contract().installation_identifier()
        );
        require_exact_type(recovered);
        assert_eq!(
            fake.unprotected_inputs.borrow().as_slice(),
            &[vec![0x61], vec![0x62]]
        );
    }

    #[test]
    fn loaded_pair_key_failures_stop_before_anchor_processing() {
        let anchor = wrapper_with_blob(ProtectedObjectKind::AuthenticatedFreshnessAnchor, &[0x62]);
        let malformed_key = LoadedActiveFreshnessAnchorWrapperPair::from_synthetic_wrapper_bytes(
            b"malformed".to_vec(),
            anchor.as_bytes().to_vec(),
        );
        let fake = FakeProtector::unprotecting(encoded_key_payload());
        assert_eq!(
            recover_and_validate_loaded_freshness_anchor_pair_with(&fake, malformed_key)
                .unwrap_err(),
            LoadedFreshnessAnchorValidationError::KeyWrapperProtectionOrPayloadFailed
        );
        assert!(fake.unprotected_inputs.borrow().is_empty());

        let wrong_kind = loaded_pair(
            &wrapper_with_blob(ProtectedObjectKind::AuthenticatedFreshnessAnchor, &[0x61]),
            &anchor,
        );
        let fake = FakeProtector::unprotecting(encoded_key_payload());
        assert_eq!(
            recover_and_validate_loaded_freshness_anchor_pair_with(&fake, wrong_kind).unwrap_err(),
            LoadedFreshnessAnchorValidationError::KeyWrapperProtectionOrPayloadFailed
        );
        assert!(fake.unprotected_inputs.borrow().is_empty());

        let fake = FakeProtector::unprotection_failure();
        assert_eq!(
            recover_and_validate_loaded_freshness_anchor_pair_with(&fake, canonical_loaded_pair())
                .unwrap_err(),
            LoadedFreshnessAnchorValidationError::KeyWrapperProtectionOrPayloadFailed
        );
        assert_eq!(fake.unprotected_inputs.borrow().as_slice(), &[vec![0x61]]);
    }

    #[test]
    fn loaded_pair_rejects_malformed_unsupported_and_zero_identifier_key_payloads() {
        let mut unsupported = encoded_key_payload();
        unsupported[0] = 2;
        let mut zero_identifier = encoded_key_payload();
        zero_identifier[1..17].fill(0);

        for payload in [vec![0; 48], unsupported, zero_identifier] {
            let fake = FakeProtector::unprotecting(payload);
            assert_eq!(
                recover_and_validate_loaded_freshness_anchor_pair_with(
                    &fake,
                    canonical_loaded_pair()
                )
                .unwrap_err(),
                LoadedFreshnessAnchorValidationError::KeyWrapperProtectionOrPayloadFailed
            );
            assert_eq!(fake.unprotected_inputs.borrow().as_slice(), &[vec![0x61]]);
        }
    }

    #[test]
    fn loaded_pair_anchor_wrapper_and_unprotection_fail_after_key_recovery() {
        let key = wrapper_with_blob(ProtectedObjectKind::AnchorAuthenticationKey, &[0x61]);
        for anchor_bytes in [
            b"malformed".to_vec(),
            wrapper_with_blob(ProtectedObjectKind::AnchorAuthenticationKey, &[0x62])
                .as_bytes()
                .to_vec(),
        ] {
            let fake = FakeProtector::unprotecting_many([Ok(encoded_key_payload())]);
            let pair = LoadedActiveFreshnessAnchorWrapperPair::from_synthetic_wrapper_bytes(
                key.as_bytes().to_vec(),
                anchor_bytes,
            );
            assert_eq!(
                recover_and_validate_loaded_freshness_anchor_pair_with(&fake, pair).unwrap_err(),
                LoadedFreshnessAnchorValidationError::AuthenticatedAnchorWrapperOrProtectionFailed
            );
            assert_eq!(fake.unprotected_inputs.borrow().as_slice(), &[vec![0x61]]);
        }

        let fake = FakeProtector::unprotecting_many([
            Ok(encoded_key_payload()),
            Err(ProtectorOperationError),
        ]);
        assert_eq!(
            recover_and_validate_loaded_freshness_anchor_pair_with(&fake, canonical_loaded_pair())
                .unwrap_err(),
            LoadedFreshnessAnchorValidationError::AuthenticatedAnchorWrapperOrProtectionFailed
        );
        assert_eq!(
            fake.unprotected_inputs.borrow().as_slice(),
            &[vec![0x61], vec![0x62]]
        );
    }

    #[test]
    fn loaded_pair_framing_hmac_tag_and_generation_fail_closed() {
        let valid = envelope();
        let mut wrong_framing = valid.as_bytes().to_vec();
        wrong_framing[0] ^= 1;
        let mut altered_tag = valid.as_bytes().to_vec();
        altered_tag[137] ^= 1;
        let wrong_key_envelope = construct_authenticated_freshness_anchor_v1(
            &AnchorAuthenticationKey::from_bytes([0x77; 32]),
            identifier(IDENTIFIER),
            &EncodedFreshnessAnchorV1::encode(&contract()),
        )
        .unwrap();
        let generation_mismatch = construct_authenticated_freshness_anchor_v1(
            &AnchorAuthenticationKey::from_bytes(KEY),
            identifier([0x88; 16]),
            &EncodedFreshnessAnchorV1::encode(&contract()),
        )
        .unwrap();

        for (bytes, expected) in [
            (
                wrong_framing,
                LoadedFreshnessAnchorValidationError::AuthenticatedAnchorFramingOrAuthenticationFailed,
            ),
            (
                wrong_key_envelope.as_bytes().to_vec(),
                LoadedFreshnessAnchorValidationError::AuthenticatedAnchorFramingOrAuthenticationFailed,
            ),
            (
                altered_tag,
                LoadedFreshnessAnchorValidationError::AuthenticatedAnchorFramingOrAuthenticationFailed,
            ),
            (
                generation_mismatch.as_bytes().to_vec(),
                LoadedFreshnessAnchorValidationError::GenerationMismatch,
            ),
        ] {
            let fake =
                FakeProtector::unprotecting_many([Ok(encoded_key_payload()), Ok(bytes)]);
            assert_eq!(
                recover_and_validate_loaded_freshness_anchor_pair_with(
                    &fake,
                    canonical_loaded_pair()
                )
                .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn loaded_pair_authenticated_inner_failures_remain_distinct_and_late() {
        let valid = envelope();
        let mut malformed = *valid.as_bytes();
        malformed[30] ^= 1;
        retag(&mut malformed);
        let mut invalid = *valid.as_bytes();
        invalid[30 + 12..30 + 28].fill(0);
        retag(&mut invalid);

        for (bytes, expected) in [
            (
                malformed.to_vec(),
                LoadedFreshnessAnchorValidationError::AnchorPlaintextParseFailed,
            ),
            (
                invalid.to_vec(),
                LoadedFreshnessAnchorValidationError::AnchorStructuralValidationFailed,
            ),
        ] {
            let fake = FakeProtector::unprotecting_many([Ok(encoded_key_payload()), Ok(bytes)]);
            assert_eq!(
                recover_and_validate_loaded_freshness_anchor_pair_with(
                    &fake,
                    canonical_loaded_pair()
                )
                .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn loaded_pair_boundary_is_consuming_redacted_and_authority_free() {
        const SOURCE: &str = include_str!("freshness_anchor_current_user_dpapi.rs");
        const LOADER_SOURCE: &str = include_str!("../freshness_anchor_active_wrapper_loader.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let composition = production
            .split_once("fn recover_and_validate_loaded_freshness_anchor_pair_with(")
            .unwrap()
            .1;
        let key_position = composition.find("loaded_pair.key_wrapper_bytes()").unwrap();
        let anchor_position = composition
            .find("loaded_pair.authenticated_anchor_wrapper_bytes()")
            .unwrap();
        assert!(key_position < anchor_position);
        assert!(production.contains(
            "#[cfg(windows)]\npub(crate) fn recover_and_validate_loaded_freshness_anchor_pair("
        ));
        assert!(production.contains(
            "loaded_pair: LoadedActiveFreshnessAnchorWrapperPair,\n) -> Result<AuthenticatedActiveFreshnessAnchor"
        ));
        assert!(!LOADER_SOURCE.contains("impl Clone for LoadedActiveFreshnessAnchorWrapperPair"));
        assert!(!LOADER_SOURCE.contains("impl Copy for LoadedActiveFreshnessAnchorWrapperPair"));
        assert!(!LOADER_SOURCE.contains("-> Vec<u8>"));

        for error in [
            LoadedFreshnessAnchorValidationError::KeyWrapperProtectionOrPayloadFailed,
            LoadedFreshnessAnchorValidationError::AuthenticatedAnchorWrapperOrProtectionFailed,
            LoadedFreshnessAnchorValidationError::AuthenticatedAnchorFramingOrAuthenticationFailed,
            LoadedFreshnessAnchorValidationError::GenerationMismatch,
            LoadedFreshnessAnchorValidationError::AnchorPlaintextParseFailed,
            LoadedFreshnessAnchorValidationError::AnchorStructuralValidationFailed,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains("CHDPAPI"));
            assert!(!debug.contains("CHANAUTH"));
            assert!(!debug.contains("0x"));
        }
        for excluded in [
            "AssuredFreshnessAnchor",
            "std::fs",
            "std::path",
            "FreshnessAnchorActivePresence",
            "load_active_freshness_anchor_wrapper_pair",
            "freshness_classification",
            "rusqlite",
            "tauri::command",
            "publication",
            "recovery",
            "replacement",
            "migration",
            "reset",
        ] {
            assert!(
                !production.contains(excluded),
                "unexpected authority: {excluded}"
            );
        }
    }

    #[test]
    fn source_preserves_exact_transition_order_scope_and_cfg_boundary() {
        const SOURCE: &str = include_str!("freshness_anchor_current_user_dpapi.rs");
        const PARENT_SOURCE: &str = include_str!("mod.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let parent_production = PARENT_SOURCE.split("#[cfg(test)]").next().unwrap();
        let recovery = production
            .split_once("fn recover_and_validate_freshness_anchor_with(")
            .unwrap()
            .1;
        let ordered = [
            "ValidatedProtectedWrapper::parse",
            ".unprotect(wrapper.blob())",
            "ParsedUntrustedAuthenticatedFreshnessAnchorV1::parse",
            "verify_authenticated_freshness_anchor_v1",
            ".match_generation",
            ".into_authenticated_plaintext",
            "ParsedUntrustedFreshnessAnchorV1::parse",
            ".validate_structure()",
        ];
        let mut previous = 0;
        for marker in ordered {
            let position = recovery.find(marker).unwrap();
            assert!(position >= previous, "transition out of order: {marker}");
            previous = position;
        }
        let loaded_recovery = production
            .split_once("fn recover_and_validate_loaded_freshness_anchor_pair_with(")
            .unwrap()
            .1;
        let structural_validation = loaded_recovery
            .find("recover_and_validate_freshness_anchor_with(")
            .unwrap();
        let proof_construction = loaded_recovery
            .find("AuthenticatedActiveFreshnessAnchor::from_authenticated_active_contract(")
            .unwrap();
        assert!(structural_validation < proof_construction);
        assert!(
            production
                .contains("#[cfg(windows)]\npub(crate) fn protect_anchor_authentication_material")
        );
        assert!(
            production
                .contains("#[cfg(windows)]\npub(crate) fn recover_anchor_authentication_material")
        );
        assert!(
            production
                .contains("#[cfg(windows)]\npub(crate) fn protect_authenticated_freshness_anchor")
        );
        assert!(production.contains("pub(crate) enum AnchorProtectionError"));
        assert!(parent_production.contains(
            "#[cfg(windows)]\n#[allow(unused_imports)]\npub(crate) use freshness_anchor_current_user_dpapi::{\n    AnchorProtectionError, protect_anchor_authentication_material,\n    protect_authenticated_freshness_anchor,\n};"
        ));
        assert!(!parent_production.contains("pub mod freshness_anchor_current_user_dpapi"));
        assert_eq!(
            production
                .matches("pub(crate) fn protect_anchor_authentication_material(")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches("pub(crate) fn protect_authenticated_freshness_anchor(")
                .count(),
            1
        );
        assert!(parent_production.contains(
            "pub(crate) fn protect_anchor_authentication_material_for_manual_startup_fixture("
        ));
        assert!(parent_production.contains(
            "freshness_anchor_current_user_dpapi::protect_anchor_authentication_material("
        ));
        assert!(parent_production.contains(
            "pub(crate) fn protect_authenticated_freshness_anchor_for_manual_startup_fixture("
        ));
        assert!(parent_production.contains(
            "freshness_anchor_current_user_dpapi::protect_authenticated_freshness_anchor(envelope)"
        ));

        #[cfg(windows)]
        fn require_exact_production_facade(
            _: fn(
                &AnchorAuthenticationKey,
                AnchorAuthenticationKeyGenerationIdentifier,
            ) -> Result<EncodedProtectedWrapper, AnchorProtectionError>,
            _: fn(
                &EncodedAuthenticatedFreshnessAnchorV1,
            ) -> Result<EncodedProtectedWrapper, AnchorProtectionError>,
        ) {
        }

        #[cfg(windows)]
        require_exact_production_facade(
            super::super::protect_anchor_authentication_material,
            super::super::protect_authenticated_freshness_anchor,
        );
        assert!(
            production
                .contains("#[cfg(windows)]\npub(crate) fn recover_and_validate_freshness_anchor")
        );
        for excluded in [
            "AssuredFreshnessAnchor",
            "std::fs",
            "std::path",
            "rusqlite",
            "tauri::command",
            "Present",
            "freshness_classification",
            "publication",
            "startup",
            "migration",
        ] {
            assert!(
                !production.contains(excluded),
                "unexpected authority: {excluded}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_current_user_dpapi_round_trips_exact_anchor_payloads() {
        let key = AnchorAuthenticationKey::from_bytes(KEY);
        let key_wrapper =
            protect_anchor_authentication_material(&key, identifier(IDENTIFIER)).unwrap();
        let (recovered_key, recovered_identifier) =
            recover_anchor_authentication_material(key_wrapper.as_bytes()).unwrap();
        recovered_key.expose_bytes(|bytes| assert_eq!(bytes, &KEY));
        assert!(recovered_identifier.matches(&identifier(IDENTIFIER)));

        let authenticated_anchor = envelope();
        let anchor_wrapper = protect_authenticated_freshness_anchor(&authenticated_anchor).unwrap();
        let recovered = recover_and_validate_freshness_anchor(
            anchor_wrapper.as_bytes(),
            &key,
            &identifier(IDENTIFIER),
        )
        .unwrap();
        assert_eq!(recovered, contract());

        let loaded = LoadedActiveFreshnessAnchorWrapperPair::from_synthetic_wrapper_bytes(
            key_wrapper.as_bytes().to_vec(),
            anchor_wrapper.as_bytes().to_vec(),
        );
        let recovered_proof = recover_and_validate_loaded_freshness_anchor_pair(loaded).unwrap();
        assert_eq!(
            recovered_proof.installation_identifier(),
            contract().installation_identifier()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_current_user_dpapi_corruption_fails_closed_for_both_anchor_kinds() {
        let key = AnchorAuthenticationKey::from_bytes(KEY);
        let key_wrapper =
            protect_anchor_authentication_material(&key, identifier(IDENTIFIER)).unwrap();
        let anchor_wrapper = protect_authenticated_freshness_anchor(&envelope()).unwrap();
        for original in [key_wrapper.as_bytes(), anchor_wrapper.as_bytes()] {
            let first = super::super::protected_blob_wrapper::HEADER_LENGTH;
            for offset in [
                first,
                first + (original.len() - first) / 2,
                original.len() - 1,
            ] {
                let mut corrupted = original.to_vec();
                corrupted[offset] ^= 1;
                if original[9] == 0x03 {
                    assert!(recover_anchor_authentication_material(&corrupted).is_err());
                } else {
                    assert!(
                        recover_and_validate_freshness_anchor(
                            &corrupted,
                            &key,
                            &identifier(IDENTIFIER),
                        )
                        .is_err()
                    );
                }

                let loaded = if original[9] == 0x03 {
                    LoadedActiveFreshnessAnchorWrapperPair::from_synthetic_wrapper_bytes(
                        corrupted,
                        anchor_wrapper.as_bytes().to_vec(),
                    )
                } else {
                    LoadedActiveFreshnessAnchorWrapperPair::from_synthetic_wrapper_bytes(
                        key_wrapper.as_bytes().to_vec(),
                        corrupted,
                    )
                };
                assert!(recover_and_validate_loaded_freshness_anchor_pair(loaded).is_err());
            }
        }

        let mut substituted_key_kind = key_wrapper.as_bytes().to_vec();
        substituted_key_kind[9] = 0x04;
        let substituted_key_pair =
            LoadedActiveFreshnessAnchorWrapperPair::from_synthetic_wrapper_bytes(
                substituted_key_kind,
                anchor_wrapper.as_bytes().to_vec(),
            );
        assert!(recover_and_validate_loaded_freshness_anchor_pair(substituted_key_pair).is_err());

        let mut substituted_anchor_kind = anchor_wrapper.as_bytes().to_vec();
        substituted_anchor_kind[9] = 0x03;
        let substituted_anchor_pair =
            LoadedActiveFreshnessAnchorWrapperPair::from_synthetic_wrapper_bytes(
                key_wrapper.as_bytes().to_vec(),
                substituted_anchor_kind,
            );
        assert!(
            recover_and_validate_loaded_freshness_anchor_pair(substituted_anchor_pair).is_err()
        );
    }
}
