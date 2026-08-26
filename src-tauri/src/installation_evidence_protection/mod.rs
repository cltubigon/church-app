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
    database_freshness_classification::{
        AssuredFreshnessAnchor, AssuredFreshnessAnchorConstructionToken,
    },
    freshness_anchor_contract::FreshnessAnchorContractV1,
    installation_evidence_authenticated_envelope::{
        CryptographicallyAuthenticatedEnvelopeV1, EncodedAuthenticatedEnvelopeV1,
        EvidenceAuthenticationKeyGenerationIdentifier, GenerationMatchedAuthenticatedEnvelopeV1,
        ParsedUntrustedAuthenticatedEnvelopeV1, verify_authenticated_envelope_v1,
    },
    installation_evidence_authentication_key::EvidenceAuthenticationKey,
    installation_evidence_contract::{
        ParsedUntrustedInstallationEvidenceContract, StructurallyValidatedInstallationEvidence,
    },
};
#[cfg(windows)]
use crate::{
    installation_evidence_persistence::load_active_installation_evidence_wrapper_pair,
    storage_foundation::InstallationEvidencePersistencePaths,
};

mod authenticated_active_freshness_anchor;
mod database_key_current_user_dpapi;
mod freshness_anchor_current_user_dpapi;
mod freshness_anchor_observation;
mod generation_bound_database_key;
mod installation_bound_authenticated_active_freshness_anchor;
mod protected_blob_wrapper;
mod protected_key_payload;
mod trusted_current_installation_evidence_assessment;
mod trusted_current_installation_identity;
#[cfg(windows)]
mod windows_current_user_dpapi;

pub(crate) use authenticated_active_freshness_anchor::AuthenticatedActiveFreshnessAnchor;
#[allow(unused_imports)]
pub(crate) use database_key_current_user_dpapi::DatabaseKeyCandidateRecoveryError;
#[cfg(all(test, windows))]
pub(crate) use database_key_current_user_dpapi::protect_database_key_for_manual_startup_fixture;
#[cfg(windows)]
#[allow(unused_imports)]
pub(crate) use database_key_current_user_dpapi::recover_database_key_candidate_from_loaded_wrapper;
#[cfg(windows)]
pub(crate) use freshness_anchor_observation::observe_normalized_current_freshness_anchor;
#[allow(unused_imports)]
pub(crate) use generation_bound_database_key::{
    DatabaseKeyGenerationBindingError, GenerationBoundDatabaseKey,
    bind_database_key_candidate_to_trusted_installation_evidence,
};
pub(crate) use installation_bound_authenticated_active_freshness_anchor::InstallationBoundAuthenticatedActiveFreshnessAnchor;
pub(crate) use protected_blob_wrapper::EncodedProtectedWrapper;
use protected_blob_wrapper::{ProtectedObjectKind, ValidatedProtectedWrapper};
pub(crate) use protected_key_payload::DecodedProtectedKeyMaterial;
use protected_key_payload::EncodedProtectedKeyPayload;
pub(crate) use trusted_current_installation_evidence_assessment::TrustedCurrentInstallationEvidenceAssessment;
#[cfg(windows)]
pub(crate) use trusted_current_installation_evidence_assessment::load_trusted_current_installation_evidence_assessment;
pub(crate) use trusted_current_installation_identity::TrustedCurrentInstallationIdentity;
#[cfg(windows)]
use windows_current_user_dpapi::WindowsCurrentUserDpapi;

#[cfg(all(test, windows))]
pub(crate) fn protect_anchor_authentication_material_for_manual_startup_fixture(
    key: &crate::freshness_anchor_authentication_key::AnchorAuthenticationKey,
    generation_identifier: crate::freshness_anchor_authenticated_envelope::AnchorAuthenticationKeyGenerationIdentifier,
) -> Result<EncodedProtectedWrapper, ProtectionStageError> {
    freshness_anchor_current_user_dpapi::protect_anchor_authentication_material(
        key,
        generation_identifier,
    )
    .map_err(|_| ProtectionStageError::ProtectionUnavailable)
}

#[cfg(all(test, windows))]
pub(crate) fn protect_authenticated_freshness_anchor_for_manual_startup_fixture(
    envelope: &crate::freshness_anchor_authenticated_envelope::EncodedAuthenticatedFreshnessAnchorV1,
) -> Result<EncodedProtectedWrapper, ProtectionStageError> {
    freshness_anchor_current_user_dpapi::protect_authenticated_freshness_anchor(envelope)
        .map_err(|_| ProtectionStageError::ProtectionUnavailable)
}

const AUTHENTICATED_ENVELOPE_LENGTH: usize = 226;

pub(crate) enum FreshnessAnchorInstallationBindingError {
    InstallationIdentifierMismatch,
}

impl fmt::Debug for FreshnessAnchorInstallationBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InstallationIdentifierMismatch => {
                formatter.write_str("InstallationIdentifierMismatch")
            }
        }
    }
}

pub(crate) fn bind_authenticated_active_freshness_anchor_to_current_installation(
    authenticated_anchor: AuthenticatedActiveFreshnessAnchor,
    trusted_installation: &TrustedCurrentInstallationIdentity,
) -> Result<
    InstallationBoundAuthenticatedActiveFreshnessAnchor,
    FreshnessAnchorInstallationBindingError,
> {
    if authenticated_anchor.installation_identifier()
        == trusted_installation.installation_identifier()
    {
        Ok(
            InstallationBoundAuthenticatedActiveFreshnessAnchor::from_authenticated_anchor(
                authenticated_anchor,
            ),
        )
    } else {
        Err(FreshnessAnchorInstallationBindingError::InstallationIdentifierMismatch)
    }
}

pub(crate) struct SealedAssuredFreshnessAnchorHandoff {
    authenticated_anchor: AuthenticatedActiveFreshnessAnchor,
}

impl SealedAssuredFreshnessAnchorHandoff {
    const fn from_authenticated_anchor(
        authenticated_anchor: AuthenticatedActiveFreshnessAnchor,
    ) -> Self {
        Self {
            authenticated_anchor,
        }
    }

    pub(crate) fn complete_assured_construction(
        self,
        _token: AssuredFreshnessAnchorConstructionToken,
        construct: fn(FreshnessAnchorContractV1) -> AssuredFreshnessAnchor,
    ) -> AssuredFreshnessAnchor {
        construct(self.authenticated_anchor.into_contract())
    }
}

pub(crate) fn assure_installation_bound_authenticated_active_freshness_anchor(
    bound_anchor: InstallationBoundAuthenticatedActiveFreshnessAnchor,
) -> AssuredFreshnessAnchor {
    let authenticated_anchor = bound_anchor.into_authenticated_anchor();
    AssuredFreshnessAnchor::from_sealed_handoff(
        SealedAssuredFreshnessAnchorHandoff::from_authenticated_anchor(authenticated_anchor),
    )
}

#[cfg(test)]
pub(crate) use trusted_current_installation_evidence_assessment::trusted_current_installation_evidence_assessment_for_test;

#[cfg(test)]
pub(crate) fn synthetic_installation_bound_authenticated_active_freshness_anchor(
    contract: FreshnessAnchorContractV1,
) -> InstallationBoundAuthenticatedActiveFreshnessAnchor {
    let installation_identifier = contract.installation_identifier();
    let authenticated_anchor =
        AuthenticatedActiveFreshnessAnchor::from_authenticated_active_contract(contract);
    let trusted_installation =
        TrustedCurrentInstallationIdentity::from_validated_installation_identifier(
            installation_identifier,
        );

    bind_authenticated_active_freshness_anchor_to_current_installation(
        authenticated_anchor,
        &trusted_installation,
    )
    .expect("synthetic matching installation identifiers must bind")
}

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
    PlaintextParseFailed,
    StructuralValidationFailed,
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
            Self::PlaintextParseFailed => "PlaintextParseFailed",
            Self::StructuralValidationFailed => "StructuralValidationFailed",
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

struct UnprotectedBytes(
    Vec<u8>,
    #[cfg(test)] Option<std::rc::Rc<std::cell::Cell<bool>>>,
);

impl UnprotectedBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(
            bytes,
            #[cfg(test)]
            None,
        )
    }

    #[cfg(test)]
    fn new_with_clear_observer(
        bytes: Vec<u8>,
        cleared: std::rc::Rc<std::cell::Cell<bool>>,
    ) -> Self {
        Self(bytes, Some(cleared))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for UnprotectedBytes {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        if let Some(cleared) = &self.1 {
            cleared.set(self.0.iter().all(|byte| *byte == 0));
        }
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

/// Returns authenticated evidence first and the recovered key-generation
/// identifier second. Success establishes only exact envelope length, valid
/// envelope framing, and HMAC authentication with the decoded key.
fn authenticate_unprotected_installation_evidence(
    decoded_key_material: DecodedProtectedKeyMaterial,
    unprotected_authenticated_evidence: UnprotectedBytes,
) -> Result<
    (
        CryptographicallyAuthenticatedEnvelopeV1,
        EvidenceAuthenticationKeyGenerationIdentifier,
    ),
    ProtectionStageError,
> {
    let raw_envelope =
        RawUntrustedAuthenticatedEnvelopeV1::from_unprotected(&unprotected_authenticated_evidence)?;
    let parsed_envelope = raw_envelope.parse()?;
    let (authentication_key, recovered_generation_identifier) = decoded_key_material.into_parts();
    let authenticated_envelope =
        verify_authenticated_envelope_v1(parsed_envelope, &authentication_key)
            .map_err(|_| ProtectionStageError::AuthenticationFailed)?;

    Ok((authenticated_envelope, recovered_generation_identifier))
}

fn match_authenticated_installation_evidence_generation(
    authenticated_envelope: CryptographicallyAuthenticatedEnvelopeV1,
    recovered_generation_identifier: EvidenceAuthenticationKeyGenerationIdentifier,
) -> Result<GenerationMatchedAuthenticatedEnvelopeV1, ProtectionStageError> {
    authenticated_envelope
        .match_generation(&recovered_generation_identifier)
        .map_err(|_| ProtectionStageError::GenerationMismatch)
}

fn parse_generation_matched_installation_evidence_plaintext(
    matched_envelope: GenerationMatchedAuthenticatedEnvelopeV1,
) -> Result<ParsedUntrustedInstallationEvidenceContract, ProtectionStageError> {
    matched_envelope
        .parse_inner_plaintext()
        .map_err(|_| ProtectionStageError::PlaintextParseFailed)
}

fn validate_parsed_installation_evidence_structure(
    parsed: ParsedUntrustedInstallationEvidenceContract,
) -> Result<StructurallyValidatedInstallationEvidence, ProtectionStageError> {
    parsed
        .validate_structure()
        .map_err(|_| ProtectionStageError::StructuralValidationFailed)
}

#[cfg(windows)]
#[cfg_attr(test, allow(dead_code))]
fn recover_generation_matched_installation_evidence_from_wrappers(
    authentication_key_wrapper: ProtectedWrapperBytes,
    authenticated_evidence_wrapper: ProtectedWrapperBytes,
) -> Result<GenerationMatchedAuthenticatedEnvelopeV1, ProtectionStageError> {
    let (unprotected_authentication_key, unprotected_authenticated_evidence) =
        unprotect_active_installation_evidence_wrappers(
            authentication_key_wrapper,
            authenticated_evidence_wrapper,
        )?;
    let (decoded_authentication_key, unprotected_authenticated_evidence) =
        decode_unprotected_installation_evidence_key_material(
            unprotected_authentication_key,
            unprotected_authenticated_evidence,
        )?;
    let (authenticated_envelope, recovered_generation_identifier) =
        authenticate_unprotected_installation_evidence(
            decoded_authentication_key,
            unprotected_authenticated_evidence,
        )?;
    match_authenticated_installation_evidence_generation(
        authenticated_envelope,
        recovered_generation_identifier,
    )
}

#[cfg(windows)]
enum ActiveInstallationEvidenceRecoveryError {
    LoadFailed,
    ProtectionFailed,
}

#[cfg(windows)]
impl fmt::Debug for ActiveInstallationEvidenceRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LoadFailed => "ActiveEvidenceLoadFailed",
            Self::ProtectionFailed => "ActiveEvidenceProtectionFailed",
        })
    }
}

#[cfg(windows)]
#[allow(clippy::enum_variant_names)]
enum ActiveStructurallyValidatedEvidenceRecoveryError {
    LoadFailed,
    ProtectionFailed,
    PlaintextParseFailed,
    StructuralValidationFailed,
}

#[cfg(windows)]
impl fmt::Debug for ActiveStructurallyValidatedEvidenceRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LoadFailed => "ActiveEvidenceLoadFailed",
            Self::ProtectionFailed => "ActiveEvidenceProtectionFailed",
            Self::PlaintextParseFailed => "ActiveEvidencePlaintextParseFailed",
            Self::StructuralValidationFailed => "ActiveEvidenceStructuralValidationFailed",
        })
    }
}

#[cfg(windows)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum TrustedCurrentInstallationIdentityError {
    ActiveEvidenceLoadingUnavailable,
    EvidenceProtectionOrAuthenticationFailed,
    EvidencePlaintextParseFailed,
    EvidenceStructuralValidationFailed,
}

#[cfg(windows)]
impl fmt::Debug for TrustedCurrentInstallationIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ActiveEvidenceLoadingUnavailable => "ActiveEvidenceLoadingUnavailable",
            Self::EvidenceProtectionOrAuthenticationFailed => {
                "EvidenceProtectionOrAuthenticationFailed"
            }
            Self::EvidencePlaintextParseFailed => "EvidencePlaintextParseFailed",
            Self::EvidenceStructuralValidationFailed => "EvidenceStructuralValidationFailed",
        })
    }
}

#[cfg(windows)]
#[cfg_attr(test, allow(dead_code))]
fn load_and_recover_generation_matched_installation_evidence(
    paths: &InstallationEvidencePersistencePaths,
) -> Result<GenerationMatchedAuthenticatedEnvelopeV1, ActiveInstallationEvidenceRecoveryError> {
    let (authentication_key_wrapper, authenticated_evidence_wrapper) =
        load_active_installation_evidence_wrapper_pair(paths)
            .map_err(|_| ActiveInstallationEvidenceRecoveryError::LoadFailed)?;
    recover_generation_matched_installation_evidence_from_wrappers(
        authentication_key_wrapper,
        authenticated_evidence_wrapper,
    )
    .map_err(|_| ActiveInstallationEvidenceRecoveryError::ProtectionFailed)
}

#[cfg(windows)]
fn load_and_validate_active_installation_evidence(
    paths: &InstallationEvidencePersistencePaths,
) -> Result<
    StructurallyValidatedInstallationEvidence,
    ActiveStructurallyValidatedEvidenceRecoveryError,
> {
    let matched_envelope = load_and_recover_generation_matched_installation_evidence(paths)
        .map_err(|error| match error {
            ActiveInstallationEvidenceRecoveryError::LoadFailed => {
                ActiveStructurallyValidatedEvidenceRecoveryError::LoadFailed
            }
            ActiveInstallationEvidenceRecoveryError::ProtectionFailed => {
                ActiveStructurallyValidatedEvidenceRecoveryError::ProtectionFailed
            }
        })?;
    let parsed = parse_generation_matched_installation_evidence_plaintext(matched_envelope)
        .map_err(|error| match error {
            ProtectionStageError::PlaintextParseFailed => {
                ActiveStructurallyValidatedEvidenceRecoveryError::PlaintextParseFailed
            }
            // This narrow boundary currently emits only PlaintextParseFailed. Any
            // future broader protection-stage failure remains fail-closed.
            _ => ActiveStructurallyValidatedEvidenceRecoveryError::ProtectionFailed,
        })?;
    validate_parsed_installation_evidence_structure(parsed).map_err(|error| match error {
        ProtectionStageError::StructuralValidationFailed => {
            ActiveStructurallyValidatedEvidenceRecoveryError::StructuralValidationFailed
        }
        // This narrow boundary currently emits only StructuralValidationFailed.
        // Any future broader protection-stage failure remains fail-closed.
        _ => ActiveStructurallyValidatedEvidenceRecoveryError::ProtectionFailed,
    })
}

#[cfg(windows)]
pub(crate) fn load_trusted_current_installation_identity(
    paths: &InstallationEvidencePersistencePaths,
) -> Result<TrustedCurrentInstallationIdentity, TrustedCurrentInstallationIdentityError> {
    load_trusted_current_installation_evidence_assessment(paths)
        .map(TrustedCurrentInstallationEvidenceAssessment::into_trusted_identity)
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
    #[cfg(windows)]
    use std::{
        env, fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    use super::*;

    fn source_before_test_module(source: &str) -> &str {
        source
            .split_once("mod tests {")
            .expect("source must contain the test module boundary")
            .0
    }
    #[cfg(windows)]
    use crate::storage_foundation::{
        InstallationEvidencePersistencePaths, installation_evidence_persistence_paths,
    };
    use crate::{
        freshness_anchor_contract::FreshnessAnchorContractV1,
        installation_evidence_authenticated_envelope::construct_authenticated_envelope_v1,
        installation_evidence_contract::{
            ContractValidationError, DatabaseKeyGenerationIdentifier, EncodedInstallationEvidence,
            INSTALLATION_EVIDENCE_FORMAT_IDENTITY, InstallationEvidenceParseError,
            InstallationGeneration, InstallationIdentifier, PERMANENT_APPLICATION_IDENTIFIER,
            RecoveryOrReplacementGeneration, SUPPORTED_EVIDENCE_FORMAT_VERSION,
            SetupPublicationIdentifier, UnvalidatedInstallationEvidenceContract,
        },
        installation_evidence_persistence::read_bounded_protected_wrapper,
        storage_foundation::APPLICATION_DATABASE_FORMAT_IDENTITY,
    };

    const KEY: [u8; 32] = [0x5a; 32];
    const IDENTIFIER: [u8; 16] = [0xa5; 16];

    fn synthetic_freshness_anchor_binding_inputs(
        anchor_installation_identifier: [u8; 16],
        trusted_installation_identifier: [u8; 16],
    ) -> (
        AuthenticatedActiveFreshnessAnchor,
        TrustedCurrentInstallationIdentity,
    ) {
        let anchor_contract = FreshnessAnchorContractV1::new(
            InstallationIdentifier::from_bytes(anchor_installation_identifier).unwrap(),
            InstallationGeneration::new(7).unwrap(),
            RecoveryOrReplacementGeneration::new(9).unwrap(),
            DatabaseKeyGenerationIdentifier::from_bytes([0x42; 16]).unwrap(),
            SetupPublicationIdentifier::from_bytes([0x53; 16]).unwrap(),
        );
        let authenticated_anchor =
            AuthenticatedActiveFreshnessAnchor::from_authenticated_active_contract(anchor_contract);
        let trusted_installation =
            TrustedCurrentInstallationIdentity::from_validated_installation_identifier(
                InstallationIdentifier::from_bytes(trusted_installation_identifier).unwrap(),
            );
        (authenticated_anchor, trusted_installation)
    }

    #[test]
    fn bind_authenticated_active_freshness_anchor_to_current_installation_matches_typed_identity() {
        let (authenticated_anchor, trusted_installation) =
            synthetic_freshness_anchor_binding_inputs([0x31; 16], [0x31; 16]);
        let expected_identifier = authenticated_anchor.installation_identifier();
        let binding: fn(
            AuthenticatedActiveFreshnessAnchor,
            &TrustedCurrentInstallationIdentity,
        ) -> Result<
            InstallationBoundAuthenticatedActiveFreshnessAnchor,
            FreshnessAnchorInstallationBindingError,
        > = bind_authenticated_active_freshness_anchor_to_current_installation;

        let bound = binding(authenticated_anchor, &trusted_installation)
            .expect("matching typed installation identifiers must bind");
        assert_eq!(
            trusted_installation.installation_identifier(),
            expected_identifier,
            "the trusted proof remains borrowed and available"
        );
        let recovered_authenticated_anchor = bound.into_authenticated_anchor();
        assert_eq!(
            recovered_authenticated_anchor.installation_identifier(),
            expected_identifier,
            "the bound proof must preserve ownership of the authenticated proof"
        );
    }

    #[test]
    fn bind_authenticated_active_freshness_anchor_to_current_installation_mismatch_fails_closed() {
        let (authenticated_anchor, trusted_installation) =
            synthetic_freshness_anchor_binding_inputs([0x31; 16], [0x32; 16]);

        let error = bind_authenticated_active_freshness_anchor_to_current_installation(
            authenticated_anchor,
            &trusted_installation,
        )
        .expect_err("different typed installation identifiers must not bind");

        assert!(matches!(
            error,
            FreshnessAnchorInstallationBindingError::InstallationIdentifierMismatch
        ));
        assert_eq!(format!("{error:?}"), "InstallationIdentifierMismatch");
        assert!(!format!("{error:?}").contains("31"));
        assert!(!format!("{error:?}").contains("32"));
    }

    #[test]
    fn bind_authenticated_active_freshness_anchor_boundary_is_pure_strong_and_narrow() {
        const SOURCE: &str = include_str!("mod.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let marker =
            "pub(crate) fn bind_authenticated_active_freshness_anchor_to_current_installation(";
        assert_eq!(production.matches(marker).count(), 1);
        let boundary = production
            .split_once(marker)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;

        assert!(boundary.contains(
            "authenticated_anchor: AuthenticatedActiveFreshnessAnchor,\n    trusted_installation: &TrustedCurrentInstallationIdentity,"
        ));
        assert!(boundary.contains(
            ") -> Result<\n    InstallationBoundAuthenticatedActiveFreshnessAnchor,\n    FreshnessAnchorInstallationBindingError,\n>"
        ));
        assert_eq!(
            boundary
                .matches("authenticated_anchor.installation_identifier()")
                .count(),
            1
        );
        assert_eq!(
            boundary
                .matches("trusted_installation.installation_identifier()")
                .count(),
            1
        );
        assert!(boundary.contains(
            "authenticated_anchor.installation_identifier()\n        == trusted_installation.installation_identifier()"
        ));
        assert!(boundary.contains(
            "InstallationBoundAuthenticatedActiveFreshnessAnchor::from_authenticated_anchor(\n                authenticated_anchor,"
        ));
        assert!(boundary.contains(
            "Err(FreshnessAnchorInstallationBindingError::InstallationIdentifierMismatch)"
        ));

        for excluded in [
            "FreshnessAnchorContractV1",
            "InstallationIdentifier,",
            "StructurallyValidatedInstallationEvidence",
            "bool",
            "AssuredFreshnessAnchor",
            "NormalizedFreshnessAnchorObservation",
            "classify_database_freshness",
            "Present",
            "write_bytes_into",
            "as_bytes",
            "database",
            "filesystem",
            "DPAPI",
            "HMAC",
            "parse",
            "publication",
            "startup",
            "recovery",
            "replacement",
        ] {
            assert!(
                !boundary.contains(excluded),
                "binding boundary unexpectedly contains out-of-scope surface: {excluded}"
            );
        }
    }

    #[test]
    fn assured_contract_ownership_boundary_returns_only_the_assured_type() {
        const SOURCE: &str = include_str!("mod.rs");
        const ASSURANCE_SOURCE: &str = include_str!("../database_freshness_classification.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let assurance_production = ASSURANCE_SOURCE.split("#[cfg(test)]").next().unwrap();
        let marker =
            "pub(crate) fn assure_installation_bound_authenticated_active_freshness_anchor(";
        let transition = production
            .split_once(marker)
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let handoff_body = production
            .split_once("pub(crate) struct SealedAssuredFreshnessAnchorHandoff {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let completion = production
            .split_once("    pub(crate) fn complete_assured_construction(")
            .unwrap()
            .1
            .split_once("\n    }")
            .unwrap()
            .0;
        let token_body = assurance_production
            .split_once("pub(crate) struct AssuredFreshnessAnchorConstructionToken {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;

        assert_eq!(production.matches(marker).count(), 1);
        assert_eq!(
            handoff_body,
            "\n    authenticated_anchor: AuthenticatedActiveFreshnessAnchor,"
        );
        assert!(!handoff_body.contains("pub"));
        assert_eq!(token_body, "\n    _private: (),");
        assert!(!token_body.contains("pub"));
        assert!(production.contains("    const fn from_authenticated_anchor("));
        assert!(!production.contains("pub(crate) const fn from_authenticated_anchor("));
        assert!(completion.contains("_token: AssuredFreshnessAnchorConstructionToken,"));
        assert!(completion.contains(") -> AssuredFreshnessAnchor {"));
        assert!(completion.contains("construct(self.authenticated_anchor.into_contract())"));
        assert!(!completion.contains("clone"));
        assert!(
            transition
                .contains("bound_anchor: InstallationBoundAuthenticatedActiveFreshnessAnchor,")
        );
        assert!(transition.contains(") -> AssuredFreshnessAnchor {"));
        assert!(
            transition
                .contains("let authenticated_anchor = bound_anchor.into_authenticated_anchor();")
        );
        assert!(transition.contains("AssuredFreshnessAnchor::from_sealed_handoff("));
        assert_eq!(transition.matches("into_authenticated_anchor()").count(), 1);
        assert_eq!(transition.matches("into_contract()").count(), 0);
        assert_eq!(completion.matches("into_contract()").count(), 1);
        assert_eq!(
            assurance_production
                .matches("pub(crate) fn from_sealed_handoff(")
                .count(),
            1
        );
        assert!(
            !production
                .contains("pub(crate) const fn into_contract(self) -> FreshnessAnchorContractV1")
        );
        assert!(
            !production.contains("pub(crate) fn into_contract(self) -> FreshnessAnchorContractV1")
        );
        assert!(!production.contains(
            ") -> FreshnessAnchorContractV1 {\n    bound_anchor.into_authenticated_anchor()"
        ));

        for source in [production, assurance_production] {
            let lines: Vec<_> = source.lines().collect();
            for start in 0..lines.len() {
                if lines[start].contains("pub(crate)") && lines[start].contains("fn ") {
                    let signature = lines[start..]
                        .iter()
                        .take_while(|line| !line.contains('{'))
                        .copied()
                        .chain(
                            lines[start..]
                                .iter()
                                .find(|line| line.contains('{'))
                                .copied(),
                        )
                        .collect::<Vec<_>>()
                        .join("\n");
                    assert!(
                        !signature.contains("-> FreshnessAnchorContractV1"),
                        "crate-visible production function unexpectedly returns a plain contract"
                    );
                }
            }
        }

        for excluded in [
            "installation_identifier()",
            "==",
            "clone",
            "filesystem",
            "DPAPI",
            "HMAC",
            "parse",
            "database",
            "NormalizedFreshnessAnchorObservation",
            "classify_database_freshness",
            "publication",
            "startup",
            "recovery",
            "replacement",
        ] {
            assert!(
                !transition.contains(excluded),
                "ownership transition unexpectedly contains out-of-scope behavior: {excluded}"
            );
        }
    }

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

    fn matched_envelope_with_inner_plaintext(
        inner_plaintext: [u8; 164],
    ) -> GenerationMatchedAuthenticatedEnvelopeV1 {
        let key_wrapper = dummy_wrapper(ProtectedObjectKind::AuthenticationKey);
        let evidence_wrapper = dummy_wrapper(ProtectedObjectKind::AuthenticatedEvidence);
        let mut envelope_bytes = *encoded_envelope(KEY, IDENTIFIER).as_bytes();
        envelope_bytes[30..194].copy_from_slice(&inner_plaintext);
        let mut hmac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        hmac.update(&envelope_bytes[..194]);
        envelope_bytes[194..226].copy_from_slice(&hmac.finalize().into_bytes());
        let fake = FakeProtector::with_unprotected([
            key_payload(KEY, IDENTIFIER),
            envelope_bytes.to_vec(),
        ]);

        recover_and_authenticate_in_memory_with(
            &fake,
            key_wrapper.as_bytes(),
            evidence_wrapper.as_bytes(),
        )
        .expect("retagged test-owned plaintext must authenticate and generation-match")
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
    fn authenticated_evidence_hmac_boundary_returns_authenticated_envelope_then_identifier() {
        let decoded_key_material =
            DecodedProtectedKeyMaterial::parse(&key_payload(KEY, IDENTIFIER)).unwrap();
        let unprotected_authenticated_evidence =
            UnprotectedBytes::new(encoded_envelope(KEY, IDENTIFIER).as_bytes().to_vec());

        let (authenticated_envelope, recovered_generation_identifier) =
            authenticate_unprotected_installation_evidence(
                decoded_key_material,
                unprotected_authenticated_evidence,
            )
            .expect("canonical evidence authenticated by the decoded key must succeed");

        fn require_authenticated_envelope(_: &CryptographicallyAuthenticatedEnvelopeV1) {}
        fn require_generation_identifier(_: &EvidenceAuthenticationKeyGenerationIdentifier) {}
        require_authenticated_envelope(&authenticated_envelope);
        require_generation_identifier(&recovered_generation_identifier);
        assert!(recovered_generation_identifier.matches(&identifier(IDENTIFIER)));
        assert_eq!(
            format!("{authenticated_envelope:?}"),
            "CryptographicallyAuthenticatedEnvelopeV1([REDACTED])"
        );
        assert_eq!(
            format!("{recovered_generation_identifier:?}"),
            "EvidenceAuthenticationKeyGenerationIdentifier([REDACTED])"
        );
    }

    #[test]
    fn authenticated_evidence_hmac_boundary_rejects_wrong_lengths_and_malformed_framing() {
        for evidence in [vec![0x31; 225], vec![0x42; 227]] {
            let result = authenticate_unprotected_installation_evidence(
                DecodedProtectedKeyMaterial::parse(&key_payload(KEY, IDENTIFIER)).unwrap(),
                UnprotectedBytes::new(evidence),
            );
            assert_eq!(
                result.expect_err("wrong evidence length must return no output tuple"),
                ProtectionStageError::WrapperParseFailed
            );
        }

        let mut malformed = *encoded_envelope(KEY, IDENTIFIER).as_bytes();
        malformed[0] ^= 1;
        let result = authenticate_unprotected_installation_evidence(
            DecodedProtectedKeyMaterial::parse(&key_payload(KEY, IDENTIFIER)).unwrap(),
            UnprotectedBytes::new(malformed.to_vec()),
        );
        assert_eq!(
            result.expect_err("malformed framing must return no output tuple"),
            ProtectionStageError::AuthenticationFailed
        );
    }

    #[test]
    fn authenticated_evidence_hmac_boundary_rejects_wrong_key_and_corrupted_authenticated_bytes() {
        let envelope = encoded_envelope(KEY, IDENTIFIER);
        let wrong_key_result = authenticate_unprotected_installation_evidence(
            DecodedProtectedKeyMaterial::parse(&key_payload([0x44; 32], IDENTIFIER)).unwrap(),
            UnprotectedBytes::new(envelope.as_bytes().to_vec()),
        );
        assert_eq!(
            wrong_key_result.expect_err("wrong HMAC key must return no output tuple"),
            ProtectionStageError::AuthenticationFailed
        );

        let mut corrupted = *envelope.as_bytes();
        corrupted[30] ^= 1;
        let corrupted_result = authenticate_unprotected_installation_evidence(
            DecodedProtectedKeyMaterial::parse(&key_payload(KEY, IDENTIFIER)).unwrap(),
            UnprotectedBytes::new(corrupted.to_vec()),
        );
        assert_eq!(
            corrupted_result
                .expect_err("corrupted authenticated bytes must return no output tuple"),
            ProtectionStageError::AuthenticationFailed
        );
    }

    #[test]
    fn authenticated_evidence_hmac_boundary_defers_generation_match_and_plaintext_parse() {
        const DIFFERENT_IDENTIFIER: [u8; 16] = [0x77; 16];
        let result = authenticate_unprotected_installation_evidence(
            DecodedProtectedKeyMaterial::parse(&key_payload(KEY, DIFFERENT_IDENTIFIER)).unwrap(),
            UnprotectedBytes::new(encoded_envelope(KEY, IDENTIFIER).as_bytes().to_vec()),
        )
        .expect("a valid HMAC must succeed before separately scoped generation matching");
        assert!(result.1.matches(&identifier(DIFFERENT_IDENTIFIER)));

        const SOURCE: &str = include_str!("mod.rs");
        let definition_marker = "fn authenticate_unprotected_installation_evidence(";
        let production_source = source_before_test_module(SOURCE);
        assert_eq!(production_source.matches(definition_marker).count(), 1);
        let before_definition = production_source.split_once(definition_marker).unwrap().0;
        let declaration_attributes = before_definition.rsplit_once("\n\n").unwrap().1;
        assert!(!declaration_attributes.contains("#[cfg(test)]"));
        assert!(!declaration_attributes.contains("pub"));

        let boundary = production_source
            .split_once(definition_marker)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(boundary.contains("decoded_key_material: DecodedProtectedKeyMaterial"));
        assert!(boundary.contains("unprotected_authenticated_evidence: UnprotectedBytes"));
        assert!(boundary.contains("RawUntrustedAuthenticatedEnvelopeV1::from_unprotected"));
        assert!(boundary.contains("raw_envelope.parse()"));
        assert!(boundary.contains("decoded_key_material.into_parts()"));
        assert!(boundary.contains("verify_authenticated_envelope_v1"));
        assert!(boundary.contains("CryptographicallyAuthenticatedEnvelopeV1"));
        assert!(boundary.contains("EvidenceAuthenticationKeyGenerationIdentifier"));
        assert!(!boundary.contains("match_generation"));
        assert!(!boundary.contains("parse_inner_plaintext"));
        assert!(!boundary.contains("as_bytes()"));
        assert!(!boundary.contains("Vec<u8>"));
        assert_eq!(production_source.matches(definition_marker).count(), 1);

        let secure_unprotected_drop = SOURCE
            .split_once("impl Drop for UnprotectedBytes")
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(secure_unprotected_drop.contains("self.0.zeroize();"));
        let secure_raw_drop = SOURCE
            .split_once("impl Drop for RawUntrustedAuthenticatedEnvelopeV1")
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(secure_raw_drop.contains("self.bytes.zeroize();"));
    }

    #[test]
    fn generation_matched_evidence_boundary_returns_exact_existing_type_for_matching_identifiers() {
        let (authenticated_envelope, recovered_generation_identifier) =
            authenticate_unprotected_installation_evidence(
                DecodedProtectedKeyMaterial::parse(&key_payload(KEY, IDENTIFIER)).unwrap(),
                UnprotectedBytes::new(encoded_envelope(KEY, IDENTIFIER).as_bytes().to_vec()),
            )
            .expect("canonical synthetic evidence must authenticate");

        let matched = match_authenticated_installation_evidence_generation(
            authenticated_envelope,
            recovered_generation_identifier,
        )
        .expect("matching generation identifiers must succeed");

        fn require_exact_result_type(_: &GenerationMatchedAuthenticatedEnvelopeV1) {}
        require_exact_result_type(&matched);
        assert_eq!(
            format!("{matched:?}"),
            "GenerationMatchedAuthenticatedEnvelopeV1([REDACTED])"
        );
    }

    #[test]
    fn generation_matched_evidence_boundary_returns_only_coarse_mismatch_error() {
        const DIFFERENT_IDENTIFIER: [u8; 16] = [0x77; 16];
        let (authenticated_envelope, recovered_generation_identifier) =
            authenticate_unprotected_installation_evidence(
                DecodedProtectedKeyMaterial::parse(&key_payload(KEY, DIFFERENT_IDENTIFIER))
                    .unwrap(),
                UnprotectedBytes::new(encoded_envelope(KEY, IDENTIFIER).as_bytes().to_vec()),
            )
            .expect("generation matching must remain separate from HMAC authentication");

        let error = match_authenticated_installation_evidence_generation(
            authenticated_envelope,
            recovered_generation_identifier,
        )
        .expect_err("different valid nonzero identifiers must return no matched evidence");

        assert_eq!(error, ProtectionStageError::GenerationMismatch);
        assert_eq!(format!("{error:?}"), "GenerationMismatch");
    }

    #[test]
    fn generation_matched_evidence_boundary_source_proves_private_narrow_transition() {
        const SOURCE: &str = include_str!("mod.rs");
        let production_source = source_before_test_module(SOURCE);
        let definition_marker = "fn match_authenticated_installation_evidence_generation(";
        assert_eq!(production_source.matches(definition_marker).count(), 1);
        assert_eq!(
            production_source
                .matches("match_authenticated_installation_evidence_generation(")
                .count(),
            2
        );

        let before_definition = production_source.split_once(definition_marker).unwrap().0;
        let declaration_attributes = before_definition.rsplit_once("\n\n").unwrap().1;
        assert!(!declaration_attributes.contains("cfg"));
        assert!(!declaration_attributes.contains("pub"));

        let boundary = production_source
            .split_once(definition_marker)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(
            boundary.contains("authenticated_envelope: CryptographicallyAuthenticatedEnvelopeV1")
        );
        assert!(boundary.contains(
            "recovered_generation_identifier: EvidenceAuthenticationKeyGenerationIdentifier"
        ));
        assert!(
            boundary
                .contains("Result<GenerationMatchedAuthenticatedEnvelopeV1, ProtectionStageError>")
        );
        assert_eq!(boundary.matches(".match_generation(").count(), 1);
        assert!(boundary.contains(".match_generation(&recovered_generation_identifier)"));
        assert!(boundary.contains(".map_err(|_| ProtectionStageError::GenerationMismatch)"));

        for excluded in [
            "Ok((",
            "matches(",
            "from_bytes",
            "write_bytes_into",
            "as_bytes",
            "parse",
            "verify_authenticated_envelope_v1",
            "DecodedProtectedKeyMaterial",
            "UnprotectedBytes",
            "ProtectedWrapper",
            "Dpapi",
            "rusqlite",
            "setup",
            "startup",
            "tauri",
            "unsafe",
        ] {
            assert!(!boundary.contains(excluded));
        }
        assert!(!boundary.contains(&["std", "::fs"].concat()));
        assert!(!boundary.contains(&["installation", "_state"].concat()));
    }

    #[test]
    fn protected_wrapper_trust_chain_orchestration_source_proves_exact_private_windows_composition()
    {
        const SOURCE: &str = include_str!("mod.rs");
        let production_source = source_before_test_module(SOURCE);
        let definition_marker =
            "fn recover_generation_matched_installation_evidence_from_wrappers(";
        assert_eq!(production_source.matches(definition_marker).count(), 1);
        assert_eq!(
            production_source
                .matches("recover_generation_matched_installation_evidence_from_wrappers(")
                .count(),
            2
        );

        let before_definition = production_source.split_once(definition_marker).unwrap().0;
        let declaration_attributes = before_definition.rsplit_once("\n\n").unwrap().1;
        assert!(declaration_attributes.contains("#[cfg(windows)]"));
        assert!(declaration_attributes.contains("#[cfg_attr(test, allow(dead_code))]"));
        assert!(!declaration_attributes.contains("pub"));

        let boundary = production_source
            .split_once(definition_marker)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(boundary.contains("authentication_key_wrapper: ProtectedWrapperBytes"));
        assert!(boundary.contains("authenticated_evidence_wrapper: ProtectedWrapperBytes"));
        assert!(
            boundary
                .contains("Result<GenerationMatchedAuthenticatedEnvelopeV1, ProtectionStageError>")
        );

        let stages = [
            "unprotect_active_installation_evidence_wrappers(",
            "decode_unprotected_installation_evidence_key_material(",
            "authenticate_unprotected_installation_evidence(",
            "match_authenticated_installation_evidence_generation(",
        ];
        let positions = stages.map(|stage| {
            assert_eq!(boundary.matches(stage).count(), 1);
            boundary.find(stage).unwrap()
        });
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));

        for excluded in [
            "ValidatedProtectedWrapper::parse",
            "WindowsCurrentUserDpapi",
            "DecodedProtectedKeyMaterial::parse",
            "RawUntrustedAuthenticatedEnvelopeV1::from_unprotected",
            "verify_authenticated_envelope_v1",
            ".match_generation",
            "recover_and_authenticate_in_memory",
            "recover_and_authenticate_in_memory_with",
            "parse_inner_plaintext",
            "setup",
            "startup",
            "unsafe",
        ] {
            assert!(!boundary.contains(excluded));
        }
        assert!(!boundary.contains(&["std", "::fs"].concat()));
        assert!(!boundary.contains(&["rusqlite", "::"].concat()));
        assert!(!boundary.contains(&["installation", "_state"].concat()));
        assert!(!boundary.contains(&["tauri", "::command"].concat()));

        let secure_unprotected_drop = SOURCE
            .split_once("impl Drop for UnprotectedBytes")
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(secure_unprotected_drop.contains("self.0.zeroize();"));
        assert_eq!(
            format!("{:?}", ProtectionStageError::AuthenticationFailed),
            "AuthenticationFailed"
        );
    }

    #[cfg(windows)]
    fn protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
        kind: ProtectedObjectKind,
        plaintext: &[u8],
    ) -> ProtectedWrapperBytes {
        let protected = WindowsCurrentUserDpapi
            .protect(plaintext)
            .expect("synthetic test plaintext must be protectable for the current user");
        let wrapper = EncodedProtectedWrapper::encode(kind, protected)
            .expect("synthetic DPAPI output must fit the canonical wrapper");
        owned_wrapper_bytes(wrapper.as_bytes())
    }

    #[cfg(windows)]
    struct ActiveEvidenceLoadTrustChainCompositionTestRoot {
        root: PathBuf,
        paths: InstallationEvidencePersistencePaths,
    }

    #[cfg(windows)]
    impl ActiveEvidenceLoadTrustChainCompositionTestRoot {
        fn create(
            authentication_key_wrapper: &[u8],
            authenticated_evidence_wrapper: &[u8],
        ) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock must follow epoch")
                .as_nanos();
            let root = env::temp_dir().join(format!(
                "church-app-active-load-trust-chain-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("unique composition root must be new");
            let paths = installation_evidence_persistence_paths(&root);
            fs::create_dir(paths.evidence_directory.as_path())
                .expect("exact synthetic evidence directory must be created");
            fs::write(
                paths.active_authentication_key.as_path(),
                authentication_key_wrapper,
            )
            .expect("synthetic active authentication-key wrapper must be written");
            fs::write(
                paths.active_authenticated_evidence.as_path(),
                authenticated_evidence_wrapper,
            )
            .expect("synthetic active authenticated-evidence wrapper must be written");
            let fixture = Self { root, paths };
            fixture.assert_canonical_active_state();
            fixture
        }

        fn assert_no_stage_artifacts(&self) {
            assert!(!self.paths.staged_authentication_key.as_path().exists());
            assert!(!self.paths.staged_authenticated_evidence.as_path().exists());
        }

        fn assert_canonical_active_state(&self) {
            self.assert_no_stage_artifacts();

            let mut actual_children = fs::read_dir(self.paths.evidence_directory.as_path())
                .expect("canonical evidence directory must remain enumerable")
                .map(|entry| {
                    entry
                        .expect("canonical child must remain inspectable")
                        .path()
                })
                .collect::<Vec<_>>();
            actual_children.sort();
            let mut expected_children = vec![
                self.paths.active_authentication_key.as_path().to_path_buf(),
                self.paths
                    .active_authenticated_evidence
                    .as_path()
                    .to_path_buf(),
            ];
            expected_children.sort();
            assert_eq!(actual_children, expected_children);
        }
    }

    #[cfg(windows)]
    impl Drop for ActiveEvidenceLoadTrustChainCompositionTestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(windows)]
    fn active_evidence_load_trust_chain_composition_fixture(
        key: [u8; 32],
        key_identifier: [u8; 16],
        envelope_identifier: [u8; 16],
    ) -> ActiveEvidenceLoadTrustChainCompositionTestRoot {
        let authentication_key_wrapper = protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
            ProtectedObjectKind::AuthenticationKey,
            &key_payload(key, key_identifier),
        );
        let envelope = encoded_envelope(KEY, envelope_identifier);
        let authenticated_evidence_wrapper =
            protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
                ProtectedObjectKind::AuthenticatedEvidence,
                envelope.as_bytes(),
            );
        ActiveEvidenceLoadTrustChainCompositionTestRoot::create(
            authentication_key_wrapper.as_bytes(),
            authenticated_evidence_wrapper.as_bytes(),
        )
    }

    #[cfg(windows)]
    fn structurally_validated_active_evidence_composition_fixture(
        key: [u8; 32],
        key_identifier: [u8; 16],
        envelope_identifier: [u8; 16],
        inner_plaintext: [u8; 164],
    ) -> ActiveEvidenceLoadTrustChainCompositionTestRoot {
        let authentication_key_wrapper = protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
            ProtectedObjectKind::AuthenticationKey,
            &key_payload(key, key_identifier),
        );
        let mut envelope_bytes = *encoded_envelope(KEY, envelope_identifier).as_bytes();
        envelope_bytes[30..194].copy_from_slice(&inner_plaintext);
        let mut hmac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        hmac.update(&envelope_bytes[..194]);
        envelope_bytes[194..226].copy_from_slice(&hmac.finalize().into_bytes());
        let authenticated_evidence_wrapper =
            protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
                ProtectedObjectKind::AuthenticatedEvidence,
                &envelope_bytes,
            );
        ActiveEvidenceLoadTrustChainCompositionTestRoot::create(
            authentication_key_wrapper.as_bytes(),
            authenticated_evidence_wrapper.as_bytes(),
        )
    }

    #[cfg(windows)]
    #[test]
    fn structurally_validated_active_evidence_composition_returns_exact_existing_type() {
        let canonical_plaintext = *plaintext().as_bytes();
        let expected = ParsedUntrustedInstallationEvidenceContract::parse_v1(&canonical_plaintext)
            .unwrap()
            .validate_structure()
            .unwrap();
        let fixture = structurally_validated_active_evidence_composition_fixture(
            KEY,
            IDENTIFIER,
            IDENTIFIER,
            canonical_plaintext,
        );

        let validated = load_and_validate_active_installation_evidence(&fixture.paths)
            .expect("canonical active evidence must reach structural validation");

        fn require_exact_result_type(_: StructurallyValidatedInstallationEvidence) {}
        require_exact_result_type(validated);
        assert_eq!(validated, expected);
        assert_eq!(validated.encode_v1().as_bytes(), &canonical_plaintext);
        fixture.assert_canonical_active_state();
    }

    #[cfg(windows)]
    #[test]
    fn structurally_validated_active_evidence_composition_preserves_load_and_protection_failures() {
        let incomplete = structurally_validated_active_evidence_composition_fixture(
            KEY,
            IDENTIFIER,
            IDENTIFIER,
            *plaintext().as_bytes(),
        );
        fs::remove_file(incomplete.paths.active_authenticated_evidence.as_path()).unwrap();
        let load_error = load_and_validate_active_installation_evidence(&incomplete.paths)
            .expect_err("incomplete active wrappers must return no validated evidence");
        assert!(matches!(
            load_error,
            ActiveStructurallyValidatedEvidenceRecoveryError::LoadFailed
        ));
        incomplete.assert_no_stage_artifacts();

        let wrong_hmac = structurally_validated_active_evidence_composition_fixture(
            [0x44; 32],
            IDENTIFIER,
            IDENTIFIER,
            *plaintext().as_bytes(),
        );
        let hmac_error = load_and_validate_active_installation_evidence(&wrong_hmac.paths)
            .expect_err("wrong HMAC must return no validated evidence");
        assert!(matches!(
            hmac_error,
            ActiveStructurallyValidatedEvidenceRecoveryError::ProtectionFailed
        ));
        wrong_hmac.assert_canonical_active_state();

        let generation_mismatch = structurally_validated_active_evidence_composition_fixture(
            KEY,
            [0x77; 16],
            IDENTIFIER,
            *plaintext().as_bytes(),
        );
        let generation_error =
            load_and_validate_active_installation_evidence(&generation_mismatch.paths)
                .expect_err("generation mismatch must return no validated evidence");
        assert!(matches!(
            generation_error,
            ActiveStructurallyValidatedEvidenceRecoveryError::ProtectionFailed
        ));
        generation_mismatch.assert_canonical_active_state();
    }

    #[cfg(windows)]
    #[test]
    fn structurally_validated_active_evidence_composition_preserves_plaintext_parse_failures() {
        for (case, offset, replacement) in [
            ("wrong inner magic", 0, 0),
            ("unsupported inner version", 9, 2),
        ] {
            let mut malformed_plaintext = *plaintext().as_bytes();
            malformed_plaintext[offset] = replacement;
            let fixture = structurally_validated_active_evidence_composition_fixture(
                KEY,
                IDENTIFIER,
                IDENTIFIER,
                malformed_plaintext,
            );

            let error =
                load_and_validate_active_installation_evidence(&fixture.paths).expect_err(case);

            assert!(
                matches!(
                    &error,
                    ActiveStructurallyValidatedEvidenceRecoveryError::PlaintextParseFailed
                ),
                "expected coarse plaintext-parse failure, got {error:?}"
            );
            fixture.assert_canonical_active_state();
        }
    }

    #[cfg(windows)]
    #[test]
    fn structurally_validated_active_evidence_composition_preserves_structural_failures() {
        for (case, start, end, replacement) in [
            ("wrong evidence-format identity", 12, 28, 0),
            ("wrong permanent application identifier", 31, 60, b'x'),
        ] {
            let mut structurally_invalid_plaintext = *plaintext().as_bytes();
            structurally_invalid_plaintext[start..end].fill(replacement);
            ParsedUntrustedInstallationEvidenceContract::parse_v1(&structurally_invalid_plaintext)
                .expect("structural fixture must remain parseable");
            let fixture = structurally_validated_active_evidence_composition_fixture(
                KEY,
                IDENTIFIER,
                IDENTIFIER,
                structurally_invalid_plaintext,
            );

            let error =
                load_and_validate_active_installation_evidence(&fixture.paths).expect_err(case);

            assert!(
                matches!(
                    &error,
                    ActiveStructurallyValidatedEvidenceRecoveryError::StructuralValidationFailed
                ),
                "expected coarse structural-validation failure, got {error:?}"
            );
            fixture.assert_canonical_active_state();
        }
    }

    #[cfg(windows)]
    #[test]
    fn structurally_validated_active_evidence_composition_error_debug_is_coarse_and_redacted() {
        for (error, expected) in [
            (
                ActiveStructurallyValidatedEvidenceRecoveryError::LoadFailed,
                "ActiveEvidenceLoadFailed",
            ),
            (
                ActiveStructurallyValidatedEvidenceRecoveryError::ProtectionFailed,
                "ActiveEvidenceProtectionFailed",
            ),
            (
                ActiveStructurallyValidatedEvidenceRecoveryError::PlaintextParseFailed,
                "ActiveEvidencePlaintextParseFailed",
            ),
            (
                ActiveStructurallyValidatedEvidenceRecoveryError::StructuralValidationFailed,
                "ActiveEvidenceStructuralValidationFailed",
            ),
        ] {
            let debug = format!("{error:?}");
            assert_eq!(debug, expected);
            for forbidden in ["path", "CHDPAPI", "CHEVAUTH", "[0,", "native"] {
                assert!(!debug.contains(forbidden));
            }
        }
    }

    #[test]
    fn structurally_validated_active_evidence_composition_source_proves_private_narrow_boundary() {
        const SOURCE: &str = include_str!("mod.rs");
        const ASSESSMENT_SOURCE: &str =
            include_str!("trusted_current_installation_evidence_assessment.rs");
        let production_source = SOURCE.split("\n#[cfg(test)]\nmod tests {").next().unwrap();
        let assessment_production = ASSESSMENT_SOURCE.split("#[cfg(test)]").next().unwrap();
        let error_marker = "enum ActiveStructurallyValidatedEvidenceRecoveryError {";
        assert_eq!(production_source.matches(error_marker).count(), 1);
        let error_body = production_source
            .split_once(error_marker)
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(error_body.matches("Failed,").count(), 4);
        for variant in [
            "LoadFailed,",
            "ProtectionFailed,",
            "PlaintextParseFailed,",
            "StructuralValidationFailed,",
        ] {
            assert!(error_body.contains(variant));
        }
        assert!(!error_body.contains('('));

        let definition_marker = "fn load_and_validate_active_installation_evidence(";
        assert_eq!(production_source.matches(definition_marker).count(), 1);
        assert_eq!(
            production_source
                .matches("load_and_validate_active_installation_evidence(")
                .count(),
            1
        );
        assert_eq!(
            assessment_production
                .matches("load_and_validate_active_installation_evidence(paths)")
                .count(),
            1
        );
        let before_definition = production_source.split_once(definition_marker).unwrap().0;
        let declaration_attributes = before_definition.rsplit_once("\n\n").unwrap().1;
        assert!(declaration_attributes.contains("#[cfg(windows)]"));
        assert!(!declaration_attributes.contains("pub"));

        let boundary = production_source
            .split_once(definition_marker)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(boundary.contains("paths: &InstallationEvidencePersistencePaths"));
        assert!(boundary.contains("StructurallyValidatedInstallationEvidence"));
        assert!(boundary.contains("ActiveStructurallyValidatedEvidenceRecoveryError"));
        let stages = [
            "load_and_recover_generation_matched_installation_evidence(",
            "parse_generation_matched_installation_evidence_plaintext(",
            "validate_parsed_installation_evidence_structure(",
        ];
        let positions = stages.map(|stage| {
            assert_eq!(boundary.matches(stage).count(), 1);
            boundary.find(stage).unwrap()
        });
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));

        for excluded in [
            "load_active_installation_evidence_wrapper_pair",
            "recover_generation_matched_installation_evidence_from_wrappers",
            "WindowsCurrentUserDpapi",
            "ValidatedProtectedWrapper::parse",
            "verify_authenticated_envelope_v1",
            "parse_inner_plaintext",
            "parse_v1",
            "validate_structure",
            "rusqlite",
            "database",
            "freshness",
            "rollback",
            "setup",
            "startup",
            "tauri",
            "unsafe",
            "retry",
            "fallback",
            "repair",
            "replace",
            "cleanup",
        ] {
            assert!(!boundary.contains(excluded), "unexpected term: {excluded}");
        }
        assert!(!boundary.contains(&["std", "::fs"].concat()));
        assert!(!boundary.contains(&["installation", "_state"].concat()));
    }

    #[cfg(windows)]
    #[test]
    fn load_trusted_current_installation_evidence_assessment_returns_both_same_load_outputs() {
        let canonical_plaintext = *plaintext().as_bytes();
        let expected = ParsedUntrustedInstallationEvidenceContract::parse_v1(&canonical_plaintext)
            .unwrap()
            .validate_structure()
            .unwrap();
        let fixture = structurally_validated_active_evidence_composition_fixture(
            KEY,
            IDENTIFIER,
            IDENTIFIER,
            canonical_plaintext,
        );

        let assessment = load_trusted_current_installation_evidence_assessment(&fixture.paths)
            .expect("canonical hardened active evidence must produce both trusted outputs");

        fn require_exact_result_type(_: &TrustedCurrentInstallationEvidenceAssessment) {}
        fn require_evidence_borrow(_: &StructurallyValidatedInstallationEvidence) {}
        fn require_identity_borrow(_: &TrustedCurrentInstallationIdentity) {}
        require_exact_result_type(&assessment);
        require_evidence_borrow(assessment.evidence());
        require_identity_borrow(assessment.trusted_identity());

        assert_eq!(assessment.evidence(), &expected);
        assert_eq!(
            assessment.trusted_identity().installation_identifier(),
            assessment.evidence().installation_identifier()
        );
        assert_eq!(
            format!("{assessment:?}"),
            "TrustedCurrentInstallationEvidenceAssessment([REDACTED])"
        );
        fixture.assert_canonical_active_state();
    }

    #[cfg(windows)]
    #[test]
    fn load_trusted_current_installation_evidence_assessment_returns_no_partial_result_on_failure()
    {
        let missing = structurally_validated_active_evidence_composition_fixture(
            KEY,
            IDENTIFIER,
            IDENTIFIER,
            *plaintext().as_bytes(),
        );
        fs::remove_file(missing.paths.active_authenticated_evidence.as_path()).unwrap();
        assert!(matches!(
            load_trusted_current_installation_evidence_assessment(&missing.paths),
            Err(TrustedCurrentInstallationIdentityError::ActiveEvidenceLoadingUnavailable)
        ));

        let canonical_evidence = protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
            ProtectedObjectKind::AuthenticatedEvidence,
            encoded_envelope(KEY, IDENTIFIER).as_bytes(),
        );
        let dpapi_failure = ActiveEvidenceLoadTrustChainCompositionTestRoot::create(
            owned_wrapper(ProtectedObjectKind::AuthenticationKey, vec![0; 16]).as_bytes(),
            canonical_evidence.as_bytes(),
        );
        assert!(matches!(
            load_trusted_current_installation_evidence_assessment(&dpapi_failure.paths),
            Err(TrustedCurrentInstallationIdentityError::EvidenceProtectionOrAuthenticationFailed)
        ));

        let wrong_hmac = structurally_validated_active_evidence_composition_fixture(
            [0x44; 32],
            IDENTIFIER,
            IDENTIFIER,
            *plaintext().as_bytes(),
        );
        assert!(matches!(
            load_trusted_current_installation_evidence_assessment(&wrong_hmac.paths),
            Err(TrustedCurrentInstallationIdentityError::EvidenceProtectionOrAuthenticationFailed)
        ));

        let generation_mismatch = structurally_validated_active_evidence_composition_fixture(
            KEY,
            [0x77; 16],
            IDENTIFIER,
            *plaintext().as_bytes(),
        );
        assert!(matches!(
            load_trusted_current_installation_evidence_assessment(&generation_mismatch.paths),
            Err(TrustedCurrentInstallationIdentityError::EvidenceProtectionOrAuthenticationFailed)
        ));

        let mut malformed_plaintext = *plaintext().as_bytes();
        malformed_plaintext[0] = 0;
        let parse_failure = structurally_validated_active_evidence_composition_fixture(
            KEY,
            IDENTIFIER,
            IDENTIFIER,
            malformed_plaintext,
        );
        assert!(matches!(
            load_trusted_current_installation_evidence_assessment(&parse_failure.paths),
            Err(TrustedCurrentInstallationIdentityError::EvidencePlaintextParseFailed)
        ));

        let mut structurally_invalid_plaintext = *plaintext().as_bytes();
        structurally_invalid_plaintext[12..28].fill(0);
        let structural_failure = structurally_validated_active_evidence_composition_fixture(
            KEY,
            IDENTIFIER,
            IDENTIFIER,
            structurally_invalid_plaintext,
        );
        assert!(matches!(
            load_trusted_current_installation_evidence_assessment(&structural_failure.paths),
            Err(TrustedCurrentInstallationIdentityError::EvidenceStructuralValidationFailed)
        ));
    }

    #[test]
    fn load_trusted_current_installation_evidence_assessment_source_proves_one_canonical_load() {
        const SOURCE: &str = include_str!("mod.rs");
        const AGGREGATE_SOURCE: &str =
            include_str!("trusted_current_installation_evidence_assessment.rs");
        let production = SOURCE.split("\n#[cfg(test)]\nmod tests {").next().unwrap();
        let aggregate_production = AGGREGATE_SOURCE.split("#[cfg(test)]").next().unwrap();
        let marker = "pub(crate) fn load_trusted_current_installation_evidence_assessment(";
        assert_eq!(aggregate_production.matches(marker).count(), 1);
        let before = aggregate_production.split_once(marker).unwrap().0;
        let attributes = before.rsplit_once("\n\n").unwrap().1;
        assert!(attributes.contains("#[cfg(windows)]"));
        let boundary = aggregate_production
            .split_once(marker)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;

        assert!(boundary.contains("paths: &InstallationEvidencePersistencePaths"));
        assert!(boundary.contains("TrustedCurrentInstallationEvidenceAssessment"));
        assert!(boundary.contains("TrustedCurrentInstallationIdentityError"));
        assert_eq!(
            boundary
                .matches("load_and_validate_active_installation_evidence(paths)")
                .count(),
            1
        );
        assert_eq!(
            boundary
                .matches("TrustedCurrentInstallationEvidenceAssessment {")
                .count(),
            1
        );

        for excluded in [
            "load_active_installation_evidence_wrapper_pair",
            "load_and_recover_generation_matched_installation_evidence",
            "WindowsCurrentUserDpapi",
            "parse_generation_matched_installation_evidence_plaintext",
            "validate_parsed_installation_evidence_structure",
            "encode_v1",
            ".clone()",
            "FreshnessAnchor",
            "database_metadata",
            "classify_database_freshness",
            "startup",
            "publication",
            "replacement",
            "migration",
            "reset",
            "repair",
            "retry",
            "fallback",
            "tauri",
            "unsafe",
        ] {
            assert!(!boundary.contains(excluded), "unexpected term: {excluded}");
        }

        assert_eq!(
            aggregate_production
                .matches("evidence.installation_identifier()")
                .count(),
            1
        );
        assert_eq!(
            aggregate_production
                .matches(
                    "TrustedCurrentInstallationIdentity::from_validated_installation_identifier("
                )
                .count(),
            1
        );
        assert!(!aggregate_production.contains("encode_v1"));
        assert!(!aggregate_production.contains("parse_v1"));
        assert!(!aggregate_production.contains(".clone()"));
        assert!(!aggregate_production.contains("fn from_"));
        assert_eq!(production.matches(marker).count(), 0);
        assert_eq!(
            production
                .matches(
                    "pub(crate) use trusted_current_installation_evidence_assessment::load_trusted_current_installation_evidence_assessment;"
                )
                .count(),
            1
        );
    }

    #[cfg(windows)]
    #[test]
    fn trusted_current_installation_identity_returns_only_the_validated_active_identifier() {
        let canonical_plaintext = *plaintext().as_bytes();
        let expected = ParsedUntrustedInstallationEvidenceContract::parse_v1(&canonical_plaintext)
            .unwrap()
            .validate_structure()
            .unwrap()
            .installation_identifier();
        let fixture = structurally_validated_active_evidence_composition_fixture(
            KEY,
            IDENTIFIER,
            IDENTIFIER,
            canonical_plaintext,
        );

        let proof = load_trusted_current_installation_identity(&fixture.paths)
            .expect("canonical hardened active evidence must produce a trusted identity");

        fn require_exact_result_type(_: &TrustedCurrentInstallationIdentity) {}
        require_exact_result_type(&proof);
        assert_eq!(proof.installation_identifier(), expected);
        assert_eq!(
            format!("{proof:?}"),
            "TrustedCurrentInstallationIdentity([REDACTED])"
        );
        fixture.assert_canonical_active_state();
    }

    #[cfg(windows)]
    #[test]
    fn trusted_current_installation_identity_rejects_missing_stage_and_unexpected_artifacts() {
        for missing_key in [true, false] {
            let fixture = structurally_validated_active_evidence_composition_fixture(
                KEY,
                IDENTIFIER,
                IDENTIFIER,
                *plaintext().as_bytes(),
            );
            let missing = if missing_key {
                fixture.paths.active_authentication_key.as_path()
            } else {
                fixture.paths.active_authenticated_evidence.as_path()
            };
            fs::remove_file(missing).unwrap();

            assert!(matches!(
                load_trusted_current_installation_identity(&fixture.paths),
                Err(TrustedCurrentInstallationIdentityError::ActiveEvidenceLoadingUnavailable)
            ));
            fixture.assert_no_stage_artifacts();
        }

        for stages in [(true, false), (false, true), (true, true)] {
            let fixture = structurally_validated_active_evidence_composition_fixture(
                KEY,
                IDENTIFIER,
                IDENTIFIER,
                *plaintext().as_bytes(),
            );
            if stages.0 {
                fs::write(
                    fixture.paths.staged_authentication_key.as_path(),
                    b"synthetic-stage-key",
                )
                .unwrap();
            }
            if stages.1 {
                fs::write(
                    fixture.paths.staged_authenticated_evidence.as_path(),
                    b"synthetic-stage-evidence",
                )
                .unwrap();
            }

            assert!(matches!(
                load_trusted_current_installation_identity(&fixture.paths),
                Err(TrustedCurrentInstallationIdentityError::ActiveEvidenceLoadingUnavailable)
            ));
        }

        for unexpected_directory in [false, true] {
            let fixture = structurally_validated_active_evidence_composition_fixture(
                KEY,
                IDENTIFIER,
                IDENTIFIER,
                *plaintext().as_bytes(),
            );
            let unexpected = fixture
                .paths
                .evidence_directory
                .as_path()
                .join("unexpected.synthetic");
            if unexpected_directory {
                fs::create_dir(unexpected).unwrap();
            } else {
                fs::write(unexpected, b"synthetic").unwrap();
            }

            assert!(matches!(
                load_trusted_current_installation_identity(&fixture.paths),
                Err(TrustedCurrentInstallationIdentityError::ActiveEvidenceLoadingUnavailable)
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn trusted_current_installation_identity_rejects_wrapper_dpapi_key_and_authentication_failures()
    {
        let canonical_key = protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
            ProtectedObjectKind::AuthenticationKey,
            &key_payload(KEY, IDENTIFIER),
        );
        let canonical_envelope = encoded_envelope(KEY, IDENTIFIER);
        let canonical_evidence = protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
            ProtectedObjectKind::AuthenticatedEvidence,
            canonical_envelope.as_bytes(),
        );

        let wrong_key_kind = protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
            ProtectedObjectKind::AuthenticatedEvidence,
            &key_payload(KEY, IDENTIFIER),
        );
        let fixture = ActiveEvidenceLoadTrustChainCompositionTestRoot::create(
            wrong_key_kind.as_bytes(),
            canonical_evidence.as_bytes(),
        );
        assert!(matches!(
            load_trusted_current_installation_identity(&fixture.paths),
            Err(TrustedCurrentInstallationIdentityError::ActiveEvidenceLoadingUnavailable)
        ));

        let wrong_evidence_kind = protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
            ProtectedObjectKind::AuthenticationKey,
            canonical_envelope.as_bytes(),
        );
        let fixture = ActiveEvidenceLoadTrustChainCompositionTestRoot::create(
            canonical_key.as_bytes(),
            wrong_evidence_kind.as_bytes(),
        );
        assert!(matches!(
            load_trusted_current_installation_identity(&fixture.paths),
            Err(TrustedCurrentInstallationIdentityError::ActiveEvidenceLoadingUnavailable)
        ));

        let key_dpapi_failure = owned_wrapper(ProtectedObjectKind::AuthenticationKey, vec![0; 16]);
        let fixture = ActiveEvidenceLoadTrustChainCompositionTestRoot::create(
            key_dpapi_failure.as_bytes(),
            canonical_evidence.as_bytes(),
        );
        assert!(matches!(
            load_trusted_current_installation_identity(&fixture.paths),
            Err(TrustedCurrentInstallationIdentityError::EvidenceProtectionOrAuthenticationFailed)
        ));

        let evidence_dpapi_failure =
            owned_wrapper(ProtectedObjectKind::AuthenticatedEvidence, vec![0; 16]);
        let fixture = ActiveEvidenceLoadTrustChainCompositionTestRoot::create(
            canonical_key.as_bytes(),
            evidence_dpapi_failure.as_bytes(),
        );
        assert!(matches!(
            load_trusted_current_installation_identity(&fixture.paths),
            Err(TrustedCurrentInstallationIdentityError::EvidenceProtectionOrAuthenticationFailed)
        ));

        let malformed_key_payload = protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
            ProtectedObjectKind::AuthenticationKey,
            b"synthetic-malformed-key-payload",
        );
        let fixture = ActiveEvidenceLoadTrustChainCompositionTestRoot::create(
            malformed_key_payload.as_bytes(),
            canonical_evidence.as_bytes(),
        );
        assert!(matches!(
            load_trusted_current_installation_identity(&fixture.paths),
            Err(TrustedCurrentInstallationIdentityError::EvidenceProtectionOrAuthenticationFailed)
        ));

        let wrong_hmac = structurally_validated_active_evidence_composition_fixture(
            [0x44; 32],
            IDENTIFIER,
            IDENTIFIER,
            *plaintext().as_bytes(),
        );
        assert!(matches!(
            load_trusted_current_installation_identity(&wrong_hmac.paths),
            Err(TrustedCurrentInstallationIdentityError::EvidenceProtectionOrAuthenticationFailed)
        ));

        let generation_mismatch = structurally_validated_active_evidence_composition_fixture(
            KEY,
            [0x77; 16],
            IDENTIFIER,
            *plaintext().as_bytes(),
        );
        assert!(matches!(
            load_trusted_current_installation_identity(&generation_mismatch.paths),
            Err(TrustedCurrentInstallationIdentityError::EvidenceProtectionOrAuthenticationFailed)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn trusted_current_installation_identity_rejects_parse_and_structural_failures() {
        let mut malformed_plaintext = *plaintext().as_bytes();
        malformed_plaintext[0] = 0;
        let fixture = structurally_validated_active_evidence_composition_fixture(
            KEY,
            IDENTIFIER,
            IDENTIFIER,
            malformed_plaintext,
        );
        assert!(matches!(
            load_trusted_current_installation_identity(&fixture.paths),
            Err(TrustedCurrentInstallationIdentityError::EvidencePlaintextParseFailed)
        ));

        let mut structurally_invalid_plaintext = *plaintext().as_bytes();
        structurally_invalid_plaintext[12..28].fill(0);
        ParsedUntrustedInstallationEvidenceContract::parse_v1(&structurally_invalid_plaintext)
            .expect("structural failure fixture must remain parseable");
        let fixture = structurally_validated_active_evidence_composition_fixture(
            KEY,
            IDENTIFIER,
            IDENTIFIER,
            structurally_invalid_plaintext,
        );
        assert!(matches!(
            load_trusted_current_installation_identity(&fixture.paths),
            Err(TrustedCurrentInstallationIdentityError::EvidenceStructuralValidationFailed)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn trusted_current_installation_identity_errors_are_payload_free_and_redacted() {
        for (error, expected) in [
            (
                TrustedCurrentInstallationIdentityError::ActiveEvidenceLoadingUnavailable,
                "ActiveEvidenceLoadingUnavailable",
            ),
            (
                TrustedCurrentInstallationIdentityError::EvidenceProtectionOrAuthenticationFailed,
                "EvidenceProtectionOrAuthenticationFailed",
            ),
            (
                TrustedCurrentInstallationIdentityError::EvidencePlaintextParseFailed,
                "EvidencePlaintextParseFailed",
            ),
            (
                TrustedCurrentInstallationIdentityError::EvidenceStructuralValidationFailed,
                "EvidenceStructuralValidationFailed",
            ),
        ] {
            let debug = format!("{error:?}");
            assert_eq!(debug, expected);
            for forbidden in [
                "path",
                "CHDPAPI",
                "CHEVAUTH",
                "identifier",
                "native",
                "account",
            ] {
                assert!(!debug.to_ascii_lowercase().contains(forbidden));
            }
        }
    }

    #[test]
    fn trusted_current_installation_identity_source_proves_canonical_aggregate_delegation() {
        const SOURCE: &str = include_str!("mod.rs");
        const TYPE_SOURCE: &str = include_str!("trusted_current_installation_identity.rs");
        const LIB_SOURCE: &str = include_str!("../lib.rs");
        let production = SOURCE.split("\n#[cfg(test)]\nmod tests {").next().unwrap();
        let marker = "pub(crate) fn load_trusted_current_installation_identity(";
        assert_eq!(production.matches(marker).count(), 1);
        let before = production.split_once(marker).unwrap().0;
        let attributes = before.rsplit_once("\n\n").unwrap().1;
        assert!(attributes.contains("#[cfg(windows)]"));
        let boundary = production
            .split_once(marker)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;

        assert!(boundary.contains("paths: &InstallationEvidencePersistencePaths"));
        assert!(!boundary.contains("paths:".repeat(2).as_str()));
        assert!(boundary.contains("Result<TrustedCurrentInstallationIdentity"));
        assert_eq!(
            boundary
                .matches("load_trusted_current_installation_evidence_assessment(paths)")
                .count(),
            1
        );
        assert_eq!(
            boundary
                .matches("TrustedCurrentInstallationEvidenceAssessment::into_trusted_identity")
                .count(),
            1
        );
        assert!(!boundary.contains("load_and_validate_active_installation_evidence"));
        assert!(!boundary.contains("from_validated_installation_identifier"));
        assert!(!boundary.contains("installation_identifier()"));

        for excluded in [
            "FreshnessAnchor",
            "AssuredFreshnessAnchor",
            "classif",
            "database",
            "startup",
            "publication",
            "recovery",
            "replacement",
            "migration",
            "reset",
            "tauri",
            "unsafe",
        ] {
            assert!(!boundary.contains(excluded), "unexpected term: {excluded}");
        }

        let type_production = TYPE_SOURCE.split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            type_production
                .matches("pub(super) const fn from_validated_installation_identifier(")
                .count(),
            1
        );
        assert!(!type_production.contains("pub(crate) const fn from_"));
        assert!(!type_production.contains("StructurallyValidatedInstallationEvidence"));
        assert!(!type_production.contains("UnvalidatedInstallationEvidenceContract"));
        assert_eq!(
            LIB_SOURCE
                .matches("TrustedCurrentInstallationIdentity")
                .count(),
            0
        );
        assert_eq!(
            LIB_SOURCE
                .matches("trusted_current_installation_identity")
                .count(),
            0
        );
    }

    #[cfg(windows)]
    #[test]
    fn active_evidence_load_trust_chain_composition_returns_exact_matched_type_in_canonical_order()
    {
        let fixture =
            active_evidence_load_trust_chain_composition_fixture(KEY, IDENTIFIER, IDENTIFIER);

        let matched = load_and_recover_generation_matched_installation_evidence(&fixture.paths)
            .expect("canonical active wrappers must load and reach generation matching");

        fn require_exact_result_type(_: &GenerationMatchedAuthenticatedEnvelopeV1) {}
        require_exact_result_type(&matched);
        assert_eq!(
            format!("{matched:?}"),
            "GenerationMatchedAuthenticatedEnvelopeV1([REDACTED])"
        );
        fixture.assert_canonical_active_state();
    }

    #[cfg(windows)]
    #[test]
    fn active_evidence_load_trust_chain_composition_maps_load_failure_without_partial_result() {
        let fixture =
            active_evidence_load_trust_chain_composition_fixture(KEY, IDENTIFIER, IDENTIFIER);
        fs::remove_file(fixture.paths.active_authenticated_evidence.as_path())
            .expect("synthetic second active wrapper must be removable");

        let error = load_and_recover_generation_matched_installation_evidence(&fixture.paths)
            .expect_err("an incomplete active pair must return no matched evidence");

        assert!(matches!(
            error,
            ActiveInstallationEvidenceRecoveryError::LoadFailed
        ));
        assert_eq!(format!("{error:?}"), "ActiveEvidenceLoadFailed");
        fixture.assert_no_stage_artifacts();
    }

    #[cfg(windows)]
    #[test]
    fn active_evidence_load_trust_chain_composition_maps_wrong_hmac_to_protection_failure() {
        let fixture = active_evidence_load_trust_chain_composition_fixture(
            [0x44; 32], IDENTIFIER, IDENTIFIER,
        );

        let error = load_and_recover_generation_matched_installation_evidence(&fixture.paths)
            .expect_err("wrong HMAC key must return no matched evidence");

        assert!(matches!(
            error,
            ActiveInstallationEvidenceRecoveryError::ProtectionFailed
        ));
        assert_eq!(format!("{error:?}"), "ActiveEvidenceProtectionFailed");
        fixture.assert_canonical_active_state();
    }

    #[cfg(windows)]
    #[test]
    fn active_evidence_load_trust_chain_composition_maps_generation_mismatch_to_protection_failure()
    {
        let fixture =
            active_evidence_load_trust_chain_composition_fixture(KEY, [0x77; 16], IDENTIFIER);

        let error = load_and_recover_generation_matched_installation_evidence(&fixture.paths)
            .expect_err("generation mismatch must return no matched evidence");

        assert!(matches!(
            error,
            ActiveInstallationEvidenceRecoveryError::ProtectionFailed
        ));
        assert_eq!(format!("{error:?}"), "ActiveEvidenceProtectionFailed");
        fixture.assert_canonical_active_state();
    }

    #[test]
    fn active_evidence_load_trust_chain_composition_source_proves_exact_private_boundary() {
        const SOURCE: &str = include_str!("mod.rs");
        let production_source = SOURCE.split("\n#[cfg(test)]\nmod tests {").next().unwrap();
        let error_marker = "enum ActiveInstallationEvidenceRecoveryError {";
        assert_eq!(production_source.matches(error_marker).count(), 1);
        let error_body = production_source
            .split_once(error_marker)
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(error_body.matches("Failed,").count(), 2);
        assert!(error_body.contains("LoadFailed,"));
        assert!(error_body.contains("ProtectionFailed,"));
        assert!(!error_body.contains('('));

        let definition_marker = "fn load_and_recover_generation_matched_installation_evidence(";
        assert_eq!(production_source.matches(definition_marker).count(), 1);
        assert_eq!(
            production_source
                .matches("load_and_recover_generation_matched_installation_evidence(")
                .count(),
            2
        );
        let before_definition = production_source.split_once(definition_marker).unwrap().0;
        let declaration_attributes = before_definition.rsplit_once("\n\n").unwrap().1;
        assert!(declaration_attributes.contains("#[cfg(windows)]"));
        assert!(declaration_attributes.contains("#[cfg_attr(test, allow(dead_code))]"));
        assert!(!declaration_attributes.contains("pub"));

        let boundary = production_source
            .split_once(definition_marker)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(boundary.contains("paths: &InstallationEvidencePersistencePaths"));
        assert!(boundary.contains("GenerationMatchedAuthenticatedEnvelopeV1"));
        assert!(boundary.contains("ActiveInstallationEvidenceRecoveryError"));
        assert_eq!(
            boundary
                .matches("load_active_installation_evidence_wrapper_pair(")
                .count(),
            1
        );
        assert_eq!(
            boundary
                .matches("recover_generation_matched_installation_evidence_from_wrappers(")
                .count(),
            1
        );
        assert!(
            boundary
                .find("load_active_installation_evidence_wrapper_pair(")
                .unwrap()
                < boundary
                    .find("recover_generation_matched_installation_evidence_from_wrappers(")
                    .unwrap()
        );
        assert!(
            boundary.contains("let (authentication_key_wrapper, authenticated_evidence_wrapper) =")
        );
        assert!(boundary.contains("ActiveInstallationEvidenceRecoveryError::LoadFailed"));
        assert!(boundary.contains("ActiveInstallationEvidenceRecoveryError::ProtectionFailed"));

        for excluded in [
            "windows_filesystem",
            "single_wrapper",
            "ValidatedProtectedWrapper::parse",
            "WindowsCurrentUserDpapi",
            "DecodedProtectedKeyMaterial::parse",
            "RawUntrustedAuthenticatedEnvelopeV1::from_unprotected",
            "verify_authenticated_envelope_v1",
            ".match_generation",
            "recover_and_authenticate_in_memory",
            "recover_and_authenticate_in_memory_with",
            "parse_inner_plaintext",
            "database",
            "stage",
            "setup",
            "startup",
            "tauri",
            "unsafe",
            "retry",
            "fallback",
            "repair",
            "replace",
            "cleanup",
        ] {
            assert!(
                !boundary.contains(excluded),
                "unexpected boundary term: {excluded}"
            );
        }
        assert!(!boundary.contains(&["std", "::fs"].concat()));
        assert!(!boundary.contains(&["rusqlite", "::"].concat()));
        assert!(!boundary.contains(&["installation", "_state"].concat()));

        let error_debug = production_source
            .split_once("impl fmt::Debug for ActiveInstallationEvidenceRecoveryError")
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(error_debug.contains("\"ActiveEvidenceLoadFailed\""));
        assert!(error_debug.contains("\"ActiveEvidenceProtectionFailed\""));
        for forbidden in ["path", "CHDPAPI", "CHEVAUTH", "[0,", "native"] {
            assert!(!error_debug.contains(forbidden));
        }
    }

    #[cfg(windows)]
    #[test]
    fn protected_wrapper_trust_chain_orchestration_returns_exact_matched_type_without_plaintext_parse()
     {
        let authentication_key_wrapper = protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
            ProtectedObjectKind::AuthenticationKey,
            &key_payload(KEY, IDENTIFIER),
        );
        let envelope = encoded_envelope(KEY, IDENTIFIER);
        let authenticated_evidence_wrapper =
            protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
                ProtectedObjectKind::AuthenticatedEvidence,
                envelope.as_bytes(),
            );

        let matched = recover_generation_matched_installation_evidence_from_wrappers(
            authentication_key_wrapper,
            authenticated_evidence_wrapper,
        )
        .expect("canonical matching wrappers must traverse all four typed stages");

        fn require_exact_result_type(_: &GenerationMatchedAuthenticatedEnvelopeV1) {}
        require_exact_result_type(&matched);
        assert_eq!(
            format!("{matched:?}"),
            "GenerationMatchedAuthenticatedEnvelopeV1([REDACTED])"
        );
    }

    #[cfg(windows)]
    #[test]
    fn protected_wrapper_trust_chain_orchestration_fails_closed_before_later_stages() {
        let envelope = encoded_envelope(KEY, IDENTIFIER);
        let malformed_key_wrapper = owned_wrapper_bytes(&[0; 15]);
        let authenticated_evidence_wrapper =
            protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
                ProtectedObjectKind::AuthenticatedEvidence,
                envelope.as_bytes(),
            );
        assert_eq!(
            recover_generation_matched_installation_evidence_from_wrappers(
                malformed_key_wrapper,
                authenticated_evidence_wrapper,
            )
            .expect_err("malformed key wrapper must return no matched evidence"),
            ProtectionStageError::WrapperParseFailed
        );

        let protected_key = protect_authentication_material(
            &EvidenceAuthenticationKey::from_bytes(KEY),
            identifier(IDENTIFIER),
        )
        .expect("synthetic key material must be protectable for the current user");
        let mut corrupted_key_wrapper = protected_key.as_bytes().to_vec();
        corrupted_key_wrapper[protected_blob_wrapper::HEADER_LENGTH] ^= 1;
        let authenticated_evidence_wrapper =
            protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
                ProtectedObjectKind::AuthenticatedEvidence,
                envelope.as_bytes(),
            );
        assert_eq!(
            recover_generation_matched_installation_evidence_from_wrappers(
                owned_wrapper_bytes(&corrupted_key_wrapper),
                authenticated_evidence_wrapper,
            )
            .expect_err("key DPAPI failure must return no matched evidence"),
            ProtectionStageError::UnprotectionUnavailable
        );

        let malformed_key_payload_wrapper =
            protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
                ProtectedObjectKind::AuthenticationKey,
                &[0x31; 48],
            );
        let authenticated_evidence_wrapper =
            protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
                ProtectedObjectKind::AuthenticatedEvidence,
                envelope.as_bytes(),
            );
        assert_eq!(
            recover_generation_matched_installation_evidence_from_wrappers(
                malformed_key_payload_wrapper,
                authenticated_evidence_wrapper,
            )
            .expect_err("malformed key payload must return no matched evidence"),
            ProtectionStageError::MalformedProtectedKeyPayload
        );

        let authentication_key_wrapper = protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
            ProtectedObjectKind::AuthenticationKey,
            &key_payload(KEY, IDENTIFIER),
        );
        let wrong_length_evidence_wrapper =
            protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
                ProtectedObjectKind::AuthenticatedEvidence,
                &[0x42; 225],
            );
        assert_eq!(
            recover_generation_matched_installation_evidence_from_wrappers(
                authentication_key_wrapper,
                wrong_length_evidence_wrapper,
            )
            .expect_err("wrong evidence length must return no matched evidence"),
            ProtectionStageError::WrapperParseFailed
        );
    }

    #[cfg(windows)]
    #[test]
    fn protected_wrapper_trust_chain_orchestration_authentication_precedes_generation_matching() {
        let envelope = encoded_envelope(KEY, IDENTIFIER);
        let wrong_key_wrapper = protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
            ProtectedObjectKind::AuthenticationKey,
            &key_payload([0x44; 32], IDENTIFIER),
        );
        let authenticated_evidence_wrapper =
            protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
                ProtectedObjectKind::AuthenticatedEvidence,
                envelope.as_bytes(),
            );
        assert_eq!(
            recover_generation_matched_installation_evidence_from_wrappers(
                wrong_key_wrapper,
                authenticated_evidence_wrapper,
            )
            .expect_err("wrong HMAC key must return no matched evidence"),
            ProtectionStageError::AuthenticationFailed
        );

        let different_generation_wrapper =
            protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
                ProtectedObjectKind::AuthenticationKey,
                &key_payload(KEY, [0x77; 16]),
            );
        let authenticated_evidence_wrapper =
            protected_wrapper_trust_chain_orchestration_dpapi_wrapper(
                ProtectedObjectKind::AuthenticatedEvidence,
                envelope.as_bytes(),
            );
        assert_eq!(
            recover_generation_matched_installation_evidence_from_wrappers(
                different_generation_wrapper,
                authenticated_evidence_wrapper,
            )
            .expect_err("generation mismatch must return no matched evidence"),
            ProtectionStageError::GenerationMismatch
        );
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
    fn generation_matched_plaintext_parse_boundary_returns_exact_existing_parsed_type() {
        let canonical_plaintext = *plaintext().as_bytes();
        let expected = ParsedUntrustedInstallationEvidenceContract::parse_v1(&canonical_plaintext)
            .expect("canonical synthetic plaintext must parse");
        let parsed = parse_generation_matched_installation_evidence_plaintext(
            matched_envelope_with_inner_plaintext(canonical_plaintext),
        )
        .expect("canonical generation-matched plaintext must parse");

        fn require_exact_result_type(_: ParsedUntrustedInstallationEvidenceContract) {}
        require_exact_result_type(parsed);
        assert_eq!(parsed, expected);

        let parsed_debug = format!("{parsed:?}");
        assert!(parsed_debug.contains("ParsedUntrustedInstallationEvidenceContract"));
        assert!(parsed_debug.contains("[REDACTED]"));
        for sensitive in [
            "io.github.cltubigon.churchapp",
            "101112131415161718191a1b1c1d1e1f",
            "3131313131313131",
            "4242424242424242",
            "5353535353535353",
        ] {
            assert!(!parsed_debug.contains(sensitive));
        }
    }

    #[test]
    fn generation_matched_plaintext_parse_boundary_maps_malformed_framing_to_one_coarse_error() {
        let canonical_plaintext = *plaintext().as_bytes();
        let cases: [(&str, [u8; 164]); 3] = [
            ("wrong magic", {
                let mut malformed = canonical_plaintext;
                malformed[0] ^= 1;
                malformed
            }),
            ("unsupported version", {
                let mut malformed = canonical_plaintext;
                malformed[8..10].copy_from_slice(&2_u16.to_be_bytes());
                malformed
            }),
            ("wrong declared payload length", {
                let mut malformed = canonical_plaintext;
                malformed[10..12].copy_from_slice(&151_u16.to_be_bytes());
                malformed
            }),
        ];

        for (case, malformed_plaintext) in cases {
            let error = parse_generation_matched_installation_evidence_plaintext(
                matched_envelope_with_inner_plaintext(malformed_plaintext),
            )
            .expect_err(case);
            assert_eq!(error, ProtectionStageError::PlaintextParseFailed);
            assert_eq!(format!("{error:?}"), "PlaintextParseFailed");
        }
    }

    #[test]
    fn generation_matched_plaintext_parse_boundary_accepts_parseable_structural_failure() {
        let mut structurally_invalid_plaintext = *plaintext().as_bytes();
        structurally_invalid_plaintext[12] ^= 1;

        let parsed = parse_generation_matched_installation_evidence_plaintext(
            matched_envelope_with_inner_plaintext(structurally_invalid_plaintext),
        )
        .expect("inner framing remains parseable before structural validation");

        assert_eq!(
            parsed.validate_structure(),
            Err(ContractValidationError::WrongEvidenceFormatIdentity)
        );
    }

    #[test]
    fn generation_matched_plaintext_parse_boundary_source_proves_private_narrow_transition() {
        const SOURCE: &str = include_str!("mod.rs");
        const CONTRACT_SOURCE: &str = include_str!("../installation_evidence_contract.rs");
        const ENVELOPE_SOURCE: &str =
            include_str!("../installation_evidence_authenticated_envelope.rs");
        let production_source = source_before_test_module(SOURCE);
        let definition_marker = "fn parse_generation_matched_installation_evidence_plaintext(";

        assert_eq!(production_source.matches(definition_marker).count(), 1);
        assert_eq!(
            production_source
                .matches("parse_generation_matched_installation_evidence_plaintext(")
                .count(),
            2
        );
        let before_definition = production_source.split_once(definition_marker).unwrap().0;
        let declaration_attributes = before_definition.rsplit_once("\n\n").unwrap().1;
        assert!(!declaration_attributes.contains("cfg"));
        assert!(!declaration_attributes.contains("pub"));

        let boundary = production_source
            .split_once(definition_marker)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(boundary.contains("matched_envelope: GenerationMatchedAuthenticatedEnvelopeV1"));
        assert!(
            boundary.contains(
                "Result<ParsedUntrustedInstallationEvidenceContract, ProtectionStageError>"
            )
        );
        assert_eq!(boundary.matches(".parse_inner_plaintext()").count(), 1);
        assert_eq!(
            boundary
                .matches(".map_err(|_| ProtectionStageError::PlaintextParseFailed)")
                .count(),
            1
        );

        for excluded in [
            "validate_structure",
            "UnvalidatedInstallationEvidenceContract::new",
            "as_bytes",
            "into_bytes",
            "copy_from_slice",
            "get(",
            "Ok((",
            "load_active_installation_evidence_wrapper_pair",
            "WindowsCurrentUserDpapi",
            "ValidatedProtectedWrapper::parse",
            "verify_authenticated_envelope_v1",
            "match_generation",
            "rusqlite",
            "database",
            "setup",
            "startup",
            "tauri",
            "unsafe",
            "retry",
            "fallback",
            "repair",
            "recover",
            "replace",
        ] {
            assert!(
                !boundary.contains(excluded),
                "unexpected parse-boundary term: {excluded}"
            );
        }
        assert!(!boundary.contains(&["std", "::fs"].concat()));
        assert!(!boundary.contains(&["installation", "_state"].concat()));
        for parsed_field in [
            "evidence_format_identity",
            "evidence_format_version",
            "application_identifier",
            "application_database_format_identity",
            "parish_identifier",
            "installation_identifier",
            "installation_generation",
            "recovery_or_replacement_generation",
            "database_key_generation_identifier",
            "setup_publication_identifier",
            "creation_timestamp",
        ] {
            assert!(!boundary.contains(parsed_field));
        }

        assert!(ENVELOPE_SOURCE.contains(
            "formatter.write_str(\"GenerationMatchedAuthenticatedEnvelopeV1([REDACTED])\")"
        ));
        assert!(
            CONTRACT_SOURCE
                .contains(".debug_struct(\"ParsedUntrustedInstallationEvidenceContract\")")
        );
        assert!(CONTRACT_SOURCE.contains(".field(\"installation_identifier\", &\"[REDACTED]\")"));
        assert!(
            CONTRACT_SOURCE
                .contains(".field(\"database_key_generation_identifier\", &\"[REDACTED]\")")
        );
        assert!(
            CONTRACT_SOURCE.contains(".field(\"setup_publication_identifier\", &\"[REDACTED]\")")
        );
    }

    #[test]
    fn parsed_evidence_structural_validation_boundary_returns_exact_existing_validated_type() {
        let canonical_plaintext = *plaintext().as_bytes();
        let parsed = ParsedUntrustedInstallationEvidenceContract::parse_v1(&canonical_plaintext)
            .expect("canonical synthetic plaintext must parse before structural validation");
        let expected = parsed
            .validate_structure()
            .expect("canonical parsed evidence must validate structurally");

        let validated = validate_parsed_installation_evidence_structure(parsed)
            .expect("canonical parsed evidence must cross the structural boundary");

        fn require_exact_result_type(_: StructurallyValidatedInstallationEvidence) {}
        require_exact_result_type(validated);
        assert_eq!(validated, expected);
        assert_eq!(validated.encode_v1().as_bytes(), &canonical_plaintext);

        let debug = format!("{validated:?}");
        assert!(debug.contains("StructurallyValidatedInstallationEvidence"));
        assert!(debug.contains("[REDACTED]"));
        for sensitive in [
            "101112131415161718191a1b1c1d1e1f",
            "3131313131313131",
            "4242424242424242",
            "5353535353535353",
        ] {
            assert!(!debug.contains(sensitive));
        }
    }

    #[test]
    fn parsed_evidence_structural_validation_boundary_maps_all_defects_to_one_coarse_error() {
        let canonical_plaintext = *plaintext().as_bytes();
        let cases: [(&str, usize, usize, u8); 5] = [
            ("wrong evidence-format identity", 12, 28, 0),
            ("wrong evidence-format version", 28, 30, 0),
            ("wrong permanent application identifier", 31, 60, b'x'),
            ("wrong database-format identity", 60, 76, 0),
            ("invalid installation identifier", 92, 108, 0),
        ];

        for (case, start, end, replacement) in cases {
            let mut structurally_invalid_plaintext = canonical_plaintext;
            structurally_invalid_plaintext[start..end].fill(replacement);
            let parsed = ParsedUntrustedInstallationEvidenceContract::parse_v1(
                &structurally_invalid_plaintext,
            )
            .expect("structurally invalid fixture must remain parseable");

            let error = validate_parsed_installation_evidence_structure(parsed).expect_err(case);

            assert_eq!(error, ProtectionStageError::StructuralValidationFailed);
            assert_eq!(format!("{error:?}"), "StructuralValidationFailed");
        }
    }

    #[test]
    fn parsed_evidence_structural_validation_boundary_source_proves_private_narrow_transition() {
        const SOURCE: &str = include_str!("mod.rs");
        const CONTRACT_SOURCE: &str = include_str!("../installation_evidence_contract.rs");
        let production_source = source_before_test_module(SOURCE);
        let definition_marker = "fn validate_parsed_installation_evidence_structure(";

        assert_eq!(production_source.matches(definition_marker).count(), 1);
        assert_eq!(
            production_source
                .matches("validate_parsed_installation_evidence_structure(")
                .count(),
            2
        );
        let before_definition = production_source.split_once(definition_marker).unwrap().0;
        let declaration_attributes = before_definition.rsplit_once("\n\n").unwrap().1;
        assert!(!declaration_attributes.contains("cfg"));
        assert!(!declaration_attributes.contains("pub"));

        let boundary = production_source
            .split_once(definition_marker)
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(boundary.contains("parsed: ParsedUntrustedInstallationEvidenceContract"));
        assert!(
            boundary.contains(
                "Result<StructurallyValidatedInstallationEvidence, ProtectionStageError>"
            )
        );
        assert_eq!(boundary.matches(".validate_structure()").count(), 1);
        assert_eq!(
            boundary
                .matches(".map_err(|_| ProtectionStageError::StructuralValidationFailed)")
                .count(),
            1
        );

        for excluded in [
            "parse_inner_plaintext",
            "parse_v1",
            "UnvalidatedInstallationEvidenceContract::new",
            "as_bytes",
            "encode_v1",
            "Ok((",
            "load_active_installation_evidence_wrapper_pair",
            "WindowsCurrentUserDpapi",
            "ValidatedProtectedWrapper::parse",
            "verify_authenticated_envelope_v1",
            "match_generation",
            "rusqlite",
            "database",
            "freshness",
            "rollback",
            "setup",
            "startup",
            "tauri",
            "unsafe",
            "retry",
            "fallback",
            "repair",
            "recover",
            "replace",
        ] {
            assert!(
                !boundary.contains(excluded),
                "unexpected structural-boundary term: {excluded}"
            );
        }
        assert!(!boundary.contains(&["std", "::fs"].concat()));
        assert!(!boundary.contains(&["installation", "_state"].concat()));
        for parsed_field in [
            "evidence_format_identity",
            "evidence_format_version",
            "application_identifier",
            "application_database_format_identity",
            "parish_identifier",
            "installation_identifier",
            "installation_generation",
            "recovery_or_replacement_generation",
            "database_key_generation_identifier",
            "setup_publication_identifier",
            "creation_timestamp",
        ] {
            assert!(!boundary.contains(parsed_field));
        }

        assert!(
            CONTRACT_SOURCE
                .contains(".debug_struct(\"ParsedUntrustedInstallationEvidenceContract\")")
        );
        assert!(
            CONTRACT_SOURCE
                .contains(".debug_struct(\"StructurallyValidatedInstallationEvidence\")")
        );
        assert!(CONTRACT_SOURCE.contains(".field(\"parish_identifier\", &\"[REDACTED]\")"));
        assert!(CONTRACT_SOURCE.contains(".field(\"installation_identifier\", &\"[REDACTED]\")"));
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
            ProtectionStageError::PlaintextParseFailed,
            ProtectionStageError::StructuralValidationFailed,
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
