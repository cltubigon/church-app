//! Private consuming integration of the verified encrypted migration-backup
//! stage with Migration Recovery Envelope Format V1.

#![allow(dead_code)]

use std::{fmt, os::windows::fs::FileExt};

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::{
    database_metadata_contract::DatabaseMetadataContractV1,
    installation_evidence_protection::{
        TrustedCurrentInstallationEvidenceAssessment,
        bind_database_key_candidate_to_trusted_installation_evidence,
    },
    production_database_connection_handoff::{
        ProductionDatabaseMigrationBackupStageVerifierOpenError,
        close_production_database_migration_backup_stage_verifier,
        observe_production_database_fixed_metadata_and_headers_on_borrowed_connection,
        open_production_database_migration_backup_stage_verifier,
        validate_production_database_cipher_integrity_on_borrowed_connection,
    },
    production_database_migration_recovery_envelope::{
        EncodedMigrationRecoveryEnvelopeV1, GeneratedMigrationRecoveryKeyMaterial,
        MigrationBackupStageSha256Digest, MigrationRecoveryOpeningError,
        MigrationRecoveryPayloadMatchError, ParsedUntrustedMigrationRecoveryEnvelopeV1,
        generate_migration_backup_set_identifier, generate_migration_recovery_key_material,
        open_migration_recovery_envelope_v1, seal_migration_recovery_envelope_v1,
    },
};

use super::{
    ProductionDatabaseMigrationBackupContext, ProductionDatabaseMigrationBackupStageError,
    SourceCloseState, VerifiedEncryptedProductionDatabaseMigrationBackupStage,
    VerifiedEncryptedProductionDatabaseMigrationBackupStageProof, close_source,
    destroy_migration_authorization, load_fresh_bound_key, retry_source_close_state,
};

const HASH_BUFFER_LENGTH: usize = 64 * 1024;

pub(crate) struct IndependentlyVerifiedMigrationRecoveryEnvelopeV1 {
    encoded: EncodedMigrationRecoveryEnvelopeV1,
}

pub(crate) struct VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup {
    encrypted_stage: VerifiedEncryptedProductionDatabaseMigrationBackupStage,
    verified_envelope: IndependentlyVerifiedMigrationRecoveryEnvelopeV1,
    recovery_key_material: GeneratedMigrationRecoveryKeyMaterial,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProductionDatabaseMigrationRecoveryEnvelopeError {
    RecoveryMaterialGenerationUnavailable,
    BackupSetGenerationUnavailable,
    StageIdentityUnavailableOrChanged,
    StageDigestUnavailable,
    ActiveDatabaseKeyUnavailable,
    ActiveDatabaseKeyRecoveryFailed,
    ActiveDatabaseKeyBindingFailed,
    EnvelopeSealingFailed,
    EnvelopeFramingFailed,
    RecoveryGenerationMismatchOrAuthenticationFailed,
    AuthenticatedPayloadInvalid,
    BackupSetMismatch,
    EnvelopeRecoveredCandidateBindingFailed,
    FreshStageIdentityOrDigestUnavailable,
    DigestMismatch,
    VerifierOpenFailed,
    VerifierKeyOrPolicyFailed,
    CipherIntegrityVerificationFailed,
    MetadataOrHeaderVerificationFailed,
    VerifierCloseFailed,
    FinalStageIdentityChanged,
}

struct RecoveryEnvelopeFailureArtifacts {
    backup_stage_proof: VerifiedEncryptedProductionDatabaseMigrationBackupStageProof,
    encoded: Option<EncodedMigrationRecoveryEnvelopeV1>,
    source_close: SourceCloseState,
}

pub(crate) struct ProductionDatabaseMigrationRecoveryEnvelopeFailure {
    category: ProductionDatabaseMigrationRecoveryEnvelopeError,
    artifacts: RecoveryEnvelopeFailureArtifacts,
}

pub(crate) struct ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseFailure {
    category: ProductionDatabaseMigrationRecoveryEnvelopeError,
    artifacts: RecoveryEnvelopeFailureArtifacts,
    verifier: Connection,
}

#[must_use = "the recovery-envelope transition outcome must be handled"]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProductionDatabaseMigrationRecoveryEnvelopeOutcome {
    Verified(VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup),
    Failed(ProductionDatabaseMigrationRecoveryEnvelopeFailure),
    VerifierCloseFailed(ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseFailure),
}

#[must_use = "a recovery-envelope source-close retry outcome must be handled"]
pub(crate) enum ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome<T> {
    Closed(T),
    Failed(T),
}

#[must_use = "a verifier-close retry outcome must be handled"]
pub(crate) enum ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseRetryOutcome {
    Closed(ProductionDatabaseMigrationRecoveryEnvelopeFailure),
    Failed(ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseFailure),
}

macro_rules! redacted_debug {
    ($type:ty, $name:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($name, "([REDACTED])"))
            }
        }
    };
}

redacted_debug!(
    IndependentlyVerifiedMigrationRecoveryEnvelopeV1,
    "IndependentlyVerifiedMigrationRecoveryEnvelopeV1"
);
redacted_debug!(
    VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup,
    "VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup"
);
redacted_debug!(
    ProductionDatabaseMigrationRecoveryEnvelopeFailure,
    "ProductionDatabaseMigrationRecoveryEnvelopeFailure"
);
redacted_debug!(
    ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseFailure,
    "ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseFailure"
);

impl fmt::Debug for ProductionDatabaseMigrationRecoveryEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RecoveryMaterialGenerationUnavailable => "RecoveryMaterialGenerationUnavailable",
            Self::BackupSetGenerationUnavailable => "BackupSetGenerationUnavailable",
            Self::StageIdentityUnavailableOrChanged => "StageIdentityUnavailableOrChanged",
            Self::StageDigestUnavailable => "StageDigestUnavailable",
            Self::ActiveDatabaseKeyUnavailable => "ActiveDatabaseKeyUnavailable",
            Self::ActiveDatabaseKeyRecoveryFailed => "ActiveDatabaseKeyRecoveryFailed",
            Self::ActiveDatabaseKeyBindingFailed => "ActiveDatabaseKeyBindingFailed",
            Self::EnvelopeSealingFailed => "EnvelopeSealingFailed",
            Self::EnvelopeFramingFailed => "EnvelopeFramingFailed",
            Self::RecoveryGenerationMismatchOrAuthenticationFailed => {
                "RecoveryGenerationMismatchOrAuthenticationFailed"
            }
            Self::AuthenticatedPayloadInvalid => "AuthenticatedPayloadInvalid",
            Self::BackupSetMismatch => "BackupSetMismatch",
            Self::EnvelopeRecoveredCandidateBindingFailed => {
                "EnvelopeRecoveredCandidateBindingFailed"
            }
            Self::FreshStageIdentityOrDigestUnavailable => "FreshStageIdentityOrDigestUnavailable",
            Self::DigestMismatch => "DigestMismatch",
            Self::VerifierOpenFailed => "VerifierOpenFailed",
            Self::VerifierKeyOrPolicyFailed => "VerifierKeyOrPolicyFailed",
            Self::CipherIntegrityVerificationFailed => "CipherIntegrityVerificationFailed",
            Self::MetadataOrHeaderVerificationFailed => "MetadataOrHeaderVerificationFailed",
            Self::VerifierCloseFailed => "VerifierCloseFailed",
            Self::FinalStageIdentityChanged => "FinalStageIdentityChanged",
        })
    }
}

impl fmt::Debug for ProductionDatabaseMigrationRecoveryEnvelopeOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified(_) => formatter.write_str("Verified([REDACTED])"),
            Self::Failed(failure) => formatter
                .debug_tuple("Failed")
                .field(&failure.category)
                .finish(),
            Self::VerifierCloseFailed(_) => formatter.write_str("VerifierCloseFailed([REDACTED])"),
        }
    }
}

enum InternalFailure {
    Primary {
        category: ProductionDatabaseMigrationRecoveryEnvelopeError,
        encoded: Option<EncodedMigrationRecoveryEnvelopeV1>,
    },
    VerifierClose {
        category: ProductionDatabaseMigrationRecoveryEnvelopeError,
        encoded: EncodedMigrationRecoveryEnvelopeV1,
        verifier: Connection,
    },
}

struct VerifiedEnvelopeParts {
    verified_envelope: IndependentlyVerifiedMigrationRecoveryEnvelopeV1,
    recovery_key_material: GeneratedMigrationRecoveryKeyMaterial,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestFailurePoint {
    RecoveryMaterialGeneration,
    RecoveryAuthentication,
    AuthenticatedPayload,
    BackupSet,
    CandidateBinding,
    CipherIntegrity,
    MetadataOrHeader,
    FinalStageIdentity,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestEvent {
    RecoveryMaterialGenerated,
    StageHashed,
    ActiveWrapperReloaded,
    EnvelopeSealed,
    ConstructionKeyDestroyed,
    EnvelopeParsed,
    EnvelopeAuthenticated,
    PayloadMatched,
    CandidateReleased,
    CandidateBound,
    VerifierOpened,
    CipherIntegrityVerified,
    MetadataAndHeadersVerified,
    VerifierCloseAttempted,
    FinalIdentityObserved,
}

#[cfg(test)]
mod test_orchestration {
    use std::cell::RefCell;

    use super::{TestEvent, TestFailurePoint};

    #[derive(Default)]
    pub(super) struct State {
        pub(super) failure: Option<TestFailurePoint>,
        pub(super) wrong_authenticated_digest: bool,
        pub(super) events: Vec<TestEvent>,
    }

    thread_local! {
        static STATE: RefCell<State> = RefCell::new(State::default());
    }

    pub(super) struct Reset(Option<State>);

    impl Drop for Reset {
        fn drop(&mut self) {
            STATE.with(|state| *state.borrow_mut() = self.0.take().unwrap_or_default());
        }
    }

    pub(super) fn run<T>(
        failure: Option<TestFailurePoint>,
        wrong_authenticated_digest: bool,
        operation: impl FnOnce() -> T,
    ) -> (T, Vec<TestEvent>) {
        let prior = STATE.with(|state| {
            state.replace(State {
                failure,
                wrong_authenticated_digest,
                events: Vec::new(),
            })
        });
        let reset = Reset(Some(prior));
        let outcome = operation();
        let events = STATE.with(|state| state.borrow().events.clone());
        drop(reset);
        (outcome, events)
    }

    pub(super) fn fails_at(point: TestFailurePoint) -> bool {
        STATE.with(|state| state.borrow().failure == Some(point))
    }

    pub(super) fn wrong_authenticated_digest() -> bool {
        STATE.with(|state| state.borrow().wrong_authenticated_digest)
    }

    pub(super) fn record(event: TestEvent) {
        STATE.with(|state| state.borrow_mut().events.push(event));
    }
}

#[cfg(test)]
fn record_test_event(event: TestEvent) {
    test_orchestration::record(event);
}

#[cfg(not(test))]
fn record_test_event(_: ()) {}

#[cfg(test)]
fn injected_test_failure(point: TestFailurePoint) -> bool {
    test_orchestration::fails_at(point)
}

#[cfg(test)]
fn destroy_construction_key_for_test(
    construction_key: crate::installation_evidence_protection::GenerationBoundDatabaseKey,
) {
    drop(construction_key);
    record_test_event(TestEvent::ConstructionKeyDestroyed);
}

fn stage_digest(
    proof: &VerifiedEncryptedProductionDatabaseMigrationBackupStageProof,
) -> Result<MigrationBackupStageSha256Digest, ()> {
    if !proof.identity_is_unchanged() {
        return Err(());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_LENGTH];
    let mut offset = 0_u64;
    loop {
        let read = proof.leaf.seek_read(&mut buffer, offset).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| ())?)
            .ok_or(())?;
    }
    if !proof.identity_is_unchanged() {
        return Err(());
    }
    Ok(MigrationBackupStageSha256Digest::from_bytes(
        hasher.finalize().into(),
    ))
}

fn map_key_load_error(
    error: ProductionDatabaseMigrationBackupStageError,
) -> ProductionDatabaseMigrationRecoveryEnvelopeError {
    match error {
        ProductionDatabaseMigrationBackupStageError::ActiveDatabaseKeyUnavailable => {
            ProductionDatabaseMigrationRecoveryEnvelopeError::ActiveDatabaseKeyUnavailable
        }
        ProductionDatabaseMigrationBackupStageError::ActiveDatabaseKeyRecoveryFailed => {
            ProductionDatabaseMigrationRecoveryEnvelopeError::ActiveDatabaseKeyRecoveryFailed
        }
        ProductionDatabaseMigrationBackupStageError::ActiveDatabaseKeyBindingFailed => {
            ProductionDatabaseMigrationRecoveryEnvelopeError::ActiveDatabaseKeyBindingFailed
        }
        _ => ProductionDatabaseMigrationRecoveryEnvelopeError::ActiveDatabaseKeyUnavailable,
    }
}

#[allow(clippy::result_large_err)]
fn run_transition(
    proof: &VerifiedEncryptedProductionDatabaseMigrationBackupStageProof,
    context: &ProductionDatabaseMigrationBackupContext,
    metadata: &DatabaseMetadataContractV1,
    assessment: &TrustedCurrentInstallationEvidenceAssessment,
) -> Result<VerifiedEnvelopeParts, InternalFailure> {
    #[cfg(test)]
    if injected_test_failure(TestFailurePoint::RecoveryMaterialGeneration) {
        return Err(InternalFailure::Primary {
            category:
                ProductionDatabaseMigrationRecoveryEnvelopeError::RecoveryMaterialGenerationUnavailable,
            encoded: None,
        });
    }
    let recovery_key_material = generate_migration_recovery_key_material().map_err(|_| InternalFailure::Primary {
        category: ProductionDatabaseMigrationRecoveryEnvelopeError::RecoveryMaterialGenerationUnavailable,
        encoded: None,
    })?;
    #[cfg(test)]
    record_test_event(TestEvent::RecoveryMaterialGenerated);
    let backup_set_identifier =
        generate_migration_backup_set_identifier().map_err(|_| InternalFailure::Primary {
            category:
                ProductionDatabaseMigrationRecoveryEnvelopeError::BackupSetGenerationUnavailable,
            encoded: None,
        })?;
    if !proof.identity_is_unchanged() {
        return Err(InternalFailure::Primary {
            category:
                ProductionDatabaseMigrationRecoveryEnvelopeError::StageIdentityUnavailableOrChanged,
            encoded: None,
        });
    }
    let first_digest = stage_digest(proof).map_err(|_| InternalFailure::Primary {
        category: ProductionDatabaseMigrationRecoveryEnvelopeError::StageDigestUnavailable,
        encoded: None,
    })?;
    #[cfg(test)]
    record_test_event(TestEvent::StageHashed);

    #[cfg(test)]
    record_test_event(TestEvent::ActiveWrapperReloaded);
    let construction_key =
        load_fresh_bound_key(context, assessment).map_err(|error| InternalFailure::Primary {
            category: map_key_load_error(error),
            encoded: None,
        })?;
    #[cfg(test)]
    let envelope_digest = if test_orchestration::wrong_authenticated_digest() {
        MigrationBackupStageSha256Digest::from_bytes([0x5a; 32])
    } else {
        first_digest
    };
    #[cfg(not(test))]
    let envelope_digest = first_digest;
    let encoded = construction_key
        .expose_key(|database_key| {
            seal_migration_recovery_envelope_v1(
                &recovery_key_material,
                database_key,
                metadata.database_key_generation_identifier(),
                backup_set_identifier,
                envelope_digest,
            )
        })
        .map_err(|_| InternalFailure::Primary {
            category: ProductionDatabaseMigrationRecoveryEnvelopeError::EnvelopeSealingFailed,
            encoded: None,
        })?;
    #[cfg(test)]
    record_test_event(TestEvent::EnvelopeSealed);
    #[cfg(test)]
    destroy_construction_key_for_test(construction_key);
    #[cfg(not(test))]
    drop(construction_key);

    let parsed = match ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(encoded.as_bytes()) {
        Ok(parsed) => parsed,
        Err(_) => {
            return Err(InternalFailure::Primary {
                category: ProductionDatabaseMigrationRecoveryEnvelopeError::EnvelopeFramingFailed,
                encoded: Some(encoded),
            });
        }
    };
    #[cfg(test)]
    record_test_event(TestEvent::EnvelopeParsed);
    #[cfg(test)]
    if injected_test_failure(TestFailurePoint::RecoveryAuthentication) {
        return Err(InternalFailure::Primary {
            category: ProductionDatabaseMigrationRecoveryEnvelopeError::RecoveryGenerationMismatchOrAuthenticationFailed,
            encoded: Some(encoded),
        });
    }
    let authenticated = match open_migration_recovery_envelope_v1(parsed, &recovery_key_material) {
        Ok(authenticated) => authenticated,
        Err(
            MigrationRecoveryOpeningError::RecoveryKeyGenerationMismatch
            | MigrationRecoveryOpeningError::AuthenticationFailed,
        ) => {
            return Err(InternalFailure::Primary {
                category: ProductionDatabaseMigrationRecoveryEnvelopeError::RecoveryGenerationMismatchOrAuthenticationFailed,
                encoded: Some(encoded),
            });
        }
    };
    #[cfg(test)]
    record_test_event(TestEvent::EnvelopeAuthenticated);
    #[cfg(test)]
    if injected_test_failure(TestFailurePoint::AuthenticatedPayload) {
        return Err(InternalFailure::Primary {
            category: ProductionDatabaseMigrationRecoveryEnvelopeError::AuthenticatedPayloadInvalid,
            encoded: Some(encoded),
        });
    }
    #[cfg(test)]
    if injected_test_failure(TestFailurePoint::BackupSet) {
        return Err(InternalFailure::Primary {
            category: ProductionDatabaseMigrationRecoveryEnvelopeError::BackupSetMismatch,
            encoded: Some(encoded),
        });
    }
    let matched = match authenticated.validate_payload_and_match_backup_set() {
        Ok(matched) => matched,
        Err(error) => {
            return Err(InternalFailure::Primary {
                category: match error {
                    MigrationRecoveryPayloadMatchError::InvalidAuthenticatedPayload => {
                        ProductionDatabaseMigrationRecoveryEnvelopeError::AuthenticatedPayloadInvalid
                    }
                    MigrationRecoveryPayloadMatchError::BackupSetMismatch => {
                        ProductionDatabaseMigrationRecoveryEnvelopeError::BackupSetMismatch
                    }
                },
                encoded: Some(encoded),
            });
        }
    };
    #[cfg(test)]
    record_test_event(TestEvent::PayloadMatched);
    let (candidate, authenticated_digest) = matched.release_database_key_candidate();
    #[cfg(test)]
    record_test_event(TestEvent::CandidateReleased);
    #[cfg(test)]
    if injected_test_failure(TestFailurePoint::CandidateBinding) {
        drop(candidate);
        return Err(InternalFailure::Primary {
            category:
                ProductionDatabaseMigrationRecoveryEnvelopeError::EnvelopeRecoveredCandidateBindingFailed,
            encoded: Some(encoded),
        });
    }
    let recovered_key = match bind_database_key_candidate_to_trusted_installation_evidence(
        candidate, assessment,
    ) {
        Ok(recovered_key) => recovered_key,
        Err(_) => {
            return Err(InternalFailure::Primary {
                    category: ProductionDatabaseMigrationRecoveryEnvelopeError::EnvelopeRecoveredCandidateBindingFailed,
                    encoded: Some(encoded),
                });
        }
    };
    #[cfg(test)]
    record_test_event(TestEvent::CandidateBound);
    let second_digest = match stage_digest(proof) {
        Ok(digest) => digest,
        Err(()) => {
            return Err(InternalFailure::Primary {
                category: ProductionDatabaseMigrationRecoveryEnvelopeError::FreshStageIdentityOrDigestUnavailable,
                encoded: Some(encoded),
            });
        }
    };
    #[cfg(test)]
    record_test_event(TestEvent::StageHashed);
    if second_digest != authenticated_digest {
        return Err(InternalFailure::Primary {
            category: ProductionDatabaseMigrationRecoveryEnvelopeError::DigestMismatch,
            encoded: Some(encoded),
        });
    }

    let verifier = match open_production_database_migration_backup_stage_verifier(
        proof.created.prepared.path(),
        &recovered_key,
    ) {
        Ok(verifier) => verifier,
        Err(ProductionDatabaseMigrationBackupStageVerifierOpenError::Open) => {
            return Err(InternalFailure::Primary {
                category: ProductionDatabaseMigrationRecoveryEnvelopeError::VerifierOpenFailed,
                encoded: Some(encoded),
            });
        }
        Err(ProductionDatabaseMigrationBackupStageVerifierOpenError::KeyOrPolicy) => {
            return Err(InternalFailure::Primary {
                category:
                    ProductionDatabaseMigrationRecoveryEnvelopeError::VerifierKeyOrPolicyFailed,
                encoded: Some(encoded),
            });
        }
        Err(ProductionDatabaseMigrationBackupStageVerifierOpenError::Close(verifier)) => {
            return Err(InternalFailure::VerifierClose {
                category:
                    ProductionDatabaseMigrationRecoveryEnvelopeError::VerifierKeyOrPolicyFailed,
                encoded,
                verifier,
            });
        }
    };
    #[cfg(test)]
    record_test_event(TestEvent::VerifierOpened);
    drop(recovered_key);

    #[cfg(test)]
    let cipher_verification = if injected_test_failure(TestFailurePoint::CipherIntegrity) {
        Err(())
    } else {
        validate_production_database_cipher_integrity_on_borrowed_connection(&verifier)
            .map_err(|_| ())
    };
    #[cfg(not(test))]
    let cipher_verification =
        validate_production_database_cipher_integrity_on_borrowed_connection(&verifier);
    let verification = cipher_verification
        .map_err(|_| ProductionDatabaseMigrationRecoveryEnvelopeError::CipherIntegrityVerificationFailed)
        .and_then(|_| {
            #[cfg(test)]
            record_test_event(TestEvent::CipherIntegrityVerified);
            #[cfg(test)]
            let metadata_matches = if injected_test_failure(TestFailurePoint::MetadataOrHeader) {
                false
            } else {
                observe_production_database_fixed_metadata_and_headers_on_borrowed_connection(&verifier).as_ref() == Ok(metadata)
            };
            #[cfg(not(test))]
            let metadata_matches = observe_production_database_fixed_metadata_and_headers_on_borrowed_connection(&verifier).as_ref() == Ok(metadata);
            if metadata_matches {
                #[cfg(test)]
                record_test_event(TestEvent::MetadataAndHeadersVerified);
                Ok(())
            } else {
                Err(ProductionDatabaseMigrationRecoveryEnvelopeError::MetadataOrHeaderVerificationFailed)
            }
        });
    if let Err(category) = verification {
        #[cfg(test)]
        record_test_event(TestEvent::VerifierCloseAttempted);
        return match close_production_database_migration_backup_stage_verifier(verifier) {
            Ok(()) => Err(InternalFailure::Primary {
                category,
                encoded: Some(encoded),
            }),
            Err(verifier) => Err(InternalFailure::VerifierClose {
                category,
                encoded,
                verifier,
            }),
        };
    }
    #[cfg(test)]
    record_test_event(TestEvent::VerifierCloseAttempted);
    if let Err(verifier) = close_production_database_migration_backup_stage_verifier(verifier) {
        return Err(InternalFailure::VerifierClose {
            category: ProductionDatabaseMigrationRecoveryEnvelopeError::VerifierCloseFailed,
            encoded,
            verifier,
        });
    }
    #[cfg(test)]
    record_test_event(TestEvent::FinalIdentityObserved);
    #[cfg(test)]
    if injected_test_failure(TestFailurePoint::FinalStageIdentity) {
        return Err(InternalFailure::Primary {
            category: ProductionDatabaseMigrationRecoveryEnvelopeError::FinalStageIdentityChanged,
            encoded: Some(encoded),
        });
    }
    if !proof.identity_is_unchanged() {
        return Err(InternalFailure::Primary {
            category: ProductionDatabaseMigrationRecoveryEnvelopeError::FinalStageIdentityChanged,
            encoded: Some(encoded),
        });
    }
    Ok(VerifiedEnvelopeParts {
        verified_envelope: IndependentlyVerifiedMigrationRecoveryEnvelopeV1 { encoded },
        recovery_key_material,
    })
}

#[allow(clippy::result_large_err)]
pub(crate) fn verify_production_database_migration_recovery_envelope(
    encrypted_stage: VerifiedEncryptedProductionDatabaseMigrationBackupStage,
) -> ProductionDatabaseMigrationRecoveryEnvelopeOutcome {
    let VerifiedEncryptedProductionDatabaseMigrationBackupStage {
        authorization,
        source,
        backup_stage_proof,
        context,
    } = encrypted_stage;
    let result = source.with_migration_backup_source(|_, metadata, assessment| {
        run_transition(&backup_stage_proof, &context, metadata, assessment)
    });
    match result {
        Ok(parts) => ProductionDatabaseMigrationRecoveryEnvelopeOutcome::Verified(
            VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup {
                encrypted_stage: VerifiedEncryptedProductionDatabaseMigrationBackupStage {
                    authorization,
                    source,
                    backup_stage_proof,
                    context,
                },
                verified_envelope: parts.verified_envelope,
                recovery_key_material: parts.recovery_key_material,
            },
        ),
        Err(failure) => {
            destroy_migration_authorization(authorization);
            drop(context);
            let source_close = close_source(source);
            match failure {
                InternalFailure::Primary { category, encoded } => {
                    ProductionDatabaseMigrationRecoveryEnvelopeOutcome::Failed(
                        ProductionDatabaseMigrationRecoveryEnvelopeFailure {
                            category,
                            artifacts: RecoveryEnvelopeFailureArtifacts {
                                backup_stage_proof,
                                encoded,
                                source_close,
                            },
                        },
                    )
                }
                InternalFailure::VerifierClose {
                    category,
                    encoded,
                    verifier,
                } => ProductionDatabaseMigrationRecoveryEnvelopeOutcome::VerifierCloseFailed(
                    ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseFailure {
                        category,
                        artifacts: RecoveryEnvelopeFailureArtifacts {
                            backup_stage_proof,
                            encoded: Some(encoded),
                            source_close,
                        },
                        verifier,
                    },
                ),
            }
        }
    }
}

impl ProductionDatabaseMigrationRecoveryEnvelopeFailure {
    pub(crate) fn retry_source_close(
        self,
    ) -> ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome<Self> {
        let Self {
            category,
            artifacts,
        } = self;
        let RecoveryEnvelopeFailureArtifacts {
            backup_stage_proof,
            encoded,
            source_close,
        } = artifacts;
        let (source_close, closed) = retry_source_close_state(source_close);
        let failure = Self {
            category,
            artifacts: RecoveryEnvelopeFailureArtifacts {
                backup_stage_proof,
                encoded,
                source_close,
            },
        };
        if closed {
            ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome::Closed(failure)
        } else {
            ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome::Failed(failure)
        }
    }
}

impl ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseFailure {
    pub(crate) fn retry_source_close(
        self,
    ) -> ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome<Self> {
        let Self {
            category,
            artifacts,
            verifier,
        } = self;
        let RecoveryEnvelopeFailureArtifacts {
            backup_stage_proof,
            encoded,
            source_close,
        } = artifacts;
        let (source_close, closed) = retry_source_close_state(source_close);
        let failure = Self {
            category,
            artifacts: RecoveryEnvelopeFailureArtifacts {
                backup_stage_proof,
                encoded,
                source_close,
            },
            verifier,
        };
        if closed {
            ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome::Closed(failure)
        } else {
            ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome::Failed(failure)
        }
    }

    pub(crate) fn retry_close(
        self,
    ) -> ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseRetryOutcome {
        let Self {
            category,
            artifacts,
            verifier,
        } = self;
        #[cfg(test)]
        record_test_event(TestEvent::VerifierCloseAttempted);
        match close_production_database_migration_backup_stage_verifier(verifier) {
            Ok(()) => ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseRetryOutcome::Closed(
                ProductionDatabaseMigrationRecoveryEnvelopeFailure {
                    category,
                    artifacts,
                },
            ),
            Err(verifier) => {
                ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseRetryOutcome::Failed(Self {
                    category,
                    artifacts,
                    verifier,
                })
            }
        }
    }
}

impl VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup {
    #[cfg(test)]
    fn close(
        self,
    ) -> crate::production_database_connection_handoff::ProductionDatabaseConnectionCloseOutcome
    {
        let Self {
            encrypted_stage,
            verified_envelope: _,
            recovery_key_material,
        } = self;
        drop(recovery_key_material);
        encrypted_stage.close()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::Read,
        mem::needs_drop,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::{
        database_key::DatabaseKey,
        installation_evidence_contract::DatabaseKeyGenerationIdentifier,
        installation_evidence_protection::protect_database_key,
        production_database_connection_handoff::{
            ProductionDatabaseConnectionCloseOutcome,
            with_production_database_close_failure_injected,
            with_production_database_close_failure_injected_at,
        },
        storage_foundation::database_key_persistence_paths,
    };

    use super::super::super::genuine_full_integrity_validated_migration_handoff_for_test;
    use super::super::{
        PreparedProductionDatabaseMigrationBackupStage, ProductionDatabaseMigrationBackupContext,
        ProductionDatabaseMigrationBackupStageOutcome,
        stage_encrypted_production_database_migration_backup,
    };
    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const KEY_BYTES: [u8; 32] = [0x74; 32];
    const KEY_GENERATION: [u8; 16] = [0x43; 16];

    struct StageRoot(PathBuf);

    impl StageRoot {
        fn create() -> Self {
            let path = std::env::temp_dir().join(format!(
                "church-app-migration-recovery-envelope-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for StageRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn verified_stage() -> (
        impl Drop,
        StageRoot,
        VerifiedEncryptedProductionDatabaseMigrationBackupStage,
    ) {
        let (source_root, handoff) = genuine_full_integrity_validated_migration_handoff_for_test();
        let paths = database_key_persistence_paths(source_root.path());
        fs::create_dir_all(paths.database_key_directory.as_path()).unwrap();
        let key = DatabaseKey::from_bytes(KEY_BYTES);
        let generation = DatabaseKeyGenerationIdentifier::from_bytes(KEY_GENERATION).unwrap();
        let wrapper = protect_database_key(&key, generation).unwrap();
        fs::write(paths.active_database_key.as_path(), wrapper.as_bytes()).unwrap();
        let stage_root = StageRoot::create();
        let prepared =
            PreparedProductionDatabaseMigrationBackupStage::from_synthetic_temp_root(&stage_root.0)
                .unwrap();
        let outcome = stage_encrypted_production_database_migration_backup(
            handoff,
            prepared,
            ProductionDatabaseMigrationBackupContext::from_synthetic_root(source_root.path()),
        );
        let ProductionDatabaseMigrationBackupStageOutcome::Verified(verified) = outcome else {
            panic!("stage fixture must verify");
        };
        (source_root, stage_root, verified)
    }

    fn assert_count(events: &[TestEvent], expected: usize, event: TestEvent) {
        assert_eq!(
            events.iter().filter(|observed| **observed == event).count(),
            expected,
            "unexpected event count for {event:?}: {events:?}"
        );
    }

    fn assert_primary_failure(
        outcome: ProductionDatabaseMigrationRecoveryEnvelopeOutcome,
        expected: ProductionDatabaseMigrationRecoveryEnvelopeError,
        encoded_expected: bool,
    ) -> ProductionDatabaseMigrationRecoveryEnvelopeFailure {
        let ProductionDatabaseMigrationRecoveryEnvelopeOutcome::Failed(failure) = outcome else {
            panic!("expected ordinary primary failure, got {outcome:?}");
        };
        assert_eq!(failure.category, expected);
        assert_eq!(failure.artifacts.encoded.is_some(), encoded_expected);
        assert!(failure.artifacts.backup_stage_proof.identity_is_unchanged());
        failure
    }

    #[test]
    fn verified_stage_consumes_into_independently_verified_recovery_envelope() {
        let (source_root, _stage_root, verified) = verified_stage();
        let expected = verified.preservation_evidence_for_test();
        let (outcome, events) = test_orchestration::run(None, false, || {
            verify_production_database_migration_recovery_envelope(verified)
        });
        let ProductionDatabaseMigrationRecoveryEnvelopeOutcome::Verified(verified) = outcome else {
            panic!("verified encrypted stage must recovery-envelope successfully");
        };
        assert_eq!(
            verified.encrypted_stage.preservation_evidence_for_test(),
            expected
        );
        assert_eq!(verified.verified_envelope.encoded.as_bytes().len(), 182);
        let VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup {
            encrypted_stage,
            verified_envelope,
            recovery_key_material,
        } = verified;
        assert_eq!(verified_envelope.encoded.as_bytes().len(), 182);
        assert!(needs_drop::<GeneratedMigrationRecoveryKeyMaterial>());
        assert_eq!(
            events,
            vec![
                TestEvent::RecoveryMaterialGenerated,
                TestEvent::StageHashed,
                TestEvent::ActiveWrapperReloaded,
                TestEvent::EnvelopeSealed,
                TestEvent::ConstructionKeyDestroyed,
                TestEvent::EnvelopeParsed,
                TestEvent::EnvelopeAuthenticated,
                TestEvent::PayloadMatched,
                TestEvent::CandidateReleased,
                TestEvent::CandidateBound,
                TestEvent::StageHashed,
                TestEvent::VerifierOpened,
                TestEvent::CipherIntegrityVerified,
                TestEvent::MetadataAndHeadersVerified,
                TestEvent::VerifierCloseAttempted,
                TestEvent::FinalIdentityObserved,
            ]
        );
        assert_count(&events, 1, TestEvent::ActiveWrapperReloaded);
        let destroyed = events
            .iter()
            .position(|event| *event == TestEvent::ConstructionKeyDestroyed)
            .unwrap();
        let parsed = events
            .iter()
            .position(|event| *event == TestEvent::EnvelopeParsed)
            .unwrap();
        assert!(destroyed < parsed);
        drop(recovery_key_material);
        assert!(matches!(
            encrypted_stage.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        drop(source_root);
    }

    #[test]
    fn deterministic_primary_failures_enforce_candidate_verifier_and_ownership_boundaries() {
        let cases = [
            (
                TestFailurePoint::RecoveryMaterialGeneration,
                ProductionDatabaseMigrationRecoveryEnvelopeError::RecoveryMaterialGenerationUnavailable,
                false,
                false,
                false,
            ),
            (
                TestFailurePoint::RecoveryAuthentication,
                ProductionDatabaseMigrationRecoveryEnvelopeError::RecoveryGenerationMismatchOrAuthenticationFailed,
                true,
                false,
                false,
            ),
            (
                TestFailurePoint::AuthenticatedPayload,
                ProductionDatabaseMigrationRecoveryEnvelopeError::AuthenticatedPayloadInvalid,
                true,
                false,
                false,
            ),
            (
                TestFailurePoint::BackupSet,
                ProductionDatabaseMigrationRecoveryEnvelopeError::BackupSetMismatch,
                true,
                false,
                false,
            ),
            (
                TestFailurePoint::CandidateBinding,
                ProductionDatabaseMigrationRecoveryEnvelopeError::EnvelopeRecoveredCandidateBindingFailed,
                true,
                true,
                false,
            ),
            (
                TestFailurePoint::CipherIntegrity,
                ProductionDatabaseMigrationRecoveryEnvelopeError::CipherIntegrityVerificationFailed,
                true,
                true,
                true,
            ),
            (
                TestFailurePoint::MetadataOrHeader,
                ProductionDatabaseMigrationRecoveryEnvelopeError::MetadataOrHeaderVerificationFailed,
                true,
                true,
                true,
            ),
            (
                TestFailurePoint::FinalStageIdentity,
                ProductionDatabaseMigrationRecoveryEnvelopeError::FinalStageIdentityChanged,
                true,
                true,
                true,
            ),
        ];
        for (point, category, encoded_expected, candidate_expected, verifier_expected) in cases {
            let (source_root, stage_root, verified) = verified_stage();
            let stage_path = verified.stage_path_for_test().to_path_buf();
            let leaf_identity = verified.backup_stage_proof.leaf_identity;
            let (outcome, events) = test_orchestration::run(Some(point), false, || {
                verify_production_database_migration_recovery_envelope(verified)
            });
            let failure = assert_primary_failure(outcome, category, encoded_expected);
            assert_eq!(
                failure.artifacts.backup_stage_proof.created.prepared.path(),
                stage_path
            );
            assert!(failure.artifacts.backup_stage_proof.leaf_identity == leaf_identity);
            assert!(stage_path.exists());
            assert_eq!(
                events.contains(&TestEvent::CandidateReleased),
                candidate_expected
            );
            assert_eq!(
                events.contains(&TestEvent::VerifierOpened),
                verifier_expected
            );
            assert!(
                !events.contains(&TestEvent::FinalIdentityObserved)
                    || point == TestFailurePoint::FinalStageIdentity
            );
            assert_count(
                &events,
                usize::from(point != TestFailurePoint::RecoveryMaterialGeneration),
                TestEvent::ActiveWrapperReloaded,
            );
            drop(failure);
            drop(stage_root);
            drop(source_root);
        }
    }

    #[test]
    fn authenticated_wrong_digest_is_rejected_before_verifier_and_retains_exact_artifacts() {
        let (source_root, stage_root, verified) = verified_stage();
        let stage_path = verified.stage_path_for_test().to_path_buf();
        let leaf_identity = verified.backup_stage_proof.leaf_identity;
        let (outcome, events) = test_orchestration::run(None, true, || {
            verify_production_database_migration_recovery_envelope(verified)
        });
        let failure = assert_primary_failure(
            outcome,
            ProductionDatabaseMigrationRecoveryEnvelopeError::DigestMismatch,
            true,
        );
        assert!(events.contains(&TestEvent::EnvelopeAuthenticated));
        assert!(events.contains(&TestEvent::CandidateBound));
        assert!(!events.contains(&TestEvent::VerifierOpened));
        assert_count(&events, 2, TestEvent::StageHashed);
        assert_count(&events, 1, TestEvent::ActiveWrapperReloaded);
        assert_eq!(
            failure.artifacts.backup_stage_proof.created.prepared.path(),
            stage_path
        );
        assert!(failure.artifacts.backup_stage_proof.leaf_identity == leaf_identity);
        assert!(failure.artifacts.encoded.is_some());
        assert!(stage_path.exists());
        drop(failure);
        drop(stage_root);
        drop(source_root);
    }

    #[test]
    fn verifier_close_failure_retains_only_close_and_artifact_owners_and_retry_only_closes() {
        let (source_root, stage_root, verified) = verified_stage();
        let stage_path = verified.stage_path_for_test().to_path_buf();
        let ((failure, category), events) = test_orchestration::run(None, false, || {
            let outcome = with_production_database_close_failure_injected_at(0, || {
                verify_production_database_migration_recovery_envelope(verified)
            });
            let ProductionDatabaseMigrationRecoveryEnvelopeOutcome::VerifierCloseFailed(failure) =
                outcome
            else {
                panic!("injected verifier close must retain verifier ownership");
            };
            assert!(failure.artifacts.encoded.is_some());
            assert!(matches!(
                failure.artifacts.source_close,
                SourceCloseState::Closed
            ));
            assert!(failure.artifacts.backup_stage_proof.identity_is_unchanged());
            let category = failure.category;
            let ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseRetryOutcome::Failed(
                failure,
            ) = with_production_database_close_failure_injected(|| failure.retry_close())
            else {
                panic!("repeated injected close failure must retain verifier");
            };
            let ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseRetryOutcome::Closed(
                failure,
            ) = failure.retry_close()
            else {
                panic!("retry without injection must close verifier");
            };
            (failure, category)
        });
        assert_eq!(
            category,
            ProductionDatabaseMigrationRecoveryEnvelopeError::VerifierCloseFailed
        );
        assert_eq!(failure.category, category);
        assert_count(&events, 3, TestEvent::VerifierCloseAttempted);
        assert_count(&events, 2, TestEvent::StageHashed);
        assert_count(&events, 1, TestEvent::ActiveWrapperReloaded);
        assert_count(&events, 1, TestEvent::EnvelopeSealed);
        assert_count(&events, 1, TestEvent::EnvelopeParsed);
        assert_count(&events, 1, TestEvent::CipherIntegrityVerified);
        assert_count(&events, 1, TestEvent::MetadataAndHeadersVerified);
        assert_eq!(
            failure.artifacts.backup_stage_proof.created.prepared.path(),
            stage_path
        );
        assert!(stage_path.exists());
        drop(failure);
        drop(stage_root);
        drop(source_root);
    }

    #[test]
    fn primary_and_verifier_close_failure_preserves_primary_category() {
        let (source_root, stage_root, verified) = verified_stage();
        let (outcome, events) =
            test_orchestration::run(Some(TestFailurePoint::CipherIntegrity), false, || {
                with_production_database_close_failure_injected_at(0, || {
                    verify_production_database_migration_recovery_envelope(verified)
                })
            });
        let ProductionDatabaseMigrationRecoveryEnvelopeOutcome::VerifierCloseFailed(failure) =
            outcome
        else {
            panic!("cipher failure plus close failure must retain verifier");
        };
        assert_eq!(
            failure.category,
            ProductionDatabaseMigrationRecoveryEnvelopeError::CipherIntegrityVerificationFailed
        );
        assert!(failure.artifacts.encoded.is_some());
        assert_count(&events, 1, TestEvent::VerifierCloseAttempted);
        drop(failure);
        drop(stage_root);
        drop(source_root);
    }

    #[test]
    fn source_close_failure_and_retry_preserve_primary_and_only_retry_close() {
        let (source_root, stage_root, verified) = verified_stage();
        let stage_path = verified.stage_path_for_test().to_path_buf();
        let (failure, events) = test_orchestration::run(
            Some(TestFailurePoint::CipherIntegrity),
            false,
            || {
                let outcome = with_production_database_close_failure_injected_at(1, || {
                    verify_production_database_migration_recovery_envelope(verified)
                });
                let failure = assert_primary_failure(
                    outcome,
                    ProductionDatabaseMigrationRecoveryEnvelopeError::CipherIntegrityVerificationFailed,
                    true,
                );
                assert!(matches!(
                    failure.artifacts.source_close,
                    SourceCloseState::RetryRequired(_)
                ));
                let ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome::Failed(
                    failure,
                ) = with_production_database_close_failure_injected(|| {
                    failure.retry_source_close()
                })
                else {
                    panic!("repeated source close failure must retain the same failure");
                };
                assert_eq!(
                    failure.category,
                    ProductionDatabaseMigrationRecoveryEnvelopeError::CipherIntegrityVerificationFailed
                );
                assert!(failure.artifacts.encoded.is_some());
                let ProductionDatabaseMigrationRecoveryEnvelopeSourceCloseRetryOutcome::Closed(
                    failure,
                ) = failure.retry_source_close()
                else {
                    panic!("source close retry must close after injection is removed");
                };
                failure
            },
        );
        assert_eq!(
            failure.category,
            ProductionDatabaseMigrationRecoveryEnvelopeError::CipherIntegrityVerificationFailed
        );
        assert!(matches!(
            failure.artifacts.source_close,
            SourceCloseState::Closed
        ));
        assert!(failure.artifacts.encoded.is_some());
        assert!(failure.artifacts.backup_stage_proof.identity_is_unchanged());
        assert_eq!(
            failure.artifacts.backup_stage_proof.created.prepared.path(),
            stage_path
        );
        assert_count(&events, 2, TestEvent::StageHashed);
        assert_count(&events, 1, TestEvent::ActiveWrapperReloaded);
        assert_count(&events, 1, TestEvent::EnvelopeSealed);
        assert_count(&events, 1, TestEvent::VerifierOpened);
        assert_count(&events, 1, TestEvent::VerifierCloseAttempted);
        drop(failure);
        drop(stage_root);
        drop(source_root);
    }

    #[test]
    fn outward_failure_types_cannot_own_authorization_recovery_key_or_construction_key() {
        const SOURCE: &str = include_str!("recovery_envelope.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        let ordinary = production
            .split_once("pub(crate) struct ProductionDatabaseMigrationRecoveryEnvelopeFailure {")
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        let verifier_close = production
            .split_once("pub(crate) struct ProductionDatabaseMigrationRecoveryEnvelopeVerifierCloseFailure {")
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        for failure in [ordinary, verifier_close] {
            assert!(failure.contains("RecoveryEnvelopeFailureArtifacts"));
            assert!(!failure.contains("ProductionDatabaseMigrationAuthorization"));
            assert!(!failure.contains("GeneratedMigrationRecoveryKeyMaterial"));
            assert!(!failure.contains("GenerationBoundDatabaseKey"));
        }
        let failure_arm = production
            .split_once("Err(failure) => {")
            .unwrap()
            .1
            .split_once("    }\n}")
            .unwrap()
            .0;
        assert!(failure_arm.contains("destroy_migration_authorization(authorization);"));
        assert!(failure_arm.contains("drop(context);"));
        assert!(failure_arm.contains("close_source(source)"));
        assert!(!failure_arm.contains("authorization,"));
        assert!(!failure_arm.contains("recovery_key_material"));
    }

    #[test]
    fn retained_leaf_identity_hashes_exact_bytes_and_blocks_write_and_delete() {
        let (source_root, stage_root, verified) = verified_stage();
        let digest = stage_digest(&verified.backup_stage_proof).unwrap();
        let mut bytes = Vec::new();
        OpenOptions::new()
            .read(true)
            .open(verified.stage_path_for_test())
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        let expected = MigrationBackupStageSha256Digest::from_bytes(Sha256::digest(bytes).into());
        assert_eq!(digest, expected);
        assert!(
            OpenOptions::new()
                .write(true)
                .open(verified.stage_path_for_test())
                .is_err()
        );
        assert!(fs::remove_file(verified.stage_path_for_test()).is_err());
        assert!(verified.backup_stage_proof.identity_is_unchanged());
        assert!(matches!(
            verified.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        drop(stage_root);
        drop(source_root);
    }

    #[test]
    fn production_composition_reuses_canonical_primitives_and_omits_forbidden_work() {
        const SOURCE: &str = include_str!("recovery_envelope.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        for required in [
            "generate_migration_recovery_key_material()",
            "generate_migration_backup_set_identifier()",
            "seal_migration_recovery_envelope_v1(",
            "ParsedUntrustedMigrationRecoveryEnvelopeV1::parse",
            "open_migration_recovery_envelope_v1",
            "bind_database_key_candidate_to_trusted_installation_evidence(",
            "validate_production_database_cipher_integrity_on_borrowed_connection(&verifier)",
            "observe_production_database_fixed_metadata_and_headers_on_borrowed_connection(&verifier)",
            "drop(construction_key)",
            "close_production_database_migration_backup_stage_verifier(verifier)",
        ] {
            assert!(
                production.contains(required),
                "missing composition: {required}"
            );
        }
        for forbidden in [
            "validate_production_database_full_integrity",
            "PRAGMA main.integrity_check",
            "quick_check",
            "tauri::command",
            "ProductionDatabaseMigrationCrossProcessExclusivity",
            "restore_stage",
            "DELETE FROM",
            "CREATE TABLE",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden work: {forbidden}"
            );
        }
    }
}
