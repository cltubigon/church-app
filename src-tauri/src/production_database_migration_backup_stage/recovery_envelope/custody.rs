//! Private, unwired ownership states for the two-readback custody ceremony.

#[cfg(windows)]
#[path = "custody/native_windows.rs"]
mod native_windows;

#[cfg(windows)]
pub(crate) use native_windows::{
    NativeMigrationRecoveryKeyCustodyOutcome, run_migration_recovery_key_custody_native_ceremony,
};

use std::fmt;

use sha2::{Digest, Sha256};

use crate::production_database_migration_recovery_envelope::{
    EncodedMigrationRecoveryKeyCustodyV1, ParsedUntrustedMigrationRecoveryEnvelopeV1,
    RecoverySetManifestV1, RecoverySetRequiredBytes, encode_migration_recovery_key_custody_v1,
    validate_migration_recovery_key_custody_v1,
};
use crate::{
    database_key_protected_payload::DecodedDatabaseKeyCandidate,
    database_metadata_contract::DatabaseMetadataContractV1,
    installation_evidence_protection::{
        GenerationBoundDatabaseKey, bind_database_key_candidate_to_trusted_installation_evidence,
    },
};

use super::super::{
    SourceCloseState, VerifiedEncryptedProductionDatabaseMigrationBackupStageProof, close_source,
    destroy_migration_authorization, retry_source_close_state,
};
use super::{
    IndependentlyVerifiedMigrationRecoveryEnvelopeV1, StageObservationError,
    VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup,
};

pub(crate) struct PreparedUndisclosedMigrationRecoveryKeyCustody {
    backup: VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup,
    encoded: EncodedMigrationRecoveryKeyCustodyV1,
}

pub(crate) struct DisclosedMigrationRecoveryKeyCustody {
    backup: VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup,
    encoded: EncodedMigrationRecoveryKeyCustodyV1,
}

pub(crate) struct FirstCopyVerifiedMigrationRecoveryKeyCustody {
    backup: VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup,
    encoded: EncodedMigrationRecoveryKeyCustodyV1,
}

pub(crate) struct VerifiedMigrationRecoveryKeyCustody {
    _private: (),
}

pub(crate) struct RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup {
    encrypted_stage: super::super::VerifiedEncryptedProductionDatabaseMigrationBackupStage,
    verified_envelope: IndependentlyVerifiedMigrationRecoveryEnvelopeV1,
    custody: VerifiedMigrationRecoveryKeyCustody,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RecoverySetManifestPreparationError {
    SourceObservationUnavailable,
    StageIdentityUnavailableOrChanged,
    ManifestConstructionRejected,
}

struct PossiblyExposedMigrationRecoveryKeyCustodyFailureArtifacts {
    backup_stage_proof: VerifiedEncryptedProductionDatabaseMigrationBackupStageProof,
    verified_envelope: IndependentlyVerifiedMigrationRecoveryEnvelopeV1,
    source_close: SourceCloseState,
}

pub(crate) struct PossiblyExposedMigrationRecoveryKeyCustodyFailure {
    category: MigrationRecoveryKeyCustodyError,
    artifacts: PossiblyExposedMigrationRecoveryKeyCustodyFailureArtifacts,
}

pub(crate) struct UndisclosedMigrationRecoveryKeyCustodyInterruption {
    category: MigrationRecoveryKeyCustodyError,
    prepared: PreparedUndisclosedMigrationRecoveryKeyCustody,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MigrationRecoveryKeyCustodyError {
    CancelledBeforeCustodyExposure,
    CancelledAfterCustodyExposure,
    NativeCeremonyFailedAfterCustodyExposure,
    FirstCustodyCopyVerificationFailed,
    SecondCustodyCopyVerificationFailed,
}

#[must_use = "a custody source-close retry outcome must be handled"]
pub(crate) enum MigrationRecoveryKeyCustodySourceCloseRetryOutcome {
    Closed(PossiblyExposedMigrationRecoveryKeyCustodyFailure),
    Failed(PossiblyExposedMigrationRecoveryKeyCustodyFailure),
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
    PreparedUndisclosedMigrationRecoveryKeyCustody,
    "PreparedUndisclosedMigrationRecoveryKeyCustody"
);

impl fmt::Debug for RecoverySetManifestPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceObservationUnavailable => "SourceObservationUnavailable",
            Self::StageIdentityUnavailableOrChanged => "StageIdentityUnavailableOrChanged",
            Self::ManifestConstructionRejected => "ManifestConstructionRejected",
        })
    }
}
redacted_debug!(
    DisclosedMigrationRecoveryKeyCustody,
    "DisclosedMigrationRecoveryKeyCustody"
);
redacted_debug!(
    FirstCopyVerifiedMigrationRecoveryKeyCustody,
    "FirstCopyVerifiedMigrationRecoveryKeyCustody"
);
redacted_debug!(
    RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    "RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup"
);
redacted_debug!(
    PossiblyExposedMigrationRecoveryKeyCustodyFailure,
    "PossiblyExposedMigrationRecoveryKeyCustodyFailure"
);
redacted_debug!(
    UndisclosedMigrationRecoveryKeyCustodyInterruption,
    "UndisclosedMigrationRecoveryKeyCustodyInterruption"
);

impl fmt::Debug for VerifiedMigrationRecoveryKeyCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedMigrationRecoveryKeyCustody")
    }
}

impl fmt::Debug for MigrationRecoveryKeyCustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CancelledBeforeCustodyExposure => "CancelledBeforeCustodyExposure",
            Self::CancelledAfterCustodyExposure => "CancelledAfterCustodyExposure",
            Self::NativeCeremonyFailedAfterCustodyExposure => {
                "NativeCeremonyFailedAfterCustodyExposure"
            }
            Self::FirstCustodyCopyVerificationFailed => "FirstCustodyCopyVerificationFailed",
            Self::SecondCustodyCopyVerificationFailed => "SecondCustodyCopyVerificationFailed",
        })
    }
}

pub(crate) fn prepare_migration_recovery_key_custody(
    backup: VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup,
) -> PreparedUndisclosedMigrationRecoveryKeyCustody {
    let (_, backup_set_identifier) = custody_association(&backup.verified_envelope);
    let encoded = encode_migration_recovery_key_custody_v1(
        &backup.recovery_key_material,
        backup_set_identifier,
    );
    PreparedUndisclosedMigrationRecoveryKeyCustody { backup, encoded }
}

fn custody_association(
    envelope: &IndependentlyVerifiedMigrationRecoveryEnvelopeV1,
) -> (
    crate::production_database_migration_recovery_envelope::MigrationRecoveryKeyGenerationIdentifier,
    crate::production_database_migration_recovery_envelope::MigrationBackupSetIdentifier,
){
    let parsed = ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(envelope.encoded.as_bytes())
        .expect("independently verified envelope retains valid fixed framing");
    (
        parsed.recovery_key_generation_identifier(),
        parsed.backup_set_identifier(),
    )
}

impl PreparedUndisclosedMigrationRecoveryKeyCustody {
    pub(crate) fn disclose(self) -> DisclosedMigrationRecoveryKeyCustody {
        let Self { backup, encoded } = self;
        DisclosedMigrationRecoveryKeyCustody { backup, encoded }
    }

    pub(crate) fn cancel_before_exposure(
        self,
    ) -> UndisclosedMigrationRecoveryKeyCustodyInterruption {
        UndisclosedMigrationRecoveryKeyCustodyInterruption {
            category: MigrationRecoveryKeyCustodyError::CancelledBeforeCustodyExposure,
            prepared: self,
        }
    }

    pub(crate) fn abort_before_exposure_for_shutdown(
        self,
    ) -> super::super::UndisclosedMigrationRecoveryKeyCustodyShutdown {
        let Self { backup, encoded } = self;
        let VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup {
            encrypted_stage,
            verified_envelope,
            recovery_key_material,
        } = backup;
        drop(encoded);
        drop(recovery_key_material);
        let super::super::VerifiedEncryptedProductionDatabaseMigrationBackupStage {
            authorization,
            source,
            backup_stage_proof,
            context,
        } = encrypted_stage;
        destroy_migration_authorization(authorization);
        drop(context);
        super::super::UndisclosedMigrationRecoveryKeyCustodyShutdown {
            backup_stage_proof,
            verified_envelope,
            source_close: close_source(source),
        }
    }

    #[cfg(test)]
    pub(crate) fn encoded_for_test(&self) -> &[u8; 196] {
        self.encoded.bytes_for_test()
    }
}

impl UndisclosedMigrationRecoveryKeyCustodyInterruption {
    pub(crate) fn retry(self) -> PreparedUndisclosedMigrationRecoveryKeyCustody {
        self.prepared
    }
}

impl DisclosedMigrationRecoveryKeyCustody {
    #[allow(clippy::result_large_err)]
    pub(crate) fn verify_first_copy(
        self,
        readback: &[u8],
    ) -> Result<
        FirstCopyVerifiedMigrationRecoveryKeyCustody,
        PossiblyExposedMigrationRecoveryKeyCustodyFailure,
    > {
        let Self { backup, encoded } = self;
        let (generation_identifier, backup_set_identifier) =
            custody_association(&backup.verified_envelope);
        if validate_migration_recovery_key_custody_v1(
            readback,
            generation_identifier,
            backup_set_identifier,
            &backup.recovery_key_material,
        )
        .is_err()
        {
            return Err(terminal_failure(
                backup,
                encoded,
                MigrationRecoveryKeyCustodyError::FirstCustodyCopyVerificationFailed,
            ));
        }
        Ok(FirstCopyVerifiedMigrationRecoveryKeyCustody { backup, encoded })
    }

    pub(crate) fn cancel(self) -> PossiblyExposedMigrationRecoveryKeyCustodyFailure {
        terminal_failure(
            self.backup,
            self.encoded,
            MigrationRecoveryKeyCustodyError::CancelledAfterCustodyExposure,
        )
    }
}

impl FirstCopyVerifiedMigrationRecoveryKeyCustody {
    #[allow(clippy::result_large_err)]
    pub(crate) fn verify_second_copy(
        self,
        readback: &[u8],
    ) -> Result<
        RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
        PossiblyExposedMigrationRecoveryKeyCustodyFailure,
    > {
        let Self { backup, encoded } = self;
        let (generation_identifier, backup_set_identifier) =
            custody_association(&backup.verified_envelope);
        if validate_migration_recovery_key_custody_v1(
            readback,
            generation_identifier,
            backup_set_identifier,
            &backup.recovery_key_material,
        )
        .is_err()
        {
            return Err(terminal_failure(
                backup,
                encoded,
                MigrationRecoveryKeyCustodyError::SecondCustodyCopyVerificationFailed,
            ));
        }
        let VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup {
            encrypted_stage,
            verified_envelope,
            recovery_key_material,
        } = backup;
        drop(encoded);
        drop(recovery_key_material);
        Ok(
            RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup {
                encrypted_stage,
                verified_envelope,
                custody: VerifiedMigrationRecoveryKeyCustody { _private: () },
            },
        )
    }

    pub(crate) fn cancel(self) -> PossiblyExposedMigrationRecoveryKeyCustodyFailure {
        terminal_failure(
            self.backup,
            self.encoded,
            MigrationRecoveryKeyCustodyError::CancelledAfterCustodyExposure,
        )
    }
}

fn terminal_failure(
    backup: VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup,
    encoded: EncodedMigrationRecoveryKeyCustodyV1,
    category: MigrationRecoveryKeyCustodyError,
) -> PossiblyExposedMigrationRecoveryKeyCustodyFailure {
    let VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup {
        encrypted_stage,
        verified_envelope,
        recovery_key_material,
    } = backup;
    drop(encoded);
    drop(recovery_key_material);
    let super::super::VerifiedEncryptedProductionDatabaseMigrationBackupStage {
        authorization,
        source,
        backup_stage_proof,
        context,
    } = encrypted_stage;
    destroy_migration_authorization(authorization);
    drop(context);
    let source_close = close_source(source);
    PossiblyExposedMigrationRecoveryKeyCustodyFailure {
        category,
        artifacts: PossiblyExposedMigrationRecoveryKeyCustodyFailureArtifacts {
            backup_stage_proof,
            verified_envelope,
            source_close,
        },
    }
}

impl PossiblyExposedMigrationRecoveryKeyCustodyFailure {
    pub(crate) fn retry_source_close(self) -> MigrationRecoveryKeyCustodySourceCloseRetryOutcome {
        let Self {
            category,
            artifacts,
        } = self;
        let PossiblyExposedMigrationRecoveryKeyCustodyFailureArtifacts {
            backup_stage_proof,
            verified_envelope,
            source_close,
        } = artifacts;
        let (source_close, closed) = retry_source_close_state(source_close);
        let failure = Self {
            category,
            artifacts: PossiblyExposedMigrationRecoveryKeyCustodyFailureArtifacts {
                backup_stage_proof,
                verified_envelope,
                source_close,
            },
        };
        if closed {
            MigrationRecoveryKeyCustodySourceCloseRetryOutcome::Closed(failure)
        } else {
            MigrationRecoveryKeyCustodySourceCloseRetryOutcome::Failed(failure)
        }
    }
}

impl RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup {
    pub(crate) fn bind_recovered_database_key_candidate(
        &self,
        candidate: DecodedDatabaseKeyCandidate,
    ) -> Result<(GenerationBoundDatabaseKey, DatabaseMetadataContractV1), ()> {
        self.encrypted_stage
            .source
            .with_migration_backup_source(|_, metadata, assessment| {
                bind_database_key_candidate_to_trusted_installation_evidence(candidate, assessment)
                    .map(|key| (key, *metadata))
                    .map_err(|_| ())
            })
    }

    pub(crate) fn with_verified_recovery_envelope_bytes<T>(
        &self,
        operation: impl FnOnce(
            &[u8; crate::production_database_migration_recovery_envelope::MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
        ) -> T,
    ) -> Result<T, RecoverySetManifestPreparationError> {
        let envelope_bytes = self.verified_envelope.encoded.as_bytes();
        ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(envelope_bytes)
            .map_err(|_| RecoverySetManifestPreparationError::SourceObservationUnavailable)?;
        Ok(operation(envelope_bytes))
    }

    pub(crate) fn observe_recovery_database_source(
        &self,
    ) -> Result<super::MigrationBackupStageManifestObservation, RecoverySetManifestPreparationError>
    {
        super::stage_manifest_observation(&self.encrypted_stage.backup_stage_proof).map_err(
            |error| match error {
                StageObservationError::ObservationUnavailable => {
                    RecoverySetManifestPreparationError::SourceObservationUnavailable
                }
                StageObservationError::IdentityUnavailableOrChanged => {
                    RecoverySetManifestPreparationError::StageIdentityUnavailableOrChanged
                }
            },
        )
    }

    pub(crate) fn stream_recovery_database_source(
        &self,
        sink: impl FnMut(&[u8]) -> Result<(), ()>,
    ) -> Result<super::MigrationBackupStageManifestObservation, RecoverySetManifestPreparationError>
    {
        super::stream_stage_for_recovery_database_publication(
            &self.encrypted_stage.backup_stage_proof,
            sink,
        )
        .map_err(|error| match error {
            StageObservationError::ObservationUnavailable => {
                RecoverySetManifestPreparationError::SourceObservationUnavailable
            }
            StageObservationError::IdentityUnavailableOrChanged => {
                RecoverySetManifestPreparationError::StageIdentityUnavailableOrChanged
            }
        })
    }

    pub(crate) fn prepare_recovery_set_manifest_v1(
        &self,
    ) -> Result<RecoverySetManifestV1, RecoverySetManifestPreparationError> {
        let envelope_bytes = self.verified_envelope.encoded.as_bytes();
        let backup_set_identifier =
            ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(envelope_bytes)
                .map_err(|_| RecoverySetManifestPreparationError::SourceObservationUnavailable)?
                .backup_set_identifier();
        let stage_observation = self.observe_recovery_database_source()?;
        let recovery_envelope_sha256 = Sha256::digest(envelope_bytes).into();

        RecoverySetManifestV1::from_trusted_internal_facts(
            backup_set_identifier,
            stage_observation.database_byte_length,
            stage_observation.database_sha256,
            recovery_envelope_sha256,
        )
        .map_err(|_| RecoverySetManifestPreparationError::ManifestConstructionRejected)
    }

    pub(crate) fn prepare_recovery_set_required_bytes(
        &self,
    ) -> Result<RecoverySetRequiredBytes, RecoverySetManifestPreparationError> {
        self.prepare_recovery_set_manifest_v1()?
            .required_set_bytes()
            .map_err(|_| RecoverySetManifestPreparationError::ManifestConstructionRejected)
    }

    pub(crate) fn abort_for_shutdown(
        self,
    ) -> super::super::UndisclosedMigrationRecoveryKeyCustodyShutdown {
        let Self {
            encrypted_stage,
            verified_envelope,
            custody: _custody,
        } = self;
        let super::super::VerifiedEncryptedProductionDatabaseMigrationBackupStage {
            authorization,
            source,
            backup_stage_proof,
            context,
        } = encrypted_stage;
        destroy_migration_authorization(authorization);
        drop(context);
        super::super::UndisclosedMigrationRecoveryKeyCustodyShutdown {
            backup_stage_proof,
            verified_envelope,
            source_close: close_source(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
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
        },
        storage_foundation::database_key_persistence_paths,
    };

    use super::super::super::super::genuine_full_integrity_validated_migration_handoff_for_test;
    use super::super::super::{
        PreparedProductionDatabaseMigrationBackupStage, ProductionDatabaseMigrationBackupContext,
        ProductionDatabaseMigrationBackupStageOutcome,
        UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome,
        stage_encrypted_production_database_migration_backup,
    };
    use super::super::{
        ProductionDatabaseMigrationRecoveryEnvelopeOutcome,
        verify_production_database_migration_recovery_envelope,
    };
    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct StageRoot(PathBuf);

    impl StageRoot {
        fn create() -> Self {
            let path = std::env::temp_dir().join(format!(
                "church-app-migration-custody-{}-{}",
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

    fn verified_backup() -> (
        impl Drop,
        StageRoot,
        VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup,
    ) {
        let (source_root, handoff) = genuine_full_integrity_validated_migration_handoff_for_test();
        let paths = database_key_persistence_paths(source_root.path());
        fs::create_dir_all(paths.database_key_directory.as_path()).unwrap();
        let key = DatabaseKey::from_bytes([0x74; 32]);
        let generation = DatabaseKeyGenerationIdentifier::from_bytes([0x43; 16]).unwrap();
        let wrapper = protect_database_key(&key, generation).unwrap();
        fs::write(paths.active_database_key.as_path(), wrapper.as_bytes()).unwrap();
        let stage_root = StageRoot::create();
        let prepared =
            PreparedProductionDatabaseMigrationBackupStage::from_synthetic_temp_root(&stage_root.0)
                .unwrap();
        let ProductionDatabaseMigrationBackupStageOutcome::Verified(stage) =
            stage_encrypted_production_database_migration_backup(
                handoff,
                prepared,
                ProductionDatabaseMigrationBackupContext::from_synthetic_root(source_root.path()),
            )
        else {
            panic!("stage fixture must verify");
        };
        let ProductionDatabaseMigrationRecoveryEnvelopeOutcome::Verified(verified) =
            verify_production_database_migration_recovery_envelope(stage)
        else {
            panic!("envelope fixture must verify");
        };
        (source_root, stage_root, verified)
    }

    fn custody_verified_backup() -> (
        impl Drop,
        StageRoot,
        RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    ) {
        let (source_root, stage_root, backup) = verified_backup();
        let prepared = prepare_migration_recovery_key_custody(backup);
        let readback = *prepared.encoded_for_test();
        let verified = prepared
            .disclose()
            .verify_first_copy(&readback)
            .unwrap()
            .verify_second_copy(&readback)
            .unwrap();
        (source_root, stage_root, verified)
    }

    fn production_region(source: &str) -> &str {
        source.split("#[cfg(test)]\nmod tests").next().unwrap()
    }

    fn declaration_region<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        source
            .split_once(start)
            .unwrap()
            .1
            .split_once(end)
            .unwrap()
            .0
    }

    #[test]
    fn two_exact_readbacks_are_required_and_success_is_keyless() {
        let (source_root, _stage_root, backup) = verified_backup();
        let prepared = prepare_migration_recovery_key_custody(backup);
        let readback = *prepared.encoded_for_test();
        let first = prepared.disclose().verify_first_copy(&readback).unwrap();
        let verified = first.verify_second_copy(&readback).unwrap();
        let RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup {
            encrypted_stage,
            verified_envelope,
            custody,
        } = verified;
        assert_eq!(
            format!("{custody:?}"),
            "VerifiedMigrationRecoveryKeyCustody"
        );
        assert_eq!(verified_envelope.encoded.as_bytes().len(), 182);
        assert!(matches!(
            encrypted_stage.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        drop(source_root);
    }

    #[test]
    fn custody_verified_owner_prepares_manifest_from_fresh_retained_source_observations() {
        let (source_root, _stage_root, verified) = custody_verified_backup();
        let stage_bytes = fs::read(verified.encrypted_stage.stage_path_for_test()).unwrap();
        let envelope_bytes = *verified.verified_envelope.encoded.as_bytes();
        let expected_identifier =
            ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&envelope_bytes)
                .unwrap()
                .backup_set_identifier();
        let expected_database_digest: [u8; 32] = Sha256::digest(&stage_bytes).into();
        let expected_envelope_digest: [u8; 32] = Sha256::digest(envelope_bytes).into();

        let encoded = verified
            .prepare_recovery_set_manifest_v1()
            .unwrap()
            .encode();

        assert_eq!(encoded.len(), 98);
        assert_eq!(&encoded[10..26], &expected_identifier.bytes_for_test());
        assert_eq!(
            &encoded[26..34],
            &u64::try_from(stage_bytes.len()).unwrap().to_be_bytes()
        );
        assert_eq!(&encoded[34..66], &expected_database_digest);
        assert_eq!(&encoded[66..98], &expected_envelope_digest);
        assert!(stage_bytes.len() >= 512);

        assert_eq!(
            verified.verified_envelope.encoded.as_bytes(),
            &envelope_bytes
        );
        assert!(
            verified
                .encrypted_stage
                .backup_stage_proof
                .identity_is_unchanged()
        );
        assert_eq!(
            format!("{:?}", verified.custody),
            "VerifiedMigrationRecoveryKeyCustody"
        );
        let shutdown = verified.abort_for_shutdown();
        assert!(matches!(shutdown.source_close, SourceCloseState::Closed));
        drop(source_root);
    }

    #[test]
    fn custody_verified_owner_borrows_the_exact_verified_envelope_without_regeneration() {
        let (source_root, _stage_root, verified) = custody_verified_backup();
        let retained = *verified.verified_envelope.encoded.as_bytes();
        let borrowed = verified
            .with_verified_recovery_envelope_bytes(|bytes| *bytes)
            .unwrap();
        assert_eq!(borrowed, retained);

        let production = production_region(include_str!("custody.rs"));
        let boundary = declaration_region(
            production,
            "pub(crate) fn with_verified_recovery_envelope_bytes",
            "pub(crate) fn observe_recovery_database_source",
        );
        for required in [
            "&self",
            "impl FnOnce",
            "self.verified_envelope.encoded.as_bytes()",
            "ParsedUntrustedMigrationRecoveryEnvelopeV1::parse",
        ] {
            assert!(boundary.contains(required));
        }
        for forbidden in [
            "seal_migration_recovery_envelope_v1",
            "generate_migration_recovery_key_material",
            "generate_migration_backup_set_identifier",
            "open_migration_recovery_envelope_v1",
            "pub fn",
        ] {
            assert!(!boundary.contains(forbidden));
        }

        let shutdown = verified.abort_for_shutdown();
        assert!(matches!(shutdown.source_close, SourceCloseState::Closed));
        drop(source_root);
    }

    #[test]
    fn required_set_size_is_derived_from_the_trusted_manifest_source_observation() {
        let (source_root, _stage_root, verified) = custody_verified_backup();
        let database_length = verified
            .encrypted_stage
            .backup_stage_proof
            .leaf
            .metadata()
            .unwrap()
            .len();
        let manifest_length = u64::try_from(
            verified
                .prepare_recovery_set_manifest_v1()
                .unwrap()
                .encode()
                .len(),
        )
        .unwrap();
        let envelope_length =
            u64::try_from(verified.verified_envelope.encoded.as_bytes().len()).unwrap();
        let exact_requirement = database_length
            .checked_add(envelope_length)
            .and_then(|total| total.checked_add(manifest_length))
            .unwrap();

        let required = verified.prepare_recovery_set_required_bytes().unwrap();
        assert!(required.is_satisfied_by(exact_requirement));
        assert!(!required.is_satisfied_by(exact_requirement - 1));

        let shutdown = verified.abort_for_shutdown();
        assert!(matches!(shutdown.source_close, SourceCloseState::Closed));
        drop(source_root);
    }

    #[test]
    fn manifest_observation_identity_failure_is_redacted_and_preserves_owner() {
        let (source_root, _stage_root, verified) = custody_verified_backup();
        let (result, _) = super::super::test_orchestration::run(
            Some(super::super::TestFailurePoint::ManifestStageIdentity),
            false,
            || verified.prepare_recovery_set_manifest_v1(),
        );
        let error = result.unwrap_err();
        assert_eq!(
            error,
            RecoverySetManifestPreparationError::StageIdentityUnavailableOrChanged
        );
        assert_eq!(format!("{error:?}"), "StageIdentityUnavailableOrChanged");
        assert!(
            verified
                .encrypted_stage
                .backup_stage_proof
                .identity_is_unchanged()
        );
        let shutdown = verified.abort_for_shutdown();
        assert!(matches!(shutdown.source_close, SourceCloseState::Closed));
        drop(source_root);
    }

    #[test]
    fn manifest_preparation_errors_are_fixed_and_redacted() {
        for (error, expected) in [
            (
                RecoverySetManifestPreparationError::SourceObservationUnavailable,
                "SourceObservationUnavailable",
            ),
            (
                RecoverySetManifestPreparationError::StageIdentityUnavailableOrChanged,
                "StageIdentityUnavailableOrChanged",
            ),
            (
                RecoverySetManifestPreparationError::ManifestConstructionRejected,
                "ManifestConstructionRejected",
            ),
        ] {
            let debug = format!("{error:?}");
            assert_eq!(debug, expected);
            for sensitive in [
                "CHMRECV",
                "parish-data",
                "migration-backup",
                "182",
                "512",
                "sha256",
                "FileIdentity",
                "os error",
            ] {
                assert!(!debug.contains(sensitive));
            }
        }
    }

    #[test]
    fn manifest_preparation_surface_adds_no_authority_or_publication_capability() {
        let production = production_region(include_str!("custody.rs"));
        let boundary = declaration_region(
            production,
            "pub(crate) fn prepare_recovery_set_manifest_v1",
            "pub(crate) fn abort_for_shutdown",
        );
        for required in [
            "&self",
            "ParsedUntrustedMigrationRecoveryEnvelopeV1::parse",
            "observe_recovery_database_source",
            "Sha256::digest(envelope_bytes)",
            "RecoverySetManifestV1::from_trusted_internal_facts",
        ] {
            assert!(boundary.contains(required), "missing boundary: {required}");
        }
        for forbidden in [
            "File",
            "Path",
            "Connection",
            "authorization",
            "MigrationRecoveryKey",
            "custody:",
            "tauri::command",
            "publish",
            "destination",
            "device",
            "write(",
            "create(",
            "restore",
            "execute",
        ] {
            assert!(
                !boundary.contains(forbidden),
                "unexpected manifest-preparation capability: {forbidden}"
            );
        }
    }

    #[test]
    fn verified_owner_shutdown_consumes_authority_and_retries_only_source_close() {
        let (source_root, _stage_root, backup) = verified_backup();
        let prepared = prepare_migration_recovery_key_custody(backup);
        let readback = *prepared.encoded_for_test();
        let verified = prepared
            .disclose()
            .verify_first_copy(&readback)
            .unwrap()
            .verify_second_copy(&readback)
            .unwrap();
        let shutdown =
            with_production_database_close_failure_injected(|| verified.abort_for_shutdown());
        assert!(matches!(
            shutdown.source_close,
            SourceCloseState::RetryRequired(_)
        ));
        let UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome::Closed(shutdown) =
            shutdown.retry_source_close()
        else {
            panic!("verified shutdown must retry only the retained source close");
        };
        assert!(matches!(shutdown.source_close, SourceCloseState::Closed));
        drop(shutdown);
        drop(source_root);
    }

    #[test]
    fn failed_first_readback_is_terminal_and_pre_exposure_interruption_retries_whole_owner() {
        let (source_root, _stage_root, backup) = verified_backup();
        let prepared = prepare_migration_recovery_key_custody(backup);
        let prepared = prepared.cancel_before_exposure().retry();
        let readback = *prepared.encoded_for_test();
        let mut bad = readback;
        bad[37] = if bad[37] == b'0' { b'1' } else { b'0' };
        let failure = with_production_database_close_failure_injected(|| {
            prepared.disclose().verify_first_copy(&bad).unwrap_err()
        });
        assert_eq!(
            failure.category,
            MigrationRecoveryKeyCustodyError::FirstCustodyCopyVerificationFailed
        );
        assert!(matches!(
            failure.artifacts.source_close,
            SourceCloseState::RetryRequired(_)
        ));
        assert!(failure.artifacts.backup_stage_proof.identity_is_unchanged());
        assert_eq!(
            failure.artifacts.verified_envelope.encoded.as_bytes().len(),
            182
        );
        let MigrationRecoveryKeyCustodySourceCloseRetryOutcome::Closed(failure) =
            failure.retry_source_close()
        else {
            panic!("canonical source-close retry must close after injection ends");
        };
        assert!(matches!(
            failure.artifacts.source_close,
            SourceCloseState::Closed
        ));
        drop(source_root);
    }

    #[test]
    fn second_readback_failure_is_terminal_after_first_success() {
        let (source_root, _stage_root, backup) = verified_backup();
        let prepared = prepare_migration_recovery_key_custody(backup);
        let readback = *prepared.encoded_for_test();
        let first = prepared.disclose().verify_first_copy(&readback).unwrap();
        let mut bad = readback;
        bad[111] = if bad[111] == b'0' { b'1' } else { b'0' };
        let failure = first.verify_second_copy(&bad).unwrap_err();
        assert_eq!(
            failure.category,
            MigrationRecoveryKeyCustodyError::SecondCustodyCopyVerificationFailed
        );
        assert!(matches!(
            failure.artifacts.source_close,
            SourceCloseState::Closed
        ));
        drop(source_root);
    }

    #[test]
    fn state_surface_is_redacted_and_has_no_reverse_or_privileged_transition() {
        let source = include_str!("custody.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        for excluded in [
            "impl DisclosedMigrationRecoveryKeyCustody {\n    pub(crate) fn prepare",
            "publish",
            "restore",
            "execute",
            "tauri::command",
            "clipboard",
            "serde",
        ] {
            assert!(
                !production.contains(excluded),
                "excluded surface: {excluded}"
            );
        }
        assert!(production.contains("destroy_migration_authorization(authorization)"));
        assert!(production.contains("let source_close = close_source(source)"));
        assert!(!production.contains("MigrationRecoveryKey {"));
        assert!(!production.contains("GeneratedMigrationRecoveryKeyMaterial {"));
    }

    #[test]
    fn pre_exposure_interruption_preserves_exact_prepared_owner_and_artifacts() {
        let (source_root, _stage_root, backup) = verified_backup();
        let envelope_before = *backup.verified_envelope.encoded.as_bytes();
        assert!(
            backup
                .encrypted_stage
                .backup_stage_proof
                .identity_is_unchanged()
        );
        let prepared = prepare_migration_recovery_key_custody(backup);
        let encoded_before = *prepared.encoded_for_test();
        let prepared = prepared.cancel_before_exposure().retry();
        assert_eq!(prepared.encoded_for_test(), &encoded_before);
        assert_eq!(
            prepared.backup.verified_envelope.encoded.as_bytes(),
            &envelope_before
        );
        assert!(
            prepared
                .backup
                .encrypted_stage
                .backup_stage_proof
                .identity_is_unchanged()
        );
        let readback = *prepared.encoded_for_test();
        let verified = prepared
            .disclose()
            .verify_first_copy(&readback)
            .unwrap()
            .verify_second_copy(&readback)
            .unwrap();
        assert!(matches!(
            verified.encrypted_stage.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        drop(source_root);
    }

    #[test]
    fn pre_exposure_shutdown_is_terminal_secret_free_and_close_only_retryable() {
        let (source_root, _stage_root, backup) = verified_backup();
        let prepared = prepare_migration_recovery_key_custody(backup);
        let shutdown = with_production_database_close_failure_injected(|| {
            prepared.abort_before_exposure_for_shutdown()
        });
        assert_eq!(
            format!("{shutdown:?}"),
            "UndisclosedMigrationRecoveryKeyCustodyShutdown([REDACTED])"
        );

        let UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome::Failed(shutdown) =
            with_production_database_close_failure_injected(|| shutdown.retry_source_close())
        else {
            panic!("repeated injected close failure must preserve exact shutdown ownership");
        };
        let UndisclosedMigrationRecoveryKeyCustodyShutdownCloseRetryOutcome::Closed(shutdown) =
            shutdown.retry_source_close()
        else {
            panic!("close-only retry must eventually resolve the original shutdown");
        };
        drop(shutdown);
        drop(source_root);

        let production = production_region(include_str!("custody.rs"));
        let transition = declaration_region(
            production,
            "pub(crate) fn abort_before_exposure_for_shutdown",
            "#[cfg(test)]\n    fn encoded_for_test",
        );
        assert!(transition.contains("drop(encoded)"));
        assert!(transition.contains("drop(recovery_key_material)"));
        assert!(transition.contains("destroy_migration_authorization(authorization)"));
        assert!(transition.contains("close_source(source)"));
        for forbidden in [
            "disclose(",
            "run_migration_recovery_key_custody_native_ceremony",
            "retry(self) -> PreparedUndisclosedMigrationRecoveryKeyCustody",
            "publish",
            "execute(",
        ] {
            assert!(
                !transition.contains(forbidden),
                "forbidden shutdown work: {forbidden}"
            );
        }
    }

    #[test]
    fn cancellation_after_disclosure_is_terminal() {
        let (source_root, _stage_root, backup) = verified_backup();
        let failure = prepare_migration_recovery_key_custody(backup)
            .disclose()
            .cancel();
        assert_eq!(
            failure.category,
            MigrationRecoveryKeyCustodyError::CancelledAfterCustodyExposure
        );
        assert!(matches!(
            failure.artifacts.source_close,
            SourceCloseState::Closed
        ));
        assert!(failure.artifacts.backup_stage_proof.identity_is_unchanged());
        drop(source_root);
    }

    #[test]
    fn cancellation_after_first_verified_copy_is_terminal() {
        let (source_root, _stage_root, backup) = verified_backup();
        let prepared = prepare_migration_recovery_key_custody(backup);
        let readback = *prepared.encoded_for_test();
        let failure = prepared
            .disclose()
            .verify_first_copy(&readback)
            .unwrap()
            .cancel();
        assert_eq!(
            failure.category,
            MigrationRecoveryKeyCustodyError::CancelledAfterCustodyExposure
        );
        assert!(matches!(
            failure.artifacts.source_close,
            SourceCloseState::Closed
        ));
        assert!(failure.artifacts.backup_stage_proof.identity_is_unchanged());
        drop(source_root);
    }

    #[test]
    fn native_callback_panic_before_disclosure_preserves_prepared_ownership() {
        let (source_root, _stage_root, backup) = verified_backup();
        let prepared = prepare_migration_recovery_key_custody(backup);
        let outcome = native_windows::contain_pre_exposure_panic_for_test(prepared);
        let native_windows::NativeMigrationRecoveryKeyCustodyOutcome::UnavailableBeforeExposure(
            prepared,
        ) = outcome
        else {
            panic!("pre-exposure callback panic must preserve prepared ownership");
        };
        let failure = prepared.disclose().cancel();
        assert!(matches!(
            failure.artifacts.source_close,
            SourceCloseState::Closed
        ));
        drop(source_root);
    }

    #[test]
    fn native_callback_panic_after_disclosure_is_terminal() {
        let (source_root, _stage_root, backup) = verified_backup();
        let prepared = prepare_migration_recovery_key_custody(backup);
        let outcome = native_windows::contain_post_exposure_panic_for_test(prepared);
        let native_windows::NativeMigrationRecoveryKeyCustodyOutcome::FailedAfterExposure(failure) =
            outcome
        else {
            panic!("post-exposure callback panic must be terminal");
        };
        assert_eq!(
            failure.category,
            MigrationRecoveryKeyCustodyError::NativeCeremonyFailedAfterCustodyExposure
        );
        assert!(matches!(
            failure.artifacts.source_close,
            SourceCloseState::Closed
        ));
        drop(source_root);
    }

    #[test]
    fn success_preserves_exact_stage_and_envelope_owners() {
        let (source_root, _stage_root, backup) = verified_backup();
        let envelope_before = *backup.verified_envelope.encoded.as_bytes();
        assert!(
            backup
                .encrypted_stage
                .backup_stage_proof
                .identity_is_unchanged()
        );
        let prepared = prepare_migration_recovery_key_custody(backup);
        let readback = *prepared.encoded_for_test();
        let verified = prepared
            .disclose()
            .verify_first_copy(&readback)
            .unwrap()
            .verify_second_copy(&readback)
            .unwrap();
        assert_eq!(
            verified.verified_envelope.encoded.as_bytes(),
            &envelope_before
        );
        assert!(
            verified
                .encrypted_stage
                .backup_stage_proof
                .identity_is_unchanged()
        );
        assert!(matches!(
            verified.encrypted_stage.close(),
            ProductionDatabaseConnectionCloseOutcome::Closed
        ));
        drop(source_root);
    }

    #[test]
    fn source_close_retry_repeats_only_close_and_preserves_failure_artifacts() {
        let (source_root, _stage_root, backup) = verified_backup();
        let envelope_before = *backup.verified_envelope.encoded.as_bytes();
        let prepared = prepare_migration_recovery_key_custody(backup);
        let readback = *prepared.encoded_for_test();
        let failure = with_production_database_close_failure_injected(|| {
            prepared.disclose().verify_first_copy(&[]).unwrap_err()
        });
        assert!(matches!(
            failure.artifacts.source_close,
            SourceCloseState::RetryRequired(_)
        ));
        let MigrationRecoveryKeyCustodySourceCloseRetryOutcome::Failed(failure) =
            with_production_database_close_failure_injected(|| failure.retry_source_close())
        else {
            panic!("injected repeated close failure must retain retry ownership");
        };
        assert_eq!(
            failure.category,
            MigrationRecoveryKeyCustodyError::FirstCustodyCopyVerificationFailed
        );
        assert_eq!(
            failure.artifacts.verified_envelope.encoded.as_bytes(),
            &envelope_before
        );
        assert!(failure.artifacts.backup_stage_proof.identity_is_unchanged());
        assert!(matches!(
            failure.artifacts.source_close,
            SourceCloseState::RetryRequired(_)
        ));
        let MigrationRecoveryKeyCustodySourceCloseRetryOutcome::Closed(failure) =
            failure.retry_source_close()
        else {
            panic!("retry after injection must close");
        };
        assert_eq!(
            failure.artifacts.verified_envelope.encoded.as_bytes(),
            &envelope_before
        );
        assert!(failure.artifacts.backup_stage_proof.identity_is_unchanged());
        assert!(matches!(
            failure.artifacts.source_close,
            SourceCloseState::Closed
        ));
        assert_ne!(readback, [0; 196]);
        drop(source_root);
    }

    #[test]
    fn all_state_error_variants_have_fixed_redacted_debug() {
        for (error, expected) in [
            (
                MigrationRecoveryKeyCustodyError::CancelledBeforeCustodyExposure,
                "CancelledBeforeCustodyExposure",
            ),
            (
                MigrationRecoveryKeyCustodyError::CancelledAfterCustodyExposure,
                "CancelledAfterCustodyExposure",
            ),
            (
                MigrationRecoveryKeyCustodyError::NativeCeremonyFailedAfterCustodyExposure,
                "NativeCeremonyFailedAfterCustodyExposure",
            ),
            (
                MigrationRecoveryKeyCustodyError::FirstCustodyCopyVerificationFailed,
                "FirstCustodyCopyVerificationFailed",
            ),
            (
                MigrationRecoveryKeyCustodyError::SecondCustodyCopyVerificationFailed,
                "SecondCustodyCopyVerificationFailed",
            ),
        ] {
            let debug = format!("{error:?}");
            assert_eq!(debug, expected);
            for secret in ["GEN-", "KEY-", "CHK-", "40GJ", "position"] {
                assert!(!debug.contains(secret));
            }
        }
    }

    #[test]
    fn state_owner_surfaces_are_nonduplicable_and_secret_owners_need_drop() {
        let source = production_region(include_str!("custody.rs"));
        let owners = [
            (
                "pub(crate) struct PreparedUndisclosedMigrationRecoveryKeyCustody",
                "pub(crate) struct DisclosedMigrationRecoveryKeyCustody",
            ),
            (
                "pub(crate) struct DisclosedMigrationRecoveryKeyCustody",
                "pub(crate) struct FirstCopyVerifiedMigrationRecoveryKeyCustody",
            ),
            (
                "pub(crate) struct FirstCopyVerifiedMigrationRecoveryKeyCustody",
                "pub(crate) struct VerifiedMigrationRecoveryKeyCustody",
            ),
        ];
        for (start, end) in owners {
            let region = declaration_region(source, start, end);
            for forbidden in [
                "derive(Clone",
                "impl Clone",
                "impl Copy",
                "Serialize",
                "Deserialize",
                "impl fmt::Display",
                "impl Deref",
                "impl AsRef",
                "Into<String>",
                "-> String",
                "-> &[u8]",
            ] {
                assert!(!region.contains(forbidden), "{start}: {forbidden}");
            }
        }
        assert!(needs_drop::<PreparedUndisclosedMigrationRecoveryKeyCustody>());
        assert!(needs_drop::<DisclosedMigrationRecoveryKeyCustody>());
        assert!(needs_drop::<FirstCopyVerifiedMigrationRecoveryKeyCustody>());
    }

    #[test]
    fn preparation_and_association_have_only_the_whole_owner_input() {
        let source = production_region(include_str!("custody.rs"));
        assert!(source.contains(
            "pub(crate) fn prepare_migration_recovery_key_custody(\n    backup: VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup,"
        ));
        assert!(!source.contains("prepare_migration_recovery_key_custody(\n    recovery_key"));
        assert!(!source.contains("prepare_migration_recovery_key_custody(\n    generation"));
        assert!(!source.contains("prepare_migration_recovery_key_custody(\n    backup_set"));
        assert!(source.contains("custody_association(&backup.verified_envelope)"));
        assert!(source.contains("&backup.recovery_key_material"));
        assert!(
            source.contains("PreparedUndisclosedMigrationRecoveryKeyCustody { backup, encoded }")
        );
    }

    #[test]
    fn disclosure_is_irreversible_and_first_copy_cannot_finish_custody() {
        let source = production_region(include_str!("custody.rs"));
        let prepared = declaration_region(
            source,
            "impl PreparedUndisclosedMigrationRecoveryKeyCustody",
            "impl UndisclosedMigrationRecoveryKeyCustodyInterruption",
        );
        assert!(prepared.contains("fn disclose"));
        let disclosed = declaration_region(
            source,
            "impl DisclosedMigrationRecoveryKeyCustody",
            "impl FirstCopyVerifiedMigrationRecoveryKeyCustody",
        );
        let first = declaration_region(
            source,
            "impl FirstCopyVerifiedMigrationRecoveryKeyCustody",
            "fn terminal_failure",
        );
        for region in [disclosed, first] {
            assert!(!region.contains("-> PreparedUndisclosedMigrationRecoveryKeyCustody"));
            assert!(!region.contains("fn prepare"));
            assert!(!region.contains("fn disclose"));
        }
        assert!(!disclosed.contains("RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup"));
        assert!(!disclosed.contains("VerifiedMigrationRecoveryKeyCustody { _private"));
        assert!(first.contains("fn verify_second_copy"));
        for region in [disclosed, first] {
            for excluded in ["publish", "restore", "execute"] {
                assert!(!region.contains(excluded));
            }
        }
    }

    #[test]
    fn terminal_failures_and_keyless_success_have_exact_ownership_shapes() {
        let source = production_region(include_str!("custody.rs"));
        let failure_shape = declaration_region(
            source,
            "struct PossiblyExposedMigrationRecoveryKeyCustodyFailureArtifacts",
            "pub(crate) struct PossiblyExposedMigrationRecoveryKeyCustodyFailure",
        );
        assert!(failure_shape.contains("backup_stage_proof"));
        assert!(failure_shape.contains("verified_envelope"));
        assert!(failure_shape.contains("source_close"));
        for forbidden in [
            "recovery_key_material",
            "EncodedMigrationRecoveryKeyCustodyV1",
            "authorization",
            "source:",
        ] {
            assert!(!failure_shape.contains(forbidden));
        }
        let keyless_shape = declaration_region(
            source,
            "pub(crate) struct RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup",
            "struct PossiblyExposedMigrationRecoveryKeyCustodyFailureArtifacts",
        );
        assert!(keyless_shape.contains("encrypted_stage"));
        assert!(keyless_shape.contains("verified_envelope"));
        assert!(keyless_shape.contains("custody"));
        for forbidden in [
            "GeneratedMigrationRecoveryKeyMaterial",
            "MigrationRecoveryKey,",
            "EncodedMigrationRecoveryKeyCustodyV1",
            "[u8; 32]",
        ] {
            assert!(!keyless_shape.contains(forbidden));
        }
        let terminal = declaration_region(
            source,
            "fn terminal_failure",
            "impl PossiblyExposedMigrationRecoveryKeyCustodyFailure",
        );
        for evidence in [
            "drop(encoded);",
            "drop(recovery_key_material);",
            "destroy_migration_authorization(authorization);",
            "let source_close = close_source(source);",
        ] {
            assert!(terminal.contains(evidence));
        }
    }

    #[test]
    fn continuation_moves_existing_owners_and_close_retry_has_no_custody_work() {
        let source = production_region(include_str!("custody.rs"));
        let second = declaration_region(
            source,
            "impl FirstCopyVerifiedMigrationRecoveryKeyCustody",
            "fn terminal_failure",
        );
        assert!(second.contains(
            "RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup {\n                encrypted_stage,\n                verified_envelope,"
        ));
        assert!(!second.contains("VerifiedEncryptedProductionDatabaseMigrationBackupStage {"));
        assert!(!second.contains("IndependentlyVerifiedMigrationRecoveryEnvelopeV1 {"));

        let retry = source
            .split_once("impl PossiblyExposedMigrationRecoveryKeyCustodyFailure")
            .unwrap()
            .1
            .split_once("impl RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup")
            .unwrap()
            .0;
        assert!(retry.contains("retry_source_close_state(source_close)"));
        for excluded in [
            "validate_migration_recovery_key_custody_v1",
            "encode_migration_recovery_key_custody_v1",
            "disclose",
            "generate_",
            "custody_association",
            "fn retry_custody",
            "fn prepare",
            "fn reconstruct",
        ] {
            assert!(!retry.contains(excluded), "retry performed {excluded}");
        }
    }
}
