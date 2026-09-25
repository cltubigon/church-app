//! Private recovered-key verification of the already published first set.

#[path = "reentered_recovery_key_verification/first_complete_set.rs"]
mod first_complete_recovery_set_verification;

#[allow(unused_imports)]
pub(crate) use first_complete_recovery_set_verification::{
    FinalTwoSetVerificationError, FinalTwoSetVerificationFailure, FinalTwoSetVerificationOutcome,
    FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    FirstCompleteRecoverySetVerificationError, FirstCompleteRecoverySetVerificationFailure,
    FirstCompleteRecoverySetVerificationOutcome, FirstCompleteRecoverySetVerified,
    SecondCompleteRecoverySetVerificationError, SecondCompleteRecoverySetVerificationFailure,
    SecondCompleteRecoverySetVerificationOutcome,
    SecondCompleteRecoverySetVerificationVerifierCloseFailure, SecondCompleteRecoverySetVerified,
    TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
    verify_final_two_recovery_sets, verify_first_complete_recovery_set,
    verify_second_complete_recovery_set,
};

use std::{
    ffi::OsString,
    fmt,
    fs::File,
    io::{Seek, SeekFrom},
    os::windows::ffi::OsStringExt,
    path::PathBuf,
};

use rusqlite::Connection;

use crate::{
    production_database_connection_handoff::{
        ProductionDatabaseMigrationBackupStageVerifierOpenError,
        close_production_database_migration_backup_stage_verifier,
        observe_production_database_fixed_metadata_and_headers_on_borrowed_connection,
        open_production_database_migration_backup_stage_verifier,
        validate_production_database_cipher_integrity_on_borrowed_connection,
    },
    production_database_migration_recovery_envelope::{
        MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH, MigrationBackupStageSha256Digest,
        MigrationRecoveryKeyCustodyValidationError, ParsedUntrustedMigrationRecoveryEnvelopeV1,
        ReenteredMigrationRecoveryKeyCustodyV1, open_migration_recovery_envelope_v1,
    },
};

use super::*;

struct FreshDatabaseObservation {
    path: PathBuf,
    file: File,
    facts: super::super::super::PublishedDatabaseFacts,
}

pub(crate) struct FirstRecoverySetRecoveredKeyVerified {
    prior: FirstRecoverySetArtifactsPublished,
    _verified: (),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FirstRecoverySetRecoveredKeyVerificationError {
    SourceUnavailableOrChanged,
    DestinationChangedOrInconsistent,
    PriorArtifactChangedOrInvalid,
    CustodyRecordMalformedOrInvalid,
    CustodyRecordAssociationMismatch,
    EnvelopeVerificationFailed,
    DatabaseCorrespondenceFailed,
    RecoveredKeyDatabaseVerificationFailed,
    VerifierCloseFailed,
}

pub(crate) struct FirstRecoverySetRecoveredKeyVerificationFailure {
    prior: FirstRecoverySetArtifactsPublished,
    error: FirstRecoverySetRecoveredKeyVerificationError,
}

pub(crate) struct FirstRecoverySetRecoveredKeyVerificationVerifierCloseFailure {
    prior: FirstRecoverySetArtifactsPublished,
    error: FirstRecoverySetRecoveredKeyVerificationError,
    verifier: Connection,
}

#[must_use = "the recovered-key verification outcome must be handled"]
pub(crate) enum FirstRecoverySetRecoveredKeyVerificationOutcome {
    Verified(FirstRecoverySetRecoveredKeyVerified),
    Failed(FirstRecoverySetRecoveredKeyVerificationFailure),
    VerifierCloseFailed(FirstRecoverySetRecoveredKeyVerificationVerifierCloseFailure),
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
    FirstRecoverySetRecoveredKeyVerified,
    "FirstRecoverySetRecoveredKeyVerified"
);
redacted_debug!(
    FirstRecoverySetRecoveredKeyVerificationFailure,
    "FirstRecoverySetRecoveredKeyVerificationFailure"
);
redacted_debug!(
    FirstRecoverySetRecoveredKeyVerificationVerifierCloseFailure,
    "FirstRecoverySetRecoveredKeyVerificationVerifierCloseFailure"
);

impl fmt::Debug for FirstRecoverySetRecoveredKeyVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceUnavailableOrChanged => "SourceUnavailableOrChanged",
            Self::DestinationChangedOrInconsistent => "DestinationChangedOrInconsistent",
            Self::PriorArtifactChangedOrInvalid => "PriorArtifactChangedOrInvalid",
            Self::CustodyRecordMalformedOrInvalid => "CustodyRecordMalformedOrInvalid",
            Self::CustodyRecordAssociationMismatch => "CustodyRecordAssociationMismatch",
            Self::EnvelopeVerificationFailed => "EnvelopeVerificationFailed",
            Self::DatabaseCorrespondenceFailed => "DatabaseCorrespondenceFailed",
            Self::RecoveredKeyDatabaseVerificationFailed => {
                "RecoveredKeyDatabaseVerificationFailed"
            }
            Self::VerifierCloseFailed => "VerifierCloseFailed",
        })
    }
}

fn failed(
    prior: FirstRecoverySetArtifactsPublished,
    error: FirstRecoverySetRecoveredKeyVerificationError,
) -> FirstRecoverySetRecoveredKeyVerificationOutcome {
    FirstRecoverySetRecoveredKeyVerificationOutcome::Failed(
        FirstRecoverySetRecoveredKeyVerificationFailure { prior, error },
    )
}

fn map_prior_error(
    error: FirstRecoveryEnvelopeArtifactPublicationError,
) -> FirstRecoverySetRecoveredKeyVerificationError {
    match error {
        FirstRecoveryEnvelopeArtifactPublicationError::SourceUnavailableOrChanged => {
            FirstRecoverySetRecoveredKeyVerificationError::SourceUnavailableOrChanged
        }
        FirstRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent => {
            FirstRecoverySetRecoveredKeyVerificationError::DestinationChangedOrInconsistent
        }
        _ => FirstRecoverySetRecoveredKeyVerificationError::PriorArtifactChangedOrInvalid,
    }
}

fn revalidate_published_set(
    published: &mut FirstRecoverySetArtifactsPublished,
    expected_database_length: u64,
    expected_database_digest: [u8; 32],
    expected_envelope: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
    expected_manifest: &[u8; RECOVERY_SET_MANIFEST_V1_LENGTH],
) -> Result<(), FirstRecoverySetRecoveredKeyVerificationError> {
    published
        .prior
        .revalidate_for_manifest_publication(
            expected_database_length,
            expected_database_digest,
            expected_envelope,
        )
        .map_err(map_prior_error)?;
    let parent = &published.prior.prior.destinations.first.initial_child;
    let file = published
        .first_manifest
        .file
        .as_mut()
        .ok_or(FirstRecoverySetRecoveredKeyVerificationError::PriorArtifactChangedOrInvalid)?;
    let before = query_manifest_facts(file)
        .and_then(|facts| {
            validate_fresh_manifest_facts(&parent.identity, &parent.normalized_path, &facts)?;
            Ok(facts)
        })
        .map_err(|_| {
            FirstRecoverySetRecoveredKeyVerificationError::PriorArtifactChangedOrInvalid
        })?;
    if published.first_manifest.initial.as_ref() != Some(&before) {
        return Err(FirstRecoverySetRecoveredKeyVerificationError::PriorArtifactChangedOrInvalid);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| {
        FirstRecoverySetRecoveredKeyVerificationError::PriorArtifactChangedOrInvalid
    })?;
    verify_fresh_manifest_contents(file, expected_manifest).map_err(|_| {
        FirstRecoverySetRecoveredKeyVerificationError::PriorArtifactChangedOrInvalid
    })?;
    if query_manifest_facts(file).as_ref() != Ok(&before) {
        return Err(FirstRecoverySetRecoveredKeyVerificationError::PriorArtifactChangedOrInvalid);
    }
    published
        .prior
        .prior
        .destinations
        .revalidate()
        .map_err(|_| {
            FirstRecoverySetRecoveredKeyVerificationError::DestinationChangedOrInconsistent
        })
}

fn freshly_read_envelope(
    published: &FirstRecoverySetArtifactsPublished,
    expected: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
) -> Result<
    [u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
    FirstRecoverySetRecoveredKeyVerificationError,
> {
    let parent = &published.prior.prior.destinations.first.initial_child;
    let path = super::super::fixed_envelope_path(&parent.normalized_path);
    let mut reopened = super::super::open_envelope_for_verification(&path)
        .map_err(|_| FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed)?;
    let before = super::super::query_envelope_facts(&reopened)
        .and_then(|facts| {
            super::super::validate_fresh_envelope_facts(
                &parent.identity,
                &parent.normalized_path,
                &facts,
            )?;
            Ok(facts)
        })
        .map_err(|_| FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed)?;
    if published
        .prior
        .first_envelope
        .initial
        .as_ref()
        .map(|facts| &facts.identity)
        != Some(&before.identity)
    {
        return Err(FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed);
    }
    let mut fresh = [0_u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH];
    use std::io::Read;
    reopened
        .read_exact(&mut fresh)
        .map_err(|_| FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed)?;
    #[cfg(test)]
    FRESH_ENVELOPE_DIFFERENCE_INJECTED.with(|injected| {
        if injected.replace(false) {
            fresh[MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH - 1] ^= 1;
        }
    });
    let mut trailing = [0_u8; 1];
    if reopened
        .read(&mut trailing)
        .map_err(|_| FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed)?
        != 0
        || fresh != *expected
    {
        return Err(FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed);
    }
    if super::super::query_envelope_facts(&reopened).as_ref() != Ok(&before) {
        return Err(FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed);
    }
    Ok(fresh)
}

#[cfg(test)]
thread_local! {
    static FRESH_ENVELOPE_DIFFERENCE_INJECTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn with_fresh_envelope_difference_injected<T>(operation: impl FnOnce() -> T) -> T {
    FRESH_ENVELOPE_DIFFERENCE_INJECTED.with(|injected| {
        assert!(!injected.replace(true));
    });
    operation()
}

fn freshly_verify_database_correspondence(
    published: &FirstRecoverySetArtifactsPublished,
    expected_length: u64,
    expected_digest: [u8; 32],
) -> Result<FreshDatabaseObservation, FirstRecoverySetRecoveredKeyVerificationError> {
    let parent = &published.prior.prior.destinations.first.initial_child;
    let wide_path = super::super::super::fixed_database_path(&parent.normalized_path);
    let mut reopened = super::super::super::open_database_for_verification(&wide_path)
        .map_err(|_| FirstRecoverySetRecoveredKeyVerificationError::DatabaseCorrespondenceFailed)?;
    let before = super::super::super::query_database_facts(&reopened)
        .and_then(|facts| {
            super::super::super::validate_database_facts(
                &parent.identity,
                &parent.normalized_path,
                &facts,
            )?;
            Ok(facts)
        })
        .map_err(|_| FirstRecoverySetRecoveredKeyVerificationError::DatabaseCorrespondenceFailed)?;
    if before.byte_length != expected_length
        || published
            .prior
            .prior
            .first_database
            .initial
            .as_ref()
            .map(|facts| &facts.identity)
            != Some(&before.identity)
    {
        return Err(FirstRecoverySetRecoveredKeyVerificationError::DatabaseCorrespondenceFailed);
    }
    super::super::super::verify_fresh_contents(&mut reopened, expected_length, expected_digest)
        .map_err(|_| FirstRecoverySetRecoveredKeyVerificationError::DatabaseCorrespondenceFailed)?;
    if super::super::super::query_database_facts(&reopened).as_ref() != Ok(&before) {
        return Err(FirstRecoverySetRecoveredKeyVerificationError::DatabaseCorrespondenceFailed);
    }
    Ok(FreshDatabaseObservation {
        path: PathBuf::from(OsString::from_wide(&wide_path)),
        file: reopened,
        facts: before,
    })
}

pub(crate) fn verify_first_recovery_set_with_reentered_recovery_key(
    mut published: FirstRecoverySetArtifactsPublished,
    entered_record: ReenteredMigrationRecoveryKeyCustodyV1,
) -> FirstRecoverySetRecoveredKeyVerificationOutcome {
    let expected_database = match published
        .prior
        .prior
        .source
        .observe_recovery_database_source()
    {
        Ok(expected) => expected,
        Err(_) => {
            return failed(
                published,
                FirstRecoverySetRecoveredKeyVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_envelope = match published
        .prior
        .prior
        .source
        .with_verified_recovery_envelope_bytes(|bytes| *bytes)
    {
        Ok(expected) => expected,
        Err(_) => {
            return failed(
                published,
                FirstRecoverySetRecoveredKeyVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_manifest = match published
        .prior
        .prior
        .source
        .prepare_recovery_set_manifest_v1()
    {
        Ok(manifest) => manifest.encode(),
        Err(_) => {
            return failed(
                published,
                FirstRecoverySetRecoveredKeyVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    if let Err(error) = revalidate_published_set(
        &mut published,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &expected_manifest,
    ) {
        return failed(published, error);
    }
    let retained_envelope =
        match ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&expected_envelope) {
            Ok(parsed) => parsed,
            Err(_) => {
                return failed(
                    published,
                    FirstRecoverySetRecoveredKeyVerificationError::SourceUnavailableOrChanged,
                );
            }
        };
    let validated_record = match entered_record.validate_checksum_and_association(
        retained_envelope.recovery_key_generation_identifier(),
        retained_envelope.backup_set_identifier(),
    ) {
        Ok(material) => material,
        Err(
            MigrationRecoveryKeyCustodyValidationError::RecoveryKeyGenerationMismatch
            | MigrationRecoveryKeyCustodyValidationError::BackupSetMismatch,
        ) => {
            return failed(
                published,
                FirstRecoverySetRecoveredKeyVerificationError::CustodyRecordAssociationMismatch,
            );
        }
        Err(_) => {
            return failed(
                published,
                FirstRecoverySetRecoveredKeyVerificationError::CustodyRecordMalformedOrInvalid,
            );
        }
    };
    let fresh_envelope = match freshly_read_envelope(&published, &expected_envelope) {
        Ok(bytes) => bytes,
        Err(error) => return failed(published, error),
    };
    let recovery_key_material = validated_record.into_recovery_key_material();
    let parsed = match ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&fresh_envelope) {
        Ok(parsed) => parsed,
        Err(_) => {
            return failed(
                published,
                FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed,
            );
        }
    };
    let authenticated = match open_migration_recovery_envelope_v1(parsed, &recovery_key_material) {
        Ok(authenticated) => authenticated,
        Err(_) => {
            return failed(
                published,
                FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed,
            );
        }
    };
    drop(recovery_key_material);
    let matched = match authenticated.validate_payload_and_match_backup_set() {
        Ok(matched) => matched,
        Err(_) => {
            return failed(
                published,
                FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed,
            );
        }
    };
    let (candidate, authenticated_digest) = matched.release_database_key_candidate();
    if authenticated_digest
        != MigrationBackupStageSha256Digest::from_bytes(expected_database.database_sha256)
    {
        return failed(
            published,
            FirstRecoverySetRecoveredKeyVerificationError::DatabaseCorrespondenceFailed,
        );
    }
    let (recovered_key, expected_metadata) = match published
        .prior
        .prior
        .source
        .bind_recovered_database_key_candidate(candidate)
    {
        Ok(bound) => bound,
        Err(()) => {
            return failed(
                published,
                FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed,
            );
        }
    };
    let fresh_database = match freshly_verify_database_correspondence(
        &published,
        expected_database.database_byte_length,
        expected_database.database_sha256,
    ) {
        Ok(path) => path,
        Err(error) => return failed(published, error),
    };
    let verifier = match open_production_database_migration_backup_stage_verifier(
        &fresh_database.path,
        &recovered_key,
    ) {
        Ok(verifier) => verifier,
        Err(ProductionDatabaseMigrationBackupStageVerifierOpenError::Close(verifier)) => {
            drop(recovered_key);
            return FirstRecoverySetRecoveredKeyVerificationOutcome::VerifierCloseFailed(
                FirstRecoverySetRecoveredKeyVerificationVerifierCloseFailure {
                    prior: published,
                    error: FirstRecoverySetRecoveredKeyVerificationError::RecoveredKeyDatabaseVerificationFailed,
                    verifier,
                },
            );
        }
        Err(_) => {
            drop(recovered_key);
            return failed(
                published,
                FirstRecoverySetRecoveredKeyVerificationError::RecoveredKeyDatabaseVerificationFailed,
            );
        }
    };
    drop(recovered_key);
    let verification =
        validate_production_database_cipher_integrity_on_borrowed_connection(&verifier)
            .map_err(|_| ())
            .and_then(|_| {
                if observe_production_database_fixed_metadata_and_headers_on_borrowed_connection(
                    &verifier,
                )
                .as_ref()
                    == Ok(&expected_metadata)
                {
                    Ok(())
                } else {
                    Err(())
                }
            });
    let close_result = close_production_database_migration_backup_stage_verifier(verifier);
    if let Err(verifier) = close_result {
        return FirstRecoverySetRecoveredKeyVerificationOutcome::VerifierCloseFailed(
            FirstRecoverySetRecoveredKeyVerificationVerifierCloseFailure {
                prior: published,
                error: if verification.is_ok() {
                    FirstRecoverySetRecoveredKeyVerificationError::VerifierCloseFailed
                } else {
                    FirstRecoverySetRecoveredKeyVerificationError::RecoveredKeyDatabaseVerificationFailed
                },
                verifier,
            },
        );
    }
    if verification.is_err() {
        return failed(
            published,
            FirstRecoverySetRecoveredKeyVerificationError::RecoveredKeyDatabaseVerificationFailed,
        );
    }
    if super::super::super::query_database_facts(&fresh_database.file).as_ref()
        != Ok(&fresh_database.facts)
    {
        return failed(
            published,
            FirstRecoverySetRecoveredKeyVerificationError::DatabaseCorrespondenceFailed,
        );
    }
    if let Err(error) = revalidate_published_set(
        &mut published,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &expected_manifest,
    ) {
        return failed(published, error);
    }
    if published
        .prior
        .prior
        .source
        .observe_recovery_database_source()
        .as_ref()
        != Ok(&expected_database)
        || published
            .prior
            .prior
            .source
            .with_verified_recovery_envelope_bytes(|bytes| *bytes)
            .as_ref()
            != Ok(&expected_envelope)
    {
        return failed(
            published,
            FirstRecoverySetRecoveredKeyVerificationError::SourceUnavailableOrChanged,
        );
    }
    FirstRecoverySetRecoveredKeyVerificationOutcome::Verified(
        FirstRecoverySetRecoveredKeyVerified {
            prior: published,
            _verified: (),
        },
    )
}

impl FirstRecoverySetRecoveredKeyVerificationVerifierCloseFailure {
    pub(crate) fn category(&self) -> FirstRecoverySetRecoveredKeyVerificationError {
        self.error
    }

    pub(crate) fn retry_close(self) -> FirstRecoverySetRecoveredKeyVerificationOutcome {
        let Self {
            prior,
            error,
            verifier,
        } = self;
        match close_production_database_migration_backup_stage_verifier(verifier) {
            Ok(()) => FirstRecoverySetRecoveredKeyVerificationOutcome::Failed(
                FirstRecoverySetRecoveredKeyVerificationFailure { prior, error },
            ),
            Err(verifier) => FirstRecoverySetRecoveredKeyVerificationOutcome::VerifierCloseFailed(
                FirstRecoverySetRecoveredKeyVerificationVerifierCloseFailure {
                    prior,
                    error,
                    verifier,
                },
            ),
        }
    }
}

impl FirstRecoverySetRecoveredKeyVerificationFailure {
    pub(crate) fn category(&self) -> FirstRecoverySetRecoveredKeyVerificationError {
        self.error
    }

    pub(crate) fn retry_with_fresh_record(
        self,
        entered_record: ReenteredMigrationRecoveryKeyCustodyV1,
    ) -> FirstRecoverySetRecoveredKeyVerificationOutcome {
        verify_first_recovery_set_with_reentered_recovery_key(self.prior, entered_record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        mem::needs_drop,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::{
        application_lifecycle::{
            PreparedProductionDatabaseMigrationBackupStage,
            ProductionDatabaseMigrationBackupContext,
            ProductionDatabaseMigrationBackupStageOutcome,
            ProductionDatabaseMigrationRecoveryEnvelopeOutcome,
            genuine_full_integrity_validated_migration_handoff_for_test,
            prepare_migration_recovery_key_custody,
            stage_encrypted_production_database_migration_backup,
            verify_production_database_migration_recovery_envelope,
        },
        database_key::DatabaseKey,
        installation_evidence_contract::DatabaseKeyGenerationIdentifier,
        installation_evidence_protection::protect_database_key,
        production_database_connection_handoff::with_production_database_close_failure_injected,
        production_database_migration_recovery_envelope::{
            ReenteredMigrationRecoveryKeyCustodyV1, correctly_associated_wrong_key_record_for_test,
        },
        storage_foundation::database_key_persistence_paths,
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn create(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "church-app-reentered-verification-{label}-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct PublishedFixture {
        published: Option<FirstRecoverySetArtifactsPublished>,
        record: [u8; 196],
        _destination_root: TestRoot,
        _stage_root: TestRoot,
        _source_root: crate::production_database_connection_handoff::MigrationDiscoveryTestRoot,
    }

    fn published_fixture() -> PublishedFixture {
        let (source_root, handoff) = genuine_full_integrity_validated_migration_handoff_for_test();
        let paths = database_key_persistence_paths(source_root.path());
        fs::create_dir_all(paths.database_key_directory.as_path()).unwrap();
        let key = DatabaseKey::from_bytes([0x74; 32]);
        let generation = DatabaseKeyGenerationIdentifier::from_bytes([0x43; 16]).unwrap();
        let wrapper = protect_database_key(&key, generation).unwrap();
        fs::write(paths.active_database_key.as_path(), wrapper.as_bytes()).unwrap();

        let stage_root = TestRoot::create("stage");
        let prepared = PreparedProductionDatabaseMigrationBackupStage::from_synthetic_temp_root(
            stage_root.path(),
        )
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
        let ProductionDatabaseMigrationRecoveryEnvelopeOutcome::Verified(enveloped) =
            verify_production_database_migration_recovery_envelope(stage)
        else {
            panic!("envelope fixture must verify");
        };
        let prepared_custody = prepare_migration_recovery_key_custody(enveloped);
        let record = *prepared_custody.encoded_for_test();
        let source = prepared_custody
            .disclose()
            .verify_first_copy(&record)
            .unwrap()
            .verify_second_copy(&record)
            .unwrap();

        let destination_root = TestRoot::create("destination");
        let first = destination_root.path().join("first");
        let second = destination_root.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let destinations =
            super::super::super::super::super::retained_recovery_set_directories_for_test(
                &first, &second,
            );
        let database = super::super::super::super::publish_first_recovery_database_artifact(
            source,
            destinations,
        )
        .unwrap();
        let envelope =
            super::super::super::publish_first_recovery_envelope_artifact(database).unwrap();
        let published = super::super::publish_first_recovery_manifest_artifact(envelope).unwrap();

        PublishedFixture {
            published: Some(published),
            record,
            _destination_root: destination_root,
            _stage_root: stage_root,
            _source_root: source_root,
        }
    }

    fn publish_complete_second_set(
        fixture: &mut PublishedFixture,
    ) -> FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished {
        let entered =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&fixture.record).unwrap();
        let FirstRecoverySetRecoveredKeyVerificationOutcome::Verified(verified) =
            verify_first_recovery_set_with_reentered_recovery_key(
                fixture.published.take().unwrap(),
                entered,
            )
        else {
            panic!("the first recovered-key predecessor must verify");
        };
        let FirstCompleteRecoverySetVerificationOutcome::Verified(complete) =
            verify_first_complete_recovery_set(verified)
        else {
            panic!("the first complete set must verify");
        };
        let database =
            first_complete_recovery_set_verification::publish_second_recovery_database_artifact(
                complete,
            )
            .unwrap();
        let envelope =
            first_complete_recovery_set_verification::publish_second_recovery_envelope_artifact(
                database,
            )
            .unwrap();
        first_complete_recovery_set_verification::publish_second_recovery_manifest_artifact(
            envelope,
        )
        .unwrap()
    }

    fn first_set_bytes(fixture: &PublishedFixture) -> [Vec<u8>; 3] {
        let first = fixture._destination_root.path().join("first");
        [
            fs::read(first.join(crate::storage_foundation::PRODUCTION_DATABASE_FILENAME)).unwrap(),
            fs::read(first.join(super::super::super::FIRST_RECOVERY_ENVELOPE_FILENAME)).unwrap(),
            fs::read(first.join(super::super::FIRST_RECOVERY_MANIFEST_FILENAME)).unwrap(),
        ]
    }

    #[test]
    fn manifest_success_abandonment_leaves_all_artifacts_and_returns_shutdown_source() {
        let mut fixture = published_fixture();
        let before = first_set_bytes(&fixture);
        let source = fixture
            .published
            .take()
            .unwrap()
            .abandon_published_destination_and_retain_source();
        assert_eq!(first_set_bytes(&fixture), before);
        let shutdown = source.abort_for_shutdown();
        let _close_outcome = shutdown.retry_source_close();
    }

    #[test]
    fn manifest_failure_abandonment_leaves_existing_artifacts_and_returns_shutdown_source() {
        let mut fixture = published_fixture();
        let before = first_set_bytes(&fixture);
        let FirstRecoverySetArtifactsPublished {
            prior,
            first_manifest,
        } = fixture.published.take().unwrap();
        drop(first_manifest);
        let failure = super::super::publish_first_recovery_manifest_artifact(prior).unwrap_err();
        let source = failure.abandon_partial_destination_and_retain_source();
        assert_eq!(first_set_bytes(&fixture), before);
        let shutdown = source.abort_for_shutdown();
        let _close_outcome = shutdown.retry_source_close();
    }

    #[test]
    fn outward_owners_are_keyless_and_success_is_not_complete_set_proof() {
        assert!(needs_drop::<FirstRecoverySetRecoveredKeyVerified>());
        assert!(needs_drop::<FirstRecoverySetRecoveredKeyVerificationFailure>());
        let source = include_str!("reentered_recovery_key_verification.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        let success = production
            .split_once("pub(crate) struct FirstRecoverySetRecoveredKeyVerified {")
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        assert!(success.contains("prior: FirstRecoverySetArtifactsPublished"));
        for forbidden in [
            "MigrationRecoveryKey",
            "GeneratedMigrationRecoveryKeyMaterial",
            "GenerationBoundDatabaseKey",
            "ReenteredMigrationRecoveryKeyCustodyV1",
            "String",
        ] {
            assert!(!success.contains(forbidden));
        }
        assert!(!production.contains("ReadDirectoryChangesW"));
        assert!(!production.contains("FindFirstFileW"));
        assert!(!production.contains("set_2"));
        assert!(!production.contains("tauri::command"));
        assert!(!production.contains("restore"));
        assert!(!production.contains("migration execution"));
        assert!(production.contains("retry_with_fresh_record"));
    }

    #[test]
    fn production_signature_accepts_only_published_owner_and_owned_record() {
        let source = include_str!("reentered_recovery_key_verification.rs");
        assert!(source.contains(
            "mut published: FirstRecoverySetArtifactsPublished,\n    entered_record: ReenteredMigrationRecoveryKeyCustodyV1,"
        ));
        for forbidden in [
            "PathBuf,\n    mut published",
            "MigrationRecoveryKey,\n    mut published",
        ] {
            assert!(!source.contains(forbidden));
        }
    }

    #[test]
    fn verification_composes_fresh_reopen_crypto_correspondence_and_sqlcipher_primitives() {
        let source = include_str!("reentered_recovery_key_verification.rs");
        for required in [
            "open_envelope_for_verification",
            "query_envelope_facts",
            "verify_fresh_envelope_contents",
            "open_migration_recovery_envelope_v1",
            "release_database_key_candidate",
            "open_database_for_verification",
            "verify_fresh_contents",
            "open_production_database_migration_backup_stage_verifier",
            "validate_production_database_cipher_integrity_on_borrowed_connection",
            "observe_production_database_fixed_metadata_and_headers_on_borrowed_connection",
            "close_production_database_migration_backup_stage_verifier",
        ] {
            assert!(source.contains(required), "missing primitive: {required}");
        }
    }

    #[test]
    fn valid_reentered_record_runs_first_complete_recovery_set_transition() {
        let mut fixture = published_fixture();
        let entered =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&fixture.record).unwrap();
        let outcome = verify_first_recovery_set_with_reentered_recovery_key(
            fixture.published.take().unwrap(),
            entered,
        );
        let FirstRecoverySetRecoveredKeyVerificationOutcome::Verified(verified) = outcome else {
            panic!("valid published first set and bearer record must verify");
        };
        assert_eq!(
            format!("{verified:?}"),
            "FirstRecoverySetRecoveredKeyVerified([REDACTED])"
        );
        let FirstCompleteRecoverySetVerificationOutcome::Verified(complete) =
            verify_first_complete_recovery_set(verified)
        else {
            panic!("the exact freshly verified first recovery set must be complete");
        };
        assert_eq!(
            format!("{complete:?}"),
            "FirstCompleteRecoverySetVerified([REDACTED])"
        );
        drop(complete);
    }

    #[test]
    fn verified_first_set_publishes_only_second_database_from_original_stage() {
        use crate::storage_foundation::{
            PRODUCTION_DATABASE_FILENAME, PRODUCTION_DATABASE_MIGRATION_BACKUP_STAGE_FILENAME,
        };

        let mut fixture = published_fixture();
        let first_set = fixture._destination_root.path().join("first");
        let second_set = fixture._destination_root.path().join("second");
        let first_database_path = first_set.join(PRODUCTION_DATABASE_FILENAME);
        let first_envelope_path = first_set.join("migration-recovery-envelope-v1.bin");
        let first_manifest_path = first_set.join("recovery-set-v1.manifest");
        let second_database_path = second_set.join(PRODUCTION_DATABASE_FILENAME);
        let original_stage_path = fixture
            ._stage_root
            .path()
            .join(PRODUCTION_DATABASE_MIGRATION_BACKUP_STAGE_FILENAME);
        let original_stage = fs::read(&original_stage_path).unwrap();
        let first_database_before = fs::read(&first_database_path).unwrap();
        let first_envelope_before = fs::read(&first_envelope_path).unwrap();
        let first_manifest_before = fs::read(&first_manifest_path).unwrap();
        assert_eq!(first_database_before, original_stage);
        assert!(fs::read_dir(&second_set).unwrap().next().is_none());

        let entered =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&fixture.record).unwrap();
        let FirstRecoverySetRecoveredKeyVerificationOutcome::Verified(verified) =
            verify_first_recovery_set_with_reentered_recovery_key(
                fixture.published.take().unwrap(),
                entered,
            )
        else {
            panic!("the recovered-key predecessor must verify");
        };
        let FirstCompleteRecoverySetVerificationOutcome::Verified(complete) =
            verify_first_complete_recovery_set(verified)
        else {
            panic!("the first set must independently verify as complete");
        };
        let published =
            first_complete_recovery_set_verification::publish_second_recovery_database_artifact(
                complete,
            )
            .unwrap();
        assert_eq!(
            format!("{published:?}"),
            "FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished([REDACTED])"
        );

        let second_database = fs::read(&second_database_path).unwrap();
        assert_eq!(second_database, original_stage);
        assert_eq!(
            fs::read(&first_database_path).unwrap(),
            first_database_before
        );
        assert_eq!(
            fs::read(&first_envelope_path).unwrap(),
            first_envelope_before
        );
        assert_eq!(
            fs::read(&first_manifest_path).unwrap(),
            first_manifest_before
        );
        assert!(
            !second_set
                .join("migration-recovery-envelope-v1.bin")
                .exists()
        );
        assert!(!second_set.join("recovery-set-v1.manifest").exists());

        use std::os::windows::ffi::OsStrExt;
        let second_database_wide: Vec<u16> =
            second_database_path.as_os_str().encode_wide().collect();
        assert_eq!(
            super::super::super::super::create_new_database(&second_database_wide).unwrap_err(),
            super::super::super::super::FirstRecoveryDatabaseArtifactPublicationError::ArtifactConflict
        );
        drop(published);
    }

    #[test]
    fn second_database_owner_publishes_only_original_second_envelope_create_new() {
        use crate::storage_foundation::{
            PRODUCTION_DATABASE_FILENAME, PRODUCTION_DATABASE_MIGRATION_BACKUP_STAGE_FILENAME,
        };

        let mut fixture = published_fixture();
        let first_set = fixture._destination_root.path().join("first");
        let second_set = fixture._destination_root.path().join("second");
        let first_database_path = first_set.join(PRODUCTION_DATABASE_FILENAME);
        let first_envelope_path = first_set.join("migration-recovery-envelope-v1.bin");
        let first_manifest_path = first_set.join("recovery-set-v1.manifest");
        let second_database_path = second_set.join(PRODUCTION_DATABASE_FILENAME);
        let second_envelope_path = second_set.join("migration-recovery-envelope-v1.bin");
        let second_manifest_path = second_set.join("recovery-set-v1.manifest");
        let original_stage = fs::read(
            fixture
                ._stage_root
                .path()
                .join(PRODUCTION_DATABASE_MIGRATION_BACKUP_STAGE_FILENAME),
        )
        .unwrap();
        let first_database_before = fs::read(&first_database_path).unwrap();
        let first_envelope_before = fs::read(&first_envelope_path).unwrap();
        let first_manifest_before = fs::read(&first_manifest_path).unwrap();

        let entered =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&fixture.record).unwrap();
        let FirstRecoverySetRecoveredKeyVerificationOutcome::Verified(verified) =
            verify_first_recovery_set_with_reentered_recovery_key(
                fixture.published.take().unwrap(),
                entered,
            )
        else {
            panic!("the recovered-key predecessor must verify");
        };
        let FirstCompleteRecoverySetVerificationOutcome::Verified(complete) =
            verify_first_complete_recovery_set(verified)
        else {
            panic!("the first set must independently verify as complete");
        };
        let database =
            first_complete_recovery_set_verification::publish_second_recovery_database_artifact(
                complete,
            )
            .unwrap();
        assert!(!second_envelope_path.exists());
        let published =
            first_complete_recovery_set_verification::publish_second_recovery_envelope_artifact(
                database,
            )
            .unwrap();
        assert_eq!(
            format!("{published:?}"),
            "FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished([REDACTED])"
        );
        assert_eq!(fs::read(&second_database_path).unwrap(), original_stage);
        assert_eq!(
            fs::read(&second_envelope_path).unwrap(),
            first_envelope_before
        );
        assert_eq!(
            fs::read(&first_database_path).unwrap(),
            first_database_before
        );
        assert_eq!(
            fs::read(&first_envelope_path).unwrap(),
            first_envelope_before
        );
        assert_eq!(
            fs::read(&first_manifest_path).unwrap(),
            first_manifest_before
        );
        assert!(!second_manifest_path.exists());

        use std::os::windows::ffi::OsStrExt;
        let second_envelope_wide: Vec<u16> =
            second_envelope_path.as_os_str().encode_wide().collect();
        assert_eq!(
            super::super::super::create_new_envelope(&second_envelope_wide).unwrap_err(),
            super::super::super::FirstRecoveryEnvelopeArtifactPublicationError::ArtifactConflict
        );
        drop(published);
    }

    #[test]
    fn second_envelope_owner_publishes_manifest_last_from_original_source_facts() {
        use crate::storage_foundation::PRODUCTION_DATABASE_FILENAME;

        let mut fixture = published_fixture();
        let first_set = fixture._destination_root.path().join("first");
        let second_set = fixture._destination_root.path().join("second");
        let first_database_path = first_set.join(PRODUCTION_DATABASE_FILENAME);
        let first_envelope_path = first_set.join("migration-recovery-envelope-v1.bin");
        let first_manifest_path = first_set.join("recovery-set-v1.manifest");
        let second_database_path = second_set.join(PRODUCTION_DATABASE_FILENAME);
        let second_envelope_path = second_set.join("migration-recovery-envelope-v1.bin");
        let second_manifest_path = second_set.join("recovery-set-v1.manifest");
        let trusted_source_manifest = fixture
            .published
            .as_ref()
            .unwrap()
            .prior
            .prior
            .source
            .prepare_recovery_set_manifest_v1()
            .unwrap()
            .encode();
        let first_database_before = fs::read(&first_database_path).unwrap();
        let first_envelope_before = fs::read(&first_envelope_path).unwrap();
        let first_manifest_before = fs::read(&first_manifest_path).unwrap();

        let entered =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&fixture.record).unwrap();
        let FirstRecoverySetRecoveredKeyVerificationOutcome::Verified(verified) =
            verify_first_recovery_set_with_reentered_recovery_key(
                fixture.published.take().unwrap(),
                entered,
            )
        else {
            panic!("the recovered-key predecessor must verify");
        };
        let FirstCompleteRecoverySetVerificationOutcome::Verified(complete) =
            verify_first_complete_recovery_set(verified)
        else {
            panic!("the first set must independently verify as complete");
        };
        let database =
            first_complete_recovery_set_verification::publish_second_recovery_database_artifact(
                complete,
            )
            .unwrap();
        let envelope =
            first_complete_recovery_set_verification::publish_second_recovery_envelope_artifact(
                database,
            )
            .unwrap();
        let second_database_before = fs::read(&second_database_path).unwrap();
        let second_envelope_before = fs::read(&second_envelope_path).unwrap();
        assert!(!second_manifest_path.exists());

        let published =
            first_complete_recovery_set_verification::publish_second_recovery_manifest_artifact(
                envelope,
            )
            .unwrap();
        let debug = format!("{published:?}");
        assert_eq!(
            debug,
            "FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished([REDACTED])"
        );
        assert!(!debug.contains("CompleteSecondRecoverySet"));
        let second_manifest = fs::read(&second_manifest_path).unwrap();
        assert_eq!(second_manifest.len(), RECOVERY_SET_MANIFEST_V1_LENGTH);
        assert_eq!(second_manifest, trusted_source_manifest);
        assert_eq!(second_manifest, first_manifest_before);
        assert_eq!(
            fs::read(&first_database_path).unwrap(),
            first_database_before
        );
        assert_eq!(
            fs::read(&first_envelope_path).unwrap(),
            first_envelope_before
        );
        assert_eq!(
            fs::read(&first_manifest_path).unwrap(),
            first_manifest_before
        );
        assert_eq!(
            fs::read(&second_database_path).unwrap(),
            second_database_before
        );
        assert_eq!(
            fs::read(&second_envelope_path).unwrap(),
            second_envelope_before
        );

        let mut names: Vec<_> = fs::read_dir(&second_set)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                std::ffi::OsString::from("migration-recovery-envelope-v1.bin"),
                std::ffi::OsString::from("parish-data.db"),
                std::ffi::OsString::from("recovery-set-v1.manifest"),
            ]
        );

        use std::os::windows::ffi::OsStrExt;
        let second_manifest_wide: Vec<u16> =
            second_manifest_path.as_os_str().encode_wide().collect();
        assert_eq!(
            super::super::create_new_manifest(&second_manifest_wide).unwrap_err(),
            super::super::FirstRecoveryManifestArtifactPublicationError::ArtifactConflict
        );
        drop(published);
    }

    #[test]
    fn correctly_associated_wrong_key_fails_envelope_authentication_and_retry_needs_fresh_record() {
        let mut fixture = published_fixture();
        let wrong = correctly_associated_wrong_key_record_for_test(&fixture.record);
        let outcome = verify_first_recovery_set_with_reentered_recovery_key(
            fixture.published.take().unwrap(),
            wrong,
        );
        let FirstRecoverySetRecoveredKeyVerificationOutcome::Failed(failure) = outcome else {
            panic!("wrong recovery key must fail without verifier-close ownership");
        };
        assert_eq!(
            failure.category(),
            FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed
        );
        let fresh =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&fixture.record).unwrap();
        assert!(matches!(
            failure.retry_with_fresh_record(fresh),
            FirstRecoverySetRecoveredKeyVerificationOutcome::Verified(_)
        ));
    }

    #[test]
    fn changed_fresh_destination_envelope_cannot_fall_back_to_retained_expected_bytes() {
        let mut fixture = published_fixture();
        let entered =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&fixture.record).unwrap();
        let outcome = with_fresh_envelope_difference_injected(|| {
            verify_first_recovery_set_with_reentered_recovery_key(
                fixture.published.take().unwrap(),
                entered,
            )
        });
        let FirstRecoverySetRecoveredKeyVerificationOutcome::Failed(failure) = outcome else {
            panic!("changed fresh destination bytes must fail");
        };
        assert_eq!(
            failure.category(),
            FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed
        );
    }

    #[test]
    fn layout_change_across_complete_set_verification_fails_and_preserves_retry() {
        let mut fixture = published_fixture();
        let entered =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&fixture.record).unwrap();
        let FirstRecoverySetRecoveredKeyVerificationOutcome::Verified(verified) =
            verify_first_recovery_set_with_reentered_recovery_key(
                fixture.published.take().unwrap(),
                entered,
            )
        else {
            panic!("recovered-key predecessor must verify");
        };
        let outcome =
            first_complete_recovery_set_verification::with_second_layout_observation_failure(
                || verify_first_complete_recovery_set(verified),
            );
        let FirstCompleteRecoverySetVerificationOutcome::Failed(failure) = outcome else {
            panic!("a failed second layout observation must fail closed");
        };
        assert_eq!(
            failure.category(),
            FirstCompleteRecoverySetVerificationError::DirectoryLayoutInvalid
        );
        assert!(matches!(
            failure.retry(),
            FirstCompleteRecoverySetVerificationOutcome::Verified(_)
        ));
    }

    #[test]
    fn material_release_is_structurally_after_fresh_correspondence() {
        let source = include_str!("reentered_recovery_key_verification.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        let transition = production
            .split_once("pub(crate) fn verify_first_recovery_set_with_reentered_recovery_key")
            .unwrap()
            .1;
        let association = transition
            .find("validate_checksum_and_association")
            .unwrap();
        let fresh = transition.find("freshly_read_envelope").unwrap();
        let release = transition.find("into_recovery_key_material").unwrap();
        let parse = transition
            .find("ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&fresh_envelope)")
            .unwrap();
        let authenticate = transition
            .find("open_migration_recovery_envelope_v1")
            .unwrap();
        assert!(association < fresh && fresh < release && release < parse && parse < authenticate);
        assert!(!production.contains("Ok(*expected)"));
    }

    #[test]
    fn genuine_final_two_set_verification_is_keyless_and_preserves_both_sets() {
        use crate::storage_foundation::{
            PRODUCTION_DATABASE_FILENAME, PRODUCTION_DATABASE_MIGRATION_BACKUP_STAGE_FILENAME,
        };

        let mut fixture = published_fixture();
        let first_set = fixture._destination_root.path().join("first");
        let second_set = fixture._destination_root.path().join("second");
        let source_database = fs::read(
            fixture
                ._stage_root
                .path()
                .join(PRODUCTION_DATABASE_MIGRATION_BACKUP_STAGE_FILENAME),
        )
        .unwrap();
        let published = publish_complete_second_set(&mut fixture);
        let first_before = [
            fs::read(first_set.join(PRODUCTION_DATABASE_FILENAME)).unwrap(),
            fs::read(first_set.join("migration-recovery-envelope-v1.bin")).unwrap(),
            fs::read(first_set.join("recovery-set-v1.manifest")).unwrap(),
        ];
        let second_before = [
            fs::read(second_set.join(PRODUCTION_DATABASE_FILENAME)).unwrap(),
            fs::read(second_set.join("migration-recovery-envelope-v1.bin")).unwrap(),
            fs::read(second_set.join("recovery-set-v1.manifest")).unwrap(),
        ];
        let fresh =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&fixture.record).unwrap();
        let SecondCompleteRecoverySetVerificationOutcome::Verified(second_complete) =
            verify_second_complete_recovery_set(published, fresh)
        else {
            panic!("the independently reopened second complete set must verify");
        };
        assert_eq!(
            format!("{second_complete:?}"),
            "SecondCompleteRecoverySetVerified([REDACTED])"
        );
        let FinalTwoSetVerificationOutcome::Verified(verified) =
            verify_final_two_recovery_sets(second_complete)
        else {
            panic!("the final aggregate two-set proof must verify");
        };
        assert_eq!(
            format!("{verified:?}"),
            "TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup([REDACTED])"
        );
        assert_eq!(first_before[0], source_database);
        assert_eq!(second_before[0], source_database);
        assert_eq!(first_before[1], second_before[1]);
        assert_eq!(first_before[2], second_before[2]);
        assert_eq!(
            first_before,
            [
                fs::read(first_set.join(PRODUCTION_DATABASE_FILENAME)).unwrap(),
                fs::read(first_set.join("migration-recovery-envelope-v1.bin")).unwrap(),
                fs::read(first_set.join("recovery-set-v1.manifest")).unwrap(),
            ]
        );
        assert_eq!(
            second_before,
            [
                fs::read(second_set.join(PRODUCTION_DATABASE_FILENAME)).unwrap(),
                fs::read(second_set.join("migration-recovery-envelope-v1.bin")).unwrap(),
                fs::read(second_set.join("recovery-set-v1.manifest")).unwrap(),
            ]
        );
        for set in [&first_set, &second_set] {
            let mut names: Vec<_> = fs::read_dir(set)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            assert_eq!(
                names,
                [
                    std::ffi::OsString::from("migration-recovery-envelope-v1.bin"),
                    std::ffi::OsString::from("parish-data.db"),
                    std::ffi::OsString::from("recovery-set-v1.manifest"),
                ]
            );
        }
        assert!(
            fixture
                ._stage_root
                .path()
                .join(PRODUCTION_DATABASE_MIGRATION_BACKUP_STAGE_FILENAME)
                .exists()
        );
        drop(verified);
    }

    #[test]
    fn final_two_set_verification_rejects_an_extra_entry_and_preserves_retry_owner() {
        let mut fixture = published_fixture();
        let published = publish_complete_second_set(&mut fixture);
        let fresh =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&fixture.record).unwrap();
        let SecondCompleteRecoverySetVerificationOutcome::Verified(second_complete) =
            verify_second_complete_recovery_set(published, fresh)
        else {
            panic!("the second complete-set predecessor must verify");
        };
        let extra = fixture
            ._destination_root
            .path()
            .join("second")
            .join("unexpected-entry.synthetic");
        fs::write(&extra, b"synthetic non-secret test entry").unwrap();
        let FinalTwoSetVerificationOutcome::Failed(failure) =
            verify_final_two_recovery_sets(second_complete)
        else {
            panic!("an extra final-layout entry must fail closed");
        };
        assert_eq!(
            failure.category(),
            FinalTwoSetVerificationError::DirectoryLayoutInvalid
        );
        assert!(extra.exists(), "the transition must not clean up artifacts");
        fs::remove_file(extra).unwrap();
        assert!(matches!(
            failure.retry(),
            FinalTwoSetVerificationOutcome::Verified(_)
        ));
    }

    #[test]
    fn second_complete_set_wrong_key_fails_and_retry_requires_a_fresh_record() {
        let mut fixture = published_fixture();
        let published = publish_complete_second_set(&mut fixture);
        let wrong = correctly_associated_wrong_key_record_for_test(&fixture.record);
        let SecondCompleteRecoverySetVerificationOutcome::Failed(failure) =
            verify_second_complete_recovery_set(published, wrong)
        else {
            panic!("a checksum-valid wrong key must fail envelope authentication");
        };
        assert_eq!(
            failure.category(),
            SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed
        );
        let fresh =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&fixture.record).unwrap();
        assert!(matches!(
            failure.retry_with_fresh_record(fresh),
            SecondCompleteRecoverySetVerificationOutcome::Verified(_)
        ));
    }

    #[test]
    fn second_complete_set_rejects_changed_fresh_envelope_and_layout_observation() {
        let mut envelope_fixture = published_fixture();
        let published = publish_complete_second_set(&mut envelope_fixture);
        let fresh =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&envelope_fixture.record)
                .unwrap();
        let outcome = first_complete_recovery_set_verification::with_fresh_second_envelope_difference_injected(|| {
            verify_second_complete_recovery_set(published, fresh)
        });
        let SecondCompleteRecoverySetVerificationOutcome::Failed(failure) = outcome else {
            panic!("changed freshly read second envelope bytes must fail");
        };
        assert_eq!(
            failure.category(),
            SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed
        );

        let mut layout_fixture = published_fixture();
        let published = publish_complete_second_set(&mut layout_fixture);
        let fresh =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&layout_fixture.record)
                .unwrap();
        let outcome =
            first_complete_recovery_set_verification::with_second_layout_change_injected(|| {
                verify_second_complete_recovery_set(published, fresh)
            });
        let SecondCompleteRecoverySetVerificationOutcome::Failed(failure) = outcome else {
            panic!("a changed second layout observation must fail closed");
        };
        assert_eq!(
            failure.category(),
            SecondCompleteRecoverySetVerificationError::DirectoryLayoutInvalid
        );
    }

    #[test]
    fn second_complete_set_verifier_close_failure_retains_only_close_retry_ownership() {
        let mut fixture = published_fixture();
        let published = publish_complete_second_set(&mut fixture);
        let fresh =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&fixture.record).unwrap();
        let outcome = with_production_database_close_failure_injected(|| {
            verify_second_complete_recovery_set(published, fresh)
        });
        let SecondCompleteRecoverySetVerificationOutcome::VerifierCloseFailed(failure) = outcome
        else {
            panic!("injected verifier close failure must retain close-only ownership");
        };
        assert_eq!(
            failure.category(),
            SecondCompleteRecoverySetVerificationError::VerifierCloseFailed
        );
        assert!(matches!(
            failure.retry_close(),
            SecondCompleteRecoverySetVerificationOutcome::Failed(_)
        ));
    }
}
