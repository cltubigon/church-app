//! Private recovered-key verification of the already published first set.

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
    super::super::verify_fresh_envelope_contents(&mut reopened, expected)
        .map_err(|_| FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed)?;
    if super::super::query_envelope_facts(&reopened).as_ref() != Ok(&before) {
        return Err(FirstRecoverySetRecoveredKeyVerificationError::EnvelopeVerificationFailed);
    }
    Ok(*expected)
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
    let recovery_key_material = match entered_record
        .validate_association_and_into_recovery_key_material(
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
    use std::mem::needs_drop;

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
}
