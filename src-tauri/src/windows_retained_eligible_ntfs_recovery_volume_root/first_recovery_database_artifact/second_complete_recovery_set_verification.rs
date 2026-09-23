//! Independent verification of the complete second digital recovery set.

#[path = "final_two.rs"]
mod final_two_set_verification;

#[allow(unused_imports)]
pub(crate) use final_two_set_verification::{
    FinalTwoSetVerificationError, FinalTwoSetVerificationFailure, FinalTwoSetVerificationOutcome,
    TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
    verify_final_two_recovery_sets,
};

use std::{ffi::OsString, fmt, fs::File, io::Read, os::windows::ffi::OsStringExt, path::PathBuf};

use rusqlite::Connection;
use sha2::{Digest, Sha256};

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
        ParsedUntrustedRecoverySetManifestV1, RECOVERY_SET_MANIFEST_V1_LENGTH,
        RecoverySetManifestV1, ReenteredMigrationRecoveryKeyCustodyV1,
        open_migration_recovery_envelope_v1,
    },
};

use super::*;

struct FreshSecondDatabaseObservation {
    path: PathBuf,
    file: File,
    facts: database_publication::PublishedDatabaseFacts,
}

pub(crate) struct SecondCompleteRecoverySetVerified {
    published: FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    _second_complete_set_verified: (),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum SecondCompleteRecoverySetVerificationError {
    SourceUnavailableOrChanged,
    DestinationChangedOrInconsistent,
    DirectoryLayoutInvalid,
    PriorArtifactChangedOrInvalid,
    CustodyRecordMalformedOrInvalid,
    CustodyRecordAssociationMismatch,
    ManifestVerificationFailed,
    EnvelopeVerificationFailed,
    DatabaseVerificationFailed,
    SetCorrespondenceFailed,
    RecoveredKeyDatabaseVerificationFailed,
    VerifierCloseFailed,
}

pub(crate) struct SecondCompleteRecoverySetVerificationFailure {
    published: FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    error: SecondCompleteRecoverySetVerificationError,
}

pub(crate) struct SecondCompleteRecoverySetVerificationVerifierCloseFailure {
    published: FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    error: SecondCompleteRecoverySetVerificationError,
    verifier: Connection,
}

#[must_use = "the second complete-set verification outcome must be handled"]
pub(crate) enum SecondCompleteRecoverySetVerificationOutcome {
    Verified(SecondCompleteRecoverySetVerified),
    Failed(SecondCompleteRecoverySetVerificationFailure),
    VerifierCloseFailed(SecondCompleteRecoverySetVerificationVerifierCloseFailure),
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
    SecondCompleteRecoverySetVerified,
    "SecondCompleteRecoverySetVerified"
);
redacted_debug!(
    SecondCompleteRecoverySetVerificationFailure,
    "SecondCompleteRecoverySetVerificationFailure"
);
redacted_debug!(
    SecondCompleteRecoverySetVerificationVerifierCloseFailure,
    "SecondCompleteRecoverySetVerificationVerifierCloseFailure"
);

impl fmt::Debug for SecondCompleteRecoverySetVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceUnavailableOrChanged => "SourceUnavailableOrChanged",
            Self::DestinationChangedOrInconsistent => "DestinationChangedOrInconsistent",
            Self::DirectoryLayoutInvalid => "DirectoryLayoutInvalid",
            Self::PriorArtifactChangedOrInvalid => "PriorArtifactChangedOrInvalid",
            Self::CustodyRecordMalformedOrInvalid => "CustodyRecordMalformedOrInvalid",
            Self::CustodyRecordAssociationMismatch => "CustodyRecordAssociationMismatch",
            Self::ManifestVerificationFailed => "ManifestVerificationFailed",
            Self::EnvelopeVerificationFailed => "EnvelopeVerificationFailed",
            Self::DatabaseVerificationFailed => "DatabaseVerificationFailed",
            Self::SetCorrespondenceFailed => "SetCorrespondenceFailed",
            Self::RecoveredKeyDatabaseVerificationFailed => {
                "RecoveredKeyDatabaseVerificationFailed"
            }
            Self::VerifierCloseFailed => "VerifierCloseFailed",
        })
    }
}

fn fail(
    published: FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    error: SecondCompleteRecoverySetVerificationError,
) -> SecondCompleteRecoverySetVerificationOutcome {
    SecondCompleteRecoverySetVerificationOutcome::Failed(
        SecondCompleteRecoverySetVerificationFailure { published, error },
    )
}

fn map_predecessor_error(
    error: SecondRecoveryManifestArtifactPublicationError,
) -> SecondCompleteRecoverySetVerificationError {
    match error {
        SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged => {
            SecondCompleteRecoverySetVerificationError::SourceUnavailableOrChanged
        }
        SecondRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent => {
            SecondCompleteRecoverySetVerificationError::DestinationChangedOrInconsistent
        }
        _ => SecondCompleteRecoverySetVerificationError::PriorArtifactChangedOrInvalid,
    }
}

fn observe_second_layout(
    retained_directory_path: &[u16],
) -> Result<super::super::super::super::ExactLayoutState, ()> {
    #[cfg(test)]
    SECOND_LAYOUT_FAILURE_INJECTION.with(|injection| {
        let (call, fail_on) = injection.get();
        let Some(fail_on) = fail_on else {
            return Ok(());
        };
        let call = call.saturating_add(1);
        injection.set((call, Some(fail_on)));
        if fail_on == call {
            return Err(());
        }
        Ok(())
    })?;
    super::super::super::super::exact_layout(retained_directory_path).map_err(|_| ())
}

#[cfg(test)]
thread_local! {
    static SECOND_LAYOUT_FAILURE_INJECTION: std::cell::Cell<(u8, Option<u8>)> = const {
        std::cell::Cell::new((0, None))
    };
    static FRESH_SECOND_ENVELOPE_DIFFERENCE_INJECTED: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(crate) fn with_second_layout_change_injected<T>(operation: impl FnOnce() -> T) -> T {
    SECOND_LAYOUT_FAILURE_INJECTION.with(|injection| {
        assert_eq!(injection.replace((0, Some(2))), (0, None));
    });
    let result = operation();
    SECOND_LAYOUT_FAILURE_INJECTION.with(|injection| injection.set((0, None)));
    result
}

#[cfg(test)]
pub(crate) fn with_fresh_second_envelope_difference_injected<T>(
    operation: impl FnOnce() -> T,
) -> T {
    FRESH_SECOND_ENVELOPE_DIFFERENCE_INJECTED.with(|injected| {
        assert!(!injected.replace(true));
    });
    operation()
}

fn freshly_read_second_manifest(
    published: &FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
) -> Result<
    ([u8; RECOVERY_SET_MANIFEST_V1_LENGTH], RecoverySetManifestV1),
    SecondCompleteRecoverySetVerificationError,
> {
    let parent = &published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations
        .second
        .initial_child;
    let path = manifest_publication::fixed_manifest_path(&parent.normalized_path);
    let mut reopened = manifest_publication::open_manifest_for_verification(&path)
        .map_err(|_| SecondCompleteRecoverySetVerificationError::ManifestVerificationFailed)?;
    let before = manifest_publication::query_manifest_facts(&reopened)
        .and_then(|facts| {
            manifest_publication::validate_fresh_manifest_facts(
                &parent.identity,
                &parent.normalized_path,
                &facts,
            )?;
            Ok(facts)
        })
        .map_err(|_| SecondCompleteRecoverySetVerificationError::ManifestVerificationFailed)?;
    if published
        .second_manifest
        .initial
        .as_ref()
        .map(|facts| &facts.identity)
        != Some(&before.identity)
    {
        return Err(SecondCompleteRecoverySetVerificationError::ManifestVerificationFailed);
    }
    let mut bytes = [0_u8; RECOVERY_SET_MANIFEST_V1_LENGTH];
    reopened
        .read_exact(&mut bytes)
        .map_err(|_| SecondCompleteRecoverySetVerificationError::ManifestVerificationFailed)?;
    let mut trailing = [0_u8; 1];
    if reopened
        .read(&mut trailing)
        .map_err(|_| SecondCompleteRecoverySetVerificationError::ManifestVerificationFailed)?
        != 0
    {
        return Err(SecondCompleteRecoverySetVerificationError::ManifestVerificationFailed);
    }
    let parsed = ParsedUntrustedRecoverySetManifestV1::parse(&bytes)
        .map_err(|_| SecondCompleteRecoverySetVerificationError::ManifestVerificationFailed)?;
    let manifest = parsed
        .validate_structure()
        .map_err(|_| SecondCompleteRecoverySetVerificationError::ManifestVerificationFailed)?;
    if manifest.encode() != bytes
        || manifest_publication::query_manifest_facts(&reopened).as_ref() != Ok(&before)
    {
        return Err(SecondCompleteRecoverySetVerificationError::ManifestVerificationFailed);
    }
    Ok((bytes, manifest))
}

fn freshly_read_second_envelope(
    published: &FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    expected: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
) -> Result<[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH], SecondCompleteRecoverySetVerificationError>
{
    let parent = &published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations
        .second
        .initial_child;
    let path = envelope_publication::fixed_envelope_path(&parent.normalized_path);
    let mut reopened = envelope_publication::open_envelope_for_verification(&path)
        .map_err(|_| SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed)?;
    let before = envelope_publication::query_envelope_facts(&reopened)
        .and_then(|facts| {
            envelope_publication::validate_fresh_envelope_facts(
                &parent.identity,
                &parent.normalized_path,
                &facts,
            )?;
            Ok(facts)
        })
        .map_err(|_| SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed)?;
    if published
        .prior
        .second_envelope
        .initial
        .as_ref()
        .map(|facts| &facts.identity)
        != Some(&before.identity)
    {
        return Err(SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed);
    }
    let mut bytes = [0_u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH];
    reopened
        .read_exact(&mut bytes)
        .map_err(|_| SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed)?;
    #[cfg(test)]
    FRESH_SECOND_ENVELOPE_DIFFERENCE_INJECTED.with(|injected| {
        if injected.replace(false) {
            bytes[MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH - 1] ^= 1;
        }
    });
    let mut trailing = [0_u8; 1];
    if reopened
        .read(&mut trailing)
        .map_err(|_| SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed)?
        != 0
        || bytes != *expected
        || envelope_publication::query_envelope_facts(&reopened).as_ref() != Ok(&before)
    {
        return Err(SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed);
    }
    Ok(bytes)
}

fn freshly_verify_second_database(
    published: &FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    expected_length: u64,
    expected_digest: [u8; 32],
) -> Result<FreshSecondDatabaseObservation, SecondCompleteRecoverySetVerificationError> {
    let parent = &published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations
        .second
        .initial_child;
    let wide_path = database_publication::fixed_database_path(&parent.normalized_path);
    let mut reopened = database_publication::open_database_for_verification(&wide_path)
        .map_err(|_| SecondCompleteRecoverySetVerificationError::DatabaseVerificationFailed)?;
    let before = database_publication::query_database_facts(&reopened)
        .and_then(|facts| {
            database_publication::validate_database_facts(
                &parent.identity,
                &parent.normalized_path,
                &facts,
            )?;
            Ok(facts)
        })
        .map_err(|_| SecondCompleteRecoverySetVerificationError::DatabaseVerificationFailed)?;
    if before.byte_length != expected_length
        || published
            .prior
            .prior
            .second_database
            .initial
            .as_ref()
            .map(|facts| &facts.identity)
            != Some(&before.identity)
    {
        return Err(SecondCompleteRecoverySetVerificationError::DatabaseVerificationFailed);
    }
    database_publication::verify_fresh_contents(&mut reopened, expected_length, expected_digest)
        .map_err(|_| SecondCompleteRecoverySetVerificationError::DatabaseVerificationFailed)?;
    if database_publication::query_database_facts(&reopened).as_ref() != Ok(&before) {
        return Err(SecondCompleteRecoverySetVerificationError::DatabaseVerificationFailed);
    }
    Ok(FreshSecondDatabaseObservation {
        path: PathBuf::from(OsString::from_wide(&wide_path)),
        file: reopened,
        facts: before,
    })
}

pub(crate) fn verify_second_complete_recovery_set(
    mut published: FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    entered_record: ReenteredMigrationRecoveryKeyCustodyV1,
) -> SecondCompleteRecoverySetVerificationOutcome {
    let expected_database = match published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .observe_recovery_database_source()
    {
        Ok(observation) => observation,
        Err(_) => {
            return fail(
                published,
                SecondCompleteRecoverySetVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_envelope = match published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .with_verified_recovery_envelope_bytes(|bytes| *bytes)
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return fail(
                published,
                SecondCompleteRecoverySetVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_manifest = match published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .prepare_recovery_set_manifest_v1()
    {
        Ok(manifest) => manifest.encode(),
        Err(_) => {
            return fail(
                published,
                SecondCompleteRecoverySetVerificationError::SourceUnavailableOrChanged,
            );
        }
    };
    if let Err(error) = super::revalidate_predecessor(
        &mut published.prior,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &expected_manifest,
    ) {
        return fail(published, map_predecessor_error(error));
    }
    let retained_directory_path = published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations
        .second
        .initial_child
        .normalized_path
        .clone();
    let before_layout = match observe_second_layout(&retained_directory_path) {
        Ok(layout) => layout,
        Err(()) => {
            return fail(
                published,
                SecondCompleteRecoverySetVerificationError::DirectoryLayoutInvalid,
            );
        }
    };
    let (fresh_manifest_bytes, fresh_manifest) = match freshly_read_second_manifest(&published) {
        Ok(observation) => observation,
        Err(error) => return fail(published, error),
    };
    if fresh_manifest_bytes != expected_manifest {
        return fail(
            published,
            SecondCompleteRecoverySetVerificationError::SetCorrespondenceFailed,
        );
    }
    let fresh_envelope = match freshly_read_second_envelope(&published, &expected_envelope) {
        Ok(bytes) => bytes,
        Err(error) => return fail(published, error),
    };
    let parsed_envelope = match ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&fresh_envelope) {
        Ok(parsed) => parsed,
        Err(_) => {
            return fail(
                published,
                SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed,
            );
        }
    };
    let envelope_digest: [u8; 32] = Sha256::digest(fresh_envelope).into();
    if fresh_manifest.recovery_envelope_sha256() != envelope_digest
        || fresh_manifest.backup_set_identifier() != parsed_envelope.backup_set_identifier()
        || fresh_manifest.database_byte_length() != expected_database.database_byte_length
        || fresh_manifest.database_sha256() != expected_database.database_sha256
    {
        return fail(
            published,
            SecondCompleteRecoverySetVerificationError::SetCorrespondenceFailed,
        );
    }
    let validated_record = match entered_record.validate_checksum_and_association(
        parsed_envelope.recovery_key_generation_identifier(),
        parsed_envelope.backup_set_identifier(),
    ) {
        Ok(material) => material,
        Err(
            MigrationRecoveryKeyCustodyValidationError::RecoveryKeyGenerationMismatch
            | MigrationRecoveryKeyCustodyValidationError::BackupSetMismatch,
        ) => {
            return fail(
                published,
                SecondCompleteRecoverySetVerificationError::CustodyRecordAssociationMismatch,
            );
        }
        Err(_) => {
            return fail(
                published,
                SecondCompleteRecoverySetVerificationError::CustodyRecordMalformedOrInvalid,
            );
        }
    };
    let recovery_key_material = validated_record.into_recovery_key_material();
    let parsed_fresh = match ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&fresh_envelope) {
        Ok(parsed) => parsed,
        Err(_) => {
            return fail(
                published,
                SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed,
            );
        }
    };
    let authenticated =
        match open_migration_recovery_envelope_v1(parsed_fresh, &recovery_key_material) {
            Ok(authenticated) => authenticated,
            Err(_) => {
                return fail(
                    published,
                    SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed,
                );
            }
        };
    drop(recovery_key_material);
    let matched = match authenticated.validate_payload_and_match_backup_set() {
        Ok(matched) => matched,
        Err(_) => {
            return fail(
                published,
                SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed,
            );
        }
    };
    let (candidate, authenticated_digest) = matched.release_database_key_candidate();
    if authenticated_digest
        != MigrationBackupStageSha256Digest::from_bytes(expected_database.database_sha256)
    {
        return fail(
            published,
            SecondCompleteRecoverySetVerificationError::SetCorrespondenceFailed,
        );
    }
    let (recovered_key, expected_metadata) = match published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .bind_recovered_database_key_candidate(candidate)
    {
        Ok(bound) => bound,
        Err(()) => {
            return fail(
                published,
                SecondCompleteRecoverySetVerificationError::EnvelopeVerificationFailed,
            );
        }
    };
    let fresh_database = match freshly_verify_second_database(
        &published,
        fresh_manifest.database_byte_length(),
        fresh_manifest.database_sha256(),
    ) {
        Ok(observation) => observation,
        Err(error) => return fail(published, error),
    };
    let verifier = match open_production_database_migration_backup_stage_verifier(
        &fresh_database.path,
        &recovered_key,
    ) {
        Ok(verifier) => verifier,
        Err(ProductionDatabaseMigrationBackupStageVerifierOpenError::Close(verifier)) => {
            drop(recovered_key);
            return SecondCompleteRecoverySetVerificationOutcome::VerifierCloseFailed(
                SecondCompleteRecoverySetVerificationVerifierCloseFailure {
                    published,
                    error: SecondCompleteRecoverySetVerificationError::RecoveredKeyDatabaseVerificationFailed,
                    verifier,
                },
            );
        }
        Err(_) => {
            drop(recovered_key);
            return fail(
                published,
                SecondCompleteRecoverySetVerificationError::RecoveredKeyDatabaseVerificationFailed,
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
    if let Err(verifier) = close_production_database_migration_backup_stage_verifier(verifier) {
        return SecondCompleteRecoverySetVerificationOutcome::VerifierCloseFailed(
            SecondCompleteRecoverySetVerificationVerifierCloseFailure {
                published,
                error: if verification.is_ok() {
                    SecondCompleteRecoverySetVerificationError::VerifierCloseFailed
                } else {
                    SecondCompleteRecoverySetVerificationError::RecoveredKeyDatabaseVerificationFailed
                },
                verifier,
            },
        );
    }
    if verification.is_err() {
        return fail(
            published,
            SecondCompleteRecoverySetVerificationError::RecoveredKeyDatabaseVerificationFailed,
        );
    }
    if database_publication::query_database_facts(&fresh_database.file).as_ref()
        != Ok(&fresh_database.facts)
    {
        return fail(
            published,
            SecondCompleteRecoverySetVerificationError::DatabaseVerificationFailed,
        );
    }
    if let Err(error) = super::revalidate_predecessor(
        &mut published.prior,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &expected_manifest,
    ) {
        return fail(published, map_predecessor_error(error));
    }
    let source = &published
        .prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source;
    let source_still_matches = source.observe_recovery_database_source().as_ref()
        == Ok(&expected_database)
        && source
            .with_verified_recovery_envelope_bytes(|bytes| *bytes)
            .as_ref()
            == Ok(&expected_envelope)
        && source
            .prepare_recovery_set_manifest_v1()
            .is_ok_and(|manifest| manifest.encode() == expected_manifest);
    if !source_still_matches {
        return fail(
            published,
            SecondCompleteRecoverySetVerificationError::SourceUnavailableOrChanged,
        );
    }
    let after_layout = match observe_second_layout(&retained_directory_path) {
        Ok(layout) => layout,
        Err(()) => {
            return fail(
                published,
                SecondCompleteRecoverySetVerificationError::DirectoryLayoutInvalid,
            );
        }
    };
    if before_layout != after_layout {
        return fail(
            published,
            SecondCompleteRecoverySetVerificationError::DirectoryLayoutInvalid,
        );
    }
    SecondCompleteRecoverySetVerificationOutcome::Verified(SecondCompleteRecoverySetVerified {
        published,
        _second_complete_set_verified: (),
    })
}

impl SecondCompleteRecoverySetVerificationFailure {
    pub(crate) fn category(&self) -> SecondCompleteRecoverySetVerificationError {
        self.error
    }

    pub(crate) fn retry_with_fresh_record(
        self,
        entered_record: ReenteredMigrationRecoveryKeyCustodyV1,
    ) -> SecondCompleteRecoverySetVerificationOutcome {
        verify_second_complete_recovery_set(self.published, entered_record)
    }
}

impl SecondCompleteRecoverySetVerificationVerifierCloseFailure {
    pub(crate) fn category(&self) -> SecondCompleteRecoverySetVerificationError {
        self.error
    }

    pub(crate) fn retry_close(self) -> SecondCompleteRecoverySetVerificationOutcome {
        let Self {
            published,
            error,
            verifier,
        } = self;
        match close_production_database_migration_backup_stage_verifier(verifier) {
            Ok(()) => SecondCompleteRecoverySetVerificationOutcome::Failed(
                SecondCompleteRecoverySetVerificationFailure { published, error },
            ),
            Err(verifier) => SecondCompleteRecoverySetVerificationOutcome::VerifierCloseFailed(
                SecondCompleteRecoverySetVerificationVerifierCloseFailure {
                    published,
                    error,
                    verifier,
                },
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::needs_drop;

    #[test]
    fn signature_owners_and_redaction_are_narrow_and_keyless() {
        assert!(needs_drop::<SecondCompleteRecoverySetVerified>());
        assert!(needs_drop::<SecondCompleteRecoverySetVerificationFailure>());
        let source = include_str!("second_complete_recovery_set_verification.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(production.contains(
            "mut published: FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,\n    entered_record: ReenteredMigrationRecoveryKeyCustodyV1,"
        ));
        let success = production
            .split_once("pub(crate) struct SecondCompleteRecoverySetVerified {")
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        assert!(
            success.contains(
                "published: FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished"
            )
        );
        for forbidden in [
            "ReenteredMigrationRecoveryKeyCustodyV1",
            "MigrationRecoveryKey",
            "DatabaseKey",
            "PathBuf",
            "[u8;",
        ] {
            assert!(!success.contains(forbidden), "success leaked {forbidden}");
        }
        assert!(!production.contains("remove_file"));
        assert!(!production.contains("remove_dir"));
        assert!(!production.contains("tauri::command"));
        assert!(!production.contains("FinalLayerD"));
    }

    #[test]
    fn canonical_fresh_verification_and_ordering_are_locked() {
        let source = include_str!("second_complete_recovery_set_verification.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        for required in [
            "observe_second_layout",
            "open_manifest_for_verification",
            "validate_fresh_manifest_facts",
            "ParsedUntrustedRecoverySetManifestV1::parse(&bytes)",
            "validate_structure()",
            "open_envelope_for_verification",
            "validate_fresh_envelope_facts",
            "ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&fresh_envelope)",
            "open_database_for_verification",
            "verify_fresh_contents",
            "validate_checksum_and_association",
            "into_recovery_key_material",
            "open_migration_recovery_envelope_v1",
            "release_database_key_candidate",
            "bind_recovered_database_key_candidate",
            "open_production_database_migration_backup_stage_verifier",
            "validate_production_database_cipher_integrity_on_borrowed_connection",
            "observe_production_database_fixed_metadata_and_headers_on_borrowed_connection",
            "close_production_database_migration_backup_stage_verifier",
            "retry_with_fresh_record",
            "retry_close",
        ] {
            assert!(production.contains(required), "missing {required}");
        }
        let transition = production
            .split_once("pub(crate) fn verify_second_complete_recovery_set")
            .unwrap()
            .1;
        let fresh = transition.find("freshly_read_second_envelope").unwrap();
        let association = transition
            .find("validate_checksum_and_association")
            .unwrap();
        let release = transition.find("into_recovery_key_material").unwrap();
        let authentication = transition
            .find("open_migration_recovery_envelope_v1")
            .unwrap();
        let database = transition.find("freshly_verify_second_database").unwrap();
        assert!(fresh < association && association < release && release < authentication);
        assert!(authentication < database);
        assert_eq!(transition.matches("observe_second_layout").count(), 2);
    }

    #[test]
    fn exact_layout_classifier_remains_the_single_canonical_implementation() {
        let source = include_str!("second_complete_recovery_set_verification.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(production.contains("super::super::super::super::exact_layout"));
        assert!(!production.contains("FindFirstFileW"));
        assert!(!production.contains("FindNextFileW"));
        assert!(!production.contains("FindClose"));
    }
}
