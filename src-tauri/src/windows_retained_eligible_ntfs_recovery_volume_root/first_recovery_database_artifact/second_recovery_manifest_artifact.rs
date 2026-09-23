//! Publication of only the second recovery set's fixed manifest-last artifact.

#[path = "second_complete_recovery_set_verification.rs"]
mod second_complete_set;

#[allow(unused_imports)]
pub(crate) use second_complete_set::{
    SecondCompleteRecoverySetVerificationError, SecondCompleteRecoverySetVerificationFailure,
    SecondCompleteRecoverySetVerificationOutcome,
    SecondCompleteRecoverySetVerificationVerifierCloseFailure, SecondCompleteRecoverySetVerified,
    verify_second_complete_recovery_set,
};
#[cfg(test)]
pub(crate) use second_complete_set::{
    with_fresh_second_envelope_difference_injected, with_second_layout_change_injected,
};

use std::{
    fmt,
    fs::File,
    io::{Seek, SeekFrom},
};

use sha2::{Digest, Sha256};

use crate::production_database_migration_recovery_envelope::{
    MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH, ParsedUntrustedMigrationRecoveryEnvelopeV1,
    ParsedUntrustedRecoverySetManifestV1, RECOVERY_SET_MANIFEST_V1_LENGTH,
};

use super::super::super::super::super as manifest_publication;
use super::super::super::super::super::super as envelope_publication;
use super::*;

struct RetainedSecondRecoveryManifestArtifact {
    file: Option<File>,
    initial: Option<manifest_publication::PublishedManifestFacts>,
}

impl RetainedSecondRecoveryManifestArtifact {
    fn revalidate(
        &mut self,
        parent_identity: &database_publication::RootIdentity,
        parent_path: &[u16],
        expected: &[u8; RECOVERY_SET_MANIFEST_V1_LENGTH],
    ) -> Result<(), SecondRecoveryManifestArtifactPublicationError> {
        let file = self
            .file
            .as_mut()
            .ok_or(SecondRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed)?;
        let before = manifest_publication::query_manifest_facts(file)
            .and_then(|facts| {
                manifest_publication::validate_fresh_manifest_facts(
                    parent_identity,
                    parent_path,
                    &facts,
                )?;
                Ok(facts)
            })
            .map_err(map_shared_error)?;
        if self.initial.as_ref() != Some(&before) {
            return Err(SecondRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
        }
        file.seek(SeekFrom::Start(0)).map_err(|_| {
            SecondRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed
        })?;
        manifest_publication::read_and_verify_fresh_manifest_contents(file, expected)
            .map_err(map_shared_error)?;
        let after = manifest_publication::query_manifest_facts(file).map_err(map_shared_error)?;
        if before != after {
            return Err(SecondRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
        }
        Ok(())
    }
}

pub(crate) struct FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished {
    prior: FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,
    second_manifest: RetainedSecondRecoveryManifestArtifact,
    _second_manifest_published_only: (),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum SecondRecoveryManifestArtifactPublicationError {
    SourceUnavailableOrChanged,
    DestinationChangedOrInconsistent,
    PriorArtifactChangedOrInvalid,
    ArtifactConflict,
    ArtifactCreationUnavailable,
    ArtifactWriteUnavailable,
    ArtifactFlushOrCloseUnavailable,
    ArtifactVerificationFailed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PublicationPhase {
    BeforeCreation,
    DuringWrite,
    DuringFlushOrClose,
    DuringFreshVerification,
}

pub(crate) struct SecondRecoveryManifestArtifactPublicationFailure {
    prior: FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,
    partial_second_manifest: Option<RetainedSecondRecoveryManifestArtifact>,
    phase: PublicationPhase,
    error: SecondRecoveryManifestArtifactPublicationError,
}

struct AttemptFailure {
    partial: Option<RetainedSecondRecoveryManifestArtifact>,
    phase: PublicationPhase,
    error: SecondRecoveryManifestArtifactPublicationError,
}

impl fmt::Debug for RetainedSecondRecoveryManifestArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedSecondRecoveryManifestArtifact([REDACTED])")
    }
}

impl fmt::Debug for FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished([REDACTED])")
    }
}

impl fmt::Debug for SecondRecoveryManifestArtifactPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceUnavailableOrChanged => "SourceUnavailableOrChanged",
            Self::DestinationChangedOrInconsistent => "DestinationChangedOrInconsistent",
            Self::PriorArtifactChangedOrInvalid => "PriorArtifactChangedOrInvalid",
            Self::ArtifactConflict => "ArtifactConflict",
            Self::ArtifactCreationUnavailable => "ArtifactCreationUnavailable",
            Self::ArtifactWriteUnavailable => "ArtifactWriteUnavailable",
            Self::ArtifactFlushOrCloseUnavailable => "ArtifactFlushOrCloseUnavailable",
            Self::ArtifactVerificationFailed => "ArtifactVerificationFailed",
        })
    }
}

impl fmt::Debug for SecondRecoveryManifestArtifactPublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            PublicationPhase::BeforeCreation => "BeforeCreation",
            PublicationPhase::DuringWrite => "DuringWrite",
            PublicationPhase::DuringFlushOrClose => "DuringFlushOrClose",
            PublicationPhase::DuringFreshVerification => "DuringFreshVerification",
        };
        write!(
            formatter,
            "SecondRecoveryManifestArtifactPublicationFailure({phase}, {:?})",
            self.error
        )
    }
}

fn map_shared_error(
    error: manifest_publication::FirstRecoveryManifestArtifactPublicationError,
) -> SecondRecoveryManifestArtifactPublicationError {
    use manifest_publication::FirstRecoveryManifestArtifactPublicationError as Shared;
    match error {
        Shared::SourceUnavailableOrChanged => {
            SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged
        }
        Shared::DestinationChangedOrInconsistent => {
            SecondRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent
        }
        Shared::PriorArtifactChangedOrInvalid => {
            SecondRecoveryManifestArtifactPublicationError::PriorArtifactChangedOrInvalid
        }
        Shared::ArtifactConflict => {
            SecondRecoveryManifestArtifactPublicationError::ArtifactConflict
        }
        Shared::ArtifactCreationUnavailable => {
            SecondRecoveryManifestArtifactPublicationError::ArtifactCreationUnavailable
        }
        Shared::ArtifactWriteUnavailable => {
            SecondRecoveryManifestArtifactPublicationError::ArtifactWriteUnavailable
        }
        Shared::ArtifactFlushOrCloseUnavailable => {
            SecondRecoveryManifestArtifactPublicationError::ArtifactFlushOrCloseUnavailable
        }
        Shared::ArtifactVerificationFailed => {
            SecondRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed
        }
    }
}

fn fail(
    prior: FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,
    partial_second_manifest: Option<RetainedSecondRecoveryManifestArtifact>,
    phase: PublicationPhase,
    error: SecondRecoveryManifestArtifactPublicationError,
) -> Result<
    FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    Box<SecondRecoveryManifestArtifactPublicationFailure>,
> {
    Err(Box::new(SecondRecoveryManifestArtifactPublicationFailure {
        prior,
        partial_second_manifest,
        phase,
        error,
    }))
}

fn revalidate_second_artifacts(
    prior: &mut FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,
    expected_database_length: u64,
    expected_database_digest: [u8; 32],
    expected_envelope: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
) -> Result<(), SecondRecoveryManifestArtifactPublicationError> {
    let destinations = &mut prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    destinations.revalidate().map_err(|_| {
        SecondRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent
    })?;
    prior
        .prior
        .second_database
        .revalidate(
            &destinations.second.initial_child.identity,
            &destinations.second.initial_child.normalized_path,
            expected_database_length,
            expected_database_digest,
        )
        .map_err(|_| {
            SecondRecoveryManifestArtifactPublicationError::PriorArtifactChangedOrInvalid
        })?;
    prior
        .second_envelope
        .revalidate(
            &destinations.second.initial_child.identity,
            &destinations.second.initial_child.normalized_path,
            expected_envelope,
        )
        .map_err(|_| {
            SecondRecoveryManifestArtifactPublicationError::PriorArtifactChangedOrInvalid
        })?;
    destinations.revalidate().map_err(|_| {
        SecondRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent
    })
}

fn revalidate_predecessor(
    prior: &mut FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,
    expected_database_length: u64,
    expected_database_digest: [u8; 32],
    expected_envelope: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
    expected_manifest: &[u8; RECOVERY_SET_MANIFEST_V1_LENGTH],
) -> Result<(), SecondRecoveryManifestArtifactPublicationError> {
    let manifest = ParsedUntrustedRecoverySetManifestV1::parse(expected_manifest)
        .map_err(|_| SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged)?
        .validate_structure()
        .map_err(|_| SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged)?;
    let envelope = ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(expected_envelope)
        .map_err(|_| SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged)?;
    let envelope_digest: [u8; 32] = Sha256::digest(expected_envelope).into();
    if manifest.encode() != *expected_manifest
        || manifest.database_byte_length() != expected_database_length
        || manifest.database_sha256() != expected_database_digest
        || manifest.recovery_envelope_sha256() != envelope_digest
        || manifest.backup_set_identifier() != envelope.backup_set_identifier()
    {
        return Err(SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged);
    }

    super::super::super::super::revalidate_published_set(
        &mut prior
            .prior
            .first_complete_set
            .recovered_key_verified
            .prior,
        expected_database_length,
        expected_database_digest,
        expected_envelope,
        expected_manifest,
    )
    .map_err(|error| match error {
        super::super::super::super::FirstRecoverySetRecoveredKeyVerificationError::SourceUnavailableOrChanged => SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged,
        super::super::super::super::FirstRecoverySetRecoveredKeyVerificationError::DestinationChangedOrInconsistent => SecondRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent,
        _ => SecondRecoveryManifestArtifactPublicationError::PriorArtifactChangedOrInvalid,
    })?;
    let first_directory = &prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations
        .first
        .initial_child
        .normalized_path;
    if super::super::super::exact_layout(first_directory).is_err() {
        return Err(SecondRecoveryManifestArtifactPublicationError::PriorArtifactChangedOrInvalid);
    }
    revalidate_second_artifacts(
        prior,
        expected_database_length,
        expected_database_digest,
        expected_envelope,
    )
}

fn attempt_publication(
    prior: &FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,
    expected: &[u8; RECOVERY_SET_MANIFEST_V1_LENGTH],
) -> Result<RetainedSecondRecoveryManifestArtifact, AttemptFailure> {
    let destinations = &prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    let parent = &destinations.second.initial_child;
    let final_path = manifest_publication::fixed_manifest_path(&parent.normalized_path);
    let writer =
        manifest_publication::create_new_manifest(&final_path).map_err(|error| AttemptFailure {
            partial: None,
            phase: PublicationPhase::BeforeCreation,
            error: map_shared_error(error),
        })?;
    let mut partial = RetainedSecondRecoveryManifestArtifact {
        file: Some(writer),
        initial: None,
    };
    let initial = manifest_publication::query_manifest_facts(
        partial
            .file
            .as_ref()
            .expect("new second manifest writer remains retained"),
    )
    .and_then(|facts| {
        manifest_publication::validate_manifest_facts(
            &parent.identity,
            &parent.normalized_path,
            &facts,
        )?;
        Ok(facts)
    });
    let initial = match initial {
        Ok(initial) => initial,
        Err(error) => {
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringWrite,
                error: map_shared_error(error),
            });
        }
    };
    partial.initial = Some(initial);
    if let Err(error) = manifest_publication::write_exact_manifest(
        partial
            .file
            .as_mut()
            .expect("second manifest writer remains retained during exact write"),
        expected,
    ) {
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringWrite,
            error: map_shared_error(error),
        });
    }
    let writer = partial
        .file
        .take()
        .expect("second manifest writer remains retained until flush and close");
    if manifest_publication::flush(&writer).is_err() {
        partial.file = Some(writer);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFlushOrClose,
            error: SecondRecoveryManifestArtifactPublicationError::ArtifactFlushOrCloseUnavailable,
        });
    }
    envelope_publication::close_writer(writer);
    if destinations.revalidate().is_err() {
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error: SecondRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent,
        });
    }
    let mut reopened = match manifest_publication::open_manifest_for_verification(&final_path) {
        Ok(reopened) => reopened,
        Err(error) => {
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringFreshVerification,
                error: map_shared_error(error),
            });
        }
    };
    let before = match manifest_publication::query_manifest_facts(&reopened).and_then(|facts| {
        manifest_publication::validate_fresh_manifest_facts(
            &parent.identity,
            &parent.normalized_path,
            &facts,
        )?;
        if facts.identity
            != partial
                .initial
                .as_ref()
                .expect("initial second manifest facts remain retained")
                .identity
        {
            return Err(
                manifest_publication::FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed,
            );
        }
        Ok(facts)
    }) {
        Ok(before) => before,
        Err(error) => {
            partial.file = Some(reopened);
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringFreshVerification,
                error: map_shared_error(error),
            });
        }
    };
    if let Err(error) =
        manifest_publication::read_and_verify_fresh_manifest_contents(&mut reopened, expected)
    {
        partial.file = Some(reopened);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error: map_shared_error(error),
        });
    }
    let after = match manifest_publication::query_manifest_facts(&reopened) {
        Ok(after) => after,
        Err(error) => {
            partial.file = Some(reopened);
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringFreshVerification,
                error: map_shared_error(error),
            });
        }
    };
    if before != after {
        partial.file = Some(reopened);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error: SecondRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed,
        });
    }
    if destinations.revalidate().is_err() {
        partial.file = Some(reopened);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error: SecondRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent,
        });
    }
    partial.file = Some(reopened);
    partial.initial = Some(after);
    Ok(partial)
}

pub(crate) fn publish_second_recovery_manifest_artifact(
    mut prior: FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,
) -> Result<
    FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    Box<SecondRecoveryManifestArtifactPublicationFailure>,
> {
    let source = &prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source;
    let expected_database = match source.observe_recovery_database_source() {
        Ok(expected) => expected,
        Err(_) => {
            return fail(
                prior,
                None,
                PublicationPhase::BeforeCreation,
                SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_envelope = match source.with_verified_recovery_envelope_bytes(|bytes| *bytes) {
        Ok(expected) => expected,
        Err(_) => {
            return fail(
                prior,
                None,
                PublicationPhase::BeforeCreation,
                SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
    };
    if let Err(error) = revalidate_second_artifacts(
        &mut prior,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
    ) {
        return fail(prior, None, PublicationPhase::BeforeCreation, error);
    }
    let source_is_current = prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .observe_recovery_database_source()
        .as_ref()
        == Ok(&expected_database)
        && prior
            .prior
            .first_complete_set
            .recovered_key_verified
            .prior
            .prior
            .prior
            .source
            .with_verified_recovery_envelope_bytes(|bytes| *bytes == expected_envelope)
            .is_ok_and(|matches| matches);
    if !source_is_current {
        return fail(
            prior,
            None,
            PublicationPhase::BeforeCreation,
            SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged,
        );
    }
    let trusted_manifest = match prior
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
                prior,
                None,
                PublicationPhase::BeforeCreation,
                SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
    };
    if let Err(error) = revalidate_predecessor(
        &mut prior,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &trusted_manifest,
    ) {
        return fail(prior, None, PublicationPhase::BeforeCreation, error);
    }
    let mut second_manifest = match attempt_publication(&prior, &trusted_manifest) {
        Ok(second_manifest) => second_manifest,
        Err(attempt_failure) => {
            return fail(
                prior,
                attempt_failure.partial,
                attempt_failure.phase,
                attempt_failure.error,
            );
        }
    };
    let source_still_matches = prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .observe_recovery_database_source()
        .as_ref()
        == Ok(&expected_database)
        && prior
            .prior
            .first_complete_set
            .recovered_key_verified
            .prior
            .prior
            .prior
            .source
            .with_verified_recovery_envelope_bytes(|bytes| *bytes == expected_envelope)
            .is_ok_and(|matches| matches)
        && prior
            .prior
            .first_complete_set
            .recovered_key_verified
            .prior
            .prior
            .prior
            .source
            .prepare_recovery_set_manifest_v1()
            .is_ok_and(|manifest| manifest.encode() == trusted_manifest);
    if !source_still_matches {
        return fail(
            prior,
            Some(second_manifest),
            PublicationPhase::DuringFreshVerification,
            SecondRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged,
        );
    }
    if let Err(error) = revalidate_predecessor(
        &mut prior,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
        &trusted_manifest,
    ) {
        return fail(
            prior,
            Some(second_manifest),
            PublicationPhase::DuringFreshVerification,
            error,
        );
    }
    let destinations = &mut prior
        .prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    if second_manifest
        .revalidate(
            &destinations.second.initial_child.identity,
            &destinations.second.initial_child.normalized_path,
            &trusted_manifest,
        )
        .is_err()
    {
        return fail(
            prior,
            Some(second_manifest),
            PublicationPhase::DuringFreshVerification,
            SecondRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed,
        );
    }
    if destinations.revalidate().is_err() {
        return fail(
            prior,
            Some(second_manifest),
            PublicationPhase::DuringFreshVerification,
            SecondRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent,
        );
    }
    Ok(
        FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished {
            prior,
            second_manifest,
            _second_manifest_published_only: (),
        },
    )
}

impl SecondRecoveryManifestArtifactPublicationFailure {
    pub(crate) fn category(&self) -> SecondRecoveryManifestArtifactPublicationError {
        self.error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io, io::Write, mem::needs_drop};

    fn canonical_manifest() -> [u8; RECOVERY_SET_MANIFEST_V1_LENGTH] {
        let mut bytes = [0_u8; RECOVERY_SET_MANIFEST_V1_LENGTH];
        bytes[..8].copy_from_slice(b"CHLDRSM\0");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[26..34].copy_from_slice(&512_u64.to_be_bytes());
        bytes[34..66].fill(0x5a);
        bytes[66..98].fill(0xa5);
        bytes
    }

    struct PartialWriter {
        bytes: Vec<u8>,
        maximum_write: usize,
    }

    impl Write for PartialWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let written = buffer.len().min(self.maximum_write);
            self.bytes.extend_from_slice(&buffer[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ZeroWriter;

    impl Write for ZeroWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn fixed_name_exact_length_partial_write_and_zero_progress_are_locked() {
        let directory: Vec<u16> =
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\church-app-recovery-set"
                .encode_utf16()
                .collect();
        let path =
            String::from_utf16(&manifest_publication::fixed_manifest_path(&directory)).unwrap();
        assert!(path.ends_with(r"\church-app-recovery-set\recovery-set-v1.manifest"));
        assert_eq!(
            manifest_publication::FIRST_RECOVERY_MANIFEST_FILENAME,
            "recovery-set-v1.manifest"
        );
        let expected = canonical_manifest();
        let mut partial = PartialWriter {
            bytes: Vec::new(),
            maximum_write: 7,
        };
        manifest_publication::write_exact_manifest(&mut partial, &expected).unwrap();
        assert_eq!(partial.bytes, expected);
        assert!(manifest_publication::write_exact_manifest(&mut ZeroWriter, &expected).is_err());
    }

    #[test]
    fn production_signature_owner_and_failure_are_narrow_keyless_and_redacted() {
        assert!(needs_drop::<
            FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
        >());
        assert!(needs_drop::<SecondRecoveryManifestArtifactPublicationFailure>());
        let source = include_str!("second_recovery_manifest_artifact.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains(
            "mut prior: FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,"
        ));
        assert!(production.contains(
            "prior: FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished"
        ));
        assert!(production.contains("second_manifest: RetainedSecondRecoveryManifestArtifact"));
        for forbidden in [
            "PathBuf",
            "MigrationRecoveryKey",
            "DatabaseKey",
            "generate_migration_recovery_key_material",
            "generate_migration_backup_set_identifier",
            "seal_migration_recovery_envelope_v1",
            "remove_file",
            "remove_dir",
            "serde",
            "tauri::",
            "pub fn",
            "CompleteSecondRecoverySet",
            "LayerD",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected surface: {forbidden}"
            );
        }
    }

    #[test]
    fn publication_uses_original_source_second_destination_and_not_first_manifest() {
        let source = include_str!("second_recovery_manifest_artifact.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for required in [
            "prepare_recovery_set_manifest_v1",
            "observe_recovery_database_source",
            "with_verified_recovery_envelope_bytes",
            ".second.initial_child",
            "revalidate_predecessor",
            ".second_database\n        .revalidate",
            ".second_envelope\n        .revalidate",
            "manifest_publication::fixed_manifest_path",
            "manifest_publication::create_new_manifest",
            "manifest_publication::query_manifest_facts",
            "manifest_publication::validate_fresh_manifest_facts",
            "manifest_publication::write_exact_manifest",
            "manifest_publication::flush",
            "envelope_publication::close_writer",
            "manifest_publication::open_manifest_for_verification",
            "manifest_publication::read_and_verify_fresh_manifest_contents",
            "ParsedUntrustedRecoverySetManifestV1::parse",
            "validate_structure",
            "backup_set_identifier()",
            "database_byte_length()",
            "database_sha256()",
            "recovery_envelope_sha256()",
        ] {
            assert!(
                production.contains(required),
                "missing contract: {required}"
            );
        }
        for forbidden in [
            "first_manifest.file",
            "first_manifest.initial",
            "destinations.first.initial_child",
            "fs::copy",
            "std::fs::copy",
        ] {
            assert!(
                !production.contains(forbidden),
                "set 1 used as source: {forbidden}"
            );
        }
    }

    #[test]
    fn publication_order_and_terminal_close_policy_are_locked() {
        let source = include_str!("second_recovery_manifest_artifact.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let publication = production
            .split_once("pub(crate) fn publish_second_recovery_manifest_artifact")
            .unwrap()
            .1;
        let database = publication
            .find("observe_recovery_database_source()")
            .unwrap();
        let envelope = publication
            .find("with_verified_recovery_envelope_bytes")
            .unwrap();
        let artifacts = publication.find("revalidate_second_artifacts(").unwrap();
        let prepare = publication
            .find("prepare_recovery_set_manifest_v1()")
            .unwrap();
        let pre = publication.find("revalidate_predecessor(").unwrap();
        let create = publication.find("attempt_publication(&prior").unwrap();
        let post_prepare = publication
            .rfind("prepare_recovery_set_manifest_v1()")
            .unwrap();
        let post = publication.rfind("revalidate_predecessor(").unwrap();
        assert!(
            database < envelope
                && envelope < artifacts
                && artifacts < prepare
                && prepare < pre
                && pre < create
                && create < post_prepare
                && post_prepare < post
        );

        let attempt = production
            .split_once("fn attempt_publication")
            .unwrap()
            .1
            .split_once("pub(crate) fn publish_second_recovery_manifest_artifact")
            .unwrap()
            .0;
        let write = attempt.find("write_exact_manifest(").unwrap();
        let flush = attempt.find("flush(&writer)").unwrap();
        let close = attempt.find("close_writer(writer)").unwrap();
        let reopen = attempt.find("open_manifest_for_verification").unwrap();
        let read = attempt
            .find("read_and_verify_fresh_manifest_contents")
            .unwrap();
        assert!(write < flush && flush < close && close < reopen && reopen < read);
        let close_transition = attempt
            .split_once("envelope_publication::close_writer(writer)")
            .unwrap()
            .1
            .split_once("if destinations.revalidate()")
            .unwrap()
            .0;
        assert!(!close_transition.contains("partial.file = Some(writer)"));
        assert!(!production.contains("File::from_raw_handle"));
    }

    #[test]
    fn shared_windows_contract_is_create_new_zero_share_hardened_and_exact() {
        const SHARED: &str = include_str!("first_recovery_manifest_artifact.rs");
        let production = SHARED.split("#[cfg(test)]").next().unwrap();
        for required in [
            "GENERIC_WRITE | FILE_READ_ATTRIBUTES",
            "CREATE_NEW",
            "FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT",
            "GENERIC_READ",
            "FILE_SHARE_READ",
            "FlushFileBuffers",
            "FILE_ID_INFO",
            "read_exact(&mut actual)",
            "canonical != actual || canonical != *expected",
        ] {
            assert!(
                production.contains(required),
                "missing shared primitive: {required}"
            );
        }
    }
}
