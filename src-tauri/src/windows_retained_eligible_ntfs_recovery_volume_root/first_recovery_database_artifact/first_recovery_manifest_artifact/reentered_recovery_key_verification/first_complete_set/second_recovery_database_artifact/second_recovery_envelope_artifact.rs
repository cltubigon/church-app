//! Publication of only the second recovery set's fixed recovery envelope.

#[path = "../../../../second_recovery_manifest_artifact.rs"]
mod second_recovery_manifest_artifact;

#[allow(unused_imports)]
pub(crate) use second_recovery_manifest_artifact::{
    FinalTwoSetVerificationError, FinalTwoSetVerificationFailure, FinalTwoSetVerificationOutcome,
    FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    SecondCompleteRecoverySetVerificationError, SecondCompleteRecoverySetVerificationFailure,
    SecondCompleteRecoverySetVerificationOutcome,
    SecondCompleteRecoverySetVerificationVerifierCloseFailure, SecondCompleteRecoverySetVerified,
    SecondRecoveryManifestArtifactPublicationError,
    SecondRecoveryManifestArtifactPublicationFailure,
    TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
    publish_second_recovery_manifest_artifact, verify_final_two_recovery_sets,
    verify_second_complete_recovery_set,
};
#[cfg(test)]
pub(crate) use second_recovery_manifest_artifact::{
    with_fresh_second_envelope_difference_injected, with_second_layout_change_injected,
};

use std::{
    fmt,
    fs::File,
    io::{Seek, SeekFrom},
};

use crate::production_database_migration_recovery_envelope::{
    MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH, ParsedUntrustedMigrationRecoveryEnvelopeV1,
};

use super::super::super::super::super as envelope_publication;
use super::*;

struct RetainedSecondRecoveryEnvelopeArtifact {
    file: Option<File>,
    initial: Option<envelope_publication::PublishedEnvelopeFacts>,
}

impl RetainedSecondRecoveryEnvelopeArtifact {
    fn revalidate(
        &mut self,
        parent_identity: &database_publication::RootIdentity,
        parent_path: &[u16],
        expected: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
    ) -> Result<(), SecondRecoveryEnvelopeArtifactPublicationError> {
        let file = self
            .file
            .as_mut()
            .ok_or(SecondRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed)?;
        let before = envelope_publication::query_envelope_facts(file)
            .and_then(|facts| {
                envelope_publication::validate_fresh_envelope_facts(
                    parent_identity,
                    parent_path,
                    &facts,
                )?;
                Ok(facts)
            })
            .map_err(map_shared_error)?;
        if self.initial.as_ref() != Some(&before) {
            return Err(SecondRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
        }
        file.seek(SeekFrom::Start(0)).map_err(|_| {
            SecondRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed
        })?;
        envelope_publication::verify_fresh_envelope_contents(file, expected)
            .map_err(map_shared_error)?;
        let after = envelope_publication::query_envelope_facts(file).map_err(map_shared_error)?;
        if before != after {
            return Err(SecondRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
        }
        Ok(())
    }
}

pub(crate) struct FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished {
    prior: FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished,
    second_envelope: RetainedSecondRecoveryEnvelopeArtifact,
    _second_database_and_envelope_only: (),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum SecondRecoveryEnvelopeArtifactPublicationError {
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

pub(crate) struct SecondRecoveryEnvelopeArtifactPublicationFailure {
    prior: FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished,
    partial_second_envelope: Option<RetainedSecondRecoveryEnvelopeArtifact>,
    phase: PublicationPhase,
    error: SecondRecoveryEnvelopeArtifactPublicationError,
}

struct AttemptFailure {
    partial: Option<RetainedSecondRecoveryEnvelopeArtifact>,
    phase: PublicationPhase,
    error: SecondRecoveryEnvelopeArtifactPublicationError,
}

impl fmt::Debug for RetainedSecondRecoveryEnvelopeArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedSecondRecoveryEnvelopeArtifact([REDACTED])")
    }
}

impl fmt::Debug for FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished([REDACTED])",
        )
    }
}

impl fmt::Debug for SecondRecoveryEnvelopeArtifactPublicationError {
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

impl fmt::Debug for SecondRecoveryEnvelopeArtifactPublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            PublicationPhase::BeforeCreation => "BeforeCreation",
            PublicationPhase::DuringWrite => "DuringWrite",
            PublicationPhase::DuringFlushOrClose => "DuringFlushOrClose",
            PublicationPhase::DuringFreshVerification => "DuringFreshVerification",
        };
        write!(
            formatter,
            "SecondRecoveryEnvelopeArtifactPublicationFailure({phase}, {:?})",
            self.error
        )
    }
}

fn map_shared_error(
    error: envelope_publication::FirstRecoveryEnvelopeArtifactPublicationError,
) -> SecondRecoveryEnvelopeArtifactPublicationError {
    use envelope_publication::FirstRecoveryEnvelopeArtifactPublicationError as Shared;
    match error {
        Shared::SourceUnavailableOrChanged => {
            SecondRecoveryEnvelopeArtifactPublicationError::SourceUnavailableOrChanged
        }
        Shared::DestinationChangedOrInconsistent => {
            SecondRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent
        }
        Shared::PriorArtifactChangedOrInvalid => {
            SecondRecoveryEnvelopeArtifactPublicationError::PriorArtifactChangedOrInvalid
        }
        Shared::ArtifactConflict => {
            SecondRecoveryEnvelopeArtifactPublicationError::ArtifactConflict
        }
        Shared::ArtifactCreationUnavailable => {
            SecondRecoveryEnvelopeArtifactPublicationError::ArtifactCreationUnavailable
        }
        Shared::ArtifactWriteUnavailable => {
            SecondRecoveryEnvelopeArtifactPublicationError::ArtifactWriteUnavailable
        }
        Shared::ArtifactFlushOrCloseUnavailable => {
            SecondRecoveryEnvelopeArtifactPublicationError::ArtifactFlushOrCloseUnavailable
        }
        Shared::ArtifactVerificationFailed => {
            SecondRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed
        }
    }
}

fn fail(
    prior: FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished,
    partial_second_envelope: Option<RetainedSecondRecoveryEnvelopeArtifact>,
    phase: PublicationPhase,
    error: SecondRecoveryEnvelopeArtifactPublicationError,
) -> Result<
    FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,
    Box<SecondRecoveryEnvelopeArtifactPublicationFailure>,
> {
    Err(Box::new(SecondRecoveryEnvelopeArtifactPublicationFailure {
        prior,
        partial_second_envelope,
        phase,
        error,
    }))
}

fn revalidate_predecessor(
    prior: &mut FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished,
    expected_database_length: u64,
    expected_database_digest: [u8; 32],
    expected_envelope: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
) -> Result<(), SecondRecoveryEnvelopeArtifactPublicationError> {
    let expected_manifest = prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .prepare_recovery_set_manifest_v1()
        .map_err(|_| SecondRecoveryEnvelopeArtifactPublicationError::SourceUnavailableOrChanged)?
        .encode();
    super::super::super::revalidate_published_set(
        &mut prior.first_complete_set.recovered_key_verified.prior,
        expected_database_length,
        expected_database_digest,
        expected_envelope,
        &expected_manifest,
    ).map_err(|error| match error {
        super::super::super::FirstRecoverySetRecoveredKeyVerificationError::SourceUnavailableOrChanged => SecondRecoveryEnvelopeArtifactPublicationError::SourceUnavailableOrChanged,
        super::super::super::FirstRecoverySetRecoveredKeyVerificationError::DestinationChangedOrInconsistent => SecondRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent,
        _ => SecondRecoveryEnvelopeArtifactPublicationError::PriorArtifactChangedOrInvalid,
    })?;
    let first_directory = &prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations
        .first
        .initial_child
        .normalized_path;
    if super::super::exact_layout(first_directory).is_err() {
        return Err(SecondRecoveryEnvelopeArtifactPublicationError::PriorArtifactChangedOrInvalid);
    }
    let destinations = &mut prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    destinations.revalidate().map_err(|_| {
        SecondRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent
    })?;
    prior
        .second_database
        .revalidate(
            &destinations.second.initial_child.identity,
            &destinations.second.initial_child.normalized_path,
            expected_database_length,
            expected_database_digest,
        )
        .map_err(|_| {
            SecondRecoveryEnvelopeArtifactPublicationError::PriorArtifactChangedOrInvalid
        })?;
    destinations.revalidate().map_err(|_| {
        SecondRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent
    })
}

fn attempt_publication(
    prior: &FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished,
    expected: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
) -> Result<RetainedSecondRecoveryEnvelopeArtifact, AttemptFailure> {
    let destinations = &prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    let parent = &destinations.second.initial_child;
    let final_path = envelope_publication::fixed_envelope_path(&parent.normalized_path);
    let writer =
        envelope_publication::create_new_envelope(&final_path).map_err(|error| AttemptFailure {
            partial: None,
            phase: PublicationPhase::BeforeCreation,
            error: map_shared_error(error),
        })?;
    let mut partial = RetainedSecondRecoveryEnvelopeArtifact {
        file: Some(writer),
        initial: None,
    };
    let initial_result = envelope_publication::query_envelope_facts(
        partial
            .file
            .as_ref()
            .expect("new second envelope writer remains retained"),
    )
    .and_then(|facts| {
        envelope_publication::validate_envelope_facts(
            &parent.identity,
            &parent.normalized_path,
            &facts,
        )?;
        Ok(facts)
    });
    let initial = match initial_result {
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
    if let Err(error) = envelope_publication::write_exact_envelope(
        partial
            .file
            .as_mut()
            .expect("second envelope writer remains retained during exact write"),
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
        .expect("second envelope writer remains retained until flush and close");
    if envelope_publication::flush(&writer).is_err() {
        partial.file = Some(writer);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFlushOrClose,
            error: SecondRecoveryEnvelopeArtifactPublicationError::ArtifactFlushOrCloseUnavailable,
        });
    }
    envelope_publication::close_writer(writer);
    if destinations.revalidate().is_err() {
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error: SecondRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent,
        });
    }
    let mut reopened = match envelope_publication::open_envelope_for_verification(&final_path) {
        Ok(reopened) => reopened,
        Err(error) => {
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringFreshVerification,
                error: map_shared_error(error),
            });
        }
    };
    let before_result = envelope_publication::query_envelope_facts(&reopened).and_then(|facts| {
        envelope_publication::validate_fresh_envelope_facts(&parent.identity, &parent.normalized_path, &facts)?;
        if facts.identity != partial.initial.as_ref().expect("initial second envelope facts remain retained").identity {
            return Err(envelope_publication::FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
        }
        Ok(facts)
    });
    let before = match before_result {
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
    let fresh_bytes = match envelope_publication::read_and_verify_fresh_envelope_contents(
        &mut reopened,
        expected,
    ) {
        Ok(fresh_bytes) => fresh_bytes,
        Err(_) => {
            partial.file = Some(reopened);
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringFreshVerification,
                error: SecondRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed,
            });
        }
    };
    let fresh = match ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&fresh_bytes) {
        Ok(fresh) => fresh,
        Err(_) => {
            partial.file = Some(reopened);
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringFreshVerification,
                error: SecondRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed,
            });
        }
    };
    let original = match ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(expected) {
        Ok(original) => original,
        Err(_) => {
            partial.file = Some(reopened);
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringFreshVerification,
                error: SecondRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed,
            });
        }
    };
    if fresh.backup_set_identifier() != original.backup_set_identifier() {
        partial.file = Some(reopened);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error: SecondRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed,
        });
    }
    let after = match envelope_publication::query_envelope_facts(&reopened) {
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
            error: SecondRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed,
        });
    }
    if destinations.revalidate().is_err() {
        partial.file = Some(reopened);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error: SecondRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent,
        });
    }
    partial.file = Some(reopened);
    partial.initial = Some(after);
    Ok(partial)
}

pub(crate) fn publish_second_recovery_envelope_artifact(
    mut prior: FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished,
) -> Result<
    FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,
    Box<SecondRecoveryEnvelopeArtifactPublicationFailure>,
> {
    let source = &prior
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
                SecondRecoveryEnvelopeArtifactPublicationError::SourceUnavailableOrChanged,
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
                SecondRecoveryEnvelopeArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
    };
    if let Err(error) = revalidate_predecessor(
        &mut prior,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
    ) {
        return fail(prior, None, PublicationPhase::BeforeCreation, error);
    }
    let attempt = prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .with_verified_recovery_envelope_bytes(|expected| attempt_publication(&prior, expected));
    let mut second_envelope = match attempt {
        Err(_) => {
            return fail(
                prior,
                None,
                PublicationPhase::BeforeCreation,
                SecondRecoveryEnvelopeArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
        Ok(Err(attempt_failure)) => {
            return fail(
                prior,
                attempt_failure.partial,
                attempt_failure.phase,
                attempt_failure.error,
            );
        }
        Ok(Ok(second_envelope)) => second_envelope,
    };
    if let Err(error) = revalidate_predecessor(
        &mut prior,
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
    ) {
        return fail(
            prior,
            Some(second_envelope),
            PublicationPhase::DuringFreshVerification,
            error,
        );
    }
    let source_still_matches = prior
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
            .first_complete_set
            .recovered_key_verified
            .prior
            .prior
            .prior
            .source
            .with_verified_recovery_envelope_bytes(|bytes| *bytes == expected_envelope)
            .is_ok_and(|matches| matches);
    if !source_still_matches {
        return fail(
            prior,
            Some(second_envelope),
            PublicationPhase::DuringFreshVerification,
            SecondRecoveryEnvelopeArtifactPublicationError::SourceUnavailableOrChanged,
        );
    }
    let destinations = &mut prior
        .first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    if second_envelope
        .revalidate(
            &destinations.second.initial_child.identity,
            &destinations.second.initial_child.normalized_path,
            &expected_envelope,
        )
        .is_err()
    {
        return fail(
            prior,
            Some(second_envelope),
            PublicationPhase::DuringFreshVerification,
            SecondRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed,
        );
    }
    if destinations.revalidate().is_err() {
        return fail(
            prior,
            Some(second_envelope),
            PublicationPhase::DuringFreshVerification,
            SecondRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent,
        );
    }
    Ok(
        FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished {
            prior,
            second_envelope,
            _second_database_and_envelope_only: (),
        },
    )
}

impl SecondRecoveryEnvelopeArtifactPublicationFailure {
    pub(crate) fn category(&self) -> SecondRecoveryEnvelopeArtifactPublicationError {
        self.error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io, io::Write, mem::needs_drop};

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
    fn fixed_name_and_exact_writer_contract_are_locked() {
        let directory: Vec<u16> =
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\church-app-recovery-set"
                .encode_utf16()
                .collect();
        let path =
            String::from_utf16(&envelope_publication::fixed_envelope_path(&directory)).unwrap();
        assert!(path.ends_with(r"\church-app-recovery-set\migration-recovery-envelope-v1.bin"));
        assert_eq!(
            envelope_publication::FIRST_RECOVERY_ENVELOPE_FILENAME,
            "migration-recovery-envelope-v1.bin"
        );
        let payload = [0x5a; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH];
        let mut partial = PartialWriter {
            bytes: Vec::new(),
            maximum_write: 17,
        };
        envelope_publication::write_exact_envelope(&mut partial, &payload).unwrap();
        assert_eq!(partial.bytes, payload);
        assert!(envelope_publication::write_exact_envelope(&mut ZeroWriter, &payload).is_err());
    }

    #[test]
    fn production_signature_ownership_and_surface_are_narrow() {
        assert!(needs_drop::<
            FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,
        >());
        assert!(needs_drop::<SecondRecoveryEnvelopeArtifactPublicationFailure>());
        let source = include_str!("second_recovery_envelope_artifact.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(
            production
                .contains("mut prior: FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished,")
        );
        assert!(
            production
                .contains("prior: FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished")
        );
        assert!(production.contains("second_envelope: RetainedSecondRecoveryEnvelopeArtifact"));
        for forbidden in [
            "PathBuf",
            "generate_migration_recovery_key_material",
            "generate_migration_backup_set_identifier",
            "seal_migration_recovery_envelope_v1",
            "first_envelope.file",
            "remove_file",
            "remove_dir",
            "serde",
            "tauri::",
            "pub fn",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected surface: {forbidden}"
            );
        }
    }

    #[test]
    fn publication_uses_original_source_second_destination_and_shared_hardening() {
        let source = include_str!("second_recovery_envelope_artifact.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        for required in [
            "with_verified_recovery_envelope_bytes",
            ".second.initial_child",
            "revalidate_predecessor",
            ".second_database\n        .revalidate",
            "envelope_publication::fixed_envelope_path",
            "envelope_publication::create_new_envelope",
            "envelope_publication::query_envelope_facts",
            "envelope_publication::validate_fresh_envelope_facts",
            "envelope_publication::write_exact_envelope",
            "envelope_publication::flush",
            "envelope_publication::close_writer",
            "envelope_publication::open_envelope_for_verification",
            "envelope_publication::read_and_verify_fresh_envelope_contents",
            "ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&fresh_bytes)",
            "backup_set_identifier()",
        ] {
            assert!(
                production.contains(required),
                "missing contract: {required}"
            );
        }
        assert!(!production.contains("destinations.first.initial_child"));
    }

    #[test]
    fn second_writer_uses_shared_terminal_close_without_fabricating_retry_ownership() {
        let source = include_str!("second_recovery_envelope_artifact.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        let close_transition = production
            .split_once("envelope_publication::close_writer(writer)")
            .unwrap()
            .1
            .split_once("if destinations.revalidate()")
            .unwrap()
            .0;
        assert!(!close_transition.contains("partial.file = Some(writer)"));
        assert!(!close_transition.contains("ArtifactFlushOrCloseUnavailable"));
        assert!(!production.contains("if let Err(writer) = envelope_publication::close_writer"));
        assert!(!production.contains("remove_file"));
        assert!(!production.contains("remove_dir"));
    }

    #[test]
    fn shared_windows_contract_is_create_new_zero_share_and_open_reparse_point() {
        const SHARED: &str = include_str!("../../../../first_recovery_envelope_artifact.rs");
        let production = SHARED.split("#[cfg(test)]").next().unwrap();
        for required in [
            "GENERIC_WRITE | FILE_READ_ATTRIBUTES",
            "CREATE_NEW",
            "FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT",
            "GENERIC_READ",
            "FILE_SHARE_READ",
            "FlushFileBuffers",
            "CloseHandle",
            "FILE_ID_INFO",
            "read_exact(&mut actual)",
            "actual != *expected",
        ] {
            assert!(
                production.contains(required),
                "missing shared primitive: {required}"
            );
        }
    }
}
