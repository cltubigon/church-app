//! Publication of only the second recovery set's fixed database artifact.

#[path = "second_recovery_database_artifact/second_recovery_envelope_artifact.rs"]
mod second_recovery_envelope_artifact;

#[allow(unused_imports)]
pub(crate) use second_recovery_envelope_artifact::{
    FirstCompleteRecoverySetAndSecondDatabaseAndEnvelopeArtifactsPublished,
    FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished,
    SecondRecoveryEnvelopeArtifactPublicationError,
    SecondRecoveryEnvelopeArtifactPublicationFailure,
    SecondRecoveryManifestArtifactPublicationError,
    SecondRecoveryManifestArtifactPublicationFailure, publish_second_recovery_envelope_artifact,
    publish_second_recovery_manifest_artifact,
};

use std::{
    fmt,
    fs::File,
    io::{Seek, SeekFrom, Write},
};

use super::super::super::super::super as database_publication;
use super::*;

struct RetainedSecondRecoveryDatabaseArtifact {
    file: Option<File>,
    initial: Option<database_publication::PublishedDatabaseFacts>,
}

impl RetainedSecondRecoveryDatabaseArtifact {
    fn revalidate(
        &mut self,
        parent_identity: &database_publication::RootIdentity,
        parent_path: &[u16],
        expected_length: u64,
        expected_digest: [u8; 32],
    ) -> Result<(), SecondRecoveryDatabaseArtifactPublicationError> {
        let file = self
            .file
            .as_mut()
            .ok_or(SecondRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed)?;
        let before = database_publication::query_database_facts(file)
            .and_then(|facts| {
                database_publication::validate_database_facts(
                    parent_identity,
                    parent_path,
                    &facts,
                )?;
                Ok(facts)
            })
            .map_err(map_shared_error)?;
        if self.initial.as_ref() != Some(&before) || before.byte_length != expected_length {
            return Err(SecondRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
        }
        file.seek(SeekFrom::Start(0)).map_err(|_| {
            SecondRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed
        })?;
        database_publication::verify_fresh_contents(file, expected_length, expected_digest)
            .map_err(map_shared_error)?;
        let after = database_publication::query_database_facts(file).map_err(map_shared_error)?;
        if before != after {
            return Err(SecondRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
        }
        Ok(())
    }
}

pub(crate) struct FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished {
    first_complete_set: FirstCompleteRecoverySetVerified,
    second_database: RetainedSecondRecoveryDatabaseArtifact,
    _second_database_only: (),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum SecondRecoveryDatabaseArtifactPublicationError {
    SourceUnavailableOrChanged,
    DestinationChangedOrInconsistent,
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

pub(crate) struct SecondRecoveryDatabaseArtifactPublicationFailure {
    first_complete_set: FirstCompleteRecoverySetVerified,
    partial_second_database: Option<RetainedSecondRecoveryDatabaseArtifact>,
    phase: PublicationPhase,
    error: SecondRecoveryDatabaseArtifactPublicationError,
}

impl fmt::Debug for RetainedSecondRecoveryDatabaseArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedSecondRecoveryDatabaseArtifact([REDACTED])")
    }
}

impl fmt::Debug for FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished([REDACTED])")
    }
}

impl fmt::Debug for SecondRecoveryDatabaseArtifactPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceUnavailableOrChanged => "SourceUnavailableOrChanged",
            Self::DestinationChangedOrInconsistent => "DestinationChangedOrInconsistent",
            Self::ArtifactConflict => "ArtifactConflict",
            Self::ArtifactCreationUnavailable => "ArtifactCreationUnavailable",
            Self::ArtifactWriteUnavailable => "ArtifactWriteUnavailable",
            Self::ArtifactFlushOrCloseUnavailable => "ArtifactFlushOrCloseUnavailable",
            Self::ArtifactVerificationFailed => "ArtifactVerificationFailed",
        })
    }
}

impl fmt::Debug for SecondRecoveryDatabaseArtifactPublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            PublicationPhase::BeforeCreation => "BeforeCreation",
            PublicationPhase::DuringWrite => "DuringWrite",
            PublicationPhase::DuringFlushOrClose => "DuringFlushOrClose",
            PublicationPhase::DuringFreshVerification => "DuringFreshVerification",
        };
        write!(
            formatter,
            "SecondRecoveryDatabaseArtifactPublicationFailure({phase}, {:?})",
            self.error
        )
    }
}

fn map_shared_error(
    error: database_publication::FirstRecoveryDatabaseArtifactPublicationError,
) -> SecondRecoveryDatabaseArtifactPublicationError {
    match error {
        database_publication::FirstRecoveryDatabaseArtifactPublicationError::SourceUnavailableOrChanged => {
            SecondRecoveryDatabaseArtifactPublicationError::SourceUnavailableOrChanged
        }
        database_publication::FirstRecoveryDatabaseArtifactPublicationError::DestinationChangedOrInconsistent => {
            SecondRecoveryDatabaseArtifactPublicationError::DestinationChangedOrInconsistent
        }
        database_publication::FirstRecoveryDatabaseArtifactPublicationError::ArtifactConflict => {
            SecondRecoveryDatabaseArtifactPublicationError::ArtifactConflict
        }
        database_publication::FirstRecoveryDatabaseArtifactPublicationError::ArtifactCreationUnavailable => {
            SecondRecoveryDatabaseArtifactPublicationError::ArtifactCreationUnavailable
        }
        database_publication::FirstRecoveryDatabaseArtifactPublicationError::ArtifactWriteUnavailable => {
            SecondRecoveryDatabaseArtifactPublicationError::ArtifactWriteUnavailable
        }
        database_publication::FirstRecoveryDatabaseArtifactPublicationError::ArtifactFlushOrCloseUnavailable => {
            SecondRecoveryDatabaseArtifactPublicationError::ArtifactFlushOrCloseUnavailable
        }
        database_publication::FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed => {
            SecondRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed
        }
    }
}

fn fail(
    first_complete_set: FirstCompleteRecoverySetVerified,
    partial_second_database: Option<RetainedSecondRecoveryDatabaseArtifact>,
    phase: PublicationPhase,
    error: SecondRecoveryDatabaseArtifactPublicationError,
) -> Result<
    FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished,
    Box<SecondRecoveryDatabaseArtifactPublicationFailure>,
> {
    Err(Box::new(SecondRecoveryDatabaseArtifactPublicationFailure {
        first_complete_set,
        partial_second_database,
        phase,
        error,
    }))
}

fn write_chunk(writer: &mut impl Write, chunk: &[u8]) -> Result<(), ()> {
    writer.write_all(chunk).map_err(|_| ())
}

pub(crate) fn publish_second_recovery_database_artifact(
    mut first_complete_set: FirstCompleteRecoverySetVerified,
) -> Result<
    FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished,
    Box<SecondRecoveryDatabaseArtifactPublicationFailure>,
> {
    let expected = match first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .observe_recovery_database_source()
    {
        Ok(expected) => expected,
        Err(_) => {
            return fail(
                first_complete_set,
                None,
                PublicationPhase::BeforeCreation,
                SecondRecoveryDatabaseArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
    };
    let destinations = &mut first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations;
    if destinations.revalidate().is_err() {
        return fail(
            first_complete_set,
            None,
            PublicationPhase::BeforeCreation,
            SecondRecoveryDatabaseArtifactPublicationError::DestinationChangedOrInconsistent,
        );
    }
    let parent_identity = destinations.second.initial_child.identity;
    let parent_path = destinations.second.initial_child.normalized_path.clone();
    let final_path = database_publication::fixed_database_path(&parent_path);
    let writer = match database_publication::create_new_database(&final_path) {
        Ok(writer) => writer,
        Err(error) => {
            return fail(
                first_complete_set,
                None,
                PublicationPhase::BeforeCreation,
                map_shared_error(error),
            );
        }
    };
    let mut partial = RetainedSecondRecoveryDatabaseArtifact {
        file: Some(writer),
        initial: None,
    };
    let initial = match database_publication::query_database_facts(
        partial
            .file
            .as_ref()
            .expect("new second writer remains retained during initial verification"),
    )
    .and_then(|facts| {
        database_publication::validate_database_facts(&parent_identity, &parent_path, &facts)?;
        Ok(facts)
    }) {
        Ok(initial) => initial,
        Err(error) => {
            return fail(
                first_complete_set,
                Some(partial),
                PublicationPhase::DuringWrite,
                map_shared_error(error),
            );
        }
    };
    partial.initial = Some(initial);
    let mut write_failed = false;
    let streamed = first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .stream_recovery_database_source(|chunk| {
            let result = write_chunk(
                partial
                    .file
                    .as_mut()
                    .expect("second writer remains retained during streaming"),
                chunk,
            );
            if result.is_err() {
                write_failed = true;
            }
            result
        });
    let streamed = match streamed {
        Ok(streamed) if streamed == expected => streamed,
        _ if write_failed => {
            return fail(
                first_complete_set,
                Some(partial),
                PublicationPhase::DuringWrite,
                SecondRecoveryDatabaseArtifactPublicationError::ArtifactWriteUnavailable,
            );
        }
        _ => {
            return fail(
                first_complete_set,
                Some(partial),
                PublicationPhase::DuringWrite,
                SecondRecoveryDatabaseArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
    };
    let writer = partial
        .file
        .take()
        .expect("second writer remains retained until flush and close");
    if database_publication::flush(&writer).is_err() {
        partial.file = Some(writer);
        return fail(
            first_complete_set,
            Some(partial),
            PublicationPhase::DuringFlushOrClose,
            SecondRecoveryDatabaseArtifactPublicationError::ArtifactFlushOrCloseUnavailable,
        );
    }
    if database_publication::close_writer(writer).is_err() {
        return fail(
            first_complete_set,
            Some(partial),
            PublicationPhase::DuringFlushOrClose,
            SecondRecoveryDatabaseArtifactPublicationError::ArtifactFlushOrCloseUnavailable,
        );
    }
    if first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations
        .revalidate()
        .is_err()
    {
        return fail(
            first_complete_set,
            Some(partial),
            PublicationPhase::DuringFreshVerification,
            SecondRecoveryDatabaseArtifactPublicationError::DestinationChangedOrInconsistent,
        );
    }
    let mut reopened = match database_publication::open_database_for_verification(&final_path) {
        Ok(reopened) => reopened,
        Err(error) => {
            return fail(
                first_complete_set,
                Some(partial),
                PublicationPhase::DuringFreshVerification,
                map_shared_error(error),
            );
        }
    };
    let before = match database_publication::query_database_facts(&reopened).and_then(|facts| {
        database_publication::validate_database_facts(&parent_identity, &parent_path, &facts)?;
        if facts.identity
            != partial
                .initial
                .as_ref()
                .expect("initial second facts remain retained through verification")
                .identity
            || facts.byte_length != streamed.database_byte_length
        {
            return Err(
                database_publication::FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed,
            );
        }
        Ok(facts)
    }) {
        Ok(before) => before,
        Err(error) => {
            return fail(
                first_complete_set,
                Some(partial),
                PublicationPhase::DuringFreshVerification,
                map_shared_error(error),
            );
        }
    };
    if database_publication::verify_fresh_contents(
        &mut reopened,
        streamed.database_byte_length,
        streamed.database_sha256,
    )
    .is_err()
    {
        return fail(
            first_complete_set,
            Some(partial),
            PublicationPhase::DuringFreshVerification,
            SecondRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed,
        );
    }
    let after = match database_publication::query_database_facts(&reopened) {
        Ok(after) if after == before => after,
        _ => {
            return fail(
                first_complete_set,
                Some(partial),
                PublicationPhase::DuringFreshVerification,
                SecondRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed,
            );
        }
    };
    let source_still_matches = first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .source
        .observe_recovery_database_source()
        .as_ref()
        == Ok(&expected);
    if !source_still_matches {
        return fail(
            first_complete_set,
            Some(partial),
            PublicationPhase::DuringFreshVerification,
            SecondRecoveryDatabaseArtifactPublicationError::SourceUnavailableOrChanged,
        );
    }
    if first_complete_set
        .recovered_key_verified
        .prior
        .prior
        .prior
        .destinations
        .revalidate()
        .is_err()
    {
        return fail(
            first_complete_set,
            Some(partial),
            PublicationPhase::DuringFreshVerification,
            SecondRecoveryDatabaseArtifactPublicationError::DestinationChangedOrInconsistent,
        );
    }
    partial.file = Some(reopened);
    partial.initial = Some(after);
    Ok(FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished {
        first_complete_set,
        second_database: partial,
        _second_database_only: (),
    })
}

impl SecondRecoveryDatabaseArtifactPublicationFailure {
    pub(crate) fn category(&self) -> SecondRecoveryDatabaseArtifactPublicationError {
        self.error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io, mem::needs_drop};

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
    fn bounded_chunk_writer_handles_partial_writes_and_refuses_zero_progress() {
        let payload = vec![0x5a; database_publication::COPY_BUFFER_LENGTH];
        let mut partial = PartialWriter {
            bytes: Vec::new(),
            maximum_write: 113,
        };
        assert!(write_chunk(&mut partial, &payload).is_ok());
        assert_eq!(partial.bytes, payload);
        assert!(write_chunk(&mut ZeroWriter, &[1]).is_err());
    }

    #[test]
    fn production_signature_and_owner_are_narrow_and_redacted() {
        assert!(needs_drop::<
            FirstCompleteRecoverySetAndSecondDatabaseArtifactPublished,
        >());
        assert!(needs_drop::<SecondRecoveryDatabaseArtifactPublicationFailure>());
        let source = include_str!("second_recovery_database_artifact.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("mut first_complete_set: FirstCompleteRecoverySetVerified,"));
        assert!(production.contains("first_complete_set: FirstCompleteRecoverySetVerified"));
        assert!(production.contains("second_database: RetainedSecondRecoveryDatabaseArtifact"));
        for excluded in [
            "PathBuf",
            "set_2",
            "migration-recovery-envelope-v1.bin",
            "recovery-set-v1.manifest",
            "remove_file",
            "remove_dir",
            "tauri::",
            "pub fn",
        ] {
            assert!(
                !production.contains(excluded),
                "unexpected surface: {excluded}"
            );
        }
        let debug = format!(
            "{:?}",
            SecondRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed
        );
        assert_eq!(debug, "ArtifactVerificationFailed");
    }

    #[test]
    fn transition_uses_original_source_second_destination_and_shared_hardening() {
        let source = include_str!("second_recovery_database_artifact.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for required in [
            ".source\n        .observe_recovery_database_source()",
            ".source\n        .stream_recovery_database_source",
            ".destinations",
            ".second.initial_child",
            "database_publication::fixed_database_path",
            "database_publication::create_new_database",
            "database_publication::query_database_facts",
            "database_publication::validate_database_facts",
            "database_publication::flush",
            "database_publication::close_writer",
            "database_publication::open_database_for_verification",
            "database_publication::verify_fresh_contents",
            "write_chunk(",
        ] {
            assert!(
                production.contains(required),
                "missing contract: {required}"
            );
        }
        for forbidden in [
            "first_database.file",
            "freshly_verify_database_correspondence",
            "first_manifest",
            "first_envelope",
        ] {
            assert!(
                !production.contains(forbidden),
                "set 1 used as source: {forbidden}"
            );
        }
    }

    #[test]
    fn shared_database_primitive_contract_is_fixed_create_new_and_bounded() {
        const SHARED: &str = include_str!("../../../../first_recovery_database_artifact.rs");
        let production = SHARED.split("#[cfg(test)]").next().unwrap();
        for required in [
            "COPY_BUFFER_LENGTH: usize = 64 * 1024",
            "GENERIC_WRITE | FILE_READ_ATTRIBUTES",
            "CREATE_NEW",
            "FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT",
            "FILE_SHARE_READ",
            "checked_add",
            "FlushFileBuffers",
            "CloseHandle",
            "FILE_ID_INFO",
        ] {
            assert!(
                production.contains(required),
                "missing shared primitive: {required}"
            );
        }
    }
}
