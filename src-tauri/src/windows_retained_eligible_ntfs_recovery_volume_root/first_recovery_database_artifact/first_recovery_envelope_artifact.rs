//! First-set-only publication of the fixed recovery-envelope artifact.

#[path = "first_recovery_manifest_artifact.rs"]
mod first_recovery_manifest_artifact;

pub(crate) use first_recovery_manifest_artifact::{
    FirstCompleteRecoverySetVerificationFailure, FirstCompleteRecoverySetVerificationOutcome,
    FirstCompleteRecoverySetVerified, FirstRecoverySetArtifactsPublished,
    FirstRecoverySetRecoveredKeyVerificationError, FirstRecoverySetRecoveredKeyVerificationFailure,
    FirstRecoverySetRecoveredKeyVerificationOutcome,
    FirstRecoverySetRecoveredKeyVerificationVerifierCloseFailure,
    FirstRecoverySetRecoveredKeyVerified, verify_first_complete_recovery_set,
    verify_first_recovery_set_with_reentered_recovery_key,
};

use std::{
    ffi::c_void,
    fmt,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle},
};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GENERIC_READ, GENERIC_WRITE,
        GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_STANDARD_INFO, FILE_TYPE_DISK,
        FileAttributeTagInfo, FileIdInfo, FileStandardInfo, FlushFileBuffers,
        GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW, OPEN_EXISTING,
    },
};

use crate::production_database_migration_recovery_envelope::MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH;

use super::{
    FINAL_PATH_FLAGS, FirstRecoveryDatabaseArtifactPublished,
    FirstRecoveryDatabaseArtifactRevalidationError, RootIdentity, fold_ascii,
};

pub(crate) const FIRST_RECOVERY_ENVELOPE_FILENAME: &str = "migration-recovery-envelope-v1.bin";

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PublishedEnvelopeFacts {
    pub(crate) identity: RootIdentity,
    pub(crate) disk_entry: bool,
    pub(crate) directory: bool,
    pub(crate) delete_pending: bool,
    pub(crate) attributes: u32,
    pub(crate) reparse_tag: u32,
    pub(crate) byte_length: u64,
    pub(crate) normalized_path: Vec<u16>,
}

struct RetainedFirstRecoveryEnvelopeArtifact {
    file: Option<File>,
    initial: Option<PublishedEnvelopeFacts>,
}

impl RetainedFirstRecoveryEnvelopeArtifact {
    fn revalidate(
        &mut self,
        parent_identity: &RootIdentity,
        parent_path: &[u16],
        expected: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
    ) -> Result<(), FirstRecoveryEnvelopeArtifactPublicationError> {
        let file = self
            .file
            .as_mut()
            .ok_or(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed)?;
        let before = query_envelope_facts(file)?;
        validate_fresh_envelope_facts(parent_identity, parent_path, &before)?;
        if self.initial.as_ref() != Some(&before) {
            return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
        }
        file.seek(SeekFrom::Start(0)).map_err(|_| {
            FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed
        })?;
        verify_fresh_envelope_contents(file, expected)?;
        let after = query_envelope_facts(file)?;
        if before != after {
            return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
        }
        Ok(())
    }
}

pub(crate) struct FirstRecoveryDatabaseAndEnvelopeArtifactsPublished {
    prior: FirstRecoveryDatabaseArtifactPublished,
    first_envelope: RetainedFirstRecoveryEnvelopeArtifact,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum FirstRecoveryManifestPublicationOutcome {
    Published(FirstRecoverySetArtifactsPublished),
    Source(
        crate::application_lifecycle::RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    ),
}

pub(crate) fn publish_first_recovery_manifest_artifact(
    prior: FirstRecoveryDatabaseAndEnvelopeArtifactsPublished,
) -> FirstRecoveryManifestPublicationOutcome {
    match first_recovery_manifest_artifact::publish_first_recovery_manifest_artifact(prior) {
        Ok(published) => FirstRecoveryManifestPublicationOutcome::Published(published),
        Err(failure) => FirstRecoveryManifestPublicationOutcome::Source(
            failure.abandon_partial_destination_and_retain_source(),
        ),
    }
}

impl FirstRecoveryDatabaseAndEnvelopeArtifactsPublished {
    pub(crate) fn abandon_published_destination_and_retain_source(
        self,
    ) -> crate::application_lifecycle::RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup
    {
        let Self {
            prior,
            first_envelope: _first_envelope,
        } = self;
        prior.abandon_published_destination_and_retain_source()
    }

    fn revalidate_for_manifest_publication(
        &mut self,
        expected_database_length: u64,
        expected_database_digest: [u8; 32],
        expected_envelope: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
    ) -> Result<(), FirstRecoveryEnvelopeArtifactPublicationError> {
        self.prior
            .revalidate_for_envelope_publication(
                expected_database_length,
                expected_database_digest,
            )
            .map_err(|error| match error {
                FirstRecoveryDatabaseArtifactRevalidationError::DestinationChangedOrInconsistent => {
                    FirstRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent
                }
                FirstRecoveryDatabaseArtifactRevalidationError::PriorArtifactChangedOrInvalid => {
                    FirstRecoveryEnvelopeArtifactPublicationError::PriorArtifactChangedOrInvalid
                }
            })?;
        self.first_envelope.revalidate(
            &self.prior.destinations.first.initial_child.identity,
            &self.prior.destinations.first.initial_child.normalized_path,
            expected_envelope,
        )?;
        self.prior
            .revalidate_for_envelope_publication(
                expected_database_length,
                expected_database_digest,
            )
            .map_err(|error| match error {
                FirstRecoveryDatabaseArtifactRevalidationError::DestinationChangedOrInconsistent => {
                    FirstRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent
                }
                FirstRecoveryDatabaseArtifactRevalidationError::PriorArtifactChangedOrInvalid => {
                    FirstRecoveryEnvelopeArtifactPublicationError::PriorArtifactChangedOrInvalid
                }
            })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum FirstRecoveryEnvelopeArtifactPublicationError {
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

pub(super) struct FirstRecoveryEnvelopeArtifactPublicationFailure {
    prior: FirstRecoveryDatabaseArtifactPublished,
    partial_first_envelope: Option<RetainedFirstRecoveryEnvelopeArtifact>,
    phase: PublicationPhase,
    error: FirstRecoveryEnvelopeArtifactPublicationError,
}

impl FirstRecoveryEnvelopeArtifactPublicationFailure {
    pub(super) fn abandon_partial_destination_and_retain_source(
        self,
    ) -> crate::application_lifecycle::RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup
    {
        let Self {
            prior,
            partial_first_envelope: _partial_first_envelope,
            phase: _phase,
            error: _error,
        } = self;
        prior.abandon_published_destination_and_retain_source()
    }
}

struct AttemptFailure {
    partial: Option<RetainedFirstRecoveryEnvelopeArtifact>,
    phase: PublicationPhase,
    error: FirstRecoveryEnvelopeArtifactPublicationError,
}

impl fmt::Debug for RetainedFirstRecoveryEnvelopeArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedFirstRecoveryEnvelopeArtifact([REDACTED])")
    }
}

impl fmt::Debug for FirstRecoveryDatabaseAndEnvelopeArtifactsPublished {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirstRecoveryDatabaseAndEnvelopeArtifactsPublished([REDACTED])")
    }
}

impl fmt::Debug for FirstRecoveryEnvelopeArtifactPublicationError {
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

impl fmt::Debug for FirstRecoveryEnvelopeArtifactPublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            PublicationPhase::BeforeCreation => "BeforeCreation",
            PublicationPhase::DuringWrite => "DuringWrite",
            PublicationPhase::DuringFlushOrClose => "DuringFlushOrClose",
            PublicationPhase::DuringFreshVerification => "DuringFreshVerification",
        };
        write!(
            formatter,
            "FirstRecoveryEnvelopeArtifactPublicationFailure({phase}, {:?})",
            self.error
        )
    }
}

fn fail(
    prior: FirstRecoveryDatabaseArtifactPublished,
    partial_first_envelope: Option<RetainedFirstRecoveryEnvelopeArtifact>,
    phase: PublicationPhase,
    error: FirstRecoveryEnvelopeArtifactPublicationError,
) -> Result<
    FirstRecoveryDatabaseAndEnvelopeArtifactsPublished,
    Box<FirstRecoveryEnvelopeArtifactPublicationFailure>,
> {
    Err(Box::new(FirstRecoveryEnvelopeArtifactPublicationFailure {
        prior,
        partial_first_envelope,
        phase,
        error,
    }))
}

pub(crate) fn fixed_envelope_path(directory_path: &[u16]) -> Vec<u16> {
    directory_path
        .iter()
        .copied()
        .chain(std::iter::once(b'\\' as u16))
        .chain(FIRST_RECOVERY_ENVELOPE_FILENAME.encode_utf16())
        .collect()
}

fn nul_terminated(path: &[u16]) -> Result<Vec<u16>, FirstRecoveryEnvelopeArtifactPublicationError> {
    if path.is_empty() || path.len() > super::super::MAXIMUM_FINAL_PATH_UNITS || path.contains(&0) {
        return Err(
            FirstRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent,
        );
    }
    let mut value = Vec::with_capacity(path.len() + 1);
    value.extend_from_slice(path);
    value.push(0);
    Ok(value)
}

pub(crate) fn create_new_envelope(
    path: &[u16],
) -> Result<File, FirstRecoveryEnvelopeArtifactPublicationError> {
    let path = nul_terminated(path)?;
    // SAFETY: the retained-directory-derived path is live and NUL-terminated.
    // CREATE_NEW, zero sharing, and open-reparse-point semantics prohibit
    // replacement, delete sharing, and following an unexpected leaf object.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_WRITE | FILE_READ_ATTRIBUTES,
            0,
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut::<c_void>(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        // SAFETY: read immediately after the failed create-new call.
        return match unsafe { GetLastError() } {
            ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS => {
                Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactConflict)
            }
            _ => Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactCreationUnavailable),
        };
    }
    // SAFETY: ownership of the fresh successful handle is transferred once.
    Ok(File::from(unsafe {
        OwnedHandle::from_raw_handle(raw as RawHandle)
    }))
}

pub(crate) fn open_envelope_for_verification(
    path: &[u16],
) -> Result<File, FirstRecoveryEnvelopeArtifactPublicationError> {
    let path = nul_terminated(path)?;
    // SAFETY: the exact final path is independently reopened read-only,
    // without write/delete sharing and without following a reparse leaf.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut::<c_void>(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
    }
    // SAFETY: ownership of the fresh successful handle is transferred once.
    Ok(File::from(unsafe {
        OwnedHandle::from_raw_handle(raw as RawHandle)
    }))
}

fn checked_information_size<T>() -> Result<u32, FirstRecoveryEnvelopeArtifactPublicationError> {
    u32::try_from(std::mem::size_of::<T>())
        .map_err(|_| FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed)
}

fn query_normalized_path(
    file: &File,
) -> Result<Vec<u16>, FirstRecoveryEnvelopeArtifactPublicationError> {
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: documented size query on the live owned handle.
    let required =
        unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, FINAL_PATH_FLAGS) };
    let capacity = usize::try_from(required)
        .map_err(|_| FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed)?;
    if capacity == 0 || capacity > super::super::MAXIMUM_FINAL_PATH_UNITS {
        return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
    }
    let mut output = vec![0_u16; capacity];
    // SAFETY: output is writable for the checked capacity and the handle stays live.
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, output.as_mut_ptr(), required, FINAL_PATH_FLAGS)
    };
    let written = usize::try_from(written)
        .map_err(|_| FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed)?;
    if written == 0 || written >= output.len() || written > super::super::MAXIMUM_FINAL_PATH_UNITS {
        return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
    }
    output.truncate(written);
    Ok(output)
}

pub(crate) fn query_envelope_facts(
    file: &File,
) -> Result<PublishedEnvelopeFacts, FirstRecoveryEnvelopeArtifactPublicationError> {
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: the handle remains live for each synchronous observation.
    let disk_entry = unsafe { GetFileType(handle) } == FILE_TYPE_DISK;
    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: exact initialized writable storage is supplied.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&raw mut standard).cast(),
            checked_information_size::<FILE_STANDARD_INFO>()?,
        )
    } == 0
    {
        return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
    }
    let mut attribute_tag = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: exact initialized writable storage is supplied.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&raw mut attribute_tag).cast(),
            checked_information_size::<FILE_ATTRIBUTE_TAG_INFO>()?,
        )
    } == 0
    {
        return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
    }
    let mut identity = FILE_ID_INFO::default();
    // SAFETY: exact initialized writable storage is supplied.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut identity).cast(),
            checked_information_size::<FILE_ID_INFO>()?,
        )
    } == 0
    {
        return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
    }
    let byte_length = u64::try_from(standard.EndOfFile)
        .map_err(|_| FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed)?;
    Ok(PublishedEnvelopeFacts {
        identity: RootIdentity {
            volume_serial: identity.VolumeSerialNumber,
            file_id: identity.FileId.Identifier,
        },
        disk_entry,
        directory: standard.Directory,
        delete_pending: standard.DeletePending,
        attributes: attribute_tag.FileAttributes,
        reparse_tag: attribute_tag.ReparseTag,
        byte_length,
        normalized_path: query_normalized_path(file)?,
    })
}

fn exact_envelope_path(directory: &[u16], observed: &[u16]) -> bool {
    let filename: Vec<u16> = FIRST_RECOVERY_ENVELOPE_FILENAME.encode_utf16().collect();
    observed.len() == directory.len() + 1 + filename.len()
        && observed.get(..directory.len()).is_some_and(|prefix| {
            prefix
                .iter()
                .zip(directory)
                .all(|(left, right)| fold_ascii(*left) == fold_ascii(*right))
        })
        && observed.get(directory.len()) == Some(&(b'\\' as u16))
        && observed.get(directory.len() + 1..) == Some(filename.as_slice())
}

pub(crate) fn validate_envelope_facts(
    parent_identity: &RootIdentity,
    parent_path: &[u16],
    facts: &PublishedEnvelopeFacts,
) -> Result<(), FirstRecoveryEnvelopeArtifactPublicationError> {
    if !facts.disk_entry
        || facts.directory
        || facts.delete_pending
        || facts.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || facts.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || facts.reparse_tag != 0
        || facts.identity.volume_serial != parent_identity.volume_serial
        || !exact_envelope_path(parent_path, &facts.normalized_path)
    {
        return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
    }
    Ok(())
}

pub(crate) fn validate_fresh_envelope_facts(
    parent_identity: &RootIdentity,
    parent_path: &[u16],
    facts: &PublishedEnvelopeFacts,
) -> Result<(), FirstRecoveryEnvelopeArtifactPublicationError> {
    validate_envelope_facts(parent_identity, parent_path, facts)?;
    if facts.byte_length != MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH as u64 {
        return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
    }
    Ok(())
}

pub(crate) fn write_exact_envelope(
    writer: &mut impl Write,
    expected: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
) -> Result<(), FirstRecoveryEnvelopeArtifactPublicationError> {
    let mut remaining = expected.as_slice();
    while !remaining.is_empty() {
        let written = writer
            .write(remaining)
            .map_err(|_| FirstRecoveryEnvelopeArtifactPublicationError::ArtifactWriteUnavailable)?;
        if written == 0 || written > remaining.len() {
            return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactWriteUnavailable);
        }
        remaining = &remaining[written..];
    }
    Ok(())
}

pub(crate) fn flush(file: &File) -> Result<(), FirstRecoveryEnvelopeArtifactPublicationError> {
    // SAFETY: the live writer was opened with GENERIC_WRITE.
    if unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) } == 0 {
        Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactFlushOrCloseUnavailable)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriterCloseAttempt {
    Closed,
    OwnershipAmbiguous,
}

fn classify_writer_close_attempt(closed: bool) -> WriterCloseAttempt {
    if closed {
        WriterCloseAttempt::Closed
    } else {
        WriterCloseAttempt::OwnershipAmbiguous
    }
}

pub(crate) fn close_writer(file: File) {
    let raw = file.into_raw_handle() as HANDLE;
    // SAFETY: ownership was transferred out of File exactly once and this is
    // the sole close attempt for the writer handle.
    let attempt = classify_writer_close_attempt(unsafe { CloseHandle(raw) } != 0);
    if attempt == WriterCloseAttempt::OwnershipAmbiguous {
        // CloseHandle does not document that every failure leaves the supplied
        // handle valid. Continuing or reconstructing a File could therefore
        // double-close or re-own an invalid handle. This boundary is terminal
        // and returns no ownership-bearing publication failure.
        std::process::abort();
    }
}

pub(crate) fn read_and_verify_fresh_envelope_contents(
    file: &mut impl Read,
    expected: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
) -> Result<
    [u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
    FirstRecoveryEnvelopeArtifactPublicationError,
> {
    let mut actual = [0_u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH];
    file.read_exact(&mut actual)
        .map_err(|_| FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed)?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed)?
        != 0
        || actual != *expected
    {
        return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
    }
    Ok(actual)
}

pub(crate) fn verify_fresh_envelope_contents(
    file: &mut impl Read,
    expected: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
) -> Result<(), FirstRecoveryEnvelopeArtifactPublicationError> {
    read_and_verify_fresh_envelope_contents(file, expected).map(|_| ())
}

fn attempt_publication(
    prior: &FirstRecoveryDatabaseArtifactPublished,
    expected: &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
) -> Result<RetainedFirstRecoveryEnvelopeArtifact, AttemptFailure> {
    let parent = &prior.destinations.first.initial_child;
    let final_path = fixed_envelope_path(&parent.normalized_path);
    let writer = create_new_envelope(&final_path).map_err(|error| AttemptFailure {
        partial: None,
        phase: PublicationPhase::BeforeCreation,
        error,
    })?;
    let mut partial = RetainedFirstRecoveryEnvelopeArtifact {
        file: Some(writer),
        initial: None,
    };
    let initial = query_envelope_facts(
        partial
            .file
            .as_ref()
            .expect("new envelope writer remains retained"),
    )
    .and_then(|facts| {
        validate_envelope_facts(&parent.identity, &parent.normalized_path, &facts)?;
        Ok(facts)
    });
    let initial = match initial {
        Ok(initial) => initial,
        Err(error) => {
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringWrite,
                error,
            });
        }
    };
    partial.initial = Some(initial);
    if let Err(error) = write_exact_envelope(
        partial
            .file
            .as_mut()
            .expect("envelope writer remains retained during the exact write"),
        expected,
    ) {
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringWrite,
            error,
        });
    }
    let writer = partial
        .file
        .take()
        .expect("envelope writer remains retained until flush and close");
    if flush(&writer).is_err() {
        partial.file = Some(writer);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFlushOrClose,
            error: FirstRecoveryEnvelopeArtifactPublicationError::ArtifactFlushOrCloseUnavailable,
        });
    }
    close_writer(writer);
    if prior.destinations.revalidate().is_err() {
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error: FirstRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent,
        });
    }
    let mut reopened = match open_envelope_for_verification(&final_path) {
        Ok(reopened) => reopened,
        Err(error) => {
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringFreshVerification,
                error,
            });
        }
    };
    let before = query_envelope_facts(&reopened).and_then(|facts| {
        validate_fresh_envelope_facts(&parent.identity, &parent.normalized_path, &facts)?;
        if facts.identity
            != partial
                .initial
                .as_ref()
                .expect("initial envelope facts remain retained")
                .identity
        {
            return Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed);
        }
        Ok(facts)
    });
    let before = match before {
        Ok(before) => before,
        Err(error) => {
            partial.file = Some(reopened);
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringFreshVerification,
                error,
            });
        }
    };
    if let Err(error) = verify_fresh_envelope_contents(&mut reopened, expected) {
        partial.file = Some(reopened);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error,
        });
    }
    let after = match query_envelope_facts(&reopened) {
        Ok(after) => after,
        Err(error) => {
            partial.file = Some(reopened);
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringFreshVerification,
                error,
            });
        }
    };
    if before != after {
        partial.file = Some(reopened);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error: FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed,
        });
    }
    if prior.destinations.revalidate().is_err() {
        partial.file = Some(reopened);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error: FirstRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent,
        });
    }
    partial.file = Some(reopened);
    partial.initial = Some(after);
    Ok(partial)
}

pub(super) fn publish_first_recovery_envelope_artifact(
    mut prior: FirstRecoveryDatabaseArtifactPublished,
) -> Result<
    FirstRecoveryDatabaseAndEnvelopeArtifactsPublished,
    Box<FirstRecoveryEnvelopeArtifactPublicationFailure>,
> {
    let expected_database = match prior.source.observe_recovery_database_source() {
        Ok(expected) => expected,
        Err(_) => {
            return fail(
                prior,
                None,
                PublicationPhase::BeforeCreation,
                FirstRecoveryEnvelopeArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
    };
    if let Err(error) = prior.revalidate_for_envelope_publication(
        expected_database.database_byte_length,
        expected_database.database_sha256,
    ) {
        let error = match error {
            FirstRecoveryDatabaseArtifactRevalidationError::DestinationChangedOrInconsistent => {
                FirstRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent
            }
            FirstRecoveryDatabaseArtifactRevalidationError::PriorArtifactChangedOrInvalid => {
                FirstRecoveryEnvelopeArtifactPublicationError::PriorArtifactChangedOrInvalid
            }
        };
        return fail(prior, None, PublicationPhase::BeforeCreation, error);
    }
    let attempt = prior
        .source
        .with_verified_recovery_envelope_bytes(|expected| attempt_publication(&prior, expected));
    let first_envelope = match attempt {
        Err(_) => {
            return fail(
                prior,
                None,
                PublicationPhase::BeforeCreation,
                FirstRecoveryEnvelopeArtifactPublicationError::SourceUnavailableOrChanged,
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
        Ok(Ok(first_envelope)) => first_envelope,
    };
    if let Err(error) = prior.revalidate_for_envelope_publication(
        expected_database.database_byte_length,
        expected_database.database_sha256,
    ) {
        let error = match error {
            FirstRecoveryDatabaseArtifactRevalidationError::DestinationChangedOrInconsistent => {
                FirstRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent
            }
            FirstRecoveryDatabaseArtifactRevalidationError::PriorArtifactChangedOrInvalid => {
                FirstRecoveryEnvelopeArtifactPublicationError::PriorArtifactChangedOrInvalid
            }
        };
        return fail(
            prior,
            Some(first_envelope),
            PublicationPhase::DuringFreshVerification,
            error,
        );
    }
    Ok(FirstRecoveryDatabaseAndEnvelopeArtifactsPublished {
        prior,
        first_envelope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify_writer_close_with(close: impl FnOnce() -> bool) -> WriterCloseAttempt {
        classify_writer_close_attempt(close())
    }

    #[test]
    fn first_recovery_envelope_fixed_name_and_path_are_not_caller_supplied() {
        let directory: Vec<u16> =
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\church-app-recovery-set"
                .encode_utf16()
                .collect();
        let path = String::from_utf16(&fixed_envelope_path(&directory)).unwrap();
        assert!(path.ends_with(r"\church-app-recovery-set\migration-recovery-envelope-v1.bin"));
        assert_eq!(
            FIRST_RECOVERY_ENVELOPE_FILENAME,
            "migration-recovery-envelope-v1.bin"
        );
    }

    #[test]
    fn first_recovery_envelope_exact_path_requires_filename_case_and_parent() {
        let parent: Vec<u16> =
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\church-app-recovery-set"
                .encode_utf16()
                .collect();
        let exact = fixed_envelope_path(&parent);
        assert!(exact_envelope_path(&parent, &exact));
        let folded_parent: Vec<u16> = String::from_utf16(&exact)
            .unwrap()
            .replace("Volume", "VOLUME")
            .encode_utf16()
            .collect();
        assert!(exact_envelope_path(&parent, &folded_parent));
        let wrong_name: Vec<u16> = String::from_utf16(&exact)
            .unwrap()
            .replace(
                "migration-recovery-envelope-v1.bin",
                "MIGRATION-RECOVERY-ENVELOPE-V1.BIN",
            )
            .encode_utf16()
            .collect();
        assert!(!exact_envelope_path(&parent, &wrong_name));
    }

    #[test]
    fn first_recovery_envelope_hardened_facts_reject_invalid_leafs_and_continuity() {
        let parent_path: Vec<u16> =
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\church-app-recovery-set"
                .encode_utf16()
                .collect();
        let parent_identity = RootIdentity {
            volume_serial: 7,
            file_id: [0x11; 16],
        };
        let accepted = PublishedEnvelopeFacts {
            identity: RootIdentity {
                volume_serial: 7,
                file_id: [0x22; 16],
            },
            disk_entry: true,
            directory: false,
            delete_pending: false,
            attributes: FILE_ATTRIBUTE_NORMAL,
            reparse_tag: 0,
            byte_length: MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH as u64,
            normalized_path: fixed_envelope_path(&parent_path),
        };
        assert!(validate_fresh_envelope_facts(&parent_identity, &parent_path, &accepted).is_ok());
        for rejected in [
            PublishedEnvelopeFacts {
                disk_entry: false,
                ..accepted.clone()
            },
            PublishedEnvelopeFacts {
                directory: true,
                attributes: FILE_ATTRIBUTE_DIRECTORY,
                ..accepted.clone()
            },
            PublishedEnvelopeFacts {
                delete_pending: true,
                ..accepted.clone()
            },
            PublishedEnvelopeFacts {
                attributes: FILE_ATTRIBUTE_REPARSE_POINT,
                reparse_tag: 0xa000000c,
                ..accepted.clone()
            },
            PublishedEnvelopeFacts {
                byte_length: MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH as u64 + 1,
                ..accepted.clone()
            },
            PublishedEnvelopeFacts {
                identity: RootIdentity {
                    volume_serial: 8,
                    file_id: [0x22; 16],
                },
                ..accepted.clone()
            },
            PublishedEnvelopeFacts {
                normalized_path: parent_path.clone(),
                ..accepted.clone()
            },
        ] {
            assert!(
                validate_fresh_envelope_facts(&parent_identity, &parent_path, &rejected).is_err()
            );
        }
    }

    struct PartialWriter {
        bytes: Vec<u8>,
        maximum: usize,
        fail_after: Option<usize>,
    }

    impl Write for PartialWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            if self
                .fail_after
                .is_some_and(|limit| self.bytes.len() >= limit)
            {
                return Err(std::io::Error::other("synthetic partial failure"));
            }
            let count = buffer.len().min(self.maximum);
            self.bytes.extend_from_slice(&buffer[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn first_recovery_envelope_exact_write_handles_partial_writes_and_failure() {
        let expected = [0x5a; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH];
        let mut partial = PartialWriter {
            bytes: Vec::new(),
            maximum: 7,
            fail_after: None,
        };
        write_exact_envelope(&mut partial, &expected).unwrap();
        assert_eq!(partial.bytes, expected);
        let mut failing = PartialWriter {
            bytes: Vec::new(),
            maximum: 11,
            fail_after: Some(44),
        };
        assert_eq!(
            write_exact_envelope(&mut failing, &expected),
            Err(FirstRecoveryEnvelopeArtifactPublicationError::ArtifactWriteUnavailable)
        );
        assert_eq!(failing.bytes.len(), 44);
    }

    #[test]
    fn first_recovery_envelope_fresh_bytes_require_exact_length_eof_and_equality() {
        let expected = [0x6b; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH];
        let mut exact = expected.as_slice();
        assert!(verify_fresh_envelope_contents(&mut exact, &expected).is_ok());
        let mut short = &expected[..expected.len() - 1];
        assert!(verify_fresh_envelope_contents(&mut short, &expected).is_err());
        let mut trailing = expected.to_vec();
        trailing.push(0);
        let mut trailing = trailing.as_slice();
        assert!(verify_fresh_envelope_contents(&mut trailing, &expected).is_err());
        let wrong = [0x6c; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH];
        let mut wrong = wrong.as_slice();
        assert!(verify_fresh_envelope_contents(&mut wrong, &expected).is_err());
    }

    #[test]
    fn first_recovery_envelope_create_flush_close_reopen_runtime_contract() {
        use std::os::windows::ffi::OsStrExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "church-app-first-recovery-envelope-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join(FIRST_RECOVERY_ENVELOPE_FILENAME);
        let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
        let expected = [0x3c; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH];
        let mut writer = create_new_envelope(&encoded).unwrap();
        write_exact_envelope(&mut writer, &expected).unwrap();
        flush(&writer).unwrap();
        let initial = query_envelope_facts(&writer).unwrap();
        close_writer(writer);
        let mut reopened = open_envelope_for_verification(&encoded).unwrap();
        let before = query_envelope_facts(&reopened).unwrap();
        assert!(before.identity == initial.identity);
        assert_eq!(
            before.byte_length,
            MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH as u64
        );
        verify_fresh_envelope_contents(&mut reopened, &expected).unwrap();
        let after = query_envelope_facts(&reopened).unwrap();
        assert!(before == after);
        assert_eq!(
            create_new_envelope(&encoded).unwrap_err(),
            FirstRecoveryEnvelopeArtifactPublicationError::ArtifactConflict
        );
        drop(reopened);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn injected_close_seam_classifies_success_and_ambiguous_failure_once_without_ownership() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let failure_calls = AtomicUsize::new(0);
        let failure = classify_writer_close_with(|| {
            failure_calls.fetch_add(1, Ordering::Relaxed);
            false
        });
        assert_eq!(failure_calls.load(Ordering::Relaxed), 1);
        assert_eq!(failure, WriterCloseAttempt::OwnershipAmbiguous);

        let success_calls = AtomicUsize::new(0);
        let success = classify_writer_close_with(|| {
            success_calls.fetch_add(1, Ordering::Relaxed);
            true
        });
        assert_eq!(success_calls.load(Ordering::Relaxed), 1);
        assert_eq!(success, WriterCloseAttempt::Closed);
    }

    #[test]
    fn first_recovery_envelope_surface_is_fixed_private_redacted_and_non_destructive() {
        const SOURCE: &str = include_str!("first_recovery_envelope_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        for required in [
            "CREATE_NEW",
            "FlushFileBuffers",
            "CloseHandle",
            "FILE_FLAG_OPEN_REPARSE_POINT",
            "with_verified_recovery_envelope_bytes",
            "MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH",
            "partial_first_envelope",
            "revalidate_for_envelope_publication",
        ] {
            assert!(
                production.contains(required),
                "missing contract: {required}"
            );
        }
        for excluded in [
            "recovery-set-v1.manifest",
            "remove_file",
            "remove_dir",
            "serde",
            "tauri::",
            "pub fn",
            "PathBuf",
            "seal_migration_recovery_envelope",
            "generate_migration_recovery",
        ] {
            assert!(
                !production.contains(excluded),
                "unexpected surface: {excluded}"
            );
        }
        for error in [
            FirstRecoveryEnvelopeArtifactPublicationError::ArtifactConflict,
            FirstRecoveryEnvelopeArtifactPublicationError::PriorArtifactChangedOrInvalid,
            FirstRecoveryEnvelopeArtifactPublicationError::ArtifactVerificationFailed,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains("migration-recovery-envelope"));
            assert!(!debug.contains("Volume"));
            assert!(!debug.contains("182"));
        }
    }

    #[test]
    fn first_recovery_envelope_orders_prerequisites_close_and_fresh_verification() {
        const SOURCE: &str = include_str!("first_recovery_envelope_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let publication = production
            .split_once("pub(super) fn publish_first_recovery_envelope_artifact")
            .unwrap()
            .1;
        let source_observation = publication
            .find("observe_recovery_database_source")
            .unwrap();
        let predecessor_revalidation = publication
            .find("revalidate_for_envelope_publication")
            .unwrap();
        let exact_envelope_borrow = publication
            .find("with_verified_recovery_envelope_bytes")
            .unwrap();
        let attempt = publication
            .find("attempt_publication(&prior, expected)")
            .unwrap();
        assert!(source_observation < predecessor_revalidation);
        assert!(predecessor_revalidation < exact_envelope_borrow);
        assert!(exact_envelope_borrow < attempt);

        let attempt = production
            .split_once("fn attempt_publication")
            .unwrap()
            .1
            .split_once("pub(super) fn publish_first_recovery_envelope_artifact")
            .unwrap()
            .0;
        let create = attempt.find("create_new_envelope").unwrap();
        let write = attempt.find("write_exact_envelope").unwrap();
        let flush = attempt.find("flush(&writer)").unwrap();
        let close = attempt.find("close_writer(writer)").unwrap();
        let reopen = attempt.find("open_envelope_for_verification").unwrap();
        let verify = attempt.find("verify_fresh_envelope_contents").unwrap();
        assert!(create < write);
        assert!(write < flush);
        assert!(flush < close);
        assert!(close < reopen);
        assert!(reopen < verify);
    }

    #[test]
    fn first_recovery_envelope_recoverable_failure_retains_prior_and_partial_without_cleanup() {
        const SOURCE: &str = include_str!("first_recovery_envelope_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let failure = production
            .split_once("struct FirstRecoveryEnvelopeArtifactPublicationFailure")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(failure.contains("prior: FirstRecoveryDatabaseArtifactPublished"));
        assert!(
            failure
                .contains("partial_first_envelope: Option<RetainedFirstRecoveryEnvelopeArtifact>")
        );
        assert!(failure.contains("phase: PublicationPhase"));
        let flush_failure = production
            .split_once("if flush(&writer).is_err()")
            .unwrap()
            .1
            .split_once("close_writer(writer)")
            .unwrap()
            .0;
        assert!(flush_failure.contains("partial.file = Some(writer)"));
        assert!(flush_failure.contains("partial: Some(partial)"));
        assert!(flush_failure.contains("ArtifactFlushOrCloseUnavailable"));
        assert!(!production.contains("remove_file"));
        assert!(!production.contains("remove_dir"));
    }

    #[test]
    fn close_writer_production_contract_fail_stops_without_reownership_or_retry() {
        const SOURCE: &str = include_str!("first_recovery_envelope_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let close = production
            .split_once("pub(crate) fn close_writer")
            .unwrap()
            .1
            .split_once("pub(crate) fn read_and_verify_fresh_envelope_contents")
            .unwrap()
            .0;
        assert!(close.contains("file.into_raw_handle()"));
        assert!(close.contains("CloseHandle(raw)"));
        assert!(close.contains("WriterCloseAttempt::OwnershipAmbiguous"));
        assert!(close.contains("std::process::abort()"));
        assert_eq!(close.matches("CloseHandle(raw)").count(), 1);
        assert!(!close.contains("File::from_raw_handle"));
        assert!(!close.contains("Result<"));
        assert!(!close.contains("Err("));
        assert!(!close.contains("loop"));
        assert!(!close.contains("pub fn"));
        assert!(!production.contains("File::from_raw_handle"));
        assert!(!production.contains("classify_writer_close_with"));
    }

    #[test]
    fn first_recovery_envelope_success_retains_prior_and_grants_no_completion() {
        const SOURCE: &str = include_str!("first_recovery_envelope_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let owner = production
            .split_once("struct FirstRecoveryDatabaseAndEnvelopeArtifactsPublished")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(owner.contains("prior: FirstRecoveryDatabaseArtifactPublished"));
        assert!(owner.contains("first_envelope: RetainedFirstRecoveryEnvelopeArtifact"));
        for forbidden in [
            "CompleteRecoverySet",
            "manifest",
            "second_envelope",
            "set_2",
        ] {
            assert!(!owner.contains(forbidden));
        }
    }

    #[test]
    fn envelope_failure_abandonment_is_consuming_source_only_and_filesystem_inert() {
        const SOURCE: &str = include_str!("first_recovery_envelope_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let abandonment = production
            .split_once("impl FirstRecoveryEnvelopeArtifactPublicationFailure")
            .unwrap()
            .1
            .split_once("struct AttemptFailure")
            .unwrap()
            .0;
        for required in [
            "self",
            "prior,",
            "partial_first_envelope: _partial_first_envelope",
            "phase: _phase",
            "error: _error",
            "prior.abandon_published_destination_and_retain_source()",
        ] {
            assert!(abandonment.contains(required));
        }
        for forbidden in [
            "remove_file",
            "remove_dir",
            "rename",
            "set_len",
            "truncate",
            "write",
            "create",
            "open",
            "revalidate",
            "retry",
        ] {
            assert!(!abandonment.contains(forbidden));
        }
    }

    #[test]
    fn envelope_success_abandonment_preserves_manifest_predecessor_contract() {
        const SOURCE: &str = include_str!("first_recovery_envelope_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let owner_impl = production
            .split_once("impl FirstRecoveryDatabaseAndEnvelopeArtifactsPublished")
            .unwrap()
            .1
            .split_once("enum FirstRecoveryEnvelopeArtifactPublicationError")
            .unwrap()
            .0;
        let abandonment = owner_impl
            .split_once("abandon_published_destination_and_retain_source")
            .unwrap()
            .1
            .split_once("fn revalidate_for_manifest_publication")
            .unwrap()
            .0;
        assert!(abandonment.contains("prior,"));
        assert!(abandonment.contains("first_envelope: _first_envelope"));
        assert!(abandonment.contains("prior.abandon_published_destination_and_retain_source()"));
        for forbidden in [
            "remove_file",
            "remove_dir",
            "rename",
            "set_len",
            "truncate",
            "write",
            "create",
            "open",
            "manifest",
            "retry",
        ] {
            assert!(!abandonment.contains(forbidden));
        }
        assert!(owner_impl.contains("fn revalidate_for_manifest_publication"));
        assert!(owner_impl.contains("self.prior"));
        assert!(owner_impl.contains("self.first_envelope.revalidate"));
    }
}
