//! First-set-only publication of the fixed recovery database artifact.

#[path = "first_recovery_database_artifact/first_recovery_envelope_artifact.rs"]
mod first_recovery_envelope_artifact;

pub(crate) use first_recovery_envelope_artifact::FirstRecoveryDatabaseAndEnvelopeArtifactsPublished;

use std::{
    ffi::c_void,
    fmt,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle},
};

use sha2::{Digest, Sha256};
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

use crate::{
    application_lifecycle::RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    storage_foundation::PRODUCTION_DATABASE_FILENAME,
};

use super::{FINAL_PATH_FLAGS, RootIdentity, TwoRetainedRecoverySetDirectories, fold_ascii};

const COPY_BUFFER_LENGTH: usize = 64 * 1024;

#[derive(Clone, Eq, PartialEq)]
struct PublishedDatabaseFacts {
    identity: RootIdentity,
    disk_entry: bool,
    directory: bool,
    delete_pending: bool,
    attributes: u32,
    reparse_tag: u32,
    byte_length: u64,
    normalized_path: Vec<u16>,
}

struct RetainedFirstRecoveryDatabaseArtifact {
    file: Option<File>,
    initial: Option<PublishedDatabaseFacts>,
}

impl RetainedFirstRecoveryDatabaseArtifact {
    fn revalidate(
        &mut self,
        parent_identity: &RootIdentity,
        parent_path: &[u16],
        expected_length: u64,
        expected_digest: [u8; 32],
    ) -> Result<(), FirstRecoveryDatabaseArtifactPublicationError> {
        let file = self
            .file
            .as_mut()
            .ok_or(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed)?;
        let before = query_database_facts(file)?;
        validate_database_facts(parent_identity, parent_path, &before)?;
        if self.initial.as_ref() != Some(&before) || before.byte_length != expected_length {
            return Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
        }
        file.seek(SeekFrom::Start(0)).map_err(|_| {
            FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed
        })?;
        verify_fresh_contents(file, expected_length, expected_digest)?;
        let after = query_database_facts(file)?;
        if before != after {
            return Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
        }
        Ok(())
    }
}

pub(crate) struct FirstRecoveryDatabaseArtifactPublished {
    source: RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    destinations: TwoRetainedRecoverySetDirectories,
    first_database: RetainedFirstRecoveryDatabaseArtifact,
}

enum FirstRecoveryDatabaseArtifactRevalidationError {
    DestinationChangedOrInconsistent,
    PriorArtifactChangedOrInvalid,
}

impl FirstRecoveryDatabaseArtifactPublished {
    pub(crate) fn abandon_published_destination_and_retain_source(
        self,
    ) -> RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup {
        let Self {
            source,
            destinations: _destinations,
            first_database: _first_database,
        } = self;
        source
    }

    fn revalidate_for_envelope_publication(
        &mut self,
        expected_length: u64,
        expected_digest: [u8; 32],
    ) -> Result<(), FirstRecoveryDatabaseArtifactRevalidationError> {
        self.destinations.revalidate().map_err(|_| {
            FirstRecoveryDatabaseArtifactRevalidationError::DestinationChangedOrInconsistent
        })?;
        self.first_database
            .revalidate(
                &self.destinations.first.initial_child.identity,
                &self.destinations.first.initial_child.normalized_path,
                expected_length,
                expected_digest,
            )
            .map_err(|_| {
                FirstRecoveryDatabaseArtifactRevalidationError::PriorArtifactChangedOrInvalid
            })?;
        self.destinations.revalidate().map_err(|_| {
            FirstRecoveryDatabaseArtifactRevalidationError::DestinationChangedOrInconsistent
        })
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum FirstRecoveryEnvelopePublicationOutcome {
    Published(FirstRecoveryDatabaseAndEnvelopeArtifactsPublished),
    Source(RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup),
}

pub(crate) fn publish_first_recovery_envelope_artifact(
    prior: FirstRecoveryDatabaseArtifactPublished,
) -> FirstRecoveryEnvelopePublicationOutcome {
    match first_recovery_envelope_artifact::publish_first_recovery_envelope_artifact(prior) {
        Ok(published) => FirstRecoveryEnvelopePublicationOutcome::Published(published),
        Err(failure) => FirstRecoveryEnvelopePublicationOutcome::Source(
            failure.abandon_partial_destination_and_retain_source(),
        ),
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum FirstRecoveryDatabaseArtifactPublicationError {
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

pub(super) struct FirstRecoveryDatabaseArtifactPublicationFailure {
    source: RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    destinations: TwoRetainedRecoverySetDirectories,
    partial_first_database: Option<RetainedFirstRecoveryDatabaseArtifact>,
    phase: PublicationPhase,
    error: FirstRecoveryDatabaseArtifactPublicationError,
}

impl FirstRecoveryDatabaseArtifactPublicationFailure {
    pub(super) fn abandon_partial_destination_and_retain_source(
        self,
    ) -> RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup {
        let Self {
            source,
            destinations: _destinations,
            partial_first_database: _partial_first_database,
            phase: _phase,
            error: _error,
        } = self;
        source
    }
}

impl fmt::Debug for RetainedFirstRecoveryDatabaseArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedFirstRecoveryDatabaseArtifact([REDACTED])")
    }
}

impl fmt::Debug for FirstRecoveryDatabaseArtifactPublished {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirstRecoveryDatabaseArtifactPublished([REDACTED])")
    }
}

impl fmt::Debug for FirstRecoveryDatabaseArtifactPublicationError {
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

impl fmt::Debug for FirstRecoveryDatabaseArtifactPublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            PublicationPhase::BeforeCreation => "BeforeCreation",
            PublicationPhase::DuringWrite => "DuringWrite",
            PublicationPhase::DuringFlushOrClose => "DuringFlushOrClose",
            PublicationPhase::DuringFreshVerification => "DuringFreshVerification",
        };
        write!(
            formatter,
            "FirstRecoveryDatabaseArtifactPublicationFailure({phase}, {:?})",
            self.error
        )
    }
}

fn fail(
    source: RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    destinations: TwoRetainedRecoverySetDirectories,
    partial_first_database: Option<RetainedFirstRecoveryDatabaseArtifact>,
    phase: PublicationPhase,
    error: FirstRecoveryDatabaseArtifactPublicationError,
) -> Result<
    FirstRecoveryDatabaseArtifactPublished,
    Box<FirstRecoveryDatabaseArtifactPublicationFailure>,
> {
    Err(Box::new(FirstRecoveryDatabaseArtifactPublicationFailure {
        source,
        destinations,
        partial_first_database,
        phase,
        error,
    }))
}

fn fixed_database_path(directory_path: &[u16]) -> Vec<u16> {
    directory_path
        .iter()
        .copied()
        .chain(std::iter::once(b'\\' as u16))
        .chain(PRODUCTION_DATABASE_FILENAME.encode_utf16())
        .collect()
}

fn nul_terminated(path: &[u16]) -> Result<Vec<u16>, FirstRecoveryDatabaseArtifactPublicationError> {
    if path.is_empty() || path.len() > super::MAXIMUM_FINAL_PATH_UNITS || path.contains(&0) {
        return Err(
            FirstRecoveryDatabaseArtifactPublicationError::DestinationChangedOrInconsistent,
        );
    }
    let mut value = Vec::with_capacity(path.len() + 1);
    value.extend_from_slice(path);
    value.push(0);
    Ok(value)
}

fn create_new_database(
    path: &[u16],
) -> Result<File, FirstRecoveryDatabaseArtifactPublicationError> {
    let path = nul_terminated(path)?;
    // SAFETY: the exact retained-directory-derived final path is live and
    // NUL-terminated. CREATE_NEW, zero sharing, and open-reparse-point
    // semantics prevent replacement and following an unexpected leaf object.
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
                Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactConflict)
            }
            _ => Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactCreationUnavailable),
        };
    }
    // SAFETY: ownership of the fresh successful handle is transferred once.
    Ok(File::from(unsafe {
        OwnedHandle::from_raw_handle(raw as RawHandle)
    }))
}

fn open_database_for_verification(
    path: &[u16],
) -> Result<File, FirstRecoveryDatabaseArtifactPublicationError> {
    let path = nul_terminated(path)?;
    // SAFETY: the exact retained-directory-derived final path is reopened
    // independently, read-only, without write or delete sharing, and without
    // following a reparse leaf.
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
        return Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
    }
    // SAFETY: ownership of the fresh successful handle is transferred once.
    Ok(File::from(unsafe {
        OwnedHandle::from_raw_handle(raw as RawHandle)
    }))
}

fn checked_information_size<T>() -> Result<u32, FirstRecoveryDatabaseArtifactPublicationError> {
    u32::try_from(std::mem::size_of::<T>())
        .map_err(|_| FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed)
}

fn query_normalized_path(
    file: &File,
) -> Result<Vec<u16>, FirstRecoveryDatabaseArtifactPublicationError> {
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: documented size query on the live owned handle.
    let required =
        unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, FINAL_PATH_FLAGS) };
    let capacity = usize::try_from(required)
        .map_err(|_| FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed)?;
    if capacity == 0 || capacity > super::MAXIMUM_FINAL_PATH_UNITS {
        return Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
    }
    let mut output = vec![0_u16; capacity];
    // SAFETY: output is writable for the checked capacity and the handle stays live.
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, output.as_mut_ptr(), required, FINAL_PATH_FLAGS)
    };
    let written = usize::try_from(written)
        .map_err(|_| FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed)?;
    if written == 0 || written >= output.len() || written > super::MAXIMUM_FINAL_PATH_UNITS {
        return Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
    }
    output.truncate(written);
    Ok(output)
}

fn query_database_facts(
    file: &File,
) -> Result<PublishedDatabaseFacts, FirstRecoveryDatabaseArtifactPublicationError> {
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
        return Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
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
        return Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
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
        return Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
    }
    let byte_length = u64::try_from(standard.EndOfFile)
        .map_err(|_| FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed)?;
    Ok(PublishedDatabaseFacts {
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

fn exact_database_path(directory: &[u16], observed: &[u16]) -> bool {
    let filename: Vec<u16> = PRODUCTION_DATABASE_FILENAME.encode_utf16().collect();
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

fn validate_database_facts(
    parent_identity: &RootIdentity,
    parent_path: &[u16],
    facts: &PublishedDatabaseFacts,
) -> Result<(), FirstRecoveryDatabaseArtifactPublicationError> {
    if !facts.disk_entry
        || facts.directory
        || facts.delete_pending
        || facts.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || facts.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || facts.reparse_tag != 0
        || facts.identity.volume_serial != parent_identity.volume_serial
        || !exact_database_path(parent_path, &facts.normalized_path)
    {
        return Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
    }
    Ok(())
}

fn flush(file: &File) -> Result<(), FirstRecoveryDatabaseArtifactPublicationError> {
    // SAFETY: the live writer was opened with GENERIC_WRITE.
    if unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) } == 0 {
        Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactFlushOrCloseUnavailable)
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

fn close_writer(file: File) -> Result<(), FirstRecoveryDatabaseArtifactPublicationError> {
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
    Ok(())
}

fn verify_fresh_contents(
    file: &mut File,
    expected_length: u64,
    expected_digest: [u8; 32],
) -> Result<(), FirstRecoveryDatabaseArtifactPublicationError> {
    let mut buffer = [0_u8; COPY_BUFFER_LENGTH];
    let mut count = 0_u64;
    let mut hasher = Sha256::new();
    loop {
        let read = file.read(&mut buffer).map_err(|_| {
            FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed
        })?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(u64::try_from(read).map_err(|_| {
                FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed
            })?)
            .ok_or(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed)?;
        hasher.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if count != expected_length || digest != expected_digest {
        return Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
    }
    Ok(())
}

pub(super) fn publish_first_recovery_database_artifact(
    source: RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    destinations: TwoRetainedRecoverySetDirectories,
) -> Result<
    FirstRecoveryDatabaseArtifactPublished,
    Box<FirstRecoveryDatabaseArtifactPublicationFailure>,
> {
    if source.prepare_recovery_set_manifest_v1().is_err() {
        return fail(
            source,
            destinations,
            None,
            PublicationPhase::BeforeCreation,
            FirstRecoveryDatabaseArtifactPublicationError::SourceUnavailableOrChanged,
        );
    }
    let expected = match source.observe_recovery_database_source() {
        Ok(expected) => expected,
        Err(_) => {
            return fail(
                source,
                destinations,
                None,
                PublicationPhase::BeforeCreation,
                FirstRecoveryDatabaseArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
    };
    if destinations.revalidate().is_err() {
        return fail(
            source,
            destinations,
            None,
            PublicationPhase::BeforeCreation,
            FirstRecoveryDatabaseArtifactPublicationError::DestinationChangedOrInconsistent,
        );
    }
    let final_path = fixed_database_path(&destinations.first.initial_child.normalized_path);
    let writer = match create_new_database(&final_path) {
        Ok(writer) => writer,
        Err(error) => {
            return fail(
                source,
                destinations,
                None,
                PublicationPhase::BeforeCreation,
                error,
            );
        }
    };
    let mut partial = RetainedFirstRecoveryDatabaseArtifact {
        file: Some(writer),
        initial: None,
    };
    let initial = match query_database_facts(
        partial
            .file
            .as_ref()
            .expect("new writer remains retained during initial verification"),
    )
    .and_then(|facts| {
        validate_database_facts(
            &destinations.first.initial_child.identity,
            &destinations.first.initial_child.normalized_path,
            &facts,
        )?;
        Ok(facts)
    }) {
        Ok(initial) => initial,
        Err(error) => {
            return fail(
                source,
                destinations,
                Some(partial),
                PublicationPhase::DuringWrite,
                error,
            );
        }
    };
    partial.initial = Some(initial);
    let mut write_failed = false;
    let streamed = source.stream_recovery_database_source(|chunk| {
        let result = partial
            .file
            .as_mut()
            .expect("writer remains retained during streaming")
            .write_all(chunk);
        if result.is_err() {
            write_failed = true;
        }
        result.map_err(|_| ())
    });
    let streamed = match streamed {
        Ok(streamed) if streamed == expected => streamed,
        _ if write_failed => {
            return fail(
                source,
                destinations,
                Some(partial),
                PublicationPhase::DuringWrite,
                FirstRecoveryDatabaseArtifactPublicationError::ArtifactWriteUnavailable,
            );
        }
        _ => {
            return fail(
                source,
                destinations,
                Some(partial),
                PublicationPhase::DuringWrite,
                FirstRecoveryDatabaseArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
    };
    let writer = partial
        .file
        .take()
        .expect("writer remains retained until flush and close");
    if flush(&writer).is_err() {
        partial.file = Some(writer);
        return fail(
            source,
            destinations,
            Some(partial),
            PublicationPhase::DuringFlushOrClose,
            FirstRecoveryDatabaseArtifactPublicationError::ArtifactFlushOrCloseUnavailable,
        );
    }
    close_writer(writer).expect("native writer close either succeeds or fail-stops");
    if destinations.revalidate().is_err() {
        return fail(
            source,
            destinations,
            Some(partial),
            PublicationPhase::DuringFreshVerification,
            FirstRecoveryDatabaseArtifactPublicationError::DestinationChangedOrInconsistent,
        );
    }
    let mut reopened = match open_database_for_verification(&final_path) {
        Ok(reopened) => reopened,
        Err(error) => {
            return fail(
                source,
                destinations,
                Some(partial),
                PublicationPhase::DuringFreshVerification,
                error,
            );
        }
    };
    let before = match query_database_facts(&reopened).and_then(|facts| {
        validate_database_facts(
            &destinations.first.initial_child.identity,
            &destinations.first.initial_child.normalized_path,
            &facts,
        )?;
        if facts.identity
            != partial
                .initial
                .as_ref()
                .expect("initial facts remain retained through fresh verification")
                .identity
            || facts.byte_length != streamed.database_byte_length
        {
            return Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed);
        }
        Ok(facts)
    }) {
        Ok(before) => before,
        Err(error) => {
            return fail(
                source,
                destinations,
                Some(partial),
                PublicationPhase::DuringFreshVerification,
                error,
            );
        }
    };
    if verify_fresh_contents(
        &mut reopened,
        streamed.database_byte_length,
        streamed.database_sha256,
    )
    .is_err()
    {
        return fail(
            source,
            destinations,
            Some(partial),
            PublicationPhase::DuringFreshVerification,
            FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed,
        );
    }
    let after = match query_database_facts(&reopened) {
        Ok(after) => after,
        Err(error) => {
            return fail(
                source,
                destinations,
                Some(partial),
                PublicationPhase::DuringFreshVerification,
                error,
            );
        }
    };
    if before != after {
        return fail(
            source,
            destinations,
            Some(partial),
            PublicationPhase::DuringFreshVerification,
            FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed,
        );
    }
    if destinations.revalidate().is_err() {
        return fail(
            source,
            destinations,
            Some(partial),
            PublicationPhase::DuringFreshVerification,
            FirstRecoveryDatabaseArtifactPublicationError::DestinationChangedOrInconsistent,
        );
    }
    partial.file = Some(reopened);
    partial.initial = Some(after);
    Ok(FirstRecoveryDatabaseArtifactPublished {
        source,
        destinations,
        first_database: partial,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
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
        storage_foundation::database_key_persistence_paths,
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn create(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "church-app-first-database-ownership-{label}-{}-{}",
                std::process::id(),
                TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
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

    fn custody_verified_source() -> (
        crate::production_database_connection_handoff::MigrationDiscoveryTestRoot,
        TestRoot,
        RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    ) {
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
        (source_root, stage_root, source)
    }

    fn classify_writer_close_with(close: impl FnOnce() -> bool) -> WriterCloseAttempt {
        classify_writer_close_attempt(close())
    }

    #[test]
    fn fixed_final_name_and_path_are_not_caller_supplied() {
        let directory: Vec<u16> =
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\church-app-recovery-set"
                .encode_utf16()
                .collect();
        let path = String::from_utf16(&fixed_database_path(&directory)).unwrap();
        assert!(path.ends_with(r"\church-app-recovery-set\parish-data.db"));
        assert_eq!(PRODUCTION_DATABASE_FILENAME, "parish-data.db");
    }

    #[test]
    fn final_path_requires_exact_filename_beneath_the_retained_parent() {
        let parent: Vec<u16> =
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\church-app-recovery-set"
                .encode_utf16()
                .collect();
        let exact = fixed_database_path(&parent);
        assert!(exact_database_path(&parent, &exact));

        let folded_parent: Vec<u16> = String::from_utf16(&exact)
            .unwrap()
            .replace("Volume", "VOLUME")
            .encode_utf16()
            .collect();
        assert!(exact_database_path(&parent, &folded_parent));

        let wrong_filename: Vec<u16> = String::from_utf16(&exact)
            .unwrap()
            .replace("parish-data.db", "PARISH-DATA.DB")
            .encode_utf16()
            .collect();
        assert!(!exact_database_path(&parent, &wrong_filename));
    }

    #[test]
    fn hardened_file_facts_reject_directory_reparse_pending_path_and_volume_changes() {
        let parent_path: Vec<u16> =
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\church-app-recovery-set"
                .encode_utf16()
                .collect();
        let parent_identity = RootIdentity {
            volume_serial: 7,
            file_id: [0x11; 16],
        };
        let accepted = PublishedDatabaseFacts {
            identity: RootIdentity {
                volume_serial: 7,
                file_id: [0x22; 16],
            },
            disk_entry: true,
            directory: false,
            delete_pending: false,
            attributes: FILE_ATTRIBUTE_NORMAL,
            reparse_tag: 0,
            byte_length: 4096,
            normalized_path: fixed_database_path(&parent_path),
        };
        assert!(validate_database_facts(&parent_identity, &parent_path, &accepted).is_ok());

        for rejected in [
            PublishedDatabaseFacts {
                directory: true,
                attributes: FILE_ATTRIBUTE_DIRECTORY,
                ..accepted.clone()
            },
            PublishedDatabaseFacts {
                attributes: FILE_ATTRIBUTE_REPARSE_POINT,
                reparse_tag: 0xa000000c,
                ..accepted.clone()
            },
            PublishedDatabaseFacts {
                delete_pending: true,
                ..accepted.clone()
            },
            PublishedDatabaseFacts {
                identity: RootIdentity {
                    volume_serial: 8,
                    file_id: [0x22; 16],
                },
                ..accepted.clone()
            },
            PublishedDatabaseFacts {
                normalized_path: parent_path.clone(),
                ..accepted.clone()
            },
        ] {
            assert!(validate_database_facts(&parent_identity, &parent_path, &rejected).is_err());
        }
    }

    #[test]
    fn fresh_content_verification_requires_exact_length_and_digest() {
        let root = std::env::temp_dir().join(format!(
            "church-app-first-recovery-database-{}",
            std::process::id()
        ));
        let path = root.join("synthetic-source");
        std::fs::create_dir(&root).unwrap();
        let payload = vec![0x5a; COPY_BUFFER_LENGTH + 17];
        std::fs::write(&path, &payload).unwrap();
        let expected: [u8; 32] = Sha256::digest(&payload).into();
        let mut file = File::open(&path).unwrap();
        assert!(verify_fresh_contents(&mut file, payload.len() as u64, expected).is_ok());
        let mut file = File::open(&path).unwrap();
        assert!(verify_fresh_contents(&mut file, payload.len() as u64 + 1, expected).is_err());
        let mut file = File::open(&path).unwrap();
        assert!(verify_fresh_contents(&mut file, payload.len() as u64, [0; 32]).is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn create_new_flush_close_and_fresh_reopen_runtime_contract() {
        use std::os::windows::ffi::OsStrExt;
        use std::sync::atomic::{AtomicU64, Ordering};

        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "church-app-first-recovery-publication-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join(PRODUCTION_DATABASE_FILENAME);
        let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
        let payload = vec![0x3c; COPY_BUFFER_LENGTH + 29];
        let digest: [u8; 32] = Sha256::digest(&payload).into();

        let mut writer = create_new_database(&encoded).unwrap();
        writer.write_all(&payload).unwrap();
        flush(&writer).unwrap();
        let initial = query_database_facts(&writer).unwrap();
        close_writer(writer).unwrap();

        let mut reopened = open_database_for_verification(&encoded).unwrap();
        let before = query_database_facts(&reopened).unwrap();
        assert!(before.identity == initial.identity);
        assert_eq!(before.byte_length, payload.len() as u64);
        verify_fresh_contents(&mut reopened, payload.len() as u64, digest).unwrap();
        let after = query_database_facts(&reopened).unwrap();
        assert!(before == after);
        assert_eq!(
            create_new_database(&encoded).unwrap_err(),
            FirstRecoveryDatabaseArtifactPublicationError::ArtifactConflict
        );

        drop(reopened);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn publication_surface_is_private_fixed_and_redacted() {
        const SOURCE: &str = include_str!("first_recovery_database_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        for required in [
            "CREATE_NEW",
            "FlushFileBuffers",
            "CloseHandle",
            "FILE_FLAG_OPEN_REPARSE_POINT",
            "COPY_BUFFER_LENGTH: usize = 64 * 1024",
            "prepare_recovery_set_manifest_v1",
            "observe_recovery_database_source",
            "stream_recovery_database_source",
        ] {
            assert!(production.contains(required));
        }
        for excluded in [
            "migration-recovery-envelope-v1.bin",
            "recovery-set-v1.manifest",
            "remove_file",
            "remove_dir",
            "serde",
            "tauri::",
            "pub fn",
            "PathBuf",
        ] {
            assert!(
                !production.contains(excluded),
                "unexpected production surface: {excluded}"
            );
        }
        for value in [
            format!(
                "{:?}",
                FirstRecoveryDatabaseArtifactPublicationError::ArtifactConflict
            ),
            format!(
                "{:?}",
                FirstRecoveryDatabaseArtifactPublicationError::ArtifactVerificationFailed
            ),
        ] {
            assert!(!value.contains("parish-data.db"));
            assert!(!value.contains("Volume"));
        }
    }

    #[test]
    fn source_locks_success_and_failure_ownership_without_set_completion_claim() {
        const SOURCE: &str = include_str!("first_recovery_database_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("struct FirstRecoveryDatabaseArtifactPublished"));
        assert!(
            production
                .contains("source: RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup")
        );
        assert!(production.contains("destinations: TwoRetainedRecoverySetDirectories"));
        assert!(
            production
                .contains("partial_first_database: Option<RetainedFirstRecoveryDatabaseArtifact>")
        );
        assert!(!production.contains("CompleteRecoverySet"));
        assert!(!production.contains("SecondRecoveryDatabase"));
    }

    #[test]
    fn writer_close_classification_is_single_attempt_and_ambiguous_on_failure() {
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
    fn close_writer_fail_stops_without_reownership_retry_or_fresh_verification() {
        const SOURCE: &str = include_str!("first_recovery_database_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let close = production
            .split_once("fn close_writer")
            .unwrap()
            .1
            .split_once("fn verify_fresh_contents")
            .unwrap()
            .0;
        assert!(close.contains("file.into_raw_handle()"));
        assert!(close.contains("CloseHandle(raw)"));
        assert!(close.contains("WriterCloseAttempt::OwnershipAmbiguous"));
        assert!(close.contains("std::process::abort()"));
        assert_eq!(close.matches("CloseHandle(raw)").count(), 1);
        assert!(!close.contains("File::from_raw_handle"));
        assert!(close.contains("Ok(())"));
        assert!(!close.contains("Err("));
        assert!(!close.contains("loop"));

        let publication = production
            .split_once("pub(super) fn publish_first_recovery_database_artifact")
            .unwrap()
            .1;
        let after_close = publication
            .split_once(
                "close_writer(writer).expect(\"native writer close either succeeds or fail-stops\");",
            )
            .unwrap()
            .1;
        assert!(after_close.starts_with("\n    if destinations.revalidate()"));
        assert!(!production.contains("File::from_raw_handle"));
        assert!(!production.contains("classify_writer_close_with"));
    }

    #[test]
    fn flush_failure_remains_recoverable_but_close_ambiguity_cannot_return_failure() {
        const SOURCE: &str = include_str!("first_recovery_database_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let publication = production
            .split_once("pub(super) fn publish_first_recovery_database_artifact")
            .unwrap()
            .1;
        let flush_failure = publication
            .split_once("if flush(&writer).is_err()")
            .unwrap()
            .1
            .split_once("close_writer(writer).expect")
            .unwrap()
            .0;
        assert!(flush_failure.contains("partial.file = Some(writer)"));
        assert!(flush_failure.contains("Some(partial)"));
        assert!(flush_failure.contains("ArtifactFlushOrCloseUnavailable"));

        let close_transition = publication
            .split_once("close_writer(writer).expect")
            .unwrap()
            .1
            .split_once("if destinations.revalidate()")
            .unwrap()
            .0;
        assert!(!close_transition.contains("fail("));
        assert!(!close_transition.contains("ArtifactFlushOrCloseUnavailable"));
        assert!(!close_transition.contains("open_database_for_verification"));
    }

    #[test]
    fn abandonment_is_consuming_source_only_and_filesystem_inert() {
        const SOURCE: &str = include_str!("first_recovery_database_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let abandonment = production
            .split_once("pub(super) fn abandon_partial_destination_and_retain_source")
            .unwrap()
            .1
            .split_once("impl fmt::Debug for RetainedFirstRecoveryDatabaseArtifact")
            .unwrap()
            .0;
        for required in [
            "self",
            "source,",
            "destinations: _destinations",
            "partial_first_database: _partial_first_database",
            "phase: _phase",
            "error: _error",
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
            "verify",
            "publish_first_recovery_database_artifact",
            "retry",
        ] {
            assert!(
                !abandonment.contains(forbidden),
                "unexpected operation: {forbidden}"
            );
        }
        assert!(abandonment.trim_end().ends_with("source\n    }\n}"));

        let failure_fields = production
            .split_once("pub(super) struct FirstRecoveryDatabaseArtifactPublicationFailure")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(
            failure_fields
                .contains("source: RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup")
        );
        assert!(failure_fields.contains("destinations: TwoRetainedRecoverySetDirectories"));
        assert!(
            failure_fields
                .contains("partial_first_database: Option<RetainedFirstRecoveryDatabaseArtifact>")
        );
        assert!(!abandonment.contains("Result<"));
        assert!(!abandonment.contains("Option<"));
        assert!(!abandonment.contains("TwoRetainedRecoverySetDirectories"));
        assert!(!abandonment.contains("RetainedFirstRecoveryDatabaseArtifact"));
    }

    #[test]
    fn abandonment_returns_exact_source_drops_handles_and_supports_shutdown() {
        fn accepts_fresh_destination_selection_source(
            source: RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
        ) -> RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup {
            source
        }

        let (source_root, _stage_root, source) = custody_verified_source();
        let original_observation = source.observe_recovery_database_source().unwrap();
        let destination_root = TestRoot::create("destinations");
        let first = destination_root.path().join("first");
        let second = destination_root.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let destinations =
            super::super::retained_recovery_set_directories_for_test(&first, &second);

        use std::os::windows::ffi::OsStrExt;
        let partial_path = first.join(PRODUCTION_DATABASE_FILENAME);
        let partial_encoded: Vec<u16> = partial_path.as_os_str().encode_wide().collect();
        let mut partial_file = create_new_database(&partial_encoded).unwrap();
        let partial_bytes = b"synthetic represented partial database";
        partial_file.write_all(partial_bytes).unwrap();
        flush(&partial_file).unwrap();
        let initial = query_database_facts(&partial_file).unwrap();
        let failure = FirstRecoveryDatabaseArtifactPublicationFailure {
            source,
            destinations,
            partial_first_database: Some(RetainedFirstRecoveryDatabaseArtifact {
                file: Some(partial_file),
                initial: Some(initial),
            }),
            phase: PublicationPhase::DuringFlushOrClose,
            error: FirstRecoveryDatabaseArtifactPublicationError::ArtifactFlushOrCloseUnavailable,
        };

        let retained_source = failure.abandon_partial_destination_and_retain_source();
        assert!(
            retained_source.observe_recovery_database_source().unwrap() == original_observation
        );
        assert_eq!(fs::read(&partial_path).unwrap(), partial_bytes);
        assert!(first.is_dir());
        assert!(second.is_dir());

        let moved_partial = first.join("represented-partial-moved-by-test.db");
        fs::rename(&partial_path, &moved_partial).unwrap();
        let moved_first = destination_root.path().join("first-moved-by-test");
        fs::rename(&first, &moved_first).unwrap();
        let moved_second = destination_root.path().join("second-moved-by-test");
        fs::rename(&second, &moved_second).unwrap();

        let retained_source = accepts_fresh_destination_selection_source(retained_source);
        let shutdown = retained_source.abort_for_shutdown();
        let _source_close_outcome = shutdown.retry_source_close();
        drop(source_root);
    }

    #[test]
    fn success_abandonment_is_consuming_source_only_and_filesystem_inert() {
        const SOURCE: &str = include_str!("first_recovery_database_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let abandonment = production
            .split_once("pub(crate) fn abandon_published_destination_and_retain_source")
            .unwrap()
            .1
            .split_once("fn revalidate_for_envelope_publication")
            .unwrap()
            .0;
        for required in [
            "self",
            "source,",
            "destinations: _destinations",
            "first_database: _first_database",
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
            "verify",
            "publish_first_recovery_envelope_artifact",
            "retry",
        ] {
            assert!(
                !abandonment.contains(forbidden),
                "unexpected operation: {forbidden}"
            );
        }
        assert!(abandonment.trim_end().ends_with("source\n    }"));
        assert!(!abandonment.contains("Result<"));
        assert!(!abandonment.contains("Option<"));
        assert!(!abandonment.contains("TwoRetainedRecoverySetDirectories"));
        assert!(!abandonment.contains("RetainedFirstRecoveryDatabaseArtifact"));
    }

    #[test]
    fn successful_publication_abandonment_returns_source_and_leaves_bytes_untouched() {
        let (source_root, _stage_root, source) = custody_verified_source();
        let original_observation = source.observe_recovery_database_source().unwrap();
        let destination_root = TestRoot::create("published-abandonment");
        let first = destination_root.path().join("first");
        let second = destination_root.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let destinations =
            super::super::retained_recovery_set_directories_for_test(&first, &second);

        let published = publish_first_recovery_database_artifact(source, destinations).unwrap();
        let published_path = first.join(PRODUCTION_DATABASE_FILENAME);
        let published_bytes = fs::read(&published_path).unwrap();
        assert_eq!(
            published_bytes.len() as u64,
            original_observation.database_byte_length
        );
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&published_bytes)),
            original_observation.database_sha256
        );
        assert_eq!(fs::read_dir(&second).unwrap().count(), 0);

        let retained_source = published.abandon_published_destination_and_retain_source();
        assert!(
            retained_source.observe_recovery_database_source().unwrap() == original_observation
        );
        assert_eq!(fs::read(&published_path).unwrap(), published_bytes);

        let moved_published = first.join("published-database-moved-by-test.db");
        fs::rename(&published_path, &moved_published).unwrap();
        let moved_first = destination_root.path().join("first-moved-by-test");
        fs::rename(&first, &moved_first).unwrap();
        let moved_second = destination_root.path().join("second-moved-by-test");
        fs::rename(&second, &moved_second).unwrap();
        assert_eq!(
            fs::read(moved_first.join("published-database-moved-by-test.db")).unwrap(),
            published_bytes
        );

        let shutdown = retained_source.abort_for_shutdown();
        let _source_close_outcome = shutdown.retry_source_close();
        drop(source_root);
    }

    #[test]
    fn create_new_conflict_returns_ordinary_failure_resolvable_to_source() {
        let (source_root, _stage_root, source) = custody_verified_source();
        let original_observation = source.observe_recovery_database_source().unwrap();
        let destination_root = TestRoot::create("conflict");
        let first = destination_root.path().join("first");
        let second = destination_root.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let conflict = first.join(PRODUCTION_DATABASE_FILENAME);
        let conflict_bytes = b"synthetic pre-existing conflict";
        fs::write(&conflict, conflict_bytes).unwrap();
        let destinations =
            super::super::retained_recovery_set_directories_for_test(&first, &second);

        let failure = *publish_first_recovery_database_artifact(source, destinations).unwrap_err();
        assert!(failure.partial_first_database.is_none());
        assert!(failure.phase == PublicationPhase::BeforeCreation);
        assert!(failure.error == FirstRecoveryDatabaseArtifactPublicationError::ArtifactConflict);
        assert_eq!(fs::read(&conflict).unwrap(), conflict_bytes);
        assert_eq!(fs::read_dir(&second).unwrap().count(), 0);

        let retained_source = failure.abandon_partial_destination_and_retain_source();
        assert!(
            retained_source.observe_recovery_database_source().unwrap() == original_observation
        );
        let shutdown = retained_source.abort_for_shutdown();
        let _source_close_outcome = shutdown.retry_source_close();
        drop(source_root);
    }

    #[test]
    fn envelope_failure_abandonment_returns_source_and_leaves_published_bytes_untouched() {
        let (source_root, _stage_root, source) = custody_verified_source();
        let original_observation = source.observe_recovery_database_source().unwrap();
        let destination_root = TestRoot::create("envelope-conflict-abandonment");
        let first = destination_root.path().join("first");
        let second = destination_root.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let destinations =
            super::super::retained_recovery_set_directories_for_test(&first, &second);
        let database = publish_first_recovery_database_artifact(source, destinations).unwrap();
        let database_path = first.join(PRODUCTION_DATABASE_FILENAME);
        let database_bytes = fs::read(&database_path).unwrap();
        let envelope_path =
            first.join(first_recovery_envelope_artifact::FIRST_RECOVERY_ENVELOPE_FILENAME);
        let conflict_bytes = b"synthetic pre-existing envelope conflict";
        fs::write(&envelope_path, conflict_bytes).unwrap();

        let failure =
            *first_recovery_envelope_artifact::publish_first_recovery_envelope_artifact(database)
                .unwrap_err();
        let retained_source = failure.abandon_partial_destination_and_retain_source();

        assert!(
            retained_source.observe_recovery_database_source().unwrap() == original_observation
        );
        assert_eq!(fs::read(&database_path).unwrap(), database_bytes);
        assert_eq!(fs::read(&envelope_path).unwrap(), conflict_bytes);
        assert_eq!(fs::read_dir(&second).unwrap().count(), 0);

        let moved_first = destination_root.path().join("first-moved-by-test");
        fs::rename(&first, &moved_first).unwrap();
        let moved_second = destination_root.path().join("second-moved-by-test");
        fs::rename(&second, &moved_second).unwrap();
        assert_eq!(
            fs::read(moved_first.join(PRODUCTION_DATABASE_FILENAME)).unwrap(),
            database_bytes
        );
        assert_eq!(
            fs::read(
                moved_first
                    .join(first_recovery_envelope_artifact::FIRST_RECOVERY_ENVELOPE_FILENAME)
            )
            .unwrap(),
            conflict_bytes
        );

        let shutdown = retained_source.abort_for_shutdown();
        let _source_close_outcome = shutdown.retry_source_close();
        drop(source_root);
    }

    #[test]
    fn envelope_success_abandonment_returns_source_and_leaves_both_artifacts_untouched() {
        let (source_root, _stage_root, source) = custody_verified_source();
        let original_observation = source.observe_recovery_database_source().unwrap();
        let destination_root = TestRoot::create("envelope-success-abandonment");
        let first = destination_root.path().join("first");
        let second = destination_root.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let destinations =
            super::super::retained_recovery_set_directories_for_test(&first, &second);
        let database = publish_first_recovery_database_artifact(source, destinations).unwrap();
        let published =
            first_recovery_envelope_artifact::publish_first_recovery_envelope_artifact(database)
                .unwrap();
        let database_path = first.join(PRODUCTION_DATABASE_FILENAME);
        let envelope_path =
            first.join(first_recovery_envelope_artifact::FIRST_RECOVERY_ENVELOPE_FILENAME);
        let database_bytes = fs::read(&database_path).unwrap();
        let envelope_bytes = fs::read(&envelope_path).unwrap();

        let retained_source = published.abandon_published_destination_and_retain_source();
        assert!(
            retained_source.observe_recovery_database_source().unwrap() == original_observation
        );
        assert_eq!(fs::read(&database_path).unwrap(), database_bytes);
        assert_eq!(fs::read(&envelope_path).unwrap(), envelope_bytes);
        assert_eq!(
            envelope_bytes.len(),
            crate::production_database_migration_recovery_envelope::MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH
        );
        assert_eq!(fs::read_dir(&second).unwrap().count(), 0);

        let moved_first = destination_root.path().join("first-moved-by-test");
        fs::rename(&first, &moved_first).unwrap();
        let moved_second = destination_root.path().join("second-moved-by-test");
        fs::rename(&second, &moved_second).unwrap();
        assert_eq!(
            fs::read(moved_first.join(PRODUCTION_DATABASE_FILENAME)).unwrap(),
            database_bytes
        );
        assert_eq!(
            fs::read(
                moved_first
                    .join(first_recovery_envelope_artifact::FIRST_RECOVERY_ENVELOPE_FILENAME)
            )
            .unwrap(),
            envelope_bytes
        );

        let shutdown = retained_source.abort_for_shutdown();
        let _source_close_outcome = shutdown.retry_source_close();
        drop(source_root);
    }
}
