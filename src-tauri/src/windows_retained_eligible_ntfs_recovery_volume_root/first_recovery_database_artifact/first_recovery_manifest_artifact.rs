//! First-set-only publication of the fixed manifest commit marker.

#[path = "first_recovery_manifest_artifact/reentered_recovery_key_verification.rs"]
mod reentered_recovery_key_verification;

#[allow(unused_imports)]
pub(crate) use reentered_recovery_key_verification::{
    FirstCompleteRecoverySetVerificationError, FirstCompleteRecoverySetVerificationFailure,
    FirstCompleteRecoverySetVerificationOutcome, FirstCompleteRecoverySetVerified,
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
    io::{Read, Write},
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

use crate::production_database_migration_recovery_envelope::{
    ParsedUntrustedRecoverySetManifestV1, RECOVERY_SET_MANIFEST_V1_LENGTH,
};

use super::{
    FirstRecoveryDatabaseAndEnvelopeArtifactsPublished,
    FirstRecoveryEnvelopeArtifactPublicationError, RootIdentity, fold_ascii,
};

const FIRST_RECOVERY_MANIFEST_FILENAME: &str = "recovery-set-v1.manifest";

#[derive(Clone, Eq, PartialEq)]
struct PublishedManifestFacts {
    identity: RootIdentity,
    disk_entry: bool,
    directory: bool,
    delete_pending: bool,
    attributes: u32,
    reparse_tag: u32,
    byte_length: u64,
    normalized_path: Vec<u16>,
}

struct RetainedFirstRecoveryManifestArtifact {
    file: Option<File>,
    initial: Option<PublishedManifestFacts>,
}

pub(super) struct FirstRecoverySetArtifactsPublished {
    prior: FirstRecoveryDatabaseAndEnvelopeArtifactsPublished,
    first_manifest: RetainedFirstRecoveryManifestArtifact,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum FirstRecoveryManifestArtifactPublicationError {
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

pub(super) struct FirstRecoveryManifestArtifactPublicationFailure {
    prior: FirstRecoveryDatabaseAndEnvelopeArtifactsPublished,
    partial_first_manifest: Option<RetainedFirstRecoveryManifestArtifact>,
    phase: PublicationPhase,
    error: FirstRecoveryManifestArtifactPublicationError,
}

struct AttemptFailure {
    partial: Option<RetainedFirstRecoveryManifestArtifact>,
    phase: PublicationPhase,
    error: FirstRecoveryManifestArtifactPublicationError,
}

impl fmt::Debug for RetainedFirstRecoveryManifestArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedFirstRecoveryManifestArtifact([REDACTED])")
    }
}

impl fmt::Debug for FirstRecoverySetArtifactsPublished {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirstRecoverySetArtifactsPublished([REDACTED])")
    }
}

impl fmt::Debug for FirstRecoveryManifestArtifactPublicationError {
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

impl fmt::Debug for FirstRecoveryManifestArtifactPublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            PublicationPhase::BeforeCreation => "BeforeCreation",
            PublicationPhase::DuringWrite => "DuringWrite",
            PublicationPhase::DuringFlushOrClose => "DuringFlushOrClose",
            PublicationPhase::DuringFreshVerification => "DuringFreshVerification",
        };
        write!(
            formatter,
            "FirstRecoveryManifestArtifactPublicationFailure({phase}, {:?})",
            self.error
        )
    }
}

fn fail(
    prior: FirstRecoveryDatabaseAndEnvelopeArtifactsPublished,
    partial_first_manifest: Option<RetainedFirstRecoveryManifestArtifact>,
    phase: PublicationPhase,
    error: FirstRecoveryManifestArtifactPublicationError,
) -> Result<FirstRecoverySetArtifactsPublished, Box<FirstRecoveryManifestArtifactPublicationFailure>>
{
    Err(Box::new(FirstRecoveryManifestArtifactPublicationFailure {
        prior,
        partial_first_manifest,
        phase,
        error,
    }))
}

fn fixed_manifest_path(directory_path: &[u16]) -> Vec<u16> {
    directory_path
        .iter()
        .copied()
        .chain(std::iter::once(b'\\' as u16))
        .chain(FIRST_RECOVERY_MANIFEST_FILENAME.encode_utf16())
        .collect()
}

fn nul_terminated(path: &[u16]) -> Result<Vec<u16>, FirstRecoveryManifestArtifactPublicationError> {
    if path.is_empty()
        || path.len() > super::super::super::MAXIMUM_FINAL_PATH_UNITS
        || path.contains(&0)
    {
        return Err(
            FirstRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent,
        );
    }
    let mut value = Vec::with_capacity(path.len() + 1);
    value.extend_from_slice(path);
    value.push(0);
    Ok(value)
}

fn create_new_manifest(
    path: &[u16],
) -> Result<File, FirstRecoveryManifestArtifactPublicationError> {
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
                Err(FirstRecoveryManifestArtifactPublicationError::ArtifactConflict)
            }
            _ => Err(FirstRecoveryManifestArtifactPublicationError::ArtifactCreationUnavailable),
        };
    }
    // SAFETY: ownership of the fresh successful handle is transferred once.
    Ok(File::from(unsafe {
        OwnedHandle::from_raw_handle(raw as RawHandle)
    }))
}

fn open_manifest_for_verification(
    path: &[u16],
) -> Result<File, FirstRecoveryManifestArtifactPublicationError> {
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
        return Err(FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
    }
    // SAFETY: ownership of the fresh successful handle is transferred once.
    Ok(File::from(unsafe {
        OwnedHandle::from_raw_handle(raw as RawHandle)
    }))
}

fn checked_information_size<T>() -> Result<u32, FirstRecoveryManifestArtifactPublicationError> {
    u32::try_from(std::mem::size_of::<T>())
        .map_err(|_| FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed)
}

fn query_normalized_path(
    file: &File,
) -> Result<Vec<u16>, FirstRecoveryManifestArtifactPublicationError> {
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: documented size query on the live owned handle.
    let required = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            super::super::FINAL_PATH_FLAGS,
        )
    };
    let capacity = usize::try_from(required)
        .map_err(|_| FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed)?;
    if capacity == 0 || capacity > super::super::super::MAXIMUM_FINAL_PATH_UNITS {
        return Err(FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
    }
    let mut output = vec![0_u16; capacity];
    // SAFETY: output is writable for the checked capacity and the handle stays live.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            output.as_mut_ptr(),
            required,
            super::super::FINAL_PATH_FLAGS,
        )
    };
    let written = usize::try_from(written)
        .map_err(|_| FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed)?;
    if written == 0
        || written >= output.len()
        || written > super::super::super::MAXIMUM_FINAL_PATH_UNITS
    {
        return Err(FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
    }
    output.truncate(written);
    Ok(output)
}

fn query_manifest_facts(
    file: &File,
) -> Result<PublishedManifestFacts, FirstRecoveryManifestArtifactPublicationError> {
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
        return Err(FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
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
        return Err(FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
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
        return Err(FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
    }
    let byte_length = u64::try_from(standard.EndOfFile)
        .map_err(|_| FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed)?;
    Ok(PublishedManifestFacts {
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

fn exact_manifest_path(directory: &[u16], observed: &[u16]) -> bool {
    let filename: Vec<u16> = FIRST_RECOVERY_MANIFEST_FILENAME.encode_utf16().collect();
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

fn validate_manifest_facts(
    parent_identity: &RootIdentity,
    parent_path: &[u16],
    facts: &PublishedManifestFacts,
) -> Result<(), FirstRecoveryManifestArtifactPublicationError> {
    if !facts.disk_entry
        || facts.directory
        || facts.delete_pending
        || facts.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || facts.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || facts.reparse_tag != 0
        || facts.identity.volume_serial != parent_identity.volume_serial
        || !exact_manifest_path(parent_path, &facts.normalized_path)
    {
        return Err(FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
    }
    Ok(())
}

fn validate_fresh_manifest_facts(
    parent_identity: &RootIdentity,
    parent_path: &[u16],
    facts: &PublishedManifestFacts,
) -> Result<(), FirstRecoveryManifestArtifactPublicationError> {
    validate_manifest_facts(parent_identity, parent_path, facts)?;
    if facts.byte_length != RECOVERY_SET_MANIFEST_V1_LENGTH as u64 {
        return Err(FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
    }
    Ok(())
}

fn write_exact_manifest(
    writer: &mut impl Write,
    expected: &[u8; RECOVERY_SET_MANIFEST_V1_LENGTH],
) -> Result<(), FirstRecoveryManifestArtifactPublicationError> {
    let mut remaining = expected.as_slice();
    while !remaining.is_empty() {
        let written = writer
            .write(remaining)
            .map_err(|_| FirstRecoveryManifestArtifactPublicationError::ArtifactWriteUnavailable)?;
        if written == 0 || written > remaining.len() {
            return Err(FirstRecoveryManifestArtifactPublicationError::ArtifactWriteUnavailable);
        }
        remaining = &remaining[written..];
    }
    Ok(())
}

fn flush(file: &File) -> Result<(), FirstRecoveryManifestArtifactPublicationError> {
    // SAFETY: the live writer was opened with GENERIC_WRITE.
    if unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) } == 0 {
        Err(FirstRecoveryManifestArtifactPublicationError::ArtifactFlushOrCloseUnavailable)
    } else {
        Ok(())
    }
}

fn close_writer(file: File) -> Result<(), FirstRecoveryManifestArtifactPublicationError> {
    let raw = file.into_raw_handle() as HANDLE;
    // SAFETY: ownership was transferred out of File exactly once and this is
    // the sole terminal close attempt for the writer handle.
    if unsafe { CloseHandle(raw) } == 0 {
        Err(FirstRecoveryManifestArtifactPublicationError::ArtifactFlushOrCloseUnavailable)
    } else {
        Ok(())
    }
}

fn verify_fresh_manifest_contents(
    file: &mut impl Read,
    expected: &[u8; RECOVERY_SET_MANIFEST_V1_LENGTH],
) -> Result<(), FirstRecoveryManifestArtifactPublicationError> {
    let mut actual = [0_u8; RECOVERY_SET_MANIFEST_V1_LENGTH];
    file.read_exact(&mut actual)
        .map_err(|_| FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed)?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed)?
        != 0
    {
        return Err(FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
    }
    let canonical = ParsedUntrustedRecoverySetManifestV1::parse(&actual)
        .map_err(|_| FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed)?
        .validate_structure()
        .map_err(|_| FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed)?
        .encode();
    if canonical != actual || canonical != *expected {
        return Err(FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
    }
    Ok(())
}

fn attempt_publication(
    prior: &FirstRecoveryDatabaseAndEnvelopeArtifactsPublished,
    expected: &[u8; RECOVERY_SET_MANIFEST_V1_LENGTH],
) -> Result<RetainedFirstRecoveryManifestArtifact, AttemptFailure> {
    let parent = &prior.prior.destinations.first.initial_child;
    let final_path = fixed_manifest_path(&parent.normalized_path);
    let writer = create_new_manifest(&final_path).map_err(|error| AttemptFailure {
        partial: None,
        phase: PublicationPhase::BeforeCreation,
        error,
    })?;
    let mut partial = RetainedFirstRecoveryManifestArtifact {
        file: Some(writer),
        initial: None,
    };
    let initial = query_manifest_facts(
        partial
            .file
            .as_ref()
            .expect("new manifest writer remains retained"),
    )
    .and_then(|facts| {
        validate_manifest_facts(&parent.identity, &parent.normalized_path, &facts)?;
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
    if let Err(error) = write_exact_manifest(
        partial
            .file
            .as_mut()
            .expect("manifest writer remains retained during the exact write"),
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
        .expect("manifest writer remains retained until flush and close");
    if flush(&writer).is_err() {
        partial.file = Some(writer);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFlushOrClose,
            error: FirstRecoveryManifestArtifactPublicationError::ArtifactFlushOrCloseUnavailable,
        });
    }
    if close_writer(writer).is_err() {
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFlushOrClose,
            error: FirstRecoveryManifestArtifactPublicationError::ArtifactFlushOrCloseUnavailable,
        });
    }
    if prior.prior.destinations.revalidate().is_err() {
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error: FirstRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent,
        });
    }
    let mut reopened = match open_manifest_for_verification(&final_path) {
        Ok(reopened) => reopened,
        Err(error) => {
            return Err(AttemptFailure {
                partial: Some(partial),
                phase: PublicationPhase::DuringFreshVerification,
                error,
            });
        }
    };
    let before = query_manifest_facts(&reopened).and_then(|facts| {
        validate_fresh_manifest_facts(&parent.identity, &parent.normalized_path, &facts)?;
        if facts.identity
            != partial
                .initial
                .as_ref()
                .expect("initial manifest facts remain retained")
                .identity
        {
            return Err(FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed);
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
    if let Err(error) = verify_fresh_manifest_contents(&mut reopened, expected) {
        partial.file = Some(reopened);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error,
        });
    }
    let after = match query_manifest_facts(&reopened) {
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
            error: FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed,
        });
    }
    if prior.prior.destinations.revalidate().is_err() {
        partial.file = Some(reopened);
        return Err(AttemptFailure {
            partial: Some(partial),
            phase: PublicationPhase::DuringFreshVerification,
            error: FirstRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent,
        });
    }
    partial.file = Some(reopened);
    partial.initial = Some(after);
    Ok(partial)
}

fn map_prior_revalidation_error(
    error: FirstRecoveryEnvelopeArtifactPublicationError,
) -> FirstRecoveryManifestArtifactPublicationError {
    match error {
        FirstRecoveryEnvelopeArtifactPublicationError::SourceUnavailableOrChanged => {
            FirstRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged
        }
        FirstRecoveryEnvelopeArtifactPublicationError::DestinationChangedOrInconsistent => {
            FirstRecoveryManifestArtifactPublicationError::DestinationChangedOrInconsistent
        }
        _ => FirstRecoveryManifestArtifactPublicationError::PriorArtifactChangedOrInvalid,
    }
}

pub(super) fn publish_first_recovery_manifest_artifact(
    mut prior: FirstRecoveryDatabaseAndEnvelopeArtifactsPublished,
) -> Result<FirstRecoverySetArtifactsPublished, Box<FirstRecoveryManifestArtifactPublicationFailure>>
{
    let trusted_manifest = match prior.prior.source.prepare_recovery_set_manifest_v1() {
        Ok(manifest) => manifest.encode(),
        Err(_) => {
            return fail(
                prior,
                None,
                PublicationPhase::BeforeCreation,
                FirstRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_database = match prior.prior.source.observe_recovery_database_source() {
        Ok(expected) => expected,
        Err(_) => {
            return fail(
                prior,
                None,
                PublicationPhase::BeforeCreation,
                FirstRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
    };
    let expected_envelope = match prior
        .prior
        .source
        .with_verified_recovery_envelope_bytes(|bytes| *bytes)
    {
        Ok(expected) => expected,
        Err(_) => {
            return fail(
                prior,
                None,
                PublicationPhase::BeforeCreation,
                FirstRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged,
            );
        }
    };
    if let Err(error) = prior.revalidate_for_manifest_publication(
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
    ) {
        return fail(
            prior,
            None,
            PublicationPhase::BeforeCreation,
            map_prior_revalidation_error(error),
        );
    }
    let first_manifest = match attempt_publication(&prior, &trusted_manifest) {
        Ok(first_manifest) => first_manifest,
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
        .source
        .prepare_recovery_set_manifest_v1()
        .is_ok_and(|manifest| manifest.encode() == trusted_manifest);
    if !source_still_matches {
        return fail(
            prior,
            Some(first_manifest),
            PublicationPhase::DuringFreshVerification,
            FirstRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged,
        );
    }
    if let Err(error) = prior.revalidate_for_manifest_publication(
        expected_database.database_byte_length,
        expected_database.database_sha256,
        &expected_envelope,
    ) {
        return fail(
            prior,
            Some(first_manifest),
            PublicationPhase::DuringFreshVerification,
            map_prior_revalidation_error(error),
        );
    }
    Ok(FirstRecoverySetArtifactsPublished {
        prior,
        first_manifest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn fixed_name_and_exact_path_are_not_caller_supplied() {
        let parent: Vec<u16> =
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\church-app-recovery-set"
                .encode_utf16()
                .collect();
        let exact = fixed_manifest_path(&parent);
        assert_eq!(FIRST_RECOVERY_MANIFEST_FILENAME, "recovery-set-v1.manifest");
        assert!(exact_manifest_path(&parent, &exact));
        let wrong_case: Vec<u16> = String::from_utf16(&exact)
            .unwrap()
            .replace("recovery-set-v1.manifest", "RECOVERY-SET-V1.MANIFEST")
            .encode_utf16()
            .collect();
        assert!(!exact_manifest_path(&parent, &wrong_case));
        assert!(!exact_manifest_path(&parent, &parent));
    }

    #[test]
    fn hardened_facts_reject_invalid_leafs_length_path_and_volume() {
        let parent_path: Vec<u16> =
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\church-app-recovery-set"
                .encode_utf16()
                .collect();
        let parent_identity = RootIdentity {
            volume_serial: 7,
            file_id: [0x11; 16],
        };
        let accepted = PublishedManifestFacts {
            identity: RootIdentity {
                volume_serial: 7,
                file_id: [0x22; 16],
            },
            disk_entry: true,
            directory: false,
            delete_pending: false,
            attributes: FILE_ATTRIBUTE_NORMAL,
            reparse_tag: 0,
            byte_length: RECOVERY_SET_MANIFEST_V1_LENGTH as u64,
            normalized_path: fixed_manifest_path(&parent_path),
        };
        assert!(validate_fresh_manifest_facts(&parent_identity, &parent_path, &accepted).is_ok());
        for rejected in [
            PublishedManifestFacts {
                disk_entry: false,
                ..accepted.clone()
            },
            PublishedManifestFacts {
                directory: true,
                attributes: FILE_ATTRIBUTE_DIRECTORY,
                ..accepted.clone()
            },
            PublishedManifestFacts {
                delete_pending: true,
                ..accepted.clone()
            },
            PublishedManifestFacts {
                attributes: FILE_ATTRIBUTE_REPARSE_POINT,
                reparse_tag: 0xa000000c,
                ..accepted.clone()
            },
            PublishedManifestFacts {
                byte_length: 97,
                ..accepted.clone()
            },
            PublishedManifestFacts {
                identity: RootIdentity {
                    volume_serial: 8,
                    file_id: [0x22; 16],
                },
                ..accepted.clone()
            },
            PublishedManifestFacts {
                normalized_path: parent_path.clone(),
                ..accepted.clone()
            },
        ] {
            assert!(
                validate_fresh_manifest_facts(&parent_identity, &parent_path, &rejected).is_err()
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
    fn exact_98_byte_write_handles_partial_writes_and_failure() {
        let expected = canonical_manifest();
        let mut partial = PartialWriter {
            bytes: Vec::new(),
            maximum: 7,
            fail_after: None,
        };
        write_exact_manifest(&mut partial, &expected).unwrap();
        assert_eq!(partial.bytes, expected);
        let mut failing = PartialWriter {
            bytes: Vec::new(),
            maximum: 11,
            fail_after: Some(44),
        };
        assert_eq!(
            write_exact_manifest(&mut failing, &expected),
            Err(FirstRecoveryManifestArtifactPublicationError::ArtifactWriteUnavailable)
        );
        assert_eq!(failing.bytes.len(), 44);
    }

    #[test]
    fn fresh_verification_requires_eof_structure_canonicality_and_trusted_bytes() {
        let expected = canonical_manifest();
        let mut exact = expected.as_slice();
        assert!(verify_fresh_manifest_contents(&mut exact, &expected).is_ok());
        let mut short = &expected[..97];
        assert!(verify_fresh_manifest_contents(&mut short, &expected).is_err());
        let mut trailing = expected.to_vec();
        trailing.push(0);
        assert!(verify_fresh_manifest_contents(&mut trailing.as_slice(), &expected).is_err());
        for changed in [
            {
                let mut value = expected;
                value[0] ^= 1;
                value
            },
            {
                let mut value = expected;
                value[9] = 2;
                value
            },
            {
                let mut value = expected;
                value[10..26].fill(0);
                value
            },
            {
                let mut value = expected;
                value[26..34].copy_from_slice(&0_u64.to_be_bytes());
                value
            },
            {
                let mut value = expected;
                value[97] ^= 1;
                value
            },
        ] {
            assert!(verify_fresh_manifest_contents(&mut changed.as_slice(), &expected).is_err());
        }
    }

    #[test]
    fn create_new_flush_close_and_independent_reopen_runtime_contract() {
        use std::os::windows::ffi::OsStrExt;
        use std::sync::atomic::{AtomicU64, Ordering};

        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "church-app-first-recovery-manifest-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join(FIRST_RECOVERY_MANIFEST_FILENAME);
        let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
        let expected = canonical_manifest();
        let mut writer = create_new_manifest(&encoded).unwrap();
        write_exact_manifest(&mut writer, &expected).unwrap();
        flush(&writer).unwrap();
        let initial = query_manifest_facts(&writer).unwrap();
        close_writer(writer).unwrap();
        let mut reopened = open_manifest_for_verification(&encoded).unwrap();
        let before = query_manifest_facts(&reopened).unwrap();
        assert!(before.identity == initial.identity);
        assert_eq!(before.byte_length, RECOVERY_SET_MANIFEST_V1_LENGTH as u64);
        verify_fresh_manifest_contents(&mut reopened, &expected).unwrap();
        let after = query_manifest_facts(&reopened).unwrap();
        assert!(before == after);
        assert_eq!(
            create_new_manifest(&encoded).unwrap_err(),
            FirstRecoveryManifestArtifactPublicationError::ArtifactConflict
        );
        drop(reopened);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn publication_contract_is_manifest_last_source_derived_private_and_non_destructive() {
        const SOURCE: &str = include_str!("first_recovery_manifest_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        for required in [
            "FirstRecoveryDatabaseAndEnvelopeArtifactsPublished",
            "prepare_recovery_set_manifest_v1",
            "revalidate_for_manifest_publication",
            "CREATE_NEW",
            "FlushFileBuffers",
            "CloseHandle",
            "FILE_FLAG_OPEN_REPARSE_POINT",
            "ParsedUntrustedRecoverySetManifestV1::parse",
            "validate_structure",
            "partial_first_manifest",
        ] {
            assert!(
                production.contains(required),
                "missing contract: {required}"
            );
        }
        for forbidden in [
            "from_trusted_internal_facts",
            "remove_file",
            "remove_dir",
            "serde",
            "#[tauri::command]",
            "set_2",
            "second_manifest",
            "pub fn",
            "PathBuf",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected surface: {forbidden}"
            );
        }
        let publication = production
            .split_once("pub(super) fn publish_first_recovery_manifest_artifact")
            .unwrap()
            .1;
        let creation = publication.find("attempt_publication(&prior").unwrap();
        let preparation = publication
            .find("prepare_recovery_set_manifest_v1()")
            .unwrap();
        let revalidation = publication
            .find("revalidate_for_manifest_publication(")
            .unwrap();
        assert!(preparation < revalidation && revalidation < creation);
    }

    #[test]
    fn predecessor_and_postpublication_revalidation_contracts_are_ordered() {
        const SOURCE: &str = include_str!("first_recovery_manifest_artifact.rs");
        const ENVELOPE_SOURCE: &str = include_str!("first_recovery_envelope_artifact.rs");
        let publication = SOURCE
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .split_once("pub(super) fn publish_first_recovery_manifest_artifact")
            .unwrap()
            .1;
        let signature = publication.split_once('{').unwrap().0;
        assert!(signature.contains("prior: FirstRecoveryDatabaseAndEnvelopeArtifactsPublished"));
        assert!(!signature.contains("path"));
        assert!(!signature.contains("filename"));

        let first_prepare = publication
            .find("prepare_recovery_set_manifest_v1()")
            .unwrap();
        let source_database = publication
            .find("observe_recovery_database_source()")
            .unwrap();
        let source_envelope = publication
            .find("with_verified_recovery_envelope_bytes")
            .unwrap();
        let pre_revalidation = publication
            .find("revalidate_for_manifest_publication(")
            .unwrap();
        let creation = publication.find("attempt_publication(&prior").unwrap();
        let post_prepare = publication
            .rfind("prepare_recovery_set_manifest_v1()")
            .unwrap();
        let post_revalidation = publication
            .rfind("revalidate_for_manifest_publication(")
            .unwrap();
        assert!(
            first_prepare < source_database
                && source_database < source_envelope
                && source_envelope < pre_revalidation
                && pre_revalidation < creation
                && creation < post_prepare
                && post_prepare < post_revalidation
        );

        let predecessor = ENVELOPE_SOURCE
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .split_once("fn revalidate_for_manifest_publication")
            .unwrap()
            .1
            .split_once("#[derive(Clone, Copy")
            .unwrap()
            .0;
        let first_database = predecessor
            .find("revalidate_for_envelope_publication")
            .unwrap();
        let envelope = predecessor.find("first_envelope.revalidate").unwrap();
        let second_database = predecessor
            .rfind("revalidate_for_envelope_publication")
            .unwrap();
        assert!(first_database < envelope && envelope < second_database);

        let attempt = SOURCE
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .split_once("fn attempt_publication")
            .unwrap()
            .1
            .split_once("fn map_prior_revalidation_error")
            .unwrap()
            .0;
        let write = attempt.find("write_exact_manifest(").unwrap();
        let flush = attempt.find("flush(&writer)").unwrap();
        let close = attempt.find("close_writer(writer)").unwrap();
        let reopen = attempt.find("open_manifest_for_verification").unwrap();
        let verify = attempt.find("verify_fresh_manifest_contents").unwrap();
        assert!(write < flush && flush < close && close < reopen && reopen < verify);
    }

    #[test]
    fn success_failure_and_errors_are_ownership_bearing_redacted_and_not_completion() {
        const SOURCE: &str = include_str!("first_recovery_manifest_artifact.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let success = production
            .split_once("struct FirstRecoverySetArtifactsPublished")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(success.contains("prior: FirstRecoveryDatabaseAndEnvelopeArtifactsPublished"));
        assert!(success.contains("first_manifest: RetainedFirstRecoveryManifestArtifact"));
        let failure = production
            .split_once("struct FirstRecoveryManifestArtifactPublicationFailure")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(failure.contains("prior: FirstRecoveryDatabaseAndEnvelopeArtifactsPublished"));
        assert!(
            failure
                .contains("partial_first_manifest: Option<RetainedFirstRecoveryManifestArtifact>")
        );
        for forbidden in [
            "CompleteRecoverySet",
            "VerifiedCompleteRecoverySet",
            "FirstRecoverySetComplete",
        ] {
            assert!(!production.contains(forbidden));
        }
        for output in [
            format!(
                "{:?}",
                FirstRecoveryManifestArtifactPublicationError::ArtifactVerificationFailed
            ),
            format!(
                "{:?}",
                FirstRecoveryManifestArtifactPublicationError::SourceUnavailableOrChanged
            ),
        ] {
            assert!(!output.contains("recovery-set-v1.manifest"));
            assert!(!output.contains("CHLDRSM"));
            assert!(!output.contains("Volume"));
        }
    }
}
