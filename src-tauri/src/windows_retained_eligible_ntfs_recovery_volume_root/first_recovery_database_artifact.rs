//! First-set-only publication of the fixed recovery database artifact.

use std::{
    ffi::c_void,
    fmt,
    fs::File,
    io::{Read, Write},
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

pub(super) struct FirstRecoveryDatabaseArtifactPublished {
    source: RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    destinations: TwoRetainedRecoverySetDirectories,
    first_database: RetainedFirstRecoveryDatabaseArtifact,
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

fn close_writer(file: File) -> Result<(), FirstRecoveryDatabaseArtifactPublicationError> {
    let raw = file.into_raw_handle() as HANDLE;
    // SAFETY: ownership was transferred out of File exactly once and this is
    // the sole terminal close attempt for the writer handle.
    if unsafe { CloseHandle(raw) } == 0 {
        Err(FirstRecoveryDatabaseArtifactPublicationError::ArtifactFlushOrCloseUnavailable)
    } else {
        Ok(())
    }
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
    if close_writer(writer).is_err() {
        return fail(
            source,
            destinations,
            Some(partial),
            PublicationPhase::DuringFlushOrClose,
            FirstRecoveryDatabaseArtifactPublicationError::ArtifactFlushOrCloseUnavailable,
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
}
