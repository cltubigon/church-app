//! Setup-only staging of the five fixed protected-wrapper leaves.

use std::{
    ffi::OsStr,
    fmt,
    os::windows::io::{AsRawHandle, OwnedHandle},
    path::Path,
};

use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GENERIC_WRITE, GetLastError, HANDLE},
    Storage::FileSystem::{
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_CREATION_DISPOSITION, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAGS_AND_ATTRIBUTES, FILE_READ_ATTRIBUTES, FILE_SHARE_MODE, FlushFileBuffers,
        WriteFile,
    },
};

use crate::{
    installation_evidence_persistence::{
        MAXIMUM_PROTECTED_WRAPPER_LENGTH, MINIMUM_PROTECTED_WRAPPER_LENGTH,
    },
    installation_evidence_protection::EncodedProtectedWrapper,
    storage_foundation::{
        DATABASE_KEY_DIRECTORY_NAME, FRESHNESS_ANCHOR_DIRECTORY_NAME,
        INSTALLATION_EVIDENCE_DIRECTORY_NAME, STAGED_ANCHOR_AUTHENTICATION_KEY_FILENAME,
        STAGED_AUTHENTICATED_EVIDENCE_FILENAME, STAGED_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME,
        STAGED_AUTHENTICATION_KEY_FILENAME, STAGED_DATABASE_KEY_FILENAME,
        StagedAnchorAuthenticationKeyPath, StagedAuthenticatedEvidencePath,
        StagedAuthenticatedFreshnessAnchorPath, StagedAuthenticationKeyPath, StagedDatabaseKeyPath,
    },
};

use super::super::{
    RetainedEntry, RetainedObservation, exact_named_child, open_native_handle,
    open_retained_parent, query_observation, validate_created_leaf, validate_parent,
};
use super::PreparedFirstTimeSetupProtectedArtifactDirectories;

const STAGED_LEAF_ACCESS: u32 = GENERIC_WRITE | FILE_READ_ATTRIBUTES;
const STAGED_LEAF_SHARE: FILE_SHARE_MODE = 0;
const STAGED_LEAF_DISPOSITION: FILE_CREATION_DISPOSITION = CREATE_NEW;
const STAGED_LEAF_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;

type WrapperValidator =
    fn(&[u8]) -> Result<(), crate::installation_evidence_protection::ProtectionStageError>;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum StagedProtectedWrapperWriteError {
    StageAlreadyExists,
    StageTargetUnavailableOrUnsafe,
    WrapperKindMismatch,
    StageWriteFailed,
    StageFlushFailed,
    StagePostWriteValidationFailed,
}

impl fmt::Debug for StagedProtectedWrapperWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StageAlreadyExists => "StageAlreadyExists",
            Self::StageTargetUnavailableOrUnsafe => "StageTargetUnavailableOrUnsafe",
            Self::WrapperKindMismatch => "WrapperKindMismatch",
            Self::StageWriteFailed => "StageWriteFailed",
            Self::StageFlushFailed => "StageFlushFailed",
            Self::StagePostWriteValidationFailed => "StagePostWriteValidationFailed",
        })
    }
}

struct FixedStagedTarget<'a> {
    root: &'a RetainedEntry,
    directory: &'a mut RetainedEntry,
    path: &'a Path,
    directory_name: &'static str,
    filename: &'static str,
    validate_wrapper: WrapperValidator,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StagingCheckpoint {
    Write,
    Flush,
    PostWriteValidation,
}

pub(crate) fn write_staged_database_key_wrapper(
    directories: &mut PreparedFirstTimeSetupProtectedArtifactDirectories,
    path: &StagedDatabaseKeyPath,
    wrapper: &EncodedProtectedWrapper,
) -> Result<(), StagedProtectedWrapperWriteError> {
    write_fixed_staged_wrapper(
        FixedStagedTarget {
            root: &directories.root,
            directory: &mut directories.database_key,
            path: path.as_path(),
            directory_name: DATABASE_KEY_DIRECTORY_NAME,
            filename: STAGED_DATABASE_KEY_FILENAME,
            validate_wrapper: EncodedProtectedWrapper::validate_database_key_bytes,
        },
        wrapper,
    )
}

pub(crate) fn write_staged_freshness_authentication_key_wrapper(
    directories: &mut PreparedFirstTimeSetupProtectedArtifactDirectories,
    path: &StagedAnchorAuthenticationKeyPath,
    wrapper: &EncodedProtectedWrapper,
) -> Result<(), StagedProtectedWrapperWriteError> {
    write_fixed_staged_wrapper(
        FixedStagedTarget {
            root: &directories.root,
            directory: &mut directories.freshness_anchor,
            path: path.as_path(),
            directory_name: FRESHNESS_ANCHOR_DIRECTORY_NAME,
            filename: STAGED_ANCHOR_AUTHENTICATION_KEY_FILENAME,
            validate_wrapper: EncodedProtectedWrapper::validate_anchor_authentication_key_bytes,
        },
        wrapper,
    )
}

pub(crate) fn write_staged_authenticated_freshness_anchor_wrapper(
    directories: &mut PreparedFirstTimeSetupProtectedArtifactDirectories,
    path: &StagedAuthenticatedFreshnessAnchorPath,
    wrapper: &EncodedProtectedWrapper,
) -> Result<(), StagedProtectedWrapperWriteError> {
    write_fixed_staged_wrapper(
        FixedStagedTarget {
            root: &directories.root,
            directory: &mut directories.freshness_anchor,
            path: path.as_path(),
            directory_name: FRESHNESS_ANCHOR_DIRECTORY_NAME,
            filename: STAGED_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME,
            validate_wrapper:
                EncodedProtectedWrapper::validate_authenticated_freshness_anchor_bytes,
        },
        wrapper,
    )
}

pub(crate) fn write_staged_evidence_authentication_key_wrapper(
    directories: &mut PreparedFirstTimeSetupProtectedArtifactDirectories,
    path: &StagedAuthenticationKeyPath,
    wrapper: &EncodedProtectedWrapper,
) -> Result<(), StagedProtectedWrapperWriteError> {
    write_fixed_staged_wrapper(
        FixedStagedTarget {
            root: &directories.root,
            directory: &mut directories.installation_evidence,
            path: path.as_path(),
            directory_name: INSTALLATION_EVIDENCE_DIRECTORY_NAME,
            filename: STAGED_AUTHENTICATION_KEY_FILENAME,
            validate_wrapper: EncodedProtectedWrapper::validate_authentication_key_bytes,
        },
        wrapper,
    )
}

pub(crate) fn write_staged_authenticated_evidence_wrapper(
    directories: &mut PreparedFirstTimeSetupProtectedArtifactDirectories,
    path: &StagedAuthenticatedEvidencePath,
    wrapper: &EncodedProtectedWrapper,
) -> Result<(), StagedProtectedWrapperWriteError> {
    write_fixed_staged_wrapper(
        FixedStagedTarget {
            root: &directories.root,
            directory: &mut directories.installation_evidence,
            path: path.as_path(),
            directory_name: INSTALLATION_EVIDENCE_DIRECTORY_NAME,
            filename: STAGED_AUTHENTICATED_EVIDENCE_FILENAME,
            validate_wrapper: EncodedProtectedWrapper::validate_authenticated_evidence_bytes,
        },
        wrapper,
    )
}

fn write_fixed_staged_wrapper(
    target: FixedStagedTarget<'_>,
    wrapper: &EncodedProtectedWrapper,
) -> Result<(), StagedProtectedWrapperWriteError> {
    write_fixed_staged_bytes_using(target, wrapper.as_bytes(), |_| false)
}

fn write_fixed_staged_bytes_using(
    target: FixedStagedTarget<'_>,
    bytes: &[u8],
    mut fail_at: impl FnMut(StagingCheckpoint) -> bool,
) -> Result<(), StagedProtectedWrapperWriteError> {
    validate_wrapper_length(bytes.len())?;
    (target.validate_wrapper)(bytes)
        .map_err(|_| StagedProtectedWrapperWriteError::WrapperKindMismatch)?;
    validate_target_path_and_anchor(&target)?;

    let leaf_handle = create_staged_leaf(target.path)?;
    let (initial_leaf, directory_after_creation) = validate_initial_leaf(&target, &leaf_handle)?;

    if fail_at(StagingCheckpoint::Write) {
        return Err(StagedProtectedWrapperWriteError::StageWriteFailed);
    }
    write_all(&leaf_handle, bytes)?;

    if fail_at(StagingCheckpoint::Flush) {
        return Err(StagedProtectedWrapperWriteError::StageFlushFailed);
    }
    flush(&leaf_handle)?;

    if fail_at(StagingCheckpoint::PostWriteValidation) {
        return Err(StagedProtectedWrapperWriteError::StagePostWriteValidationFailed);
    }
    revalidate_after_write(
        &target,
        &leaf_handle,
        &initial_leaf,
        &directory_after_creation,
        bytes.len(),
    )?;
    drop(leaf_handle);
    revalidate_anchor_against(
        target.root,
        target.directory,
        target.directory_name,
        &directory_after_creation,
    )
    .map_err(|_| StagedProtectedWrapperWriteError::StagePostWriteValidationFailed)?;
    target.directory.initial = directory_after_creation;
    Ok(())
}

fn validate_wrapper_length(length: usize) -> Result<(), StagedProtectedWrapperWriteError> {
    let length = u64::try_from(length)
        .map_err(|_| StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe)?;
    if !(MINIMUM_PROTECTED_WRAPPER_LENGTH..=MAXIMUM_PROTECTED_WRAPPER_LENGTH).contains(&length) {
        return Err(StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe);
    }
    Ok(())
}

fn validate_target_path_and_anchor(
    target: &FixedStagedTarget<'_>,
) -> Result<(), StagedProtectedWrapperWriteError> {
    if target.path.file_name() != Some(OsStr::new(target.filename)) {
        return Err(StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe);
    }
    let supplied_parent_path = target
        .path
        .parent()
        .ok_or(StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe)?;
    revalidate_anchor(target.root, target.directory, target.directory_name)
        .map_err(|_| StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe)?;
    let supplied_parent = open_retained_parent(supplied_parent_path)
        .map_err(|_| StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe)?;
    if supplied_parent.initial != target.directory.initial {
        return Err(StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe);
    }
    drop(supplied_parent);
    revalidate_anchor(target.root, target.directory, target.directory_name)
        .map_err(|_| StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe)?;
    Ok(())
}

fn create_staged_leaf(path: &Path) -> Result<OwnedHandle, StagedProtectedWrapperWriteError> {
    open_native_handle(
        path,
        STAGED_LEAF_ACCESS,
        STAGED_LEAF_SHARE,
        STAGED_LEAF_DISPOSITION,
        STAGED_LEAF_FLAGS,
    )
    .map_err(|code| {
        if matches!(code, ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS) {
            StagedProtectedWrapperWriteError::StageAlreadyExists
        } else {
            StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe
        }
    })
}

fn validate_initial_leaf(
    target: &FixedStagedTarget<'_>,
    leaf_handle: &OwnedHandle,
) -> Result<(RetainedObservation, RetainedObservation), StagedProtectedWrapperWriteError> {
    let leaf = query_observation(leaf_handle)
        .and_then(|observation| validate_created_leaf(&observation).map(|()| observation))
        .map_err(|_| StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe)?;
    let directory =
        observe_anchor_after_created_child(target.root, target.directory, target.directory_name)
            .map_err(|_| StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe)?;
    exact_named_child(&directory, &leaf, target.filename)
        .map_err(|_| StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe)?;
    Ok((leaf, directory))
}

fn write_all(handle: &OwnedHandle, bytes: &[u8]) -> Result<(), StagedProtectedWrapperWriteError> {
    let raw = handle.as_raw_handle() as HANDLE;
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        let requested = u32::try_from(remaining.len())
            .map_err(|_| StagedProtectedWrapperWriteError::StageWriteFailed)?;
        let mut written = 0_u32;
        // SAFETY: `raw` is owned by the live handle, the input slice remains
        // readable for the checked request, the output is writable, and this
        // synchronous handle does not use an OVERLAPPED structure.
        let succeeded = unsafe {
            WriteFile(
                raw,
                remaining.as_ptr(),
                requested,
                &raw mut written,
                std::ptr::null_mut(),
            )
        };
        let written = usize::try_from(written)
            .map_err(|_| StagedProtectedWrapperWriteError::StageWriteFailed)?;
        if succeeded == 0 || written == 0 || written > remaining.len() {
            return Err(StagedProtectedWrapperWriteError::StageWriteFailed);
        }
        offset += written;
    }
    Ok(())
}

fn flush(handle: &OwnedHandle) -> Result<(), StagedProtectedWrapperWriteError> {
    // SAFETY: the exact created file handle remains live for the synchronous
    // flush and was opened with write access.
    if unsafe { FlushFileBuffers(handle.as_raw_handle() as HANDLE) } == 0 {
        // SAFETY: called immediately after the failed native operation; the
        // code is intentionally discarded to keep the error payload-free.
        let _ = unsafe { GetLastError() };
        return Err(StagedProtectedWrapperWriteError::StageFlushFailed);
    }
    Ok(())
}

fn revalidate_after_write(
    target: &FixedStagedTarget<'_>,
    leaf_handle: &OwnedHandle,
    initial_leaf: &RetainedObservation,
    expected_directory: &RetainedObservation,
    expected_length: usize,
) -> Result<(), StagedProtectedWrapperWriteError> {
    let directory = revalidate_anchor_against(
        target.root,
        target.directory,
        target.directory_name,
        expected_directory,
    )
    .map_err(|_| StagedProtectedWrapperWriteError::StagePostWriteValidationFailed)?;
    let current_leaf = query_observation(leaf_handle)
        .map_err(|_| StagedProtectedWrapperWriteError::StagePostWriteValidationFailed)?;
    let expected_length = u64::try_from(expected_length)
        .map_err(|_| StagedProtectedWrapperWriteError::StagePostWriteValidationFailed)?;
    if !same_leaf_except_size(initial_leaf, &current_leaf)
        || current_leaf.size != expected_length
        || current_leaf.size < MINIMUM_PROTECTED_WRAPPER_LENGTH
        || current_leaf.size > MAXIMUM_PROTECTED_WRAPPER_LENGTH
        || !current_leaf.disk_entry
        || current_leaf.directory
        || current_leaf.delete_pending
        || current_leaf.link_count != 1
    {
        return Err(StagedProtectedWrapperWriteError::StagePostWriteValidationFailed);
    }
    exact_named_child(&directory, &current_leaf, target.filename)
        .map_err(|_| StagedProtectedWrapperWriteError::StagePostWriteValidationFailed)
}

fn same_leaf_except_size(initial: &RetainedObservation, current: &RetainedObservation) -> bool {
    current.identity == initial.identity
        && current.disk_entry == initial.disk_entry
        && current.attributes == initial.attributes
        && current.reparse_tag == initial.reparse_tag
        && current.delete_pending == initial.delete_pending
        && current.directory == initial.directory
        && current.link_count == initial.link_count
        && current.final_path == initial.final_path
}

fn revalidate_anchor(
    root: &RetainedEntry,
    directory: &RetainedEntry,
    directory_name: &str,
) -> Result<(RetainedObservation, RetainedObservation), ()> {
    let current_root = query_observation(&root.handle)
        .and_then(|observation| validate_parent(&observation).map(|()| observation))?;
    let current_directory = query_observation(&directory.handle)
        .and_then(|observation| validate_parent(&observation).map(|()| observation))?;
    exact_named_child(&current_root, &current_directory, directory_name)?;
    if current_root != root.initial || current_directory != directory.initial {
        return Err(());
    }
    Ok((current_root, current_directory))
}

fn observe_anchor_after_created_child(
    root: &RetainedEntry,
    directory: &RetainedEntry,
    directory_name: &str,
) -> Result<RetainedObservation, ()> {
    let current_root = query_observation(&root.handle)
        .and_then(|observation| validate_parent(&observation).map(|()| observation))?;
    let current_directory = query_observation(&directory.handle)
        .and_then(|observation| validate_parent(&observation).map(|()| observation))?;
    exact_named_child(&current_root, &current_directory, directory_name)?;
    if current_root != root.initial
        || !same_directory_except_size(&directory.initial, &current_directory)
    {
        return Err(());
    }
    Ok(current_directory)
}

fn revalidate_anchor_against(
    root: &RetainedEntry,
    directory: &RetainedEntry,
    directory_name: &str,
    expected_directory: &RetainedObservation,
) -> Result<RetainedObservation, ()> {
    let current_root = query_observation(&root.handle)
        .and_then(|observation| validate_parent(&observation).map(|()| observation))?;
    let current_directory = query_observation(&directory.handle)
        .and_then(|observation| validate_parent(&observation).map(|()| observation))?;
    exact_named_child(&current_root, &current_directory, directory_name)?;
    if current_root != root.initial || current_directory != *expected_directory {
        return Err(());
    }
    Ok(current_directory)
}

fn same_directory_except_size(
    initial: &RetainedObservation,
    current: &RetainedObservation,
) -> bool {
    current.identity == initial.identity
        && current.disk_entry == initial.disk_entry
        && current.attributes == initial.attributes
        && current.reparse_tag == initial.reparse_tag
        && current.delete_pending == initial.delete_pending
        && current.directory == initial.directory
        && current.link_count == initial.link_count
        && current.final_path == initial.final_path
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{
        production_database_connection_handoff::create_new_database::prepare_first_time_setup_protected_artifact_directories,
        storage_foundation::{
            ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME, ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME,
            ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME, ACTIVE_AUTHENTICATION_KEY_FILENAME,
            ACTIVE_DATABASE_KEY_FILENAME, DatabaseKeyPersistencePaths,
            FreshnessAnchorPersistencePaths, InstallationEvidencePersistencePaths,
            PRODUCTION_DATABASE_FILENAME, database_key_persistence_paths,
            freshness_anchor_persistence_paths, installation_evidence_persistence_paths,
        },
    };

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        database_key_paths: DatabaseKeyPersistencePaths,
        freshness_paths: FreshnessAnchorPersistencePaths,
        evidence_paths: InstallationEvidencePersistencePaths,
        directories: PreparedFirstTimeSetupProtectedArtifactDirectories,
    }

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "church-app-staged-wrapper-writer-{}-{nonce}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::write(
                root.join(PRODUCTION_DATABASE_FILENAME),
                b"synthetic-database",
            )
            .unwrap();
            let database_key_paths = database_key_persistence_paths(&root);
            let freshness_paths = freshness_anchor_persistence_paths(&root);
            let evidence_paths = installation_evidence_persistence_paths(&root);
            let directories = prepare_first_time_setup_protected_artifact_directories(
                &database_key_paths,
                &freshness_paths,
                &evidence_paths,
            )
            .unwrap();
            Self {
                root,
                database_key_paths,
                freshness_paths,
                evidence_paths,
                directories,
            }
        }

        fn target<'a>(
            root: &'a RetainedEntry,
            directory: &'a mut RetainedEntry,
            path: &'a Path,
            directory_name: &'static str,
            filename: &'static str,
            validator: WrapperValidator,
        ) -> FixedStagedTarget<'a> {
            FixedStagedTarget {
                root,
                directory,
                path,
                directory_name,
                filename,
                validate_wrapper: validator,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn database_wrapper(byte: u8) -> EncodedProtectedWrapper {
        EncodedProtectedWrapper::synthetic_database_key_for_staged_writer_test(vec![byte; 32])
            .unwrap()
    }

    fn freshness_key_wrapper(byte: u8) -> EncodedProtectedWrapper {
        EncodedProtectedWrapper::synthetic_anchor_authentication_key_for_staged_writer_test(vec![
            byte;
            32
        ])
        .unwrap()
    }

    fn freshness_anchor_wrapper(byte: u8) -> EncodedProtectedWrapper {
        EncodedProtectedWrapper::synthetic_authenticated_freshness_anchor_for_staged_writer_test(
            vec![byte; 64],
        )
        .unwrap()
    }

    fn evidence_key_wrapper(byte: u8) -> EncodedProtectedWrapper {
        EncodedProtectedWrapper::synthetic_authentication_key_for_publication_test(vec![byte; 32])
            .unwrap()
    }

    fn evidence_wrapper(byte: u8) -> EncodedProtectedWrapper {
        EncodedProtectedWrapper::synthetic_authenticated_evidence_for_loader_test(vec![byte; 64])
            .unwrap()
    }

    #[test]
    fn staged_protected_wrapper_writer_each_entry_point_writes_exact_leaf_bytes_and_size() {
        let mut fixture = Fixture::new();
        let database = database_wrapper(0x11);
        let freshness_key = freshness_key_wrapper(0x22);
        let freshness_anchor = freshness_anchor_wrapper(0x33);
        let evidence_key = evidence_key_wrapper(0x44);
        let evidence = evidence_wrapper(0x55);

        write_staged_database_key_wrapper(
            &mut fixture.directories,
            &fixture.database_key_paths.staged_database_key,
            &database,
        )
        .unwrap();
        write_staged_freshness_authentication_key_wrapper(
            &mut fixture.directories,
            &fixture.freshness_paths.staged_anchor_authentication_key,
            &freshness_key,
        )
        .unwrap();
        write_staged_authenticated_freshness_anchor_wrapper(
            &mut fixture.directories,
            &fixture
                .freshness_paths
                .staged_authenticated_freshness_anchor,
            &freshness_anchor,
        )
        .unwrap();
        write_staged_evidence_authentication_key_wrapper(
            &mut fixture.directories,
            &fixture.evidence_paths.staged_authentication_key,
            &evidence_key,
        )
        .unwrap();
        write_staged_authenticated_evidence_wrapper(
            &mut fixture.directories,
            &fixture.evidence_paths.staged_authenticated_evidence,
            &evidence,
        )
        .unwrap();

        for (path, filename, bytes) in [
            (
                fixture.database_key_paths.staged_database_key.as_path(),
                STAGED_DATABASE_KEY_FILENAME,
                database.as_bytes(),
            ),
            (
                fixture
                    .freshness_paths
                    .staged_anchor_authentication_key
                    .as_path(),
                STAGED_ANCHOR_AUTHENTICATION_KEY_FILENAME,
                freshness_key.as_bytes(),
            ),
            (
                fixture
                    .freshness_paths
                    .staged_authenticated_freshness_anchor
                    .as_path(),
                STAGED_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME,
                freshness_anchor.as_bytes(),
            ),
            (
                fixture.evidence_paths.staged_authentication_key.as_path(),
                STAGED_AUTHENTICATION_KEY_FILENAME,
                evidence_key.as_bytes(),
            ),
            (
                fixture
                    .evidence_paths
                    .staged_authenticated_evidence
                    .as_path(),
                STAGED_AUTHENTICATED_EVIDENCE_FILENAME,
                evidence.as_bytes(),
            ),
        ] {
            assert_eq!(path.file_name(), Some(OsStr::new(filename)));
            assert_eq!(fs::read(path).unwrap(), bytes);
            assert_eq!(fs::metadata(path).unwrap().len(), bytes.len() as u64);
        }

        for active in [
            fixture
                .database_key_paths
                .database_key_directory
                .as_path()
                .join(ACTIVE_DATABASE_KEY_FILENAME),
            fixture
                .freshness_paths
                .freshness_anchor_directory
                .as_path()
                .join(ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME),
            fixture
                .freshness_paths
                .freshness_anchor_directory
                .as_path()
                .join(ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME),
            fixture
                .evidence_paths
                .evidence_directory
                .as_path()
                .join(ACTIVE_AUTHENTICATION_KEY_FILENAME),
            fixture
                .evidence_paths
                .evidence_directory
                .as_path()
                .join(ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME),
        ] {
            assert!(!active.exists());
        }
    }

    #[test]
    fn staged_protected_wrapper_writer_wrong_kind_is_rejected_before_creation() {
        let mut fixture = Fixture::new();
        let wrong = evidence_wrapper(0x61);
        assert_eq!(
            write_staged_database_key_wrapper(
                &mut fixture.directories,
                &fixture.database_key_paths.staged_database_key,
                &wrong,
            ),
            Err(StagedProtectedWrapperWriteError::WrapperKindMismatch)
        );
        assert!(
            !fixture
                .database_key_paths
                .staged_database_key
                .as_path()
                .exists()
        );
    }

    #[test]
    fn staged_protected_wrapper_writer_defensive_bounds_fail_before_creation() {
        let mut fixture = Fixture::new();
        for invalid in [
            vec![0_u8; (MINIMUM_PROTECTED_WRAPPER_LENGTH - 1) as usize],
            vec![0_u8; (MAXIMUM_PROTECTED_WRAPPER_LENGTH + 1) as usize],
        ] {
            let target = Fixture::target(
                &fixture.directories.root,
                &mut fixture.directories.database_key,
                fixture.database_key_paths.staged_database_key.as_path(),
                DATABASE_KEY_DIRECTORY_NAME,
                STAGED_DATABASE_KEY_FILENAME,
                |_| Ok(()),
            );
            assert_eq!(
                write_fixed_staged_bytes_using(target, &invalid, |_| false),
                Err(StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe)
            );
            assert!(
                !fixture
                    .database_key_paths
                    .staged_database_key
                    .as_path()
                    .exists()
            );
        }
    }

    #[test]
    fn staged_protected_wrapper_writer_existing_target_is_unchanged() {
        let mut fixture = Fixture::new();
        let existing = b"synthetic-existing-stage";
        fs::write(
            fixture.database_key_paths.staged_database_key.as_path(),
            existing,
        )
        .unwrap();
        assert_eq!(
            write_staged_database_key_wrapper(
                &mut fixture.directories,
                &fixture.database_key_paths.staged_database_key,
                &database_wrapper(0x72),
            ),
            Err(StagedProtectedWrapperWriteError::StageAlreadyExists)
        );
        assert_eq!(
            fs::read(fixture.database_key_paths.staged_database_key.as_path()).unwrap(),
            existing
        );
    }

    #[test]
    fn staged_protected_wrapper_writer_failures_after_creation_leave_residue() {
        for (checkpoint, expected_error) in [
            (
                StagingCheckpoint::Write,
                StagedProtectedWrapperWriteError::StageWriteFailed,
            ),
            (
                StagingCheckpoint::Flush,
                StagedProtectedWrapperWriteError::StageFlushFailed,
            ),
            (
                StagingCheckpoint::PostWriteValidation,
                StagedProtectedWrapperWriteError::StagePostWriteValidationFailed,
            ),
        ] {
            let mut fixture = Fixture::new();
            let wrapper = database_wrapper(0x83);
            let target = Fixture::target(
                &fixture.directories.root,
                &mut fixture.directories.database_key,
                fixture.database_key_paths.staged_database_key.as_path(),
                DATABASE_KEY_DIRECTORY_NAME,
                STAGED_DATABASE_KEY_FILENAME,
                EncodedProtectedWrapper::validate_database_key_bytes,
            );
            assert_eq!(
                write_fixed_staged_bytes_using(target, wrapper.as_bytes(), |current| {
                    current == checkpoint
                }),
                Err(expected_error)
            );
            let path = fixture.database_key_paths.staged_database_key.as_path();
            assert!(path.is_file());
            if checkpoint == StagingCheckpoint::Write {
                assert_eq!(fs::metadata(path).unwrap().len(), 0);
            } else {
                assert_eq!(fs::read(path).unwrap(), wrapper.as_bytes());
            }
        }
    }

    #[test]
    fn staged_protected_wrapper_writer_rejects_a_different_prepared_directory_owner() {
        let mut owner_fixture = Fixture::new();
        let path_fixture = Fixture::new();
        assert_eq!(
            write_staged_database_key_wrapper(
                &mut owner_fixture.directories,
                &path_fixture.database_key_paths.staged_database_key,
                &database_wrapper(0x94),
            ),
            Err(StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe)
        );
        assert!(
            !path_fixture
                .database_key_paths
                .staged_database_key
                .as_path()
                .exists()
        );
        assert!(
            !owner_fixture
                .database_key_paths
                .staged_database_key
                .as_path()
                .exists()
        );
    }

    #[test]
    fn staged_protected_wrapper_writer_surface_and_scope_are_narrow_and_redacted() {
        const SOURCE: &str = include_str!("staged_protected_wrapper_writer.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert_eq!(production.matches("pub(crate) fn write_staged_").count(), 5);
        for typed_path in [
            "StagedDatabaseKeyPath",
            "StagedAnchorAuthenticationKeyPath",
            "StagedAuthenticatedFreshnessAnchorPath",
            "StagedAuthenticationKeyPath",
            "StagedAuthenticatedEvidencePath",
        ] {
            assert!(production.contains(typed_path));
        }
        for forbidden in [
            "pub(crate) fn write_staged_wrapper(",
            "pub(crate) fn handle(",
            "pub(crate) fn path(",
            "MoveFileExW",
            "ReplaceFileW",
            "rename(",
            "remove_file",
            "remove_dir",
            "CryptUnprotectData",
            "Hmac",
            "FirstTimeSetupPublicationStateMachine",
            "ProtectedDatabaseKeyWrapperStaged",
            "AllStagedArtifactsReloadVerified",
            "Mutex",
            "LockFileEx",
            "SECURITY_DESCRIPTOR",
            "SetNamedSecurityInfo",
            "FILE_SHARE_DELETE",
            "DELETE",
        ] {
            assert!(
                !production.contains(forbidden),
                "production writer crossed a prohibited boundary: {forbidden}"
            );
        }
        assert_eq!(STAGED_LEAF_ACCESS, GENERIC_WRITE | FILE_READ_ATTRIBUTES);
        assert_eq!(STAGED_LEAF_SHARE, 0);
        assert_eq!(STAGED_LEAF_DISPOSITION, CREATE_NEW);
        assert_eq!(
            STAGED_LEAF_FLAGS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
        );
        for error in [
            StagedProtectedWrapperWriteError::StageAlreadyExists,
            StagedProtectedWrapperWriteError::StageTargetUnavailableOrUnsafe,
            StagedProtectedWrapperWriteError::WrapperKindMismatch,
            StagedProtectedWrapperWriteError::StageWriteFailed,
            StagedProtectedWrapperWriteError::StageFlushFailed,
            StagedProtectedWrapperWriteError::StagePostWriteValidationFailed,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains('\\'));
            assert!(!debug.contains("0x"));
            assert!(!debug.contains("CHDPAPI"));
        }
    }
}
