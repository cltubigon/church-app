//! Fixed-purpose publication of the staged database-key wrapper only.

use std::{
    ffi::{OsStr, c_void},
    fs,
    mem::{offset_of, size_of},
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::Path,
};

use windows_sys::Win32::{
    Foundation::{GENERIC_WRITE, HANDLE},
    Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, FILE_RENAME_INFO, FILE_SHARE_MODE, FileRenameInfo, FlushFileBuffers,
        OPEN_EXISTING, ReadFile, SetFileInformationByHandle,
    },
};

use crate::{
    installation_evidence_persistence::{
        MAXIMUM_PROTECTED_WRAPPER_LENGTH, MINIMUM_PROTECTED_WRAPPER_LENGTH,
    },
    installation_evidence_protection::EncodedProtectedWrapper,
    storage_foundation::{
        ACTIVE_DATABASE_KEY_FILENAME, DATABASE_KEY_DIRECTORY_NAME, DatabaseKeyPersistencePaths,
        STAGED_DATABASE_KEY_FILENAME,
    },
};

use super::super::{
    RetainedObservation, exact_named_child, open_native_handle, open_retained_parent,
    query_observation, validate_parent,
};
use super::PreparedFirstTimeSetupProtectedArtifactDirectories;

const PUBLICATION_SOURCE_ACCESS: u32 =
    FILE_READ_DATA | FILE_READ_ATTRIBUTES | GENERIC_WRITE | DELETE;
const PUBLICATION_SOURCE_SHARE: FILE_SHARE_MODE = 0;
const PUBLICATION_SOURCE_FLAGS: u32 = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum DatabaseKeyWrapperPublicationFilesystemError {
    PrepublicationRejected,
    RenameOutcomeUnconfirmed,
    PostRenameFlushFailed,
    PostRenameValidationFailed,
}

impl std::fmt::Debug for DatabaseKeyWrapperPublicationFilesystemError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::PrepublicationRejected => "PrepublicationRejected",
            Self::RenameOutcomeUnconfirmed => "RenameOutcomeUnconfirmed",
            Self::PostRenameFlushFailed => "PostRenameFlushFailed",
            Self::PostRenameValidationFailed => "PostRenameValidationFailed",
        })
    }
}

pub(crate) fn publish_staged_database_key_wrapper(
    directories: &mut PreparedFirstTimeSetupProtectedArtifactDirectories,
    paths: &DatabaseKeyPersistencePaths,
    expected: &EncodedProtectedWrapper,
) -> Result<(), DatabaseKeyWrapperPublicationFilesystemError> {
    publish_using(directories, paths, expected, |_| false)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PublicationCheckpoint {
    Rename,
    PostRenameFlush,
    PostRenameValidation,
}

fn publish_using(
    directories: &mut PreparedFirstTimeSetupProtectedArtifactDirectories,
    paths: &DatabaseKeyPersistencePaths,
    expected: &EncodedProtectedWrapper,
    mut fail_at: impl FnMut(PublicationCheckpoint) -> bool,
) -> Result<(), DatabaseKeyWrapperPublicationFilesystemError> {
    // Selection begins when this handle is opened. A byte-identical source
    // replacement completed before this point is therefore accepted; after
    // this point, every check, flush, and rename uses this same live handle.
    validate_fixed_paths_and_anchor(directories, paths)?;
    require_destination_absent(paths)?;
    let source = open_native_handle(
        paths.staged_database_key.as_path(),
        PUBLICATION_SOURCE_ACCESS,
        PUBLICATION_SOURCE_SHARE,
        OPEN_EXISTING,
        PUBLICATION_SOURCE_FLAGS,
    )
    .map_err(|_| DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)?;
    let initial = validate_source(directories, paths, &source, expected)?;
    flush(&source)
        .map_err(|_| DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)?;
    revalidate_before_rename(directories, &source, &initial)?;

    let rename_result = if fail_at(PublicationCheckpoint::Rename) {
        false
    } else {
        rename_to_active(&source, paths.active_database_key.as_path())
    };
    if !rename_result {
        return Err(DatabaseKeyWrapperPublicationFilesystemError::RenameOutcomeUnconfirmed);
    }
    if fail_at(PublicationCheckpoint::PostRenameFlush) || flush(&source).is_err() {
        return Err(DatabaseKeyWrapperPublicationFilesystemError::PostRenameFlushFailed);
    }
    if fail_at(PublicationCheckpoint::PostRenameValidation)
        || validate_after_rename(directories, paths, &source, &initial).is_err()
    {
        return Err(DatabaseKeyWrapperPublicationFilesystemError::PostRenameValidationFailed);
    }
    Ok(())
}

fn validate_fixed_paths_and_anchor(
    directories: &PreparedFirstTimeSetupProtectedArtifactDirectories,
    paths: &DatabaseKeyPersistencePaths,
) -> Result<(), DatabaseKeyWrapperPublicationFilesystemError> {
    let staged = paths.staged_database_key.as_path();
    let active = paths.active_database_key.as_path();
    let directory = paths.database_key_directory.as_path();
    if staged.file_name() != Some(OsStr::new(STAGED_DATABASE_KEY_FILENAME))
        || active.file_name() != Some(OsStr::new(ACTIVE_DATABASE_KEY_FILENAME))
        || staged.parent() != Some(directory)
        || active.parent() != Some(directory)
    {
        return Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected);
    }
    let supplied = open_retained_parent(directory)
        .map_err(|_| DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)?;
    let (root, retained) = current_anchor(directories)
        .map_err(|_| DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)?;
    if supplied.initial != retained
        || root != directories.root.initial
        || retained != directories.database_key.initial
    {
        return Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected);
    }
    Ok(())
}

fn require_destination_absent(
    paths: &DatabaseKeyPersistencePaths,
) -> Result<(), DatabaseKeyWrapperPublicationFilesystemError> {
    match fs::symlink_metadata(paths.active_database_key.as_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected),
    }
}

fn validate_source(
    directories: &PreparedFirstTimeSetupProtectedArtifactDirectories,
    paths: &DatabaseKeyPersistencePaths,
    source: &std::os::windows::io::OwnedHandle,
    expected: &EncodedProtectedWrapper,
) -> Result<RetainedObservation, DatabaseKeyWrapperPublicationFilesystemError> {
    let observation = query_observation(source)
        .map_err(|_| DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)?;
    validate_safe_source(&observation)?;
    let (_, directory) = current_anchor(directories)
        .map_err(|_| DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)?;
    exact_named_child(&directory, &observation, STAGED_DATABASE_KEY_FILENAME)
        .map_err(|_| DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)?;
    let bytes = read_source(source, observation.size)?;
    if bytes != expected.as_bytes()
        || EncodedProtectedWrapper::validate_database_key_bytes(&bytes).is_err()
        || paths.staged_database_key.as_path().parent()
            != Some(paths.database_key_directory.as_path())
    {
        return Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected);
    }
    Ok(observation)
}

fn validate_safe_source(
    observation: &RetainedObservation,
) -> Result<(), DatabaseKeyWrapperPublicationFilesystemError> {
    if !observation.disk_entry
        || observation.directory
        || observation.delete_pending
        || observation.link_count != 1
        || observation.attributes & super::super::DISALLOWED_LEAF_ATTRIBUTES != 0
        || observation.reparse_tag != 0
        || !(MINIMUM_PROTECTED_WRAPPER_LENGTH..=MAXIMUM_PROTECTED_WRAPPER_LENGTH)
            .contains(&observation.size)
    {
        return Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected);
    }
    Ok(())
}

fn read_source(
    source: &std::os::windows::io::OwnedHandle,
    size: u64,
) -> Result<Vec<u8>, DatabaseKeyWrapperPublicationFilesystemError> {
    let length = usize::try_from(size)
        .map_err(|_| DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)?;
    let mut bytes = vec![0_u8; length];
    let mut read = 0_u32;
    let requested = u32::try_from(length)
        .map_err(|_| DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)?;
    // SAFETY: the source handle and writable buffer remain live for this
    // synchronous call; the request exactly matches the allocated buffer.
    if unsafe {
        ReadFile(
            source.as_raw_handle() as HANDLE,
            bytes.as_mut_ptr(),
            requested,
            &raw mut read,
            std::ptr::null_mut(),
        )
    } == 0
        || read != requested
    {
        return Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected);
    }
    Ok(bytes)
}

fn flush(source: &std::os::windows::io::OwnedHandle) -> Result<(), ()> {
    // SAFETY: the same live file handle was opened with GENERIC_WRITE.
    if unsafe { FlushFileBuffers(source.as_raw_handle() as HANDLE) } == 0 {
        return Err(());
    }
    Ok(())
}

fn revalidate_before_rename(
    directories: &PreparedFirstTimeSetupProtectedArtifactDirectories,
    source: &std::os::windows::io::OwnedHandle,
    initial: &RetainedObservation,
) -> Result<(), DatabaseKeyWrapperPublicationFilesystemError> {
    let (_, directory) = current_anchor(directories)
        .map_err(|_| DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)?;
    let current = query_observation(source)
        .map_err(|_| DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)?;
    if current != *initial
        || exact_named_child(&directory, &current, STAGED_DATABASE_KEY_FILENAME).is_err()
    {
        return Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected);
    }
    Ok(())
}

fn rename_to_active(source: &std::os::windows::io::OwnedHandle, active_path: &Path) -> bool {
    let mut buffer = match RenameInformationBuffer::for_exact_absolute_path(active_path) {
        Ok(value) => value,
        Err(()) => return false,
    };
    // SAFETY: `Vec<usize>` supplies alignment at least as strict as
    // FILE_RENAME_INFO. The allocation is sized through the flexible FileName
    // tail, all fields and exact absolute UTF-16 path bytes are initialized,
    // FileNameLength is in bytes, the source handle stays live, and the buffer
    // cannot move or dangle during the synchronous call. RootDirectory is NULL
    // and ReplaceIfExists is explicitly false.
    unsafe {
        SetFileInformationByHandle(
            source.as_raw_handle() as HANDLE,
            FileRenameInfo,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.call_size,
        ) != 0
    }
}

struct RenameInformationBuffer {
    storage: Vec<usize>,
    call_size: u32,
}

impl RenameInformationBuffer {
    fn for_exact_absolute_path(path: &Path) -> Result<Self, ()> {
        if !path.is_absolute() {
            return Err(());
        }
        let name: Vec<u16> = path.as_os_str().encode_wide().collect();
        if name.is_empty() || name.contains(&0) {
            return Err(());
        }
        let name_bytes = name.len().checked_mul(size_of::<u16>()).ok_or(())?;
        let buffer_bytes = offset_of!(FILE_RENAME_INFO, FileName)
            .checked_add(name_bytes)
            .ok_or(())?;
        let words =
            buffer_bytes.checked_add(size_of::<usize>() - 1).ok_or(())? / size_of::<usize>();
        let mut storage = vec![0_usize; words];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: the usize allocation has sufficient size and alignment for
        // the fixed header plus the checked, non-NUL UTF-16 flexible tail.
        unsafe {
            (*info).Anonymous.ReplaceIfExists = false;
            (*info).RootDirectory = std::ptr::null_mut();
            (*info).FileNameLength = u32::try_from(name_bytes).map_err(|_| ())?;
            std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
        }
        Ok(Self {
            storage,
            call_size: u32::try_from(buffer_bytes).map_err(|_| ())?,
        })
    }

    fn as_mut_ptr(&mut self) -> *mut FILE_RENAME_INFO {
        self.storage.as_mut_ptr().cast()
    }
}

fn validate_after_rename(
    directories: &PreparedFirstTimeSetupProtectedArtifactDirectories,
    paths: &DatabaseKeyPersistencePaths,
    source: &std::os::windows::io::OwnedHandle,
    initial: &RetainedObservation,
) -> Result<(), ()> {
    let (_, directory) = current_anchor(directories)?;
    let current = query_observation(source)?;
    validate_safe_source(&current).map_err(|_| ())?;
    if current.identity != initial.identity
        || current.disk_entry != initial.disk_entry
        || current.attributes != initial.attributes
        || current.reparse_tag != initial.reparse_tag
        || current.delete_pending != initial.delete_pending
        || current.directory != initial.directory
        || current.link_count != initial.link_count
        || current.size != initial.size
    {
        return Err(());
    }
    exact_named_child(&directory, &current, ACTIVE_DATABASE_KEY_FILENAME)?;
    let mut staged = false;
    let mut active = false;
    for entry in fs::read_dir(paths.database_key_directory.as_path()).map_err(|_| ())? {
        let name = entry.map_err(|_| ())?.file_name();
        staged |= name == OsStr::new(STAGED_DATABASE_KEY_FILENAME);
        active |= name == OsStr::new(ACTIVE_DATABASE_KEY_FILENAME);
    }
    if staged || !active {
        return Err(());
    }
    Ok(())
}

fn current_anchor(
    directories: &PreparedFirstTimeSetupProtectedArtifactDirectories,
) -> Result<(RetainedObservation, RetainedObservation), ()> {
    let root = query_observation(&directories.root.handle)
        .and_then(|value| validate_parent(&value).map(|()| value))?;
    let directory = query_observation(&directories.database_key.handle)
        .and_then(|value| validate_parent(&value).map(|()| value))?;
    exact_named_child(&root, &directory, DATABASE_KEY_DIRECTORY_NAME)?;
    if root != directories.root.initial || directory != directories.database_key.initial {
        return Err(());
    }
    Ok((root, directory))
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        os::windows::ffi::OsStringExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::storage_foundation::{
        PRODUCTION_DATABASE_FILENAME, database_key_persistence_paths,
        freshness_anchor_persistence_paths, installation_evidence_persistence_paths,
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        paths: DatabaseKeyPersistencePaths,
        directories: PreparedFirstTimeSetupProtectedArtifactDirectories,
    }

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "church-app-db-key-publish-{}-{nonce}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::write(
                root.join(PRODUCTION_DATABASE_FILENAME),
                b"synthetic-database",
            )
            .unwrap();
            let paths = database_key_persistence_paths(&root);
            let freshness = freshness_anchor_persistence_paths(&root);
            let evidence = installation_evidence_persistence_paths(&root);
            let directories =
                super::super::prepare_first_time_setup_protected_artifact_directories(
                    &paths, &freshness, &evidence,
                )
                .unwrap();
            Self {
                root,
                paths,
                directories,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn wrapper(byte: u8) -> EncodedProtectedWrapper {
        EncodedProtectedWrapper::synthetic_database_key_for_staged_writer_test(vec![byte; 32])
            .unwrap()
    }

    fn stage(fixture: &mut Fixture, value: &EncodedProtectedWrapper) {
        super::super::write_staged_database_key_wrapper(
            &mut fixture.directories,
            &fixture.paths.staged_database_key,
            value,
        )
        .unwrap();
    }

    #[test]
    fn database_key_wrapper_publication_moves_exact_bytes_without_replace() {
        let mut fixture = Fixture::new();
        let expected = wrapper(0x41);
        stage(&mut fixture, &expected);
        publish_staged_database_key_wrapper(&mut fixture.directories, &fixture.paths, &expected)
            .unwrap();
        assert!(!fixture.paths.staged_database_key.as_path().exists());
        assert_eq!(
            fs::read(fixture.paths.active_database_key.as_path()).unwrap(),
            expected.as_bytes()
        );
        assert_eq!(
            fs::read(fixture.root.join(PRODUCTION_DATABASE_FILENAME)).unwrap(),
            b"synthetic-database"
        );
    }

    #[test]
    fn database_key_wrapper_publication_rejects_existing_destination_missing_mismatch_oversize_and_hard_link()
     {
        let mut fixture = Fixture::new();
        let expected = wrapper(0x52);
        assert_eq!(
            publish_staged_database_key_wrapper(
                &mut fixture.directories,
                &fixture.paths,
                &expected
            ),
            Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)
        );
        stage(&mut fixture, &expected);
        fs::write(fixture.paths.active_database_key.as_path(), b"sentinel").unwrap();
        assert_eq!(
            publish_staged_database_key_wrapper(
                &mut fixture.directories,
                &fixture.paths,
                &expected
            ),
            Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)
        );
        assert_eq!(
            fs::read(fixture.paths.active_database_key.as_path()).unwrap(),
            b"sentinel"
        );
        drop(fixture);

        let mut fixture = Fixture::new();
        let actual = wrapper(0x53);
        stage(&mut fixture, &actual);
        assert_eq!(
            publish_staged_database_key_wrapper(
                &mut fixture.directories,
                &fixture.paths,
                &expected
            ),
            Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)
        );
        drop(fixture);

        let mut fixture = Fixture::new();
        fs::write(
            fixture.paths.staged_database_key.as_path(),
            vec![0_u8; (MAXIMUM_PROTECTED_WRAPPER_LENGTH + 1) as usize],
        )
        .unwrap();
        assert_eq!(
            publish_staged_database_key_wrapper(
                &mut fixture.directories,
                &fixture.paths,
                &expected
            ),
            Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)
        );
        drop(fixture);

        let mut fixture = Fixture::new();
        stage(&mut fixture, &expected);
        fs::hard_link(
            fixture.paths.staged_database_key.as_path(),
            fixture.root.join("alias.synthetic"),
        )
        .unwrap();
        assert_eq!(
            publish_staged_database_key_wrapper(
                &mut fixture.directories,
                &fixture.paths,
                &expected
            ),
            Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)
        );
    }

    #[test]
    fn database_key_wrapper_publication_rejects_destination_directory_and_reparse_entry() {
        let expected = wrapper(0x58);
        let mut fixture = Fixture::new();
        stage(&mut fixture, &expected);
        fs::create_dir(fixture.paths.active_database_key.as_path()).unwrap();
        assert_eq!(
            publish_staged_database_key_wrapper(
                &mut fixture.directories,
                &fixture.paths,
                &expected
            ),
            Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)
        );
        assert!(fixture.paths.staged_database_key.as_path().exists());
        drop(fixture);

        let mut fixture = Fixture::new();
        stage(&mut fixture, &expected);
        let target = fixture.root.join("reparse-target.synthetic");
        fs::write(&target, b"synthetic-reparse-target").unwrap();
        if std::os::windows::fs::symlink_file(&target, fixture.paths.active_database_key.as_path())
            .is_ok()
        {
            assert_eq!(
                publish_staged_database_key_wrapper(
                    &mut fixture.directories,
                    &fixture.paths,
                    &expected
                ),
                Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)
            );
            assert!(fixture.paths.staged_database_key.as_path().exists());
        }
    }

    #[test]
    fn database_key_wrapper_publication_rejects_source_reparse_entry_where_supported() {
        let expected = wrapper(0x59);
        let mut fixture = Fixture::new();
        stage(&mut fixture, &expected);
        let target = fixture.root.join("source-reparse-target.synthetic");
        fs::rename(fixture.paths.staged_database_key.as_path(), &target).unwrap();
        if std::os::windows::fs::symlink_file(&target, fixture.paths.staged_database_key.as_path())
            .is_ok()
        {
            assert_eq!(
                publish_staged_database_key_wrapper(
                    &mut fixture.directories,
                    &fixture.paths,
                    &expected
                ),
                Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)
            );
            assert!(!fixture.paths.active_database_key.as_path().exists());
        }
    }

    #[test]
    fn database_key_wrapper_publication_accepts_byte_identical_replacement_before_open() {
        let expected = wrapper(0x5a);
        let mut fixture = Fixture::new();
        stage(&mut fixture, &expected);
        fs::rename(
            fixture.paths.staged_database_key.as_path(),
            fixture.root.join("replaced-source.synthetic"),
        )
        .unwrap();
        fs::write(
            fixture.paths.staged_database_key.as_path(),
            expected.as_bytes(),
        )
        .unwrap();

        publish_staged_database_key_wrapper(&mut fixture.directories, &fixture.paths, &expected)
            .unwrap();
        assert!(!fixture.paths.staged_database_key.as_path().exists());
        assert_eq!(
            fs::read(fixture.paths.active_database_key.as_path()).unwrap(),
            expected.as_bytes()
        );
    }

    #[test]
    fn database_key_wrapper_publication_rejects_directory_identity_mismatch() {
        let expected = wrapper(0x5b);
        let mut retained = Fixture::new();
        let mut different = Fixture::new();
        stage(&mut different, &expected);

        assert_eq!(
            publish_staged_database_key_wrapper(
                &mut retained.directories,
                &different.paths,
                &expected
            ),
            Err(DatabaseKeyWrapperPublicationFilesystemError::PrepublicationRejected)
        );
        assert!(different.paths.staged_database_key.as_path().exists());
        assert!(!different.paths.active_database_key.as_path().exists());
    }

    #[test]
    fn database_key_wrapper_publication_phase_failures_are_distinct_and_never_rollback() {
        let expected = wrapper(0x64);
        let mut fixture = Fixture::new();
        stage(&mut fixture, &expected);
        assert_eq!(
            publish_using(
                &mut fixture.directories,
                &fixture.paths,
                &expected,
                |point| point == PublicationCheckpoint::Rename
            ),
            Err(DatabaseKeyWrapperPublicationFilesystemError::RenameOutcomeUnconfirmed)
        );
        assert!(fixture.paths.staged_database_key.as_path().exists());
        drop(fixture);

        for (point, error) in [
            (
                PublicationCheckpoint::PostRenameFlush,
                DatabaseKeyWrapperPublicationFilesystemError::PostRenameFlushFailed,
            ),
            (
                PublicationCheckpoint::PostRenameValidation,
                DatabaseKeyWrapperPublicationFilesystemError::PostRenameValidationFailed,
            ),
        ] {
            let mut fixture = Fixture::new();
            stage(&mut fixture, &expected);
            assert_eq!(
                publish_using(
                    &mut fixture.directories,
                    &fixture.paths,
                    &expected,
                    |current| current == point
                ),
                Err(error)
            );
            assert!(!fixture.paths.staged_database_key.as_path().exists());
            assert_eq!(
                fs::read(fixture.paths.active_database_key.as_path()).unwrap(),
                expected.as_bytes()
            );
        }
    }

    #[test]
    fn database_key_wrapper_publication_live_handle_excludes_mutation_delete_and_rename() {
        let mut fixture = Fixture::new();
        let expected = wrapper(0x75);
        stage(&mut fixture, &expected);
        let staged = fixture.paths.staged_database_key.as_path().to_owned();
        let alternate = fixture.root.join("alternate.synthetic");
        publish_using(
            &mut fixture.directories,
            &fixture.paths,
            &expected,
            |checkpoint| {
                if checkpoint == PublicationCheckpoint::Rename {
                    assert!(fs::OpenOptions::new().write(true).open(&staged).is_err());
                    assert!(fs::remove_file(&staged).is_err());
                    assert!(fs::rename(&staged, &alternate).is_err());
                }
                false
            },
        )
        .unwrap();
        assert!(!staged.exists());
        assert!(!alternate.exists());
    }

    #[test]
    fn database_key_wrapper_publication_buffer_is_exact_absolute_no_replace_and_rootless() {
        let fixture = Fixture::new();
        let path = fixture.paths.active_database_key.as_path();
        let expected: Vec<u16> = path.as_os_str().encode_wide().collect();
        let mut buffer = RenameInformationBuffer::for_exact_absolute_path(path).unwrap();
        let info = buffer.as_mut_ptr();
        // SAFETY: the test owns the initialized buffer for all reads.
        unsafe {
            assert!(!(*info).Anonymous.ReplaceIfExists);
            assert!((*info).RootDirectory.is_null());
            assert_eq!((*info).FileNameLength as usize, expected.len() * 2);
            assert_eq!(
                std::slice::from_raw_parts((*info).FileName.as_ptr(), expected.len()),
                expected
            );
        }
        assert_eq!(
            buffer.call_size as usize,
            offset_of!(FILE_RENAME_INFO, FileName) + expected.len() * 2
        );
        assert!(RenameInformationBuffer::for_exact_absolute_path(Path::new("relative")).is_err());
        let invalid = PathBuf::from(OsString::from_wide(&[
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            b'x' as u16,
            0,
            b'y' as u16,
        ]));
        assert!(RenameInformationBuffer::for_exact_absolute_path(&invalid).is_err());
    }

    #[test]
    fn database_key_wrapper_publication_native_contract_is_narrow() {
        assert_eq!(
            PUBLICATION_SOURCE_ACCESS,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | GENERIC_WRITE | DELETE
        );
        assert_eq!(PUBLICATION_SOURCE_SHARE, 0);
        assert_eq!(offset_of!(FILE_RENAME_INFO, FileName), 20);
        assert_eq!(size_of::<FILE_RENAME_INFO>(), 24);
        let source = include_str!("database_key_wrapper_publication.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert_eq!(source.matches("SetFileInformationByHandle(").count(), 1);
        assert!(source.contains("ReplaceIfExists = false"));
        assert!(source.contains("RootDirectory = std::ptr::null_mut()"));
        assert!(source.contains("paths.active_database_key.as_path()"));
        for forbidden in [
            "MoveFileExW",
            "ReplaceFileW",
            "MOVEFILE_COPY_ALLOWED",
            "remove_file",
            "remove_dir",
            "load_active",
        ] {
            assert!(!source.contains(forbidden));
        }
    }
}
