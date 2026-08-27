//! Windows test-only proof for the proposed retained create-handle mechanics.
//!
//! This proves only atomic create-new behavior, handle-sharing compatibility,
//! writable SQLite opening without create authority, exact main-file identity,
//! and delete/rename exclusion while the retained leaf handle remains live. It
//! does not prove encryption, key application, schema or metadata creation,
//! integrity, durability, publication, setup, cleanup policy, or hostile-race
//! completeness, and it grants no production database-creation authority.

use std::{
    ffi::{OsStr, c_void},
    fs,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OpenFlags};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
        FILE_CREATION_DISPOSITION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAGS_AND_ATTRIBUTES, FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
        FILE_TYPE_DISK, FileAttributeTagInfo, FileIdInfo, FileStandardInfo,
        GETFINALPATHNAMEBYHANDLE_FLAGS, GetFileInformationByHandle, GetFileInformationByHandleEx,
        GetFileType, GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_GUID,
    },
};

use super::sqlite_main_database_handle;

const DATABASE_LEAF: &str = "parish-data.db";
const RENAME_DESTINATION: &str = "renamed.synthetic";
const PARENT_ACCESS: u32 = FILE_READ_ATTRIBUTES;
const PARENT_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ | FILE_SHARE_WRITE;
const PARENT_DISPOSITION: FILE_CREATION_DISPOSITION = OPEN_EXISTING;
const PARENT_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
const LEAF_ACCESS: u32 = FILE_READ_ATTRIBUTES | FILE_READ_DATA;
const LEAF_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ | FILE_SHARE_WRITE;
const LEAF_DISPOSITION: FILE_CREATION_DISPOSITION = CREATE_NEW;
const LEAF_FLAGS: FILE_FLAGS_AND_ATTRIBUTES = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
const FINAL_PATH_FLAGS: GETFINALPATHNAMEBYHANDLE_FLAGS = FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;
const SQLITE_FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE
    .union(OpenFlags::SQLITE_OPEN_FULL_MUTEX)
    .union(OpenFlags::SQLITE_OPEN_PRIVATE_CACHE)
    .union(OpenFlags::SQLITE_OPEN_NOFOLLOW);
const MAXIMUM_FINAL_PATH_UNITS: usize = 32_767;
const VOLUME_GUID_PREFIX_UNITS: usize = 49;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

#[derive(Clone, Eq, PartialEq)]
struct Observation {
    identity: FileIdentity,
    disk_entry: bool,
    attributes: u32,
    reparse_tag: u32,
    delete_pending: bool,
    directory: bool,
    link_count: u32,
    size: u64,
    final_path: Vec<u16>,
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn create() -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the test clock should be after the Unix epoch")
            .as_nanos();
        let temporary_directory = std::env::temp_dir();
        let path = temporary_directory.join(format!(
            "church-app-retained-create-handle-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        assert!(path.starts_with(&temporary_directory));
        assert!(!path.exists(), "the unique test root must not pre-exist");
        fs::create_dir(&path).expect("isolated test-root creation should succeed");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn assert_exact_cleanup(self) {
        fs::remove_dir_all(&self.0).expect("exact test-root cleanup should succeed");
        assert!(!self.0.exists(), "the exact test root must be absent");
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn encode_path(path: &Path) -> Vec<u16> {
    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    assert!(!encoded.is_empty());
    assert!(!encoded.contains(&0));
    encoded.push(0);
    encoded
}

fn open_handle(
    path: &Path,
    access: u32,
    share: FILE_SHARE_MODE,
    disposition: FILE_CREATION_DISPOSITION,
    flags: FILE_FLAGS_AND_ATTRIBUTES,
) -> Result<OwnedHandle, ()> {
    let encoded = encode_path(path);
    // SAFETY: the encoded path is NUL-terminated and live for the synchronous
    // call. Optional pointers are null and a successful fresh handle is moved
    // exactly once into OwnedHandle.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            access,
            share,
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            disposition,
            flags,
            std::ptr::null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(());
    }
    // SAFETY: ownership of this fresh successful handle is transferred once.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
}

fn checked_size(value: usize) -> u32 {
    u32::try_from(value).expect("native information structure size should fit u32")
}

fn query_identity(handle: HANDLE) -> FileIdentity {
    assert!(!handle.is_null() && handle != INVALID_HANDLE_VALUE);
    let mut information = FILE_ID_INFO::default();
    // SAFETY: the borrowed handle remains live and the initialized output has
    // exactly the size required for FileIdInfo.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut information).cast::<c_void>(),
            checked_size(std::mem::size_of::<FILE_ID_INFO>()),
        )
    };
    assert_ne!(succeeded, 0, "full file identity should be observable");
    FileIdentity {
        volume_serial: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    }
}

fn query_final_path(handle: HANDLE) -> Vec<u16> {
    // SAFETY: this is the documented size query on a live borrowed handle.
    let required =
        unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, FINAL_PATH_FLAGS) };
    let capacity = usize::try_from(required).expect("final-path size should fit usize");
    assert!((1..=MAXIMUM_FINAL_PATH_UNITS).contains(&capacity));
    let mut output = vec![0_u16; capacity];
    // SAFETY: output is writable for exactly the requested checked capacity.
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, output.as_mut_ptr(), required, FINAL_PATH_FLAGS)
    };
    let written = usize::try_from(written).expect("written path size should fit usize");
    assert!(written > 0 && written < output.len());
    output.truncate(written);
    output
}

fn query_observation(handle: &OwnedHandle) -> Observation {
    let raw = handle.as_raw_handle() as HANDLE;
    let mut standard = FILE_STANDARD_INFO::default();
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    for (class, output, size) in [
        (
            FileStandardInfo,
            (&raw mut standard).cast::<c_void>(),
            std::mem::size_of::<FILE_STANDARD_INFO>(),
        ),
        (
            FileAttributeTagInfo,
            (&raw mut attributes).cast::<c_void>(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>(),
        ),
    ] {
        // SAFETY: each output points to initialized writable storage matching
        // the requested information class and checked size.
        let succeeded =
            unsafe { GetFileInformationByHandleEx(raw, class, output, checked_size(size)) };
        assert_ne!(succeeded, 0, "handle facts should be observable");
    }
    let mut legacy = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: legacy is initialized writable storage and the handle is live.
    let legacy_succeeded = unsafe { GetFileInformationByHandle(raw, &raw mut legacy) };
    assert_ne!(legacy_succeeded, 0, "hard-link count should be observable");
    Observation {
        identity: query_identity(raw),
        // SAFETY: the borrowed handle remains live for this synchronous query.
        disk_entry: unsafe { GetFileType(raw) } == FILE_TYPE_DISK,
        attributes: attributes.FileAttributes,
        reparse_tag: attributes.ReparseTag,
        delete_pending: standard.DeletePending,
        directory: standard.Directory,
        link_count: legacy.nNumberOfLinks,
        size: u64::try_from(standard.EndOfFile).expect("file size should be nonnegative"),
        final_path: query_final_path(raw),
    }
}

fn volume_prefix(path: &[u16]) -> &[u16] {
    assert!(path.len() >= VOLUME_GUID_PREFIX_UNITS);
    let prefix: Vec<u16> = r"\\?\Volume{".encode_utf16().collect();
    assert_eq!(path.get(..prefix.len()), Some(prefix.as_slice()));
    assert_eq!(path[47], b'}' as u16);
    assert_eq!(path[48], b'\\' as u16);
    &path[..VOLUME_GUID_PREFIX_UNITS]
}

fn assert_directory(observation: &Observation) {
    assert!(observation.disk_entry);
    assert_ne!(observation.attributes & FILE_ATTRIBUTE_DIRECTORY, 0);
    assert_eq!(observation.attributes & FILE_ATTRIBUTE_REPARSE_POINT, 0);
    assert_eq!(observation.reparse_tag, 0);
    assert!(observation.directory);
    assert!(!observation.delete_pending);
    volume_prefix(&observation.final_path);
}

fn assert_zero_length_regular_leaf(observation: &Observation) {
    assert!(observation.disk_entry);
    assert_eq!(observation.attributes & FILE_ATTRIBUTE_DIRECTORY, 0);
    assert_eq!(observation.attributes & FILE_ATTRIBUTE_REPARSE_POINT, 0);
    assert_eq!(observation.reparse_tag, 0);
    assert!(!observation.directory);
    assert!(!observation.delete_pending);
    assert_eq!(observation.link_count, 1);
    assert_eq!(observation.size, 0);
    volume_prefix(&observation.final_path);
}

fn assert_exact_child(parent: &Observation, leaf: &Observation) {
    assert_eq!(parent.identity.volume_serial, leaf.identity.volume_serial);
    assert_eq!(
        volume_prefix(&parent.final_path),
        volume_prefix(&leaf.final_path)
    );
    let mut expected = parent.final_path.clone();
    if expected.last() != Some(&(b'\\' as u16)) {
        expected.push(b'\\' as u16);
    }
    expected.extend(OsStr::new(DATABASE_LEAF).encode_wide());
    assert!(
        expected == leaf.final_path,
        "leaf must be the exact parent child"
    );
}

fn assert_rename_and_delete_excluded(root: &Path) {
    let leaf = root.join(DATABASE_LEAF);
    let renamed = root.join(RENAME_DESTINATION);
    assert!(!renamed.exists());
    assert!(
        fs::rename(&leaf, &renamed).is_err(),
        "rename must fail while the no-delete-sharing leaf handle is live"
    );
    assert!(leaf.exists());
    assert!(!renamed.exists());
    assert!(
        fs::remove_file(&leaf).is_err(),
        "delete must fail while the no-delete-sharing leaf handle is live"
    );
    assert!(leaf.exists());
}

#[test]
fn retained_create_handle_is_compatible_with_exact_writable_sqlite_open_and_identity() {
    const HANDOFF_SOURCE: &str = include_str!("../production_database_connection_handoff.rs");
    assert!(HANDOFF_SOURCE.contains("#[cfg(test)]\nmod retained_create_handle_feasibility;"));

    let root = TestRoot::create();
    let leaf_path = root.path().join(DATABASE_LEAF);
    let parent_handle = open_handle(
        root.path(),
        PARENT_ACCESS,
        PARENT_SHARE,
        PARENT_DISPOSITION,
        PARENT_FLAGS,
    )
    .expect("the exact retained parent handle should open");
    let leaf_handle = open_handle(
        &leaf_path,
        LEAF_ACCESS,
        LEAF_SHARE,
        LEAF_DISPOSITION,
        LEAF_FLAGS,
    )
    .expect("the exact retained leaf handle should create the file atomically");

    assert!(
        open_handle(
            &leaf_path,
            LEAF_ACCESS,
            LEAF_SHARE,
            LEAF_DISPOSITION,
            LEAF_FLAGS,
        )
        .is_err(),
        "a second exact create-new attempt must fail"
    );

    let initial_parent = query_observation(&parent_handle);
    let initial_leaf = query_observation(&leaf_handle);
    assert_directory(&initial_parent);
    assert_zero_length_regular_leaf(&initial_leaf);
    assert_exact_child(&initial_parent, &initial_leaf);

    let connection = Connection::open_with_flags_and_vfs(&leaf_path, SQLITE_FLAGS, "win32")
        .expect("the exact writable no-create SQLite open should succeed");
    assert_eq!(connection.is_readonly("main").ok(), Some(false));

    let sqlite_handle = sqlite_main_database_handle(&connection)
        .expect("SQLite should expose its borrowed main-file Windows handle");
    assert!(
        query_identity(sqlite_handle) == initial_leaf.identity,
        "SQLite must hold the exact atomically created file object"
    );

    let post_open_parent = query_observation(&parent_handle);
    let post_open_leaf = query_observation(&leaf_handle);
    assert_directory(&post_open_parent);
    assert_zero_length_regular_leaf(&post_open_leaf);
    assert_exact_child(&post_open_parent, &post_open_leaf);
    assert!(post_open_parent == initial_parent);
    assert!(post_open_leaf == initial_leaf);

    assert_rename_and_delete_excluded(root.path());
    connection
        .close()
        .map_err(|(_, error)| error)
        .expect("the SQLite connection should close explicitly");
    assert_rename_and_delete_excluded(root.path());

    drop(leaf_handle);
    drop(parent_handle);
    root.assert_exact_cleanup();
}
