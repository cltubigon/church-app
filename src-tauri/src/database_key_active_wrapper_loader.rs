//! Hardened read-only loading of the active database-key protected wrapper.
//!
//! Success establishes only bounded, stable selection of the exact approved
//! active artifact. The returned bytes remain opaque and untrusted. It does
//! not prove wrapper framing or object kind, CurrentUser-DPAPI provenance,
//! database-key payload validity, generation correspondence, SQLCipher
//! correctness, or any startup, recovery, publication, or operational authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::{fmt, io::Read};

use crate::database_key_presence::DatabaseKeyActivePresence;

const MINIMUM_PROTECTED_WRAPPER_LENGTH: u64 = 15;
const MAXIMUM_PROTECTED_WRAPPER_LENGTH: u64 = 65_550;

#[derive(Eq, PartialEq)]
pub(crate) struct LoadedActiveDatabaseKeyWrapper {
    bytes: Vec<u8>,
}

impl LoadedActiveDatabaseKeyWrapper {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for LoadedActiveDatabaseKeyWrapper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoadedActiveDatabaseKeyWrapper([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum DatabaseKeyActiveWrapperLoadError {
    PresenceNotPresent,
    InspectionUnavailable,
    InvalidActiveArtifact,
    WrapperSizeInvalid,
    ActiveArtifactUnstable,
    WrapperReadUnavailable,
}

impl fmt::Debug for DatabaseKeyActiveWrapperLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PresenceNotPresent => "PresenceNotPresent",
            Self::InspectionUnavailable => "InspectionUnavailable",
            Self::InvalidActiveArtifact => "InvalidActiveArtifact",
            Self::WrapperSizeInvalid => "WrapperSizeInvalid",
            Self::ActiveArtifactUnstable => "ActiveArtifactUnstable",
            Self::WrapperReadUnavailable => "WrapperReadUnavailable",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundedReadError {
    SizeInvalid,
    ReadUnavailable,
    Unstable,
}

fn read_bounded_wrapper<R: Read>(
    reader: &mut R,
    reported_length: u64,
) -> Result<LoadedActiveDatabaseKeyWrapper, BoundedReadError> {
    if !(MINIMUM_PROTECTED_WRAPPER_LENGTH..=MAXIMUM_PROTECTED_WRAPPER_LENGTH)
        .contains(&reported_length)
    {
        return Err(BoundedReadError::SizeInvalid);
    }
    let length = usize::try_from(reported_length).map_err(|_| BoundedReadError::SizeInvalid)?;
    let mut bytes = vec![0_u8; length];
    let mut filled = 0;
    while filled < length {
        match reader.read(&mut bytes[filled..]) {
            Ok(0) => return Err(BoundedReadError::Unstable),
            Ok(count) => filled += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(BoundedReadError::ReadUnavailable),
        }
    }
    let mut trailing = [0_u8; 1];
    loop {
        match reader.read(&mut trailing) {
            Ok(0) => return Ok(LoadedActiveDatabaseKeyWrapper { bytes }),
            Ok(_) => return Err(BoundedReadError::Unstable),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(BoundedReadError::ReadUnavailable),
        }
    }
}

fn require_present<T, F>(
    presence: DatabaseKeyActivePresence,
    load: F,
) -> Result<T, DatabaseKeyActiveWrapperLoadError>
where
    F: FnOnce() -> Result<T, DatabaseKeyActiveWrapperLoadError>,
{
    if presence != DatabaseKeyActivePresence::Present {
        return Err(DatabaseKeyActiveWrapperLoadError::PresenceNotPresent);
    }
    load()
}

#[cfg(windows)]
pub(crate) fn load_active_database_key_wrapper(
    paths: &crate::storage_foundation::DatabaseKeyPersistencePaths,
    presence: DatabaseKeyActivePresence,
) -> Result<LoadedActiveDatabaseKeyWrapper, DatabaseKeyActiveWrapperLoadError> {
    require_present(presence, || windows::load(paths))
}

#[cfg(windows)]
mod windows {
    use std::{
        ffi::{OsStr, c_void},
        fs::{self, File},
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
        },
        path::Path,
    };

    use windows_sys::Win32::{
        Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GENERIC_READ, GetLastError, HANDLE,
            INVALID_HANDLE_VALUE,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
            FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_FLAGS_AND_ATTRIBUTES, FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_SHARE_MODE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_TYPE_DISK,
            FileAttributeTagInfo, FileBasicInfo, FileIdInfo, FileStandardInfo,
            GETFINALPATHNAMEBYHANDLE_FLAGS, GetFileInformationByHandle,
            GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW, OPEN_EXISTING,
            VOLUME_NAME_GUID,
        },
    };

    use crate::storage_foundation::{
        ACTIVE_DATABASE_KEY_FILENAME, DATABASE_KEY_DIRECTORY_NAME, DatabaseKeyPersistencePaths,
    };

    use super::{
        BoundedReadError, DatabaseKeyActiveWrapperLoadError, LoadedActiveDatabaseKeyWrapper,
        MAXIMUM_PROTECTED_WRAPPER_LENGTH, MINIMUM_PROTECTED_WRAPPER_LENGTH, read_bounded_wrapper,
    };

    const DIRECTORY_ACCESS: u32 = 0;
    const DIRECTORY_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ | FILE_SHARE_WRITE;
    const DIRECTORY_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    const FILE_ACCESS: u32 = GENERIC_READ;
    const FILE_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ;
    const FILE_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    const FINAL_PATH_FLAGS: GETFINALPATHNAMEBYHANDLE_FLAGS =
        FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;
    const MAXIMUM_FINAL_PATH_UNITS: usize = 32_767;
    const VOLUME_GUID_PREFIX_UNITS: usize = 49;

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct Identity {
        volume_serial: u64,
        file_id: [u8; 16],
    }

    #[derive(Clone, Eq, PartialEq)]
    struct Observation {
        identity: Identity,
        size: u64,
        allocation_size: u64,
        attributes: u32,
        reparse_tag: u32,
        link_count: u32,
        delete_pending: bool,
        directory: bool,
        creation_time: i64,
        last_write_time: i64,
        change_time: i64,
        final_path: Vec<u16>,
    }

    struct RetainedDirectory {
        handle: File,
        initial: Observation,
    }

    struct LoadedFile {
        handle: File,
        observation: Observation,
        loaded: LoadedActiveDatabaseKeyWrapper,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Failure {
        Inspection,
        Invalid,
        Read,
        Size,
        Unstable,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum OpenFailure {
        Missing,
        Unavailable,
        Invalid,
    }

    impl From<Failure> for DatabaseKeyActiveWrapperLoadError {
        fn from(value: Failure) -> Self {
            match value {
                Failure::Inspection => Self::InspectionUnavailable,
                Failure::Invalid => Self::InvalidActiveArtifact,
                Failure::Read => Self::WrapperReadUnavailable,
                Failure::Size => Self::WrapperSizeInvalid,
                Failure::Unstable => Self::ActiveArtifactUnstable,
            }
        }
    }

    fn checked_size(value: usize) -> Result<u32, Failure> {
        u32::try_from(value).map_err(|_| Failure::Inspection)
    }

    fn encode_path(path: &Path) -> Result<Vec<u16>, Failure> {
        let mut encoded = Vec::new();
        for unit in path.as_os_str().encode_wide() {
            if unit == 0 {
                return Err(Failure::Invalid);
            }
            encoded.push(unit);
        }
        encoded.push(0);
        Ok(encoded)
    }

    fn open(
        path: &Path,
        access: u32,
        share: FILE_SHARE_MODE,
        flags: FILE_FLAGS_AND_ATTRIBUTES,
    ) -> Result<File, OpenFailure> {
        let encoded = encode_path(path).map_err(|_| OpenFailure::Invalid)?;
        // SAFETY: the path is NUL-terminated and live for this synchronous call;
        // optional pointers are null and a successful fresh handle is owned once.
        let raw = unsafe {
            CreateFileW(
                encoded.as_ptr(),
                access,
                share,
                std::ptr::null::<SECURITY_ATTRIBUTES>(),
                OPEN_EXISTING,
                flags,
                std::ptr::null_mut::<c_void>(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            // SAFETY: this immediately follows the failed native call.
            let error = unsafe { GetLastError() };
            return if matches!(error, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
                Err(OpenFailure::Missing)
            } else {
                Err(OpenFailure::Unavailable)
            };
        }
        // SAFETY: ownership of the successful fresh native handle moves once.
        let owned = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        Ok(File::from(owned))
    }

    fn query_final_path(file: &File) -> Result<Vec<u16>, Failure> {
        let handle = file.as_raw_handle() as HANDLE;
        // SAFETY: documented size query on a live synchronous handle.
        let required =
            unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, FINAL_PATH_FLAGS) };
        let capacity = usize::try_from(required).map_err(|_| Failure::Inspection)?;
        if capacity == 0 || capacity > MAXIMUM_FINAL_PATH_UNITS {
            return Err(Failure::Inspection);
        }
        let mut output = vec![0_u16; capacity];
        // SAFETY: output has exactly the checked writable capacity.
        let written = unsafe {
            GetFinalPathNameByHandleW(handle, output.as_mut_ptr(), required, FINAL_PATH_FLAGS)
        };
        let written = usize::try_from(written).map_err(|_| Failure::Inspection)?;
        if written == 0 || written >= output.len() || written > MAXIMUM_FINAL_PATH_UNITS {
            return Err(Failure::Inspection);
        }
        output.truncate(written);
        Ok(output)
    }

    fn query_observation(file: &File) -> Result<Observation, Failure> {
        let handle = file.as_raw_handle() as HANDLE;
        // SAFETY: the File owns this handle for every query below.
        if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
            return Err(Failure::Invalid);
        }
        let mut standard = FILE_STANDARD_INFO::default();
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        let mut basic = FILE_BASIC_INFO::default();
        let mut identity = FILE_ID_INFO::default();
        for (class, pointer, size) in [
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
            (
                FileBasicInfo,
                (&raw mut basic).cast::<c_void>(),
                std::mem::size_of::<FILE_BASIC_INFO>(),
            ),
            (
                FileIdInfo,
                (&raw mut identity).cast::<c_void>(),
                std::mem::size_of::<FILE_ID_INFO>(),
            ),
        ] {
            // SAFETY: each pointer names initialized writable storage matching
            // the class and checked size; the handle remains live.
            if unsafe { GetFileInformationByHandleEx(handle, class, pointer, checked_size(size)?) }
                == 0
            {
                return Err(Failure::Inspection);
            }
        }
        let mut legacy = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: initialized writable output and a live owned handle.
        if unsafe { GetFileInformationByHandle(handle, &raw mut legacy) } == 0 {
            return Err(Failure::Inspection);
        }
        Ok(Observation {
            identity: Identity {
                volume_serial: identity.VolumeSerialNumber,
                file_id: identity.FileId.Identifier,
            },
            size: u64::try_from(standard.EndOfFile).map_err(|_| Failure::Invalid)?,
            allocation_size: u64::try_from(standard.AllocationSize)
                .map_err(|_| Failure::Invalid)?,
            attributes: attributes.FileAttributes,
            reparse_tag: attributes.ReparseTag,
            link_count: legacy.nNumberOfLinks,
            delete_pending: standard.DeletePending,
            directory: standard.Directory,
            creation_time: basic.CreationTime,
            last_write_time: basic.LastWriteTime,
            change_time: basic.ChangeTime,
            final_path: query_final_path(file)?,
        })
    }

    fn ascii_units(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn fold_hex(unit: u16) -> u16 {
        if (b'A' as u16..=b'F' as u16).contains(&unit) {
            unit + 32
        } else {
            unit
        }
    }

    fn is_ascii_hex(unit: u16) -> bool {
        (b'0' as u16..=b'9' as u16).contains(&unit)
            || (b'a' as u16..=b'f' as u16).contains(&unit)
            || (b'A' as u16..=b'F' as u16).contains(&unit)
    }

    fn volume_prefix(path: &[u16]) -> Result<&[u16], Failure> {
        let prefix = ascii_units(r"\\?\Volume{");
        if path.len() < VOLUME_GUID_PREFIX_UNITS
            || path.len() > MAXIMUM_FINAL_PATH_UNITS
            || path.contains(&0)
            || path.get(..prefix.len()) != Some(prefix.as_slice())
            || path[47] != b'}' as u16
            || path[48] != b'\\' as u16
        {
            return Err(Failure::Invalid);
        }
        for (offset, unit) in path[11..47].iter().copied().enumerate() {
            let valid = if matches!(offset, 8 | 13 | 18 | 23) {
                unit == b'-' as u16
            } else {
                is_ascii_hex(unit)
            };
            if !valid {
                return Err(Failure::Invalid);
            }
        }
        Ok(&path[..VOLUME_GUID_PREFIX_UNITS])
    }

    fn same_volume(left: &Observation, right: &Observation) -> Result<(), Failure> {
        let left_prefix = volume_prefix(&left.final_path)?;
        let right_prefix = volume_prefix(&right.final_path)?;
        if left.identity.volume_serial != right.identity.volume_serial
            || left_prefix[..11] != right_prefix[..11]
            || left_prefix[47..] != right_prefix[47..]
            || !left_prefix[11..47]
                .iter()
                .zip(&right_prefix[11..47])
                .all(|(left, right)| fold_hex(*left) == fold_hex(*right))
        {
            return Err(Failure::Invalid);
        }
        Ok(())
    }

    fn exact_child(parent: &Observation, child: &Observation, name: &OsStr) -> Result<(), Failure> {
        same_volume(parent, child)?;
        let component: Vec<u16> = name.encode_wide().collect();
        if component.is_empty() || component.iter().any(|unit| matches!(*unit, 0 | 47 | 92)) {
            return Err(Failure::Invalid);
        }
        let mut expected = parent.final_path.clone();
        if expected.last() != Some(&(b'\\' as u16)) {
            expected.push(b'\\' as u16);
        }
        expected.extend_from_slice(&component);
        if expected.len() != child.final_path.len()
            || expected[..11] != child.final_path[..11]
            || expected[47..] != child.final_path[47..]
            || !expected[11..47]
                .iter()
                .zip(&child.final_path[11..47])
                .all(|(left, right)| fold_hex(*left) == fold_hex(*right))
        {
            return Err(Failure::Invalid);
        }
        Ok(())
    }

    fn validate_directory(observation: &Observation) -> Result<(), Failure> {
        if observation.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || observation.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || observation.reparse_tag != 0
            || !observation.directory
            || observation.delete_pending
        {
            return Err(Failure::Invalid);
        }
        volume_prefix(&observation.final_path)?;
        Ok(())
    }

    fn validate_file(observation: &Observation) -> Result<(), Failure> {
        if observation.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || observation.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || observation.reparse_tag != 0
            || observation.directory
            || observation.delete_pending
            || observation.link_count != 1
        {
            return Err(Failure::Invalid);
        }
        if !(MINIMUM_PROTECTED_WRAPPER_LENGTH..=MAXIMUM_PROTECTED_WRAPPER_LENGTH)
            .contains(&observation.size)
        {
            return Err(Failure::Size);
        }
        Ok(())
    }

    fn open_directory(
        path: &Path,
        parent: Option<(&Observation, &OsStr)>,
    ) -> Result<RetainedDirectory, Failure> {
        let handle =
            open(path, DIRECTORY_ACCESS, DIRECTORY_SHARE, DIRECTORY_FLAGS).map_err(|failure| {
                match failure {
                    OpenFailure::Invalid => Failure::Invalid,
                    OpenFailure::Missing | OpenFailure::Unavailable => Failure::Inspection,
                }
            })?;
        let initial = query_observation(&handle)?;
        validate_directory(&initial)?;
        if let Some((parent, name)) = parent {
            exact_child(parent, &initial, name)?;
        }
        Ok(RetainedDirectory { handle, initial })
    }

    fn validate_contract(paths: &DatabaseKeyPersistencePaths) -> Result<&Path, Failure> {
        let directory = paths.database_key_directory.as_path();
        let parent = directory.parent().ok_or(Failure::Invalid)?;
        if directory != parent.join(DATABASE_KEY_DIRECTORY_NAME)
            || paths.active_database_key.as_path() != directory.join(ACTIVE_DATABASE_KEY_FILENAME)
        {
            return Err(Failure::Invalid);
        }
        Ok(parent)
    }

    fn enumerate_exact_active(directory: &Path) -> Result<(), Failure> {
        let mut active_count = 0_u8;
        for entry in fs::read_dir(directory).map_err(|_| Failure::Inspection)? {
            let name = entry.map_err(|_| Failure::Inspection)?.file_name();
            if name
                .encode_wide()
                .eq(ACTIVE_DATABASE_KEY_FILENAME.encode_utf16())
            {
                active_count = active_count.saturating_add(1);
            } else {
                return Err(Failure::Invalid);
            }
        }
        if active_count != 1 {
            return Err(Failure::Unstable);
        }
        Ok(())
    }

    fn load_file(
        path: &Path,
        directory: &RetainedDirectory,
        mut before_read: impl FnMut(),
    ) -> Result<LoadedFile, Failure> {
        if path.file_name() != Some(OsStr::new(ACTIVE_DATABASE_KEY_FILENAME)) {
            return Err(Failure::Invalid);
        }
        let mut handle =
            open(path, FILE_ACCESS, FILE_SHARE, FILE_FLAGS).map_err(|failure| match failure {
                OpenFailure::Invalid => Failure::Invalid,
                OpenFailure::Missing => Failure::Unstable,
                OpenFailure::Unavailable => Failure::Read,
            })?;
        let before = query_observation(&handle)?;
        validate_file(&before)?;
        exact_child(
            &directory.initial,
            &before,
            OsStr::new(ACTIVE_DATABASE_KEY_FILENAME),
        )?;
        before_read();
        let loaded =
            read_bounded_wrapper(&mut handle, before.size).map_err(|error| match error {
                BoundedReadError::SizeInvalid => Failure::Size,
                BoundedReadError::ReadUnavailable => Failure::Read,
                BoundedReadError::Unstable => Failure::Unstable,
            })?;
        let after = query_observation(&handle)?;
        if before != after {
            return Err(Failure::Unstable);
        }
        if directory.initial != query_observation(&directory.handle)? {
            return Err(Failure::Unstable);
        }
        Ok(LoadedFile {
            handle,
            observation: before,
            loaded,
        })
    }

    fn confirm_file(
        path: &Path,
        loaded: &LoadedFile,
        directory: &RetainedDirectory,
    ) -> Result<(), Failure> {
        if query_observation(&loaded.handle)? != loaded.observation {
            return Err(Failure::Unstable);
        }
        let reopened =
            open(path, FILE_ACCESS, FILE_SHARE, FILE_FLAGS).map_err(|failure| match failure {
                OpenFailure::Invalid => Failure::Invalid,
                OpenFailure::Missing => Failure::Unstable,
                OpenFailure::Unavailable => Failure::Inspection,
            })?;
        let reopened_observation = query_observation(&reopened)?;
        validate_file(&reopened_observation)?;
        exact_child(
            &directory.initial,
            &reopened_observation,
            OsStr::new(ACTIVE_DATABASE_KEY_FILENAME),
        )?;
        if reopened_observation != loaded.observation {
            return Err(Failure::Unstable);
        }
        Ok(())
    }

    #[cfg(test)]
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(super) enum LoadPhase {
        BeforeRead,
        AfterRead,
        BeforeFinalConfirmation,
    }

    fn load_inner_with_hook<F>(
        paths: &DatabaseKeyPersistencePaths,
        mut hook: F,
    ) -> Result<LoadedActiveDatabaseKeyWrapper, Failure>
    where
        F: FnMut(TestPhase),
    {
        let parent_path = validate_contract(paths)?;
        let directory_path = paths.database_key_directory.as_path();
        let parent = open_directory(parent_path, None)?;
        let directory = open_directory(
            directory_path,
            Some((&parent.initial, OsStr::new(DATABASE_KEY_DIRECTORY_NAME))),
        )?;
        enumerate_exact_active(directory_path)?;
        let loaded = load_file(paths.active_database_key.as_path(), &directory, || {
            hook(TestPhase::BeforeRead)
        })?;
        hook(TestPhase::AfterRead);
        enumerate_exact_active(directory_path).map_err(|failure| match failure {
            Failure::Invalid => Failure::Unstable,
            other => other,
        })?;
        confirm_file(paths.active_database_key.as_path(), &loaded, &directory)?;
        hook(TestPhase::BeforeFinalConfirmation);
        if query_observation(&parent.handle)? != parent.initial
            || query_observation(&directory.handle)? != directory.initial
        {
            return Err(Failure::Unstable);
        }
        let reopened_parent = open_directory(parent_path, None)?;
        if reopened_parent.initial != parent.initial {
            return Err(Failure::Unstable);
        }
        let reopened_directory = open_directory(
            directory_path,
            Some((
                &reopened_parent.initial,
                OsStr::new(DATABASE_KEY_DIRECTORY_NAME),
            )),
        )?;
        if reopened_directory.initial != directory.initial {
            return Err(Failure::Unstable);
        }
        enumerate_exact_active(directory_path).map_err(|failure| match failure {
            Failure::Invalid => Failure::Unstable,
            other => other,
        })?;
        confirm_file(paths.active_database_key.as_path(), &loaded, &directory)?;
        Ok(loaded.loaded)
    }

    #[cfg(test)]
    type TestPhase = LoadPhase;
    #[cfg(not(test))]
    #[derive(Clone, Copy)]
    enum TestPhase {
        BeforeRead,
        AfterRead,
        BeforeFinalConfirmation,
    }

    fn load_inner(
        paths: &DatabaseKeyPersistencePaths,
    ) -> Result<LoadedActiveDatabaseKeyWrapper, Failure> {
        load_inner_with_hook(paths, |_| {})
    }

    #[cfg(test)]
    pub(super) fn load_with_test_hook<F>(
        paths: &DatabaseKeyPersistencePaths,
        hook: F,
    ) -> Result<LoadedActiveDatabaseKeyWrapper, DatabaseKeyActiveWrapperLoadError>
    where
        F: FnMut(LoadPhase),
    {
        load_inner_with_hook(paths, hook).map_err(Into::into)
    }

    pub(super) fn load(
        paths: &DatabaseKeyPersistencePaths,
    ) -> Result<LoadedActiveDatabaseKeyWrapper, DatabaseKeyActiveWrapperLoadError> {
        load_inner(paths).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, io, io::Cursor, mem::size_of};

    use super::*;

    #[test]
    fn loaded_value_is_nominal_owned_exact_and_redacted() {
        let bytes = vec![0xa5; 31];
        let loaded = read_bounded_wrapper(&mut Cursor::new(bytes.clone()), 31).unwrap();
        assert_eq!(loaded.as_bytes(), bytes);
        assert_eq!(
            format!("{loaded:?}"),
            "LoadedActiveDatabaseKeyWrapper([REDACTED])"
        );
        assert_eq!(
            size_of::<LoadedActiveDatabaseKeyWrapper>(),
            size_of::<Vec<u8>>()
        );
    }

    #[test]
    fn error_vocabulary_is_exact_payload_free_and_redacted_by_construction() {
        for (error, expected) in [
            (
                DatabaseKeyActiveWrapperLoadError::PresenceNotPresent,
                "PresenceNotPresent",
            ),
            (
                DatabaseKeyActiveWrapperLoadError::InspectionUnavailable,
                "InspectionUnavailable",
            ),
            (
                DatabaseKeyActiveWrapperLoadError::InvalidActiveArtifact,
                "InvalidActiveArtifact",
            ),
            (
                DatabaseKeyActiveWrapperLoadError::WrapperSizeInvalid,
                "WrapperSizeInvalid",
            ),
            (
                DatabaseKeyActiveWrapperLoadError::ActiveArtifactUnstable,
                "ActiveArtifactUnstable",
            ),
            (
                DatabaseKeyActiveWrapperLoadError::WrapperReadUnavailable,
                "WrapperReadUnavailable",
            ),
        ] {
            let debug = format!("{error:?}");
            assert_eq!(debug, expected);
            for forbidden in ["\\", "/", ".dpapi", "0x", "["] {
                assert!(!debug.contains(forbidden));
            }
        }
    }

    #[test]
    fn only_present_invokes_the_loader() {
        for presence in [
            DatabaseKeyActivePresence::Missing,
            DatabaseKeyActivePresence::Unavailable,
            DatabaseKeyActivePresence::Invalid,
        ] {
            let calls = Cell::new(0);
            let result = require_present(presence, || {
                calls.set(calls.get() + 1);
                Ok(())
            });
            assert_eq!(
                result,
                Err(DatabaseKeyActiveWrapperLoadError::PresenceNotPresent)
            );
            assert_eq!(calls.get(), 0);
        }
        let calls = Cell::new(0);
        assert_eq!(
            require_present(DatabaseKeyActivePresence::Present, || {
                calls.set(calls.get() + 1);
                Ok(7)
            }),
            Ok(7)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn bounded_reader_accepts_limits_representative_and_arbitrary_opaque_bytes() {
        for bytes in [vec![0x11; 15], vec![0x22; 257], vec![0x33; 65_550]] {
            let loaded =
                read_bounded_wrapper(&mut Cursor::new(bytes.clone()), bytes.len() as u64).unwrap();
            assert_eq!(loaded.as_bytes(), bytes);
        }
        let mut malformed = b"not-CHDPAPI!!".to_vec();
        malformed.resize(29, 0xff);
        let loaded =
            read_bounded_wrapper(&mut Cursor::new(malformed.clone()), malformed.len() as u64)
                .unwrap();
        assert_eq!(loaded.as_bytes(), malformed);
    }

    #[test]
    fn bounded_reader_rejects_all_short_and_representative_oversize_lengths() {
        for length in 0..15_u64 {
            assert_eq!(
                read_bounded_wrapper(&mut Cursor::new(vec![0; length as usize]), length),
                Err(BoundedReadError::SizeInvalid)
            );
        }
        for length in [65_551_u64, 70_000, u64::MAX] {
            assert_eq!(
                read_bounded_wrapper(&mut Cursor::new(Vec::new()), length),
                Err(BoundedReadError::SizeInvalid)
            );
        }
    }

    struct ShortReader;
    impl Read for ShortReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if output.len() == 15 {
                output[..14].fill(1);
                Ok(14)
            } else {
                Ok(0)
            }
        }
    }

    struct FailedReader;
    impl Read for FailedReader {
        fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "synthetic"))
        }
    }

    struct InterruptedReader {
        interrupted: bool,
        cursor: Cursor<Vec<u8>>,
    }

    impl Read for InterruptedReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            self.cursor.read(output)
        }
    }

    #[test]
    fn bounded_reader_distinguishes_truncation_growth_and_read_failure() {
        assert_eq!(
            read_bounded_wrapper(&mut ShortReader, 15),
            Err(BoundedReadError::Unstable)
        );
        assert_eq!(
            read_bounded_wrapper(&mut Cursor::new(vec![3; 16]), 15),
            Err(BoundedReadError::Unstable)
        );
        assert_eq!(
            read_bounded_wrapper(&mut FailedReader, 15),
            Err(BoundedReadError::ReadUnavailable)
        );
        let mut interrupted = InterruptedReader {
            interrupted: false,
            cursor: Cursor::new(vec![4; 15]),
        };
        assert_eq!(
            read_bounded_wrapper(&mut interrupted, 15)
                .unwrap()
                .as_bytes(),
            &[4; 15]
        );
    }

    #[test]
    fn source_contract_is_private_typed_opaque_read_only_and_non_authoritative() {
        const SOURCE: &str = include_str!("database_key_active_wrapper_loader.rs");
        const LIB_SOURCE: &str = include_str!("lib.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        let owner = production
            .split_once("pub(crate) struct LoadedActiveDatabaseKeyWrapper {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(owner.lines().filter(|line| line.contains(':')).count(), 1);
        assert!(owner.contains("    bytes: Vec<u8>,"));
        assert!(!owner.contains("pub "));
        assert!(!production.contains("derive(Clone, Eq, PartialEq)]\npub(crate) struct Loaded"));
        assert!(!production.contains("derive(Copy, Eq, PartialEq)]\npub(crate) struct Loaded"));
        assert!(production.contains(
            "pub(crate) fn load_active_database_key_wrapper(\n    paths: &crate::storage_foundation::DatabaseKeyPersistencePaths,\n    presence: DatabaseKeyActivePresence,"
        ));
        assert_eq!(
            LIB_SOURCE
                .matches("mod database_key_active_wrapper_loader;")
                .count(),
            1
        );
        assert!(!LIB_SOURCE.contains("pub mod database_key_active_wrapper_loader;"));
        for forbidden in [
            "Serialize",
            "Deserialize",
            "impl fmt::Display",
            "impl std::error::Error",
            "impl Into<",
            "pub Vec",
            "&Path,\n    presence",
            "ValidatedProtectedWrapper",
            "EncodedProtectedWrapper",
            "ProtectedObjectKind",
            "DecodedDatabaseKeyCandidate",
            "CryptProtectData",
            "CryptUnprotectData",
            "DatabaseKey::",
            "generation_identifier",
            "rusqlite",
            "ReplaceFileW",
            "MoveFileExW",
            "CreateDirectory",
            "remove_file",
            "remove_dir",
            "rename(",
            "write_all",
            "tauri::command",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected loader capability: {forbidden}"
            );
        }
        assert!(!owner.contains("impl From<"));
        assert!(!owner.contains("impl Into<"));
    }

    #[cfg(target_os = "windows")]
    mod windows_filesystem {
        use std::{
            fs,
            path::PathBuf,
            sync::atomic::{AtomicU64, Ordering},
            time::{SystemTime, UNIX_EPOCH},
        };

        use crate::{
            database_key_presence::inspect_database_key_active_presence,
            storage_foundation::{
                ACTIVE_DATABASE_KEY_FILENAME, DATABASE_KEY_DIRECTORY_NAME,
                DatabaseKeyPersistencePaths, database_key_persistence_paths,
            },
        };

        use super::*;

        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        struct Fixture {
            root: PathBuf,
            paths: DatabaseKeyPersistencePaths,
        }

        impl Fixture {
            fn new(bytes: &[u8]) -> Self {
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let root = std::env::temp_dir().join(format!(
                    "church-app-database-key-loader-{}-{nanos}-{id}",
                    std::process::id()
                ));
                fs::create_dir(&root).unwrap();
                let paths = database_key_persistence_paths(&root);
                fs::create_dir(paths.database_key_directory.as_path()).unwrap();
                fs::write(paths.active_database_key.as_path(), bytes).unwrap();
                Self { root, paths }
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                fs::remove_dir_all(&self.root).unwrap();
            }
        }

        fn load(
            fixture: &Fixture,
        ) -> Result<LoadedActiveDatabaseKeyWrapper, DatabaseKeyActiveWrapperLoadError> {
            let presence = inspect_database_key_active_presence(&fixture.paths);
            load_active_database_key_wrapper(&fixture.paths, presence)
        }

        #[test]
        fn canonical_minimum_representative_and_maximum_load_exact_owned_bytes() {
            for bytes in [vec![0x13; 15], vec![0x27; 257], vec![0x37; 65_550]] {
                let fixture = Fixture::new(&bytes);
                let loaded = load(&fixture).unwrap();
                assert_eq!(loaded.as_bytes(), bytes);
            }
        }

        #[test]
        fn malformed_wrong_kind_looking_and_random_opaque_contents_load_unchanged() {
            let mut malformed = b"CHDPAPI\0\xff\x05bad".to_vec();
            malformed.resize(31, 0xcc);
            let fixture = Fixture::new(&malformed);
            assert_eq!(load(&fixture).unwrap().as_bytes(), malformed);

            let mut state = 0x9e37_79b9_u32;
            let random: Vec<u8> = (0..1021)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect();
            let fixture = Fixture::new(&random);
            assert_eq!(load(&fixture).unwrap().as_bytes(), random);
        }

        #[test]
        fn every_short_size_and_oversize_return_wrapper_size_invalid() {
            for length in 0..15 {
                let fixture = Fixture::new(&vec![0; length]);
                assert_eq!(
                    load(&fixture),
                    Err(DatabaseKeyActiveWrapperLoadError::WrapperSizeInvalid)
                );
            }
            for length in [65_551, 70_000] {
                let fixture = Fixture::new(&vec![0; length]);
                assert_eq!(
                    load(&fixture),
                    Err(DatabaseKeyActiveWrapperLoadError::WrapperSizeInvalid)
                );
            }
        }

        #[test]
        fn unexpected_multiple_and_nested_children_are_rejected() {
            for child in ["unexpected.synthetic", "nested"] {
                let fixture = Fixture::new(&[1; 15]);
                let path = fixture.paths.database_key_directory.as_path().join(child);
                if child == "nested" {
                    fs::create_dir(path).unwrap();
                } else {
                    fs::write(path, b"synthetic").unwrap();
                }
                assert_eq!(
                    load_active_database_key_wrapper(
                        &fixture.paths,
                        DatabaseKeyActivePresence::Present
                    ),
                    Err(DatabaseKeyActiveWrapperLoadError::InvalidActiveArtifact)
                );
            }
        }

        #[test]
        fn typed_path_contract_tampering_is_rejected_before_loading() {
            let fixture = Fixture::new(&[1; 15]);
            let other = Fixture::new(&[2; 15]);

            let mut wrong_active = fixture.paths.clone();
            wrong_active.active_database_key = other.paths.active_database_key.clone();
            assert_eq!(
                load_active_database_key_wrapper(&wrong_active, DatabaseKeyActivePresence::Present),
                Err(DatabaseKeyActiveWrapperLoadError::InvalidActiveArtifact)
            );

            let mut wrong_directory = fixture.paths.clone();
            wrong_directory.database_key_directory = other.paths.database_key_directory.clone();
            assert_eq!(
                load_active_database_key_wrapper(
                    &wrong_directory,
                    DatabaseKeyActivePresence::Present
                ),
                Err(DatabaseKeyActiveWrapperLoadError::InvalidActiveArtifact)
            );
        }

        #[test]
        fn alternate_case_directory_and_active_name_are_rejected() {
            let directory_fixture = Fixture::new(&[1; 15]);
            let alternate_directory = directory_fixture.root.join("DATABASE-KEY");
            fs::rename(
                directory_fixture.paths.database_key_directory.as_path(),
                &alternate_directory,
            )
            .unwrap();
            assert_eq!(
                load_active_database_key_wrapper(
                    &directory_fixture.paths,
                    DatabaseKeyActivePresence::Present
                ),
                Err(DatabaseKeyActiveWrapperLoadError::InvalidActiveArtifact)
            );

            let file_fixture = Fixture::new(&[1; 15]);
            fs::rename(
                file_fixture.paths.active_database_key.as_path(),
                file_fixture
                    .paths
                    .database_key_directory
                    .as_path()
                    .join("ACTIVE-DATABASE-KEY.DPAPI"),
            )
            .unwrap();
            assert_eq!(
                load_active_database_key_wrapper(
                    &file_fixture.paths,
                    DatabaseKeyActivePresence::Present
                ),
                Err(DatabaseKeyActiveWrapperLoadError::InvalidActiveArtifact)
            );
            assert_eq!(DATABASE_KEY_DIRECTORY_NAME, "database-key");
            assert_eq!(ACTIVE_DATABASE_KEY_FILENAME, "active-database-key.dpapi");
        }

        #[test]
        fn directory_reparse_and_hard_link_active_artifacts_are_rejected() {
            let directory_fixture = Fixture::new(&[1; 15]);
            fs::remove_file(directory_fixture.paths.active_database_key.as_path()).unwrap();
            fs::create_dir(directory_fixture.paths.active_database_key.as_path()).unwrap();
            assert_eq!(
                load_active_database_key_wrapper(
                    &directory_fixture.paths,
                    DatabaseKeyActivePresence::Present
                ),
                Err(DatabaseKeyActiveWrapperLoadError::InvalidActiveArtifact)
            );

            let hard_link_fixture = Fixture::new(&[1; 15]);
            let alias = hard_link_fixture.root.join("database-key-alias.synthetic");
            fs::hard_link(hard_link_fixture.paths.active_database_key.as_path(), alias).unwrap();
            assert_eq!(
                load_active_database_key_wrapper(
                    &hard_link_fixture.paths,
                    DatabaseKeyActivePresence::Present
                ),
                Err(DatabaseKeyActiveWrapperLoadError::InvalidActiveArtifact)
            );

            let reparse_fixture = Fixture::new(&[1; 15]);
            let target = reparse_fixture.root.join("reparse-target.synthetic");
            fs::write(&target, [4; 15]).unwrap();
            fs::remove_file(reparse_fixture.paths.active_database_key.as_path()).unwrap();
            if std::os::windows::fs::symlink_file(
                &target,
                reparse_fixture.paths.active_database_key.as_path(),
            )
            .is_ok()
            {
                assert_eq!(
                    load_active_database_key_wrapper(
                        &reparse_fixture.paths,
                        DatabaseKeyActivePresence::Present
                    ),
                    Err(DatabaseKeyActiveWrapperLoadError::InvalidActiveArtifact)
                );
            }
        }

        #[test]
        fn unexpected_sibling_introduced_after_read_is_unstable() {
            let fixture = Fixture::new(&[1; 15]);
            let sibling = fixture
                .paths
                .database_key_directory
                .as_path()
                .join("appeared-during-load.synthetic");
            let result = super::super::windows::load_with_test_hook(&fixture.paths, |phase| {
                if phase == super::super::windows::LoadPhase::AfterRead {
                    fs::write(&sibling, b"synthetic").unwrap();
                }
            });
            assert_eq!(
                result,
                Err(DatabaseKeyActiveWrapperLoadError::ActiveArtifactUnstable)
            );
        }

        #[test]
        fn retained_handles_prevent_file_parent_and_directory_mutation() {
            let fixture = Fixture::new(&[1; 15]);
            let displaced_file = fixture.root.join("displaced-file.synthetic");
            let displaced_directory = fixture.root.join("displaced-directory.synthetic");
            let displaced_parent = fixture.root.with_extension("displaced-parent.synthetic");
            let delete_blocked = Cell::new(false);
            let growth_blocked = Cell::new(false);
            let shrink_blocked = Cell::new(false);
            let file_blocked = Cell::new(false);
            let directory_blocked = Cell::new(false);
            let parent_blocked = Cell::new(false);
            let loaded = super::super::windows::load_with_test_hook(&fixture.paths, |phase| {
                if phase == super::super::windows::LoadPhase::BeforeRead {
                    delete_blocked
                        .set(fs::remove_file(fixture.paths.active_database_key.as_path()).is_err());
                    growth_blocked.set(
                        fs::OpenOptions::new()
                            .append(true)
                            .open(fixture.paths.active_database_key.as_path())
                            .is_err(),
                    );
                    shrink_blocked.set(
                        fs::OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(fixture.paths.active_database_key.as_path())
                            .is_err(),
                    );
                    file_blocked.set(
                        fs::rename(fixture.paths.active_database_key.as_path(), &displaced_file)
                            .is_err(),
                    );
                }
                if phase == super::super::windows::LoadPhase::BeforeFinalConfirmation {
                    directory_blocked.set(
                        fs::rename(
                            fixture.paths.database_key_directory.as_path(),
                            &displaced_directory,
                        )
                        .is_err(),
                    );
                    parent_blocked.set(fs::rename(&fixture.root, &displaced_parent).is_err());
                }
            })
            .unwrap();
            assert!(delete_blocked.get());
            assert!(growth_blocked.get());
            assert!(shrink_blocked.get());
            assert!(file_blocked.get());
            assert!(directory_blocked.get());
            assert!(parent_blocked.get());
            assert_eq!(loaded.as_bytes(), &[1; 15]);
        }

        #[test]
        fn missing_after_typed_present_and_initial_inspection_failure_are_coarse() {
            let fixture = Fixture::new(&[1; 15]);
            fs::remove_file(fixture.paths.active_database_key.as_path()).unwrap();
            assert_eq!(
                load_active_database_key_wrapper(
                    &fixture.paths,
                    DatabaseKeyActivePresence::Present
                ),
                Err(DatabaseKeyActiveWrapperLoadError::ActiveArtifactUnstable)
            );

            let missing_root = fixture.root.join("missing-root");
            let paths = database_key_persistence_paths(&missing_root);
            assert_eq!(
                load_active_database_key_wrapper(&paths, DatabaseKeyActivePresence::Present),
                Err(DatabaseKeyActiveWrapperLoadError::InspectionUnavailable)
            );
        }
    }
}
