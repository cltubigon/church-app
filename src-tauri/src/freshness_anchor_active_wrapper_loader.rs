//! Read-only loading of the two active freshness-anchor protected wrappers.
//!
//! This boundary proves only bounded, stable selection of the two current
//! active names. The returned bytes remain opaque and grant no authentication,
//! freshness, recovery, publication, or operational authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::{fmt, io::Read};

use crate::freshness_anchor_presence::FreshnessAnchorActivePresence;

const MINIMUM_PROTECTED_WRAPPER_LENGTH: u64 = 15;
const MAXIMUM_PROTECTED_WRAPPER_LENGTH: u64 = 65_550;

#[derive(Eq, PartialEq)]
struct FreshnessAnchorProtectedWrapperBytes(Vec<u8>);

impl FreshnessAnchorProtectedWrapperBytes {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for FreshnessAnchorProtectedWrapperBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshnessAnchorProtectedWrapperBytes([REDACTED])")
    }
}

#[derive(Eq, PartialEq)]
pub(crate) struct LoadedActiveFreshnessAnchorWrapperPair {
    key_wrapper: FreshnessAnchorProtectedWrapperBytes,
    authenticated_anchor_wrapper: FreshnessAnchorProtectedWrapperBytes,
}

impl LoadedActiveFreshnessAnchorWrapperPair {
    pub(crate) fn key_wrapper_bytes(&self) -> &[u8] {
        self.key_wrapper.as_bytes()
    }

    pub(crate) fn authenticated_anchor_wrapper_bytes(&self) -> &[u8] {
        self.authenticated_anchor_wrapper.as_bytes()
    }

    #[cfg(test)]
    pub(crate) fn from_synthetic_wrapper_bytes(
        key_wrapper: Vec<u8>,
        authenticated_anchor_wrapper: Vec<u8>,
    ) -> Self {
        Self {
            key_wrapper: FreshnessAnchorProtectedWrapperBytes(key_wrapper),
            authenticated_anchor_wrapper: FreshnessAnchorProtectedWrapperBytes(
                authenticated_anchor_wrapper,
            ),
        }
    }
}

impl fmt::Debug for LoadedActiveFreshnessAnchorWrapperPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoadedActiveFreshnessAnchorWrapperPair([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FreshnessAnchorActiveWrapperLoadError {
    PresenceNotComplete,
    InspectionUnavailable,
    InvalidActiveArtifacts,
    WrapperReadUnavailable,
    WrapperSizeInvalid,
    ActiveArtifactsUnstable,
}

impl fmt::Debug for FreshnessAnchorActiveWrapperLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PresenceNotComplete => "PresenceNotComplete",
            Self::InspectionUnavailable => "InspectionUnavailable",
            Self::InvalidActiveArtifacts => "InvalidActiveArtifacts",
            Self::WrapperReadUnavailable => "WrapperReadUnavailable",
            Self::WrapperSizeInvalid => "WrapperSizeInvalid",
            Self::ActiveArtifactsUnstable => "ActiveArtifactsUnstable",
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
) -> Result<FreshnessAnchorProtectedWrapperBytes, BoundedReadError> {
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
            Ok(0) => return Ok(FreshnessAnchorProtectedWrapperBytes(bytes)),
            Ok(_) => return Err(BoundedReadError::Unstable),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(BoundedReadError::ReadUnavailable),
        }
    }
}

fn require_complete_presence<T, F>(
    presence: FreshnessAnchorActivePresence,
    load: F,
) -> Result<T, FreshnessAnchorActiveWrapperLoadError>
where
    F: FnOnce() -> Result<T, FreshnessAnchorActiveWrapperLoadError>,
{
    if presence != FreshnessAnchorActivePresence::CompleteActivePair {
        return Err(FreshnessAnchorActiveWrapperLoadError::PresenceNotComplete);
    }
    load()
}

#[cfg(windows)]
pub(crate) fn load_active_freshness_anchor_wrapper_pair(
    paths: &crate::storage_foundation::FreshnessAnchorPersistencePaths,
    presence: FreshnessAnchorActivePresence,
) -> Result<LoadedActiveFreshnessAnchorWrapperPair, FreshnessAnchorActiveWrapperLoadError> {
    require_complete_presence(presence, || windows::load(paths))
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
        Foundation::{GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE},
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
        ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME, ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME,
        FRESHNESS_ANCHOR_DIRECTORY_NAME, FreshnessAnchorPersistencePaths,
    };

    use super::{
        BoundedReadError, FreshnessAnchorActiveWrapperLoadError,
        FreshnessAnchorProtectedWrapperBytes, LoadedActiveFreshnessAnchorWrapperPair,
        MAXIMUM_PROTECTED_WRAPPER_LENGTH, MINIMUM_PROTECTED_WRAPPER_LENGTH, read_bounded_wrapper,
    };

    const DIRECTORY_ACCESS: u32 = 0;
    const DIRECTORY_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ | FILE_SHARE_WRITE;
    const DIRECTORY_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    const FILE_ACCESS: u32 = GENERIC_READ;
    const FILE_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ;
    const FILE_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
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
        bytes: FreshnessAnchorProtectedWrapperBytes,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Failure {
        Inspection,
        Invalid,
        Read,
        Size,
        Unstable,
    }

    impl From<Failure> for FreshnessAnchorActiveWrapperLoadError {
        fn from(value: Failure) -> Self {
            match value {
                Failure::Inspection => Self::InspectionUnavailable,
                Failure::Invalid => Self::InvalidActiveArtifacts,
                Failure::Read => Self::WrapperReadUnavailable,
                Failure::Size => Self::WrapperSizeInvalid,
                Failure::Unstable => Self::ActiveArtifactsUnstable,
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
    ) -> Result<File, Failure> {
        let encoded = encode_path(path)?;
        // SAFETY: the path is NUL-terminated and live for the synchronous call;
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
            return Err(Failure::Inspection);
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
        let handle = open(path, DIRECTORY_ACCESS, DIRECTORY_SHARE, DIRECTORY_FLAGS)?;
        let initial = query_observation(&handle)?;
        validate_directory(&initial)?;
        if let Some((parent, name)) = parent {
            exact_child(parent, &initial, name)?;
        }
        Ok(RetainedDirectory { handle, initial })
    }

    fn validate_contract(paths: &FreshnessAnchorPersistencePaths) -> Result<&Path, Failure> {
        let directory = paths.freshness_anchor_directory.as_path();
        let parent = directory.parent().ok_or(Failure::Invalid)?;
        if directory != parent.join(FRESHNESS_ANCHOR_DIRECTORY_NAME)
            || paths.active_anchor_authentication_key.as_path()
                != directory.join(ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME)
            || paths.active_authenticated_freshness_anchor.as_path()
                != directory.join(ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME)
        {
            return Err(Failure::Invalid);
        }
        Ok(parent)
    }

    fn enumerate_exact_pair(directory: &Path) -> Result<(), Failure> {
        let mut key_count = 0_u8;
        let mut anchor_count = 0_u8;
        for entry in fs::read_dir(directory).map_err(|_| Failure::Inspection)? {
            let name = entry.map_err(|_| Failure::Inspection)?.file_name();
            if name
                .encode_wide()
                .eq(ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME.encode_utf16())
            {
                key_count = key_count.saturating_add(1);
            } else if name
                .encode_wide()
                .eq(ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME.encode_utf16())
            {
                anchor_count = anchor_count.saturating_add(1);
            } else {
                return Err(Failure::Invalid);
            }
        }
        if key_count != 1 || anchor_count != 1 {
            return Err(Failure::Invalid);
        }
        Ok(())
    }

    fn load_file(
        path: &Path,
        expected_name: &str,
        directory: &RetainedDirectory,
    ) -> Result<LoadedFile, Failure> {
        if path.file_name() != Some(OsStr::new(expected_name)) {
            return Err(Failure::Invalid);
        }
        let mut handle = open(path, FILE_ACCESS, FILE_SHARE, FILE_FLAGS)?;
        let before = query_observation(&handle)?;
        validate_file(&before)?;
        exact_child(&directory.initial, &before, OsStr::new(expected_name))?;
        let bytes =
            read_bounded_wrapper(&mut handle, before.size).map_err(|error| match error {
                BoundedReadError::SizeInvalid => Failure::Size,
                BoundedReadError::ReadUnavailable => Failure::Read,
                BoundedReadError::Unstable => Failure::Unstable,
            })?;
        let after = query_observation(&handle)?;
        if before != after {
            return Err(Failure::Unstable);
        }
        let directory_after = query_observation(&directory.handle)?;
        if directory.initial != directory_after {
            return Err(Failure::Unstable);
        }
        Ok(LoadedFile {
            handle,
            observation: before,
            bytes,
        })
    }

    fn confirm_file(
        path: &Path,
        name: &str,
        loaded: &LoadedFile,
        directory: &RetainedDirectory,
    ) -> Result<(), Failure> {
        let original_after = query_observation(&loaded.handle)?;
        if original_after != loaded.observation {
            return Err(Failure::Unstable);
        }
        let reopened = open(path, FILE_ACCESS, FILE_SHARE, FILE_FLAGS)?;
        let reopened_observation = query_observation(&reopened)?;
        validate_file(&reopened_observation)?;
        exact_child(&directory.initial, &reopened_observation, OsStr::new(name))?;
        if reopened_observation != loaded.observation {
            return Err(Failure::Unstable);
        }
        Ok(())
    }

    #[cfg(test)]
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(super) enum LoadPhase {
        AfterKeyRead,
        AfterAnchorRead,
        BeforeFinalConfirmation,
    }

    fn load_inner_with_hook<F>(
        paths: &FreshnessAnchorPersistencePaths,
        mut hook: F,
    ) -> Result<LoadedActiveFreshnessAnchorWrapperPair, Failure>
    where
        F: FnMut(TestPhase),
    {
        let parent_path = validate_contract(paths)?;
        let directory_path = paths.freshness_anchor_directory.as_path();
        let parent = open_directory(parent_path, None)?;
        let directory = open_directory(
            directory_path,
            Some((&parent.initial, OsStr::new(FRESHNESS_ANCHOR_DIRECTORY_NAME))),
        )?;
        enumerate_exact_pair(directory_path)?;
        let key = load_file(
            paths.active_anchor_authentication_key.as_path(),
            ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME,
            &directory,
        )?;
        hook(TestPhase::AfterKeyRead);
        enumerate_exact_pair(directory_path)?;
        let anchor = load_file(
            paths.active_authenticated_freshness_anchor.as_path(),
            ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME,
            &directory,
        )?;
        hook(TestPhase::AfterAnchorRead);
        enumerate_exact_pair(directory_path)?;
        confirm_file(
            paths.active_anchor_authentication_key.as_path(),
            ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME,
            &key,
            &directory,
        )?;
        confirm_file(
            paths.active_authenticated_freshness_anchor.as_path(),
            ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME,
            &anchor,
            &directory,
        )?;
        if key.observation.identity == anchor.observation.identity {
            return Err(Failure::Invalid);
        }
        hook(TestPhase::BeforeFinalConfirmation);
        if query_observation(&parent.handle)? != parent.initial
            || query_observation(&directory.handle)? != directory.initial
        {
            return Err(Failure::Unstable);
        }
        let reopened_directory = open_directory(
            directory_path,
            Some((&parent.initial, OsStr::new(FRESHNESS_ANCHOR_DIRECTORY_NAME))),
        )?;
        if reopened_directory.initial != directory.initial {
            return Err(Failure::Unstable);
        }
        enumerate_exact_pair(directory_path)?;
        Ok(LoadedActiveFreshnessAnchorWrapperPair {
            key_wrapper: key.bytes,
            authenticated_anchor_wrapper: anchor.bytes,
        })
    }

    #[cfg(test)]
    type TestPhase = LoadPhase;
    #[cfg(not(test))]
    #[derive(Clone, Copy)]
    enum TestPhase {
        AfterKeyRead,
        AfterAnchorRead,
        BeforeFinalConfirmation,
    }

    fn load_inner(
        paths: &FreshnessAnchorPersistencePaths,
    ) -> Result<LoadedActiveFreshnessAnchorWrapperPair, Failure> {
        load_inner_with_hook(paths, |_| {})
    }

    #[cfg(test)]
    pub(super) fn load_with_test_hook<F>(
        paths: &FreshnessAnchorPersistencePaths,
        hook: F,
    ) -> Result<LoadedActiveFreshnessAnchorWrapperPair, FreshnessAnchorActiveWrapperLoadError>
    where
        F: FnMut(LoadPhase),
    {
        load_inner_with_hook(paths, hook).map_err(Into::into)
    }

    pub(super) fn load(
        paths: &FreshnessAnchorPersistencePaths,
    ) -> Result<LoadedActiveFreshnessAnchorWrapperPair, FreshnessAnchorActiveWrapperLoadError> {
        load_inner(paths).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        io::{self, Cursor, Read},
    };

    use super::*;

    fn pair(key: Vec<u8>, anchor: Vec<u8>) -> LoadedActiveFreshnessAnchorWrapperPair {
        LoadedActiveFreshnessAnchorWrapperPair {
            key_wrapper: FreshnessAnchorProtectedWrapperBytes(key),
            authenticated_anchor_wrapper: FreshnessAnchorProtectedWrapperBytes(anchor),
        }
    }

    #[test]
    fn owned_pair_is_ordered_and_fully_redacted() {
        let loaded = pair(vec![1; 15], vec![2; 16]);
        assert_eq!(loaded.key_wrapper_bytes(), &[1; 15]);
        assert_eq!(loaded.authenticated_anchor_wrapper_bytes(), &[2; 16]);
        assert_eq!(
            format!("{loaded:?}"),
            "LoadedActiveFreshnessAnchorWrapperPair([REDACTED])"
        );
        for error in [
            FreshnessAnchorActiveWrapperLoadError::PresenceNotComplete,
            FreshnessAnchorActiveWrapperLoadError::InspectionUnavailable,
            FreshnessAnchorActiveWrapperLoadError::InvalidActiveArtifacts,
            FreshnessAnchorActiveWrapperLoadError::WrapperReadUnavailable,
            FreshnessAnchorActiveWrapperLoadError::WrapperSizeInvalid,
            FreshnessAnchorActiveWrapperLoadError::ActiveArtifactsUnstable,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains('\\'));
            assert!(!debug.contains(".dpapi"));
            assert!(!debug.contains("0x"));
        }
        assert_eq!(
            format!("{:?}", loaded.key_wrapper),
            "FreshnessAnchorProtectedWrapperBytes([REDACTED])"
        );
    }

    #[test]
    fn non_complete_presence_never_invokes_loader() {
        for presence in [
            FreshnessAnchorActivePresence::Missing,
            FreshnessAnchorActivePresence::Unavailable,
            FreshnessAnchorActivePresence::Invalid,
        ] {
            let calls = Cell::new(0);
            let result = require_complete_presence(presence, || {
                calls.set(calls.get() + 1);
                Ok(())
            });
            assert_eq!(
                result,
                Err(FreshnessAnchorActiveWrapperLoadError::PresenceNotComplete)
            );
            assert_eq!(calls.get(), 0);
        }
        let calls = Cell::new(0);
        assert_eq!(
            require_complete_presence(FreshnessAnchorActivePresence::CompleteActivePair, || {
                calls.set(calls.get() + 1);
                Ok(7)
            }),
            Ok(7)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn bounded_reader_accepts_exact_limits_and_preserves_opaque_content() {
        for bytes in [vec![0xa5; 15], vec![0x5a; 65_550]] {
            let loaded =
                read_bounded_wrapper(&mut Cursor::new(bytes.clone()), bytes.len() as u64).unwrap();
            assert_eq!(loaded.as_bytes(), bytes);
        }
        let mut malformed_looking = b"CHDPAPI\0\xff\xffbad".to_vec();
        malformed_looking.resize(15, 0x7e);
        let loaded = read_bounded_wrapper(&mut Cursor::new(malformed_looking.clone()), 15).unwrap();
        assert_eq!(loaded.as_bytes(), malformed_looking);
    }

    #[test]
    fn bounded_reader_rejects_every_below_minimum_and_representative_oversize() {
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

    #[test]
    fn bounded_reader_rejects_truncation_and_growth() {
        assert_eq!(
            read_bounded_wrapper(&mut ShortReader, 15),
            Err(BoundedReadError::Unstable)
        );
        assert_eq!(
            read_bounded_wrapper(&mut Cursor::new(vec![3; 16]), 15),
            Err(BoundedReadError::Unstable)
        );
    }

    #[test]
    fn source_contract_has_private_owned_api_and_no_protocol_or_write_boundary() {
        const SOURCE: &str = include_str!("freshness_anchor_active_wrapper_loader.rs");
        let production = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        let owner = production
            .split("pub(crate) struct LoadedActiveFreshnessAnchorWrapperPair")
            .nth(1)
            .unwrap()
            .split("impl LoadedActiveFreshnessAnchorWrapperPair")
            .next()
            .unwrap();
        assert_eq!(
            owner
                .matches("FreshnessAnchorProtectedWrapperBytes")
                .count(),
            2
        );
        assert!(production.contains(
            "#[derive(Eq, PartialEq)]\npub(crate) struct LoadedActiveFreshnessAnchorWrapperPair"
        ));
        for forbidden in [
            "Serialize",
            "pub Vec",
            "into_vec",
            "ProtectedObjectKind",
            "ValidatedProtectedWrapper",
            "CryptUnprotectData",
            "Hmac",
            "AssuredFreshnessAnchor",
            "classifier",
            "ReplaceFileW",
            "MoveFileExW",
            "CreateDirectory",
            "remove_file",
            "write_all",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden boundary: {forbidden}"
            );
        }
        assert!(!owner.contains("derive(Clone"));
        assert!(!owner.contains("derive(Copy"));
        assert!(
            production.contains(
                "#[cfg(windows)]\npub(crate) fn load_active_freshness_anchor_wrapper_pair"
            )
        );
        assert!(!production.contains("#[cfg(not(windows))]"));
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
            freshness_anchor_presence::inspect_freshness_anchor_active_presence,
            storage_foundation::{
                ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME,
                ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME, freshness_anchor_persistence_paths,
            },
        };

        use super::*;

        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        struct Fixture {
            root: PathBuf,
            paths: crate::storage_foundation::FreshnessAnchorPersistencePaths,
        }
        impl Fixture {
            fn new(key: &[u8], anchor: &[u8]) -> Self {
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let root = std::env::temp_dir().join(format!(
                    "church-app-anchor-loader-{}-{nanos}-{id}",
                    std::process::id()
                ));
                fs::create_dir(&root).unwrap();
                let paths = freshness_anchor_persistence_paths(&root);
                fs::create_dir(paths.freshness_anchor_directory.as_path()).unwrap();
                fs::write(paths.active_anchor_authentication_key.as_path(), key).unwrap();
                fs::write(
                    paths.active_authenticated_freshness_anchor.as_path(),
                    anchor,
                )
                .unwrap();
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
        ) -> Result<LoadedActiveFreshnessAnchorWrapperPair, FreshnessAnchorActiveWrapperLoadError>
        {
            let presence = inspect_freshness_anchor_active_presence(&fixture.paths);
            load_active_freshness_anchor_wrapper_pair(&fixture.paths, presence)
        }

        #[test]
        fn exact_two_ordinary_opaque_files_load_at_both_limits() {
            let fixture = Fixture::new(&[0x13; 15], &[0x37; 65_550]);
            let loaded = load(&fixture).unwrap();
            assert_eq!(loaded.key_wrapper_bytes(), &[0x13; 15]);
            assert_eq!(loaded.authenticated_anchor_wrapper_bytes(), &[0x37; 65_550]);
        }

        #[test]
        fn malformed_and_wrong_kind_looking_contents_load_unchanged() {
            let mut key = b"CHDPAPI\0\x01\x04\0\0\0\x01x".to_vec();
            key.resize(31, 0xcc);
            let mut anchor = b"not-a-wrapper!!".to_vec();
            anchor.resize(15, 0xdd);
            let fixture = Fixture::new(&key, &anchor);
            let loaded = load(&fixture).unwrap();
            assert_eq!(loaded.key_wrapper_bytes(), key);
            assert_eq!(loaded.authenticated_anchor_wrapper_bytes(), anchor);
        }

        #[test]
        fn deterministic_random_contents_load_unchanged() {
            let mut state = 0x9e37_79b9_u32;
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            };
            let key: Vec<u8> = (0..257).map(|_| next()).collect();
            let anchor: Vec<u8> = (0..1021).map(|_| next()).collect();
            let fixture = Fixture::new(&key, &anchor);
            let loaded = load(&fixture).unwrap();
            assert_eq!(loaded.key_wrapper_bytes(), key);
            assert_eq!(loaded.authenticated_anchor_wrapper_bytes(), anchor);
        }

        #[test]
        fn invalid_sizes_return_no_pair() {
            for (key, anchor) in [
                (vec![], vec![1; 15]),
                (vec![1; 14], vec![2; 15]),
                (vec![1; 15], vec![2; 65_551]),
            ] {
                let fixture = Fixture::new(&key, &anchor);
                assert!(load(&fixture).is_err());
            }
        }

        #[test]
        fn directory_hard_link_and_unexpected_child_are_rejected() {
            let directory_fixture = Fixture::new(&[1; 15], &[2; 15]);
            fs::remove_file(
                directory_fixture
                    .paths
                    .active_anchor_authentication_key
                    .as_path(),
            )
            .unwrap();
            fs::create_dir(
                directory_fixture
                    .paths
                    .active_anchor_authentication_key
                    .as_path(),
            )
            .unwrap();
            assert!(load(&directory_fixture).is_err());

            let hard_link_fixture = Fixture::new(&[1; 15], &[2; 15]);
            let alias = hard_link_fixture.root.join("anchor-key-alias.synthetic");
            fs::hard_link(
                hard_link_fixture
                    .paths
                    .active_anchor_authentication_key
                    .as_path(),
                &alias,
            )
            .unwrap();
            assert!(load(&hard_link_fixture).is_err());

            let extra_fixture = Fixture::new(&[1; 15], &[2; 15]);
            fs::write(
                extra_fixture
                    .paths
                    .freshness_anchor_directory
                    .as_path()
                    .join("unexpected.synthetic"),
                b"synthetic",
            )
            .unwrap();
            assert!(load(&extra_fixture).is_err());
        }

        #[test]
        fn missing_second_file_never_returns_partial_pair() {
            let fixture = Fixture::new(&[1; 15], &[2; 15]);
            fs::remove_file(
                fixture
                    .paths
                    .active_authenticated_freshness_anchor
                    .as_path(),
            )
            .unwrap();
            let result = load_active_freshness_anchor_wrapper_pair(
                &fixture.paths,
                FreshnessAnchorActivePresence::CompleteActivePair,
            );
            assert!(result.is_err());
        }

        #[test]
        fn alternate_case_active_name_is_not_authoritative() {
            let fixture = Fixture::new(&[1; 15], &[2; 15]);
            let alternate = fixture
                .paths
                .freshness_anchor_directory
                .as_path()
                .join("ANCHOR-AUTHENTICATION-KEY.DPAPI");
            fs::rename(
                fixture.paths.active_anchor_authentication_key.as_path(),
                alternate,
            )
            .unwrap();
            assert!(load(&fixture).is_err());
            assert_eq!(
                ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME,
                "anchor-authentication-key.dpapi"
            );
            assert_eq!(
                ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME,
                "authenticated-freshness-anchor.dpapi"
            );
        }

        #[test]
        fn unexpected_child_appearing_after_either_read_returns_no_pair() {
            for phase_to_mutate in [
                crate::freshness_anchor_active_wrapper_loader::windows::LoadPhase::AfterKeyRead,
                crate::freshness_anchor_active_wrapper_loader::windows::LoadPhase::AfterAnchorRead,
            ] {
                let fixture = Fixture::new(&[1; 15], &[2; 15]);
                let unexpected = fixture
                    .paths
                    .freshness_anchor_directory
                    .as_path()
                    .join("appeared-during-load.synthetic");
                let result =
                    crate::freshness_anchor_active_wrapper_loader::windows::load_with_test_hook(
                        &fixture.paths,
                        |phase| {
                            if phase == phase_to_mutate {
                                fs::write(&unexpected, b"synthetic").unwrap();
                            }
                        },
                    );
                assert!(result.is_err());
            }
        }

        #[test]
        fn second_file_disappearance_is_rejected_and_replacement_never_returns_stale_pair() {
            let absent_fixture = Fixture::new(&[1; 15], &[2; 15]);
            let absent_anchor_path = absent_fixture
                .paths
                .active_authenticated_freshness_anchor
                .as_path()
                .to_path_buf();
            let absent_result =
                crate::freshness_anchor_active_wrapper_loader::windows::load_with_test_hook(
                    &absent_fixture.paths,
                    |phase| {
                        if phase == crate::freshness_anchor_active_wrapper_loader::windows::LoadPhase::AfterKeyRead {
                            fs::remove_file(&absent_anchor_path).unwrap();
                        }
                    },
                );
            assert!(absent_result.is_err());

            for (case, replacement) in [
                ("replacement-15", vec![9; 15]),
                ("replacement-16", vec![8; 16]),
            ] {
                let fixture = Fixture::new(&[1; 15], &[2; 15]);
                let anchor_path = fixture
                    .paths
                    .active_authenticated_freshness_anchor
                    .as_path()
                    .to_path_buf();
                let result =
                    crate::freshness_anchor_active_wrapper_loader::windows::load_with_test_hook(
                        &fixture.paths,
                        |phase| {
                            if phase == crate::freshness_anchor_active_wrapper_loader::windows::LoadPhase::AfterKeyRead {
                                fs::remove_file(&anchor_path).unwrap();
                                fs::write(&anchor_path, &replacement).unwrap();
                            }
                        },
                    );
                if let Ok(pair) = result {
                    assert_eq!(pair.key_wrapper_bytes(), &[1; 15], "{case}");
                    assert_eq!(
                        pair.authenticated_anchor_wrapper_bytes(),
                        replacement.as_slice(),
                        "{case}"
                    );
                    assert_ne!(
                        pair.authenticated_anchor_wrapper_bytes(),
                        &[2; 15],
                        "{case}"
                    );
                }
            }
        }

        #[test]
        fn retained_handles_block_loaded_file_swaps_and_directory_replacement() {
            let fixture = Fixture::new(&[1; 15], &[2; 15]);
            let key_path = fixture
                .paths
                .active_anchor_authentication_key
                .as_path()
                .to_path_buf();
            let displaced_key = fixture.root.join("loaded-key-displaced.synthetic");
            let displaced = fixture.root.join("freshness-anchor-displaced.synthetic");
            let blocked_file_change = Cell::new(false);
            let blocked_directory_change = Cell::new(false);
            let loaded = crate::freshness_anchor_active_wrapper_loader::windows::load_with_test_hook(
                &fixture.paths,
                |phase| {
                    if phase == crate::freshness_anchor_active_wrapper_loader::windows::LoadPhase::BeforeFinalConfirmation {
                        blocked_file_change.set(fs::rename(&key_path, &displaced_key).is_err());
                        blocked_directory_change.set(
                            fs::rename(
                                fixture.paths.freshness_anchor_directory.as_path(),
                                &displaced,
                            )
                            .is_err(),
                        );
                    }
                },
            )
            .unwrap();
            assert!(blocked_file_change.get());
            assert!(blocked_directory_change.get());
            assert_eq!(loaded.key_wrapper_bytes(), &[1; 15]);
            assert_eq!(loaded.authenticated_anchor_wrapper_bytes(), &[2; 15]);
        }

        #[test]
        fn reparse_active_file_is_rejected_when_symlink_creation_is_supported() {
            let fixture = Fixture::new(&[1; 15], &[2; 15]);
            let target = fixture.root.join("reparse-target.synthetic");
            fs::write(&target, [4; 15]).unwrap();
            fs::remove_file(fixture.paths.active_anchor_authentication_key.as_path()).unwrap();
            if std::os::windows::fs::symlink_file(
                &target,
                fixture.paths.active_anchor_authentication_key.as_path(),
            )
            .is_ok()
            {
                let result = load_active_freshness_anchor_wrapper_pair(
                    &fixture.paths,
                    FreshnessAnchorActivePresence::CompleteActivePair,
                );
                assert!(result.is_err());
            }
        }
    }
}
