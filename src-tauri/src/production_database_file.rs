//! Hardened filesystem-only inspection of the production database file.
//!
//! Success establishes only canonical, stable filesystem selection and
//! identity for the fixed production database path. It does not read database
//! bytes or establish SQLite validity, SQLCipher encryption, key correctness,
//! metadata validity, integrity, correspondence, freshness, startup safety,
//! lifecycle authority, or operational authorization.

#![cfg_attr(not(test), allow(dead_code))]

use std::{fmt, fs::File};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProductionDatabasePresence {
    Missing,
    Present,
    Unavailable,
    Invalid,
}

impl fmt::Debug for ProductionDatabasePresence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "Missing",
            Self::Present => "Present",
            Self::Unavailable => "Unavailable",
            Self::Invalid => "Invalid",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RetainedFileIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

pub(crate) struct InspectedProductionDatabaseFile {
    _retained_parent: File,
    _retained_file: File,
    _parent_identity: RetainedFileIdentity,
    _file_identity: RetainedFileIdentity,
}

impl fmt::Debug for InspectedProductionDatabaseFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InspectedProductionDatabaseFile([REDACTED])")
    }
}

pub(crate) enum ProductionDatabaseInspection {
    Missing,
    Present(InspectedProductionDatabaseFile),
    Unavailable,
    Invalid,
}

impl ProductionDatabaseInspection {
    pub(crate) const fn presence(&self) -> ProductionDatabasePresence {
        match self {
            Self::Missing => ProductionDatabasePresence::Missing,
            Self::Present(_) => ProductionDatabasePresence::Present,
            Self::Unavailable => ProductionDatabasePresence::Unavailable,
            Self::Invalid => ProductionDatabasePresence::Invalid,
        }
    }
}

impl fmt::Debug for ProductionDatabaseInspection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "Missing",
            Self::Present(_) => "Present([REDACTED])",
            Self::Unavailable => "Unavailable",
            Self::Invalid => "Invalid",
        })
    }
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
            ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
            FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES,
            FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_MODE,
            FILE_SHARE_READ, FILE_STANDARD_INFO, FILE_TYPE_DISK, FileAttributeTagInfo,
            FileBasicInfo, FileIdInfo, FileStandardInfo, GETFINALPATHNAMEBYHANDLE_FLAGS,
            GetDriveTypeW, GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileType,
            GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, OPEN_EXISTING,
            VOLUME_NAME_GUID,
        },
    };

    use crate::storage_foundation::{PRODUCTION_DATABASE_FILENAME, ProductionDatabasePath};

    use super::{
        InspectedProductionDatabaseFile, ProductionDatabaseInspection, RetainedFileIdentity,
    };

    const DIRECTORY_ACCESS: u32 = FILE_READ_ATTRIBUTES;
    const DIRECTORY_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ;
    const DIRECTORY_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    const FILE_ACCESS: u32 = FILE_READ_ATTRIBUTES;
    const FILE_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ;
    const FILE_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    const FINAL_PATH_FLAGS: GETFINALPATHNAMEBYHANDLE_FLAGS =
        FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;
    const MAXIMUM_FINAL_PATH_UNITS: usize = 32_767;
    const VOLUME_GUID_PREFIX_UNITS: usize = 49;
    const DOCUMENTED_FIXED_DRIVE_CATEGORY: u32 = 3;
    const FILESYSTEM_NAME_CAPACITY: usize = 32;
    const DISALLOWED_FILE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_REPARSE_POINT
        | FILE_ATTRIBUTE_SPARSE_FILE
        | FILE_ATTRIBUTE_OFFLINE
        | FILE_ATTRIBUTE_ENCRYPTED
        | FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

    #[derive(Clone, Eq, PartialEq)]
    struct Observation {
        identity: RetainedFileIdentity,
        allocation_size: u64,
        size: u64,
        attributes: u32,
        reparse_tag: u32,
        link_count: u32,
        delete_pending: bool,
        directory: bool,
        creation_time: i64,
        last_write_time: i64,
        change_time: i64,
        disk_entry: bool,
        final_path: Vec<u16>,
    }

    struct RetainedEntry {
        handle: File,
        initial: Observation,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum InspectionIssue {
        Unavailable,
        Invalid,
        Unstable,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum OpenIssue {
        Missing,
        Unavailable,
        Invalid,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct DirectoryNames {
        canonical_count: u8,
    }

    #[cfg(test)]
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(super) enum InspectionPhase {
        AfterFirstEnumeration,
        BeforeFinalConfirmation,
    }

    #[cfg(not(test))]
    #[derive(Clone, Copy)]
    enum InspectionPhase {
        AfterFirstEnumeration,
        BeforeFinalConfirmation,
    }

    fn checked_size(value: usize) -> Result<u32, InspectionIssue> {
        u32::try_from(value).map_err(|_| InspectionIssue::Unavailable)
    }

    fn encode_path(path: &Path) -> Result<Vec<u16>, OpenIssue> {
        let mut encoded = Vec::new();
        for unit in path.as_os_str().encode_wide() {
            if unit == 0 {
                return Err(OpenIssue::Invalid);
            }
            encoded.push(unit);
        }
        encoded.push(0);
        Ok(encoded)
    }

    fn open_entry(
        path: &Path,
        access: u32,
        share: FILE_SHARE_MODE,
        flags: FILE_FLAGS_AND_ATTRIBUTES,
    ) -> Result<File, OpenIssue> {
        let encoded = encode_path(path)?;
        // SAFETY: the path is NUL-terminated and remains live for this
        // synchronous call. Optional pointers are null and a successful fresh
        // handle is transferred to exactly one Rust owner.
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
                Err(OpenIssue::Missing)
            } else {
                Err(OpenIssue::Unavailable)
            };
        }
        // SAFETY: ownership of the successful fresh handle moves exactly once.
        let owned = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        Ok(File::from(owned))
    }

    fn query_final_path(file: &File) -> Result<Vec<u16>, InspectionIssue> {
        let handle = file.as_raw_handle() as HANDLE;
        // SAFETY: documented size query on a live handle.
        let required =
            unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, FINAL_PATH_FLAGS) };
        let capacity = usize::try_from(required).map_err(|_| InspectionIssue::Unavailable)?;
        if capacity == 0 || capacity > MAXIMUM_FINAL_PATH_UNITS {
            return Err(InspectionIssue::Unavailable);
        }
        let mut output = vec![0_u16; capacity];
        // SAFETY: output has exactly the checked writable capacity.
        let written = unsafe {
            GetFinalPathNameByHandleW(handle, output.as_mut_ptr(), required, FINAL_PATH_FLAGS)
        };
        let written = usize::try_from(written).map_err(|_| InspectionIssue::Unavailable)?;
        if written == 0 || written >= output.len() || written > MAXIMUM_FINAL_PATH_UNITS {
            return Err(InspectionIssue::Unavailable);
        }
        output.truncate(written);
        Ok(output)
    }

    fn query_observation(file: &File) -> Result<Observation, InspectionIssue> {
        let handle = file.as_raw_handle() as HANDLE;
        let disk_entry = unsafe { GetFileType(handle) } == FILE_TYPE_DISK;
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
            // SAFETY: each output pointer names initialized writable storage
            // matching its information class and checked size.
            if unsafe { GetFileInformationByHandleEx(handle, class, pointer, checked_size(size)?) }
                == 0
            {
                return Err(InspectionIssue::Unavailable);
            }
        }
        let mut legacy = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: initialized output is writable and the handle remains live.
        if unsafe { GetFileInformationByHandle(handle, &raw mut legacy) } == 0 {
            return Err(InspectionIssue::Unavailable);
        }
        Ok(Observation {
            identity: RetainedFileIdentity {
                volume_serial: identity.VolumeSerialNumber,
                file_id: identity.FileId.Identifier,
            },
            allocation_size: u64::try_from(standard.AllocationSize)
                .map_err(|_| InspectionIssue::Invalid)?,
            size: u64::try_from(standard.EndOfFile).map_err(|_| InspectionIssue::Invalid)?,
            attributes: attributes.FileAttributes,
            reparse_tag: attributes.ReparseTag,
            link_count: legacy.nNumberOfLinks,
            delete_pending: standard.DeletePending,
            directory: standard.Directory,
            creation_time: basic.CreationTime,
            last_write_time: basic.LastWriteTime,
            change_time: basic.ChangeTime,
            disk_entry,
            final_path: query_final_path(file)?,
        })
    }

    fn ascii_units(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn fold_ascii(unit: u16) -> u16 {
        if (b'A' as u16..=b'Z' as u16).contains(&unit) {
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

    fn volume_prefix(path: &[u16]) -> Result<&[u16], InspectionIssue> {
        let prefix = ascii_units(r"\\?\Volume{");
        if path.len() < VOLUME_GUID_PREFIX_UNITS
            || path.len() > MAXIMUM_FINAL_PATH_UNITS
            || path.contains(&0)
            || path.get(..prefix.len()) != Some(prefix.as_slice())
            || path[47] != b'}' as u16
            || path[48] != b'\\' as u16
        {
            return Err(InspectionIssue::Invalid);
        }
        for (offset, unit) in path[11..47].iter().copied().enumerate() {
            let valid = if matches!(offset, 8 | 13 | 18 | 23) {
                unit == b'-' as u16
            } else {
                is_ascii_hex(unit)
            };
            if !valid {
                return Err(InspectionIssue::Invalid);
            }
        }
        Ok(&path[..VOLUME_GUID_PREFIX_UNITS])
    }

    fn same_volume(left: &Observation, right: &Observation) -> Result<(), InspectionIssue> {
        let left_prefix = volume_prefix(&left.final_path)?;
        let right_prefix = volume_prefix(&right.final_path)?;
        if left.identity.volume_serial != right.identity.volume_serial
            || !left_prefix
                .iter()
                .zip(right_prefix)
                .all(|(left, right)| fold_ascii(*left) == fold_ascii(*right))
        {
            return Err(InspectionIssue::Invalid);
        }
        Ok(())
    }

    fn exact_child(
        parent: &Observation,
        child: &Observation,
        expected_name: &str,
    ) -> Result<(), InspectionIssue> {
        same_volume(parent, child)?;
        let mut expected = parent.final_path.clone();
        if expected.last() != Some(&(b'\\' as u16)) {
            expected.push(b'\\' as u16);
        }
        expected.extend(expected_name.encode_utf16());
        if expected.len() != child.final_path.len()
            || expected[..11] != child.final_path[..11]
            || expected[47..] != child.final_path[47..]
            || !expected[11..47]
                .iter()
                .zip(&child.final_path[11..47])
                .all(|(left, right)| fold_ascii(*left) == fold_ascii(*right))
        {
            return Err(InspectionIssue::Invalid);
        }
        Ok(())
    }

    fn validate_directory(observation: &Observation) -> Result<(), InspectionIssue> {
        if !observation.disk_entry
            || observation.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || observation.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || observation.reparse_tag != 0
            || !observation.directory
            || observation.delete_pending
        {
            return Err(InspectionIssue::Invalid);
        }
        volume_prefix(&observation.final_path)?;
        Ok(())
    }

    fn validate_file(observation: &Observation) -> Result<(), InspectionIssue> {
        if !observation.disk_entry
            || observation.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || observation.attributes & DISALLOWED_FILE_ATTRIBUTES != 0
            || observation.reparse_tag != 0
            || observation.directory
            || observation.delete_pending
            || observation.link_count != 1
        {
            return Err(InspectionIssue::Invalid);
        }
        Ok(())
    }

    fn open_retained_directory(path: &Path) -> Result<RetainedEntry, InspectionIssue> {
        let handle = open_entry(path, DIRECTORY_ACCESS, DIRECTORY_SHARE, DIRECTORY_FLAGS).map_err(
            |issue| match issue {
                OpenIssue::Invalid => InspectionIssue::Invalid,
                OpenIssue::Missing | OpenIssue::Unavailable => InspectionIssue::Unavailable,
            },
        )?;
        let initial = query_observation(&handle)?;
        validate_directory(&initial)?;
        Ok(RetainedEntry { handle, initial })
    }

    fn validate_local_ntfs(parent: &RetainedEntry) -> Result<(), InspectionIssue> {
        let prefix = volume_prefix(&parent.initial.final_path)?;
        let mut root = prefix.to_vec();
        root.push(0);
        // SAFETY: root is the validated NUL-terminated volume-GUID root.
        let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
        if drive_type == 0 || drive_type == 1 {
            return Err(InspectionIssue::Unavailable);
        }
        if drive_type != DOCUMENTED_FIXED_DRIVE_CATEGORY {
            return Err(InspectionIssue::Invalid);
        }

        let mut filesystem_name = [0_u16; FILESYSTEM_NAME_CAPACITY];
        // SAFETY: the retained parent handle is live; optional outputs are
        // null; filesystem_name is writable for its checked fixed capacity.
        if unsafe {
            GetVolumeInformationByHandleW(
                parent.handle.as_raw_handle() as HANDLE,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                filesystem_name.as_mut_ptr(),
                FILESYSTEM_NAME_CAPACITY as u32,
            )
        } == 0
        {
            return Err(InspectionIssue::Unavailable);
        }
        let length = filesystem_name
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(InspectionIssue::Unavailable)?;
        let expected: Vec<u16> = "NTFS".encode_utf16().collect();
        if filesystem_name[..length].len() != expected.len()
            || !filesystem_name[..length]
                .iter()
                .zip(expected)
                .all(|(left, right)| fold_ascii(*left) == fold_ascii(right))
        {
            return Err(InspectionIssue::Invalid);
        }
        Ok(())
    }

    fn exact_name(name: &OsStr, expected: &str) -> bool {
        name.encode_wide().eq(expected.encode_utf16())
    }

    fn ascii_case_insensitive_prefix(name: &OsStr, prefix: &str) -> bool {
        let units: Vec<u16> = name.encode_wide().collect();
        let prefix: Vec<u16> = prefix.encode_utf16().collect();
        units.len() >= prefix.len()
            && units
                .iter()
                .take(prefix.len())
                .zip(prefix)
                .all(|(left, right)| fold_ascii(*left) == fold_ascii(right))
    }

    fn enumerate_database_names(parent: &Path) -> Result<DirectoryNames, InspectionIssue> {
        let mut canonical_count = 0_u8;
        for entry in fs::read_dir(parent).map_err(|_| InspectionIssue::Unavailable)? {
            let name = entry.map_err(|_| InspectionIssue::Unavailable)?.file_name();
            if exact_name(&name, PRODUCTION_DATABASE_FILENAME) {
                canonical_count = canonical_count.saturating_add(1);
            } else if ascii_case_insensitive_prefix(&name, PRODUCTION_DATABASE_FILENAME) {
                return Err(InspectionIssue::Invalid);
            }
        }
        if canonical_count > 1 {
            return Err(InspectionIssue::Invalid);
        }
        Ok(DirectoryNames { canonical_count })
    }

    fn validate_path_contract(path: &ProductionDatabasePath) -> Result<&Path, InspectionIssue> {
        let database = path.as_path();
        let parent = database.parent().ok_or(InspectionIssue::Invalid)?;
        if database != parent.join(PRODUCTION_DATABASE_FILENAME)
            || database.file_name() != Some(OsStr::new(PRODUCTION_DATABASE_FILENAME))
        {
            return Err(InspectionIssue::Invalid);
        }
        Ok(parent)
    }

    fn map_issue(issue: InspectionIssue) -> ProductionDatabaseInspection {
        match issue {
            InspectionIssue::Unavailable => ProductionDatabaseInspection::Unavailable,
            InspectionIssue::Invalid | InspectionIssue::Unstable => {
                ProductionDatabaseInspection::Invalid
            }
        }
    }

    fn stable_entry(entry: &RetainedEntry) -> Result<(), InspectionIssue> {
        if query_observation(&entry.handle)? != entry.initial {
            return Err(InspectionIssue::Unstable);
        }
        Ok(())
    }

    fn reopen_and_confirm(
        path: &Path,
        retained: &RetainedEntry,
        directory: bool,
    ) -> Result<(), InspectionIssue> {
        let reopened = open_entry(
            path,
            if directory {
                DIRECTORY_ACCESS
            } else {
                FILE_ACCESS
            },
            if directory {
                DIRECTORY_SHARE
            } else {
                FILE_SHARE
            },
            if directory {
                DIRECTORY_FLAGS
            } else {
                FILE_FLAGS
            },
        )
        .map_err(|issue| match issue {
            OpenIssue::Invalid => InspectionIssue::Invalid,
            OpenIssue::Missing => InspectionIssue::Unstable,
            OpenIssue::Unavailable => InspectionIssue::Unavailable,
        })?;
        let observation = query_observation(&reopened)?;
        if directory {
            validate_directory(&observation)?;
        } else {
            validate_file(&observation)?;
        }
        if observation != retained.initial {
            return Err(InspectionIssue::Unstable);
        }
        Ok(())
    }

    fn inspect_with_hook<F>(
        path: &ProductionDatabasePath,
        mut hook: F,
    ) -> ProductionDatabaseInspection
    where
        F: FnMut(InspectionPhase),
    {
        let parent_path = match validate_path_contract(path) {
            Ok(parent) => parent,
            Err(issue) => return map_issue(issue),
        };
        let parent = match open_retained_directory(parent_path) {
            Ok(parent) => parent,
            Err(issue) => return map_issue(issue),
        };
        if let Err(issue) = validate_local_ntfs(&parent) {
            return map_issue(issue);
        }

        let first_names = match enumerate_database_names(parent_path) {
            Ok(names) => names,
            Err(issue) => return map_issue(issue),
        };
        hook(InspectionPhase::AfterFirstEnumeration);

        if first_names.canonical_count == 0 {
            let second_names = match enumerate_database_names(parent_path) {
                Ok(names) => names,
                Err(issue) => return map_issue(issue),
            };
            if second_names != first_names {
                return ProductionDatabaseInspection::Invalid;
            }
            if let Err(issue) = stable_entry(&parent) {
                return map_issue(issue);
            }
            if let Err(issue) = reopen_and_confirm(parent_path, &parent, true) {
                return map_issue(issue);
            }
            return ProductionDatabaseInspection::Missing;
        }

        let file_handle = match open_entry(path.as_path(), FILE_ACCESS, FILE_SHARE, FILE_FLAGS) {
            Ok(file) => file,
            Err(OpenIssue::Invalid) => return ProductionDatabaseInspection::Invalid,
            Err(OpenIssue::Missing) => return ProductionDatabaseInspection::Invalid,
            Err(OpenIssue::Unavailable) => return ProductionDatabaseInspection::Unavailable,
        };
        let file_initial = match query_observation(&file_handle) {
            Ok(observation) => observation,
            Err(issue) => return map_issue(issue),
        };
        if let Err(issue) = validate_file(&file_initial)
            .and_then(|_| exact_child(&parent.initial, &file_initial, PRODUCTION_DATABASE_FILENAME))
        {
            return map_issue(issue);
        }
        let file = RetainedEntry {
            handle: file_handle,
            initial: file_initial,
        };

        let second_names = match enumerate_database_names(parent_path) {
            Ok(names) => names,
            Err(issue) => return map_issue(issue),
        };
        if second_names != first_names {
            return ProductionDatabaseInspection::Invalid;
        }
        hook(InspectionPhase::BeforeFinalConfirmation);

        let confirmation = stable_entry(&parent)
            .and_then(|_| stable_entry(&file))
            .and_then(|_| reopen_and_confirm(parent_path, &parent, true))
            .and_then(|_| reopen_and_confirm(path.as_path(), &file, false))
            .and_then(|_| {
                let final_names = enumerate_database_names(parent_path)?;
                if final_names != first_names {
                    return Err(InspectionIssue::Unstable);
                }
                exact_child(&parent.initial, &file.initial, PRODUCTION_DATABASE_FILENAME)
            });
        if let Err(issue) = confirmation {
            return map_issue(issue);
        }

        ProductionDatabaseInspection::Present(InspectedProductionDatabaseFile {
            _parent_identity: parent.initial.identity,
            _file_identity: file.initial.identity,
            _retained_parent: parent.handle,
            _retained_file: file.handle,
        })
    }

    pub(super) fn inspect(path: &ProductionDatabasePath) -> ProductionDatabaseInspection {
        inspect_with_hook(path, |_| {})
    }

    #[cfg(test)]
    pub(super) fn inspect_with_test_hook<F>(
        path: &ProductionDatabasePath,
        hook: F,
    ) -> ProductionDatabaseInspection
    where
        F: FnMut(InspectionPhase),
    {
        inspect_with_hook(path, hook)
    }

    #[cfg(test)]
    pub(super) fn synthetic_validation(
        attributes: u32,
        reparse_tag: u32,
        link_count: u32,
        delete_pending: bool,
        directory: bool,
        disk_entry: bool,
    ) -> bool {
        let observation = Observation {
            identity: RetainedFileIdentity {
                volume_serial: 1,
                file_id: [1; 16],
            },
            allocation_size: 0,
            size: 0,
            attributes,
            reparse_tag,
            link_count,
            delete_pending,
            directory,
            creation_time: 0,
            last_write_time: 0,
            change_time: 0,
            disk_entry,
            final_path: Vec::new(),
        };
        validate_file(&observation).is_ok()
    }

    #[cfg(test)]
    pub(super) fn synthetic_required_failure_presence() -> super::ProductionDatabasePresence {
        map_issue(InspectionIssue::Unavailable).presence()
    }

    #[cfg(test)]
    pub(super) fn synthetic_unstable_presence() -> super::ProductionDatabasePresence {
        map_issue(InspectionIssue::Unstable).presence()
    }

    #[cfg(test)]
    pub(super) fn synthetic_file_open_presence(
        missing_after_enumeration: bool,
    ) -> super::ProductionDatabasePresence {
        if missing_after_enumeration {
            super::ProductionDatabasePresence::Invalid
        } else {
            super::ProductionDatabasePresence::Unavailable
        }
    }

    #[cfg(test)]
    pub(super) fn synthetic_non_ntfs_presence() -> super::ProductionDatabasePresence {
        map_issue(InspectionIssue::Invalid).presence()
    }
}

#[cfg(windows)]
pub(crate) fn inspect_production_database_file(
    path: &crate::storage_foundation::ProductionDatabasePath,
) -> ProductionDatabaseInspection {
    windows::inspect(path)
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        fs,
        mem::{needs_drop, size_of},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::storage_foundation::{
        PRODUCTION_DATABASE_FILENAME, production_database_path,
        production_database_path_from_synthetic_value,
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn create() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "church-app-production-database-file-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("synthetic root creation should succeed");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn database_path(&self) -> crate::storage_foundation::ProductionDatabasePath {
            production_database_path(self.0.clone())
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn production_presence_vocabulary_and_debug_are_exact() {
        for (value, expected) in [
            (ProductionDatabasePresence::Missing, "Missing"),
            (ProductionDatabasePresence::Present, "Present"),
            (ProductionDatabasePresence::Unavailable, "Unavailable"),
            (ProductionDatabasePresence::Invalid, "Invalid"),
        ] {
            assert_eq!(format!("{value:?}"), expected);
        }
    }

    #[test]
    fn proof_is_owned_sealed_and_redacted() {
        assert!(needs_drop::<InspectedProductionDatabaseFile>());
        assert!(size_of::<InspectedProductionDatabaseFile>() > size_of::<File>());
        const SOURCE: &str = include_str!("production_database_file.rs");
        let production = SOURCE
            .split("#[cfg(all(test, windows))]\nmod tests")
            .next()
            .unwrap();
        let proof = production
            .split_once("pub(crate) struct InspectedProductionDatabaseFile {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(!proof.contains("pub"));
        assert!(!production.contains("impl Clone for InspectedProductionDatabaseFile"));
        assert!(!production.contains("impl Copy for InspectedProductionDatabaseFile"));
        for forbidden in [
            "fn as_path",
            "fn path(",
            "fn handle(",
            "fn file(",
            "fn bytes(",
            "fn read(",
            "Deref",
            "AsRef",
            "Serialize",
            "Deserialize",
        ] {
            assert!(!production.contains(forbidden));
        }
    }

    #[test]
    fn source_boundary_excludes_database_content_and_later_authorities() {
        const SOURCE: &str = include_str!("production_database_file.rs");
        let production = SOURCE
            .split("#[cfg(all(test, windows))]\nmod tests")
            .next()
            .unwrap();
        for forbidden in [
            ["std", "::io::Read"].concat(),
            ["read", "_to_end"].concat(),
            ["read", "_exact"].concat(),
            ["rusq", "lite"].concat(),
            ["sql", "cipher"].concat(),
            ["GenerationBound", "DatabaseKey"].concat(),
            ["database", "_metadata"].concat(),
            ["std", "::fs::write"].concat(),
            ["File", "::create"].concat(),
            ["OpenOptions", "::new"].concat(),
            ["remove", "_file"].concat(),
            ["rename", "("].concat(),
            ["ReplaceFile", "W"].concat(),
            ["MoveFile", "ExW"].concat(),
            ["tauri", "::command"].concat(),
        ] {
            assert!(!production.contains(&forbidden));
        }
    }

    #[test]
    fn typed_path_tampering_is_invalid() {
        let root = TestRoot::create();
        let tampered = production_database_path_from_synthetic_value(
            root.path().join("alternate-production-name.db"),
        );
        assert_eq!(
            inspect_production_database_file(&tampered).presence(),
            ProductionDatabasePresence::Invalid
        );
    }

    #[test]
    fn absent_database_is_missing_without_creating_any_artifact() {
        let root = TestRoot::create();
        for name in [
            "installation-evidence",
            "freshness-anchor",
            "database-key",
            "restore-staging",
            "unrelated.synthetic",
        ] {
            fs::create_dir(root.path().join(name)).unwrap();
        }
        let path = root.database_path();
        assert_eq!(
            inspect_production_database_file(&path).presence(),
            ProductionDatabasePresence::Missing
        );
        assert!(!path.as_path().exists());
        for suffix in ["-journal", "-wal", "-shm"] {
            assert!(
                !root
                    .path()
                    .join(format!("{PRODUCTION_DATABASE_FILENAME}{suffix}"))
                    .exists()
            );
        }
    }

    #[test]
    fn absent_parent_is_unavailable() {
        let root = TestRoot::create();
        let absent_parent = root.path().join("absent-application-local-data");
        let path = production_database_path(absent_parent.clone());

        assert_eq!(
            inspect_production_database_file(&path).presence(),
            ProductionDatabasePresence::Unavailable
        );
        assert!(!absent_parent.exists());
    }

    #[test]
    fn stable_zero_and_arbitrary_content_files_are_present_without_content_reading() {
        for contents in [&[][..], &[0xde, 0xad, 0xbe, 0xef][..]] {
            let root = TestRoot::create();
            fs::write(root.path().join(PRODUCTION_DATABASE_FILENAME), contents).unwrap();
            fs::create_dir(root.path().join("installation-evidence")).unwrap();
            fs::write(root.path().join("unrelated.synthetic"), b"unrelated").unwrap();
            let inspection = inspect_production_database_file(&root.database_path());
            assert_eq!(inspection.presence(), ProductionDatabasePresence::Present);
            assert_eq!(format!("{inspection:?}"), "Present([REDACTED])");
            let ProductionDatabaseInspection::Present(proof) = inspection else {
                panic!("stable synthetic file should produce a proof");
            };
            assert_eq!(
                format!("{proof:?}"),
                "InspectedProductionDatabaseFile([REDACTED])"
            );
        }
    }

    #[test]
    fn repeated_stable_inspection_remains_present() {
        let root = TestRoot::create();
        fs::write(root.path().join(PRODUCTION_DATABASE_FILENAME), b"synthetic").unwrap();

        assert_eq!(
            inspect_production_database_file(&root.database_path()).presence(),
            ProductionDatabasePresence::Present
        );
        assert_eq!(
            inspect_production_database_file(&root.database_path()).presence(),
            ProductionDatabasePresence::Present
        );
    }

    #[test]
    fn reserved_sidecars_and_suspicious_prefixes_are_invalid() {
        for name in [
            "parish-data.db-journal",
            "parish-data.db-wal",
            "parish-data.db-shm",
            "PARISH-DATA.DB-JOURNAL",
            "Parish-Data.Db-Wal",
            "PARISH-DATA.DB-SHM",
            "parish-data.db.tmp",
            "parish-data.db.backup",
            "parish-data.db.stage",
            "parish-data.db-old",
            "PARISH-DATA.DB.tmp",
            "PARISH-DATA.DB",
        ] {
            let root = TestRoot::create();
            fs::write(root.path().join(name), b"synthetic").unwrap();
            assert_eq!(
                inspect_production_database_file(&root.database_path()).presence(),
                ProductionDatabasePresence::Invalid,
                "reserved or suspicious name should be invalid"
            );
        }
    }

    #[test]
    fn canonical_file_plus_every_reserved_sidecar_is_invalid() {
        for suffix in ["-journal", "-wal", "-shm"] {
            let root = TestRoot::create();
            fs::write(root.path().join(PRODUCTION_DATABASE_FILENAME), b"synthetic").unwrap();
            fs::write(
                root.path()
                    .join(format!("{PRODUCTION_DATABASE_FILENAME}{suffix}")),
                b"synthetic",
            )
            .unwrap();
            assert_eq!(
                inspect_production_database_file(&root.database_path()).presence(),
                ProductionDatabasePresence::Invalid
            );
        }
    }

    #[test]
    fn canonical_path_occupied_by_directory_is_invalid() {
        let root = TestRoot::create();
        fs::create_dir(root.path().join(PRODUCTION_DATABASE_FILENAME)).unwrap();
        assert_eq!(
            inspect_production_database_file(&root.database_path()).presence(),
            ProductionDatabasePresence::Invalid
        );
    }

    #[test]
    fn hard_linked_database_is_invalid() {
        let root = TestRoot::create();
        let database = root.path().join(PRODUCTION_DATABASE_FILENAME);
        fs::write(&database, b"synthetic").unwrap();
        fs::hard_link(&database, root.path().join("unrelated-hard-link.synthetic")).unwrap();
        assert_eq!(
            inspect_production_database_file(&root.database_path()).presence(),
            ProductionDatabasePresence::Invalid
        );
    }

    #[test]
    fn injected_file_facts_reject_every_locked_unsafe_property() {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_OFFLINE,
            FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE,
        };

        assert!(windows::synthetic_validation(0, 0, 1, false, false, true));
        for attributes in [
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_ATTRIBUTE_SPARSE_FILE,
            FILE_ATTRIBUTE_OFFLINE,
            FILE_ATTRIBUTE_ENCRYPTED,
            FILE_ATTRIBUTE_RECALL_ON_OPEN,
            FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        ] {
            assert!(!windows::synthetic_validation(
                attributes, 0, 1, false, false, true
            ));
        }
        assert!(!windows::synthetic_validation(
            FILE_ATTRIBUTE_REPARSE_POINT,
            0xa000_000c,
            1,
            false,
            false,
            true
        ));
        assert!(!windows::synthetic_validation(0, 0, 2, false, false, true));
        assert!(!windows::synthetic_validation(0, 0, 1, true, false, true));
        assert!(!windows::synthetic_validation(0, 0, 1, false, true, true));
        assert!(!windows::synthetic_validation(0, 0, 1, false, false, false));
        assert_eq!(
            windows::synthetic_non_ntfs_presence(),
            ProductionDatabasePresence::Invalid
        );
    }

    #[test]
    fn required_inspection_failures_are_unavailable_and_proven_mutations_are_invalid() {
        for _failure in [
            "parent-inspection",
            "directory-enumeration",
            "file-open-not-proving-absence",
            "metadata-query",
            "filesystem-name-query",
            "volume-query",
            "final-path-query",
        ] {
            assert_eq!(
                windows::synthetic_required_failure_presence(),
                ProductionDatabasePresence::Unavailable
            );
        }
        for _mutation in [
            "file-replacement",
            "parent-replacement",
            "identity-mismatch",
            "link-count-change",
        ] {
            assert_eq!(
                windows::synthetic_unstable_presence(),
                ProductionDatabasePresence::Invalid
            );
        }
        assert_eq!(
            windows::synthetic_file_open_presence(true),
            ProductionDatabasePresence::Invalid
        );
        assert_eq!(
            windows::synthetic_file_open_presence(false),
            ProductionDatabasePresence::Unavailable
        );
    }

    #[test]
    fn sidecar_appearing_between_observations_is_invalid() {
        let root = TestRoot::create();
        let sidecar = root.path().join("parish-data.db-wal");
        let inspection = windows::inspect_with_test_hook(&root.database_path(), |phase| {
            if phase == windows::InspectionPhase::AfterFirstEnumeration && !sidecar.exists() {
                fs::write(&sidecar, b"synthetic").unwrap();
            }
        });
        assert_eq!(inspection.presence(), ProductionDatabasePresence::Invalid);
    }

    #[test]
    fn present_proof_retains_parent_and_file_handles_and_identities() {
        use std::os::windows::io::AsRawHandle;

        let root = TestRoot::create();
        fs::write(root.path().join(PRODUCTION_DATABASE_FILENAME), b"synthetic").unwrap();
        let inspection = inspect_production_database_file(&root.database_path());
        let ProductionDatabaseInspection::Present(proof) = inspection else {
            panic!("stable file should produce retained proof");
        };
        assert!(!proof._retained_parent.as_raw_handle().is_null());
        assert!(!proof._retained_file.as_raw_handle().is_null());
        assert_ne!(proof._parent_identity.file_id, [0; 16]);
        assert_ne!(proof._file_identity.file_id, [0; 16]);
    }

    #[test]
    fn production_surface_contains_no_rusqlite_or_content_read_capability() {
        const SOURCE: &str = include_str!("production_database_file.rs");
        const CARGO: &str = include_str!("../Cargo.toml");
        const LIB: &str = include_str!("lib.rs");
        const WINDOWS_DEPENDENCIES: &str = "[target.'cfg(windows)'.dependencies]";
        const WINDOWS_DEV_DEPENDENCIES: &str = "[target.'cfg(windows)'.dev-dependencies]";
        const RUSQLITE_DECLARATION: &str = "rusqlite = { version = \"=0.39.0\", default-features = false, features = [\"bundled-sqlcipher-vendored-openssl\"] }";
        assert_eq!(LIB.matches("mod production_database_file;").count(), 1);
        assert!(!LIB.contains("pub mod production_database_file"));
        assert_eq!(
            CARGO
                .matches(&[WINDOWS_DEPENDENCIES, RUSQLITE_DECLARATION].join("\n"))
                .count(),
            1
        );
        assert_eq!(CARGO.matches("rusqlite").count(), 1);
        let windows_dev_dependencies = CARGO
            .split_once(WINDOWS_DEV_DEPENDENCIES)
            .map(|(_, remainder)| remainder.split("\n[").next().unwrap_or(remainder))
            .unwrap_or_default();
        assert!(!windows_dev_dependencies.contains("rusqlite"));
        assert!(!CARGO.contains("libsqlite3-sys"));
        assert!(!SOURCE.contains(&["use rusq", "lite"].concat()));
        assert!(!SOURCE.contains(&["std::io::", "Read"].concat()));
    }
}
