//! Windows-only installation-evidence filesystem boundary.
//!
//! Production compilation includes only private read-hardening primitives for
//! already-supplied paths. They have no production caller. Filesystem mutation,
//! publication, replacement, cleanup, and host-classification behavior remains
//! compiler-gated to tests beneath unique test-owned temporary roots.

#![allow(dead_code)]

use std::{
    ffi::OsStr,
    ffi::c_void,
    fmt,
    fs::File,
    os::windows::ffi::OsStrExt,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    path::Path,
};

use windows_sys::{
    Win32::{
        Foundation::{
            GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WIN32_ERROR,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
            FILE_CREATION_DISPOSITION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_FLAGS_AND_ATTRIBUTES, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS,
            FILE_NAME_NORMALIZED, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FILE_STANDARD_INFO, FILE_TYPE, FILE_TYPE_DISK, FileAttributeTagInfo, FileIdInfo,
            FileStandardInfo, FlushFileBuffers, GETFINALPATHNAMEBYHANDLE_FLAGS, GetDriveTypeW,
            GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileType,
            GetFinalPathNameByHandleW, GetVolumePathNameW, MOVE_FILE_FLAGS, MOVEFILE_COPY_ALLOWED,
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_EXISTING,
            REPLACE_FILE_FLAGS, ReplaceFileW, VOLUME_NAME_GUID,
        },
    },
    core::{BOOL, PCWSTR, PWSTR},
};

use crate::{
    installation_evidence_protection::EncodedProtectedWrapper,
    storage_foundation::{
        ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME, ACTIVE_AUTHENTICATION_KEY_FILENAME,
        INSTALLATION_EVIDENCE_DIRECTORY_NAME, InstallationEvidencePersistencePaths,
        PRODUCTION_DATABASE_FILENAME,
    },
};

use super::{
    BoundedReadError, MAXIMUM_PROTECTED_WRAPPER_LENGTH, MINIMUM_PROTECTED_WRAPPER_LENGTH,
    ProtectedWrapperBytes, read_bounded_protected_wrapper,
};

type CreateFileWBinding = unsafe extern "system" fn(
    PCWSTR,
    u32,
    FILE_SHARE_MODE,
    *const SECURITY_ATTRIBUTES,
    FILE_CREATION_DISPOSITION,
    FILE_FLAGS_AND_ATTRIBUTES,
    HANDLE,
) -> HANDLE;
type FlushFileBuffersBinding = unsafe extern "system" fn(HANDLE) -> BOOL;
type GetFileInformationByHandleBinding =
    unsafe extern "system" fn(HANDLE, *mut BY_HANDLE_FILE_INFORMATION) -> BOOL;
type GetFileInformationByHandleExBinding =
    unsafe extern "system" fn(HANDLE, FILE_INFO_BY_HANDLE_CLASS, *mut c_void, u32) -> BOOL;
type GetFinalPathNameByHandleWBinding =
    unsafe extern "system" fn(HANDLE, PWSTR, u32, GETFINALPATHNAMEBYHANDLE_FLAGS) -> u32;
type GetFileTypeBinding = unsafe extern "system" fn(HANDLE) -> FILE_TYPE;
type GetVolumePathNameWBinding = unsafe extern "system" fn(PCWSTR, PWSTR, u32) -> BOOL;
type GetDriveTypeWBinding = unsafe extern "system" fn(PCWSTR) -> u32;
type MoveFileExWBinding = unsafe extern "system" fn(PCWSTR, PCWSTR, MOVE_FILE_FLAGS) -> BOOL;
type ReplaceFileWBinding = unsafe extern "system" fn(
    PCWSTR,
    PCWSTR,
    PCWSTR,
    REPLACE_FILE_FLAGS,
    *const c_void,
    *const c_void,
) -> BOOL;
type GetLastErrorBinding = unsafe extern "system" fn() -> WIN32_ERROR;

const CREATE_FILE_W_BINDING: CreateFileWBinding = CreateFileW;
const FLUSH_FILE_BUFFERS_BINDING: FlushFileBuffersBinding = FlushFileBuffers;
const GET_FILE_INFORMATION_BY_HANDLE_BINDING: GetFileInformationByHandleBinding =
    GetFileInformationByHandle;
const GET_FILE_INFORMATION_BY_HANDLE_EX_BINDING: GetFileInformationByHandleExBinding =
    GetFileInformationByHandleEx;
const GET_FINAL_PATH_NAME_BY_HANDLE_W_BINDING: GetFinalPathNameByHandleWBinding =
    GetFinalPathNameByHandleW;
const GET_FILE_TYPE_BINDING: GetFileTypeBinding = GetFileType;
const GET_VOLUME_PATH_NAME_W_BINDING: GetVolumePathNameWBinding = GetVolumePathNameW;
const GET_DRIVE_TYPE_W_BINDING: GetDriveTypeWBinding = GetDriveTypeW;
const MOVE_FILE_EX_W_BINDING: MoveFileExWBinding = MoveFileExW;
const REPLACE_FILE_W_BINDING: ReplaceFileWBinding = ReplaceFileW;
const GET_LAST_ERROR_BINDING: GetLastErrorBinding = GetLastError;

type OwnedHandleFromRawBinding = unsafe fn(RawHandle) -> OwnedHandle;
type OwnedHandleAsRawBinding = fn(&OwnedHandle) -> RawHandle;
type OwnedHandleIntoFileBinding = fn(OwnedHandle) -> File;

const OWNED_HANDLE_FROM_RAW_BINDING: OwnedHandleFromRawBinding =
    <OwnedHandle as FromRawHandle>::from_raw_handle;
const OWNED_HANDLE_AS_RAW_BINDING: OwnedHandleAsRawBinding =
    <OwnedHandle as AsRawHandle>::as_raw_handle;
const OWNED_HANDLE_INTO_FILE_BINDING: OwnedHandleIntoFileBinding = File::from;

type NullTerminatedUtf16Input = PCWSTR;
type MutableUtf16Output = PWSTR;
type StandardFileInformation = FILE_STANDARD_INFO;
type AttributeTagFileInformation = FILE_ATTRIBUTE_TAG_INFO;
type FileIdFileInformation = FILE_ID_INFO;

const NULL_CREATE_SECURITY_ATTRIBUTES: *const SECURITY_ATTRIBUTES = std::ptr::null();
const NULL_CREATE_TEMPLATE_HANDLE: HANDLE = std::ptr::null_mut();
const NULL_REPLACE_BACKUP_PATH: PCWSTR = std::ptr::null();
const NULL_REPLACE_EXCLUDE_CONTEXT: *const c_void = std::ptr::null();
const NULL_REPLACE_RESERVED_CONTEXT: *const c_void = std::ptr::null();
const INVALID_HANDLE_SENTINEL: HANDLE = INVALID_HANDLE_VALUE;
const DIRECTORY_ATTRIBUTE: FILE_FLAGS_AND_ATTRIBUTES = FILE_ATTRIBUTE_DIRECTORY;
const REPARSE_POINT_ATTRIBUTE: FILE_FLAGS_AND_ATTRIBUTES = FILE_ATTRIBUTE_REPARSE_POINT;
const DISK_FILE_TYPE: FILE_TYPE = FILE_TYPE_DISK;
const FORBIDDEN_INITIAL_PUBLICATION_FLAGS: MOVE_FILE_FLAGS =
    MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED;

const ACTIVE_READ_ACCESS: u32 = GENERIC_READ;
const ACTIVE_READ_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ;
const ACTIVE_READ_DISPOSITION: FILE_CREATION_DISPOSITION = OPEN_EXISTING;
const ACTIVE_READ_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;

const STAGE_CREATE_ACCESS: u32 = GENERIC_WRITE;
const STAGE_CREATE_SHARE: FILE_SHARE_MODE = 0;
const STAGE_CREATE_DISPOSITION: FILE_CREATION_DISPOSITION = CREATE_NEW;
const STAGE_CREATE_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;

const DIRECTORY_OPEN_ACCESS: u32 = 0;
const DIRECTORY_OPEN_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ | FILE_SHARE_WRITE;
const DIRECTORY_OPEN_DISPOSITION: FILE_CREATION_DISPOSITION = OPEN_EXISTING;
const DIRECTORY_OPEN_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;

const INITIAL_PUBLICATION_FLAGS: MOVE_FILE_FLAGS = MOVEFILE_WRITE_THROUGH;
const REPLACEMENT_FLAGS: REPLACE_FILE_FLAGS = 0;
const NORMALIZED_GUID_FINAL_PATH_FLAGS: GETFINALPATHNAMEBYHANDLE_FLAGS =
    FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;

const STANDARD_INFORMATION_CLASS: FILE_INFO_BY_HANDLE_CLASS = FileStandardInfo;
const ATTRIBUTE_TAG_INFORMATION_CLASS: FILE_INFO_BY_HANDLE_CLASS = FileAttributeTagInfo;
const FILE_ID_INFORMATION_CLASS: FILE_INFO_BY_HANDLE_CLASS = FileIdInfo;

// PRODUCTION READ-HARDENING CORE START: private, read-only, and currently uncalled.
const MAXIMUM_FINAL_PATH_UNITS: usize = 32_767;
const VOLUME_GUID_PREFIX_UNITS: usize = 49;

#[derive(Clone, Copy, Eq, PartialEq)]
struct HandleIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

impl fmt::Debug for HandleIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandleIdentity([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct HardeningObservation {
    identity: HandleIdentity,
    size: u64,
    attributes: u32,
    reparse_tag: u32,
    link_count: u32,
    final_path: Vec<u16>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum HardeningError {
    PathUnavailable,
    ComponentReparse,
    WrongEntryType,
    IdentityChanged,
    HardLinkRejected,
    FinalPathMismatch,
    SameVolumeMismatch,
    InspectionUnavailable,
    FactsChanged,
    ReadUnavailable,
    WrapperInvalid,
}

impl fmt::Debug for HardeningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PathUnavailable => "PathUnavailable",
            Self::ComponentReparse => "ComponentReparse",
            Self::WrongEntryType => "WrongEntryType",
            Self::IdentityChanged => "IdentityChanged",
            Self::HardLinkRejected => "HardLinkRejected",
            Self::FinalPathMismatch => "FinalPathMismatch",
            Self::SameVolumeMismatch => "SameVolumeMismatch",
            Self::InspectionUnavailable => "InspectionUnavailable",
            Self::FactsChanged => "FactsChanged",
            Self::ReadUnavailable => "ReadUnavailable",
            Self::WrapperInvalid => "WrapperInvalid",
        })
    }
}

struct RetainedDirectory {
    handle: File,
    initial: HardeningObservation,
}

fn checked_buffer_length(length: usize) -> Option<u32> {
    u32::try_from(length).ok()
}

fn encode_utf16_path(path: &Path) -> Result<Vec<u16>, HardeningError> {
    let mut encoded = Vec::new();
    for unit in path.as_os_str().encode_wide() {
        if unit == 0 {
            return Err(HardeningError::PathUnavailable);
        }
        encoded.push(unit);
    }
    encoded.push(0);
    Ok(encoded)
}

fn open_for_read(path: &[u16]) -> Result<File, HardeningError> {
    // SAFETY: `path` is NUL-terminated and lives for the call; optional pointers
    // are null, and no overlapped I/O flag is supplied.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            ACTIVE_READ_ACCESS,
            ACTIVE_READ_SHARE,
            NULL_CREATE_SECURITY_ATTRIBUTES,
            ACTIVE_READ_DISPOSITION,
            ACTIVE_READ_FLAGS,
            NULL_CREATE_TEMPLATE_HANDLE,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(HardeningError::InspectionUnavailable);
    }
    // SAFETY: `raw` is a fresh successful CreateFileW handle and ownership is
    // transferred immediately to exactly one OwnedHandle, then to File.
    let owned = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
    Ok(File::from(owned))
}

fn validate_disk_handle(file: &File) -> Result<(), HardeningError> {
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: `handle` is owned by the live File for the duration of the call.
    let file_type = unsafe { GetFileType(handle) };
    if file_type != FILE_TYPE_DISK {
        return Err(HardeningError::WrongEntryType);
    }
    Ok(())
}

fn query_entry_information(
    file: &File,
) -> Result<(FILE_STANDARD_INFO, FILE_ATTRIBUTE_TAG_INFO), HardeningError> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut standard = FILE_STANDARD_INFO::default();
    let standard_size = checked_buffer_length(std::mem::size_of::<FILE_STANDARD_INFO>())
        .ok_or(HardeningError::InspectionUnavailable)?;
    // SAFETY: `standard` is initialized writable storage of exactly the reported
    // checked size, and `handle` remains owned by the live File.
    let standard_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&raw mut standard).cast::<c_void>(),
            standard_size,
        )
    };
    if standard_ok == 0 {
        return Err(HardeningError::InspectionUnavailable);
    }

    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    let attributes_size = checked_buffer_length(std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>())
        .ok_or(HardeningError::InspectionUnavailable)?;
    // SAFETY: `attributes` is initialized writable storage of exactly the
    // reported checked size, and `handle` remains owned by the live File.
    let attributes_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&raw mut attributes).cast::<c_void>(),
            attributes_size,
        )
    };
    if attributes_ok == 0 {
        return Err(HardeningError::InspectionUnavailable);
    }
    Ok((standard, attributes))
}

fn query_handle_identity(file: &File) -> Result<HandleIdentity, HardeningError> {
    let mut information = FileIdFileInformation::default();
    let size = checked_buffer_length(std::mem::size_of::<FileIdFileInformation>())
        .ok_or(HardeningError::InspectionUnavailable)?;
    // SAFETY: `information` is initialized writable storage of the exact checked
    // size and the live File owns `handle` for the duration of the call.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            (&raw mut information).cast::<c_void>(),
            size,
        )
    };
    if succeeded == 0 {
        return Err(HardeningError::InspectionUnavailable);
    }
    Ok(HandleIdentity {
        volume_serial: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

fn query_link_count(file: &File) -> Result<u32, HardeningError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `information` is initialized writable storage and the live File
    // owns the handle for the duration of the call.
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &raw mut information) };
    if succeeded == 0 {
        return Err(HardeningError::InspectionUnavailable);
    }
    Ok(information.nNumberOfLinks)
}

fn query_hardening_observation(file: &File) -> Result<HardeningObservation, HardeningError> {
    validate_disk_handle(file)?;
    let (standard, attribute_tag) = query_entry_information(file)?;
    let size = u64::try_from(standard.EndOfFile).map_err(|_| HardeningError::WrongEntryType)?;
    Ok(HardeningObservation {
        identity: query_handle_identity(file)?,
        size,
        attributes: attribute_tag.FileAttributes,
        reparse_tag: attribute_tag.ReparseTag,
        link_count: query_link_count(file)?,
        final_path: query_bounded_final_guid_path(file)?,
    })
}

fn query_bounded_final_guid_path(file: &File) -> Result<Vec<u16>, HardeningError> {
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: this is the documented size query and the live File retains the
    // handle; no output storage is accessed.
    let required = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            NORMALIZED_GUID_FINAL_PATH_FLAGS,
        )
    };
    let capacity = usize::try_from(required).map_err(|_| HardeningError::PathUnavailable)?;
    if required == 0 || capacity > MAXIMUM_FINAL_PATH_UNITS {
        return Err(HardeningError::PathUnavailable);
    }
    let mut output = vec![0_u16; capacity];
    let capacity_u32 = checked_buffer_length(capacity).ok_or(HardeningError::PathUnavailable)?;
    // SAFETY: `output` is initialized writable storage of the checked capacity
    // and the live File retains the handle for the call.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            output.as_mut_ptr(),
            capacity_u32,
            NORMALIZED_GUID_FINAL_PATH_FLAGS,
        )
    };
    let written = usize::try_from(written).map_err(|_| HardeningError::PathUnavailable)?;
    if written == 0 || written >= output.len() || written > MAXIMUM_FINAL_PATH_UNITS {
        return Err(HardeningError::PathUnavailable);
    }
    output.truncate(written);
    Ok(output)
}

fn validate_reparse_facts(attributes: u32, tag: u32) -> Result<(), HardeningError> {
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || tag != 0 {
        return Err(HardeningError::ComponentReparse);
    }
    Ok(())
}

fn validate_wrapper_link_count(link_count: u32) -> Result<(), HardeningError> {
    if link_count != 1 {
        return Err(HardeningError::HardLinkRejected);
    }
    Ok(())
}

fn ascii_units(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn is_ascii_hex(unit: u16) -> bool {
    (b'0' as u16..=b'9' as u16).contains(&unit)
        || (b'a' as u16..=b'f' as u16).contains(&unit)
        || (b'A' as u16..=b'F' as u16).contains(&unit)
}

fn ascii_hex_fold(unit: u16) -> u16 {
    if (b'A' as u16..=b'F' as u16).contains(&unit) {
        unit + u16::from(b'a' - b'A')
    } else {
        unit
    }
}

fn validated_volume_guid_prefix(path: &[u16]) -> Result<&[u16], HardeningError> {
    if path.is_empty()
        || path.len() > MAXIMUM_FINAL_PATH_UNITS
        || path.contains(&0)
        || path.len() < VOLUME_GUID_PREFIX_UNITS
    {
        return Err(HardeningError::PathUnavailable);
    }
    let fixed_prefix = ascii_units(r"\\?\Volume{");
    if path.get(..fixed_prefix.len()) != Some(fixed_prefix.as_slice())
        || path[47] != b'}' as u16
        || path[48] != b'\\' as u16
    {
        return Err(HardeningError::FinalPathMismatch);
    }
    for (offset, unit) in path[11..47].iter().copied().enumerate() {
        if matches!(offset, 8 | 13 | 18 | 23) {
            if unit != b'-' as u16 {
                return Err(HardeningError::FinalPathMismatch);
            }
        } else if !is_ascii_hex(unit) {
            return Err(HardeningError::FinalPathMismatch);
        }
    }
    Ok(&path[..VOLUME_GUID_PREFIX_UNITS])
}

fn same_volume_guid(left: &[u16], right: &[u16]) -> Result<bool, HardeningError> {
    let left = validated_volume_guid_prefix(left)?;
    let right = validated_volume_guid_prefix(right)?;
    Ok(left[..11] == right[..11]
        && left[47..] == right[47..]
        && left[11..47]
            .iter()
            .zip(&right[11..47])
            .all(|(left, right)| ascii_hex_fold(*left) == ascii_hex_fold(*right)))
}

fn exact_child_final_path(
    parent: &[u16],
    actual: &[u16],
    expected_component: &[u16],
) -> Result<(), HardeningError> {
    if expected_component.is_empty()
        || expected_component
            .iter()
            .any(|unit| matches!(*unit, 0 | 47 | 92))
        || !same_volume_guid(parent, actual)?
    {
        return Err(HardeningError::FinalPathMismatch);
    }
    let mut expected = parent.to_vec();
    if expected.last() != Some(&(b'\\' as u16)) {
        expected.push(b'\\' as u16);
    }
    expected.extend_from_slice(expected_component);
    if expected.len() != actual.len()
        || expected[..11] != actual[..11]
        || expected[47..] != actual[47..]
        || !expected[11..47]
            .iter()
            .zip(&actual[11..47])
            .all(|(left, right)| ascii_hex_fold(*left) == ascii_hex_fold(*right))
    {
        return Err(HardeningError::FinalPathMismatch);
    }
    Ok(())
}

fn validate_same_volume(
    parent: &HardeningObservation,
    child: &HardeningObservation,
) -> Result<(), HardeningError> {
    if parent.identity.volume_serial != child.identity.volume_serial
        || !same_volume_guid(&parent.final_path, &child.final_path)?
    {
        return Err(HardeningError::SameVolumeMismatch);
    }
    Ok(())
}

fn open_hardened_directory(
    path: &Path,
    parent: Option<(&HardeningObservation, &[u16])>,
) -> Result<RetainedDirectory, HardeningError> {
    let encoded = encode_utf16_path(path)?;
    // SAFETY: `encoded` is NUL-terminated and live for the call; the exact
    // directory flags open the entry itself and request no mutation access.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            DIRECTORY_OPEN_ACCESS,
            DIRECTORY_OPEN_SHARE,
            NULL_CREATE_SECURITY_ATTRIBUTES,
            DIRECTORY_OPEN_DISPOSITION,
            DIRECTORY_OPEN_FLAGS,
            NULL_CREATE_TEMPLATE_HANDLE,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(HardeningError::InspectionUnavailable);
    }
    // SAFETY: ownership of the fresh successful handle is transferred once.
    let handle = File::from(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) });
    let observation = query_hardening_observation(&handle)?;
    if observation.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(HardeningError::WrongEntryType);
    }
    validate_reparse_facts(observation.attributes, observation.reparse_tag)?;
    validated_volume_guid_prefix(&observation.final_path)?;
    if let Some((parent, expected_component)) = parent {
        validate_same_volume(parent, &observation)?;
        exact_child_final_path(
            &parent.final_path,
            &observation.final_path,
            expected_component,
        )?;
    }
    Ok(RetainedDirectory {
        handle,
        initial: observation,
    })
}

fn validate_stable_observations(
    before: Option<&HardeningObservation>,
    after: Option<&HardeningObservation>,
) -> Result<(), HardeningError> {
    let (before, after) = before
        .zip(after)
        .ok_or(HardeningError::InspectionUnavailable)?;
    if before.identity.volume_serial != after.identity.volume_serial {
        return Err(HardeningError::SameVolumeMismatch);
    }
    if before.identity.file_id != after.identity.file_id {
        return Err(HardeningError::IdentityChanged);
    }
    if before.link_count != after.link_count {
        return Err(HardeningError::HardLinkRejected);
    }
    if before.final_path != after.final_path {
        return Err(HardeningError::FinalPathMismatch);
    }
    if !same_volume_guid(&before.final_path, &after.final_path)? {
        return Err(HardeningError::SameVolumeMismatch);
    }
    if before.size != after.size
        || before.attributes != after.attributes
        || before.reparse_tag != after.reparse_tag
    {
        return Err(HardeningError::FactsChanged);
    }
    Ok(())
}

fn inspect_hardened_authentication_key_wrapper(
    path: &Path,
    expected_name: &str,
    retained: &[RetainedDirectory],
) -> Result<ProtectedWrapperBytes, HardeningError> {
    inspect_hardened_authentication_key_wrapper_with(
        path,
        expected_name,
        retained,
        || {},
        read_bounded_protected_wrapper,
    )
}

fn inspect_hardened_authentication_key_wrapper_with<M, R>(
    path: &Path,
    expected_name: &str,
    retained: &[RetainedDirectory],
    mutation: M,
    reader: R,
) -> Result<ProtectedWrapperBytes, HardeningError>
where
    M: FnOnce(),
    R: FnOnce(&mut File, u64) -> Result<ProtectedWrapperBytes, BoundedReadError>,
{
    inspect_hardened_wrapper_with(path, expected_name, retained, mutation, reader, |bytes| {
        EncodedProtectedWrapper::validate_authentication_key_bytes(bytes)
            .map_err(|_| HardeningError::WrapperInvalid)
    })
}

fn inspect_hardened_authenticated_evidence_wrapper(
    path: &Path,
    expected_name: &str,
    retained: &[RetainedDirectory],
) -> Result<ProtectedWrapperBytes, HardeningError> {
    inspect_hardened_wrapper_with(
        path,
        expected_name,
        retained,
        || {},
        read_bounded_protected_wrapper,
        |bytes| {
            EncodedProtectedWrapper::validate_authenticated_evidence_bytes(bytes)
                .map_err(|_| HardeningError::WrapperInvalid)
        },
    )
}

fn inspect_hardened_wrapper_with<M, R, V>(
    path: &Path,
    expected_name: &str,
    retained: &[RetainedDirectory],
    mutation: M,
    reader: R,
    validator: V,
) -> Result<ProtectedWrapperBytes, HardeningError>
where
    M: FnOnce(),
    R: FnOnce(&mut File, u64) -> Result<ProtectedWrapperBytes, BoundedReadError>,
    V: FnOnce(&[u8]) -> Result<(), HardeningError>,
{
    let parent = retained
        .last()
        .ok_or(HardeningError::InspectionUnavailable)?;
    let directory_identities_before = retained
        .iter()
        .map(|directory| query_handle_identity(&directory.handle))
        .collect::<Result<Vec<_>, _>>()?;
    let encoded = encode_utf16_path(path)?;
    let mut file = open_for_read(&encoded)?;
    let before = query_hardening_observation(&file)?;
    if before.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(HardeningError::WrongEntryType);
    }
    validate_reparse_facts(before.attributes, before.reparse_tag)?;
    validate_wrapper_link_count(before.link_count)?;
    if !(MINIMUM_PROTECTED_WRAPPER_LENGTH..=MAXIMUM_PROTECTED_WRAPPER_LENGTH).contains(&before.size)
    {
        return Err(HardeningError::WrongEntryType);
    }
    validate_approved_wrapper_name(path, expected_name)?;
    validate_same_volume(&parent.initial, &before)?;
    exact_child_final_path(
        &parent.initial.final_path,
        &before.final_path,
        &ascii_units(expected_name),
    )?;

    mutation();
    let loaded = reader(&mut file, before.size).map_err(|_| HardeningError::ReadUnavailable)?;
    validator(loaded.as_bytes())?;
    let after = query_hardening_observation(&file)?;
    validate_stable_observations(Some(&before), Some(&after))?;
    let directory_identities_after = retained
        .iter()
        .map(|directory| query_handle_identity(&directory.handle))
        .collect::<Result<Vec<_>, _>>()?;
    if directory_identities_before != directory_identities_after
        || retained
            .iter()
            .map(|directory| directory.initial.identity)
            .ne(directory_identities_after)
    {
        return Err(HardeningError::IdentityChanged);
    }
    Ok(loaded)
}

fn validate_approved_wrapper_name(path: &Path, expected_name: &str) -> Result<(), HardeningError> {
    if path.file_name() != Some(OsStr::new(expected_name)) {
        return Err(HardeningError::FinalPathMismatch);
    }
    Ok(())
}

fn load_active_authentication_key_wrapper(
    paths: &InstallationEvidencePersistencePaths,
) -> Result<ProtectedWrapperBytes, HardeningError> {
    let active_database = paths.active_database.as_path();
    let root = active_database
        .parent()
        .ok_or(HardeningError::PathUnavailable)?;
    let evidence_directory = paths.evidence_directory.as_path();
    let active_authentication_key = paths.active_authentication_key.as_path();

    if active_database != root.join(PRODUCTION_DATABASE_FILENAME)
        || evidence_directory != root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME)
        || active_authentication_key != evidence_directory.join(ACTIVE_AUTHENTICATION_KEY_FILENAME)
    {
        return Err(HardeningError::FinalPathMismatch);
    }

    let parent_path = root.parent().ok_or(HardeningError::PathUnavailable)?;
    let root_component = root
        .file_name()
        .ok_or(HardeningError::PathUnavailable)?
        .encode_wide()
        .collect::<Vec<_>>();
    let parent = open_hardened_directory(parent_path, None)?;
    let root = open_hardened_directory(root, Some((&parent.initial, root_component.as_slice())))?;
    let evidence = open_hardened_directory(
        evidence_directory,
        Some((
            &root.initial,
            &ascii_units(INSTALLATION_EVIDENCE_DIRECTORY_NAME),
        )),
    )?;
    let retained = [parent, root, evidence];

    inspect_hardened_authentication_key_wrapper(
        active_authentication_key,
        ACTIVE_AUTHENTICATION_KEY_FILENAME,
        &retained,
    )
}

fn load_active_authenticated_evidence_wrapper(
    paths: &InstallationEvidencePersistencePaths,
) -> Result<ProtectedWrapperBytes, HardeningError> {
    let active_database = paths.active_database.as_path();
    let root = active_database
        .parent()
        .ok_or(HardeningError::PathUnavailable)?;
    let evidence_directory = paths.evidence_directory.as_path();
    let active_authenticated_evidence = paths.active_authenticated_evidence.as_path();

    if active_database != root.join(PRODUCTION_DATABASE_FILENAME)
        || evidence_directory != root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME)
        || active_authenticated_evidence
            != evidence_directory.join(ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME)
    {
        return Err(HardeningError::FinalPathMismatch);
    }

    let parent_path = root.parent().ok_or(HardeningError::PathUnavailable)?;
    let root_component = root
        .file_name()
        .ok_or(HardeningError::PathUnavailable)?
        .encode_wide()
        .collect::<Vec<_>>();
    let parent = open_hardened_directory(parent_path, None)?;
    let root = open_hardened_directory(root, Some((&parent.initial, root_component.as_slice())))?;
    let evidence = open_hardened_directory(
        evidence_directory,
        Some((
            &root.initial,
            &ascii_units(INSTALLATION_EVIDENCE_DIRECTORY_NAME),
        )),
    )?;
    let retained = [parent, root, evidence];

    inspect_hardened_authenticated_evidence_wrapper(
        active_authenticated_evidence,
        ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME,
        &retained,
    )
}
// PRODUCTION READ-HARDENING CORE END.

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::{OsStr, OsString},
        fmt, fs,
        io::{self, Cursor, Write},
        os::windows::ffi::{OsStrExt, OsStringExt},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
        ERROR_UNABLE_TO_MOVE_REPLACEMENT, ERROR_UNABLE_TO_MOVE_REPLACEMENT_2,
        ERROR_UNABLE_TO_REMOVE_REPLACED,
    };

    use crate::{
        installation_evidence_protection::EncodedProtectedWrapper,
        storage_foundation::{
            ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME, ACTIVE_AUTHENTICATION_KEY_FILENAME,
            INSTALLATION_EVIDENCE_DIRECTORY_NAME, InstallationEvidencePersistencePaths,
            PRODUCTION_DATABASE_FILENAME, PRODUCTION_DATABASE_STAGE_FILENAME,
            STAGED_AUTHENTICATED_EVIDENCE_FILENAME, STAGED_AUTHENTICATION_KEY_FILENAME,
            installation_evidence_persistence_paths,
        },
    };

    use super::super::{
        BoundedReadError, MAXIMUM_PROTECTED_WRAPPER_LENGTH, MINIMUM_PROTECTED_WRAPPER_LENGTH,
        read_bounded_protected_wrapper,
    };

    fn mutable_utf16_output(buffer: &mut [u16]) -> MutableUtf16Output {
        buffer.as_mut_ptr()
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(crate) enum TemporaryPublicationError {
        PathEncodingFailed,
        StageAlreadyExists,
        OpenFailed,
        EntryTypeInvalid,
        ProtectedFileSizeInvalid,
        WriteFailed,
        FlushFailed,
        ReadFailed,
        ReloadVerificationFailed,
        WrapperValidationFailed,
        InitialPublicationFailed,
        StateChangedDuringInspection,
    }

    impl fmt::Debug for TemporaryPublicationError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(match self {
                Self::PathEncodingFailed => "PathEncodingFailed",
                Self::StageAlreadyExists => "StageAlreadyExists",
                Self::OpenFailed => "OpenFailed",
                Self::EntryTypeInvalid => "EntryTypeInvalid",
                Self::ProtectedFileSizeInvalid => "ProtectedFileSizeInvalid",
                Self::WriteFailed => "WriteFailed",
                Self::FlushFailed => "FlushFailed",
                Self::ReadFailed => "ReadFailed",
                Self::ReloadVerificationFailed => "ReloadVerificationFailed",
                Self::WrapperValidationFailed => "WrapperValidationFailed",
                Self::InitialPublicationFailed => "InitialPublicationFailed",
                Self::StateChangedDuringInspection => "StateChangedDuringInspection",
            })
        }
    }

    impl From<HardeningError> for TemporaryPublicationError {
        fn from(error: HardeningError) -> Self {
            match error {
                HardeningError::PathUnavailable => Self::PathEncodingFailed,
                HardeningError::WrongEntryType => Self::EntryTypeInvalid,
                _ => Self::OpenFailed,
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct TemporaryPublicationProof {
        pub(crate) stage_reload_verified: bool,
        pub(crate) published_without_replacement: bool,
        pub(crate) active_reload_verified: bool,
    }

    pub(crate) fn publish_synthetic_authentication_key_wrapper(
        paths: &InstallationEvidencePersistencePaths,
        intended_bytes: &[u8],
    ) -> Result<TemporaryPublicationProof, TemporaryPublicationError> {
        publish_synthetic_authentication_key_wrapper_with_expected_reload(
            paths,
            intended_bytes,
            intended_bytes,
        )
    }

    fn publish_synthetic_authentication_key_wrapper_with_expected_reload(
        paths: &InstallationEvidencePersistencePaths,
        intended_bytes: &[u8],
        expected_stage_reload: &[u8],
    ) -> Result<TemporaryPublicationProof, TemporaryPublicationError> {
        validate_proof_paths(paths)?;
        validate_intended_length(intended_bytes.len())?;

        let (directory, directory_final_path) =
            open_and_validate_directory(paths.evidence_directory.as_path())?;
        let stage_path = encode_utf16_path(paths.staged_authentication_key.as_path())?;
        let active_path = encode_utf16_path(paths.active_authentication_key.as_path())?;

        let stage_handle = create_stage_file(&stage_path)?;
        let mut stage_file = File::from(stage_handle);
        stage_file
            .write_all(intended_bytes)
            .map_err(|_| TemporaryPublicationError::WriteFailed)?;
        flush_file_buffers(&stage_file)?;
        drop(stage_file);

        reload_and_validate(
            paths.staged_authentication_key.as_path(),
            &stage_path,
            STAGED_AUTHENTICATION_KEY_FILENAME,
            &directory_final_path,
            expected_stage_reload,
        )?;

        publish_initial(&stage_path, &active_path)?;

        reload_and_validate(
            paths.active_authentication_key.as_path(),
            &active_path,
            ACTIVE_AUTHENTICATION_KEY_FILENAME,
            &directory_final_path,
            intended_bytes,
        )?;

        if paths
            .staged_authentication_key
            .as_path()
            .try_exists()
            .map_err(|_| TemporaryPublicationError::StateChangedDuringInspection)?
        {
            return Err(TemporaryPublicationError::StateChangedDuringInspection);
        }

        drop(directory);
        Ok(TemporaryPublicationProof {
            stage_reload_verified: true,
            published_without_replacement: true,
            active_reload_verified: true,
        })
    }

    fn validate_proof_paths(
        paths: &InstallationEvidencePersistencePaths,
    ) -> Result<(), TemporaryPublicationError> {
        let evidence_directory = paths.evidence_directory.as_path();
        let stage = paths.staged_authentication_key.as_path();
        let active = paths.active_authentication_key.as_path();
        if stage.parent() != Some(evidence_directory)
            || active.parent() != Some(evidence_directory)
            || stage.file_name() != Some(OsStr::new(STAGED_AUTHENTICATION_KEY_FILENAME))
            || active.file_name() != Some(OsStr::new(ACTIVE_AUTHENTICATION_KEY_FILENAME))
        {
            return Err(TemporaryPublicationError::EntryTypeInvalid);
        }
        Ok(())
    }

    fn validate_intended_length(length: usize) -> Result<(), TemporaryPublicationError> {
        let length = u64::try_from(length)
            .map_err(|_| TemporaryPublicationError::ProtectedFileSizeInvalid)?;
        let _native_length = u32::try_from(length)
            .map_err(|_| TemporaryPublicationError::ProtectedFileSizeInvalid)?;
        if !(MINIMUM_PROTECTED_WRAPPER_LENGTH..=MAXIMUM_PROTECTED_WRAPPER_LENGTH).contains(&length)
        {
            return Err(TemporaryPublicationError::ProtectedFileSizeInvalid);
        }
        Ok(())
    }

    fn create_stage_file(path: &[u16]) -> Result<OwnedHandle, TemporaryPublicationError> {
        // SAFETY: `path` is NUL-terminated and lives for the call; optional pointers
        // are null, and no overlapped I/O flag is supplied.
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                STAGE_CREATE_ACCESS,
                STAGE_CREATE_SHARE,
                NULL_CREATE_SECURITY_ATTRIBUTES,
                STAGE_CREATE_DISPOSITION,
                STAGE_CREATE_FLAGS,
                NULL_CREATE_TEMPLATE_HANDLE,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            // SAFETY: called immediately after the failed native operation.
            let native_error = unsafe { GetLastError() };
            return Err(
                if matches!(native_error, ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS) {
                    TemporaryPublicationError::StageAlreadyExists
                } else {
                    TemporaryPublicationError::OpenFailed
                },
            );
        }

        // SAFETY: `raw` is a fresh successful CreateFileW handle and ownership is
        // transferred immediately to exactly one OwnedHandle.
        Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
    }

    fn open_and_validate_directory(
        path: &Path,
    ) -> Result<(File, Vec<u16>), TemporaryPublicationError> {
        let encoded = encode_utf16_path(path)?;
        // SAFETY: `encoded` is NUL-terminated and lives for the call; optional
        // pointers are null, and the directory is opened without overlapped I/O.
        let raw = unsafe {
            CreateFileW(
                encoded.as_ptr(),
                DIRECTORY_OPEN_ACCESS,
                DIRECTORY_OPEN_SHARE,
                NULL_CREATE_SECURITY_ATTRIBUTES,
                DIRECTORY_OPEN_DISPOSITION,
                DIRECTORY_OPEN_FLAGS,
                NULL_CREATE_TEMPLATE_HANDLE,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            // SAFETY: called immediately after the failed native operation.
            let _native_error = unsafe { GetLastError() };
            return Err(TemporaryPublicationError::OpenFailed);
        }
        // SAFETY: `raw` is a fresh successful CreateFileW handle and ownership is
        // transferred immediately to exactly one OwnedHandle, then to File.
        let owned = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        let directory = File::from(owned);
        validate_disk_handle(&directory)?;
        let (standard, attributes) = query_entry_information(&directory)?;
        if !standard.Directory
            || attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(TemporaryPublicationError::EntryTypeInvalid);
        }
        let final_path = query_final_guid_path(&directory)?;
        validate_local_guid_path(&final_path)?;
        Ok((directory, final_path))
    }

    fn flush_file_buffers(file: &File) -> Result<(), TemporaryPublicationError> {
        let handle = file.as_raw_handle() as HANDLE;
        // SAFETY: `handle` is owned by the live File for the duration of the call.
        let succeeded = unsafe { FlushFileBuffers(handle) };
        if succeeded == 0 {
            // SAFETY: called immediately after the failed native operation.
            let _native_error = unsafe { GetLastError() };
            return Err(TemporaryPublicationError::FlushFailed);
        }
        Ok(())
    }

    fn reload_and_validate(
        expected_path: &Path,
        encoded_path: &[u16],
        expected_name: &str,
        directory_final_path: &[u16],
        intended_bytes: &[u8],
    ) -> Result<(), TemporaryPublicationError> {
        let mut file = open_for_read(encoded_path)?;
        validate_disk_handle(&file)?;
        let (standard, attributes) = query_entry_information(&file)?;
        if standard.Directory
            || attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(TemporaryPublicationError::EntryTypeInvalid);
        }
        let initial_size = size_from_standard_information(standard)?;
        let final_path = query_final_guid_path(&file)?;
        validate_expected_child_final_path(&final_path, directory_final_path, expected_name)?;
        if expected_path.file_name() != Some(OsStr::new(expected_name)) {
            return Err(TemporaryPublicationError::EntryTypeInvalid);
        }

        let loaded =
            read_bounded_protected_wrapper(&mut file, initial_size).map_err(map_read_error)?;
        let (after_read, _) = query_entry_information(&file)?;
        if size_from_standard_information(after_read)? != initial_size {
            return Err(TemporaryPublicationError::StateChangedDuringInspection);
        }
        if loaded.as_bytes() != intended_bytes {
            return Err(TemporaryPublicationError::ReloadVerificationFailed);
        }
        EncodedProtectedWrapper::validate_authentication_key_bytes(loaded.as_bytes())
            .map_err(|_| TemporaryPublicationError::WrapperValidationFailed)?;
        drop(file);
        Ok(())
    }

    fn size_from_standard_information(
        information: FILE_STANDARD_INFO,
    ) -> Result<u64, TemporaryPublicationError> {
        let size = u64::try_from(information.EndOfFile)
            .map_err(|_| TemporaryPublicationError::ProtectedFileSizeInvalid)?;
        if !(MINIMUM_PROTECTED_WRAPPER_LENGTH..=MAXIMUM_PROTECTED_WRAPPER_LENGTH).contains(&size) {
            return Err(TemporaryPublicationError::ProtectedFileSizeInvalid);
        }
        Ok(size)
    }

    fn query_final_guid_path(file: &File) -> Result<Vec<u16>, TemporaryPublicationError> {
        let handle = file.as_raw_handle() as HANDLE;
        // SAFETY: a null output pointer with zero capacity is the documented size
        // query; `handle` remains owned by the live File.
        let required = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                std::ptr::null_mut(),
                0,
                NORMALIZED_GUID_FINAL_PATH_FLAGS,
            )
        };
        if required == 0 {
            // SAFETY: called immediately after the failed native operation.
            let _native_error = unsafe { GetLastError() };
            return Err(TemporaryPublicationError::OpenFailed);
        }
        let capacity =
            usize::try_from(required).map_err(|_| TemporaryPublicationError::OpenFailed)?;
        let mut output = vec![0_u16; capacity];
        let capacity_u32 =
            checked_buffer_length(output.len()).ok_or(TemporaryPublicationError::OpenFailed)?;
        // SAFETY: `output` is initialized writable storage with the checked capacity,
        // and `handle` remains owned by the live File.
        let written = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                output.as_mut_ptr(),
                capacity_u32,
                NORMALIZED_GUID_FINAL_PATH_FLAGS,
            )
        };
        if written == 0 {
            // SAFETY: called immediately after the failed native operation.
            let _native_error = unsafe { GetLastError() };
            return Err(TemporaryPublicationError::OpenFailed);
        }
        let written =
            usize::try_from(written).map_err(|_| TemporaryPublicationError::OpenFailed)?;
        if written >= output.len() {
            return Err(TemporaryPublicationError::StateChangedDuringInspection);
        }
        output.truncate(written);
        Ok(output)
    }

    fn validate_local_guid_path(path: &[u16]) -> Result<(), TemporaryPublicationError> {
        let volume_prefix: Vec<u16> = OsStr::new(r"\\?\Volume{").encode_wide().collect();
        let unc_prefix: Vec<u16> = OsStr::new(r"\\?\UNC\").encode_wide().collect();
        let ordinary_unc_prefix: Vec<u16> = OsStr::new(r"\\").encode_wide().collect();
        if path.starts_with(&unc_prefix)
            || (path.starts_with(&ordinary_unc_prefix) && !path.starts_with(&volume_prefix))
            || !path.starts_with(&volume_prefix)
        {
            return Err(TemporaryPublicationError::EntryTypeInvalid);
        }
        Ok(())
    }

    fn validate_expected_child_final_path(
        actual: &[u16],
        directory: &[u16],
        expected_name: &str,
    ) -> Result<(), TemporaryPublicationError> {
        validate_local_guid_path(actual)?;
        let mut expected = directory.to_vec();
        if expected.last() != Some(&(b'\\' as u16)) {
            expected.push(b'\\' as u16);
        }
        expected.extend(OsStr::new(expected_name).encode_wide());
        if actual != expected {
            return Err(TemporaryPublicationError::EntryTypeInvalid);
        }
        Ok(())
    }

    fn map_read_error(error: BoundedReadError) -> TemporaryPublicationError {
        match error {
            BoundedReadError::Empty
            | BoundedReadError::BelowMinimum
            | BoundedReadError::AboveMaximum => TemporaryPublicationError::ProtectedFileSizeInvalid,
            BoundedReadError::TrailingData => {
                TemporaryPublicationError::StateChangedDuringInspection
            }
            BoundedReadError::ShortRead | BoundedReadError::ReadUnavailable => {
                TemporaryPublicationError::ReadFailed
            }
        }
    }

    fn publish_initial(stage: &[u16], active: &[u16]) -> Result<(), TemporaryPublicationError> {
        // SAFETY: both paths are NUL-terminated and live for the call. The exact
        // flags enable write-through only: no replacement and no copy fallback.
        let succeeded =
            unsafe { MoveFileExW(stage.as_ptr(), active.as_ptr(), INITIAL_PUBLICATION_FLAGS) };
        if succeeded == 0 {
            // SAFETY: called immediately after the failed native operation.
            let _native_error = unsafe { GetLastError() };
            return Err(TemporaryPublicationError::InitialPublicationFailed);
        }
        Ok(())
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct FileIdentity {
        volume_serial: u32,
        file_index: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReplacementFailureFamily {
        UnableToRemoveReplaced,
        UnableToMoveReplacement,
        UnableToMoveReplacement2,
        OtherFailure,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReplacementCallOutcome {
        Success,
        Failure(ReplacementFailureFamily),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReplacementObservationClass {
        ActiveNewStageAbsent,
        ActiveOldStageNew,
        ActiveAbsentStageNew,
        ReportedFailureButActiveNewStageAbsent,
        UnexpectedOrUnavailable,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum ExactNameObservation {
        Absent,
        RegularOld(FileIdentity),
        RegularNew(FileIdentity),
        UnexpectedBytesOrMalformed,
        UnexpectedEntryType,
        Unavailable,
    }

    impl fmt::Debug for ExactNameObservation {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(match self {
                Self::Absent => "Absent",
                Self::RegularOld(_) => "RegularOld",
                Self::RegularNew(_) => "RegularNew",
                Self::UnexpectedBytesOrMalformed => "UnexpectedBytesOrMalformed",
                Self::UnexpectedEntryType => "UnexpectedEntryType",
                Self::Unavailable => "Unavailable",
            })
        }
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum ExistingFileReplacementError {
        ActiveMissing,
        StageMissing,
        PreflightValidationFailed,
        ReplacementFailed,
        ReplacementStateAmbiguous,
        ReplacementVerificationFailed,
        StateChangedDuringInspection,
    }

    impl fmt::Debug for ExistingFileReplacementError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(match self {
                Self::ActiveMissing => "ActiveMissing",
                Self::StageMissing => "StageMissing",
                Self::PreflightValidationFailed => "PreflightValidationFailed",
                Self::ReplacementFailed => "ReplacementFailed",
                Self::ReplacementStateAmbiguous => "ReplacementStateAmbiguous",
                Self::ReplacementVerificationFailed => "ReplacementVerificationFailed",
                Self::StateChangedDuringInspection => "StateChangedDuringInspection",
            })
        }
    }

    struct ReplacementPreflight {
        old_active_identity: FileIdentity,
        staged_replacement_identity: FileIdentity,
    }

    struct ReplacementAttemptReport {
        outcome: ReplacementCallOutcome,
        classification: ReplacementObservationClass,
        active: ExactNameObservation,
        stage: ExactNameObservation,
        preflight: ReplacementPreflight,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ExistingFileReplacementProof {
        active_replacement_verified: bool,
        stage_absence_verified: bool,
        stage_identity_continuity_verified: bool,
        old_active_identity_replaced: bool,
    }

    fn query_file_identity(file: &File) -> Result<FileIdentity, TemporaryPublicationError> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `information` is initialized writable storage and `file` owns a
        // valid handle for the entire call.
        let succeeded = unsafe {
            GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &raw mut information)
        };
        if succeeded == 0 {
            // SAFETY: called immediately after the failed native operation.
            let _native_error = unsafe { GetLastError() };
            return Err(TemporaryPublicationError::OpenFailed);
        }
        Ok(FileIdentity {
            volume_serial: information.dwVolumeSerialNumber,
            file_index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        })
    }

    fn reload_validate_and_identify(
        expected_path: &Path,
        encoded_path: &[u16],
        expected_name: &str,
        directory_final_path: &[u16],
        intended_bytes: &[u8],
    ) -> Result<FileIdentity, TemporaryPublicationError> {
        let mut file = open_for_read(encoded_path)?;
        validate_disk_handle(&file)?;
        let (standard, attributes) = query_entry_information(&file)?;
        if standard.Directory
            || attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(TemporaryPublicationError::EntryTypeInvalid);
        }
        let initial_size = size_from_standard_information(standard)?;
        let final_path = query_final_guid_path(&file)?;
        validate_expected_child_final_path(&final_path, directory_final_path, expected_name)?;
        if expected_path.file_name() != Some(OsStr::new(expected_name)) {
            return Err(TemporaryPublicationError::EntryTypeInvalid);
        }
        let identity = query_file_identity(&file)?;
        let loaded =
            read_bounded_protected_wrapper(&mut file, initial_size).map_err(map_read_error)?;
        let (after_read, _) = query_entry_information(&file)?;
        if size_from_standard_information(after_read)? != initial_size
            || query_file_identity(&file)? != identity
        {
            return Err(TemporaryPublicationError::StateChangedDuringInspection);
        }
        if loaded.as_bytes() != intended_bytes {
            return Err(TemporaryPublicationError::ReloadVerificationFailed);
        }
        EncodedProtectedWrapper::validate_authentication_key_bytes(loaded.as_bytes())
            .map_err(|_| TemporaryPublicationError::WrapperValidationFailed)?;
        drop(file);
        Ok(identity)
    }

    fn create_and_verify_replacement_stage(
        paths: &InstallationEvidencePersistencePaths,
        replacement_bytes: &[u8],
    ) -> Result<FileIdentity, ExistingFileReplacementError> {
        validate_proof_paths(paths)
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        validate_intended_length(replacement_bytes.len())
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        let (directory, directory_final_path) =
            open_and_validate_directory(paths.evidence_directory.as_path())
                .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        let directory_identity = query_file_identity(&directory)
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        let stage_path = encode_utf16_path(paths.staged_authentication_key.as_path())
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        let stage_handle = create_stage_file(&stage_path)
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        let mut stage_file = File::from(stage_handle);
        stage_file
            .write_all(replacement_bytes)
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        flush_file_buffers(&stage_file)
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        drop(stage_file);
        let identity = reload_validate_and_identify(
            paths.staged_authentication_key.as_path(),
            &stage_path,
            STAGED_AUTHENTICATION_KEY_FILENAME,
            &directory_final_path,
            replacement_bytes,
        )
        .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        if identity.volume_serial != directory_identity.volume_serial {
            return Err(ExistingFileReplacementError::PreflightValidationFailed);
        }
        drop(directory);
        Ok(identity)
    }

    fn preflight_existing_replacement(
        paths: &InstallationEvidencePersistencePaths,
        expected_old_bytes: &[u8],
        expected_replacement_bytes: &[u8],
    ) -> Result<ReplacementPreflight, ExistingFileReplacementError> {
        validate_proof_paths(paths)
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        for bytes in [expected_old_bytes, expected_replacement_bytes] {
            validate_intended_length(bytes.len())
                .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
            EncodedProtectedWrapper::validate_authentication_key_bytes(bytes)
                .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        }
        if !paths
            .active_authentication_key
            .as_path()
            .try_exists()
            .map_err(|_| ExistingFileReplacementError::StateChangedDuringInspection)?
        {
            return Err(ExistingFileReplacementError::ActiveMissing);
        }
        if !paths
            .staged_authentication_key
            .as_path()
            .try_exists()
            .map_err(|_| ExistingFileReplacementError::StateChangedDuringInspection)?
        {
            return Err(ExistingFileReplacementError::StageMissing);
        }

        let (directory, directory_final_path) =
            open_and_validate_directory(paths.evidence_directory.as_path())
                .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        let directory_identity = query_file_identity(&directory)
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        let active_path = encode_utf16_path(paths.active_authentication_key.as_path())
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        let stage_path = encode_utf16_path(paths.staged_authentication_key.as_path())
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        let old_active_identity = reload_validate_and_identify(
            paths.active_authentication_key.as_path(),
            &active_path,
            ACTIVE_AUTHENTICATION_KEY_FILENAME,
            &directory_final_path,
            expected_old_bytes,
        )
        .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        let staged_replacement_identity = reload_validate_and_identify(
            paths.staged_authentication_key.as_path(),
            &stage_path,
            STAGED_AUTHENTICATION_KEY_FILENAME,
            &directory_final_path,
            expected_replacement_bytes,
        )
        .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        if old_active_identity.volume_serial != directory_identity.volume_serial
            || staged_replacement_identity.volume_serial != directory_identity.volume_serial
        {
            return Err(ExistingFileReplacementError::PreflightValidationFailed);
        }
        drop(directory);
        Ok(ReplacementPreflight {
            old_active_identity,
            staged_replacement_identity,
        })
    }

    fn call_replace_file_once(active: &[u16], stage: &[u16]) -> ReplacementCallOutcome {
        // SAFETY: `active` and `stage` are NUL-terminated and live for the call.
        // The locked call supplies no backup, flags exactly zero, and null reserved
        // pointers. This helper is test-only and performs exactly one native call.
        let succeeded = unsafe {
            ReplaceFileW(
                active.as_ptr(),
                stage.as_ptr(),
                NULL_REPLACE_BACKUP_PATH,
                REPLACEMENT_FLAGS,
                NULL_REPLACE_EXCLUDE_CONTEXT,
                NULL_REPLACE_RESERVED_CONTEXT,
            )
        };
        if succeeded != 0 {
            return ReplacementCallOutcome::Success;
        }
        // SAFETY: captured immediately after the single failed native call.
        let native_error = unsafe { GetLastError() };
        ReplacementCallOutcome::Failure(match native_error {
            ERROR_UNABLE_TO_REMOVE_REPLACED => ReplacementFailureFamily::UnableToRemoveReplaced,
            ERROR_UNABLE_TO_MOVE_REPLACEMENT => ReplacementFailureFamily::UnableToMoveReplacement,
            ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 => {
                ReplacementFailureFamily::UnableToMoveReplacement2
            }
            _ => ReplacementFailureFamily::OtherFailure,
        })
    }

    fn classify_replacement_observation(
        outcome: ReplacementCallOutcome,
        active: ExactNameObservation,
        stage: ExactNameObservation,
    ) -> ReplacementObservationClass {
        match (outcome, active, stage) {
            (
                ReplacementCallOutcome::Success,
                ExactNameObservation::RegularNew(_),
                ExactNameObservation::Absent,
            ) => ReplacementObservationClass::ActiveNewStageAbsent,
            (
                ReplacementCallOutcome::Failure(_),
                ExactNameObservation::RegularNew(_),
                ExactNameObservation::Absent,
            ) => ReplacementObservationClass::ReportedFailureButActiveNewStageAbsent,
            (_, ExactNameObservation::RegularOld(_), ExactNameObservation::RegularNew(_)) => {
                ReplacementObservationClass::ActiveOldStageNew
            }
            (_, ExactNameObservation::Absent, ExactNameObservation::RegularNew(_)) => {
                ReplacementObservationClass::ActiveAbsentStageNew
            }
            _ => ReplacementObservationClass::UnexpectedOrUnavailable,
        }
    }

    fn observe_exact_name(
        path: &Path,
        encoded_path: &[u16],
        expected_name: &str,
        directory_final_path: &[u16],
        old_bytes: &[u8],
        replacement_bytes: &[u8],
    ) -> ExactNameObservation {
        // SAFETY: `encoded_path` is NUL-terminated and lives for the call.
        let raw = unsafe {
            CreateFileW(
                encoded_path.as_ptr(),
                ACTIVE_READ_ACCESS,
                ACTIVE_READ_SHARE,
                NULL_CREATE_SECURITY_ATTRIBUTES,
                ACTIVE_READ_DISPOSITION,
                ACTIVE_READ_FLAGS,
                NULL_CREATE_TEMPLATE_HANDLE,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            // SAFETY: captured immediately after the failed exact-name open.
            return match unsafe { GetLastError() } {
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => ExactNameObservation::Absent,
                _ => ExactNameObservation::Unavailable,
            };
        }
        // SAFETY: ownership of the fresh successful handle is transferred once.
        let mut file = File::from(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) });
        if validate_disk_handle(&file).is_err() {
            return ExactNameObservation::UnexpectedEntryType;
        }
        let Ok((standard, attributes)) = query_entry_information(&file) else {
            return ExactNameObservation::Unavailable;
        };
        if standard.Directory
            || attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return ExactNameObservation::UnexpectedEntryType;
        }
        let Ok(initial_size) = size_from_standard_information(standard) else {
            return ExactNameObservation::UnexpectedBytesOrMalformed;
        };
        let Ok(final_path) = query_final_guid_path(&file) else {
            return ExactNameObservation::Unavailable;
        };
        if path.file_name() != Some(OsStr::new(expected_name))
            || validate_expected_child_final_path(&final_path, directory_final_path, expected_name)
                .is_err()
        {
            return ExactNameObservation::UnexpectedEntryType;
        }
        let Ok(identity) = query_file_identity(&file) else {
            return ExactNameObservation::Unavailable;
        };
        let Ok(loaded) = read_bounded_protected_wrapper(&mut file, initial_size) else {
            return ExactNameObservation::UnexpectedBytesOrMalformed;
        };
        let Ok((after_read, _)) = query_entry_information(&file) else {
            return ExactNameObservation::Unavailable;
        };
        if size_from_standard_information(after_read).ok() != Some(initial_size)
            || query_file_identity(&file).ok() != Some(identity)
        {
            return ExactNameObservation::Unavailable;
        }
        if EncodedProtectedWrapper::validate_authentication_key_bytes(loaded.as_bytes()).is_err() {
            return ExactNameObservation::UnexpectedBytesOrMalformed;
        }
        if loaded.as_bytes() == old_bytes {
            ExactNameObservation::RegularOld(identity)
        } else if loaded.as_bytes() == replacement_bytes {
            ExactNameObservation::RegularNew(identity)
        } else {
            ExactNameObservation::UnexpectedBytesOrMalformed
        }
    }

    fn fresh_exact_name_observations(
        paths: &InstallationEvidencePersistencePaths,
        old_bytes: &[u8],
        replacement_bytes: &[u8],
    ) -> (ExactNameObservation, ExactNameObservation) {
        let Ok((directory, directory_final_path)) =
            open_and_validate_directory(paths.evidence_directory.as_path())
        else {
            return (
                ExactNameObservation::Unavailable,
                ExactNameObservation::Unavailable,
            );
        };
        let Ok(active_path) = encode_utf16_path(paths.active_authentication_key.as_path()) else {
            return (
                ExactNameObservation::Unavailable,
                ExactNameObservation::Unavailable,
            );
        };
        let Ok(stage_path) = encode_utf16_path(paths.staged_authentication_key.as_path()) else {
            return (
                ExactNameObservation::Unavailable,
                ExactNameObservation::Unavailable,
            );
        };
        let active = observe_exact_name(
            paths.active_authentication_key.as_path(),
            &active_path,
            ACTIVE_AUTHENTICATION_KEY_FILENAME,
            &directory_final_path,
            old_bytes,
            replacement_bytes,
        );
        let stage = observe_exact_name(
            paths.staged_authentication_key.as_path(),
            &stage_path,
            STAGED_AUTHENTICATION_KEY_FILENAME,
            &directory_final_path,
            old_bytes,
            replacement_bytes,
        );
        drop(directory);
        (active, stage)
    }

    fn attempt_existing_replacement_with<F>(
        paths: &InstallationEvidencePersistencePaths,
        expected_old_bytes: &[u8],
        expected_replacement_bytes: &[u8],
        deliberate_blocker: Option<File>,
        replace_once: F,
    ) -> Result<ReplacementAttemptReport, ExistingFileReplacementError>
    where
        F: FnOnce(&[u16], &[u16]) -> ReplacementCallOutcome,
    {
        let preflight =
            preflight_existing_replacement(paths, expected_old_bytes, expected_replacement_bytes)?;
        let active = encode_utf16_path(paths.active_authentication_key.as_path())
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        let stage = encode_utf16_path(paths.staged_authentication_key.as_path())
            .map_err(|_| ExistingFileReplacementError::PreflightValidationFailed)?;
        let outcome = replace_once(&active, &stage);
        drop(deliberate_blocker);
        let (active_observation, stage_observation) =
            fresh_exact_name_observations(paths, expected_old_bytes, expected_replacement_bytes);
        let classification =
            classify_replacement_observation(outcome, active_observation, stage_observation);
        Ok(ReplacementAttemptReport {
            outcome,
            classification,
            active: active_observation,
            stage: stage_observation,
            preflight,
        })
    }

    fn prove_existing_replacement(
        paths: &InstallationEvidencePersistencePaths,
        expected_old_bytes: &[u8],
        expected_replacement_bytes: &[u8],
    ) -> Result<ExistingFileReplacementProof, ExistingFileReplacementError> {
        let report = attempt_existing_replacement_with(
            paths,
            expected_old_bytes,
            expected_replacement_bytes,
            None,
            call_replace_file_once,
        )?;
        if matches!(report.outcome, ReplacementCallOutcome::Failure(_)) {
            return Err(ExistingFileReplacementError::ReplacementFailed);
        }
        if report.classification != ReplacementObservationClass::ActiveNewStageAbsent {
            return Err(ExistingFileReplacementError::ReplacementStateAmbiguous);
        }
        let ExactNameObservation::RegularNew(result_identity) = report.active else {
            return Err(ExistingFileReplacementError::ReplacementVerificationFailed);
        };
        if report.stage != ExactNameObservation::Absent
            || result_identity != report.preflight.staged_replacement_identity
            || result_identity == report.preflight.old_active_identity
        {
            return Err(ExistingFileReplacementError::ReplacementVerificationFailed);
        }
        Ok(ExistingFileReplacementProof {
            active_replacement_verified: true,
            stage_absence_verified: true,
            stage_identity_continuity_verified: true,
            old_active_identity_replaced: true,
        })
    }

    static TEST_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);
    const SENTINEL_NAME: &str = "unrelated-sentinel.synthetic";
    const SENTINEL_CONTENT: &[u8] = b"synthetic-sentinel-preserved";

    struct TestRoot {
        root: PathBuf,
        sentinel: PathBuf,
        paths: InstallationEvidencePersistencePaths,
        cleaned: bool,
    }

    impl TestRoot {
        fn create() -> Self {
            let counter = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock must follow epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "church-app-wrapper-proof-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("unique test root must not already exist");
            let paths = installation_evidence_persistence_paths(&root);
            fs::create_dir(paths.evidence_directory.as_path())
                .expect("synthetic evidence directory must be created");
            let sentinel = root.join(SENTINEL_NAME);
            fs::write(&sentinel, SENTINEL_CONTENT).expect("synthetic sentinel must be written");
            Self {
                root,
                sentinel,
                paths,
                cleaned: false,
            }
        }

        fn assert_sentinel(&self) {
            assert_eq!(fs::read(&self.sentinel).unwrap(), SENTINEL_CONTENT);
        }

        fn cleanup(mut self) -> PathBuf {
            let removed = self.root.clone();
            fs::remove_dir_all(&removed).expect("only the unique test root is removed");
            self.cleaned = true;
            assert!(!removed.exists());
            removed
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if !self.cleaned {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    fn authentication_key_wrapper(blob_length: usize, pattern: u8) -> Vec<u8> {
        assert!((1..=65_536).contains(&blob_length));
        EncodedProtectedWrapper::synthetic_authentication_key_for_publication_test(vec![
            pattern;
            blob_length
        ])
        .unwrap()
        .as_bytes()
        .to_vec()
    }

    fn authenticated_evidence_wrapper(blob_length: usize, pattern: u8) -> Vec<u8> {
        assert!((1..=65_536).contains(&blob_length));
        EncodedProtectedWrapper::synthetic_authenticated_evidence_for_loader_test(vec![
            pattern;
            blob_length
        ])
        .unwrap()
        .as_bytes()
        .to_vec()
    }

    fn assert_successful_flow(blob_length: usize, pattern: u8) {
        let fixture = TestRoot::create();
        let intended = authentication_key_wrapper(blob_length, pattern);
        let proof =
            publish_synthetic_authentication_key_wrapper(&fixture.paths, &intended).unwrap();
        assert_eq!(
            proof,
            TemporaryPublicationProof {
                stage_reload_verified: true,
                published_without_replacement: true,
                active_reload_verified: true,
            }
        );
        assert!(!fixture.paths.staged_authentication_key.as_path().exists());
        assert!(fixture.paths.active_authentication_key.as_path().is_file());
        assert_eq!(
            fs::read(fixture.paths.active_authentication_key.as_path()).unwrap(),
            intended
        );
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    fn prepare_existing_replacement(
        fixture: &TestRoot,
        old_bytes: &[u8],
        replacement_bytes: &[u8],
    ) -> FileIdentity {
        publish_synthetic_authentication_key_wrapper(&fixture.paths, old_bytes).unwrap();
        create_and_verify_replacement_stage(&fixture.paths, replacement_bytes).unwrap()
    }

    fn assert_successful_replacement_flow(
        old_blob_length: usize,
        replacement_blob_length: usize,
        pattern: u8,
    ) {
        let fixture = TestRoot::create();
        let old_bytes = authentication_key_wrapper(old_blob_length, pattern);
        let replacement_bytes =
            authentication_key_wrapper(replacement_blob_length, pattern.wrapping_add(1));
        let staged_identity =
            prepare_existing_replacement(&fixture, &old_bytes, &replacement_bytes);
        let proof =
            prove_existing_replacement(&fixture.paths, &old_bytes, &replacement_bytes).unwrap();
        assert_eq!(
            proof,
            ExistingFileReplacementProof {
                active_replacement_verified: true,
                stage_absence_verified: true,
                stage_identity_continuity_verified: true,
                old_active_identity_replaced: true,
            }
        );
        assert_eq!(
            fs::read(fixture.paths.active_authentication_key.as_path()).unwrap(),
            replacement_bytes
        );
        assert!(!fixture.paths.staged_authentication_key.as_path().exists());
        assert!(NULL_REPLACE_BACKUP_PATH.is_null());
        assert!(
            !fixture
                .paths
                .evidence_directory
                .as_path()
                .join("authentication-key.dpapi.backup")
                .exists()
        );
        let active_path =
            encode_utf16_path(fixture.paths.active_authentication_key.as_path()).unwrap();
        let active_file = open_for_read(&active_path).unwrap();
        assert!(query_file_identity(&active_file).unwrap() == staged_identity);
        drop(active_file);
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    // HARDENING PROOF START: fixture orchestration remains inside the Windows test module.
    const HARDENING_INTERMEDIATE_NAME: &str = "ordinary-component";
    struct HardeningProof {
        retained_directory_count: usize,
        directory_identities_stable: bool,
        wrapper_facts_stable: bool,
    }

    fn open_retained_hardening_directories(
        root: &Path,
        intermediate: &Path,
        intermediate_name: &str,
        paths: &InstallationEvidencePersistencePaths,
    ) -> Result<Vec<RetainedDirectory>, HardeningError> {
        let temporary_parent = root.parent().ok_or(HardeningError::PathUnavailable)?;
        let temporary_parent = open_hardened_directory(temporary_parent, None)?;
        let root_name = root
            .file_name()
            .ok_or(HardeningError::PathUnavailable)?
            .encode_wide()
            .collect::<Vec<_>>();
        let root = open_hardened_directory(root, Some((&temporary_parent.initial, &root_name)))?;
        let intermediate = open_hardened_directory(
            intermediate,
            Some((&root.initial, &ascii_units(intermediate_name))),
        )?;
        let evidence = open_hardened_directory(
            paths.evidence_directory.as_path(),
            Some((
                &intermediate.initial,
                &ascii_units(INSTALLATION_EVIDENCE_DIRECTORY_NAME),
            )),
        )?;
        Ok(vec![temporary_parent, root, intermediate, evidence])
    }

    fn prove_normal_tree_hardening(
        fixture: &HardeningTestRoot,
        leaf: &Path,
        expected_name: &str,
    ) -> Result<HardeningProof, HardeningError> {
        let retained = open_retained_hardening_directories(
            &fixture.root,
            &fixture.intermediate,
            HARDENING_INTERMEDIATE_NAME,
            &fixture.paths,
        )?;
        inspect_hardened_authentication_key_wrapper(leaf, expected_name, &retained)?;
        Ok(HardeningProof {
            retained_directory_count: retained.len(),
            directory_identities_stable: true,
            wrapper_facts_stable: true,
        })
    }

    struct HardeningTestRoot {
        root: PathBuf,
        intermediate: PathBuf,
        sentinel: PathBuf,
        paths: InstallationEvidencePersistencePaths,
        cleaned: bool,
    }

    impl HardeningTestRoot {
        fn create(active: &[u8], staged: &[u8]) -> Self {
            let counter = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock must follow epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "church-app-normal-tree-proof-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("unique test root must be new");
            let intermediate = root.join(HARDENING_INTERMEDIATE_NAME);
            fs::create_dir(&intermediate).expect("ordinary intermediate must be created");
            let paths = installation_evidence_persistence_paths(&intermediate);
            fs::create_dir(paths.evidence_directory.as_path())
                .expect("exact evidence directory must be created");
            fs::write(paths.active_authentication_key.as_path(), active)
                .expect("synthetic active wrapper must be written");
            fs::write(paths.staged_authentication_key.as_path(), staged)
                .expect("synthetic staged wrapper must be written");
            let sentinel = root.join(SENTINEL_NAME);
            fs::write(&sentinel, SENTINEL_CONTENT).expect("synthetic sentinel must be written");
            Self {
                root,
                intermediate,
                sentinel,
                paths,
                cleaned: false,
            }
        }

        fn assert_sentinel(&self) {
            assert_eq!(fs::read(&self.sentinel).unwrap(), SENTINEL_CONTENT);
        }

        fn cleanup(mut self) -> PathBuf {
            let removed = self.root.clone();
            fs::remove_dir_all(&removed).expect("only the exact unique test root is removed");
            self.cleaned = true;
            assert!(!removed.exists());
            removed
        }
    }

    impl Drop for HardeningTestRoot {
        fn drop(&mut self) {
            if !self.cleaned {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    struct ActiveWrapperLoaderTestRoot {
        root: PathBuf,
        sentinel: PathBuf,
        paths: InstallationEvidencePersistencePaths,
        cleaned: bool,
    }

    impl ActiveWrapperLoaderTestRoot {
        fn create(active: &[u8]) -> Self {
            let counter = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock must follow epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "church-app-active-wrapper-loader-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("unique active-wrapper loader root must be new");
            let paths = installation_evidence_persistence_paths(&root);
            fs::create_dir(paths.evidence_directory.as_path())
                .expect("exact evidence directory must be created");
            fs::write(paths.active_authentication_key.as_path(), active)
                .expect("synthetic active authentication-key wrapper must be written");
            let sentinel = root.join(SENTINEL_NAME);
            fs::write(&sentinel, SENTINEL_CONTENT).expect("synthetic sentinel must be written");
            Self {
                root,
                sentinel,
                paths,
                cleaned: false,
            }
        }

        fn assert_sentinel(&self) {
            assert_eq!(fs::read(&self.sentinel).unwrap(), SENTINEL_CONTENT);
        }

        fn cleanup(mut self) -> PathBuf {
            let removed = self.root.clone();
            fs::remove_dir_all(&removed).expect("only the exact loader test root is removed");
            self.cleaned = true;
            assert!(!removed.exists());
            removed
        }
    }

    impl Drop for ActiveWrapperLoaderTestRoot {
        fn drop(&mut self) {
            if !self.cleaned {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    struct ActiveAuthenticatedEvidenceLoaderTestRoot {
        root: PathBuf,
        sentinel: PathBuf,
        paths: InstallationEvidencePersistencePaths,
        cleaned: bool,
    }

    impl ActiveAuthenticatedEvidenceLoaderTestRoot {
        fn create(active: &[u8]) -> Self {
            let counter = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock must follow epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "church-app-active-authenticated-evidence-loader-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir(&root)
                .expect("unique active authenticated-evidence loader root must be new");
            let paths = installation_evidence_persistence_paths(&root);
            fs::create_dir(paths.evidence_directory.as_path())
                .expect("exact evidence directory must be created");
            fs::write(paths.active_authenticated_evidence.as_path(), active)
                .expect("synthetic active authenticated-evidence wrapper must be written");
            let sentinel = root.join(SENTINEL_NAME);
            fs::write(&sentinel, SENTINEL_CONTENT).expect("synthetic sentinel must be written");
            Self {
                root,
                sentinel,
                paths,
                cleaned: false,
            }
        }

        fn assert_sentinel(&self) {
            assert_eq!(fs::read(&self.sentinel).unwrap(), SENTINEL_CONTENT);
        }

        fn cleanup(mut self) -> PathBuf {
            let removed = self.root.clone();
            fs::remove_dir_all(&removed)
                .expect("only the exact active authenticated-evidence loader root is removed");
            self.cleaned = true;
            assert!(!removed.exists());
            removed
        }
    }

    impl Drop for ActiveAuthenticatedEvidenceLoaderTestRoot {
        fn drop(&mut self) {
            if !self.cleaned {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    fn synthetic_observation(
        serial: u64,
        id_byte: u8,
        link_count: u32,
        path: &str,
    ) -> HardeningObservation {
        HardeningObservation {
            identity: HandleIdentity {
                volume_serial: serial,
                file_id: [id_byte; 16],
            },
            size: MINIMUM_PROTECTED_WRAPPER_LENGTH,
            attributes: FILE_ATTRIBUTE_NORMAL,
            reparse_tag: 0,
            link_count,
            final_path: ascii_units(path),
        }
    }
    // HARDENING PROOF END.

    // HARD-LINK FIXTURE START: real filesystem mutation remains Windows-test-only.
    mod hard_link_fixture {
        use super::*;
        use std::cell::Cell;

        const ALIAS_NAME: &str = "wrapper-hard-link-alias.synthetic";
        const INTERMEDIATE_NAME: &str = "synthetic-component";

        struct Fixture {
            root: PathBuf,
            intermediate: PathBuf,
            sentinel: PathBuf,
            paths: InstallationEvidencePersistencePaths,
            wrapper: PathBuf,
            alias: PathBuf,
            cleaned: bool,
        }

        impl Fixture {
            fn create(expected_name: &str, canonical: &[u8]) -> Self {
                let counter = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("test clock must follow epoch")
                    .as_nanos();
                let root = std::env::temp_dir().join(format!(
                    "church-app-hard-link-proof-{}-{nanos}-{counter}",
                    std::process::id()
                ));
                fs::create_dir(&root).expect("unique hard-link test root must be new");
                let intermediate = root.join(INTERMEDIATE_NAME);
                fs::create_dir(&intermediate).expect("synthetic component must be created");
                let paths = installation_evidence_persistence_paths(&intermediate);
                fs::create_dir(paths.evidence_directory.as_path())
                    .expect("exact evidence directory must be created");
                let wrapper = paths.evidence_directory.as_path().join(expected_name);
                fs::write(&wrapper, canonical)
                    .expect("canonical synthetic wrapper must be written");
                let alias = paths.evidence_directory.as_path().join(ALIAS_NAME);
                let sentinel = root.join(SENTINEL_NAME);
                fs::write(&sentinel, SENTINEL_CONTENT).expect("synthetic sentinel must be written");
                Self {
                    root,
                    intermediate,
                    sentinel,
                    paths,
                    wrapper,
                    alias,
                    cleaned: false,
                }
            }

            fn assert_sentinel(&self) {
                assert_eq!(fs::read(&self.sentinel).unwrap(), SENTINEL_CONTENT);
            }

            fn cleanup(mut self) -> PathBuf {
                let removed = self.root.clone();
                fs::remove_dir_all(&removed).expect("only the exact unique test root is removed");
                self.cleaned = true;
                assert!(!removed.exists());
                removed
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                if !self.cleaned {
                    let _ = fs::remove_dir_all(&self.root);
                }
            }
        }

        fn open_observation(path: &Path) -> (File, HardeningObservation) {
            let encoded = encode_utf16_path(path).expect("fixture path must encode");
            let file = open_for_read(&encoded).expect("fixture wrapper must open");
            let observation = query_hardening_observation(&file)
                .expect("fixture wrapper facts must be available");
            (file, observation)
        }

        fn bounded_read_canonical_wrapper(
            file: &mut File,
            before: &HardeningObservation,
        ) -> Vec<u8> {
            let loaded = read_bounded_protected_wrapper(file, before.size)
                .expect("fixture wrapper must pass the existing bounded reader");
            EncodedProtectedWrapper::validate_authentication_key_bytes(loaded.as_bytes())
                .expect("fixture wrapper must be canonical kind 1");
            let after = query_hardening_observation(file)
                .expect("fixture wrapper facts must remain available");
            validate_stable_observations(Some(before), Some(&after))
                .expect("fixture wrapper facts must remain stable across bounded reading");
            loaded.as_bytes().to_vec()
        }

        fn assert_case(expected_name: &str, pattern: u8) {
            for approved_name in [
                PRODUCTION_DATABASE_FILENAME,
                PRODUCTION_DATABASE_STAGE_FILENAME,
                ACTIVE_AUTHENTICATION_KEY_FILENAME,
                ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME,
                STAGED_AUTHENTICATION_KEY_FILENAME,
                STAGED_AUTHENTICATED_EVIDENCE_FILENAME,
            ] {
                assert!(!ALIAS_NAME.starts_with(approved_name));
                assert!(!ALIAS_NAME.contains(approved_name));
            }
            let canonical = authentication_key_wrapper(64, pattern);
            EncodedProtectedWrapper::validate_authentication_key_bytes(&canonical).unwrap();
            let fixture = Fixture::create(expected_name, &canonical);

            let (original_before_alias, original_initial) = open_observation(&fixture.wrapper);
            assert_eq!(original_initial.link_count, 1);
            let initial_identity = original_initial.identity;
            drop(original_before_alias);

            std::fs::hard_link(&fixture.wrapper, &fixture.alias)
                .unwrap_or_else(|_| panic!("local hard-link fixture prerequisite unavailable"));

            let retained = open_retained_hardening_directories(
                &fixture.root,
                &fixture.intermediate,
                INTERMEDIATE_NAME,
                &fixture.paths,
            )
            .unwrap();
            let evidence = retained
                .last()
                .expect("retained evidence-directory handle must exist");
            let (mut original, original_linked) = open_observation(&fixture.wrapper);
            let (mut alias, alias_linked) = open_observation(&fixture.alias);
            assert_eq!(original_linked.link_count, 2);
            assert_eq!(alias_linked.link_count, 2);
            assert_eq!(
                original_linked.identity.volume_serial,
                alias_linked.identity.volume_serial
            );
            assert_eq!(
                original_linked.identity.file_id,
                alias_linked.identity.file_id
            );
            assert_eq!(original_linked.identity, initial_identity);
            assert_ne!(original_linked.final_path, alias_linked.final_path);
            validate_same_volume(&evidence.initial, &original_linked).unwrap();
            validate_same_volume(&evidence.initial, &alias_linked).unwrap();
            exact_child_final_path(
                &evidence.initial.final_path,
                &original_linked.final_path,
                &ascii_units(expected_name),
            )
            .unwrap();
            exact_child_final_path(
                &evidence.initial.final_path,
                &alias_linked.final_path,
                &ascii_units(ALIAS_NAME),
            )
            .unwrap();
            validate_approved_wrapper_name(&fixture.wrapper, expected_name).unwrap();
            assert_eq!(
                validate_approved_wrapper_name(&fixture.alias, expected_name),
                Err(HardeningError::FinalPathMismatch)
            );
            let original_bytes = bounded_read_canonical_wrapper(&mut original, &original_linked);
            let alias_bytes = bounded_read_canonical_wrapper(&mut alias, &alias_linked);
            assert_eq!(original_bytes, alias_bytes);
            assert_eq!(original_bytes, canonical);
            assert_eq!(alias_bytes, canonical);
            drop(original);
            drop(alias);

            let mutation_calls = Cell::new(0_u8);
            let bounded_read_calls = Cell::new(0_u8);
            let result = inspect_hardened_authentication_key_wrapper_with(
                &fixture.wrapper,
                expected_name,
                &retained,
                || mutation_calls.set(mutation_calls.get() + 1),
                |file, size| {
                    bounded_read_calls.set(bounded_read_calls.get() + 1);
                    read_bounded_protected_wrapper(file, size)
                },
            );
            assert_eq!(result, Err(HardeningError::HardLinkRejected));
            assert_eq!(mutation_calls.get(), 0);
            assert_eq!(bounded_read_calls.get(), 0);
            drop(retained);

            fs::remove_file(&fixture.alias).expect("only the synthetic alias is removed");
            assert!(!fixture.alias.exists());
            let (mut restored, restored_observation) = open_observation(&fixture.wrapper);
            assert_eq!(restored_observation.link_count, 1);
            assert_eq!(restored_observation.identity, initial_identity);
            let restored_bytes =
                bounded_read_canonical_wrapper(&mut restored, &restored_observation);
            assert_eq!(restored_bytes, canonical);
            drop(restored);
            fixture.assert_sentinel();
            fixture.cleanup();
        }

        #[test]
        fn active_and_staged_wrappers_reject_a_real_second_hard_link_before_read_or_mutation() {
            let source = include_str!("windows_filesystem.rs");
            let fixture_source = source
                .split_once("// HARD-LINK FIXTURE START")
                .unwrap()
                .1
                .split_once("// HARD-LINK FIXTURE END")
                .unwrap()
                .0;
            assert_eq!(
                fixture_source
                    .matches(concat!("std::fs::", "hard_link("))
                    .count(),
                1
            );
            assert_eq!(
                fixture_source.matches(concat!("fs::", "read(")).count(),
                1,
                "only sentinel checking may use fs::read"
            );
            for forbidden in [
                concat!("Create", "HardLinkW"),
                concat!("Create", "HardLink"),
                concat!("publish_synthetic_", "authentication_key_wrapper("),
                concat!("prove_existing_", "replacement("),
                concat!("Replace", "FileW("),
                concat!("Move", "FileExW("),
                concat!("Command::", "new"),
                concat!("fs", "util"),
            ] {
                assert!(
                    !fixture_source.contains(forbidden),
                    "forbidden fixture source: {forbidden}"
                );
            }
            for (expected_name, pattern) in [
                (ACTIVE_AUTHENTICATION_KEY_FILENAME, 0xd1),
                (STAGED_AUTHENTICATION_KEY_FILENAME, 0xd2),
            ] {
                assert_case(expected_name, pattern);
            }
        }
    }
    // HARD-LINK FIXTURE END.

    // DIRECTORY SUBSTITUTION FIXTURE START: all mutation remains Windows-test-only.
    mod directory_substitution_fixture {
        use super::*;
        use std::cell::Cell;
        use std::os::windows::fs::OpenOptionsExt;

        const DISPLACED_NAME: &str = "evidence-displaced.synthetic";
        const CANDIDATE_NAME: &str = "substitute-candidate.synthetic";
        const INTERMEDIATE_NAME: &str = "ordinary-component";
        const ROOT_PREFIX: &str = "church-app-directory-substitution-proof-";

        #[derive(Clone, Copy, Eq, PartialEq)]
        enum ProofFailure {
            RenameUnexpectedlySucceeded,
            RenameFailedAfterRelease,
            SubstitutionDetected,
            IdentityUnexpectedlyMatched,
            AncestorIdentityChanged,
            PathUnexpected,
            FixtureUnavailable,
        }

        impl fmt::Debug for ProofFailure {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(match self {
                    Self::RenameUnexpectedlySucceeded => "RenameUnexpectedlySucceeded",
                    Self::RenameFailedAfterRelease => "RenameFailedAfterRelease",
                    Self::SubstitutionDetected => "SubstitutionDetected",
                    Self::IdentityUnexpectedlyMatched => "IdentityUnexpectedlyMatched",
                    Self::AncestorIdentityChanged => "AncestorIdentityChanged",
                    Self::PathUnexpected => "PathUnexpected",
                    Self::FixtureUnavailable => "FixtureUnavailable",
                })
            }
        }

        #[derive(Clone, Copy, Eq, PartialEq)]
        enum FixtureError {
            Proof(ProofFailure),
            CleanupFailed,
            ProofFailedAndCleanupFailed(ProofFailure),
        }

        impl fmt::Debug for FixtureError {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(match self {
                    Self::Proof(failure) => match failure {
                        ProofFailure::RenameUnexpectedlySucceeded => "RenameUnexpectedlySucceeded",
                        ProofFailure::RenameFailedAfterRelease => "RenameFailedAfterRelease",
                        ProofFailure::SubstitutionDetected => "SubstitutionDetected",
                        ProofFailure::IdentityUnexpectedlyMatched => "IdentityUnexpectedlyMatched",
                        ProofFailure::AncestorIdentityChanged => "AncestorIdentityChanged",
                        ProofFailure::PathUnexpected => "PathUnexpected",
                        ProofFailure::FixtureUnavailable => "FixtureUnavailable",
                    },
                    Self::CleanupFailed => "CleanupFailed",
                    Self::ProofFailedAndCleanupFailed(_) => "ProofFailedAndCleanupFailed",
                })
            }
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum RenameObservation {
            RenameBlocked,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum ContinuityObservation {
            ContinuousIdentity,
            SubstitutedIdentity,
            InvalidPath,
            AncestorIdentityChanged,
            InspectionUnavailable,
        }

        #[derive(Clone, Eq, PartialEq)]
        struct WrapperSnapshot {
            identity: HandleIdentity,
            final_path: Vec<u16>,
            bytes: Vec<u8>,
        }

        #[derive(Debug, Eq, PartialEq)]
        struct ProofReport {
            initial_identities_differed: bool,
            initial_wrappers_equal: bool,
            blocked_rename: RenameObservation,
            blocked_original_unchanged: bool,
            blocked_candidate_unchanged: bool,
            blocked_wrappers_unchanged: bool,
            ancestor_handles_retained: usize,
            displaced_retained_original_identity: bool,
            exact_path_retained_candidate_identity: bool,
            exact_path_differed_from_original: bool,
            post_substitution_wrappers_equal: bool,
            continuity: ContinuityObservation,
            continuation_calls: u8,
            publication_calls: u8,
            replacement_calls: u8,
            wrapper_mutation_calls: u8,
            sentinel_preserved: bool,
            exact_root_removed: bool,
        }

        // DIRECTORY SUBSTITUTION IMPLEMENTATION START.
        struct Fixture {
            root: PathBuf,
            intermediate: PathBuf,
            original: PathBuf,
            displaced: PathBuf,
            candidate: PathBuf,
            original_wrapper: PathBuf,
            candidate_wrapper: PathBuf,
            sentinel: PathBuf,
            cleanup_attempted: bool,
        }

        impl Fixture {
            fn create(canonical: &[u8]) -> Result<Self, FixtureError> {
                let counter = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| FixtureError::Proof(ProofFailure::FixtureUnavailable))?
                    .as_nanos();
                let root = std::env::temp_dir().join(format!(
                    "{ROOT_PREFIX}{}-{nanos}-{counter}",
                    std::process::id()
                ));
                fs::create_dir(&root)
                    .map_err(|_| FixtureError::Proof(ProofFailure::FixtureUnavailable))?;
                let intermediate = root.join(INTERMEDIATE_NAME);
                let original = intermediate.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME);
                let candidate = intermediate.join(CANDIDATE_NAME);
                let mut fixture = Self {
                    displaced: intermediate.join(DISPLACED_NAME),
                    original_wrapper: original.join(ACTIVE_AUTHENTICATION_KEY_FILENAME),
                    candidate_wrapper: candidate.join(ACTIVE_AUTHENTICATION_KEY_FILENAME),
                    sentinel: root.join(SENTINEL_NAME),
                    root,
                    intermediate,
                    original,
                    candidate,
                    cleanup_attempted: false,
                };
                let setup = (|| -> Result<(), FixtureError> {
                    fs::create_dir(&fixture.intermediate)
                        .map_err(|_| FixtureError::Proof(ProofFailure::FixtureUnavailable))?;
                    fs::create_dir(&fixture.original)
                        .map_err(|_| FixtureError::Proof(ProofFailure::FixtureUnavailable))?;
                    fs::create_dir(&fixture.candidate)
                        .map_err(|_| FixtureError::Proof(ProofFailure::FixtureUnavailable))?;
                    fs::write(&fixture.original_wrapper, canonical)
                        .map_err(|_| FixtureError::Proof(ProofFailure::FixtureUnavailable))?;
                    fs::write(&fixture.candidate_wrapper, canonical)
                        .map_err(|_| FixtureError::Proof(ProofFailure::FixtureUnavailable))?;
                    fs::write(&fixture.sentinel, SENTINEL_CONTENT)
                        .map_err(|_| FixtureError::Proof(ProofFailure::FixtureUnavailable))?;
                    Ok(())
                })();
                if let Err(primary) = setup {
                    let primary_failure = match primary {
                        FixtureError::Proof(failure)
                        | FixtureError::ProofFailedAndCleanupFailed(failure) => failure,
                        FixtureError::CleanupFailed => ProofFailure::FixtureUnavailable,
                    };
                    return match fixture.cleanup_once() {
                        Ok(()) => Err(FixtureError::Proof(primary_failure)),
                        Err(_) => Err(FixtureError::ProofFailedAndCleanupFailed(primary_failure)),
                    };
                }
                Ok(fixture)
            }

            fn sentinel_bytes(&self) -> Result<Vec<u8>, ProofFailure> {
                fs::read(&self.sentinel).map_err(|_| ProofFailure::FixtureUnavailable)
            }

            fn validate_exact_layout(&self) -> Result<(), ProofFailure> {
                let root_names = exact_entry_names(&self.root)?;
                let intermediate_names = exact_entry_names(&self.intermediate)?;
                let original_names = exact_entry_names(&self.original)?;
                let candidate_names = exact_entry_names(&self.candidate)?;
                if root_names != [INTERMEDIATE_NAME, SENTINEL_NAME]
                    || intermediate_names != [INSTALLATION_EVIDENCE_DIRECTORY_NAME, CANDIDATE_NAME]
                    || original_names != [ACTIVE_AUTHENTICATION_KEY_FILENAME]
                    || candidate_names != [ACTIVE_AUTHENTICATION_KEY_FILENAME]
                {
                    return Err(ProofFailure::FixtureUnavailable);
                }
                Ok(())
            }

            fn cleanup_once(&mut self) -> Result<(), FixtureError> {
                self.cleanup_attempted = true;
                fs::remove_dir_all(&self.root).map_err(|_| FixtureError::CleanupFailed)?;
                if self.root.exists() {
                    return Err(FixtureError::CleanupFailed);
                }
                Ok(())
            }

            fn finish(
                mut self,
                result: Result<ProofReport, ProofFailure>,
            ) -> Result<ProofReport, FixtureError> {
                match (result, self.cleanup_once()) {
                    (Ok(mut report), Ok(())) => {
                        report.exact_root_removed = true;
                        Ok(report)
                    }
                    (Ok(_), Err(_)) => Err(FixtureError::CleanupFailed),
                    (Err(primary), Ok(())) => Err(FixtureError::Proof(primary)),
                    (Err(primary), Err(_)) => {
                        Err(FixtureError::ProofFailedAndCleanupFailed(primary))
                    }
                }
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                if !self.cleanup_attempted {
                    self.cleanup_attempted = true;
                    let _ = fs::remove_dir_all(&self.root);
                }
            }
        }

        fn exact_entry_names(path: &Path) -> Result<Vec<String>, ProofFailure> {
            let mut names = fs::read_dir(path)
                .map_err(|_| ProofFailure::FixtureUnavailable)?
                .map(|entry| {
                    entry
                        .map_err(|_| ProofFailure::FixtureUnavailable)?
                        .file_name()
                        .into_string()
                        .map_err(|_| ProofFailure::FixtureUnavailable)
                })
                .collect::<Result<Vec<_>, _>>()?;
            names.sort();
            Ok(names)
        }

        fn inspect_directory(
            path: &Path,
            parent: &HardeningObservation,
            expected_name: &str,
        ) -> Result<RetainedDirectory, ProofFailure> {
            open_hardened_directory(path, Some((parent, &ascii_units(expected_name)))).map_err(
                |error| match error {
                    HardeningError::FinalPathMismatch | HardeningError::SameVolumeMismatch => {
                        ProofFailure::PathUnexpected
                    }
                    _ => ProofFailure::FixtureUnavailable,
                },
            )
        }

        fn open_restrictive_evidence_directory(
            path: &Path,
            parent: &HardeningObservation,
        ) -> Result<RetainedDirectory, ProofFailure> {
            let handle = fs::OpenOptions::new()
                .access_mode(GENERIC_READ)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .map_err(|_| ProofFailure::FixtureUnavailable)?;
            let initial = query_hardening_observation(&handle)
                .map_err(|_| ProofFailure::FixtureUnavailable)?;
            if initial.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(ProofFailure::FixtureUnavailable);
            }
            validate_reparse_facts(initial.attributes, initial.reparse_tag)
                .map_err(|_| ProofFailure::FixtureUnavailable)?;
            validate_same_volume(parent, &initial).map_err(|_| ProofFailure::PathUnexpected)?;
            exact_child_final_path(
                &parent.final_path,
                &initial.final_path,
                &ascii_units(INSTALLATION_EVIDENCE_DIRECTORY_NAME),
            )
            .map_err(|_| ProofFailure::PathUnexpected)?;
            Ok(RetainedDirectory { handle, initial })
        }

        fn inspect_wrapper(
            path: &Path,
            directory: &HardeningObservation,
        ) -> Result<WrapperSnapshot, ProofFailure> {
            validate_approved_wrapper_name(path, ACTIVE_AUTHENTICATION_KEY_FILENAME)
                .map_err(|_| ProofFailure::PathUnexpected)?;
            let encoded = encode_utf16_path(path).map_err(|_| ProofFailure::PathUnexpected)?;
            let mut file = open_for_read(&encoded).map_err(|_| ProofFailure::FixtureUnavailable)?;
            let before =
                query_hardening_observation(&file).map_err(|_| ProofFailure::FixtureUnavailable)?;
            if before.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                return Err(ProofFailure::FixtureUnavailable);
            }
            validate_reparse_facts(before.attributes, before.reparse_tag)
                .map_err(|_| ProofFailure::FixtureUnavailable)?;
            validate_wrapper_link_count(before.link_count)
                .map_err(|_| ProofFailure::FixtureUnavailable)?;
            validate_same_volume(directory, &before).map_err(|_| ProofFailure::PathUnexpected)?;
            exact_child_final_path(
                &directory.final_path,
                &before.final_path,
                &ascii_units(ACTIVE_AUTHENTICATION_KEY_FILENAME),
            )
            .map_err(|_| ProofFailure::PathUnexpected)?;
            let loaded = read_bounded_protected_wrapper(&mut file, before.size)
                .map_err(|_| ProofFailure::FixtureUnavailable)?;
            EncodedProtectedWrapper::validate_authentication_key_bytes(loaded.as_bytes())
                .map_err(|_| ProofFailure::FixtureUnavailable)?;
            let after =
                query_hardening_observation(&file).map_err(|_| ProofFailure::FixtureUnavailable)?;
            validate_stable_observations(Some(&before), Some(&after))
                .map_err(|_| ProofFailure::FixtureUnavailable)?;
            Ok(WrapperSnapshot {
                identity: before.identity,
                final_path: before.final_path,
                bytes: loaded.as_bytes().to_vec(),
            })
        }

        fn retained_ancestors_stable(retained: &[RetainedDirectory]) -> Result<bool, ProofFailure> {
            for directory in retained {
                let identity = query_handle_identity(&directory.handle)
                    .map_err(|_| ProofFailure::FixtureUnavailable)?;
                let final_path = query_bounded_final_guid_path(&directory.handle)
                    .map_err(|_| ProofFailure::FixtureUnavailable)?;
                if identity != directory.initial.identity
                    || final_path != directory.initial.final_path
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        fn classify_continuity(
            saved: &HandleIdentity,
            current: Option<&HardeningObservation>,
            exact_path_valid: bool,
            ancestors_stable: bool,
        ) -> ContinuityObservation {
            let Some(current) = current else {
                return ContinuityObservation::InspectionUnavailable;
            };
            if !ancestors_stable {
                return ContinuityObservation::AncestorIdentityChanged;
            }
            if !exact_path_valid {
                return ContinuityObservation::InvalidPath;
            }
            if current.identity == *saved {
                ContinuityObservation::ContinuousIdentity
            } else {
                ContinuityObservation::SubstitutedIdentity
            }
        }

        fn continue_after_continuity<F>(
            observation: ContinuityObservation,
            continuation: F,
        ) -> Result<(), ProofFailure>
        where
            F: FnOnce(),
        {
            match observation {
                ContinuityObservation::ContinuousIdentity => {
                    continuation();
                    Ok(())
                }
                ContinuityObservation::SubstitutedIdentity => {
                    Err(ProofFailure::SubstitutionDetected)
                }
                ContinuityObservation::InvalidPath => Err(ProofFailure::PathUnexpected),
                ContinuityObservation::AncestorIdentityChanged => {
                    Err(ProofFailure::AncestorIdentityChanged)
                }
                ContinuityObservation::InspectionUnavailable => {
                    Err(ProofFailure::FixtureUnavailable)
                }
            }
        }

        fn blocked_rename_observation(succeeded: bool) -> Result<RenameObservation, ProofFailure> {
            if succeeded {
                Err(ProofFailure::RenameUnexpectedlySucceeded)
            } else {
                Ok(RenameObservation::RenameBlocked)
            }
        }

        fn run_proof() -> Result<ProofReport, FixtureError> {
            let canonical = authentication_key_wrapper(64, 0xe3);
            EncodedProtectedWrapper::validate_authentication_key_bytes(&canonical)
                .map_err(|_| FixtureError::Proof(ProofFailure::FixtureUnavailable))?;
            let fixture = Fixture::create(&canonical)?;
            let proof_result = (|| -> Result<ProofReport, ProofFailure> {
                fixture.validate_exact_layout()?;
                let sentinel_before = fixture.sentinel_bytes()?;
                if sentinel_before != SENTINEL_CONTENT {
                    return Err(ProofFailure::FixtureUnavailable);
                }

                let synthetic_paths =
                    installation_evidence_persistence_paths(&fixture.intermediate);
                let mut retained = open_retained_hardening_directories(
                    &fixture.root,
                    &fixture.intermediate,
                    INTERMEDIATE_NAME,
                    &synthetic_paths,
                )
                .map_err(|_| ProofFailure::FixtureUnavailable)?;
                if retained.len() != 4 {
                    return Err(ProofFailure::FixtureUnavailable);
                }
                let unrestricted_evidence =
                    retained.pop().ok_or(ProofFailure::FixtureUnavailable)?;
                drop(unrestricted_evidence);
                let intermediate_initial = retained
                    .get(2)
                    .ok_or(ProofFailure::FixtureUnavailable)?
                    .initial
                    .clone();
                retained.push(open_restrictive_evidence_directory(
                    &fixture.original,
                    &intermediate_initial,
                )?);
                let evidence = retained.last().ok_or(ProofFailure::FixtureUnavailable)?;
                let original_identity = evidence.initial.identity;
                let original_path = evidence.initial.final_path.clone();
                let intermediate = retained.get(2).ok_or(ProofFailure::FixtureUnavailable)?;
                let candidate =
                    inspect_directory(&fixture.candidate, &intermediate.initial, CANDIDATE_NAME)?;
                let candidate_identity = candidate.initial.identity;
                let candidate_path = candidate.initial.final_path.clone();
                if original_identity == candidate_identity {
                    return Err(ProofFailure::IdentityUnexpectedlyMatched);
                }
                validate_same_volume(&evidence.initial, &candidate.initial)
                    .map_err(|_| ProofFailure::PathUnexpected)?;
                let original_wrapper =
                    inspect_wrapper(&fixture.original_wrapper, &evidence.initial)?;
                let candidate_wrapper =
                    inspect_wrapper(&fixture.candidate_wrapper, &candidate.initial)?;
                if original_wrapper.bytes != canonical
                    || candidate_wrapper.bytes != canonical
                    || original_wrapper.bytes != candidate_wrapper.bytes
                {
                    return Err(ProofFailure::FixtureUnavailable);
                }
                drop(candidate);

                let blocked_rename = blocked_rename_observation(
                    std::fs::rename(&fixture.original, &fixture.displaced).is_ok(),
                )?;
                if !fixture.original.is_dir()
                    || fixture.displaced.exists()
                    || !fixture.candidate.is_dir()
                {
                    return Err(ProofFailure::PathUnexpected);
                }
                let blocked_original = inspect_directory(
                    &fixture.original,
                    &intermediate.initial,
                    INSTALLATION_EVIDENCE_DIRECTORY_NAME,
                )?;
                let blocked_candidate =
                    inspect_directory(&fixture.candidate, &intermediate.initial, CANDIDATE_NAME)?;
                let blocked_original_wrapper =
                    inspect_wrapper(&fixture.original_wrapper, &blocked_original.initial)?;
                let blocked_candidate_wrapper =
                    inspect_wrapper(&fixture.candidate_wrapper, &blocked_candidate.initial)?;
                let blocked_original_unchanged = blocked_original.initial.identity
                    == original_identity
                    && blocked_original.initial.final_path == original_path;
                let blocked_candidate_unchanged = blocked_candidate.initial.identity
                    == candidate_identity
                    && blocked_candidate.initial.final_path == candidate_path;
                let blocked_wrappers_unchanged = blocked_original_wrapper == original_wrapper
                    && blocked_candidate_wrapper == candidate_wrapper;
                if !blocked_original_unchanged
                    || blocked_candidate.initial.identity != candidate_identity
                    || blocked_candidate.initial.final_path
                        != exact_directory_path(&intermediate.initial.final_path, CANDIDATE_NAME)
                    || !blocked_wrappers_unchanged
                    || fixture.sentinel_bytes()? != sentinel_before
                    || !retained_ancestors_stable(&retained)?
                {
                    return Err(ProofFailure::FixtureUnavailable);
                }
                drop(blocked_original_wrapper);
                drop(blocked_candidate_wrapper);
                drop(blocked_original);
                drop(blocked_candidate);

                let evidence = retained.pop().ok_or(ProofFailure::FixtureUnavailable)?;
                drop(evidence);
                if retained.len() != 3 || !retained_ancestors_stable(&retained)? {
                    return Err(ProofFailure::AncestorIdentityChanged);
                }

                std::fs::rename(&fixture.original, &fixture.displaced)
                    .map_err(|_| ProofFailure::RenameFailedAfterRelease)?;
                std::fs::rename(&fixture.candidate, &fixture.original)
                    .map_err(|_| ProofFailure::RenameFailedAfterRelease)?;

                let intermediate = retained.get(2).ok_or(ProofFailure::FixtureUnavailable)?;
                let displaced =
                    inspect_directory(&fixture.displaced, &intermediate.initial, DISPLACED_NAME)?;
                let substitute = inspect_directory(
                    &fixture.original,
                    &intermediate.initial,
                    INSTALLATION_EVIDENCE_DIRECTORY_NAME,
                )?;
                if displaced.initial.identity != original_identity
                    || substitute.initial.identity != candidate_identity
                    || substitute.initial.identity == original_identity
                {
                    return Err(ProofFailure::IdentityUnexpectedlyMatched);
                }
                let displaced_wrapper_path =
                    fixture.displaced.join(ACTIVE_AUTHENTICATION_KEY_FILENAME);
                let substitute_wrapper_path =
                    fixture.original.join(ACTIVE_AUTHENTICATION_KEY_FILENAME);
                let displaced_wrapper =
                    inspect_wrapper(&displaced_wrapper_path, &displaced.initial)?;
                let substitute_wrapper =
                    inspect_wrapper(&substitute_wrapper_path, &substitute.initial)?;
                if displaced_wrapper.identity != original_wrapper.identity
                    || substitute_wrapper.identity != candidate_wrapper.identity
                    || displaced_wrapper.bytes != canonical
                    || substitute_wrapper.bytes != canonical
                    || displaced_wrapper.bytes != substitute_wrapper.bytes
                {
                    return Err(ProofFailure::FixtureUnavailable);
                }
                let ancestors_stable = retained_ancestors_stable(&retained)?;
                let exact_path_valid = exact_child_final_path(
                    &intermediate.initial.final_path,
                    &substitute.initial.final_path,
                    &ascii_units(INSTALLATION_EVIDENCE_DIRECTORY_NAME),
                )
                .is_ok();
                let continuity = classify_continuity(
                    &original_identity,
                    Some(&substitute.initial),
                    exact_path_valid,
                    ancestors_stable,
                );
                let continuation_calls = Cell::new(0_u8);
                let publication_calls = Cell::new(0_u8);
                let replacement_calls = Cell::new(0_u8);
                let wrapper_mutation_calls = Cell::new(0_u8);
                let detection = continue_after_continuity(continuity, || {
                    continuation_calls.set(continuation_calls.get() + 1);
                    publication_calls.set(publication_calls.get() + 1);
                    replacement_calls.set(replacement_calls.get() + 1);
                    wrapper_mutation_calls.set(wrapper_mutation_calls.get() + 1);
                });
                if detection != Err(ProofFailure::SubstitutionDetected)
                    || continuation_calls.get() != 0
                    || publication_calls.get() != 0
                    || replacement_calls.get() != 0
                    || wrapper_mutation_calls.get() != 0
                    || fixture.sentinel_bytes()? != sentinel_before
                {
                    return Err(ProofFailure::FixtureUnavailable);
                }
                drop(displaced_wrapper);
                drop(substitute_wrapper);
                drop(displaced);
                drop(substitute);
                drop(retained);

                Ok(ProofReport {
                    initial_identities_differed: original_identity != candidate_identity,
                    initial_wrappers_equal: original_wrapper.bytes == candidate_wrapper.bytes,
                    blocked_rename,
                    blocked_original_unchanged,
                    blocked_candidate_unchanged,
                    blocked_wrappers_unchanged,
                    ancestor_handles_retained: 3,
                    displaced_retained_original_identity: true,
                    exact_path_retained_candidate_identity: true,
                    exact_path_differed_from_original: true,
                    post_substitution_wrappers_equal: true,
                    continuity,
                    continuation_calls: continuation_calls.get(),
                    publication_calls: publication_calls.get(),
                    replacement_calls: replacement_calls.get(),
                    wrapper_mutation_calls: wrapper_mutation_calls.get(),
                    sentinel_preserved: true,
                    exact_root_removed: false,
                })
            })();
            fixture.finish(proof_result)
        }

        fn exact_directory_path(parent: &[u16], name: &str) -> Vec<u16> {
            let mut expected = parent.to_vec();
            if expected.last() != Some(&(b'\\' as u16)) {
                expected.push(b'\\' as u16);
            }
            expected.extend(ascii_units(name));
            expected
        }
        // DIRECTORY SUBSTITUTION IMPLEMENTATION END.

        #[test]
        fn exact_evidence_directory_substitution_is_detected_before_any_continuation() {
            let report = run_proof().unwrap();
            assert!(report.initial_identities_differed);
            assert!(report.initial_wrappers_equal);
            assert_eq!(report.blocked_rename, RenameObservation::RenameBlocked);
            assert!(report.blocked_original_unchanged);
            assert!(report.blocked_candidate_unchanged);
            assert!(report.blocked_wrappers_unchanged);
            assert_eq!(report.ancestor_handles_retained, 3);
            assert!(report.displaced_retained_original_identity);
            assert!(report.exact_path_retained_candidate_identity);
            assert!(report.exact_path_differed_from_original);
            assert!(report.post_substitution_wrappers_equal);
            assert_eq!(
                report.continuity,
                ContinuityObservation::SubstitutedIdentity
            );
            assert_eq!(report.continuation_calls, 0);
            assert_eq!(report.publication_calls, 0);
            assert_eq!(report.replacement_calls, 0);
            assert_eq!(report.wrapper_mutation_calls, 0);
            assert!(report.sentinel_preserved);
            assert!(report.exact_root_removed);
        }

        #[test]
        fn classifier_keeps_unavailable_invalid_ancestor_and_substitution_states_distinct() {
            let saved = HandleIdentity {
                volume_serial: 41,
                file_id: [1; 16],
            };
            let continuous = synthetic_observation(
                41,
                1,
                1,
                r"\\?\Volume{abcdef12-3456-7890-abcd-ef1234567890}\root\installation-evidence",
            );
            let substituted = synthetic_observation(
                41,
                2,
                1,
                r"\\?\Volume{abcdef12-3456-7890-abcd-ef1234567890}\root\installation-evidence",
            );
            assert_eq!(
                classify_continuity(&saved, Some(&continuous), true, true),
                ContinuityObservation::ContinuousIdentity
            );
            assert_eq!(
                classify_continuity(&saved, Some(&substituted), true, true),
                ContinuityObservation::SubstitutedIdentity
            );
            assert_eq!(
                classify_continuity(&saved, Some(&continuous), false, true),
                ContinuityObservation::InvalidPath
            );
            assert_eq!(
                classify_continuity(&saved, Some(&continuous), true, false),
                ContinuityObservation::AncestorIdentityChanged
            );
            assert_eq!(
                classify_continuity(&saved, None, true, true),
                ContinuityObservation::InspectionUnavailable
            );
            let calls = Cell::new(0_u8);
            continue_after_continuity(ContinuityObservation::ContinuousIdentity, || {
                calls.set(calls.get() + 1);
            })
            .unwrap();
            assert_eq!(calls.get(), 1);
            assert_eq!(
                continue_after_continuity(ContinuityObservation::InspectionUnavailable, || {
                    calls.set(calls.get() + 1);
                }),
                Err(ProofFailure::FixtureUnavailable)
            );
            assert_eq!(calls.get(), 1);
        }

        #[test]
        fn unexpected_blocked_phase_success_fails_closed_and_errors_are_redacted() {
            assert_eq!(
                blocked_rename_observation(true),
                Err(ProofFailure::RenameUnexpectedlySucceeded)
            );
            assert_eq!(
                blocked_rename_observation(false),
                Ok(RenameObservation::RenameBlocked)
            );
            for error in [
                FixtureError::Proof(ProofFailure::RenameUnexpectedlySucceeded),
                FixtureError::Proof(ProofFailure::RenameFailedAfterRelease),
                FixtureError::Proof(ProofFailure::SubstitutionDetected),
                FixtureError::Proof(ProofFailure::IdentityUnexpectedlyMatched),
                FixtureError::Proof(ProofFailure::AncestorIdentityChanged),
                FixtureError::Proof(ProofFailure::PathUnexpected),
                FixtureError::Proof(ProofFailure::FixtureUnavailable),
                FixtureError::CleanupFailed,
                FixtureError::ProofFailedAndCleanupFailed(ProofFailure::FixtureUnavailable),
            ] {
                let debug = format!("{error:?}");
                assert!(!debug.contains('\\'));
                assert!(!debug.contains('/'));
                assert!(!debug.contains("0x"));
                assert!(!debug.contains("CHDPAPI"));
                assert!(!debug.chars().any(|character| character.is_ascii_digit()));
            }
        }

        #[test]
        fn source_is_test_only_and_contains_only_the_approved_fixture_mutations() {
            let source = include_str!("windows_filesystem.rs");
            let (production, tests) = source.split_once("#[cfg(test)]").unwrap();
            assert!(!production.contains("directory_substitution_fixture"));
            assert!(!production.contains(ROOT_PREFIX));
            let implementation = tests
                .split_once("// DIRECTORY SUBSTITUTION IMPLEMENTATION START.")
                .unwrap()
                .1
                .split_once("// DIRECTORY SUBSTITUTION IMPLEMENTATION END.")
                .unwrap()
                .0;
            assert_eq!(implementation.matches("std::fs::rename(").count(), 3);
            assert_eq!(implementation.matches("unsafe {").count(), 0);
            assert_eq!(
                implementation
                    .matches("read_bounded_protected_wrapper(")
                    .count(),
                1
            );
            assert_eq!(implementation.matches("fs::read(").count(), 1);
            for forbidden in [
                concat!("Move", "FileExW("),
                concat!("Replace", "FileW("),
                concat!("SetFileInformation", "ByHandle"),
                concat!("FILE_RENAME", "_INFO"),
                concat!("std::fs::", "hard_link"),
                concat!("publish_synthetic_", "authentication_key_wrapper("),
                concat!("publish_", "initial("),
                concat!("call_replace_", "file_once("),
                concat!("prove_existing_", "replacement("),
                concat!("Command::", "new"),
                concat!("Crypt", "ProtectData"),
                concat!("Crypt", "UnprotectData"),
                concat!("rusq", "lite"),
            ] {
                assert!(
                    !implementation.contains(forbidden),
                    "forbidden fixture source: {forbidden}"
                );
            }
        }
    }
    // DIRECTORY SUBSTITUTION FIXTURE END.

    mod retained_directory_replacement_compatibility {
        use super::*;
        use std::cell::Cell;

        const INTERMEDIATE_NAME: &str = "ordinary-component";
        const ROOT_PREFIX: &str = "church-app-retained-directory-replacement-proof-";
        const RETAINED_DIRECTORY_ACCESS: u32 = GENERIC_READ;
        const RETAINED_DIRECTORY_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ | FILE_SHARE_WRITE;
        const RETAINED_DIRECTORY_DISPOSITION: FILE_CREATION_DISPOSITION = OPEN_EXISTING;
        const RETAINED_DIRECTORY_FLAGS: FILE_FLAGS_AND_ATTRIBUTES =
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;

        #[derive(Clone, Copy, Eq, PartialEq)]
        enum CompatibilityFailure {
            DirectoryRetentionIncompatible,
            DirectoryIdentityChanged,
            DirectoryPathChanged,
            DirectoryFactsChanged,
            InspectionUnavailable,
            ReplacementStateUnexpected,
            FixtureUnavailable,
        }

        impl fmt::Debug for CompatibilityFailure {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(match self {
                    Self::DirectoryRetentionIncompatible => "DirectoryRetentionIncompatible",
                    Self::DirectoryIdentityChanged => "DirectoryIdentityChanged",
                    Self::DirectoryPathChanged => "DirectoryPathChanged",
                    Self::DirectoryFactsChanged => "DirectoryFactsChanged",
                    Self::InspectionUnavailable => "InspectionUnavailable",
                    Self::ReplacementStateUnexpected => "ReplacementStateUnexpected",
                    Self::FixtureUnavailable => "FixtureUnavailable",
                })
            }
        }

        #[derive(Clone, Copy, Eq, PartialEq)]
        enum CompatibilityError {
            Proof(CompatibilityFailure),
            CleanupFailed,
            ProofFailedAndCleanupFailed(CompatibilityFailure),
        }

        impl fmt::Debug for CompatibilityError {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(match self {
                    Self::Proof(failure) => match failure {
                        CompatibilityFailure::DirectoryRetentionIncompatible => {
                            "DirectoryRetentionIncompatible"
                        }
                        CompatibilityFailure::DirectoryIdentityChanged => {
                            "DirectoryIdentityChanged"
                        }
                        CompatibilityFailure::DirectoryPathChanged => "DirectoryPathChanged",
                        CompatibilityFailure::DirectoryFactsChanged => "DirectoryFactsChanged",
                        CompatibilityFailure::InspectionUnavailable => "InspectionUnavailable",
                        CompatibilityFailure::ReplacementStateUnexpected => {
                            "ReplacementStateUnexpected"
                        }
                        CompatibilityFailure::FixtureUnavailable => "FixtureUnavailable",
                    },
                    Self::CleanupFailed => "CleanupFailed",
                    Self::ProofFailedAndCleanupFailed(_) => "ProofFailedAndCleanupFailed",
                })
            }
        }

        #[derive(Debug, Eq, PartialEq)]
        struct CompatibilityReport {
            retained_access_exact: bool,
            retained_share_exact: bool,
            delete_share_excluded: bool,
            initial_directory_identity_saved: bool,
            initial_directory_path_saved: bool,
            initial_directory_facts_saved: bool,
            active_validated: bool,
            stage_validated: bool,
            leaf_handles_closed_before_call: bool,
            pre_call_revalidation_passed: bool,
            native_call_count: u8,
            replacement_succeeded: bool,
            post_call_revalidation_passed: bool,
            fresh_active_opened: bool,
            fresh_stage_absent: bool,
            classifier: ReplacementObservationClass,
            canonical_replacement_active: bool,
            staged_result_identity_continuous: bool,
            old_result_identity_different: bool,
            post_inspection_revalidation_passed: bool,
            sentinel_preserved: bool,
            exact_root_removed: bool,
        }

        // RETAINED DIRECTORY REPLACEMENT COMPATIBILITY IMPLEMENTATION START.
        struct Fixture {
            root: PathBuf,
            intermediate: PathBuf,
            sentinel: PathBuf,
            paths: InstallationEvidencePersistencePaths,
            cleanup_attempted: bool,
        }

        impl Fixture {
            fn create() -> Result<Self, CompatibilityError> {
                let counter = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| {
                        CompatibilityError::Proof(CompatibilityFailure::FixtureUnavailable)
                    })?
                    .as_nanos();
                let root = std::env::temp_dir().join(format!(
                    "{ROOT_PREFIX}{}-{nanos}-{counter}",
                    std::process::id()
                ));
                fs::create_dir(&root).map_err(|_| {
                    CompatibilityError::Proof(CompatibilityFailure::FixtureUnavailable)
                })?;
                let intermediate = root.join(INTERMEDIATE_NAME);
                let paths = installation_evidence_persistence_paths(&intermediate);
                let sentinel = root.join(SENTINEL_NAME);
                let mut fixture = Self {
                    root,
                    intermediate,
                    sentinel,
                    paths,
                    cleanup_attempted: false,
                };
                let setup = (|| -> Result<(), CompatibilityFailure> {
                    fs::create_dir(&fixture.intermediate)
                        .map_err(|_| CompatibilityFailure::FixtureUnavailable)?;
                    fs::create_dir(fixture.paths.evidence_directory.as_path())
                        .map_err(|_| CompatibilityFailure::FixtureUnavailable)?;
                    fs::write(&fixture.sentinel, SENTINEL_CONTENT)
                        .map_err(|_| CompatibilityFailure::FixtureUnavailable)?;
                    Ok(())
                })();
                if let Err(primary) = setup {
                    return match fixture.cleanup_once() {
                        Ok(()) => Err(CompatibilityError::Proof(primary)),
                        Err(_) => Err(CompatibilityError::ProofFailedAndCleanupFailed(primary)),
                    };
                }
                Ok(fixture)
            }

            fn validate_exact_layout(&self) -> Result<(), CompatibilityFailure> {
                let mut root_names = fs::read_dir(&self.root)
                    .map_err(|_| CompatibilityFailure::FixtureUnavailable)?
                    .map(|entry| {
                        entry
                            .map_err(|_| CompatibilityFailure::FixtureUnavailable)?
                            .file_name()
                            .into_string()
                            .map_err(|_| CompatibilityFailure::FixtureUnavailable)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                root_names.sort();
                let mut intermediate_names = fs::read_dir(&self.intermediate)
                    .map_err(|_| CompatibilityFailure::FixtureUnavailable)?
                    .map(|entry| {
                        entry
                            .map_err(|_| CompatibilityFailure::FixtureUnavailable)?
                            .file_name()
                            .into_string()
                            .map_err(|_| CompatibilityFailure::FixtureUnavailable)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                intermediate_names.sort();
                let mut evidence_names = fs::read_dir(self.paths.evidence_directory.as_path())
                    .map_err(|_| CompatibilityFailure::FixtureUnavailable)?
                    .map(|entry| {
                        entry
                            .map_err(|_| CompatibilityFailure::FixtureUnavailable)?
                            .file_name()
                            .into_string()
                            .map_err(|_| CompatibilityFailure::FixtureUnavailable)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                evidence_names.sort();
                if root_names != [INTERMEDIATE_NAME, SENTINEL_NAME]
                    || intermediate_names != [INSTALLATION_EVIDENCE_DIRECTORY_NAME]
                    || evidence_names
                        != [
                            ACTIVE_AUTHENTICATION_KEY_FILENAME,
                            STAGED_AUTHENTICATION_KEY_FILENAME,
                        ]
                {
                    return Err(CompatibilityFailure::FixtureUnavailable);
                }
                Ok(())
            }

            fn sentinel_preserved(&self) -> Result<bool, CompatibilityFailure> {
                fs::read(&self.sentinel)
                    .map(|bytes| bytes == SENTINEL_CONTENT)
                    .map_err(|_| CompatibilityFailure::FixtureUnavailable)
            }

            fn cleanup_once(&mut self) -> Result<(), CompatibilityError> {
                self.cleanup_attempted = true;
                fs::remove_dir_all(&self.root).map_err(|_| CompatibilityError::CleanupFailed)?;
                if self.root.exists() {
                    return Err(CompatibilityError::CleanupFailed);
                }
                Ok(())
            }

            fn finish(
                mut self,
                result: Result<CompatibilityReport, CompatibilityFailure>,
            ) -> Result<CompatibilityReport, CompatibilityError> {
                match (result, self.cleanup_once()) {
                    (Ok(mut report), Ok(())) => {
                        report.exact_root_removed = true;
                        Ok(report)
                    }
                    (Ok(_), Err(_)) => Err(CompatibilityError::CleanupFailed),
                    (Err(primary), Ok(())) => Err(CompatibilityError::Proof(primary)),
                    (Err(primary), Err(_)) => {
                        Err(CompatibilityError::ProofFailedAndCleanupFailed(primary))
                    }
                }
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                if !self.cleanup_attempted {
                    self.cleanup_attempted = true;
                    let _ = fs::remove_dir_all(&self.root);
                }
            }
        }

        struct RetainedEvidenceDirectory {
            handle: File,
            saved: HardeningObservation,
            synthetic_parent: HardeningObservation,
        }

        fn open_retained_evidence_directory(
            fixture: &Fixture,
        ) -> Result<RetainedEvidenceDirectory, CompatibilityFailure> {
            let parent = open_hardened_directory(&fixture.intermediate, None)
                .map_err(|_| CompatibilityFailure::InspectionUnavailable)?;
            let encoded = encode_utf16_path(fixture.paths.evidence_directory.as_path())
                .map_err(|_| CompatibilityFailure::InspectionUnavailable)?;
            // SAFETY: `encoded` is NUL-terminated and live for the call. The exact
            // test-only access, sharing, disposition, and directory flags are fixed.
            let raw = unsafe {
                CreateFileW(
                    encoded.as_ptr(),
                    RETAINED_DIRECTORY_ACCESS,
                    RETAINED_DIRECTORY_SHARE,
                    NULL_CREATE_SECURITY_ATTRIBUTES,
                    RETAINED_DIRECTORY_DISPOSITION,
                    RETAINED_DIRECTORY_FLAGS,
                    NULL_CREATE_TEMPLATE_HANDLE,
                )
            };
            if raw == INVALID_HANDLE_VALUE {
                return Err(CompatibilityFailure::InspectionUnavailable);
            }
            // SAFETY: ownership of the fresh successful handle is transferred once.
            let handle = File::from(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) });
            let saved = query_hardening_observation(&handle)
                .map_err(|_| CompatibilityFailure::InspectionUnavailable)?;
            validate_retained_observation(Some(&saved), Some(&saved), &parent.initial)?;
            let synthetic_parent = parent.initial.clone();
            drop(parent);
            Ok(RetainedEvidenceDirectory {
                handle,
                saved,
                synthetic_parent,
            })
        }

        fn validate_retained_observation(
            saved: Option<&HardeningObservation>,
            current: Option<&HardeningObservation>,
            parent: &HardeningObservation,
        ) -> Result<(), CompatibilityFailure> {
            let (saved, current) = saved
                .zip(current)
                .ok_or(CompatibilityFailure::InspectionUnavailable)?;
            if saved.identity != current.identity {
                return Err(CompatibilityFailure::DirectoryIdentityChanged);
            }
            if saved.final_path != current.final_path {
                return Err(CompatibilityFailure::DirectoryPathChanged);
            }
            if current.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
                || current.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || current.reparse_tag != 0
                || saved.attributes != current.attributes
                || saved.reparse_tag != current.reparse_tag
            {
                return Err(CompatibilityFailure::DirectoryFactsChanged);
            }
            validate_same_volume(parent, current)
                .map_err(|_| CompatibilityFailure::DirectoryFactsChanged)?;
            exact_child_final_path(
                &parent.final_path,
                &current.final_path,
                &ascii_units(INSTALLATION_EVIDENCE_DIRECTORY_NAME),
            )
            .map_err(|_| CompatibilityFailure::DirectoryPathChanged)?;
            Ok(())
        }

        fn revalidate_retained(
            retained: &RetainedEvidenceDirectory,
        ) -> Result<(), CompatibilityFailure> {
            let current = query_hardening_observation(&retained.handle)
                .map_err(|_| CompatibilityFailure::InspectionUnavailable)?;
            validate_retained_observation(
                Some(&retained.saved),
                Some(&current),
                &retained.synthetic_parent,
            )
        }

        fn run_proof() -> Result<CompatibilityReport, CompatibilityError> {
            let fixture = Fixture::create()?;
            let proof = (|| -> Result<CompatibilityReport, CompatibilityFailure> {
                let old_bytes = authentication_key_wrapper(32, 0xd1);
                let replacement_bytes = authentication_key_wrapper(64, 0xd2);
                publish_synthetic_authentication_key_wrapper(&fixture.paths, &old_bytes)
                    .map_err(|_| CompatibilityFailure::FixtureUnavailable)?;
                create_and_verify_replacement_stage(&fixture.paths, &replacement_bytes)
                    .map_err(|_| CompatibilityFailure::FixtureUnavailable)?;
                fixture.validate_exact_layout()?;

                let retained = open_retained_evidence_directory(&fixture)?;
                let preflight =
                    preflight_existing_replacement(&fixture.paths, &old_bytes, &replacement_bytes)
                        .map_err(|_| CompatibilityFailure::FixtureUnavailable)?;
                let active_path =
                    encode_utf16_path(fixture.paths.active_authentication_key.as_path())
                        .map_err(|_| CompatibilityFailure::FixtureUnavailable)?;
                let stage_path =
                    encode_utf16_path(fixture.paths.staged_authentication_key.as_path())
                        .map_err(|_| CompatibilityFailure::FixtureUnavailable)?;

                revalidate_retained(&retained)?;
                let calls = Cell::new(0_u8);
                let outcome = {
                    calls.set(calls.get() + 1);
                    call_replace_file_once(&active_path, &stage_path)
                };
                let post_call_revalidation = revalidate_retained(&retained);

                let (active, stage) =
                    fresh_exact_name_observations(&fixture.paths, &old_bytes, &replacement_bytes);
                let classifier = classify_replacement_observation(outcome, active, stage);
                let post_inspection_revalidation = revalidate_retained(&retained);
                post_call_revalidation?;
                post_inspection_revalidation?;
                let ReplacementCallOutcome::Success = outcome else {
                    return Err(CompatibilityFailure::DirectoryRetentionIncompatible);
                };
                if classifier != ReplacementObservationClass::ActiveNewStageAbsent {
                    return Err(CompatibilityFailure::ReplacementStateUnexpected);
                }
                let ExactNameObservation::RegularNew(result_identity) = active else {
                    return Err(CompatibilityFailure::ReplacementStateUnexpected);
                };
                if stage != ExactNameObservation::Absent
                    || result_identity != preflight.staged_replacement_identity
                    || result_identity == preflight.old_active_identity
                    || calls.get() != 1
                    || !fixture.sentinel_preserved()?
                {
                    return Err(CompatibilityFailure::ReplacementStateUnexpected);
                }
                drop(retained);

                Ok(CompatibilityReport {
                    retained_access_exact: RETAINED_DIRECTORY_ACCESS == GENERIC_READ,
                    retained_share_exact: RETAINED_DIRECTORY_SHARE
                        == FILE_SHARE_READ | FILE_SHARE_WRITE,
                    delete_share_excluded: RETAINED_DIRECTORY_SHARE
                        & windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE
                        == 0,
                    initial_directory_identity_saved: true,
                    initial_directory_path_saved: true,
                    initial_directory_facts_saved: true,
                    active_validated: true,
                    stage_validated: true,
                    leaf_handles_closed_before_call: true,
                    pre_call_revalidation_passed: true,
                    native_call_count: calls.get(),
                    replacement_succeeded: true,
                    post_call_revalidation_passed: true,
                    fresh_active_opened: true,
                    fresh_stage_absent: true,
                    classifier,
                    canonical_replacement_active: true,
                    staged_result_identity_continuous: true,
                    old_result_identity_different: true,
                    post_inspection_revalidation_passed: true,
                    sentinel_preserved: true,
                    exact_root_removed: false,
                })
            })();
            fixture.finish(proof)
        }
        // RETAINED DIRECTORY REPLACEMENT COMPATIBILITY IMPLEMENTATION END.

        #[test]
        fn evidence_directory_handle_remains_live_across_one_shot_replacement() {
            let report = run_proof().unwrap();
            assert!(report.retained_access_exact);
            assert!(report.retained_share_exact);
            assert!(report.delete_share_excluded);
            assert!(report.initial_directory_identity_saved);
            assert!(report.initial_directory_path_saved);
            assert!(report.initial_directory_facts_saved);
            assert!(report.active_validated);
            assert!(report.stage_validated);
            assert!(report.leaf_handles_closed_before_call);
            assert!(report.pre_call_revalidation_passed);
            assert_eq!(report.native_call_count, 1);
            assert!(report.replacement_succeeded);
            assert!(report.post_call_revalidation_passed);
            assert!(report.fresh_active_opened);
            assert!(report.fresh_stage_absent);
            assert_eq!(
                report.classifier,
                ReplacementObservationClass::ActiveNewStageAbsent
            );
            assert!(report.canonical_replacement_active);
            assert!(report.staged_result_identity_continuous);
            assert!(report.old_result_identity_different);
            assert!(report.post_inspection_revalidation_passed);
            assert!(report.sentinel_preserved);
            assert!(report.exact_root_removed);
        }

        #[test]
        fn unavailable_and_changed_directory_observations_fail_closed() {
            let parent = synthetic_observation(
                31,
                1,
                1,
                r"\\?\Volume{abcdef12-3456-7890-abcd-ef1234567890}\root\ordinary-component",
            );
            let saved = synthetic_observation(
                31,
                2,
                1,
                r"\\?\Volume{abcdef12-3456-7890-abcd-ef1234567890}\root\ordinary-component\installation-evidence",
            );
            assert_eq!(
                validate_retained_observation(Some(&saved), None, &parent),
                Err(CompatibilityFailure::InspectionUnavailable)
            );
            let mut facts_changed = saved.clone();
            facts_changed.reparse_tag = 7;
            assert_eq!(
                validate_retained_observation(Some(&saved), Some(&facts_changed), &parent),
                Err(CompatibilityFailure::DirectoryFactsChanged)
            );
            let mut identity_changed = saved.clone();
            identity_changed.identity.file_id[0] = 9;
            assert_eq!(
                validate_retained_observation(Some(&saved), Some(&identity_changed), &parent),
                Err(CompatibilityFailure::DirectoryIdentityChanged)
            );
            let mut path_changed = saved.clone();
            path_changed.final_path.pop();
            assert_eq!(
                validate_retained_observation(Some(&saved), Some(&path_changed), &parent),
                Err(CompatibilityFailure::DirectoryPathChanged)
            );
        }

        #[test]
        fn compatibility_errors_and_debug_are_redacted() {
            for error in [
                CompatibilityError::Proof(CompatibilityFailure::DirectoryRetentionIncompatible),
                CompatibilityError::Proof(CompatibilityFailure::DirectoryIdentityChanged),
                CompatibilityError::Proof(CompatibilityFailure::DirectoryPathChanged),
                CompatibilityError::Proof(CompatibilityFailure::DirectoryFactsChanged),
                CompatibilityError::Proof(CompatibilityFailure::InspectionUnavailable),
                CompatibilityError::Proof(CompatibilityFailure::ReplacementStateUnexpected),
                CompatibilityError::Proof(CompatibilityFailure::FixtureUnavailable),
                CompatibilityError::CleanupFailed,
                CompatibilityError::ProofFailedAndCleanupFailed(
                    CompatibilityFailure::FixtureUnavailable,
                ),
            ] {
                let debug = format!("{error:?}");
                assert!(!debug.contains('\\'));
                assert!(!debug.contains('/'));
                assert!(!debug.contains("0x"));
                assert!(!debug.contains("CHDPAPI"));
                assert!(!debug.chars().any(|character| character.is_ascii_digit()));
            }
        }

        #[test]
        fn source_is_test_only_and_keeps_the_fixture_and_call_locked() {
            let source = include_str!("windows_filesystem.rs");
            let (production, tests) = source.split_once("#[cfg(test)]").unwrap();
            assert!(!production.contains("retained_directory_replacement_compatibility"));
            assert!(!production.contains(ROOT_PREFIX));
            let implementation = tests
                .split_once("// RETAINED DIRECTORY REPLACEMENT COMPATIBILITY IMPLEMENTATION START.")
                .unwrap()
                .1
                .split_once("// RETAINED DIRECTORY REPLACEMENT COMPATIBILITY IMPLEMENTATION END.")
                .unwrap()
                .0;
            assert_eq!(implementation.matches("call_replace_file_once(").count(), 1);
            assert_eq!(
                implementation
                    .matches("preflight_existing_replacement(")
                    .count(),
                1
            );
            assert_eq!(
                implementation
                    .matches("fresh_exact_name_observations(")
                    .count(),
                1
            );
            assert_eq!(
                implementation
                    .matches("revalidate_retained(&retained)")
                    .count(),
                3
            );
            for forbidden in [
                concat!("std::fs::", "rename"),
                concat!("hard_", "link"),
                concat!("sym", "link"),
                concat!("MoveFile", "ExW("),
                concat!("ReplaceFile", "W("),
                concat!("Crypt", "ProtectData"),
                concat!("rusq", "lite"),
                concat!("resolve_", "production"),
                concat!("tauri::", "command"),
            ] {
                assert!(
                    !implementation.contains(forbidden),
                    "forbidden compatibility source: {forbidden}"
                );
            }
        }
    }

    // LOCAL-VOLUME CANDIDATE PROOF START: private Windows-test-only policy and fixture.
    mod local_volume_policy {
        use super::*;

        const ROOT_PREFIX: &str = "church-app-local-volume-proof-";
        const SENTINEL_NAME: &str = "unrelated-sentinel.synthetic";
        const SENTINEL_CONTENT: &[u8] = b"synthetic-sentinel-preserved";

        // GetDriveTypeW documented return values. These private test facts avoid
        // adding the WindowsProgramming feature solely for generated DRIVE_* names.
        const DOCUMENTED_DRIVE_UNKNOWN: u32 = 0;
        const DOCUMENTED_DRIVE_NO_ROOT: u32 = 1;
        const DOCUMENTED_DRIVE_REMOVABLE: u32 = 2;
        const DOCUMENTED_FIXED_DRIVE_CATEGORY: u32 = 3;
        const DOCUMENTED_DRIVE_REMOTE: u32 = 4;
        const DOCUMENTED_DRIVE_CD_ROM: u32 = 5;
        const DOCUMENTED_DRIVE_RAM_DISK: u32 = 6;

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(super) enum VolumePathFact {
            NormalizedVolumeGuid,
            Unc,
            Malformed,
            Unavailable,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(super) enum DriveTypeFact {
            Fixed,
            Removable,
            Remote,
            CdRom,
            RamDisk,
            Unknown,
            NoRoot,
            Unavailable,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(super) enum LocalVolumeRejection {
            RemoteVolumeRejected,
            RemovableVolumeRejected,
            UnsupportedDriveType,
            MalformedVolumePath,
            InconsistentFacts,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(super) enum LocalVolumeClassification {
            LocalFixedCandidate,
            Rejected(LocalVolumeRejection),
            Unavailable,
        }

        #[derive(Clone, Copy, Eq, PartialEq)]
        pub(super) enum LocalVolumeProofFailure {
            ClassifierRejected(LocalVolumeRejection),
            ClassificationUnavailable,
            HostPrerequisiteNotMet,
            FixtureUnavailable,
        }

        impl LocalVolumeProofFailure {
            fn redacted_name(self) -> &'static str {
                match self {
                    Self::ClassifierRejected(_) => "ClassifierRejected",
                    Self::ClassificationUnavailable => "ClassificationUnavailable",
                    Self::HostPrerequisiteNotMet => "HostPrerequisiteNotMet",
                    Self::FixtureUnavailable => "FixtureUnavailable",
                }
            }
        }

        impl fmt::Debug for LocalVolumeProofFailure {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.redacted_name())
            }
        }

        #[derive(Clone, Copy, Eq, PartialEq)]
        enum ProofError {
            Proof(LocalVolumeProofFailure),
            CleanupFailed,
            ProofFailedAndCleanupFailed(LocalVolumeProofFailure),
        }

        impl fmt::Debug for ProofError {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(match self {
                    Self::Proof(failure) => failure.redacted_name(),
                    Self::CleanupFailed => "CleanupFailed",
                    Self::ProofFailedAndCleanupFailed(_) => "ProofFailedAndCleanupFailed",
                })
            }
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct NonAuthoritativeCandidateReport {
            classification: LocalVolumeClassification,
            retained_test_root_handle: bool,
            strict_handle_derived_volume_guid_path: bool,
            exact_volume_root_derived: bool,
            drive_type_call_count: u8,
            sentinel_preserved: bool,
            local_fixed_candidate_only: bool,
            removable_media_assurance: bool,
            hot_plug_assurance: bool,
            device_topology_assurance: bool,
            production_approval: bool,
            setup_authority: bool,
            startup_authority: bool,
            publication_or_replacement_authority: bool,
            database_opening_authority: bool,
        }

        fn drive_type_fact(value: u32) -> DriveTypeFact {
            match value {
                DOCUMENTED_DRIVE_UNKNOWN => DriveTypeFact::Unknown,
                DOCUMENTED_DRIVE_NO_ROOT => DriveTypeFact::NoRoot,
                DOCUMENTED_DRIVE_REMOVABLE => DriveTypeFact::Removable,
                DOCUMENTED_FIXED_DRIVE_CATEGORY => DriveTypeFact::Fixed,
                DOCUMENTED_DRIVE_REMOTE => DriveTypeFact::Remote,
                DOCUMENTED_DRIVE_CD_ROM => DriveTypeFact::CdRom,
                DOCUMENTED_DRIVE_RAM_DISK => DriveTypeFact::RamDisk,
                _ => DriveTypeFact::Unavailable,
            }
        }

        fn has_prefix(path: &[u16], prefix: &str) -> bool {
            let prefix = ascii_units(prefix);
            path.get(..prefix.len()) == Some(prefix.as_slice())
        }

        pub(super) fn volume_path_fact(path: Option<&[u16]>) -> VolumePathFact {
            let Some(path) = path else {
                return VolumePathFact::Unavailable;
            };
            if has_prefix(path, r"\\?\UNC\") {
                return VolumePathFact::Unc;
            }
            if has_prefix(path, r"\\") && !has_prefix(path, r"\\?\Volume{") {
                return VolumePathFact::Unc;
            }
            match validated_volume_guid_prefix(path) {
                Ok(_) => VolumePathFact::NormalizedVolumeGuid,
                Err(_) => VolumePathFact::Malformed,
            }
        }

        pub(super) fn classify(
            path: VolumePathFact,
            drive: DriveTypeFact,
        ) -> LocalVolumeClassification {
            match (path, drive) {
                (VolumePathFact::NormalizedVolumeGuid, DriveTypeFact::Fixed) => {
                    LocalVolumeClassification::LocalFixedCandidate
                }
                (VolumePathFact::NormalizedVolumeGuid, DriveTypeFact::Removable) => {
                    LocalVolumeClassification::Rejected(
                        LocalVolumeRejection::RemovableVolumeRejected,
                    )
                }
                (VolumePathFact::NormalizedVolumeGuid, DriveTypeFact::Remote) => {
                    LocalVolumeClassification::Rejected(LocalVolumeRejection::RemoteVolumeRejected)
                }
                (
                    VolumePathFact::NormalizedVolumeGuid,
                    DriveTypeFact::CdRom | DriveTypeFact::RamDisk,
                ) => {
                    LocalVolumeClassification::Rejected(LocalVolumeRejection::UnsupportedDriveType)
                }
                (
                    VolumePathFact::NormalizedVolumeGuid,
                    DriveTypeFact::Unknown | DriveTypeFact::NoRoot | DriveTypeFact::Unavailable,
                )
                | (VolumePathFact::Unavailable, _) => LocalVolumeClassification::Unavailable,
                (VolumePathFact::Unc, DriveTypeFact::Remote) => {
                    LocalVolumeClassification::Rejected(LocalVolumeRejection::RemoteVolumeRejected)
                }
                (VolumePathFact::Malformed, _) => {
                    LocalVolumeClassification::Rejected(LocalVolumeRejection::MalformedVolumePath)
                }
                (VolumePathFact::Unc, DriveTypeFact::Unavailable) => {
                    LocalVolumeClassification::Unavailable
                }
                (VolumePathFact::Unc, _) => {
                    LocalVolumeClassification::Rejected(LocalVolumeRejection::InconsistentFacts)
                }
            }
        }

        pub(super) fn exact_volume_guid_root(
            path: &[u16],
        ) -> Result<Vec<u16>, LocalVolumeProofFailure> {
            validated_volume_guid_prefix(path)
                .map(|root| root.to_vec())
                .map_err(|_| {
                    LocalVolumeProofFailure::ClassifierRejected(
                        LocalVolumeRejection::MalformedVolumePath,
                    )
                })
        }

        pub(super) fn query_drive_type_once(root: &[u16]) -> DriveTypeFact {
            let mut nul_terminated = root.to_vec();
            nul_terminated.push(0);
            // SAFETY: the strict 49-unit root is followed by exactly one terminating
            // NUL and remains live for this single native query.
            drive_type_fact(unsafe { GetDriveTypeW(nul_terminated.as_ptr()) })
        }

        type CleanupOperation = fn(&Path) -> io::Result<()>;

        fn remove_exact_root(root: &Path) -> io::Result<()> {
            fs::remove_dir_all(root)
        }

        fn write_sentinel(path: &Path, content: &[u8]) -> io::Result<()> {
            fs::write(path, content)
        }

        struct Fixture {
            root: PathBuf,
            sentinel: PathBuf,
            cleanup_attempted: bool,
            cleanup_operation: CleanupOperation,
        }

        impl Fixture {
            fn create() -> Result<Self, ProofError> {
                Self::create_with(write_sentinel, remove_exact_root)
            }

            fn create_with(
                write_sentinel: impl FnOnce(&Path, &[u8]) -> io::Result<()>,
                cleanup_operation: CleanupOperation,
            ) -> Result<Self, ProofError> {
                let counter = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| ProofError::Proof(LocalVolumeProofFailure::FixtureUnavailable))?
                    .as_nanos();
                let root = std::env::temp_dir().join(format!(
                    "{ROOT_PREFIX}{}-{nanos}-{counter}",
                    std::process::id()
                ));
                fs::create_dir(&root)
                    .map_err(|_| ProofError::Proof(LocalVolumeProofFailure::FixtureUnavailable))?;
                let sentinel = root.join(SENTINEL_NAME);
                let mut fixture = Self {
                    root,
                    sentinel,
                    cleanup_attempted: false,
                    cleanup_operation,
                };
                if write_sentinel(&fixture.sentinel, SENTINEL_CONTENT).is_err() {
                    let primary = LocalVolumeProofFailure::FixtureUnavailable;
                    return match fixture.cleanup_once() {
                        Ok(()) => Err(ProofError::Proof(primary)),
                        Err(_) => Err(ProofError::ProofFailedAndCleanupFailed(primary)),
                    };
                }
                Ok(fixture)
            }

            fn sentinel_preserved(&self) -> Result<bool, LocalVolumeProofFailure> {
                fs::read(&self.sentinel)
                    .map(|bytes| bytes == SENTINEL_CONTENT)
                    .map_err(|_| LocalVolumeProofFailure::FixtureUnavailable)
            }

            fn cleanup_once(&mut self) -> Result<(), ProofError> {
                if self.cleanup_attempted {
                    return Ok(());
                }
                self.cleanup_attempted = true;
                (self.cleanup_operation)(&self.root).map_err(|_| ProofError::CleanupFailed)?;
                if self.root.exists() {
                    return Err(ProofError::CleanupFailed);
                }
                Ok(())
            }

            fn finish(
                mut self,
                result: Result<NonAuthoritativeCandidateReport, LocalVolumeProofFailure>,
            ) -> Result<NonAuthoritativeCandidateReport, ProofError> {
                match (result, self.cleanup_once()) {
                    (Ok(report), Ok(())) => Ok(report),
                    (Err(failure), Ok(())) => Err(ProofError::Proof(failure)),
                    (Ok(_), Err(_)) => Err(ProofError::CleanupFailed),
                    (Err(failure), Err(_)) => Err(ProofError::ProofFailedAndCleanupFailed(failure)),
                }
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                if !self.cleanup_attempted {
                    self.cleanup_attempted = true;
                    let _ = (self.cleanup_operation)(&self.root);
                }
            }
        }

        fn observe_runtime_candidate() -> Result<NonAuthoritativeCandidateReport, ProofError> {
            let fixture = Fixture::create()?;
            let result = (|| {
                let retained = open_hardened_directory(&fixture.root, None)
                    .map_err(|_| LocalVolumeProofFailure::FixtureUnavailable)?;
                validate_disk_handle(&retained.handle)
                    .map_err(|_| LocalVolumeProofFailure::FixtureUnavailable)?;
                let (standard, attributes) = query_entry_information(&retained.handle)
                    .map_err(|_| LocalVolumeProofFailure::FixtureUnavailable)?;
                if !standard.Directory || attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
                {
                    return Err(LocalVolumeProofFailure::FixtureUnavailable);
                }
                validate_reparse_facts(attributes.FileAttributes, attributes.ReparseTag)
                    .map_err(|_| LocalVolumeProofFailure::FixtureUnavailable)?;
                let final_path = &retained.initial.final_path;
                let path_fact = volume_path_fact(Some(final_path));
                let root = exact_volume_guid_root(final_path)?;
                if root.len() != VOLUME_GUID_PREFIX_UNITS {
                    return Err(LocalVolumeProofFailure::FixtureUnavailable);
                }
                let drive_fact = query_drive_type_once(&root);
                let classification = classify(path_fact, drive_fact);
                match classification {
                    LocalVolumeClassification::LocalFixedCandidate => {}
                    LocalVolumeClassification::Rejected(_) => {
                        return Err(LocalVolumeProofFailure::HostPrerequisiteNotMet);
                    }
                    LocalVolumeClassification::Unavailable => {
                        return Err(LocalVolumeProofFailure::ClassificationUnavailable);
                    }
                }
                if drive_fact != DriveTypeFact::Fixed {
                    return Err(LocalVolumeProofFailure::HostPrerequisiteNotMet);
                }
                let sentinel_preserved = fixture.sentinel_preserved()?;
                if !sentinel_preserved {
                    return Err(LocalVolumeProofFailure::FixtureUnavailable);
                }
                drop(retained);
                Ok(NonAuthoritativeCandidateReport {
                    classification,
                    retained_test_root_handle: true,
                    strict_handle_derived_volume_guid_path: true,
                    exact_volume_root_derived: true,
                    drive_type_call_count: 1,
                    sentinel_preserved,
                    local_fixed_candidate_only: true,
                    removable_media_assurance: false,
                    hot_plug_assurance: false,
                    device_topology_assurance: false,
                    production_approval: false,
                    setup_authority: false,
                    startup_authority: false,
                    publication_or_replacement_authority: false,
                    database_opening_authority: false,
                })
            })();
            fixture.finish(result)
        }

        fn strict_path() -> Vec<u16> {
            ascii_units(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\proof")
        }

        #[test]
        fn local_volume_policy_documented_drive_type_mapping_is_exact() {
            assert_eq!(drive_type_fact(0), DriveTypeFact::Unknown);
            assert_eq!(drive_type_fact(1), DriveTypeFact::NoRoot);
            assert_eq!(drive_type_fact(2), DriveTypeFact::Removable);
            assert_eq!(drive_type_fact(3), DriveTypeFact::Fixed);
            assert_eq!(drive_type_fact(4), DriveTypeFact::Remote);
            assert_eq!(drive_type_fact(5), DriveTypeFact::CdRom);
            assert_eq!(drive_type_fact(6), DriveTypeFact::RamDisk);
            assert_eq!(drive_type_fact(7), DriveTypeFact::Unavailable);
        }

        #[test]
        fn local_volume_policy_accepts_only_fixed_and_fails_closed_for_drive_facts() {
            let path = VolumePathFact::NormalizedVolumeGuid;
            assert_eq!(
                classify(path, DriveTypeFact::Fixed),
                LocalVolumeClassification::LocalFixedCandidate
            );
            assert_eq!(
                classify(path, DriveTypeFact::Removable),
                LocalVolumeClassification::Rejected(LocalVolumeRejection::RemovableVolumeRejected)
            );
            assert_eq!(
                classify(path, DriveTypeFact::Remote),
                LocalVolumeClassification::Rejected(LocalVolumeRejection::RemoteVolumeRejected)
            );
            for drive in [DriveTypeFact::CdRom, DriveTypeFact::RamDisk] {
                assert_eq!(
                    classify(path, drive),
                    LocalVolumeClassification::Rejected(LocalVolumeRejection::UnsupportedDriveType)
                );
            }
            for drive in [
                DriveTypeFact::Unknown,
                DriveTypeFact::NoRoot,
                DriveTypeFact::Unavailable,
            ] {
                assert_eq!(
                    classify(path, drive),
                    LocalVolumeClassification::Unavailable
                );
            }
        }

        #[test]
        fn local_volume_policy_unc_and_malformed_paths_fail_closed() {
            let strict = strict_path();
            let exact_root = exact_volume_guid_root(&strict).unwrap();
            assert_eq!(exact_root, strict[..VOLUME_GUID_PREFIX_UNITS]);
            assert_eq!(exact_root.len(), VOLUME_GUID_PREFIX_UNITS);
            assert_eq!(exact_root.last(), Some(&(b'\\' as u16)));
            assert!(!exact_root.contains(&0));
            assert_eq!(
                classify(
                    volume_path_fact(Some(&ascii_units(r"\\server\share"))),
                    DriveTypeFact::Remote
                ),
                LocalVolumeClassification::Rejected(LocalVolumeRejection::RemoteVolumeRejected)
            );
            assert_eq!(
                classify(
                    volume_path_fact(Some(&ascii_units(r"\\?\UNC\server\share"))),
                    DriveTypeFact::Remote
                ),
                LocalVolumeClassification::Rejected(LocalVolumeRejection::RemoteVolumeRejected)
            );
            let mut embedded_nul = strict_path();
            embedded_nul[20] = 0;
            let mut oversized = strict_path();
            oversized.resize(MAXIMUM_FINAL_PATH_UNITS + 1, b'x' as u16);
            for malformed in [
                Vec::new(),
                ascii_units(r"C:\proof"),
                ascii_units(r"\Device\HarddiskVolume1\proof"),
                ascii_units(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef\proof"),
                ascii_units(r"\\?\Volume{g1234567-89ab-cdef-0123-456789abcdef}\proof"),
                ascii_units(r"\\?\Volume{012345678-9ab-cdef-0123-456789abcdef}\proof"),
                ascii_units(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}"),
                embedded_nul,
                ascii_units(r"\\?\Volume{01234567-89ab-cdef"),
                oversized,
            ] {
                assert_eq!(
                    classify(volume_path_fact(Some(&malformed)), DriveTypeFact::Fixed),
                    LocalVolumeClassification::Rejected(LocalVolumeRejection::MalformedVolumePath)
                );
            }
        }

        #[test]
        fn local_volume_policy_inconsistent_facts_never_produce_a_candidate() {
            for drive in [
                DriveTypeFact::Fixed,
                DriveTypeFact::Removable,
                DriveTypeFact::CdRom,
            ] {
                assert_eq!(
                    classify(VolumePathFact::Unc, drive),
                    LocalVolumeClassification::Rejected(LocalVolumeRejection::InconsistentFacts)
                );
            }
            assert_eq!(
                classify(VolumePathFact::Unavailable, DriveTypeFact::Fixed),
                LocalVolumeClassification::Unavailable
            );
            assert_ne!(
                classify(VolumePathFact::NormalizedVolumeGuid, DriveTypeFact::Remote),
                LocalVolumeClassification::LocalFixedCandidate
            );
            assert_ne!(
                classify(
                    VolumePathFact::NormalizedVolumeGuid,
                    DriveTypeFact::Removable
                ),
                LocalVolumeClassification::LocalFixedCandidate
            );
        }

        #[test]
        fn local_volume_policy_errors_and_debug_are_redacted() {
            static INJECTED_CLEANUP_CALLS: AtomicU64 = AtomicU64::new(0);

            fn fail_sentinel_write(_: &Path, _: &[u8]) -> io::Result<()> {
                Err(io::Error::other("synthetic setup failure"))
            }

            fn count_cleanup_and_remove(root: &Path) -> io::Result<()> {
                INJECTED_CLEANUP_CALLS.fetch_add(1, Ordering::Relaxed);
                fs::remove_dir_all(root)
            }

            fn count_cleanup_remove_then_fail(root: &Path) -> io::Result<()> {
                INJECTED_CLEANUP_CALLS.fetch_add(1, Ordering::Relaxed);
                fs::remove_dir_all(root)?;
                Err(io::Error::other("synthetic cleanup failure"))
            }

            fn count_cleanup_failure(_: &Path) -> io::Result<()> {
                INJECTED_CLEANUP_CALLS.fetch_add(1, Ordering::Relaxed);
                Err(io::Error::other("synthetic cleanup failure"))
            }

            let combined_primary = LocalVolumeProofFailure::ClassificationUnavailable;
            for error in [
                ProofError::Proof(LocalVolumeProofFailure::ClassifierRejected(
                    LocalVolumeRejection::RemoteVolumeRejected,
                )),
                ProofError::Proof(LocalVolumeProofFailure::ClassificationUnavailable),
                ProofError::Proof(LocalVolumeProofFailure::HostPrerequisiteNotMet),
                ProofError::Proof(LocalVolumeProofFailure::FixtureUnavailable),
                ProofError::CleanupFailed,
                ProofError::ProofFailedAndCleanupFailed(combined_primary),
            ] {
                let debug = format!("{error:?}");
                assert!(!debug.contains('\\'));
                assert!(!debug.contains('/'));
                assert!(!debug.contains("0x"));
                assert!(!debug.chars().any(|character| character.is_ascii_digit()));
            }
            assert_ne!(
                LocalVolumeProofFailure::ClassificationUnavailable,
                LocalVolumeProofFailure::HostPrerequisiteNotMet
            );

            let combined = ProofError::ProofFailedAndCleanupFailed(combined_primary);
            assert!(matches!(
                combined,
                ProofError::ProofFailedAndCleanupFailed(
                    LocalVolumeProofFailure::ClassificationUnavailable
                )
            ));

            INJECTED_CLEANUP_CALLS.store(0, Ordering::Relaxed);
            let setup_failure = Fixture::create_with(fail_sentinel_write, count_cleanup_and_remove);
            assert!(matches!(
                setup_failure,
                Err(ProofError::Proof(
                    LocalVolumeProofFailure::FixtureUnavailable
                ))
            ));
            assert_eq!(INJECTED_CLEANUP_CALLS.load(Ordering::Relaxed), 1);

            INJECTED_CLEANUP_CALLS.store(0, Ordering::Relaxed);
            let setup_and_cleanup_failure =
                Fixture::create_with(fail_sentinel_write, count_cleanup_remove_then_fail);
            assert!(matches!(
                setup_and_cleanup_failure,
                Err(ProofError::ProofFailedAndCleanupFailed(
                    LocalVolumeProofFailure::FixtureUnavailable
                ))
            ));
            assert_eq!(INJECTED_CLEANUP_CALLS.load(Ordering::Relaxed), 1);

            INJECTED_CLEANUP_CALLS.store(0, Ordering::Relaxed);
            let root = std::env::temp_dir().join("church-app-local-volume-absent-test-root");
            assert!(!root.exists());
            let mut fixture = Fixture {
                sentinel: root.join(SENTINEL_NAME),
                root,
                cleanup_attempted: false,
                cleanup_operation: count_cleanup_failure,
            };
            assert_eq!(fixture.cleanup_once(), Err(ProofError::CleanupFailed));
            assert!(fixture.cleanup_attempted);
            assert_eq!(fixture.cleanup_once(), Ok(()));
            drop(fixture);
            assert_eq!(INJECTED_CLEANUP_CALLS.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn local_volume_policy_candidate_is_explicitly_non_authoritative() {
            let report = NonAuthoritativeCandidateReport {
                classification: LocalVolumeClassification::LocalFixedCandidate,
                retained_test_root_handle: true,
                strict_handle_derived_volume_guid_path: true,
                exact_volume_root_derived: true,
                drive_type_call_count: 1,
                sentinel_preserved: true,
                local_fixed_candidate_only: true,
                removable_media_assurance: false,
                hot_plug_assurance: false,
                device_topology_assurance: false,
                production_approval: false,
                setup_authority: false,
                startup_authority: false,
                publication_or_replacement_authority: false,
                database_opening_authority: false,
            };
            assert!(report.local_fixed_candidate_only);
            assert!(!report.removable_media_assurance);
            assert!(!report.hot_plug_assurance);
            assert!(!report.device_topology_assurance);
            assert!(!report.production_approval);
            assert!(!report.setup_authority);
            assert!(!report.startup_authority);
            assert!(!report.publication_or_replacement_authority);
            assert!(!report.database_opening_authority);
        }

        #[test]
        fn local_volume_policy_runtime_observes_unique_root_from_retained_handle() {
            let report = observe_runtime_candidate().unwrap_or_else(|error| panic!("{error:?}"));
            assert_eq!(
                report.classification,
                LocalVolumeClassification::LocalFixedCandidate
            );
            assert!(report.retained_test_root_handle);
            assert!(report.strict_handle_derived_volume_guid_path);
            assert!(report.exact_volume_root_derived);
            assert_eq!(report.drive_type_call_count, 1);
            assert!(report.sentinel_preserved);
        }

        #[test]
        fn local_volume_policy_source_is_test_only_narrow_and_has_no_authority_conversion() {
            let source = include_str!("windows_filesystem.rs");
            let (production, tests) = source.split_once("#[cfg(test)]").unwrap();
            assert!(!production.contains("local_volume_policy"));
            assert!(!production.contains(ROOT_PREFIX));
            let implementation = tests
                .split_once("// LOCAL-VOLUME CANDIDATE PROOF START")
                .unwrap()
                .1
                .split_once("// LOCAL-VOLUME CANDIDATE PROOF END")
                .unwrap()
                .0;
            assert!(tests.contains("fn query_bounded_final_guid_path"));
            assert!(implementation.contains("validated_volume_guid_prefix"));
            assert!(implementation.contains("open_hardened_directory"));
            assert!(implementation.contains("validate_disk_handle"));
            assert!(implementation.contains("validate_reparse_facts"));
            assert_eq!(
                implementation
                    .matches("GetDriveTypeW(nul_terminated.as_ptr())")
                    .count(),
                1
            );
            for forbidden in [
                concat!("DRIVE_", "FIXED"),
                concat!("GetVolumePath", "NameW"),
                concat!("GetVolumeNameForVolume", "MountPointW"),
                concat!("QueryDos", "DeviceW"),
                concat!("GetVolume", "InformationW"),
                concat!("Device", "IoControl"),
                concat!("IOCTL_", "STORAGE"),
                concat!("Physical", "Drive"),
                concat!("resolve_", "production"),
                concat!("Replace", "FileW("),
                concat!("publish_synthetic_", "authentication_key_wrapper("),
                concat!("Crypt", "ProtectData"),
                concat!("rusq", "lite"),
                concat!("tauri::", "command"),
                concat!("Command::", "new"),
                concat!("impl Fr", "om<LocalVolumeClassification"),
                concat!("impl In", "to<"),
            ] {
                assert!(
                    !implementation.contains(forbidden),
                    "forbidden local-volume source"
                );
            }
        }
    }
    // LOCAL-VOLUME CANDIDATE PROOF END.

    // DEVICE-PROPERTY CANDIDATE PROOF START: private Windows-test-only policy and fixture.
    mod device_property_policy {
        use super::*;
        use std::mem::{offset_of, size_of};

        use windows_sys::Win32::{
            Storage::FileSystem::{
                BusType1394, BusTypeAta, BusTypeAtapi, BusTypeFibre, BusTypeFileBackedVirtual,
                BusTypeMax, BusTypeMmc, BusTypeNvme, BusTypeRAID, BusTypeSCM, BusTypeSas,
                BusTypeSata, BusTypeScsi, BusTypeSd, BusTypeSpaces, BusTypeUfs, BusTypeUnknown,
                BusTypeUsb, BusTypeVirtual, BusTypeiScsi,
            },
            System::{
                IO::{DeviceIoControl, OVERLAPPED},
                Ioctl::{
                    IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery, STORAGE_DESCRIPTOR_HEADER,
                    STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY, StorageDeviceProperty,
                },
            },
        };

        const ROOT_PREFIX: &str = "church-app-device-property-proof-";
        const SENTINEL_NAME: &str = "unrelated-sentinel.synthetic";
        const SENTINEL_CONTENT: &[u8] = b"synthetic-sentinel-preserved";
        const DOCUMENTED_FIXED_DRIVE_CATEGORY: u32 = 3;
        const MAXIMUM_DESCRIPTOR_LENGTH: usize = 65_536;

        const HEADER_LENGTH: usize = size_of::<STORAGE_DESCRIPTOR_HEADER>();
        const DESCRIPTOR_LAYOUT_LENGTH: usize = size_of::<STORAGE_DEVICE_DESCRIPTOR>();
        const VERSION_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, Version);
        const SIZE_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, Size);
        const REMOVABLE_MEDIA_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, RemovableMedia);
        const VENDOR_ID_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, VendorIdOffset);
        const PRODUCT_ID_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, ProductIdOffset);
        const PRODUCT_REVISION_OFFSET: usize =
            offset_of!(STORAGE_DEVICE_DESCRIPTOR, ProductRevisionOffset);
        const SERIAL_NUMBER_OFFSET: usize =
            offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset);
        const BUS_TYPE_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, BusType);
        const REQUIRED_FIXED_PREFIX_LENGTH: usize = BUS_TYPE_OFFSET + size_of::<i32>();

        const _: () = {
            assert!(HEADER_LENGTH == 8);
            assert!(size_of::<STORAGE_PROPERTY_QUERY>() == 12);
            assert!(DESCRIPTOR_LAYOUT_LENGTH == 40);
            assert!(VERSION_OFFSET == 0);
            assert!(SIZE_OFFSET == 4);
            assert!(REMOVABLE_MEDIA_OFFSET == 10);
            assert!(BUS_TYPE_OFFSET == 28);
            assert!(REQUIRED_FIXED_PREFIX_LENGTH == 32);
        };

        type DeviceIoControlBinding = unsafe extern "system" fn(
            HANDLE,
            u32,
            *const c_void,
            u32,
            *mut c_void,
            u32,
            *mut u32,
            *mut OVERLAPPED,
        ) -> BOOL;

        const DEVICE_IO_CONTROL_BINDING: DeviceIoControlBinding = DeviceIoControl;

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(super) enum LocalVolumePrerequisite {
            LocalFixedCandidate,
            Unavailable,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum BusPolicy {
            Candidate,
            VirtualOrRemoteBackingUnresolved,
            ControlledHostReviewRequired,
            Unsupported,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(super) enum DevicePropertyClassification {
            DevicePropertyCandidate,
            KnownRemovableRejected,
            VirtualOrRemoteBackingUnresolved,
            ControlledHostReviewRequired,
            DeviceFactsUnavailable,
            MalformedDeviceDescriptor,
            UnsupportedBusType,
            DeviceFactsInconsistent,
        }

        #[derive(Clone, Copy, Eq, PartialEq)]
        pub(super) enum DescriptorEvidence {
            Available(ParsedDescriptor),
            Unavailable,
            Malformed,
            Inconsistent,
        }

        impl fmt::Debug for DescriptorEvidence {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(match self {
                    Self::Available(_) => "Available",
                    Self::Unavailable => "Unavailable",
                    Self::Malformed => "Malformed",
                    Self::Inconsistent => "Inconsistent",
                })
            }
        }

        #[derive(Clone, Copy, Eq, PartialEq)]
        struct DescriptorHeader {
            version: u32,
            size: usize,
        }

        impl fmt::Debug for DescriptorHeader {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("DescriptorHeader([REDACTED])")
            }
        }

        #[derive(Clone, Copy, Eq, PartialEq)]
        pub(super) struct ParsedDescriptor {
            pub(super) removable_media: bool,
            pub(super) bus_type: i32,
        }

        impl fmt::Debug for ParsedDescriptor {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("ParsedDescriptor([REDACTED])")
            }
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum DescriptorParseError {
            MalformedDeviceDescriptor,
        }

        #[derive(Clone, Copy, Eq, PartialEq)]
        pub(super) enum DeviceProofFailure {
            FixtureUnavailable,
            LocalVolumePrerequisiteUnavailable,
            HostPrerequisiteNotMet,
            DeviceAccessUnavailable,
            DevicePropertyUnavailable,
            MalformedDeviceDescriptor,
            KnownRemovableRejected,
            VirtualOrRemoteBackingUnresolved,
            ControlledHostReviewRequired,
            UnsupportedBusType,
            DeviceFactsInconsistent,
        }

        impl DeviceProofFailure {
            fn redacted_name(self) -> &'static str {
                match self {
                    Self::FixtureUnavailable => "FixtureUnavailable",
                    Self::LocalVolumePrerequisiteUnavailable => {
                        "LocalVolumePrerequisiteUnavailable"
                    }
                    Self::HostPrerequisiteNotMet => "HostPrerequisiteNotMet",
                    Self::DeviceAccessUnavailable => "DeviceAccessUnavailable",
                    Self::DevicePropertyUnavailable => "DevicePropertyUnavailable",
                    Self::MalformedDeviceDescriptor => "MalformedDeviceDescriptor",
                    Self::KnownRemovableRejected => "KnownRemovableRejected",
                    Self::VirtualOrRemoteBackingUnresolved => "VirtualOrRemoteBackingUnresolved",
                    Self::ControlledHostReviewRequired => "ControlledHostReviewRequired",
                    Self::UnsupportedBusType => "UnsupportedBusType",
                    Self::DeviceFactsInconsistent => "DeviceFactsInconsistent",
                }
            }
        }

        impl fmt::Debug for DeviceProofFailure {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.redacted_name())
            }
        }

        #[derive(Clone, Copy, Eq, PartialEq)]
        enum DeviceProofError {
            Proof(DeviceProofFailure),
            CleanupFailed,
            ProofFailedAndCleanupFailed(DeviceProofFailure),
        }

        impl fmt::Debug for DeviceProofError {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(match self {
                    Self::Proof(failure) => failure.redacted_name(),
                    Self::CleanupFailed => "CleanupFailed",
                    Self::ProofFailedAndCleanupFailed(_) => "ProofFailedAndCleanupFailed",
                })
            }
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct NonAuthoritativeDevicePropertyReport {
            classification: DevicePropertyClassification,
            retained_test_root_handle: bool,
            strict_handle_derived_volume_guid_path: bool,
            exact_volume_device_name: bool,
            volume_open_call_count: u8,
            property_ioctl_call_count: u8,
            hot_plug_ioctl_call_count: u8,
            sentinel_preserved: bool,
            device_property_candidate_only: bool,
            device_non_removability_assurance: bool,
            hot_plug_assurance: bool,
            surprise_removal_assurance: bool,
            internal_chassis_assurance: bool,
            physical_locality_assurance: bool,
            virtual_or_remote_backing_assurance: bool,
            durability_assurance: bool,
            production_approval: bool,
            setup_authority: bool,
            startup_authority: bool,
            publication_or_replacement_authority: bool,
            database_opening_authority: bool,
            operational_installation_state_authority: bool,
        }

        fn checked_field_end(offset: usize, width: usize) -> Option<usize> {
            offset.checked_add(width)
        }

        fn read_u32(
            bytes: &[u8],
            returned_bytes: usize,
            offset: usize,
        ) -> Result<u32, DescriptorParseError> {
            let end = checked_field_end(offset, size_of::<u32>())
                .ok_or(DescriptorParseError::MalformedDeviceDescriptor)?;
            if end > returned_bytes || end > bytes.len() {
                return Err(DescriptorParseError::MalformedDeviceDescriptor);
            }
            let field: [u8; 4] = bytes[offset..end]
                .try_into()
                .map_err(|_| DescriptorParseError::MalformedDeviceDescriptor)?;
            Ok(u32::from_le_bytes(field))
        }

        fn read_i32(
            bytes: &[u8],
            returned_bytes: usize,
            offset: usize,
        ) -> Result<i32, DescriptorParseError> {
            let end = checked_field_end(offset, size_of::<i32>())
                .ok_or(DescriptorParseError::MalformedDeviceDescriptor)?;
            if end > returned_bytes || end > bytes.len() {
                return Err(DescriptorParseError::MalformedDeviceDescriptor);
            }
            let field: [u8; 4] = bytes[offset..end]
                .try_into()
                .map_err(|_| DescriptorParseError::MalformedDeviceDescriptor)?;
            Ok(i32::from_le_bytes(field))
        }

        fn validate_descriptor_size(
            version: u32,
            size: u32,
        ) -> Result<usize, DescriptorParseError> {
            let version = usize::try_from(version)
                .map_err(|_| DescriptorParseError::MalformedDeviceDescriptor)?;
            let size = usize::try_from(size)
                .map_err(|_| DescriptorParseError::MalformedDeviceDescriptor)?;
            if size < REQUIRED_FIXED_PREFIX_LENGTH
                || size < version
                || size > MAXIMUM_DESCRIPTOR_LENGTH
            {
                return Err(DescriptorParseError::MalformedDeviceDescriptor);
            }
            Ok(size)
        }

        fn parse_descriptor_header(
            bytes: &[u8],
            returned_bytes: usize,
        ) -> Result<DescriptorHeader, DescriptorParseError> {
            if returned_bytes < HEADER_LENGTH || returned_bytes > bytes.len() {
                return Err(DescriptorParseError::MalformedDeviceDescriptor);
            }
            let version = read_u32(bytes, returned_bytes, VERSION_OFFSET)?;
            if version != DESCRIPTOR_LAYOUT_LENGTH as u32 {
                return Err(DescriptorParseError::MalformedDeviceDescriptor);
            }
            let size =
                validate_descriptor_size(version, read_u32(bytes, returned_bytes, SIZE_OFFSET)?)?;
            Ok(DescriptorHeader { version, size })
        }

        fn validate_unfollowed_offsets(
            bytes: &[u8],
            returned_bytes: usize,
            descriptor_size: usize,
        ) -> Result<(), DescriptorParseError> {
            for offset_location in [
                VENDOR_ID_OFFSET,
                PRODUCT_ID_OFFSET,
                PRODUCT_REVISION_OFFSET,
                SERIAL_NUMBER_OFFSET,
            ] {
                let offset = usize::try_from(read_u32(bytes, returned_bytes, offset_location)?)
                    .map_err(|_| DescriptorParseError::MalformedDeviceDescriptor)?;
                if offset != 0 && offset >= descriptor_size {
                    return Err(DescriptorParseError::MalformedDeviceDescriptor);
                }
            }
            Ok(())
        }

        fn parse_full_descriptor(
            bytes: &[u8],
            returned_bytes: usize,
            header: DescriptorHeader,
        ) -> Result<ParsedDescriptor, DescriptorParseError> {
            if returned_bytes > bytes.len() || returned_bytes < REQUIRED_FIXED_PREFIX_LENGTH {
                return Err(DescriptorParseError::MalformedDeviceDescriptor);
            }
            let repeated = parse_descriptor_header(bytes, returned_bytes)?;
            if repeated != header || repeated.size > returned_bytes || repeated.size > bytes.len() {
                return Err(DescriptorParseError::MalformedDeviceDescriptor);
            }
            validate_unfollowed_offsets(bytes, returned_bytes, repeated.size)?;
            let removable_media = *bytes
                .get(REMOVABLE_MEDIA_OFFSET)
                .ok_or(DescriptorParseError::MalformedDeviceDescriptor)?
                != 0;
            let bus_type = read_i32(bytes, returned_bytes, BUS_TYPE_OFFSET)?;
            Ok(ParsedDescriptor {
                removable_media,
                bus_type,
            })
        }

        #[allow(non_upper_case_globals)]
        fn bus_policy(bus_type: i32) -> BusPolicy {
            match bus_type {
                BusTypeAta | BusTypeAtapi | BusTypeSata | BusTypeSas | BusTypeNvme | BusTypeUfs
                | BusTypeSCM => BusPolicy::Candidate,
                BusTypeVirtual
                | BusTypeFileBackedVirtual
                | BusTypeiScsi
                | BusTypeFibre
                | BusTypeSpaces => BusPolicy::VirtualOrRemoteBackingUnresolved,
                BusTypeUsb | BusType1394 | BusTypeSd | BusTypeMmc | BusTypeScsi | BusTypeRAID => {
                    BusPolicy::ControlledHostReviewRequired
                }
                BusTypeUnknown | BusTypeMax => BusPolicy::Unsupported,
                _ => BusPolicy::Unsupported,
            }
        }

        pub(super) fn classify(
            local_volume: LocalVolumePrerequisite,
            descriptor: DescriptorEvidence,
        ) -> DevicePropertyClassification {
            if local_volume != LocalVolumePrerequisite::LocalFixedCandidate {
                return DevicePropertyClassification::DeviceFactsUnavailable;
            }
            let descriptor = match descriptor {
                DescriptorEvidence::Available(descriptor) => descriptor,
                DescriptorEvidence::Unavailable => {
                    return DevicePropertyClassification::DeviceFactsUnavailable;
                }
                DescriptorEvidence::Malformed => {
                    return DevicePropertyClassification::MalformedDeviceDescriptor;
                }
                DescriptorEvidence::Inconsistent => {
                    return DevicePropertyClassification::DeviceFactsInconsistent;
                }
            };
            if descriptor.removable_media {
                return DevicePropertyClassification::KnownRemovableRejected;
            }
            match bus_policy(descriptor.bus_type) {
                BusPolicy::Candidate => DevicePropertyClassification::DevicePropertyCandidate,
                BusPolicy::VirtualOrRemoteBackingUnresolved => {
                    DevicePropertyClassification::VirtualOrRemoteBackingUnresolved
                }
                BusPolicy::ControlledHostReviewRequired => {
                    DevicePropertyClassification::ControlledHostReviewRequired
                }
                BusPolicy::Unsupported => DevicePropertyClassification::UnsupportedBusType,
            }
        }

        fn runtime_classification_result(
            classification: DevicePropertyClassification,
        ) -> Result<(), DeviceProofFailure> {
            match classification {
                DevicePropertyClassification::DevicePropertyCandidate => Ok(()),
                DevicePropertyClassification::KnownRemovableRejected => {
                    Err(DeviceProofFailure::KnownRemovableRejected)
                }
                DevicePropertyClassification::VirtualOrRemoteBackingUnresolved => {
                    Err(DeviceProofFailure::VirtualOrRemoteBackingUnresolved)
                }
                DevicePropertyClassification::ControlledHostReviewRequired => {
                    Err(DeviceProofFailure::ControlledHostReviewRequired)
                }
                DevicePropertyClassification::DeviceFactsUnavailable => {
                    Err(DeviceProofFailure::DevicePropertyUnavailable)
                }
                DevicePropertyClassification::MalformedDeviceDescriptor => {
                    Err(DeviceProofFailure::MalformedDeviceDescriptor)
                }
                DevicePropertyClassification::UnsupportedBusType => {
                    Err(DeviceProofFailure::UnsupportedBusType)
                }
                DevicePropertyClassification::DeviceFactsInconsistent => {
                    Err(DeviceProofFailure::DeviceFactsInconsistent)
                }
            }
        }

        pub(super) fn volume_device_name(root: &[u16]) -> Result<Vec<u16>, DeviceProofFailure> {
            let validated = validated_volume_guid_prefix(root)
                .map_err(|_| DeviceProofFailure::LocalVolumePrerequisiteUnavailable)?;
            if validated.len() != VOLUME_GUID_PREFIX_UNITS || validated.len() != root.len() {
                return Err(DeviceProofFailure::LocalVolumePrerequisiteUnavailable);
            }
            let mut device_name = validated.to_vec();
            if device_name.pop() != Some(b'\\' as u16) || device_name.len() + 1 != root.len() {
                return Err(DeviceProofFailure::LocalVolumePrerequisiteUnavailable);
            }
            Ok(device_name)
        }

        pub(super) fn open_volume_device(
            device_name: &[u16],
        ) -> Result<OwnedHandle, DeviceProofFailure> {
            let mut nul_terminated = device_name.to_vec();
            nul_terminated.push(0);
            // SAFETY: the strict volume-GUID device name has exactly one appended
            // NUL and remains live for the call. The approved open requests no
            // access, read/write sharing, OPEN_EXISTING, and no flags.
            let raw = unsafe {
                CreateFileW(
                    nul_terminated.as_ptr(),
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL_CREATE_SECURITY_ATTRIBUTES,
                    OPEN_EXISTING,
                    0,
                    NULL_CREATE_TEMPLATE_HANDLE,
                )
            };
            if raw == INVALID_HANDLE_VALUE {
                return Err(DeviceProofFailure::DeviceAccessUnavailable);
            }
            // SAFETY: ownership of the fresh successful volume handle is
            // transferred immediately and exactly once.
            Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
        }

        fn property_query() -> STORAGE_PROPERTY_QUERY {
            STORAGE_PROPERTY_QUERY {
                PropertyId: StorageDeviceProperty,
                QueryType: PropertyStandardQuery,
                AdditionalParameters: [0],
            }
        }

        pub(super) fn query_device_descriptor(
            volume: &OwnedHandle,
            ioctl_call_count: &mut u8,
        ) -> Result<ParsedDescriptor, DeviceProofFailure> {
            let query = property_query();
            let query_length = checked_buffer_length(size_of::<STORAGE_PROPERTY_QUERY>())
                .ok_or(DeviceProofFailure::DevicePropertyUnavailable)?;
            let handle = volume.as_raw_handle() as HANDLE;

            let mut header_bytes = [0_u8; HEADER_LENGTH];
            let mut header_returned = 0_u32;
            // SAFETY: the initialized query and zeroed exact-size header buffers
            // remain live for this synchronous call; all lengths are checked.
            *ioctl_call_count = ioctl_call_count.saturating_add(1);
            let header_succeeded = unsafe {
                DeviceIoControl(
                    handle,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    (&raw const query).cast::<c_void>(),
                    query_length,
                    header_bytes.as_mut_ptr().cast::<c_void>(),
                    HEADER_LENGTH as u32,
                    &raw mut header_returned,
                    std::ptr::null_mut(),
                )
            };
            if header_succeeded == 0 {
                return Err(DeviceProofFailure::DevicePropertyUnavailable);
            }
            let header_returned = usize::try_from(header_returned)
                .map_err(|_| DeviceProofFailure::MalformedDeviceDescriptor)?;
            let header = parse_descriptor_header(&header_bytes, header_returned)
                .map_err(|_| DeviceProofFailure::MalformedDeviceDescriptor)?;

            let mut descriptor_bytes = vec![0_u8; header.size];
            let mut descriptor_returned = 0_u32;
            let descriptor_capacity = checked_buffer_length(descriptor_bytes.len())
                .ok_or(DeviceProofFailure::MalformedDeviceDescriptor)?;
            // SAFETY: the same initialized query and the zeroed, exactly bounded
            // descriptor buffer remain live for this second synchronous call.
            *ioctl_call_count = ioctl_call_count.saturating_add(1);
            let descriptor_succeeded = unsafe {
                DeviceIoControl(
                    handle,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    (&raw const query).cast::<c_void>(),
                    query_length,
                    descriptor_bytes.as_mut_ptr().cast::<c_void>(),
                    descriptor_capacity,
                    &raw mut descriptor_returned,
                    std::ptr::null_mut(),
                )
            };
            if descriptor_succeeded == 0 {
                return Err(DeviceProofFailure::DevicePropertyUnavailable);
            }
            let descriptor_returned = usize::try_from(descriptor_returned)
                .map_err(|_| DeviceProofFailure::MalformedDeviceDescriptor)?;
            parse_full_descriptor(&descriptor_bytes, descriptor_returned, header)
                .map_err(|_| DeviceProofFailure::MalformedDeviceDescriptor)
        }

        type CleanupOperation = fn(&Path) -> io::Result<()>;

        fn remove_exact_root(root: &Path) -> io::Result<()> {
            fs::remove_dir_all(root)
        }

        struct DeviceFixture {
            root: PathBuf,
            sentinel: PathBuf,
            cleanup_attempted: bool,
            cleanup_operation: CleanupOperation,
        }

        impl DeviceFixture {
            fn create() -> Result<Self, DeviceProofError> {
                let counter = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| DeviceProofError::Proof(DeviceProofFailure::FixtureUnavailable))?
                    .as_nanos();
                let root = std::env::temp_dir().join(format!(
                    "{ROOT_PREFIX}{}-{nanos}-{counter}",
                    std::process::id()
                ));
                fs::create_dir(&root)
                    .map_err(|_| DeviceProofError::Proof(DeviceProofFailure::FixtureUnavailable))?;
                let sentinel = root.join(SENTINEL_NAME);
                let mut fixture = Self {
                    root,
                    sentinel,
                    cleanup_attempted: false,
                    cleanup_operation: remove_exact_root,
                };
                if fs::write(&fixture.sentinel, SENTINEL_CONTENT).is_err() {
                    let primary = DeviceProofFailure::FixtureUnavailable;
                    return match fixture.cleanup_once() {
                        Ok(()) => Err(DeviceProofError::Proof(primary)),
                        Err(_) => Err(DeviceProofError::ProofFailedAndCleanupFailed(primary)),
                    };
                }
                Ok(fixture)
            }

            fn sentinel_preserved(&self) -> Result<bool, DeviceProofFailure> {
                fs::read(&self.sentinel)
                    .map(|bytes| bytes == SENTINEL_CONTENT)
                    .map_err(|_| DeviceProofFailure::FixtureUnavailable)
            }

            fn cleanup_once(&mut self) -> Result<(), DeviceProofError> {
                if self.cleanup_attempted {
                    return Ok(());
                }
                self.cleanup_attempted = true;
                (self.cleanup_operation)(&self.root)
                    .map_err(|_| DeviceProofError::CleanupFailed)?;
                if self.root.exists() {
                    return Err(DeviceProofError::CleanupFailed);
                }
                Ok(())
            }

            fn finish(
                mut self,
                result: Result<NonAuthoritativeDevicePropertyReport, DeviceProofFailure>,
            ) -> Result<NonAuthoritativeDevicePropertyReport, DeviceProofError> {
                match (result, self.cleanup_once()) {
                    (Ok(report), Ok(())) => Ok(report),
                    (Err(failure), Ok(())) => Err(DeviceProofError::Proof(failure)),
                    (Ok(_), Err(_)) => Err(DeviceProofError::CleanupFailed),
                    (Err(failure), Err(_)) => {
                        Err(DeviceProofError::ProofFailedAndCleanupFailed(failure))
                    }
                }
            }
        }

        impl Drop for DeviceFixture {
            fn drop(&mut self) {
                if !self.cleanup_attempted {
                    self.cleanup_attempted = true;
                    let _ = (self.cleanup_operation)(&self.root);
                }
            }
        }

        fn query_fixed_drive_prerequisite(root: &[u16]) -> LocalVolumePrerequisite {
            let mut nul_terminated = root.to_vec();
            nul_terminated.push(0);
            // SAFETY: the validated exact 49-unit root has exactly one appended
            // NUL and remains live for this single prerequisite query.
            if unsafe { GetDriveTypeW(nul_terminated.as_ptr()) } == DOCUMENTED_FIXED_DRIVE_CATEGORY
            {
                LocalVolumePrerequisite::LocalFixedCandidate
            } else {
                LocalVolumePrerequisite::Unavailable
            }
        }

        fn observe_runtime_candidate()
        -> Result<NonAuthoritativeDevicePropertyReport, DeviceProofError> {
            let fixture = DeviceFixture::create()?;
            let result = (|| {
                let retained = open_hardened_directory(&fixture.root, None)
                    .map_err(|_| DeviceProofFailure::FixtureUnavailable)?;
                validate_disk_handle(&retained.handle)
                    .map_err(|_| DeviceProofFailure::FixtureUnavailable)?;
                validate_reparse_facts(retained.initial.attributes, retained.initial.reparse_tag)
                    .map_err(|_| DeviceProofFailure::FixtureUnavailable)?;
                let exact_root = validated_volume_guid_prefix(&retained.initial.final_path)
                    .map_err(|_| DeviceProofFailure::LocalVolumePrerequisiteUnavailable)?
                    .to_vec();
                if exact_root.len() != VOLUME_GUID_PREFIX_UNITS {
                    return Err(DeviceProofFailure::LocalVolumePrerequisiteUnavailable);
                }
                let local_volume = query_fixed_drive_prerequisite(&exact_root);
                if local_volume != LocalVolumePrerequisite::LocalFixedCandidate {
                    return Err(DeviceProofFailure::HostPrerequisiteNotMet);
                }
                let device_name = volume_device_name(&exact_root)?;
                let volume = open_volume_device(&device_name)?;
                let mut property_ioctl_call_count = 0;
                let descriptor = query_device_descriptor(&volume, &mut property_ioctl_call_count)?;
                let classification =
                    classify(local_volume, DescriptorEvidence::Available(descriptor));
                runtime_classification_result(classification)?;
                let sentinel_preserved = fixture.sentinel_preserved()?;
                if !sentinel_preserved {
                    return Err(DeviceProofFailure::FixtureUnavailable);
                }
                drop(volume);
                drop(retained);
                Ok(NonAuthoritativeDevicePropertyReport {
                    classification,
                    retained_test_root_handle: true,
                    strict_handle_derived_volume_guid_path: true,
                    exact_volume_device_name: true,
                    volume_open_call_count: 1,
                    property_ioctl_call_count,
                    hot_plug_ioctl_call_count: 0,
                    sentinel_preserved,
                    device_property_candidate_only: true,
                    device_non_removability_assurance: false,
                    hot_plug_assurance: false,
                    surprise_removal_assurance: false,
                    internal_chassis_assurance: false,
                    physical_locality_assurance: false,
                    virtual_or_remote_backing_assurance: false,
                    durability_assurance: false,
                    production_approval: false,
                    setup_authority: false,
                    startup_authority: false,
                    publication_or_replacement_authority: false,
                    database_opening_authority: false,
                    operational_installation_state_authority: false,
                })
            })();
            fixture.finish(result)
        }

        fn strict_root() -> Vec<u16> {
            ascii_units(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\")
        }

        fn descriptor_bytes(removable: u8, bus_type: i32) -> Vec<u8> {
            let mut bytes = vec![0_u8; DESCRIPTOR_LAYOUT_LENGTH];
            bytes[VERSION_OFFSET..VERSION_OFFSET + 4]
                .copy_from_slice(&(DESCRIPTOR_LAYOUT_LENGTH as u32).to_le_bytes());
            bytes[SIZE_OFFSET..SIZE_OFFSET + 4]
                .copy_from_slice(&(DESCRIPTOR_LAYOUT_LENGTH as u32).to_le_bytes());
            bytes[REMOVABLE_MEDIA_OFFSET] = removable;
            bytes[BUS_TYPE_OFFSET..BUS_TYPE_OFFSET + 4].copy_from_slice(&bus_type.to_le_bytes());
            bytes
        }

        fn header_bytes(version: u32, size: u32) -> [u8; HEADER_LENGTH] {
            let mut bytes = [0_u8; HEADER_LENGTH];
            bytes[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&version.to_le_bytes());
            bytes[SIZE_OFFSET..SIZE_OFFSET + 4].copy_from_slice(&size.to_le_bytes());
            bytes
        }

        fn parsed(removable_media: bool, bus_type: i32) -> DescriptorEvidence {
            DescriptorEvidence::Available(ParsedDescriptor {
                removable_media,
                bus_type,
            })
        }

        fn injected_cleanup_failure(_: &Path) -> io::Result<()> {
            Err(io::ErrorKind::Other.into())
        }

        #[test]
        fn device_property_policy_bindings_features_signatures_sizes_and_offsets_are_exact() {
            let _: DeviceIoControlBinding = DEVICE_IO_CONTROL_BINDING;
            let _: STORAGE_PROPERTY_QUERY = property_query();
            let _: STORAGE_DESCRIPTOR_HEADER = STORAGE_DESCRIPTOR_HEADER::default();
            let _: STORAGE_DEVICE_DESCRIPTOR = STORAGE_DEVICE_DESCRIPTOR::default();
            assert_eq!(HEADER_LENGTH, 8);
            assert_eq!(size_of::<STORAGE_PROPERTY_QUERY>(), 12);
            assert_eq!(DESCRIPTOR_LAYOUT_LENGTH, 40);
            assert_eq!(VERSION_OFFSET, 0);
            assert_eq!(SIZE_OFFSET, 4);
            assert_eq!(REMOVABLE_MEDIA_OFFSET, 10);
            assert_eq!(BUS_TYPE_OFFSET, 28);
            assert_eq!(REQUIRED_FIXED_PREFIX_LENGTH, 32);
            let query = property_query();
            assert_eq!(query.PropertyId, StorageDeviceProperty);
            assert_eq!(query.QueryType, PropertyStandardQuery);
            assert_eq!(query.AdditionalParameters, [0]);

            let cargo = include_str!("../../Cargo.toml");
            for feature in ["Win32_System_IO", "Win32_System_Ioctl"] {
                assert_eq!(cargo.matches(feature).count(), 1);
            }
        }

        #[test]
        fn device_property_policy_exact_root_transformation_is_narrow_and_malformed_fails() {
            let root = strict_root();
            assert_eq!(root.len(), VOLUME_GUID_PREFIX_UNITS);
            let device = volume_device_name(&root).unwrap();
            assert_eq!(device.len(), VOLUME_GUID_PREFIX_UNITS - 1);
            assert_eq!(
                device,
                ascii_units(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}")
            );
            assert!(!device.contains(&0));

            for malformed in [
                ascii_units(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}"),
                ascii_units(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\\"),
                ascii_units(r"\\.\C:\"),
                ascii_units(r"\\server\share\"),
                ascii_units(r"\\?\Volume{g1234567-89ab-cdef-0123-456789abcdef}\"),
            ] {
                assert_eq!(
                    volume_device_name(&malformed),
                    Err(DeviceProofFailure::LocalVolumePrerequisiteUnavailable)
                );
            }
        }

        #[test]
        fn device_property_policy_header_bounds_version_size_and_overflow_fail_closed() {
            let valid = header_bytes(
                DESCRIPTOR_LAYOUT_LENGTH as u32,
                DESCRIPTOR_LAYOUT_LENGTH as u32,
            );
            assert!(parse_descriptor_header(&valid, HEADER_LENGTH).is_ok());
            assert_eq!(
                parse_descriptor_header(&valid, HEADER_LENGTH - 1),
                Err(DescriptorParseError::MalformedDeviceDescriptor)
            );
            assert_eq!(
                parse_descriptor_header(&valid, HEADER_LENGTH + 1),
                Err(DescriptorParseError::MalformedDeviceDescriptor)
            );
            for size in REQUIRED_FIXED_PREFIX_LENGTH..DESCRIPTOR_LAYOUT_LENGTH {
                assert_eq!(
                    parse_descriptor_header(
                        &header_bytes(DESCRIPTOR_LAYOUT_LENGTH as u32, size as u32),
                        HEADER_LENGTH,
                    ),
                    Err(DescriptorParseError::MalformedDeviceDescriptor)
                );
            }
            for (version, size) in [
                (DESCRIPTOR_LAYOUT_LENGTH as u32, 0),
                (
                    DESCRIPTOR_LAYOUT_LENGTH as u32,
                    (REQUIRED_FIXED_PREFIX_LENGTH - 1) as u32,
                ),
                (
                    DESCRIPTOR_LAYOUT_LENGTH as u32,
                    (MAXIMUM_DESCRIPTOR_LENGTH + 1) as u32,
                ),
                (
                    (DESCRIPTOR_LAYOUT_LENGTH - 1) as u32,
                    DESCRIPTOR_LAYOUT_LENGTH as u32,
                ),
                (
                    (DESCRIPTOR_LAYOUT_LENGTH + 1) as u32,
                    DESCRIPTOR_LAYOUT_LENGTH as u32,
                ),
            ] {
                assert_eq!(
                    parse_descriptor_header(&header_bytes(version, size), HEADER_LENGTH),
                    Err(DescriptorParseError::MalformedDeviceDescriptor)
                );
            }
            assert_eq!(checked_field_end(usize::MAX, 1), None);
        }

        #[test]
        fn device_property_policy_full_descriptor_rejects_truncation_changes_and_bad_offsets() {
            let bytes = descriptor_bytes(0, BusTypeNvme);
            let header = parse_descriptor_header(&bytes, HEADER_LENGTH).unwrap();
            assert!(parse_full_descriptor(&bytes, bytes.len(), header).is_ok());
            assert_eq!(
                parse_full_descriptor(&bytes, REQUIRED_FIXED_PREFIX_LENGTH - 1, header),
                Err(DescriptorParseError::MalformedDeviceDescriptor)
            );
            assert_eq!(
                parse_full_descriptor(&bytes, bytes.len() + 1, header),
                Err(DescriptorParseError::MalformedDeviceDescriptor)
            );

            let mut changed_version = bytes.clone();
            changed_version[VERSION_OFFSET..VERSION_OFFSET + 4]
                .copy_from_slice(&((DESCRIPTOR_LAYOUT_LENGTH + 1) as u32).to_le_bytes());
            assert_eq!(
                parse_full_descriptor(&changed_version, changed_version.len(), header),
                Err(DescriptorParseError::MalformedDeviceDescriptor)
            );

            for changed_size_value in REQUIRED_FIXED_PREFIX_LENGTH..DESCRIPTOR_LAYOUT_LENGTH {
                let mut changed_size = bytes.clone();
                changed_size[SIZE_OFFSET..SIZE_OFFSET + 4]
                    .copy_from_slice(&(changed_size_value as u32).to_le_bytes());
                assert_eq!(
                    parse_full_descriptor(&changed_size, changed_size.len(), header),
                    Err(DescriptorParseError::MalformedDeviceDescriptor)
                );
            }

            for offset_location in [
                VENDOR_ID_OFFSET,
                PRODUCT_ID_OFFSET,
                PRODUCT_REVISION_OFFSET,
                SERIAL_NUMBER_OFFSET,
            ] {
                let mut impossible = bytes.clone();
                impossible[offset_location..offset_location + 4]
                    .copy_from_slice(&(DESCRIPTOR_LAYOUT_LENGTH as u32).to_le_bytes());
                assert_eq!(
                    parse_full_descriptor(&impossible, impossible.len(), header),
                    Err(DescriptorParseError::MalformedDeviceDescriptor)
                );
            }
        }

        #[test]
        fn device_property_policy_removable_byte_and_removable_precedence_are_exact() {
            for removable in [0_u8, 1, 2, u8::MAX] {
                let bytes = descriptor_bytes(removable, BusTypeNvme);
                let header = parse_descriptor_header(&bytes, HEADER_LENGTH).unwrap();
                let parsed = parse_full_descriptor(&bytes, bytes.len(), header).unwrap();
                assert_eq!(parsed.removable_media, removable != 0);
            }
            for bus in [
                BusTypeAta,
                BusTypeVirtual,
                BusTypeUsb,
                BusTypeUnknown,
                BusTypeMax,
                127,
            ] {
                assert_eq!(
                    classify(
                        LocalVolumePrerequisite::LocalFixedCandidate,
                        parsed(true, bus),
                    ),
                    DevicePropertyClassification::KnownRemovableRejected
                );
            }
        }

        #[test]
        fn device_property_policy_bus_families_follow_the_locked_policy() {
            for bus in [
                BusTypeAta,
                BusTypeAtapi,
                BusTypeSata,
                BusTypeSas,
                BusTypeNvme,
                BusTypeUfs,
                BusTypeSCM,
            ] {
                assert_eq!(bus_policy(bus), BusPolicy::Candidate);
                assert_eq!(
                    classify(
                        LocalVolumePrerequisite::LocalFixedCandidate,
                        parsed(false, bus),
                    ),
                    DevicePropertyClassification::DevicePropertyCandidate
                );
            }
            for bus in [
                BusTypeVirtual,
                BusTypeFileBackedVirtual,
                BusTypeiScsi,
                BusTypeFibre,
                BusTypeSpaces,
            ] {
                assert_eq!(
                    classify(
                        LocalVolumePrerequisite::LocalFixedCandidate,
                        parsed(false, bus),
                    ),
                    DevicePropertyClassification::VirtualOrRemoteBackingUnresolved
                );
            }
            for bus in [
                BusTypeUsb,
                BusType1394,
                BusTypeSd,
                BusTypeMmc,
                BusTypeScsi,
                BusTypeRAID,
            ] {
                assert_eq!(
                    classify(
                        LocalVolumePrerequisite::LocalFixedCandidate,
                        parsed(false, bus),
                    ),
                    DevicePropertyClassification::ControlledHostReviewRequired
                );
            }
            for bus in [BusTypeUnknown, BusTypeMax, -1, 20, 21, 127, i32::MAX] {
                assert_eq!(bus_policy(bus), BusPolicy::Unsupported);
                assert_eq!(
                    classify(
                        LocalVolumePrerequisite::LocalFixedCandidate,
                        parsed(false, bus),
                    ),
                    DevicePropertyClassification::UnsupportedBusType
                );
            }
        }

        #[test]
        fn device_property_policy_unavailable_malformed_inconsistent_and_authority_are_closed() {
            for descriptor in [
                DescriptorEvidence::Available(ParsedDescriptor {
                    removable_media: false,
                    bus_type: BusTypeNvme,
                }),
                DescriptorEvidence::Unavailable,
                DescriptorEvidence::Malformed,
                DescriptorEvidence::Inconsistent,
            ] {
                assert_ne!(
                    classify(LocalVolumePrerequisite::Unavailable, descriptor),
                    DevicePropertyClassification::DevicePropertyCandidate
                );
            }
            assert_eq!(
                classify(
                    LocalVolumePrerequisite::LocalFixedCandidate,
                    DescriptorEvidence::Unavailable,
                ),
                DevicePropertyClassification::DeviceFactsUnavailable
            );
            assert_eq!(
                classify(
                    LocalVolumePrerequisite::LocalFixedCandidate,
                    DescriptorEvidence::Malformed,
                ),
                DevicePropertyClassification::MalformedDeviceDescriptor
            );
            assert_eq!(
                classify(
                    LocalVolumePrerequisite::LocalFixedCandidate,
                    DescriptorEvidence::Inconsistent,
                ),
                DevicePropertyClassification::DeviceFactsInconsistent
            );

            let runtime_failures = [
                (
                    DevicePropertyClassification::KnownRemovableRejected,
                    DeviceProofFailure::KnownRemovableRejected,
                ),
                (
                    DevicePropertyClassification::VirtualOrRemoteBackingUnresolved,
                    DeviceProofFailure::VirtualOrRemoteBackingUnresolved,
                ),
                (
                    DevicePropertyClassification::ControlledHostReviewRequired,
                    DeviceProofFailure::ControlledHostReviewRequired,
                ),
                (
                    DevicePropertyClassification::UnsupportedBusType,
                    DeviceProofFailure::UnsupportedBusType,
                ),
                (
                    DevicePropertyClassification::MalformedDeviceDescriptor,
                    DeviceProofFailure::MalformedDeviceDescriptor,
                ),
                (
                    DevicePropertyClassification::DeviceFactsUnavailable,
                    DeviceProofFailure::DevicePropertyUnavailable,
                ),
                (
                    DevicePropertyClassification::DeviceFactsInconsistent,
                    DeviceProofFailure::DeviceFactsInconsistent,
                ),
            ];
            assert_eq!(
                runtime_classification_result(
                    DevicePropertyClassification::DevicePropertyCandidate
                ),
                Ok(())
            );
            for (classification, failure) in runtime_failures {
                assert_eq!(runtime_classification_result(classification), Err(failure));
                if classification != DevicePropertyClassification::DeviceFactsUnavailable {
                    assert_ne!(failure, DeviceProofFailure::DevicePropertyUnavailable);
                }
            }

            for primary in [
                DeviceProofFailure::KnownRemovableRejected,
                DeviceProofFailure::VirtualOrRemoteBackingUnresolved,
                DeviceProofFailure::ControlledHostReviewRequired,
                DeviceProofFailure::UnsupportedBusType,
                DeviceProofFailure::DeviceFactsInconsistent,
            ] {
                let fixture = DeviceFixture {
                    root: PathBuf::from("synthetic-device-property-root"),
                    sentinel: PathBuf::from("synthetic-device-property-sentinel"),
                    cleanup_attempted: false,
                    cleanup_operation: injected_cleanup_failure,
                };
                assert_eq!(
                    fixture.finish(Err(primary)),
                    Err(DeviceProofError::ProofFailedAndCleanupFailed(primary))
                );
            }

            assert_ne!(
                DeviceProofFailure::DeviceAccessUnavailable,
                DeviceProofFailure::DevicePropertyUnavailable
            );
            assert_ne!(
                DeviceProofFailure::LocalVolumePrerequisiteUnavailable,
                DeviceProofFailure::HostPrerequisiteNotMet
            );

            let report = NonAuthoritativeDevicePropertyReport {
                classification: DevicePropertyClassification::DevicePropertyCandidate,
                retained_test_root_handle: true,
                strict_handle_derived_volume_guid_path: true,
                exact_volume_device_name: true,
                volume_open_call_count: 1,
                property_ioctl_call_count: 2,
                hot_plug_ioctl_call_count: 0,
                sentinel_preserved: true,
                device_property_candidate_only: true,
                device_non_removability_assurance: false,
                hot_plug_assurance: false,
                surprise_removal_assurance: false,
                internal_chassis_assurance: false,
                physical_locality_assurance: false,
                virtual_or_remote_backing_assurance: false,
                durability_assurance: false,
                production_approval: false,
                setup_authority: false,
                startup_authority: false,
                publication_or_replacement_authority: false,
                database_opening_authority: false,
                operational_installation_state_authority: false,
            };
            assert!(report.device_property_candidate_only);
            assert!(!report.device_non_removability_assurance);
            assert!(!report.hot_plug_assurance);
            assert!(!report.surprise_removal_assurance);
            assert!(!report.internal_chassis_assurance);
            assert!(!report.physical_locality_assurance);
            assert!(!report.virtual_or_remote_backing_assurance);
            assert!(!report.durability_assurance);
            assert!(!report.production_approval);
            assert!(!report.setup_authority);
            assert!(!report.startup_authority);
            assert!(!report.publication_or_replacement_authority);
            assert!(!report.database_opening_authority);
            assert!(!report.operational_installation_state_authority);
        }

        #[test]
        fn device_property_policy_errors_and_debug_are_redacted() {
            for failure in [
                DeviceProofFailure::FixtureUnavailable,
                DeviceProofFailure::LocalVolumePrerequisiteUnavailable,
                DeviceProofFailure::HostPrerequisiteNotMet,
                DeviceProofFailure::DeviceAccessUnavailable,
                DeviceProofFailure::DevicePropertyUnavailable,
                DeviceProofFailure::MalformedDeviceDescriptor,
                DeviceProofFailure::KnownRemovableRejected,
                DeviceProofFailure::VirtualOrRemoteBackingUnresolved,
                DeviceProofFailure::ControlledHostReviewRequired,
                DeviceProofFailure::UnsupportedBusType,
                DeviceProofFailure::DeviceFactsInconsistent,
            ] {
                let debug = format!("{failure:?}");
                assert!(!debug.contains('\\'));
                assert!(!debug.contains('/'));
                assert!(!debug.contains("0x"));
                assert!(!debug.chars().any(|character| character.is_ascii_digit()));
            }
            assert_eq!(format!("{:?}", parsed(false, BusTypeNvme)), "Available");
            assert_eq!(
                format!(
                    "{:?}",
                    DescriptorHeader {
                        version: DESCRIPTOR_LAYOUT_LENGTH as u32,
                        size: DESCRIPTOR_LAYOUT_LENGTH,
                    }
                ),
                "DescriptorHeader([REDACTED])"
            );
        }

        #[test]
        fn device_property_policy_runtime_observes_unique_root_volume_and_descriptor() {
            let report = observe_runtime_candidate().unwrap_or_else(|error| panic!("{error:?}"));
            assert_eq!(
                report.classification,
                DevicePropertyClassification::DevicePropertyCandidate
            );
            assert!(report.retained_test_root_handle);
            assert!(report.strict_handle_derived_volume_guid_path);
            assert!(report.exact_volume_device_name);
            assert_eq!(report.volume_open_call_count, 1);
            assert_eq!(report.property_ioctl_call_count, 2);
            assert_eq!(report.hot_plug_ioctl_call_count, 0);
            assert!(report.sentinel_preserved);
        }

        #[test]
        fn device_property_policy_source_is_test_only_narrow_and_excludes_unapproved_surfaces() {
            let source = include_str!("windows_filesystem.rs");
            let (production, tests) = source.split_once("#[cfg(test)]").unwrap();
            assert!(!production.contains("device_property_policy"));
            assert!(!production.contains("DeviceIoControl"));
            assert!(!production.contains(ROOT_PREFIX));
            let implementation = tests
                .split_once("// DEVICE-PROPERTY CANDIDATE PROOF START")
                .unwrap()
                .1
                .split_once("// DEVICE-PROPERTY CANDIDATE PROOF END")
                .unwrap()
                .0;
            let implementation_without_tests = implementation.split_once("#[test]").unwrap().0;
            assert!(implementation_without_tests.contains("IOCTL_STORAGE_QUERY_PROPERTY"));
            assert!(implementation_without_tests.contains("StorageDeviceProperty"));
            assert!(implementation_without_tests.contains("PropertyStandardQuery"));
            assert_eq!(
                implementation_without_tests
                    .matches("IOCTL_STORAGE_QUERY_PROPERTY")
                    .count(),
                3
            );
            assert_eq!(
                implementation_without_tests
                    .matches("DeviceIoControl(")
                    .count(),
                2
            );
            assert_eq!(
                implementation_without_tests
                    .matches("CreateFileW(\n                    nul_terminated.as_ptr()")
                    .count(),
                1
            );
            for forbidden in [
                concat!("IOCTL_STORAGE_GET_", "HOTPLUG_INFO"),
                concat!("STORAGE_", "HOTPLUG_INFO"),
                concat!("IOCTL_STORAGE_GET_", "DEVICE_NUMBER"),
                concat!("IOCTL_VOLUME_GET_", "VOLUME_DISK_EXTENTS"),
                concat!("Physical", "Drive"),
                concat!("Setup", "Di"),
                concat!("CM_Get_", "Device_Interface"),
                concat!("Win32_", "PnPEntity"),
                concat!("Reg", "OpenKey"),
                concat!("Command::", "new"),
                concat!("Virt", "Disk"),
                concat!("resolve_", "production"),
                concat!("Crypt", "ProtectData"),
                concat!("rusq", "lite"),
                concat!("tauri::", "command"),
                concat!("impl Fr", "om<DevicePropertyClassification"),
                concat!("impl In", "to<"),
            ] {
                assert!(
                    !implementation_without_tests.contains(forbidden),
                    "forbidden device source"
                );
            }
            assert!(!implementation_without_tests.contains("FILE_SHARE_DELETE"));
            assert!(!implementation_without_tests.contains("FILE_FLAG_BACKUP_SEMANTICS"));
            assert!(!implementation_without_tests.contains("FILE_FLAG_OVERLAPPED"));
            assert!(!implementation_without_tests.contains("FILE_READ_ATTRIBUTES"));
        }
    }
    // DEVICE-PROPERTY CANDIDATE PROOF END.

    // CONTROLLED STORAGE HOST MATRIX START. This entire private harness remains
    // beneath the Windows #[cfg(test)] boundary above.
    mod controlled_storage_host_matrix {
        use super::*;
        use super::{device_property_policy as device, local_volume_policy as local};

        const USB_ROOT_ENVIRONMENT_VARIABLE: &str = "CHURCH_APP_USB_TEST_ROOT";
        const USB_CHILD_PREFIX: &str = "church-app-usb-flash-proof-";
        const BASELINE_CHILD_PREFIX: &str = "church-app-current-account-proof-";
        const SENTINEL_NAME: &str = "unrelated-sentinel.synthetic";
        const SENTINEL_CONTENT: &[u8] = b"synthetic-sentinel-preserved";
        const ACCOUNT_CONTEXT: &str = "Current Windows account, non-elevated session; administrator-group membership not established.";

        static CLEANUP_TEST_CALLS: AtomicU64 = AtomicU64::new(0);

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum CaseKind {
            CurrentWindows11InternalBaseline,
            UsbFlash,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum AccountContextCategory {
            CurrentWindowsAccountNonElevatedMembershipUnestablished,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Prerequisite {
            Present,
            Absent,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum CoarseLocalVolumeClassification {
            LocalFixedCandidate,
            LocalVolumeRejected,
            Unavailable,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum CoarseDevicePropertyClassification {
            NotReached,
            DevicePropertyCandidate,
            KnownRemovableRejected,
            ControlledHostReviewRequired,
            VirtualOrRemoteBackingUnresolved,
            Unavailable,
            Unsupported,
            MalformedOrInconsistent,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum RemovableFactBucket {
            NotReached,
            KnownRemovable,
            NotReportedRemovable,
            Unavailable,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum BusFamilyBucket {
            NotReached,
            CandidateFamily,
            ManualReviewFamily,
            VirtualOrRemoteUnresolvedFamily,
            UnsupportedFamily,
            Unavailable,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum CaseStatus {
            Pass,
            Fail,
            PrerequisiteAbsent,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum SentinelState {
            NotReached,
            Preserved,
            Unavailable,
            Changed,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum DiagnosticDisposition {
            Unavailable,
            Rejected,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum DirectoryDiagnosticStage {
            DirectoryPathEncodingUnavailable,
            DirectoryOpenUnavailable,
            DiskHandleFactUnavailable,
            NonDiskHandleRejected,
            DirectoryStandardInfoUnavailable,
            DirectoryStandardFactsRejected,
            DirectoryAttributeInfoUnavailable,
            DirectoryEntryRejected,
            DirectoryIdentityUnavailable,
            DirectoryLinkInfoUnavailable,
            NormalizedGuidPathUnavailable,
            VolumeGuidPathMalformed,
            ReparseFactsRejected,
        }

        impl DirectoryDiagnosticStage {
            const fn disposition(self) -> DiagnosticDisposition {
                match self {
                    Self::DirectoryPathEncodingUnavailable
                    | Self::DirectoryOpenUnavailable
                    | Self::DiskHandleFactUnavailable
                    | Self::DirectoryStandardInfoUnavailable
                    | Self::DirectoryAttributeInfoUnavailable
                    | Self::DirectoryIdentityUnavailable
                    | Self::DirectoryLinkInfoUnavailable
                    | Self::NormalizedGuidPathUnavailable => DiagnosticDisposition::Unavailable,
                    Self::NonDiskHandleRejected
                    | Self::DirectoryStandardFactsRejected
                    | Self::DirectoryEntryRejected
                    | Self::VolumeGuidPathMalformed
                    | Self::ReparseFactsRejected => DiagnosticDisposition::Rejected,
                }
            }
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct DirectoryDiagnosticFailure {
            stage: DirectoryDiagnosticStage,
            disposition: DiagnosticDisposition,
        }

        impl DirectoryDiagnosticFailure {
            const fn at(stage: DirectoryDiagnosticStage) -> Self {
                Self {
                    stage,
                    disposition: stage.disposition(),
                }
            }
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum FixtureCreationFailure {
            FixtureChildCreationUnavailable,
            SentinelWriteUnavailable,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum FixtureCreationCleanupOutcome {
            NotAttempted,
            Succeeded,
            Failed,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct FixtureCreationError {
            primary: FixtureCreationFailure,
            cleanup: FixtureCreationCleanupOutcome,
        }

        impl FixtureCreationError {
            const fn child_creation_unavailable() -> Self {
                Self {
                    primary: FixtureCreationFailure::FixtureChildCreationUnavailable,
                    cleanup: FixtureCreationCleanupOutcome::NotAttempted,
                }
            }
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum CoarseFailureCategory {
            None,
            MissingManualUsbRoot,
            InvalidManualRoot,
            FixtureChildCreationUnavailable,
            SentinelWriteUnavailable,
            HardenedDirectoryPrerequisite,
            ClassificationUnavailable,
            BaselineMismatch,
            UsbCandidateDefectUnresolved,
            SentinelChangedOrUnavailable,
            CleanupFailed,
            PrimaryAndCleanupFailed,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct AuthorityFields {
            production_policy: bool,
            persistence: bool,
            database_opening: bool,
            setup: bool,
            startup: bool,
            publication_or_replacement: bool,
            installation_state: bool,
        }

        impl AuthorityFields {
            const fn all_false() -> Self {
                Self {
                    production_policy: false,
                    persistence: false,
                    database_opening: false,
                    setup: false,
                    startup: false,
                    publication_or_replacement: false,
                    installation_state: false,
                }
            }

            fn every_field_is_false(self) -> bool {
                !self.production_policy
                    && !self.persistence
                    && !self.database_opening
                    && !self.setup
                    && !self.startup
                    && !self.publication_or_replacement
                    && !self.installation_state
            }
        }

        #[derive(Clone, Copy, Eq, PartialEq)]
        struct RedactedCaseResult {
            case_kind: CaseKind,
            account_context: AccountContextCategory,
            prerequisite: Prerequisite,
            local_volume: CoarseLocalVolumeClassification,
            device_property: CoarseDevicePropertyClassification,
            removable_fact: RemovableFactBucket,
            bus_family: BusFamilyBucket,
            drive_type_call_count: u8,
            volume_open_count: u8,
            property_ioctl_count: u8,
            hot_plug_count: u8,
            sentinel_state: SentinelState,
            exact_root_cleanup_attempted: bool,
            exact_root_cleanup_succeeded: bool,
            expected_result_matched: bool,
            status: CaseStatus,
            failure: CoarseFailureCategory,
            primary_failure: Option<CoarseFailureCategory>,
            diagnostic_failure: Option<DirectoryDiagnosticFailure>,
            authority: AuthorityFields,
        }

        impl fmt::Debug for RedactedCaseResult {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct("RedactedCaseResult")
                    .field("case_kind", &self.case_kind)
                    .field("account_context", &self.account_context)
                    .field("prerequisite", &self.prerequisite)
                    .field("local_volume", &self.local_volume)
                    .field("device_property", &self.device_property)
                    .field("removable_fact", &self.removable_fact)
                    .field("bus_family", &self.bus_family)
                    .field("drive_type_call_count", &self.drive_type_call_count)
                    .field("volume_open_count", &self.volume_open_count)
                    .field("property_ioctl_count", &self.property_ioctl_count)
                    .field("hot_plug_count", &self.hot_plug_count)
                    .field("sentinel_state", &self.sentinel_state)
                    .field(
                        "exact_root_cleanup_attempted",
                        &self.exact_root_cleanup_attempted,
                    )
                    .field(
                        "exact_root_cleanup_succeeded",
                        &self.exact_root_cleanup_succeeded,
                    )
                    .field("expected_result_matched", &self.expected_result_matched)
                    .field("status", &self.status)
                    .field("failure", &self.failure)
                    .field("diagnostic_failure", &self.diagnostic_failure)
                    .field("authority", &self.authority)
                    .finish()
            }
        }

        impl RedactedCaseResult {
            fn initial(case_kind: CaseKind, prerequisite: Prerequisite) -> Self {
                Self {
                    case_kind,
                    account_context:
                        AccountContextCategory::CurrentWindowsAccountNonElevatedMembershipUnestablished,
                    prerequisite,
                    local_volume: CoarseLocalVolumeClassification::Unavailable,
                    device_property: CoarseDevicePropertyClassification::NotReached,
                    removable_fact: RemovableFactBucket::NotReached,
                    bus_family: BusFamilyBucket::NotReached,
                    drive_type_call_count: 0,
                    volume_open_count: 0,
                    property_ioctl_count: 0,
                    hot_plug_count: 0,
                    sentinel_state: SentinelState::NotReached,
                    exact_root_cleanup_attempted: false,
                    exact_root_cleanup_succeeded: false,
                    expected_result_matched: false,
                    status: CaseStatus::Fail,
                    failure: CoarseFailureCategory::None,
                    primary_failure: None,
                    diagnostic_failure: None,
                    authority: AuthorityFields::all_false(),
                }
            }

            fn prerequisite_absent() -> Self {
                let mut result = Self::initial(CaseKind::UsbFlash, Prerequisite::Absent);
                result.status = CaseStatus::PrerequisiteAbsent;
                result.failure = CoarseFailureCategory::MissingManualUsbRoot;
                result
            }
        }

        fn unique_child_name(prefix: &str, pid: u32, nanos: u128, counter: u64) -> String {
            format!("{prefix}{pid}-{nanos}-{counter}")
        }

        fn contains_embedded_nul(path: &Path) -> bool {
            path.as_os_str().encode_wide().any(|unit| unit == 0)
        }

        fn validate_manual_root(root: &Path) -> bool {
            root.is_absolute() && !contains_embedded_nul(root) && root.exists() && root.is_dir()
        }

        fn sentinel_state_from_read(read: io::Result<Vec<u8>>) -> SentinelState {
            match read {
                Ok(bytes) if bytes == SENTINEL_CONTENT => SentinelState::Preserved,
                Ok(_) => SentinelState::Changed,
                Err(_) => SentinelState::Unavailable,
            }
        }

        type CleanupOperation = fn(&Path) -> io::Result<()>;

        fn remove_exact_root(root: &Path) -> io::Result<()> {
            fs::remove_dir_all(root)
        }

        struct Fixture {
            root: PathBuf,
            sentinel: PathBuf,
            cleanup_attempted: bool,
            cleanup_succeeded: bool,
            cleanup_operation: CleanupOperation,
        }

        impl Fixture {
            fn create(
                parent: &Path,
                prefix: &str,
                cleanup_operation: CleanupOperation,
            ) -> Result<Self, FixtureCreationError> {
                Self::create_with(
                    parent,
                    prefix,
                    cleanup_operation,
                    |path| fs::create_dir(path),
                    |path, content| fs::write(path, content),
                )
            }

            fn create_with(
                parent: &Path,
                prefix: &str,
                cleanup_operation: CleanupOperation,
                create_child: impl FnOnce(&Path) -> io::Result<()>,
                write_sentinel: impl FnOnce(&Path, &[u8]) -> io::Result<()>,
            ) -> Result<Self, FixtureCreationError> {
                let counter = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| FixtureCreationError::child_creation_unavailable())?
                    .as_nanos();
                let root = parent.join(unique_child_name(
                    prefix,
                    std::process::id(),
                    nanos,
                    counter,
                ));
                create_child(&root)
                    .map_err(|_| FixtureCreationError::child_creation_unavailable())?;
                let sentinel = root.join(SENTINEL_NAME);
                let mut fixture = Self {
                    root,
                    sentinel,
                    cleanup_attempted: false,
                    cleanup_succeeded: false,
                    cleanup_operation,
                };
                if write_sentinel(&fixture.sentinel, SENTINEL_CONTENT).is_err() {
                    let cleanup = match fixture.cleanup_once() {
                        Ok(()) => FixtureCreationCleanupOutcome::Succeeded,
                        Err(_) => FixtureCreationCleanupOutcome::Failed,
                    };
                    return Err(FixtureCreationError {
                        primary: FixtureCreationFailure::SentinelWriteUnavailable,
                        cleanup,
                    });
                }
                Ok(fixture)
            }

            fn sentinel_state(&self) -> SentinelState {
                sentinel_state_from_read(fs::read(&self.sentinel))
            }

            fn cleanup_once(&mut self) -> io::Result<()> {
                if self.cleanup_attempted {
                    return if self.cleanup_succeeded {
                        Ok(())
                    } else {
                        Err(io::Error::other("coarse cleanup already failed"))
                    };
                }
                self.cleanup_attempted = true;
                (self.cleanup_operation)(&self.root)?;
                if self.root.exists() {
                    return Err(io::Error::other("coarse cleanup failed"));
                }
                self.cleanup_succeeded = true;
                Ok(())
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                if !self.cleanup_attempted {
                    let _ = self.cleanup_once();
                }
            }
        }

        const DIRECTORY_DIAGNOSTIC_ORDER: [DirectoryDiagnosticStage; 13] = [
            DirectoryDiagnosticStage::DirectoryPathEncodingUnavailable,
            DirectoryDiagnosticStage::DirectoryOpenUnavailable,
            DirectoryDiagnosticStage::DiskHandleFactUnavailable,
            DirectoryDiagnosticStage::NonDiskHandleRejected,
            DirectoryDiagnosticStage::DirectoryStandardInfoUnavailable,
            DirectoryDiagnosticStage::DirectoryAttributeInfoUnavailable,
            DirectoryDiagnosticStage::DirectoryStandardFactsRejected,
            DirectoryDiagnosticStage::DirectoryIdentityUnavailable,
            DirectoryDiagnosticStage::DirectoryLinkInfoUnavailable,
            DirectoryDiagnosticStage::NormalizedGuidPathUnavailable,
            DirectoryDiagnosticStage::DirectoryEntryRejected,
            DirectoryDiagnosticStage::ReparseFactsRejected,
            DirectoryDiagnosticStage::VolumeGuidPathMalformed,
        ];

        fn first_injected_directory_failure(
            failures: &[DirectoryDiagnosticStage],
            visited: &mut Vec<DirectoryDiagnosticStage>,
        ) -> Option<DirectoryDiagnosticFailure> {
            for stage in DIRECTORY_DIAGNOSTIC_ORDER {
                visited.push(stage);
                if failures.contains(&stage) {
                    return Some(DirectoryDiagnosticFailure::at(stage));
                }
            }
            None
        }

        fn require_disk_handle_diagnostically(
            file: &File,
        ) -> Result<(), DirectoryDiagnosticFailure> {
            // SAFETY: the live File owns the handle for the duration of the call.
            let file_type = unsafe { GetFileType(file.as_raw_handle() as HANDLE) };
            if file_type == 0 {
                // SAFETY: called immediately after the potentially failed native operation,
                // matching the accepted shared helper without retaining the native value.
                let _native_error = unsafe { GetLastError() };
                return Err(DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::DiskHandleFactUnavailable,
                ));
            }
            if file_type != FILE_TYPE_DISK {
                return Err(DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::NonDiskHandleRejected,
                ));
            }
            Ok(())
        }

        fn open_hardened_directory_diagnostically(
            path: &Path,
        ) -> Result<RetainedDirectory, DirectoryDiagnosticFailure> {
            let encoded = encode_utf16_path(path).map_err(|_| {
                DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::DirectoryPathEncodingUnavailable,
                )
            })?;
            // SAFETY: `encoded` is NUL-terminated and live for the call. These are
            // the unchanged accepted directory-open policy values.
            let raw = unsafe {
                CreateFileW(
                    encoded.as_ptr(),
                    DIRECTORY_OPEN_ACCESS,
                    DIRECTORY_OPEN_SHARE,
                    NULL_CREATE_SECURITY_ATTRIBUTES,
                    DIRECTORY_OPEN_DISPOSITION,
                    DIRECTORY_OPEN_FLAGS,
                    NULL_CREATE_TEMPLATE_HANDLE,
                )
            };
            if raw == INVALID_HANDLE_VALUE {
                return Err(DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::DirectoryOpenUnavailable,
                ));
            }
            // SAFETY: ownership of the fresh successful handle is transferred once.
            let handle = File::from(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) });
            require_disk_handle_diagnostically(&handle)?;

            let native_handle = handle.as_raw_handle() as HANDLE;
            let mut standard = FILE_STANDARD_INFO::default();
            let standard_size = checked_buffer_length(std::mem::size_of::<FILE_STANDARD_INFO>())
                .ok_or_else(|| {
                    DirectoryDiagnosticFailure::at(
                        DirectoryDiagnosticStage::DirectoryStandardInfoUnavailable,
                    )
                })?;
            // SAFETY: `standard` is exact initialized writable storage and the live
            // File owns `native_handle` for the call.
            let standard_ok = unsafe {
                GetFileInformationByHandleEx(
                    native_handle,
                    FileStandardInfo,
                    (&raw mut standard).cast::<c_void>(),
                    standard_size,
                )
            };
            if standard_ok == 0 {
                // SAFETY: called immediately after the failed native operation,
                // matching the accepted shared helper without retaining the value.
                let _native_error = unsafe { GetLastError() };
                return Err(DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::DirectoryStandardInfoUnavailable,
                ));
            }

            let mut attribute_tag = FILE_ATTRIBUTE_TAG_INFO::default();
            let attribute_size = checked_buffer_length(
                std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>(),
            )
            .ok_or_else(|| {
                DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::DirectoryAttributeInfoUnavailable,
                )
            })?;
            // SAFETY: `attribute_tag` is exact initialized writable storage and the
            // live File owns `native_handle` for the call.
            let attribute_ok = unsafe {
                GetFileInformationByHandleEx(
                    native_handle,
                    FileAttributeTagInfo,
                    (&raw mut attribute_tag).cast::<c_void>(),
                    attribute_size,
                )
            };
            if attribute_ok == 0 {
                // SAFETY: called immediately after the failed native operation,
                // matching the accepted shared helper without retaining the value.
                let _native_error = unsafe { GetLastError() };
                return Err(DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::DirectoryAttributeInfoUnavailable,
                ));
            }

            let size = u64::try_from(standard.EndOfFile).map_err(|_| {
                DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::DirectoryStandardFactsRejected,
                )
            })?;
            let identity = query_handle_identity(&handle).map_err(|_| {
                DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::DirectoryIdentityUnavailable,
                )
            })?;
            let link_count = query_link_count(&handle).map_err(|_| {
                DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::DirectoryLinkInfoUnavailable,
                )
            })?;
            let final_path = query_bounded_final_guid_path(&handle).map_err(|_| {
                DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::NormalizedGuidPathUnavailable,
                )
            })?;
            let observation = HardeningObservation {
                identity,
                size,
                attributes: attribute_tag.FileAttributes,
                reparse_tag: attribute_tag.ReparseTag,
                link_count,
                final_path,
            };
            if observation.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::DirectoryEntryRejected,
                ));
            }
            validate_reparse_facts(observation.attributes, observation.reparse_tag).map_err(
                |_| DirectoryDiagnosticFailure::at(DirectoryDiagnosticStage::ReparseFactsRejected),
            )?;
            validated_volume_guid_prefix(&observation.final_path).map_err(|_| {
                DirectoryDiagnosticFailure::at(DirectoryDiagnosticStage::VolumeGuidPathMalformed)
            })?;
            Ok(RetainedDirectory {
                handle,
                initial: observation,
            })
        }

        fn map_local(
            classification: local::LocalVolumeClassification,
        ) -> CoarseLocalVolumeClassification {
            match classification {
                local::LocalVolumeClassification::LocalFixedCandidate => {
                    CoarseLocalVolumeClassification::LocalFixedCandidate
                }
                local::LocalVolumeClassification::Rejected(_) => {
                    CoarseLocalVolumeClassification::LocalVolumeRejected
                }
                local::LocalVolumeClassification::Unavailable => {
                    CoarseLocalVolumeClassification::Unavailable
                }
            }
        }

        fn map_device(
            classification: device::DevicePropertyClassification,
        ) -> (
            CoarseDevicePropertyClassification,
            RemovableFactBucket,
            BusFamilyBucket,
        ) {
            match classification {
                device::DevicePropertyClassification::DevicePropertyCandidate => (
                    CoarseDevicePropertyClassification::DevicePropertyCandidate,
                    RemovableFactBucket::NotReportedRemovable,
                    BusFamilyBucket::CandidateFamily,
                ),
                device::DevicePropertyClassification::KnownRemovableRejected => (
                    CoarseDevicePropertyClassification::KnownRemovableRejected,
                    RemovableFactBucket::KnownRemovable,
                    BusFamilyBucket::Unavailable,
                ),
                device::DevicePropertyClassification::ControlledHostReviewRequired => (
                    CoarseDevicePropertyClassification::ControlledHostReviewRequired,
                    RemovableFactBucket::NotReportedRemovable,
                    BusFamilyBucket::ManualReviewFamily,
                ),
                device::DevicePropertyClassification::VirtualOrRemoteBackingUnresolved => (
                    CoarseDevicePropertyClassification::VirtualOrRemoteBackingUnresolved,
                    RemovableFactBucket::NotReportedRemovable,
                    BusFamilyBucket::VirtualOrRemoteUnresolvedFamily,
                ),
                device::DevicePropertyClassification::UnsupportedBusType => (
                    CoarseDevicePropertyClassification::Unsupported,
                    RemovableFactBucket::NotReportedRemovable,
                    BusFamilyBucket::UnsupportedFamily,
                ),
                device::DevicePropertyClassification::DeviceFactsUnavailable => (
                    CoarseDevicePropertyClassification::Unavailable,
                    RemovableFactBucket::Unavailable,
                    BusFamilyBucket::Unavailable,
                ),
                device::DevicePropertyClassification::MalformedDeviceDescriptor
                | device::DevicePropertyClassification::DeviceFactsInconsistent => (
                    CoarseDevicePropertyClassification::MalformedOrInconsistent,
                    RemovableFactBucket::Unavailable,
                    BusFamilyBucket::Unavailable,
                ),
            }
        }

        fn usb_negative_is_acceptable(result: &RedactedCaseResult) -> bool {
            if matches!(
                result.local_volume,
                CoarseLocalVolumeClassification::LocalVolumeRejected
                    | CoarseLocalVolumeClassification::Unavailable
            ) {
                return true;
            }
            matches!(
                result.device_property,
                CoarseDevicePropertyClassification::KnownRemovableRejected
                    | CoarseDevicePropertyClassification::ControlledHostReviewRequired
                    | CoarseDevicePropertyClassification::VirtualOrRemoteBackingUnresolved
                    | CoarseDevicePropertyClassification::Unavailable
                    | CoarseDevicePropertyClassification::Unsupported
            )
        }

        fn observe_case(case_kind: CaseKind, fixture: &Fixture) -> RedactedCaseResult {
            let mut result = RedactedCaseResult::initial(case_kind, Prerequisite::Present);
            let retained = match open_hardened_directory_diagnostically(&fixture.root) {
                Ok(retained) => retained,
                Err(failure) => {
                    result.failure = CoarseFailureCategory::HardenedDirectoryPrerequisite;
                    result.diagnostic_failure = Some(failure);
                    return result;
                }
            };
            if let Err(failure) = require_disk_handle_diagnostically(&retained.handle) {
                result.failure = CoarseFailureCategory::HardenedDirectoryPrerequisite;
                result.diagnostic_failure = Some(failure);
                return result;
            }
            if validate_reparse_facts(retained.initial.attributes, retained.initial.reparse_tag)
                .is_err()
            {
                result.failure = CoarseFailureCategory::HardenedDirectoryPrerequisite;
                result.diagnostic_failure = Some(DirectoryDiagnosticFailure::at(
                    DirectoryDiagnosticStage::ReparseFactsRejected,
                ));
                return result;
            }
            let exact_root = match local::exact_volume_guid_root(&retained.initial.final_path) {
                Ok(root) if root.len() == VOLUME_GUID_PREFIX_UNITS => root,
                _ => {
                    result.failure = CoarseFailureCategory::ClassificationUnavailable;
                    return result;
                }
            };
            let path_fact = local::volume_path_fact(Some(&retained.initial.final_path));
            result.drive_type_call_count = 1;
            let drive_fact = local::query_drive_type_once(&exact_root);
            let local_classification = local::classify(path_fact, drive_fact);
            result.local_volume = map_local(local_classification);

            if local_classification == local::LocalVolumeClassification::LocalFixedCandidate {
                let device_name = match device::volume_device_name(&exact_root) {
                    Ok(name) => name,
                    Err(_) => {
                        result.device_property = CoarseDevicePropertyClassification::Unavailable;
                        result.removable_fact = RemovableFactBucket::Unavailable;
                        result.bus_family = BusFamilyBucket::Unavailable;
                        return finalize_expectation(result, fixture);
                    }
                };
                result.volume_open_count = 1;
                let volume = match device::open_volume_device(&device_name) {
                    Ok(volume) => volume,
                    Err(_) => {
                        result.device_property = CoarseDevicePropertyClassification::Unavailable;
                        result.removable_fact = RemovableFactBucket::Unavailable;
                        result.bus_family = BusFamilyBucket::Unavailable;
                        return finalize_expectation(result, fixture);
                    }
                };
                let descriptor = match device::query_device_descriptor(
                    &volume,
                    &mut result.property_ioctl_count,
                ) {
                    Ok(descriptor) => device::DescriptorEvidence::Available(descriptor),
                    Err(device::DeviceProofFailure::MalformedDeviceDescriptor) => {
                        device::DescriptorEvidence::Malformed
                    }
                    Err(_) => device::DescriptorEvidence::Unavailable,
                };
                let classification = device::classify(
                    device::LocalVolumePrerequisite::LocalFixedCandidate,
                    descriptor,
                );
                (
                    result.device_property,
                    result.removable_fact,
                    result.bus_family,
                ) = map_device(classification);
            }
            drop(retained);
            finalize_expectation(result, fixture)
        }

        fn finalize_expectation(
            mut result: RedactedCaseResult,
            fixture: &Fixture,
        ) -> RedactedCaseResult {
            result.sentinel_state = fixture.sentinel_state();
            if result.sentinel_state != SentinelState::Preserved {
                result.status = CaseStatus::Fail;
                result.failure = CoarseFailureCategory::SentinelChangedOrUnavailable;
                return result;
            }
            result.expected_result_matched = match result.case_kind {
                CaseKind::CurrentWindows11InternalBaseline => {
                    result.local_volume == CoarseLocalVolumeClassification::LocalFixedCandidate
                        && result.device_property
                            == CoarseDevicePropertyClassification::DevicePropertyCandidate
                        && result.drive_type_call_count == 1
                        && result.volume_open_count == 1
                        && result.property_ioctl_count == 2
                }
                CaseKind::UsbFlash => usb_negative_is_acceptable(&result),
            };
            if result.case_kind == CaseKind::UsbFlash
                && result.device_property
                    == CoarseDevicePropertyClassification::DevicePropertyCandidate
            {
                result.status = CaseStatus::Fail;
                result.failure = CoarseFailureCategory::UsbCandidateDefectUnresolved;
                result.expected_result_matched = false;
            } else if result.expected_result_matched {
                result.status = CaseStatus::Pass;
                result.failure = CoarseFailureCategory::None;
            } else {
                result.status = CaseStatus::Fail;
                result.failure = CoarseFailureCategory::BaselineMismatch;
            }
            result
        }

        fn result_for_creation_failure(
            case_kind: CaseKind,
            failure: FixtureCreationError,
        ) -> RedactedCaseResult {
            let mut result = RedactedCaseResult::initial(case_kind, Prerequisite::Present);
            result.failure = match failure.primary {
                FixtureCreationFailure::FixtureChildCreationUnavailable => {
                    CoarseFailureCategory::FixtureChildCreationUnavailable
                }
                FixtureCreationFailure::SentinelWriteUnavailable => {
                    CoarseFailureCategory::SentinelWriteUnavailable
                }
            };
            match failure.cleanup {
                FixtureCreationCleanupOutcome::NotAttempted => {}
                FixtureCreationCleanupOutcome::Succeeded => {
                    result.exact_root_cleanup_attempted = true;
                    result.exact_root_cleanup_succeeded = true;
                }
                FixtureCreationCleanupOutcome::Failed => {
                    result.exact_root_cleanup_attempted = true;
                    result.primary_failure = Some(result.failure);
                    result.failure = CoarseFailureCategory::PrimaryAndCleanupFailed;
                }
            }
            result
        }

        fn run_with_parent(
            case_kind: CaseKind,
            parent: &Path,
            cleanup_operation: CleanupOperation,
        ) -> RedactedCaseResult {
            if case_kind == CaseKind::UsbFlash && !validate_manual_root(parent) {
                let mut result = RedactedCaseResult::initial(case_kind, Prerequisite::Present);
                result.failure = CoarseFailureCategory::InvalidManualRoot;
                return result;
            }
            let prefix = match case_kind {
                CaseKind::CurrentWindows11InternalBaseline => BASELINE_CHILD_PREFIX,
                CaseKind::UsbFlash => USB_CHILD_PREFIX,
            };
            let mut fixture = match Fixture::create(parent, prefix, cleanup_operation) {
                Ok(fixture) => fixture,
                Err(failure) => {
                    return result_for_creation_failure(case_kind, failure);
                }
            };
            let mut result = observe_case(case_kind, &fixture);
            apply_cleanup_result(&mut result, fixture.cleanup_once());
            result
        }

        fn apply_cleanup_result(result: &mut RedactedCaseResult, cleanup: io::Result<()>) {
            result.exact_root_cleanup_attempted = true;
            match cleanup {
                Ok(()) => result.exact_root_cleanup_succeeded = true,
                Err(_) => {
                    result.exact_root_cleanup_succeeded = false;
                    result.status = CaseStatus::Fail;
                    result.expected_result_matched = false;
                    if result.failure == CoarseFailureCategory::None {
                        result.failure = CoarseFailureCategory::CleanupFailed;
                    } else {
                        result.primary_failure = Some(result.failure);
                        result.failure = CoarseFailureCategory::PrimaryAndCleanupFailed;
                    }
                }
            }
        }

        fn explicit_usb_runtime_accepted(result: &RedactedCaseResult) -> bool {
            result.prerequisite == Prerequisite::Present
                && result.status == CaseStatus::Pass
                && result.expected_result_matched
                && result.sentinel_state == SentinelState::Preserved
                && result.exact_root_cleanup_attempted
                && result.exact_root_cleanup_succeeded
                && result.authority.every_field_is_false()
        }

        fn run_baseline() -> RedactedCaseResult {
            run_with_parent(
                CaseKind::CurrentWindows11InternalBaseline,
                &std::env::temp_dir(),
                remove_exact_root,
            )
        }

        fn run_usb_from_value(value: Option<OsString>) -> RedactedCaseResult {
            let Some(value) = value else {
                return RedactedCaseResult::prerequisite_absent();
            };
            run_with_parent(CaseKind::UsbFlash, Path::new(&value), remove_exact_root)
        }

        fn counted_cleanup(root: &Path) -> io::Result<()> {
            CLEANUP_TEST_CALLS.fetch_add(1, Ordering::Relaxed);
            remove_exact_root(root)
        }

        fn counted_cleanup_remove_then_fail(root: &Path) -> io::Result<()> {
            CLEANUP_TEST_CALLS.fetch_add(1, Ordering::Relaxed);
            remove_exact_root(root)?;
            Err(io::Error::other("injected coarse cleanup failure"))
        }

        fn injected_cleanup_succeeds(_root: &Path) -> io::Result<()> {
            CLEANUP_TEST_CALLS.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn injected_cleanup_fails(_root: &Path) -> io::Result<()> {
            CLEANUP_TEST_CALLS.fetch_add(1, Ordering::Relaxed);
            Err(io::Error::other("injected sensitive cleanup failure"))
        }

        fn synthetic_result(
            case_kind: CaseKind,
            local_volume: CoarseLocalVolumeClassification,
            device_property: CoarseDevicePropertyClassification,
        ) -> RedactedCaseResult {
            let mut result = RedactedCaseResult::initial(case_kind, Prerequisite::Present);
            result.local_volume = local_volume;
            result.device_property = device_property;
            result.sentinel_state = SentinelState::Preserved;
            result
        }

        fn synthetic_pre_drive_failure(stage: DirectoryDiagnosticStage) -> RedactedCaseResult {
            let mut result = RedactedCaseResult::initial(CaseKind::UsbFlash, Prerequisite::Present);
            result.failure = CoarseFailureCategory::HardenedDirectoryPrerequisite;
            result.diagnostic_failure = Some(DirectoryDiagnosticFailure::at(stage));
            result
        }

        fn assert_fixture_creation_pre_drive_result(result: &RedactedCaseResult) {
            assert_eq!(result.status, CaseStatus::Fail);
            assert_eq!(result.drive_type_call_count, 0);
            assert_eq!(result.volume_open_count, 0);
            assert_eq!(result.property_ioctl_count, 0);
            assert_eq!(result.hot_plug_count, 0);
            assert_eq!(result.sentinel_state, SentinelState::NotReached);
            assert!(result.authority.every_field_is_false());
        }

        const PRIOR_OBSERVED_USB_FIXTURE_CONSTRUCTION_COMPLETED: bool = true;

        fn excluded_for_prior_observed_usb_run(failure: CoarseFailureCategory) -> bool {
            PRIOR_OBSERVED_USB_FIXTURE_CONSTRUCTION_COMPLETED
                && matches!(
                    failure,
                    CoarseFailureCategory::FixtureChildCreationUnavailable
                        | CoarseFailureCategory::SentinelWriteUnavailable
                )
        }

        #[test]
        fn controlled_storage_host_matrix_pure_case_kinds_are_separate_and_exact() {
            assert_ne!(
                CaseKind::CurrentWindows11InternalBaseline,
                CaseKind::UsbFlash
            );
        }

        #[test]
        fn controlled_storage_host_matrix_pure_account_context_wording_is_exact() {
            assert_eq!(
                ACCOUNT_CONTEXT,
                "Current Windows account, non-elevated session; administrator-group membership not established."
            );
        }

        #[test]
        fn controlled_storage_host_matrix_pure_each_unavailable_stage_is_distinct() {
            let unavailable = [
                DirectoryDiagnosticStage::DirectoryPathEncodingUnavailable,
                DirectoryDiagnosticStage::DirectoryOpenUnavailable,
                DirectoryDiagnosticStage::DiskHandleFactUnavailable,
                DirectoryDiagnosticStage::DirectoryStandardInfoUnavailable,
                DirectoryDiagnosticStage::DirectoryAttributeInfoUnavailable,
                DirectoryDiagnosticStage::DirectoryIdentityUnavailable,
                DirectoryDiagnosticStage::DirectoryLinkInfoUnavailable,
                DirectoryDiagnosticStage::NormalizedGuidPathUnavailable,
            ];
            for stage in unavailable {
                let failure = DirectoryDiagnosticFailure::at(stage);
                assert_eq!(failure.stage, stage);
                assert_eq!(failure.disposition, DiagnosticDisposition::Unavailable);
            }
        }

        #[test]
        fn controlled_storage_host_matrix_pure_each_rejected_stage_is_distinct() {
            let rejected = [
                DirectoryDiagnosticStage::NonDiskHandleRejected,
                DirectoryDiagnosticStage::DirectoryStandardFactsRejected,
                DirectoryDiagnosticStage::DirectoryEntryRejected,
                DirectoryDiagnosticStage::VolumeGuidPathMalformed,
                DirectoryDiagnosticStage::ReparseFactsRejected,
            ];
            for stage in rejected {
                let failure = DirectoryDiagnosticFailure::at(stage);
                assert_eq!(failure.stage, stage);
                assert_eq!(failure.disposition, DiagnosticDisposition::Rejected);
            }
        }

        #[test]
        fn controlled_storage_host_matrix_pure_first_failure_wins_and_stops_evaluation() {
            let first = DirectoryDiagnosticStage::DirectoryStandardInfoUnavailable;
            let later = DirectoryDiagnosticStage::DirectoryIdentityUnavailable;
            let mut visited = Vec::new();
            let failure = first_injected_directory_failure(&[later, first], &mut visited).unwrap();
            assert_eq!(failure, DirectoryDiagnosticFailure::at(first));
            assert_eq!(visited.last(), Some(&first));
            assert!(!visited.contains(&later));
        }

        #[test]
        fn controlled_storage_host_matrix_pure_pre_drive_failures_have_zero_calls_and_no_sentinel_read()
         {
            for stage in DIRECTORY_DIAGNOSTIC_ORDER {
                let result = synthetic_pre_drive_failure(stage);
                assert_eq!(result.drive_type_call_count, 0);
                assert_eq!(result.volume_open_count, 0);
                assert_eq!(result.property_ioctl_count, 0);
                assert_eq!(result.hot_plug_count, 0);
                assert_eq!(result.sentinel_state, SentinelState::NotReached);
                assert_eq!(
                    result.diagnostic_failure,
                    Some(DirectoryDiagnosticFailure::at(stage))
                );
            }
        }

        #[test]
        fn controlled_storage_host_matrix_pure_sentinel_states_are_distinct() {
            assert_eq!(
                sentinel_state_from_read(Err(io::Error::other("injected"))),
                SentinelState::Unavailable
            );
            assert_eq!(
                sentinel_state_from_read(Ok(b"synthetic-changed".to_vec())),
                SentinelState::Changed
            );
            assert_eq!(
                sentinel_state_from_read(Ok(SENTINEL_CONTENT.to_vec())),
                SentinelState::Preserved
            );
            assert_ne!(SentinelState::NotReached, SentinelState::Unavailable);
        }

        #[test]
        fn controlled_storage_host_matrix_pure_creation_failures_exist_but_do_not_explain_prior_run()
         {
            assert!(excluded_for_prior_observed_usb_run(
                CoarseFailureCategory::FixtureChildCreationUnavailable
            ));
            assert!(excluded_for_prior_observed_usb_run(
                CoarseFailureCategory::SentinelWriteUnavailable
            ));
            assert!(!excluded_for_prior_observed_usb_run(
                CoarseFailureCategory::HardenedDirectoryPrerequisite
            ));
        }

        #[test]
        fn controlled_storage_host_matrix_pure_child_creation_failure_has_no_cleanup_evidence() {
            CLEANUP_TEST_CALLS.store(0, Ordering::Relaxed);
            let failure = match Fixture::create_with(
                &std::env::temp_dir(),
                "church-app-injected-child-failure-",
                injected_cleanup_succeeds,
                |_| Err(io::Error::other("injected sensitive child failure")),
                |_, _| panic!("sentinel write must not be reached"),
            ) {
                Ok(_) => panic!("injected child creation unexpectedly succeeded"),
                Err(failure) => failure,
            };
            assert_eq!(failure, FixtureCreationError::child_creation_unavailable());
            assert_eq!(CLEANUP_TEST_CALLS.load(Ordering::Relaxed), 0);

            let result = result_for_creation_failure(CaseKind::UsbFlash, failure);
            assert_eq!(
                result.failure,
                CoarseFailureCategory::FixtureChildCreationUnavailable
            );
            assert!(!result.exact_root_cleanup_attempted);
            assert!(!result.exact_root_cleanup_succeeded);
            assert_fixture_creation_pre_drive_result(&result);
        }

        #[test]
        fn controlled_storage_host_matrix_pure_sentinel_write_failure_retains_cleanup_success() {
            CLEANUP_TEST_CALLS.store(0, Ordering::Relaxed);
            let failure = match Fixture::create_with(
                &std::env::temp_dir(),
                "church-app-injected-sentinel-failure-",
                injected_cleanup_succeeds,
                |_| Ok(()),
                |_, _| Err(io::Error::other("injected sensitive sentinel failure")),
            ) {
                Ok(_) => panic!("injected sentinel write unexpectedly succeeded"),
                Err(failure) => failure,
            };
            assert_eq!(
                failure.primary,
                FixtureCreationFailure::SentinelWriteUnavailable
            );
            assert_eq!(failure.cleanup, FixtureCreationCleanupOutcome::Succeeded);
            assert_eq!(CLEANUP_TEST_CALLS.load(Ordering::Relaxed), 1);

            let result = result_for_creation_failure(CaseKind::UsbFlash, failure);
            assert_eq!(
                result.failure,
                CoarseFailureCategory::SentinelWriteUnavailable
            );
            assert_eq!(result.primary_failure, None);
            assert!(result.exact_root_cleanup_attempted);
            assert!(result.exact_root_cleanup_succeeded);
            assert_fixture_creation_pre_drive_result(&result);
        }

        #[test]
        fn controlled_storage_host_matrix_pure_sentinel_write_and_cleanup_failure_are_both_retained_without_drop_retry()
         {
            CLEANUP_TEST_CALLS.store(0, Ordering::Relaxed);
            let failure = match Fixture::create_with(
                &std::env::temp_dir(),
                "church-app-injected-combined-failure-",
                injected_cleanup_fails,
                |_| Ok(()),
                |_, _| Err(io::Error::other("injected sensitive sentinel failure")),
            ) {
                Ok(_) => panic!("injected sentinel write unexpectedly succeeded"),
                Err(failure) => failure,
            };
            assert_eq!(
                failure.primary,
                FixtureCreationFailure::SentinelWriteUnavailable
            );
            assert_eq!(failure.cleanup, FixtureCreationCleanupOutcome::Failed);
            assert_eq!(CLEANUP_TEST_CALLS.load(Ordering::Relaxed), 1);

            let result = result_for_creation_failure(CaseKind::UsbFlash, failure);
            assert_eq!(
                result.failure,
                CoarseFailureCategory::PrimaryAndCleanupFailed
            );
            assert_eq!(
                result.primary_failure,
                Some(CoarseFailureCategory::SentinelWriteUnavailable)
            );
            assert!(result.exact_root_cleanup_attempted);
            assert!(!result.exact_root_cleanup_succeeded);
            assert_fixture_creation_pre_drive_result(&result);
            let debug = format!("{failure:?} {result:?}");
            for sensitive in [
                "injected sensitive",
                r"C:\sensitive\usb-root",
                USB_ROOT_ENVIRONMENT_VARIABLE,
                "Volume{",
            ] {
                assert!(!debug.contains(sensitive));
            }
        }

        #[test]
        fn controlled_storage_host_matrix_pure_actual_diagnostic_order_is_locked() {
            assert_eq!(
                DIRECTORY_DIAGNOSTIC_ORDER,
                [
                    DirectoryDiagnosticStage::DirectoryPathEncodingUnavailable,
                    DirectoryDiagnosticStage::DirectoryOpenUnavailable,
                    DirectoryDiagnosticStage::DiskHandleFactUnavailable,
                    DirectoryDiagnosticStage::NonDiskHandleRejected,
                    DirectoryDiagnosticStage::DirectoryStandardInfoUnavailable,
                    DirectoryDiagnosticStage::DirectoryAttributeInfoUnavailable,
                    DirectoryDiagnosticStage::DirectoryStandardFactsRejected,
                    DirectoryDiagnosticStage::DirectoryIdentityUnavailable,
                    DirectoryDiagnosticStage::DirectoryLinkInfoUnavailable,
                    DirectoryDiagnosticStage::NormalizedGuidPathUnavailable,
                    DirectoryDiagnosticStage::DirectoryEntryRejected,
                    DirectoryDiagnosticStage::ReparseFactsRejected,
                    DirectoryDiagnosticStage::VolumeGuidPathMalformed,
                ]
            );
        }

        #[test]
        fn controlled_storage_host_matrix_pure_absent_usb_prerequisite_is_not_a_pass() {
            let result = run_usb_from_value(None);
            assert_eq!(result.prerequisite, Prerequisite::Absent);
            assert_eq!(result.status, CaseStatus::PrerequisiteAbsent);
            assert!(!result.expected_result_matched);
            assert!(!explicit_usb_runtime_accepted(&result));
        }

        #[test]
        fn controlled_storage_host_matrix_pure_explicit_usb_runtime_requires_complete_pass() {
            let mut complete =
                RedactedCaseResult::initial(CaseKind::UsbFlash, Prerequisite::Present);
            complete.status = CaseStatus::Pass;
            complete.expected_result_matched = true;
            complete.sentinel_state = SentinelState::Preserved;
            complete.exact_root_cleanup_attempted = true;
            complete.exact_root_cleanup_succeeded = true;
            assert!(explicit_usb_runtime_accepted(&complete));

            let mut failed = complete;
            failed.status = CaseStatus::Fail;
            assert!(!explicit_usb_runtime_accepted(&failed));

            let mut authoritative = complete;
            authoritative.authority.production_policy = true;
            assert!(!explicit_usb_runtime_accepted(&authoritative));
        }

        #[test]
        fn controlled_storage_host_matrix_pure_invalid_supplied_root_fails() {
            let result = run_usb_from_value(Some(OsString::from(
                r"Z:\church-app-synthetic-missing-root",
            )));
            assert_eq!(result.status, CaseStatus::Fail);
            assert_eq!(result.failure, CoarseFailureCategory::InvalidManualRoot);
        }

        #[test]
        fn controlled_storage_host_matrix_pure_manual_root_must_be_absolute() {
            assert!(!validate_manual_root(Path::new("synthetic-relative-root")));
        }

        #[test]
        fn controlled_storage_host_matrix_pure_result_debug_discloses_no_path() {
            let result = RedactedCaseResult::prerequisite_absent();
            let debug = format!("{result:?}");
            assert!(!debug.contains('\\'));
            assert!(!debug.contains('/'));
            assert!(!debug.contains(USB_ROOT_ENVIRONMENT_VARIABLE));
        }

        #[test]
        fn controlled_storage_host_matrix_pure_unique_child_name_is_exact() {
            assert_eq!(
                unique_child_name(USB_CHILD_PREFIX, 41, 73, 5),
                "church-app-usb-flash-proof-41-73-5"
            );
        }

        #[test]
        fn controlled_storage_host_matrix_pure_sentinel_is_preserved() {
            let parent = std::env::temp_dir();
            let mut fixture =
                Fixture::create(&parent, USB_CHILD_PREFIX, remove_exact_root).unwrap();
            assert_eq!(fixture.sentinel_state(), SentinelState::Preserved);
            fixture.cleanup_once().unwrap();
        }

        #[test]
        fn controlled_storage_host_matrix_pure_cleanup_removes_only_exact_root() {
            let parent = std::env::temp_dir().join(unique_child_name(
                "church-app-controlled-parent-",
                std::process::id(),
                1,
                TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir(&parent).unwrap();
            let parent_sentinel = parent.join(SENTINEL_NAME);
            fs::write(&parent_sentinel, SENTINEL_CONTENT).unwrap();
            let mut fixture =
                Fixture::create(&parent, USB_CHILD_PREFIX, remove_exact_root).unwrap();
            fixture.cleanup_once().unwrap();
            assert!(parent_sentinel.exists());
            fs::remove_file(parent_sentinel).unwrap();
            fs::remove_dir(parent).unwrap();
        }

        #[test]
        fn controlled_storage_host_matrix_pure_cleanup_is_attempted_once() {
            CLEANUP_TEST_CALLS.store(0, Ordering::Relaxed);
            let mut fixture =
                Fixture::create(&std::env::temp_dir(), USB_CHILD_PREFIX, counted_cleanup).unwrap();
            fixture.cleanup_once().unwrap();
            fixture.cleanup_once().unwrap();
            assert_eq!(CLEANUP_TEST_CALLS.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn controlled_storage_host_matrix_pure_primary_plus_cleanup_is_preserved() {
            CLEANUP_TEST_CALLS.store(0, Ordering::Relaxed);
            let mut fixture = Fixture::create(
                &std::env::temp_dir(),
                USB_CHILD_PREFIX,
                counted_cleanup_remove_then_fail,
            )
            .unwrap();
            let mut result = RedactedCaseResult::initial(CaseKind::UsbFlash, Prerequisite::Present);
            result.failure = CoarseFailureCategory::UsbCandidateDefectUnresolved;
            apply_cleanup_result(&mut result, fixture.cleanup_once());
            assert_eq!(result.status, CaseStatus::Fail);
            assert_eq!(
                result.failure,
                CoarseFailureCategory::PrimaryAndCleanupFailed
            );
            assert_eq!(
                result.primary_failure,
                Some(CoarseFailureCategory::UsbCandidateDefectUnresolved)
            );
            assert_eq!(CLEANUP_TEST_CALLS.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn controlled_storage_host_matrix_pure_distinct_primary_survives_cleanup_failure() {
            let mut result = RedactedCaseResult::initial(
                CaseKind::CurrentWindows11InternalBaseline,
                Prerequisite::Present,
            );
            result.failure = CoarseFailureCategory::ClassificationUnavailable;
            apply_cleanup_result(
                &mut result,
                Err(io::Error::other("injected coarse cleanup failure")),
            );
            assert_eq!(
                result.primary_failure,
                Some(CoarseFailureCategory::ClassificationUnavailable)
            );
            assert_eq!(
                result.failure,
                CoarseFailureCategory::PrimaryAndCleanupFailed
            );
        }

        #[test]
        fn controlled_storage_host_matrix_pure_diagnostic_primary_survives_cleanup_failure() {
            let diagnostic = DirectoryDiagnosticFailure::at(
                DirectoryDiagnosticStage::DirectoryIdentityUnavailable,
            );
            let mut result = synthetic_pre_drive_failure(diagnostic.stage);
            apply_cleanup_result(
                &mut result,
                Err(io::Error::other("injected coarse cleanup failure")),
            );
            assert_eq!(
                result.primary_failure,
                Some(CoarseFailureCategory::HardenedDirectoryPrerequisite)
            );
            assert_eq!(
                result.failure,
                CoarseFailureCategory::PrimaryAndCleanupFailed
            );
            assert_eq!(result.diagnostic_failure, Some(diagnostic));
            assert_eq!(result.sentinel_state, SentinelState::NotReached);
        }

        #[test]
        fn controlled_storage_host_matrix_pure_cleanup_only_has_no_primary_failure() {
            let mut result = RedactedCaseResult::initial(CaseKind::UsbFlash, Prerequisite::Present);
            apply_cleanup_result(
                &mut result,
                Err(io::Error::other("injected coarse cleanup failure")),
            );
            assert_eq!(result.failure, CoarseFailureCategory::CleanupFailed);
            assert_eq!(result.primary_failure, None);
        }

        #[test]
        fn controlled_storage_host_matrix_pure_combined_failure_debug_remains_redacted() {
            let mut result =
                synthetic_pre_drive_failure(DirectoryDiagnosticStage::DirectoryIdentityUnavailable);
            apply_cleanup_result(
                &mut result,
                Err(io::Error::other("native-sensitive-detail")),
            );
            let debug = format!("{result:?}");
            for sensitive in [
                r"C:\sensitive\usb-root",
                USB_ROOT_ENVIRONMENT_VARIABLE,
                "native-sensitive-detail",
                "sensitive-identifier",
                "Volume{",
                "FILE_ID_INFO",
                "synthetic-sentinel-preserved",
            ] {
                assert!(!debug.contains(sensitive));
            }
            assert!(debug.contains("DirectoryIdentityUnavailable"));
            assert!(debug.contains("Unavailable"));
        }

        #[test]
        fn controlled_storage_host_matrix_pure_baseline_expected_classifications_are_exact() {
            let mut result = synthetic_result(
                CaseKind::CurrentWindows11InternalBaseline,
                CoarseLocalVolumeClassification::LocalFixedCandidate,
                CoarseDevicePropertyClassification::DevicePropertyCandidate,
            );
            result.drive_type_call_count = 1;
            result.volume_open_count = 1;
            result.property_ioctl_count = 2;
            assert!(finalize_expectation(result, &synthetic_fixture()).expected_result_matched);
        }

        #[test]
        fn controlled_storage_host_matrix_pure_usb_negative_classifications_are_acceptable() {
            for device_property in [
                CoarseDevicePropertyClassification::KnownRemovableRejected,
                CoarseDevicePropertyClassification::ControlledHostReviewRequired,
                CoarseDevicePropertyClassification::VirtualOrRemoteBackingUnresolved,
                CoarseDevicePropertyClassification::Unavailable,
                CoarseDevicePropertyClassification::Unsupported,
            ] {
                assert!(usb_negative_is_acceptable(&synthetic_result(
                    CaseKind::UsbFlash,
                    CoarseLocalVolumeClassification::LocalFixedCandidate,
                    device_property,
                )));
            }
            assert!(usb_negative_is_acceptable(&synthetic_result(
                CaseKind::UsbFlash,
                CoarseLocalVolumeClassification::LocalVolumeRejected,
                CoarseDevicePropertyClassification::NotReached,
            )));
        }

        #[test]
        fn controlled_storage_host_matrix_pure_usb_candidate_is_a_defect_not_pass() {
            let result = synthetic_result(
                CaseKind::UsbFlash,
                CoarseLocalVolumeClassification::LocalFixedCandidate,
                CoarseDevicePropertyClassification::DevicePropertyCandidate,
            );
            assert!(!usb_negative_is_acceptable(&result));
        }

        #[test]
        fn controlled_storage_host_matrix_pure_exact_call_counts_and_zero_hot_plug_are_locked() {
            let mut result = RedactedCaseResult::initial(
                CaseKind::CurrentWindows11InternalBaseline,
                Prerequisite::Present,
            );
            result.drive_type_call_count = 1;
            result.volume_open_count = 1;
            result.property_ioctl_count = 2;
            assert_eq!(
                (
                    result.drive_type_call_count,
                    result.volume_open_count,
                    result.property_ioctl_count,
                    result.hot_plug_count,
                ),
                (1, 1, 2, 0)
            );
        }

        #[test]
        fn controlled_storage_host_matrix_pure_every_authority_field_is_false() {
            assert!(AuthorityFields::all_false().every_field_is_false());
        }

        #[test]
        fn controlled_storage_host_matrix_pure_source_is_test_only_without_discovery() {
            let source = include_str!("windows_filesystem.rs");
            let (production, tests) = source.split_once("#[cfg(test)]").unwrap();
            assert!(!production.contains("controlled_storage_host_matrix"));
            let harness = tests
                .split_once("// CONTROLLED STORAGE HOST MATRIX START")
                .unwrap()
                .1
                .split_once("// CONTROLLED STORAGE HOST MATRIX END")
                .unwrap()
                .0;
            for forbidden in [
                concat!("read", "_dir"),
                concat!("GetLogical", "Drives"),
                concat!("FindFirst", "Volume"),
                concat!("Setup", "Di"),
                concat!("Win32_", "LogicalDisk"),
                concat!("Command::", "new"),
            ] {
                assert!(!harness.split_once("#[test]").unwrap().0.contains(forbidden));
            }
        }

        #[test]
        fn controlled_storage_host_matrix_pure_source_excludes_production_surfaces() {
            let source = include_str!("windows_filesystem.rs");
            let harness = source
                .split_once("// CONTROLLED STORAGE HOST MATRIX START")
                .unwrap()
                .1
                .split_once("// CONTROLLED STORAGE HOST MATRIX END")
                .unwrap()
                .0
                .split_once("#[test]")
                .unwrap()
                .0;
            for forbidden in [
                concat!("resolve_", "production"),
                concat!("rusq", "lite"),
                concat!("Crypt", "ProtectData"),
                concat!("tauri::", "command"),
                concat!("invoke_", "handler"),
                concat!("setup_", "authority"),
                concat!("startup_", "authority"),
                concat!("impl Fr", "om<RedactedCaseResult"),
                concat!("impl In", "to<"),
            ] {
                assert!(!harness.contains(forbidden));
            }
        }

        #[test]
        fn controlled_storage_host_matrix_pure_staged_native_calls_and_order_are_exact() {
            let source = include_str!("windows_filesystem.rs");
            let harness = source
                .split_once("// CONTROLLED STORAGE HOST MATRIX START")
                .unwrap()
                .1
                .split_once("// CONTROLLED STORAGE HOST MATRIX END")
                .unwrap()
                .0
                .split_once("#[test]")
                .unwrap()
                .0;
            assert_eq!(
                harness.matches("\n                CreateFileW(\n").count(),
                1
            );
            assert_eq!(
                harness.matches("GetFileType(file.as_raw_handle()").count(),
                1
            );
            assert_eq!(
                harness
                    .matches("\n                GetFileInformationByHandleEx(\n")
                    .count(),
                2
            );
            assert_eq!(harness.matches("query_handle_identity(&handle)").count(), 1);
            assert_eq!(harness.matches("query_link_count(&handle)").count(), 1);
            assert_eq!(
                harness
                    .matches("query_bounded_final_guid_path(&handle)")
                    .count(),
                1
            );
            assert_eq!(harness.matches("local::query_drive_type_once").count(), 1);
            assert!(!harness.contains("GetDriveTypeW("));
            assert!(!harness.contains("DeviceIoControl("));
        }

        fn synthetic_fixture() -> Fixture {
            Fixture::create(
                &std::env::temp_dir(),
                "church-app-controlled-synthetic-",
                remove_exact_root,
            )
            .unwrap()
        }

        #[test]
        fn controlled_storage_host_matrix_baseline_runtime() {
            let result = run_baseline();
            assert_eq!(result.status, CaseStatus::Pass, "{result:?}");
            assert!(result.expected_result_matched);
            assert_eq!(result.sentinel_state, SentinelState::Preserved);
            assert!(result.exact_root_cleanup_succeeded);
            assert!(result.authority.every_field_is_false());
        }

        #[test]
        #[ignore = "requires Carlo to insert the manually selected USB flash drive and supply CHURCH_APP_USB_TEST_ROOT"]
        fn controlled_storage_host_matrix_usb_flash_runtime() {
            let result = run_usb_from_value(std::env::var_os(USB_ROOT_ENVIRONMENT_VARIABLE));
            assert!(explicit_usb_runtime_accepted(&result), "{result:?}");
        }
    }
    // CONTROLLED STORAGE HOST MATRIX END.

    #[test]
    fn active_authentication_key_wrapper_loader_loads_exact_owned_redacted_bytes_only() {
        let expected = authentication_key_wrapper(64, 0xa1);
        let fixture = ActiveWrapperLoaderTestRoot::create(&expected);
        let non_active_marker = [0x5a; 15];
        fs::write(
            fixture.paths.staged_authentication_key.as_path(),
            non_active_marker,
        )
        .unwrap();
        fs::write(
            fixture.paths.active_authenticated_evidence.as_path(),
            non_active_marker,
        )
        .unwrap();
        fs::write(
            fixture.paths.staged_authenticated_evidence.as_path(),
            non_active_marker,
        )
        .unwrap();

        let loaded = load_active_authentication_key_wrapper(&fixture.paths).unwrap();
        assert_eq!(loaded.as_bytes(), expected);
        assert_eq!(format!("{loaded:?}"), "ProtectedWrapperBytes([REDACTED])");
        assert_eq!(
            fixture
                .paths
                .active_authentication_key
                .as_path()
                .file_name(),
            Some(OsStr::new(ACTIVE_AUTHENTICATION_KEY_FILENAME))
        );
        assert_eq!(
            ACTIVE_AUTHENTICATION_KEY_FILENAME,
            "authentication-key.dpapi"
        );
        assert_eq!(
            fs::read(fixture.paths.staged_authentication_key.as_path()).unwrap(),
            non_active_marker
        );
        assert_eq!(
            fs::read(fixture.paths.active_authenticated_evidence.as_path()).unwrap(),
            non_active_marker
        );
        assert_eq!(
            fs::read(fixture.paths.staged_authenticated_evidence.as_path()).unwrap(),
            non_active_marker
        );
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn active_authentication_key_wrapper_loader_rejects_aggregate_relationship_mismatches() {
        let expected = authentication_key_wrapper(16, 0xa2);
        let fixture = ActiveWrapperLoaderTestRoot::create(&expected);
        let alternate =
            installation_evidence_persistence_paths(&fixture.root.join("alternate-root"));

        let mut wrong_root = fixture.paths.clone();
        wrong_root.active_database = alternate.active_database.clone();
        assert_eq!(
            load_active_authentication_key_wrapper(&wrong_root),
            Err(HardeningError::FinalPathMismatch)
        );

        let mut wrong_evidence_directory = fixture.paths.clone();
        wrong_evidence_directory.evidence_directory = alternate.evidence_directory.clone();
        assert_eq!(
            load_active_authentication_key_wrapper(&wrong_evidence_directory),
            Err(HardeningError::FinalPathMismatch)
        );

        let nested =
            installation_evidence_persistence_paths(&fixture.root.join("nested-direct-root"));
        let mut wrong_active_parent = fixture.paths.clone();
        wrong_active_parent.active_authentication_key = nested.active_authentication_key.clone();
        assert_eq!(
            load_active_authentication_key_wrapper(&wrong_active_parent),
            Err(HardeningError::FinalPathMismatch)
        );
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn active_authentication_key_wrapper_loader_rejects_wrong_active_filename() {
        let expected = authentication_key_wrapper(16, 0xa3);
        let fixture = ActiveWrapperLoaderTestRoot::create(&expected);
        let wrong_name = fixture
            .paths
            .evidence_directory
            .as_path()
            .join("authentication-key-wrong.dpapi");
        fs::rename(
            fixture.paths.active_authentication_key.as_path(),
            &wrong_name,
        )
        .unwrap();
        assert_eq!(
            load_active_authentication_key_wrapper(&fixture.paths),
            Err(HardeningError::InspectionUnavailable)
        );
        assert_eq!(fs::read(&wrong_name).unwrap(), expected);
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn active_authentication_key_wrapper_loader_rejects_malformed_and_wrong_kind_wrappers() {
        let malformed_fixture = ActiveWrapperLoaderTestRoot::create(&[0x31; 15]);
        assert_eq!(
            load_active_authentication_key_wrapper(&malformed_fixture.paths),
            Err(HardeningError::WrapperInvalid)
        );
        malformed_fixture.assert_sentinel();
        malformed_fixture.cleanup();

        let mut wrong_kind = authentication_key_wrapper(16, 0xa4);
        wrong_kind[9] = 2;
        let wrong_kind_fixture = ActiveWrapperLoaderTestRoot::create(&wrong_kind);
        assert_eq!(
            load_active_authentication_key_wrapper(&wrong_kind_fixture.paths),
            Err(HardeningError::WrapperInvalid)
        );
        wrong_kind_fixture.assert_sentinel();
        wrong_kind_fixture.cleanup();
    }

    #[test]
    fn active_authentication_key_wrapper_loader_rejects_hard_linked_active_before_release() {
        let expected = authentication_key_wrapper(16, 0xa5);
        let fixture = ActiveWrapperLoaderTestRoot::create(&expected);
        let alias = fixture
            .paths
            .evidence_directory
            .as_path()
            .join("active-loader-hard-link-alias.synthetic");
        fs::hard_link(fixture.paths.active_authentication_key.as_path(), &alias).unwrap();
        assert_eq!(
            load_active_authentication_key_wrapper(&fixture.paths),
            Err(HardeningError::HardLinkRejected)
        );
        assert_eq!(fs::read(&alias).unwrap(), expected);
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn active_authentication_key_wrapper_loader_reuses_reparse_and_stability_policy() {
        for (attributes, tag) in [
            (FILE_ATTRIBUTE_REPARSE_POINT, 0),
            (FILE_ATTRIBUTE_NORMAL, 0xa000_0003),
        ] {
            assert_eq!(
                validate_reparse_facts(attributes, tag),
                Err(HardeningError::ComponentReparse)
            );
        }

        let before = synthetic_observation(
            31,
            1,
            1,
            r"\\?\Volume{abcdef12-3456-7890-abcd-ef1234567890}\root\leaf",
        );
        let mutations = [
            {
                let mut value = before.clone();
                value.identity.file_id[15] ^= 1;
                (value, HardeningError::IdentityChanged)
            },
            {
                let mut value = before.clone();
                value.link_count = 2;
                (value, HardeningError::HardLinkRejected)
            },
            {
                let mut value = before.clone();
                value.final_path =
                    ascii_units(r"\\?\Volume{abcdef12-3456-7890-abcd-ef1234567890}\root\other");
                (value, HardeningError::FinalPathMismatch)
            },
            {
                let mut value = before.clone();
                value.identity.volume_serial += 1;
                (value, HardeningError::SameVolumeMismatch)
            },
            {
                let mut value = before.clone();
                value.size += 1;
                (value, HardeningError::FactsChanged)
            },
            {
                let mut value = before.clone();
                value.attributes = FILE_ATTRIBUTE_REPARSE_POINT;
                (value, HardeningError::FactsChanged)
            },
            {
                let mut value = before.clone();
                value.reparse_tag = 0xa000_000c;
                (value, HardeningError::FactsChanged)
            },
        ];
        for (after, expected) in mutations {
            assert_eq!(
                validate_stable_observations(Some(&before), Some(&after)),
                Err(expected)
            );
        }
        assert_eq!(
            validate_stable_observations(Some(&before), None),
            Err(HardeningError::InspectionUnavailable)
        );
    }

    #[test]
    fn active_authentication_key_wrapper_loader_is_private_narrow_and_non_authoritative() {
        let source = include_str!("windows_filesystem.rs");
        let (production, tests) = source.split_once("#[cfg(test)]").unwrap();
        assert_eq!(
            production
                .matches("fn load_active_authentication_key_wrapper(")
                .count(),
            1
        );
        assert!(tests.contains("active_authentication_key_wrapper_loader_"));
        let loader = production
            .split_once("fn load_active_authentication_key_wrapper(")
            .unwrap()
            .1
            .split_once("fn load_active_authenticated_evidence_wrapper(")
            .unwrap()
            .0;
        for required in [
            "InstallationEvidencePersistencePaths",
            "PRODUCTION_DATABASE_FILENAME",
            "INSTALLATION_EVIDENCE_DIRECTORY_NAME",
            "ACTIVE_AUTHENTICATION_KEY_FILENAME",
            "open_hardened_directory",
            "inspect_hardened_authentication_key_wrapper",
            "ProtectedWrapperBytes",
        ] {
            assert!(
                loader.contains(required),
                "missing loader boundary: {required}"
            );
        }
        for forbidden in [
            "resolve_installation_evidence_persistence_paths",
            "resolve_production_database_path",
            "ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME",
            "STAGED_AUTHENTICATION_KEY_FILENAME",
            "STAGED_AUTHENTICATED_EVIDENCE_FILENAME",
            "CryptProtectData",
            "CryptUnprotectData",
            "recover_and_authenticate",
            "Hmac",
            "rusqlite",
            "installation_state",
            "tauri::command",
            "CreateFileW(",
            "MoveFileExW(",
            "ReplaceFileW(",
            "FlushFileBuffers(",
            "create_dir",
            "write(",
            "remove_",
        ] {
            assert!(
                !loader.contains(forbidden),
                "forbidden loader authority: {forbidden}"
            );
        }
    }

    #[test]
    fn active_authenticated_evidence_wrapper_loader_loads_exact_owned_redacted_bytes_only() {
        let expected = authenticated_evidence_wrapper(64, 0xc1);
        let fixture = ActiveAuthenticatedEvidenceLoaderTestRoot::create(&expected);
        fs::create_dir(fixture.paths.active_authentication_key.as_path()).unwrap();
        fs::create_dir(fixture.paths.staged_authentication_key.as_path()).unwrap();
        fs::create_dir(fixture.paths.staged_authenticated_evidence.as_path()).unwrap();

        let loaded = load_active_authenticated_evidence_wrapper(&fixture.paths).unwrap();
        assert_eq!(loaded.as_bytes(), expected);
        assert_eq!(format!("{loaded:?}"), "ProtectedWrapperBytes([REDACTED])");
        assert_eq!(
            fixture
                .paths
                .active_authenticated_evidence
                .as_path()
                .file_name(),
            Some(OsStr::new(ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME))
        );
        assert_eq!(
            ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME,
            "authenticated-evidence.dpapi"
        );
        assert!(fixture.paths.active_authentication_key.as_path().is_dir());
        assert!(fixture.paths.staged_authentication_key.as_path().is_dir());
        assert!(
            fixture
                .paths
                .staged_authenticated_evidence
                .as_path()
                .is_dir()
        );
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn active_authenticated_evidence_wrapper_loader_rejects_aggregate_relationship_mismatches() {
        let expected = authenticated_evidence_wrapper(16, 0xc2);
        let fixture = ActiveAuthenticatedEvidenceLoaderTestRoot::create(&expected);
        let alternate =
            installation_evidence_persistence_paths(&fixture.root.join("alternate-root"));

        let mut wrong_root = fixture.paths.clone();
        wrong_root.active_database = alternate.active_database.clone();
        assert_eq!(
            load_active_authenticated_evidence_wrapper(&wrong_root),
            Err(HardeningError::FinalPathMismatch)
        );

        let mut wrong_evidence_directory = fixture.paths.clone();
        wrong_evidence_directory.evidence_directory = alternate.evidence_directory.clone();
        assert_eq!(
            load_active_authenticated_evidence_wrapper(&wrong_evidence_directory),
            Err(HardeningError::FinalPathMismatch)
        );

        let nested =
            installation_evidence_persistence_paths(&fixture.root.join("nested-direct-root"));
        let mut wrong_active_parent = fixture.paths.clone();
        wrong_active_parent.active_authenticated_evidence =
            nested.active_authenticated_evidence.clone();
        assert_eq!(
            load_active_authenticated_evidence_wrapper(&wrong_active_parent),
            Err(HardeningError::FinalPathMismatch)
        );
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn active_authenticated_evidence_wrapper_loader_rejects_wrong_name_and_nested_leaf() {
        let expected = authenticated_evidence_wrapper(16, 0xc3);
        let fixture = ActiveAuthenticatedEvidenceLoaderTestRoot::create(&expected);
        let wrong_name = fixture
            .paths
            .evidence_directory
            .as_path()
            .join("authenticated-evidence-wrong.dpapi");
        fs::rename(
            fixture.paths.active_authenticated_evidence.as_path(),
            &wrong_name,
        )
        .unwrap();
        assert_eq!(
            load_active_authenticated_evidence_wrapper(&fixture.paths),
            Err(HardeningError::InspectionUnavailable)
        );

        let nested_directory = fixture.paths.evidence_directory.as_path().join("nested");
        fs::create_dir(&nested_directory).unwrap();
        let nested_paths = installation_evidence_persistence_paths(&nested_directory);
        let mut wrong_parent = fixture.paths.clone();
        wrong_parent.active_authenticated_evidence =
            nested_paths.active_authenticated_evidence.clone();
        assert_eq!(
            load_active_authenticated_evidence_wrapper(&wrong_parent),
            Err(HardeningError::FinalPathMismatch)
        );
        assert_eq!(fs::read(&wrong_name).unwrap(), expected);
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn active_authenticated_evidence_wrapper_loader_rejects_malformed_and_wrong_kind_wrappers() {
        let malformed_fixture = ActiveAuthenticatedEvidenceLoaderTestRoot::create(&[0x31; 15]);
        assert_eq!(
            load_active_authenticated_evidence_wrapper(&malformed_fixture.paths),
            Err(HardeningError::WrapperInvalid)
        );
        malformed_fixture.assert_sentinel();
        malformed_fixture.cleanup();

        let wrong_kind = authentication_key_wrapper(16, 0xc4);
        let wrong_kind_fixture = ActiveAuthenticatedEvidenceLoaderTestRoot::create(&wrong_kind);
        assert_eq!(
            load_active_authenticated_evidence_wrapper(&wrong_kind_fixture.paths),
            Err(HardeningError::WrapperInvalid)
        );
        wrong_kind_fixture.assert_sentinel();
        wrong_kind_fixture.cleanup();
    }

    #[test]
    fn active_authenticated_evidence_wrapper_loader_rejects_hard_linked_active_before_release() {
        let expected = authenticated_evidence_wrapper(16, 0xc5);
        let fixture = ActiveAuthenticatedEvidenceLoaderTestRoot::create(&expected);
        let alias = fixture
            .paths
            .evidence_directory
            .as_path()
            .join("active-evidence-loader-hard-link-alias.synthetic");
        fs::hard_link(
            fixture.paths.active_authenticated_evidence.as_path(),
            &alias,
        )
        .unwrap();
        assert_eq!(
            load_active_authenticated_evidence_wrapper(&fixture.paths),
            Err(HardeningError::HardLinkRejected)
        );
        assert_eq!(fs::read(&alias).unwrap(), expected);
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn active_authenticated_evidence_wrapper_loader_reuses_policy_and_is_non_authoritative() {
        for (attributes, tag) in [
            (FILE_ATTRIBUTE_REPARSE_POINT, 0),
            (FILE_ATTRIBUTE_NORMAL, 0xa000_0003),
        ] {
            assert_eq!(
                validate_reparse_facts(attributes, tag),
                Err(HardeningError::ComponentReparse)
            );
        }

        let before = synthetic_observation(
            41,
            1,
            1,
            r"\\?\Volume{abcdef12-3456-7890-abcd-ef1234567890}\root\leaf",
        );
        let mut changed = before.clone();
        changed.identity.file_id[15] ^= 1;
        assert_eq!(
            validate_stable_observations(Some(&before), Some(&changed)),
            Err(HardeningError::IdentityChanged)
        );
        assert_eq!(
            validate_stable_observations(Some(&before), None),
            Err(HardeningError::InspectionUnavailable)
        );

        let source = include_str!("windows_filesystem.rs");
        let (production, tests) = source.split_once("#[cfg(test)]").unwrap();
        assert_eq!(
            production
                .matches("fn load_active_authenticated_evidence_wrapper(")
                .count(),
            1
        );
        assert!(tests.contains("active_authenticated_evidence_wrapper_loader_"));
        let loader = production
            .split_once("fn load_active_authenticated_evidence_wrapper(")
            .unwrap()
            .1
            .split_once("// PRODUCTION READ-HARDENING CORE END")
            .unwrap()
            .0;
        for required in [
            "InstallationEvidencePersistencePaths",
            "PRODUCTION_DATABASE_FILENAME",
            "INSTALLATION_EVIDENCE_DIRECTORY_NAME",
            "ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME",
            "open_hardened_directory",
            "inspect_hardened_authenticated_evidence_wrapper",
            "ProtectedWrapperBytes",
        ] {
            assert!(
                loader.contains(required),
                "missing loader boundary: {required}"
            );
        }
        for forbidden in [
            "resolve_installation_evidence_persistence_paths",
            "resolve_production_database_path",
            "ACTIVE_AUTHENTICATION_KEY_FILENAME",
            "STAGED_AUTHENTICATION_KEY_FILENAME",
            "STAGED_AUTHENTICATED_EVIDENCE_FILENAME",
            "CryptProtectData",
            "CryptUnprotectData",
            "recover_and_authenticate",
            "Hmac",
            "generation",
            "plaintext",
            "rusqlite",
            "installation_state",
            "setup",
            "startup",
            "tauri::command",
            "CreateFileW(",
            "MoveFileExW(",
            "ReplaceFileW(",
            "FlushFileBuffers(",
            "create_dir",
            "write(",
            "remove_",
        ] {
            assert!(
                !loader.contains(forbidden),
                "forbidden loader authority: {forbidden}"
            );
        }
        assert_eq!(
            production
                .matches("fn inspect_hardened_wrapper_with<")
                .count(),
            1
        );
        assert!(
            production.contains("EncodedProtectedWrapper::validate_authenticated_evidence_bytes")
        );
        assert!(production.contains("EncodedProtectedWrapper::validate_authentication_key_bytes"));
    }

    #[test]
    fn normal_tree_handle_path_hardening_success_retains_components_and_revalidates_facts() {
        let active = authentication_key_wrapper(64, 0xb1);
        let staged = authentication_key_wrapper(32, 0xb2);
        let fixture = HardeningTestRoot::create(&active, &staged);
        let active_proof = prove_normal_tree_hardening(
            &fixture,
            fixture.paths.active_authentication_key.as_path(),
            ACTIVE_AUTHENTICATION_KEY_FILENAME,
        )
        .unwrap();
        let staged_proof = prove_normal_tree_hardening(
            &fixture,
            fixture.paths.staged_authentication_key.as_path(),
            STAGED_AUTHENTICATION_KEY_FILENAME,
        )
        .unwrap();
        for proof in [active_proof, staged_proof] {
            assert_eq!(proof.retained_directory_count, 4);
            assert!(proof.directory_identities_stable);
            assert!(proof.wrapper_facts_stable);
        }
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn normal_tree_handle_path_hardening_minimum_representative_and_maximum_wrappers() {
        for (blob_length, pattern) in [(1, 0xc1), (64, 0xc2), (65_536, 0xc3)] {
            let wrapper = authentication_key_wrapper(blob_length, pattern);
            let fixture = HardeningTestRoot::create(&wrapper, &wrapper);
            prove_normal_tree_hardening(
                &fixture,
                fixture.paths.active_authentication_key.as_path(),
                ACTIVE_AUTHENTICATION_KEY_FILENAME,
            )
            .unwrap();
            fixture.assert_sentinel();
            fixture.cleanup();
        }
    }

    #[test]
    fn normal_tree_handle_path_hardening_reparse_and_link_policies_are_fail_closed() {
        assert_eq!(validate_reparse_facts(FILE_ATTRIBUTE_NORMAL, 0), Ok(()));
        for (attributes, tag) in [
            (FILE_ATTRIBUTE_REPARSE_POINT, 0),
            (FILE_ATTRIBUTE_REPARSE_POINT, 0xa000_000c),
            (FILE_ATTRIBUTE_REPARSE_POINT, 0xdead_beef),
            (FILE_ATTRIBUTE_NORMAL, 0xa000_0003),
        ] {
            assert_eq!(
                validate_reparse_facts(attributes, tag),
                Err(HardeningError::ComponentReparse)
            );
        }
        for (links, expected) in [
            (0, Err(HardeningError::HardLinkRejected)),
            (1, Ok(())),
            (2, Err(HardeningError::HardLinkRejected)),
            (127, Err(HardeningError::HardLinkRejected)),
        ] {
            assert_eq!(validate_wrapper_link_count(links), expected);
        }
    }

    #[test]
    fn normal_tree_handle_path_hardening_guid_case_and_exact_components() {
        let parent = ascii_units(r"\\?\Volume{ABCDEF12-3456-7890-abcd-EF1234567890}\root");
        let same_case_variant =
            ascii_units(r"\\?\Volume{abcdef12-3456-7890-ABCD-ef1234567890}\root\fixed");
        assert!(same_volume_guid(&parent, &same_case_variant).unwrap());
        assert_eq!(
            exact_child_final_path(&parent, &same_case_variant, &ascii_units("fixed")),
            Ok(())
        );
        for alternate in [
            r"\\?\Volume{abcdef12-3456-7890-ABCD-ef1234567890}\root\Fixed",
            r"\\?\Volume{abcdef12-3456-7890-ABCD-ef1234567890}\root\fixed\child",
            r"\\?\UNC\server\share\root\fixed",
            r"\\?\Volume{abcdef12-3456-7890-ABCD-ef1234567891}\root\fixed",
        ] {
            assert!(
                exact_child_final_path(&parent, &ascii_units(alternate), &ascii_units("fixed"))
                    .is_err()
            );
        }
    }

    #[test]
    fn normal_tree_handle_path_hardening_changed_and_unavailable_observations_fail_closed() {
        let path = r"\\?\Volume{abcdef12-3456-7890-abcd-ef1234567890}\root\leaf";
        let before = synthetic_observation(11, 1, 1, path);
        let mut changed_identity = before.clone();
        changed_identity.identity.file_id[15] = 2;
        assert_eq!(
            validate_stable_observations(Some(&before), Some(&changed_identity)),
            Err(HardeningError::IdentityChanged)
        );
        let mut changed_link = before.clone();
        changed_link.link_count = 2;
        assert_eq!(
            validate_stable_observations(Some(&before), Some(&changed_link)),
            Err(HardeningError::HardLinkRejected)
        );
        let mut changed_path = before.clone();
        changed_path.final_path =
            ascii_units(r"\\?\Volume{abcdef12-3456-7890-abcd-ef1234567890}\root\other");
        assert_eq!(
            validate_stable_observations(Some(&before), Some(&changed_path)),
            Err(HardeningError::FinalPathMismatch)
        );
        let mut changed_volume = before.clone();
        changed_volume.identity.volume_serial = 12;
        assert_eq!(
            validate_stable_observations(Some(&before), Some(&changed_volume)),
            Err(HardeningError::SameVolumeMismatch)
        );
        assert_eq!(
            validate_stable_observations(Some(&before), None),
            Err(HardeningError::InspectionUnavailable)
        );
    }

    #[test]
    fn normal_tree_handle_path_hardening_same_volume_policy_uses_serial_and_guid() {
        let parent = synthetic_observation(
            21,
            1,
            1,
            r"\\?\Volume{abcdef12-3456-7890-abcd-ef1234567890}\root",
        );
        let child = synthetic_observation(
            21,
            2,
            1,
            r"\\?\Volume{ABCDEF12-3456-7890-ABCD-EF1234567890}\root\leaf",
        );
        assert_eq!(validate_same_volume(&parent, &child), Ok(()));
        let mut serial_mismatch = child.clone();
        serial_mismatch.identity.volume_serial = 22;
        assert_eq!(
            validate_same_volume(&parent, &serial_mismatch),
            Err(HardeningError::SameVolumeMismatch)
        );
        let guid_mismatch = synthetic_observation(
            21,
            2,
            1,
            r"\\?\Volume{abcdef12-3456-7890-abcd-ef1234567891}\root\leaf",
        );
        assert_eq!(
            validate_same_volume(&parent, &guid_mismatch),
            Err(HardeningError::SameVolumeMismatch)
        );
    }

    #[test]
    fn normal_tree_handle_path_hardening_core_is_production_compiled_private_and_redacted() {
        let identity = HandleIdentity {
            volume_serial: 987_654_321,
            file_id: [222; 16],
        };
        assert_eq!(format!("{identity:?}"), "HandleIdentity([REDACTED])");
        for error in [
            HardeningError::PathUnavailable,
            HardeningError::ComponentReparse,
            HardeningError::WrongEntryType,
            HardeningError::IdentityChanged,
            HardeningError::HardLinkRejected,
            HardeningError::FinalPathMismatch,
            HardeningError::SameVolumeMismatch,
            HardeningError::InspectionUnavailable,
            HardeningError::FactsChanged,
            HardeningError::ReadUnavailable,
            HardeningError::WrapperInvalid,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains('\\'));
            assert!(!debug.contains('/'));
            assert!(!debug.contains("0x"));
            assert!(!debug.contains("CHDPAPI"));
            assert!(!debug.chars().any(|character| character.is_ascii_digit()));
        }
        let source = include_str!("windows_filesystem.rs");
        let (production, tests) = source.split_once("#[cfg(test)]").unwrap();
        let core = production
            .split_once("// PRODUCTION READ-HARDENING CORE START")
            .unwrap()
            .1
            .split_once("// PRODUCTION READ-HARDENING CORE END")
            .unwrap()
            .0;
        for required in [
            "fn encode_utf16_path",
            "fn open_for_read",
            "fn query_entry_information",
            "fn query_handle_identity",
            "fn query_link_count",
            "fn query_bounded_final_guid_path",
            "fn validate_reparse_facts",
            "fn validate_wrapper_link_count",
            "fn exact_child_final_path",
            "fn validate_same_volume",
            "fn validate_stable_observations",
            "fn inspect_hardened_authentication_key_wrapper",
        ] {
            assert!(
                core.contains(required),
                "missing production core: {required}"
            );
            assert!(
                !tests.contains(&format!("\n    {required}")),
                "duplicate test-only hardening implementation: {required}"
            );
        }
        for forbidden in [
            "GENERIC_WRITE",
            "CREATE_NEW",
            "MoveFileExW(",
            "ReplaceFileW(",
            "FlushFileBuffers(",
            "remove_file",
            "remove_dir",
            "rename(",
            "hard_link(",
            "DeviceIoControl",
            "GetDriveTypeW(",
        ] {
            assert!(
                !core.contains(forbidden),
                "forbidden production core: {forbidden}"
            );
        }
        assert!(!production.contains("fn prove_normal_tree_hardening"));
        let hardening = tests
            .split_once("// HARDENING PROOF START")
            .unwrap()
            .1
            .split_once("// HARDENING PROOF END")
            .unwrap()
            .0;
        for forbidden in [
            "MoveFileExW(",
            "ReplaceFileW(",
            "SetFileInformationByHandle",
            "CreateHardLink",
            "DeviceIoControl",
        ] {
            assert!(
                !hardening.contains(forbidden),
                "forbidden source: {forbidden}"
            );
        }
    }

    #[test]
    fn successful_stage_flush_reload_validate_publish_and_active_reload_flow() {
        assert_successful_flow(64, 0x5a);
    }

    #[test]
    fn exact_minimum_normal_and_maximum_canonical_wrappers_publish() {
        assert_successful_flow(1, 0x11);
        assert_successful_flow(64, 0x22);
        assert_successful_flow(65_536, 0x33);
    }

    #[test]
    fn successful_existing_file_replacement_reinspects_and_preserves_identity() {
        assert_successful_replacement_flow(32, 64, 0x41);
    }

    #[test]
    fn minimum_representative_and_maximum_canonical_replacements_succeed() {
        assert_successful_replacement_flow(2, 1, 0x51);
        assert_successful_replacement_flow(16, 64, 0x61);
        assert_successful_replacement_flow(32, 65_536, 0x71);
    }

    #[test]
    fn missing_active_refuses_before_replace_file_call() {
        let fixture = TestRoot::create();
        let old_bytes = authentication_key_wrapper(8, 0x81);
        let replacement_bytes = authentication_key_wrapper(9, 0x82);
        create_and_verify_replacement_stage(&fixture.paths, &replacement_bytes).unwrap();
        let calls = std::cell::Cell::new(0_u8);
        let result = attempt_existing_replacement_with(
            &fixture.paths,
            &old_bytes,
            &replacement_bytes,
            None,
            |_, _| {
                calls.set(calls.get() + 1);
                ReplacementCallOutcome::Success
            },
        );
        assert_eq!(
            result.err(),
            Some(ExistingFileReplacementError::ActiveMissing)
        );
        assert_eq!(calls.get(), 0);
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn missing_stage_refuses_before_replace_file_call() {
        let fixture = TestRoot::create();
        let old_bytes = authentication_key_wrapper(8, 0x83);
        let replacement_bytes = authentication_key_wrapper(9, 0x84);
        publish_synthetic_authentication_key_wrapper(&fixture.paths, &old_bytes).unwrap();
        let calls = std::cell::Cell::new(0_u8);
        let result = attempt_existing_replacement_with(
            &fixture.paths,
            &old_bytes,
            &replacement_bytes,
            None,
            |_, _| {
                calls.set(calls.get() + 1);
                ReplacementCallOutcome::Success
            },
        );
        assert_eq!(
            result.err(),
            Some(ExistingFileReplacementError::StageMissing)
        );
        assert_eq!(calls.get(), 0);
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn malformed_active_refuses_before_replacement() {
        let fixture = TestRoot::create();
        let expected_old = authentication_key_wrapper(8, 0x85);
        let replacement = authentication_key_wrapper(9, 0x86);
        fs::write(
            fixture.paths.active_authentication_key.as_path(),
            vec![0x85; 15],
        )
        .unwrap();
        create_and_verify_replacement_stage(&fixture.paths, &replacement).unwrap();
        let calls = std::cell::Cell::new(0_u8);
        let result = attempt_existing_replacement_with(
            &fixture.paths,
            &expected_old,
            &replacement,
            None,
            |_, _| {
                calls.set(calls.get() + 1);
                ReplacementCallOutcome::Success
            },
        );
        assert_eq!(
            result.err(),
            Some(ExistingFileReplacementError::PreflightValidationFailed)
        );
        assert_eq!(calls.get(), 0);
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn malformed_stage_refuses_before_replacement() {
        let fixture = TestRoot::create();
        let old = authentication_key_wrapper(8, 0x87);
        let replacement = authentication_key_wrapper(9, 0x88);
        publish_synthetic_authentication_key_wrapper(&fixture.paths, &old).unwrap();
        fs::write(
            fixture.paths.staged_authentication_key.as_path(),
            vec![0x88; 15],
        )
        .unwrap();
        let calls = std::cell::Cell::new(0_u8);
        let result =
            attempt_existing_replacement_with(&fixture.paths, &old, &replacement, None, |_, _| {
                calls.set(calls.get() + 1);
                ReplacementCallOutcome::Success
            });
        assert_eq!(
            result.err(),
            Some(ExistingFileReplacementError::PreflightValidationFailed)
        );
        assert_eq!(calls.get(), 0);
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn stage_byte_mismatch_refuses_before_replacement() {
        let fixture = TestRoot::create();
        let old = authentication_key_wrapper(8, 0x89);
        let written = authentication_key_wrapper(9, 0x8a);
        let expected = authentication_key_wrapper(9, 0x8b);
        prepare_existing_replacement(&fixture, &old, &written);
        let calls = std::cell::Cell::new(0_u8);
        let result =
            attempt_existing_replacement_with(&fixture.paths, &old, &expected, None, |_, _| {
                calls.set(calls.get() + 1);
                ReplacementCallOutcome::Success
            });
        assert_eq!(
            result.err(),
            Some(ExistingFileReplacementError::PreflightValidationFailed)
        );
        assert_eq!(calls.get(), 0);
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn active_byte_mismatch_refuses_before_replacement() {
        let fixture = TestRoot::create();
        let actual_old = authentication_key_wrapper(8, 0x8c);
        let expected_old = authentication_key_wrapper(8, 0x8d);
        let replacement = authentication_key_wrapper(9, 0x8e);
        prepare_existing_replacement(&fixture, &actual_old, &replacement);
        let calls = std::cell::Cell::new(0_u8);
        let result = attempt_existing_replacement_with(
            &fixture.paths,
            &expected_old,
            &replacement,
            None,
            |_, _| {
                calls.set(calls.get() + 1);
                ReplacementCallOutcome::Success
            },
        );
        assert_eq!(
            result.err(),
            Some(ExistingFileReplacementError::PreflightValidationFailed)
        );
        assert_eq!(calls.get(), 0);
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    fn assert_blocked_replacement(block_active: bool) {
        let fixture = TestRoot::create();
        let old = authentication_key_wrapper(20, 0x91);
        let replacement = authentication_key_wrapper(21, 0x92);
        prepare_existing_replacement(&fixture, &old, &replacement);
        let blocker_path = if block_active {
            fixture.paths.active_authentication_key.as_path()
        } else {
            fixture.paths.staged_authentication_key.as_path()
        };
        let blocker = open_for_read(&encode_utf16_path(blocker_path).unwrap()).unwrap();
        let calls = std::cell::Cell::new(0_u8);
        let report = attempt_existing_replacement_with(
            &fixture.paths,
            &old,
            &replacement,
            Some(blocker),
            |active, stage| {
                calls.set(calls.get() + 1);
                call_replace_file_once(active, stage)
            },
        )
        .unwrap();
        assert!(matches!(report.outcome, ReplacementCallOutcome::Failure(_)));
        assert_eq!(calls.get(), 1);
        assert_eq!(
            report.classification,
            ReplacementObservationClass::ActiveOldStageNew
        );
        assert!(matches!(report.active, ExactNameObservation::RegularOld(_)));
        assert!(matches!(report.stage, ExactNameObservation::RegularNew(_)));
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn retained_active_handle_blocks_once_then_fresh_state_is_inspected() {
        assert_blocked_replacement(true);
    }

    #[test]
    fn retained_stage_handle_blocks_once_then_fresh_state_is_inspected() {
        assert_blocked_replacement(false);
    }

    #[test]
    fn special_failure_families_are_classified_only_from_injected_observations() {
        let identity = FileIdentity {
            volume_serial: 7,
            file_index: 11,
        };
        let old = ExactNameObservation::RegularOld(identity);
        let new = ExactNameObservation::RegularNew(identity);
        assert_eq!(
            classify_replacement_observation(
                ReplacementCallOutcome::Failure(ReplacementFailureFamily::UnableToRemoveReplaced,),
                old,
                new,
            ),
            ReplacementObservationClass::ActiveOldStageNew
        );
        assert_eq!(
            classify_replacement_observation(
                ReplacementCallOutcome::Failure(ReplacementFailureFamily::UnableToMoveReplacement,),
                ExactNameObservation::Absent,
                new,
            ),
            ReplacementObservationClass::ActiveAbsentStageNew
        );
        assert_eq!(
            classify_replacement_observation(
                ReplacementCallOutcome::Failure(ReplacementFailureFamily::UnableToMoveReplacement2,),
                old,
                ExactNameObservation::Absent,
            ),
            ReplacementObservationClass::UnexpectedOrUnavailable
        );
        assert_eq!(
            classify_replacement_observation(
                ReplacementCallOutcome::Failure(ReplacementFailureFamily::OtherFailure),
                old,
                new,
            ),
            ReplacementObservationClass::ActiveOldStageNew
        );
    }

    #[test]
    fn reported_failure_completed_state_and_unavailable_state_remain_distinct() {
        let identity = FileIdentity {
            volume_serial: 13,
            file_index: 17,
        };
        assert_eq!(
            classify_replacement_observation(
                ReplacementCallOutcome::Failure(ReplacementFailureFamily::OtherFailure),
                ExactNameObservation::RegularNew(identity),
                ExactNameObservation::Absent,
            ),
            ReplacementObservationClass::ReportedFailureButActiveNewStageAbsent
        );
        assert_eq!(
            classify_replacement_observation(
                ReplacementCallOutcome::Failure(ReplacementFailureFamily::OtherFailure),
                ExactNameObservation::Unavailable,
                ExactNameObservation::RegularNew(identity),
            ),
            ReplacementObservationClass::UnexpectedOrUnavailable
        );
        assert_eq!(
            classify_replacement_observation(
                ReplacementCallOutcome::Success,
                ExactNameObservation::UnexpectedBytesOrMalformed,
                ExactNameObservation::UnexpectedEntryType,
            ),
            ReplacementObservationClass::UnexpectedOrUnavailable
        );
    }

    #[test]
    fn fixed_stage_and_active_names_are_exact() {
        let fixture = TestRoot::create();
        assert_eq!(
            fixture
                .paths
                .staged_authentication_key
                .as_path()
                .file_name(),
            Some(OsStr::new("authentication-key.dpapi.stage"))
        );
        assert_eq!(
            fixture
                .paths
                .active_authentication_key
                .as_path()
                .file_name(),
            Some(OsStr::new("authentication-key.dpapi"))
        );
        assert_eq!(
            STAGED_AUTHENTICATION_KEY_FILENAME,
            "authentication-key.dpapi.stage"
        );
        assert_eq!(
            ACTIVE_AUTHENTICATION_KEY_FILENAME,
            "authentication-key.dpapi"
        );
        assert_eq!(
            fixture.paths.evidence_directory.as_path().file_name(),
            Some(OsStr::new(INSTALLATION_EVIDENCE_DIRECTORY_NAME))
        );
        fixture.cleanup();
    }

    #[test]
    fn create_new_refuses_an_existing_stage_without_changing_it() {
        let fixture = TestRoot::create();
        let existing = authentication_key_wrapper(2, 0x44);
        fs::write(fixture.paths.staged_authentication_key.as_path(), &existing).unwrap();
        let result = publish_synthetic_authentication_key_wrapper(
            &fixture.paths,
            &authentication_key_wrapper(3, 0x55),
        );
        assert_eq!(result, Err(TemporaryPublicationError::StageAlreadyExists));
        assert_eq!(
            fs::read(fixture.paths.staged_authentication_key.as_path()).unwrap(),
            existing
        );
        assert!(!fixture.paths.active_authentication_key.as_path().exists());
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn initial_publication_refuses_existing_active_and_never_replaces_it() {
        let fixture = TestRoot::create();
        let existing_active = authentication_key_wrapper(4, 0x66);
        fs::write(
            fixture.paths.active_authentication_key.as_path(),
            &existing_active,
        )
        .unwrap();
        let result = publish_synthetic_authentication_key_wrapper(
            &fixture.paths,
            &authentication_key_wrapper(5, 0x77),
        );
        assert_eq!(
            result,
            Err(TemporaryPublicationError::InitialPublicationFailed)
        );
        assert_eq!(
            fs::read(fixture.paths.active_authentication_key.as_path()).unwrap(),
            existing_active
        );
        assert!(fixture.paths.staged_authentication_key.as_path().is_file());
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn byte_mismatch_is_detected_during_stage_reload_verification() {
        let fixture = TestRoot::create();
        let written = authentication_key_wrapper(8, 0x88);
        let expected = authentication_key_wrapper(8, 0x89);
        let result = publish_synthetic_authentication_key_wrapper_with_expected_reload(
            &fixture.paths,
            &written,
            &expected,
        );
        assert_eq!(
            result,
            Err(TemporaryPublicationError::ReloadVerificationFailed)
        );
        assert!(fixture.paths.staged_authentication_key.as_path().is_file());
        assert!(!fixture.paths.active_authentication_key.as_path().exists());
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn malformed_wrapper_is_rejected_before_publication() {
        let fixture = TestRoot::create();
        let malformed = vec![0x91; 15];
        let result = publish_synthetic_authentication_key_wrapper(&fixture.paths, &malformed);
        assert_eq!(
            result,
            Err(TemporaryPublicationError::WrapperValidationFailed)
        );
        assert!(fixture.paths.staged_authentication_key.as_path().is_file());
        assert!(!fixture.paths.active_authentication_key.as_path().exists());
        fixture.assert_sentinel();
        fixture.cleanup();
    }

    #[test]
    fn existing_bounded_reader_rejects_trailing_or_growth_data() {
        let intended = authentication_key_wrapper(1, 0xa2);
        let mut with_growth = intended.clone();
        with_growth.push(0xff);
        let error = read_bounded_protected_wrapper(
            &mut Cursor::new(with_growth),
            u64::try_from(intended.len()).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error, BoundedReadError::TrailingData);
        assert_eq!(
            map_read_error(error),
            TemporaryPublicationError::StateChangedDuringInspection
        );
    }

    #[test]
    fn utf16_encoding_is_nul_terminated_and_rejects_interior_nul() {
        let encoded = encode_utf16_path(Path::new(r"C:\synthetic\wrapper.stage")).unwrap();
        assert_eq!(encoded.last(), Some(&0));
        assert_eq!(encoded.iter().filter(|unit| **unit == 0).count(), 1);

        let with_nul = OsString::from_wide(&[
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            b'a' as u16,
            0,
            b'b' as u16,
        ]);
        assert_eq!(
            encode_utf16_path(Path::new(&with_nul)),
            Err(HardeningError::PathUnavailable)
        );
    }

    #[test]
    fn imported_bindings_handle_ownership_and_policy_constants_are_exact() {
        let _: CreateFileWBinding = CREATE_FILE_W_BINDING;
        let _: FlushFileBuffersBinding = FLUSH_FILE_BUFFERS_BINDING;
        let _: GetFileInformationByHandleBinding = GET_FILE_INFORMATION_BY_HANDLE_BINDING;
        let _: GetFileInformationByHandleExBinding = GET_FILE_INFORMATION_BY_HANDLE_EX_BINDING;
        let _: GetFinalPathNameByHandleWBinding = GET_FINAL_PATH_NAME_BY_HANDLE_W_BINDING;
        let _: GetFileTypeBinding = GET_FILE_TYPE_BINDING;
        let _: GetVolumePathNameWBinding = GET_VOLUME_PATH_NAME_W_BINDING;
        let _: GetDriveTypeWBinding = GET_DRIVE_TYPE_W_BINDING;
        let _: MoveFileExWBinding = MOVE_FILE_EX_W_BINDING;
        let _: ReplaceFileWBinding = REPLACE_FILE_W_BINDING;
        let _: GetLastErrorBinding = GET_LAST_ERROR_BINDING;
        let _: OwnedHandleFromRawBinding = OWNED_HANDLE_FROM_RAW_BINDING;
        let _: OwnedHandleAsRawBinding = OWNED_HANDLE_AS_RAW_BINDING;
        let _: OwnedHandleIntoFileBinding = OWNED_HANDLE_INTO_FILE_BINDING;
        let _: HANDLE = INVALID_HANDLE_SENTINEL;
        let _: NullTerminatedUtf16Input = NULL_REPLACE_BACKUP_PATH;
        let _: MutableUtf16Output = std::ptr::null_mut();
        let _: fn(&mut [u16]) -> MutableUtf16Output = mutable_utf16_output;
        let _: *const SECURITY_ATTRIBUTES = NULL_CREATE_SECURITY_ATTRIBUTES;
        let _: HANDLE = NULL_CREATE_TEMPLATE_HANDLE;
        let _: *const c_void = NULL_REPLACE_EXCLUDE_CONTEXT;
        let _: *const c_void = NULL_REPLACE_RESERVED_CONTEXT;
        let _: BY_HANDLE_FILE_INFORMATION = BY_HANDLE_FILE_INFORMATION::default();
        let _: StandardFileInformation = FILE_STANDARD_INFO::default();
        let _: AttributeTagFileInformation = FILE_ATTRIBUTE_TAG_INFO::default();
        let _: FileIdFileInformation = FILE_ID_INFO::default();
        let _: FILE_INFO_BY_HANDLE_CLASS = STANDARD_INFORMATION_CLASS;
        let _: FILE_INFO_BY_HANDLE_CLASS = ATTRIBUTE_TAG_INFORMATION_CLASS;
        let _: FILE_INFO_BY_HANDLE_CLASS = FILE_ID_INFORMATION_CLASS;
        let _: FILE_FLAGS_AND_ATTRIBUTES = DIRECTORY_ATTRIBUTE;
        let _: FILE_FLAGS_AND_ATTRIBUTES = REPARSE_POINT_ATTRIBUTE;
        let _: FILE_TYPE = DISK_FILE_TYPE;

        assert_eq!(checked_buffer_length(0), Some(0));
        assert_eq!(checked_buffer_length(u32::MAX as usize), Some(u32::MAX));
        assert_eq!(ACTIVE_READ_ACCESS, GENERIC_READ);
        assert_eq!(ACTIVE_READ_SHARE, FILE_SHARE_READ);
        assert_eq!(ACTIVE_READ_DISPOSITION, OPEN_EXISTING);
        assert_eq!(
            ACTIVE_READ_FLAGS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
        );
        assert_eq!(STAGE_CREATE_ACCESS, GENERIC_WRITE);
        assert_eq!(STAGE_CREATE_SHARE, 0);
        assert_eq!(STAGE_CREATE_DISPOSITION, CREATE_NEW);
        assert_eq!(
            STAGE_CREATE_FLAGS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
        );
        assert_eq!(DIRECTORY_OPEN_ACCESS, 0);
        assert_eq!(DIRECTORY_OPEN_SHARE, FILE_SHARE_READ | FILE_SHARE_WRITE);
        assert_eq!(DIRECTORY_OPEN_DISPOSITION, OPEN_EXISTING);
        assert_eq!(
            DIRECTORY_OPEN_FLAGS,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
        );
        assert_eq!(INITIAL_PUBLICATION_FLAGS, MOVEFILE_WRITE_THROUGH);
        assert_eq!(
            INITIAL_PUBLICATION_FLAGS & FORBIDDEN_INITIAL_PUBLICATION_FLAGS,
            0
        );
        assert_eq!(REPLACEMENT_FLAGS, 0);
        assert_eq!(
            NORMALIZED_GUID_FINAL_PATH_FLAGS,
            FILE_NAME_NORMALIZED | VOLUME_NAME_GUID
        );
    }

    #[test]
    fn errors_and_debug_are_path_native_detail_and_byte_free() {
        let variants = [
            TemporaryPublicationError::PathEncodingFailed,
            TemporaryPublicationError::StageAlreadyExists,
            TemporaryPublicationError::OpenFailed,
            TemporaryPublicationError::EntryTypeInvalid,
            TemporaryPublicationError::ProtectedFileSizeInvalid,
            TemporaryPublicationError::WriteFailed,
            TemporaryPublicationError::FlushFailed,
            TemporaryPublicationError::ReadFailed,
            TemporaryPublicationError::ReloadVerificationFailed,
            TemporaryPublicationError::WrapperValidationFailed,
            TemporaryPublicationError::InitialPublicationFailed,
            TemporaryPublicationError::StateChangedDuringInspection,
        ];
        for error in variants {
            let debug = format!("{error:?}");
            assert!(!debug.contains('\\'));
            assert!(!debug.contains('/'));
            assert!(!debug.contains("0x"));
            assert!(!debug.contains("CHDPAPI"));
            assert!(!debug.chars().any(|character| character.is_ascii_digit()));
        }
        for error in [
            ExistingFileReplacementError::ActiveMissing,
            ExistingFileReplacementError::StageMissing,
            ExistingFileReplacementError::PreflightValidationFailed,
            ExistingFileReplacementError::ReplacementFailed,
            ExistingFileReplacementError::ReplacementStateAmbiguous,
            ExistingFileReplacementError::ReplacementVerificationFailed,
            ExistingFileReplacementError::StateChangedDuringInspection,
        ] {
            let debug = format!("{error:?}");
            assert!(!debug.contains('\\'));
            assert!(!debug.contains('/'));
            assert!(!debug.contains("0x"));
            assert!(!debug.contains("CHDPAPI"));
            assert!(!debug.chars().any(|character| character.is_ascii_digit()));
        }
        assert_eq!(
            format!(
                "{:?}",
                TemporaryPublicationProof {
                    stage_reload_verified: true,
                    published_without_replacement: true,
                    active_reload_verified: true,
                }
            ),
            "TemporaryPublicationProof { stage_reload_verified: true, published_without_replacement: true, active_reload_verified: true }"
        );
    }

    #[test]
    fn production_prefix_has_no_replacement_mutex_or_operational_authority() {
        let source = include_str!("windows_filesystem.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "ReplaceFileW(",
            "MOVEFILE_REPLACE_EXISTING | INITIAL_PUBLICATION_FLAGS",
            "MOVEFILE_COPY_ALLOWED | INITIAL_PUBLICATION_FLAGS",
            "CreateMutex",
            "DeviceIoControl",
            "CryptProtectData",
            "CryptUnprotectData",
            "rusqlite",
            "resolve_production",
            "installation_state",
            "tauri::command",
            "remove_dir_all",
            "remove_file",
            "hard_link",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden source: {forbidden}"
            );
        }
    }

    #[test]
    fn replacement_source_has_one_locked_test_only_native_invocation() {
        let source = include_str!("windows_filesystem.rs");
        let (production, test_only) = source.split_once("#[cfg(test)]").unwrap();
        let implementation = test_only.split("#[test]").next().unwrap();
        assert!(!production.contains("ReplaceFileW("));
        assert_eq!(
            implementation
                .matches("\n            ReplaceFileW(\n")
                .count(),
            1
        );
        assert!(implementation.contains("NULL_REPLACE_BACKUP_PATH,"));
        assert!(implementation.contains("REPLACEMENT_FLAGS,"));
        assert!(implementation.contains("NULL_REPLACE_EXCLUDE_CONTEXT,"));
        assert!(implementation.contains("NULL_REPLACE_RESERVED_CONTEXT,"));
        assert_eq!(REPLACEMENT_FLAGS, 0);
        assert!(NULL_REPLACE_BACKUP_PATH.is_null());
        assert!(NULL_REPLACE_EXCLUDE_CONTEXT.is_null());
        assert!(NULL_REPLACE_RESERVED_CONTEXT.is_null());
        for forbidden in [
            concat!("REPLACEFILE_", "WRITE_THROUGH"),
            concat!("REPLACEFILE_", "IGNORE_MERGE_ERRORS"),
            concat!("REPLACEFILE_", "IGNORE_ACL_ERRORS"),
            concat!("Create", "Mutex"),
            concat!("Device", "IoControl"),
            concat!("Crypt", "ProtectData"),
            concat!("Crypt", "UnprotectData"),
            concat!("resolve_", "production"),
            concat!("tauri::", "command"),
        ] {
            assert!(
                !implementation.contains(forbidden),
                "forbidden source: {forbidden}"
            );
        }
    }
}
