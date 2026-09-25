//! Private retained authority for one exact eligible NTFS recovery-volume root.
//!
//! Exact-root acquisition remains observation-only. It accepts only the opaque
//! result of the private Rust-native selector, retains the opened root, and
//! composes the existing topology and external/disconnectable eligibility
//! proofs. This private subtree also contains a separately typed consuming
//! boundary that creates and retains the two fixed recovery-set children.
//! Neither boundary grants artifact-publication authority.

use std::{
    ffi::c_void,
    fmt,
    fs::File,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    },
    path::PathBuf,
};

use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        FILE_STANDARD_INFO, FILE_TYPE_DISK, FileAttributeTagInfo, FileIdInfo, FileStandardInfo,
        GetDiskFreeSpaceExW, GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW,
        GetVolumeInformationByHandleW, OPEN_EXISTING, VOLUME_NAME_GUID,
    },
};

use crate::production_database_migration_recovery_envelope::RecoverySetRequiredBytes;

use super::{
    RetainedVolumeSinglePhysicalDeviceObservation, RetainedVolumeTopologyError,
    observe_retained_volume_single_physical_device,
    windows_external_recovery_device_eligibility::{
        PhysicalDeviceSeparationError, RecoveryDeviceSeparatedFromProductionStorage,
        RetainedExternalDisconnectableRecoveryDeviceObservation,
        TwoRecoveryDevicesSeparatedFromProductionStorage,
        observe_retained_external_disconnectable_recovery_device,
        separate_recovery_device_from_production_storage,
    },
};

#[path = "windows_retained_eligible_ntfs_recovery_volume_root/native_windows_selection.rs"]
mod native_windows_selection;
#[path = "windows_retained_eligible_ntfs_recovery_volume_root/retained_recovery_set_directories.rs"]
mod retained_recovery_set_directories;

pub(crate) use native_windows_selection::{
    NativeRecoveryVolumeSelectionOutcome, select_native_recovery_volume_root,
};
pub(crate) use retained_recovery_set_directories::{
    FirstCompleteRecoverySetVerificationFailure, FirstCompleteRecoverySetVerificationOutcome,
    FirstCompleteRecoverySetVerified, FirstRecoveryDatabaseAndEnvelopeArtifactsPublished,
    FirstRecoveryDatabaseArtifactPublished, FirstRecoveryDatabasePublicationOutcome,
    FirstRecoveryEnvelopePublicationOutcome, FirstRecoveryManifestPublicationOutcome,
    FirstRecoverySetArtifactsPublished, FirstRecoverySetRecoveredKeyVerificationError,
    FirstRecoverySetRecoveredKeyVerificationFailure,
    FirstRecoverySetRecoveredKeyVerificationOutcome,
    FirstRecoverySetRecoveredKeyVerificationVerifierCloseFailure,
    FirstRecoverySetRecoveredKeyVerified, publish_first_recovery_envelope_artifact,
    publish_first_recovery_manifest_artifact, verify_first_complete_recovery_set,
    verify_first_recovery_set_with_reentered_recovery_key,
};

pub(crate) struct TwoRetainedRecoverySetDirectories {
    _directories: retained_recovery_set_directories::TwoRetainedRecoverySetDirectories,
}

const MAXIMUM_FINAL_PATH_UNITS: usize = 32_767;
const VOLUME_GUID_ROOT_UNITS: usize = 49;
const FILESYSTEM_NAME_CAPACITY: usize = 32;
const FINAL_PATH_FLAGS: u32 = FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;

pub(crate) struct NativeSelectedRecoveryVolumeRoot {
    selected: PathBuf,
}

impl NativeSelectedRecoveryVolumeRoot {
    fn from_native_volume_guid_root(selected: [u16; VOLUME_GUID_ROOT_UNITS]) -> Self {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};

        Self {
            selected: PathBuf::from(OsString::from_wide(&selected)),
        }
    }
}

impl fmt::Debug for NativeSelectedRecoveryVolumeRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeSelectedRecoveryVolumeRoot([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RootIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

#[derive(Clone, Eq, PartialEq)]
struct RootFacts {
    identity: RootIdentity,
    disk_entry: bool,
    directory: bool,
    delete_pending: bool,
    attributes: u32,
    reparse_tag: u32,
    normalized_root: [u16; VOLUME_GUID_ROOT_UNITS],
}

pub(super) struct RetainedEligibleNtfsRecoveryVolumeRoot {
    selected_root: File,
    initial_root: RootFacts,
    eligible_device: RetainedExternalDisconnectableRecoveryDeviceObservation,
}

pub(crate) struct RecoveryVolumeRootSeparatedFromProductionStorage {
    selected_root: File,
    initial_root: RootFacts,
    separation: RecoveryDeviceSeparatedFromProductionStorage,
}

pub(crate) struct TwoRecoveryVolumeRootsSeparatedFromProductionStorage {
    first_selected_root: File,
    first_initial_root: RootFacts,
    second_selected_root: File,
    second_initial_root: RootFacts,
    separation: TwoRecoveryDevicesSeparatedFromProductionStorage,
}

pub(crate) struct TwoCapacityValidatedRecoveryVolumeRoots {
    roots: TwoRecoveryVolumeRootsSeparatedFromProductionStorage,
}

impl fmt::Debug for RecoveryVolumeRootSeparatedFromProductionStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryVolumeRootSeparatedFromProductionStorage([REDACTED])")
    }
}

impl fmt::Debug for TwoRecoveryVolumeRootsSeparatedFromProductionStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TwoRecoveryVolumeRootsSeparatedFromProductionStorage([REDACTED])")
    }
}

pub(crate) enum RetainAndSeparateSecondRecoveryVolumeError {
    RetentionFailed(Box<RecoveryVolumeRootSeparatedFromProductionStorage>),
    SeparationFailed,
}

impl fmt::Debug for RetainAndSeparateSecondRecoveryVolumeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RetentionFailed(_) => "RetentionFailed",
            Self::SeparationFailed => "SeparationFailed",
        })
    }
}

impl fmt::Debug for TwoCapacityValidatedRecoveryVolumeRoots {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TwoCapacityValidatedRecoveryVolumeRoots([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum RecoveryVolumeRootProductionSeparationError {
    ProductionObservationUnavailable,
    RecoveryRootUnavailableOrChanged,
    SamePhysicalDevice,
    TopologyChangedOrInconsistent,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum TwoRecoveryVolumeRootsSeparationError {
    FirstRootUnavailableOrChanged,
    SecondRootUnavailableOrChanged,
    ProductionObservationUnavailable,
    SamePhysicalDevice,
    TopologyChangedOrInconsistent,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum RecoveryVolumeCapacityValidationError {
    SourceSizeUnavailable,
    CapacityObservationUnavailable,
    InsufficientCapacity,
    DestinationChangedOrInconsistent,
}

impl fmt::Debug for RecoveryVolumeRootProductionSeparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProductionObservationUnavailable => "ProductionObservationUnavailable",
            Self::RecoveryRootUnavailableOrChanged => "RecoveryRootUnavailableOrChanged",
            Self::SamePhysicalDevice => "SamePhysicalDevice",
            Self::TopologyChangedOrInconsistent => "TopologyChangedOrInconsistent",
        })
    }
}

impl fmt::Debug for TwoRecoveryVolumeRootsSeparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FirstRootUnavailableOrChanged => "FirstRootUnavailableOrChanged",
            Self::SecondRootUnavailableOrChanged => "SecondRootUnavailableOrChanged",
            Self::ProductionObservationUnavailable => "ProductionObservationUnavailable",
            Self::SamePhysicalDevice => "SamePhysicalDevice",
            Self::TopologyChangedOrInconsistent => "TopologyChangedOrInconsistent",
        })
    }
}

impl fmt::Debug for RecoveryVolumeCapacityValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceSizeUnavailable => "SourceSizeUnavailable",
            Self::CapacityObservationUnavailable => "CapacityObservationUnavailable",
            Self::InsufficientCapacity => "InsufficientCapacity",
            Self::DestinationChangedOrInconsistent => "DestinationChangedOrInconsistent",
        })
    }
}

impl fmt::Debug for RetainedEligibleNtfsRecoveryVolumeRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedEligibleNtfsRecoveryVolumeRoot([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum RetainedEligibleNtfsRecoveryVolumeRootError {
    RootObservationUnavailable,
    InvalidOrUnsupportedRoot,
    UnsupportedFilesystem,
    EligibilityUnavailableOrChanged,
}

impl fmt::Debug for RetainedEligibleNtfsRecoveryVolumeRootError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RootObservationUnavailable => "RootObservationUnavailable",
            Self::InvalidOrUnsupportedRoot => "InvalidOrUnsupportedRoot",
            Self::UnsupportedFilesystem => "UnsupportedFilesystem",
            Self::EligibilityUnavailableOrChanged => "EligibilityUnavailableOrChanged",
        })
    }
}

fn ascii_units(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn is_ascii_hex(unit: u16) -> bool {
    (b'0' as u16..=b'9' as u16).contains(&unit)
        || (b'a' as u16..=b'f' as u16).contains(&unit)
        || (b'A' as u16..=b'F' as u16).contains(&unit)
}

fn fold_ascii(unit: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&unit) {
        unit + u16::from(b'a' - b'A')
    } else {
        unit
    }
}

fn parse_exact_volume_root(
    path: &[u16],
) -> Result<[u16; VOLUME_GUID_ROOT_UNITS], RetainedEligibleNtfsRecoveryVolumeRootError> {
    let prefix = ascii_units(r"\\?\Volume{");
    if path.len() != VOLUME_GUID_ROOT_UNITS
        || path.contains(&0)
        || path.get(..prefix.len()) != Some(prefix.as_slice())
        || path[47] != b'}' as u16
        || path[48] != b'\\' as u16
    {
        return Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot);
    }
    for (offset, unit) in path[11..47].iter().copied().enumerate() {
        let valid = if matches!(offset, 8 | 13 | 18 | 23) {
            unit == b'-' as u16
        } else {
            is_ascii_hex(unit)
        };
        if !valid {
            return Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot);
        }
    }
    path.try_into()
        .map_err(|_| RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot)
}

fn same_exact_volume_root(
    left: &[u16; VOLUME_GUID_ROOT_UNITS],
    right: &[u16; VOLUME_GUID_ROOT_UNITS],
) -> bool {
    left.iter()
        .zip(right)
        .all(|(left, right)| fold_ascii(*left) == fold_ascii(*right))
}

fn open_selected_root(
    selection: NativeSelectedRecoveryVolumeRoot,
) -> Result<File, RetainedEligibleNtfsRecoveryVolumeRootError> {
    let mut encoded = Vec::new();
    for unit in selection.selected.as_os_str().encode_wide() {
        if unit == 0 {
            return Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot);
        }
        encoded.push(unit);
    }
    encoded.push(0);
    // SAFETY: the private native-selection result is encoded as a live,
    // NUL-terminated buffer. This opens the directory entry itself, requests no
    // mutation access, permits no delete sharing, and transfers ownership once.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut::<c_void>(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable);
    }
    // SAFETY: ownership of the fresh successful handle is transferred once.
    Ok(File::from(unsafe {
        OwnedHandle::from_raw_handle(raw as RawHandle)
    }))
}

fn query_exact_final_root(
    root: &File,
) -> Result<[u16; VOLUME_GUID_ROOT_UNITS], RetainedEligibleNtfsRecoveryVolumeRootError> {
    let handle = root.as_raw_handle() as HANDLE;
    // SAFETY: this is the documented size query on the retained live handle.
    let required =
        unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, FINAL_PATH_FLAGS) };
    let capacity = usize::try_from(required)
        .map_err(|_| RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable)?;
    if capacity == 0 || capacity > MAXIMUM_FINAL_PATH_UNITS {
        return Err(RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable);
    }
    let mut output = vec![0_u16; capacity];
    // SAFETY: output is writable for the checked capacity and the handle stays live.
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, output.as_mut_ptr(), required, FINAL_PATH_FLAGS)
    };
    let written = usize::try_from(written)
        .map_err(|_| RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable)?;
    if written == 0 || written >= output.len() || written > MAXIMUM_FINAL_PATH_UNITS {
        return Err(RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable);
    }
    output.truncate(written);
    parse_exact_volume_root(&output)
}

fn checked_information_size<T>() -> Result<u32, RetainedEligibleNtfsRecoveryVolumeRootError> {
    u32::try_from(std::mem::size_of::<T>())
        .map_err(|_| RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable)
}

fn query_root_facts(root: &File) -> Result<RootFacts, RetainedEligibleNtfsRecoveryVolumeRootError> {
    let handle = root.as_raw_handle() as HANDLE;
    // SAFETY: the handle remains owned by the live File.
    let disk_entry = unsafe { GetFileType(handle) } == FILE_TYPE_DISK;
    if !disk_entry {
        return Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot);
    }

    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: standard is exact initialized writable storage for the live handle.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&raw mut standard).cast::<c_void>(),
            checked_information_size::<FILE_STANDARD_INFO>()?,
        )
    } == 0
    {
        return Err(RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable);
    }

    let mut attribute_tag = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: attribute_tag is exact initialized writable storage for the live handle.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&raw mut attribute_tag).cast::<c_void>(),
            checked_information_size::<FILE_ATTRIBUTE_TAG_INFO>()?,
        )
    } == 0
    {
        return Err(RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable);
    }

    let mut identity = FILE_ID_INFO::default();
    // SAFETY: identity is exact initialized writable storage for the live handle.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut identity).cast::<c_void>(),
            checked_information_size::<FILE_ID_INFO>()?,
        )
    } == 0
    {
        return Err(RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable);
    }

    let facts = RootFacts {
        identity: RootIdentity {
            volume_serial: identity.VolumeSerialNumber,
            file_id: identity.FileId.Identifier,
        },
        disk_entry,
        directory: standard.Directory,
        delete_pending: standard.DeletePending,
        attributes: attribute_tag.FileAttributes,
        reparse_tag: attribute_tag.ReparseTag,
        normalized_root: query_exact_final_root(root)?,
    };
    validate_root_facts(&facts)?;
    Ok(facts)
}

fn validate_root_facts(
    facts: &RootFacts,
) -> Result<(), RetainedEligibleNtfsRecoveryVolumeRootError> {
    if !facts.disk_entry
        || !facts.directory
        || facts.delete_pending
        || facts.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || facts.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || facts.reparse_tag != 0
    {
        return Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot);
    }
    parse_exact_volume_root(&facts.normalized_root)?;
    Ok(())
}

fn require_same_root(
    initial: &RootFacts,
    current: &RootFacts,
) -> Result<(), RetainedEligibleNtfsRecoveryVolumeRootError> {
    validate_root_facts(current)?;
    if initial.identity != current.identity
        || !same_exact_volume_root(&initial.normalized_root, &current.normalized_root)
    {
        return Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot);
    }
    Ok(())
}

fn require_ntfs_name(
    observed: Option<&[u16]>,
) -> Result<(), RetainedEligibleNtfsRecoveryVolumeRootError> {
    let observed =
        observed.ok_or(RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable)?;
    let expected = ascii_units("NTFS");
    if observed.len() != expected.len()
        || !observed
            .iter()
            .zip(expected)
            .all(|(left, right)| fold_ascii(*left) == fold_ascii(right))
    {
        return Err(RetainedEligibleNtfsRecoveryVolumeRootError::UnsupportedFilesystem);
    }
    Ok(())
}

fn observe_ntfs(root: &File) -> Result<(), RetainedEligibleNtfsRecoveryVolumeRootError> {
    let mut filesystem_name = [0_u16; FILESYSTEM_NAME_CAPACITY];
    // SAFETY: the selected-root handle stays live; unused outputs are null and
    // the fixed filesystem-name buffer is writable for its supplied capacity.
    if unsafe {
        GetVolumeInformationByHandleW(
            root.as_raw_handle() as HANDLE,
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
        return Err(RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable);
    }
    let length = filesystem_name
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable)?;
    require_ntfs_name(Some(&filesystem_name[..length]))
}

fn require_eligibility<T, E>(
    result: Result<T, E>,
) -> Result<T, RetainedEligibleNtfsRecoveryVolumeRootError> {
    result.map_err(|_| RetainedEligibleNtfsRecoveryVolumeRootError::EligibilityUnavailableOrChanged)
}

fn map_production_revalidation_error(
    error: RetainedVolumeTopologyError,
) -> RecoveryVolumeRootProductionSeparationError {
    match error {
        RetainedVolumeTopologyError::VolumeObservationUnavailable => {
            RecoveryVolumeRootProductionSeparationError::ProductionObservationUnavailable
        }
        RetainedVolumeTopologyError::MalformedOrUnsupportedTopology
        | RetainedVolumeTopologyError::MultiplePhysicalDisks
        | RetainedVolumeTopologyError::TopologyChangedOrInconsistent => {
            RecoveryVolumeRootProductionSeparationError::TopologyChangedOrInconsistent
        }
    }
}

fn map_separation_error(
    error: PhysicalDeviceSeparationError,
) -> RecoveryVolumeRootProductionSeparationError {
    match error {
        PhysicalDeviceSeparationError::ProductionStorageObservationUnavailable => {
            RecoveryVolumeRootProductionSeparationError::ProductionObservationUnavailable
        }
        PhysicalDeviceSeparationError::RecoveryDeviceObservationUnavailable => {
            RecoveryVolumeRootProductionSeparationError::RecoveryRootUnavailableOrChanged
        }
        PhysicalDeviceSeparationError::SamePhysicalDevice => {
            RecoveryVolumeRootProductionSeparationError::SamePhysicalDevice
        }
        PhysicalDeviceSeparationError::TopologyChangedOrInconsistent => {
            RecoveryVolumeRootProductionSeparationError::TopologyChangedOrInconsistent
        }
    }
}

fn map_two_root_first_revalidation_error(
    error: RecoveryVolumeRootProductionSeparationError,
) -> TwoRecoveryVolumeRootsSeparationError {
    match error {
        RecoveryVolumeRootProductionSeparationError::ProductionObservationUnavailable => {
            TwoRecoveryVolumeRootsSeparationError::ProductionObservationUnavailable
        }
        RecoveryVolumeRootProductionSeparationError::RecoveryRootUnavailableOrChanged => {
            TwoRecoveryVolumeRootsSeparationError::FirstRootUnavailableOrChanged
        }
        RecoveryVolumeRootProductionSeparationError::SamePhysicalDevice => {
            TwoRecoveryVolumeRootsSeparationError::SamePhysicalDevice
        }
        RecoveryVolumeRootProductionSeparationError::TopologyChangedOrInconsistent => {
            TwoRecoveryVolumeRootsSeparationError::TopologyChangedOrInconsistent
        }
    }
}

fn map_two_root_separation_error(
    error: PhysicalDeviceSeparationError,
) -> TwoRecoveryVolumeRootsSeparationError {
    match error {
        PhysicalDeviceSeparationError::ProductionStorageObservationUnavailable => {
            TwoRecoveryVolumeRootsSeparationError::ProductionObservationUnavailable
        }
        PhysicalDeviceSeparationError::RecoveryDeviceObservationUnavailable
        | PhysicalDeviceSeparationError::TopologyChangedOrInconsistent => {
            TwoRecoveryVolumeRootsSeparationError::TopologyChangedOrInconsistent
        }
        PhysicalDeviceSeparationError::SamePhysicalDevice => {
            TwoRecoveryVolumeRootsSeparationError::SamePhysicalDevice
        }
    }
}

fn revalidate_root_identity_and_filesystem(
    selected_root: &File,
    initial_root: &RootFacts,
) -> Result<(), RetainedEligibleNtfsRecoveryVolumeRootError> {
    let current = query_root_facts(selected_root)?;
    require_same_root(initial_root, &current)?;
    observe_ntfs(selected_root)
}

pub(super) fn retain_eligible_ntfs_recovery_volume_root(
    selection: NativeSelectedRecoveryVolumeRoot,
) -> Result<RetainedEligibleNtfsRecoveryVolumeRoot, RetainedEligibleNtfsRecoveryVolumeRootError> {
    let selected_root = open_selected_root(selection)?;
    let initial_root = query_root_facts(&selected_root)?;
    observe_ntfs(&selected_root)?;
    let topology = require_eligibility(observe_retained_volume_single_physical_device(
        &selected_root,
    ))?;
    let eligible_device = require_eligibility(
        observe_retained_external_disconnectable_recovery_device(topology),
    )?;
    let confirmed_root = query_root_facts(&selected_root)?;
    require_same_root(&initial_root, &confirmed_root)?;
    observe_ntfs(&selected_root)?;
    Ok(RetainedEligibleNtfsRecoveryVolumeRoot {
        selected_root,
        initial_root,
        eligible_device,
    })
}

impl RetainedEligibleNtfsRecoveryVolumeRoot {
    pub(super) fn revalidate(&self) -> Result<(), RetainedEligibleNtfsRecoveryVolumeRootError> {
        revalidate_root_identity_and_filesystem(&self.selected_root, &self.initial_root)?;
        require_eligibility(self.eligible_device.revalidate())
    }
}

pub(super) fn separate_recovery_volume_root_from_production_storage(
    production_topology: RetainedVolumeSinglePhysicalDeviceObservation,
    recovery_root: RetainedEligibleNtfsRecoveryVolumeRoot,
) -> Result<
    RecoveryVolumeRootSeparatedFromProductionStorage,
    RecoveryVolumeRootProductionSeparationError,
> {
    production_topology
        .revalidate()
        .map_err(map_production_revalidation_error)?;
    recovery_root.revalidate().map_err(|_| {
        RecoveryVolumeRootProductionSeparationError::RecoveryRootUnavailableOrChanged
    })?;
    let RetainedEligibleNtfsRecoveryVolumeRoot {
        selected_root,
        initial_root,
        eligible_device,
    } = recovery_root;
    let separation =
        separate_recovery_device_from_production_storage(production_topology, eligible_device)
            .map_err(map_separation_error)?;
    Ok(RecoveryVolumeRootSeparatedFromProductionStorage {
        selected_root,
        initial_root,
        separation,
    })
}

pub(crate) fn retain_and_separate_first_recovery_volume(
    production_topology: RetainedVolumeSinglePhysicalDeviceObservation,
    selection: NativeSelectedRecoveryVolumeRoot,
) -> Result<RecoveryVolumeRootSeparatedFromProductionStorage, ()> {
    let retained_root = retain_eligible_ntfs_recovery_volume_root(selection).map_err(|_| ())?;
    separate_recovery_volume_root_from_production_storage(production_topology, retained_root)
        .map_err(|_| ())
}

pub(crate) fn retain_and_separate_second_recovery_volume(
    first_root: RecoveryVolumeRootSeparatedFromProductionStorage,
    selection: NativeSelectedRecoveryVolumeRoot,
) -> Result<
    TwoRecoveryVolumeRootsSeparatedFromProductionStorage,
    RetainAndSeparateSecondRecoveryVolumeError,
> {
    let second_root = match retain_eligible_ntfs_recovery_volume_root(selection) {
        Ok(second_root) => second_root,
        Err(_) => {
            return Err(RetainAndSeparateSecondRecoveryVolumeError::RetentionFailed(
                Box::new(first_root),
            ));
        }
    };
    separate_two_recovery_volume_roots_from_production_storage(first_root, second_root)
        .map_err(|_| RetainAndSeparateSecondRecoveryVolumeError::SeparationFailed)
}

impl RecoveryVolumeRootSeparatedFromProductionStorage {
    pub(super) fn revalidate(&self) -> Result<(), RecoveryVolumeRootProductionSeparationError> {
        self.separation
            .revalidate_production_topology()
            .map_err(map_separation_error)?;
        revalidate_root_identity_and_filesystem(&self.selected_root, &self.initial_root).map_err(
            |_| RecoveryVolumeRootProductionSeparationError::RecoveryRootUnavailableOrChanged,
        )?;
        self.separation.revalidate().map_err(map_separation_error)
    }
}

pub(super) fn separate_two_recovery_volume_roots_from_production_storage(
    first_root: RecoveryVolumeRootSeparatedFromProductionStorage,
    second_root: RetainedEligibleNtfsRecoveryVolumeRoot,
) -> Result<
    TwoRecoveryVolumeRootsSeparatedFromProductionStorage,
    TwoRecoveryVolumeRootsSeparationError,
> {
    first_root
        .revalidate()
        .map_err(map_two_root_first_revalidation_error)?;
    second_root
        .revalidate()
        .map_err(|_| TwoRecoveryVolumeRootsSeparationError::SecondRootUnavailableOrChanged)?;
    let RecoveryVolumeRootSeparatedFromProductionStorage {
        selected_root: first_selected_root,
        initial_root: first_initial_root,
        separation,
    } = first_root;
    let RetainedEligibleNtfsRecoveryVolumeRoot {
        selected_root: second_selected_root,
        initial_root: second_initial_root,
        eligible_device: second_eligible_device,
    } = second_root;
    let separation = separation
        .separate_second_recovery_device(second_eligible_device)
        .map_err(map_two_root_separation_error)?;
    Ok(TwoRecoveryVolumeRootsSeparatedFromProductionStorage {
        first_selected_root,
        first_initial_root,
        second_selected_root,
        second_initial_root,
        separation,
    })
}

impl TwoRecoveryVolumeRootsSeparatedFromProductionStorage {
    pub(super) fn revalidate(&self) -> Result<(), TwoRecoveryVolumeRootsSeparationError> {
        revalidate_root_identity_and_filesystem(
            &self.first_selected_root,
            &self.first_initial_root,
        )
        .map_err(|_| TwoRecoveryVolumeRootsSeparationError::FirstRootUnavailableOrChanged)?;
        revalidate_root_identity_and_filesystem(
            &self.second_selected_root,
            &self.second_initial_root,
        )
        .map_err(|_| TwoRecoveryVolumeRootsSeparationError::SecondRootUnavailableOrChanged)?;
        self.separation
            .revalidate()
            .map_err(map_two_root_separation_error)
    }
}

#[derive(Clone, Copy)]
enum CapacityTarget {
    First,
    Second,
}

fn observe_available_bytes_for_current_user(
    normalized_root: &[u16; VOLUME_GUID_ROOT_UNITS],
) -> Result<u64, RecoveryVolumeCapacityValidationError> {
    let mut nul_terminated_root = [0_u16; VOLUME_GUID_ROOT_UNITS + 1];
    nul_terminated_root[..VOLUME_GUID_ROOT_UNITS].copy_from_slice(normalized_root);
    let mut available_bytes_for_current_user = 0_u64;
    // SAFETY: the exact retained handle-derived volume-GUID root is copied into
    // a fixed live NUL-terminated buffer. Only the caller-available result is
    // requested; total-capacity and total-free outputs are intentionally null.
    if unsafe {
        GetDiskFreeSpaceExW(
            nul_terminated_root.as_ptr(),
            &raw mut available_bytes_for_current_user,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(RecoveryVolumeCapacityValidationError::CapacityObservationUnavailable);
    }
    Ok(available_bytes_for_current_user)
}

fn validate_capacity_observations(
    required: &RecoverySetRequiredBytes,
    mut revalidate: impl FnMut() -> Result<(), RecoveryVolumeCapacityValidationError>,
    mut observe: impl FnMut(CapacityTarget) -> Result<u64, RecoveryVolumeCapacityValidationError>,
) -> Result<(), RecoveryVolumeCapacityValidationError> {
    revalidate()?;
    let first_available = observe(CapacityTarget::First)?;
    if !required.is_satisfied_by(first_available) {
        return Err(RecoveryVolumeCapacityValidationError::InsufficientCapacity);
    }
    let second_available = observe(CapacityTarget::Second)?;
    if !required.is_satisfied_by(second_available) {
        return Err(RecoveryVolumeCapacityValidationError::InsufficientCapacity);
    }
    revalidate()
}

pub(super) fn validate_two_recovery_volume_root_capacities<SourceSizeError>(
    required: Result<RecoverySetRequiredBytes, SourceSizeError>,
    roots: TwoRecoveryVolumeRootsSeparatedFromProductionStorage,
) -> Result<TwoCapacityValidatedRecoveryVolumeRoots, RecoveryVolumeCapacityValidationError> {
    let required =
        required.map_err(|_| RecoveryVolumeCapacityValidationError::SourceSizeUnavailable)?;
    validate_capacity_observations(
        &required,
        || {
            roots.revalidate().map_err(|_| {
                RecoveryVolumeCapacityValidationError::DestinationChangedOrInconsistent
            })
        },
        |target| {
            let normalized_root = match target {
                CapacityTarget::First => &roots.first_initial_root.normalized_root,
                CapacityTarget::Second => &roots.second_initial_root.normalized_root,
            };
            observe_available_bytes_for_current_user(normalized_root)
        },
    )?;
    Ok(TwoCapacityValidatedRecoveryVolumeRoots { roots })
}

pub(crate) fn validate_recovery_volume_capacities_for_lifecycle<SourceSizeError>(
    required: Result<RecoverySetRequiredBytes, SourceSizeError>,
    roots: TwoRecoveryVolumeRootsSeparatedFromProductionStorage,
) -> Result<TwoCapacityValidatedRecoveryVolumeRoots, ()> {
    validate_two_recovery_volume_root_capacities(required, roots).map_err(|_| ())
}

pub(crate) fn create_recovery_set_directories_for_lifecycle(
    roots: TwoCapacityValidatedRecoveryVolumeRoots,
) -> Result<TwoRetainedRecoverySetDirectories, ()> {
    retained_recovery_set_directories::create_and_retain_recovery_set_directories(roots)
        .map(|directories| TwoRetainedRecoverySetDirectories {
            _directories: directories,
        })
        .map_err(|failure| {
            drop(failure);
        })
}

pub(crate) fn publish_first_recovery_database_artifact(
    source: crate::application_lifecycle::RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    destinations: TwoRetainedRecoverySetDirectories,
) -> FirstRecoveryDatabasePublicationOutcome {
    retained_recovery_set_directories::publish_first_recovery_database_artifact(
        source,
        destinations._directories,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        fs,
        mem::needs_drop,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    impl NativeSelectedRecoveryVolumeRoot {
        fn from_test_path(selected: PathBuf) -> Self {
            Self { selected }
        }
    }

    fn valid_root() -> [u16; VOLUME_GUID_ROOT_UNITS] {
        ascii_units(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\")
            .try_into()
            .unwrap()
    }

    #[test]
    fn directory_lifecycle_facade_only_delegates_and_discards_failure_ownership() {
        const SOURCE: &str = include_str!("windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let facade = SOURCE
            .split_once("pub(crate) fn create_recovery_set_directories_for_lifecycle")
            .unwrap()
            .1
            .split_once("#[cfg(test)]")
            .unwrap()
            .0;
        assert!(facade.contains("roots: TwoCapacityValidatedRecoveryVolumeRoots"));
        assert!(facade.contains("Result<TwoRetainedRecoverySetDirectories, ()>"));
        assert!(facade.contains(
            "retained_recovery_set_directories::create_and_retain_recovery_set_directories(roots)"
        ));
        assert!(facade.contains("drop(failure)"));
        for forbidden in [
            "church-app-recovery-set",
            "CreateDirectoryW",
            "remove_",
            "delete",
            "cleanup",
            "retry",
            "path(",
            "handle(",
            "identity(",
        ] {
            assert!(
                !facade.contains(forbidden),
                "forbidden facade authority: {forbidden}"
            );
        }
    }

    fn valid_facts() -> RootFacts {
        RootFacts {
            identity: RootIdentity {
                volume_serial: 7,
                file_id: [0x2a; 16],
            },
            disk_entry: true,
            directory: true,
            delete_pending: false,
            attributes: FILE_ATTRIBUTE_DIRECTORY,
            reparse_tag: 0,
            normalized_root: valid_root(),
        }
    }

    fn required_for_test(bytes: u64) -> RecoverySetRequiredBytes {
        RecoverySetRequiredBytes::from_test_bytes(bytes)
    }

    #[test]
    fn capacity_comparison_accepts_exact_equality_and_rejects_one_byte_below() {
        let required = required_for_test(1_000);
        assert!(required.is_satisfied_by(1_000));
        assert!(!required.is_satisfied_by(999));
    }

    #[test]
    fn each_root_must_independently_have_sufficient_capacity() {
        for (available, expected_observations) in [([999, 2_000], 1), ([2_000, 999], 2)] {
            let observations = Cell::new(0_usize);
            let result = validate_capacity_observations(
                &required_for_test(1_000),
                || Ok(()),
                |target| {
                    observations.set(observations.get() + 1);
                    Ok(match target {
                        CapacityTarget::First => available[0],
                        CapacityTarget::Second => available[1],
                    })
                },
            );
            assert_eq!(
                result,
                Err(RecoveryVolumeCapacityValidationError::InsufficientCapacity)
            );
            assert_eq!(observations.get(), expected_observations);
        }
    }

    #[test]
    fn unavailable_capacity_observation_fails_closed() {
        let result = validate_capacity_observations(
            &required_for_test(1_000),
            || Ok(()),
            |_| Err(RecoveryVolumeCapacityValidationError::CapacityObservationUnavailable),
        );
        assert_eq!(
            result,
            Err(RecoveryVolumeCapacityValidationError::CapacityObservationUnavailable)
        );
    }

    #[test]
    fn pre_capacity_revalidation_failure_prevents_observation() {
        let observations = Cell::new(0_usize);
        let result = validate_capacity_observations(
            &required_for_test(1_000),
            || Err(RecoveryVolumeCapacityValidationError::DestinationChangedOrInconsistent),
            |_| {
                observations.set(observations.get() + 1);
                Ok(2_000)
            },
        );
        assert_eq!(
            result,
            Err(RecoveryVolumeCapacityValidationError::DestinationChangedOrInconsistent)
        );
        assert_eq!(observations.get(), 0);
    }

    #[test]
    fn post_capacity_revalidation_failure_rejects_two_sufficient_observations() {
        let revalidations = Cell::new(0_usize);
        let observations = Cell::new(0_usize);
        let result = validate_capacity_observations(
            &required_for_test(1_000),
            || {
                let call = revalidations.get();
                revalidations.set(call + 1);
                if call == 0 {
                    Ok(())
                } else {
                    Err(RecoveryVolumeCapacityValidationError::DestinationChangedOrInconsistent)
                }
            },
            |_| {
                observations.set(observations.get() + 1);
                Ok(1_000)
            },
        );
        assert_eq!(
            result,
            Err(RecoveryVolumeCapacityValidationError::DestinationChangedOrInconsistent)
        );
        assert_eq!(revalidations.get(), 2);
        assert_eq!(observations.get(), 2);
    }

    #[test]
    fn both_sufficient_roots_succeed_between_complete_revalidations() {
        let events = RefCell::new(Vec::new());
        validate_capacity_observations(
            &required_for_test(1_000),
            || {
                events.borrow_mut().push("revalidate");
                Ok(())
            },
            |target| {
                events.borrow_mut().push(match target {
                    CapacityTarget::First => "first-capacity",
                    CapacityTarget::Second => "second-capacity",
                });
                Ok(1_000)
            },
        )
        .unwrap();
        assert_eq!(
            events.into_inner(),
            [
                "revalidate",
                "first-capacity",
                "second-capacity",
                "revalidate"
            ]
        );
    }

    #[test]
    fn capacity_owner_and_errors_are_opaque_and_redacted() {
        assert!(needs_drop::<TwoCapacityValidatedRecoveryVolumeRoots>());
        for (error, expected) in [
            (
                RecoveryVolumeCapacityValidationError::SourceSizeUnavailable,
                "SourceSizeUnavailable",
            ),
            (
                RecoveryVolumeCapacityValidationError::CapacityObservationUnavailable,
                "CapacityObservationUnavailable",
            ),
            (
                RecoveryVolumeCapacityValidationError::InsufficientCapacity,
                "InsufficientCapacity",
            ),
            (
                RecoveryVolumeCapacityValidationError::DestinationChangedOrInconsistent,
                "DestinationChangedOrInconsistent",
            ),
        ] {
            assert_eq!(format!("{error:?}"), expected);
        }

        let source = include_str!("windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        let owner = production
            .split_once("struct TwoCapacityValidatedRecoveryVolumeRoots {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(owner.contains("roots: TwoRecoveryVolumeRootsSeparatedFromProductionStorage"));
        for forbidden in [
            "pub ",
            "available",
            "required",
            "path",
            "handle",
            "guid",
            "device",
        ] {
            assert!(!owner.to_ascii_lowercase().contains(forbidden));
        }
        let debug = production
            .split_once("impl fmt::Debug for TwoCapacityValidatedRecoveryVolumeRoots")
            .unwrap()
            .1
            .split_once("#[derive(Clone, Copy, Eq, PartialEq)]")
            .unwrap()
            .0;
        assert!(debug.contains("([REDACTED])"));
    }

    #[test]
    fn capacity_transition_has_no_getters_or_mutation_publication_surface() {
        let source = include_str!("windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let production = source.split_once("#[cfg(test)]\nmod tests").unwrap().0;
        let capacity = production
            .split_once("pub(super) fn validate_two_recovery_volume_root_capacities")
            .unwrap()
            .1
            .split_once("pub(crate) fn validate_recovery_volume_capacities_for_lifecycle")
            .unwrap()
            .0;
        let facade = production
            .split_once("pub(crate) fn validate_recovery_volume_capacities_for_lifecycle")
            .unwrap()
            .1
            .split_once("pub(crate) fn create_recovery_set_directories_for_lifecycle")
            .unwrap()
            .0;
        let lifecycle = include_str!("application_lifecycle.rs");
        let crate_root = include_str!("lib.rs");
        assert!(!capacity.contains("application_lifecycle"));
        assert!(!facade.contains("application_lifecycle"));
        assert!(facade.contains("validate_two_recovery_volume_root_capacities(required, roots)"));
        assert!(production.contains(
            "use crate::production_database_migration_recovery_envelope::RecoverySetRequiredBytes;"
        ));
        assert!(lifecycle.contains(
            "pub(crate) use production_database_migration_confirmation::production_database_migration_backup_stage::RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup;"
        ));
        assert!(
            !crate_root.contains("RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup")
        );
        for forbidden in [
            "fn available_bytes(",
            "fn required_bytes(",
            "fn path(",
            "fn handle(",
            "fn volume_guid(",
            "fn device_number(",
            "CreateDirectoryW",
            "WriteFile",
            "church-app-recovery-set",
            "tauri::command",
            "Serialize",
            "Deserialize",
            "fn source_owner(",
            "fn custody_owner(",
        ] {
            assert!(
                !capacity.contains(forbidden) && !facade.contains(forbidden),
                "unexpected surface: {forbidden}"
            );
        }
        let transition = production
            .split_once("fn validate_two_recovery_volume_root_capacities")
            .unwrap()
            .1;
        assert!(transition.contains("Result<RecoverySetRequiredBytes, SourceSizeError>"));
        assert!(transition.contains("SourceSizeUnavailable"));
        assert!(transition.contains("first_initial_root.normalized_root"));
        assert!(transition.contains("second_initial_root.normalized_root"));

        let facade = production
            .split_once("fn validate_recovery_volume_capacities_for_lifecycle")
            .unwrap()
            .1;
        assert!(facade.contains("validate_two_recovery_volume_root_capacities(required, roots)"));
        for forbidden in [
            "normalized_root",
            "available_bytes",
            "is_satisfied_by",
            "GetDiskFreeSpaceExW",
            "CreateDirectoryW",
        ] {
            assert!(!facade.contains(forbidden));
        }
    }

    #[test]
    fn exact_volume_root_is_accepted_but_child_unc_and_malformed_forms_are_rejected() {
        let root = valid_root();
        assert_eq!(parse_exact_volume_root(&root), Ok(root));
        for rejected in [
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\child",
            r"\\server\share\",
            r"\\?\UNC\server\share\",
            r"\\?\Volume{g1234567-89ab-cdef-0123-456789abcdef}\",
            r"C:\",
        ] {
            assert_eq!(
                parse_exact_volume_root(&ascii_units(rejected)),
                Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot)
            );
        }
    }

    #[test]
    fn non_directory_reparse_and_delete_pending_facts_are_rejected() {
        let mut non_directory = valid_facts();
        non_directory.directory = false;
        assert_eq!(
            validate_root_facts(&non_directory),
            Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot)
        );

        for (attributes, tag) in [
            (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT, 0),
            (FILE_ATTRIBUTE_DIRECTORY, 0xa000_0003),
        ] {
            let mut reparse = valid_facts();
            reparse.attributes = attributes;
            reparse.reparse_tag = tag;
            assert_eq!(
                validate_root_facts(&reparse),
                Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot)
            );
        }

        let mut delete_pending = valid_facts();
        delete_pending.delete_pending = true;
        assert_eq!(
            validate_root_facts(&delete_pending),
            Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot)
        );
    }

    #[test]
    fn changed_full_file_id_or_normalized_root_is_rejected_on_revalidation() {
        let initial = valid_facts();
        let mut changed_identity = initial.clone();
        changed_identity.identity.file_id[15] ^= 0xff;
        assert_eq!(
            require_same_root(&initial, &changed_identity),
            Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot)
        );

        let mut changed_root = initial.clone();
        changed_root.normalized_root =
            ascii_units(r"\\?\Volume{fedcba98-7654-3210-fedc-ba9876543210}\")
                .try_into()
                .unwrap();
        assert_eq!(
            require_same_root(&initial, &changed_root),
            Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot)
        );
    }

    #[test]
    fn only_ntfs_is_accepted_and_unavailable_observation_fails_closed() {
        assert_eq!(require_ntfs_name(Some(&ascii_units("NTFS"))), Ok(()));
        assert_eq!(require_ntfs_name(Some(&ascii_units("ntfs"))), Ok(()));
        for unsupported in ["exFAT", "FAT32", "ReFS", "UNKNOWN"] {
            assert_eq!(
                require_ntfs_name(Some(&ascii_units(unsupported))),
                Err(RetainedEligibleNtfsRecoveryVolumeRootError::UnsupportedFilesystem)
            );
        }
        assert_eq!(
            require_ntfs_name(None),
            Err(RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable)
        );
    }

    #[test]
    fn eligibility_failure_or_change_fails_closed() {
        assert_eq!(require_eligibility::<(), ()>(Ok(())), Ok(()));
        assert_eq!(
            require_eligibility::<(), ()>(Err(())),
            Err(RetainedEligibleNtfsRecoveryVolumeRootError::EligibilityUnavailableOrChanged)
        );
    }

    #[test]
    fn root_separation_error_mapping_is_coarse_and_preserves_same_device_rejection() {
        for (input, expected) in [
            (
                PhysicalDeviceSeparationError::ProductionStorageObservationUnavailable,
                RecoveryVolumeRootProductionSeparationError::ProductionObservationUnavailable,
            ),
            (
                PhysicalDeviceSeparationError::RecoveryDeviceObservationUnavailable,
                RecoveryVolumeRootProductionSeparationError::RecoveryRootUnavailableOrChanged,
            ),
            (
                PhysicalDeviceSeparationError::SamePhysicalDevice,
                RecoveryVolumeRootProductionSeparationError::SamePhysicalDevice,
            ),
            (
                PhysicalDeviceSeparationError::TopologyChangedOrInconsistent,
                RecoveryVolumeRootProductionSeparationError::TopologyChangedOrInconsistent,
            ),
        ] {
            assert_eq!(map_separation_error(input), expected);
        }
    }

    #[test]
    fn two_root_error_mapping_is_coarse_and_preserves_required_categories() {
        for (input, expected) in [
            (
                RecoveryVolumeRootProductionSeparationError::ProductionObservationUnavailable,
                TwoRecoveryVolumeRootsSeparationError::ProductionObservationUnavailable,
            ),
            (
                RecoveryVolumeRootProductionSeparationError::RecoveryRootUnavailableOrChanged,
                TwoRecoveryVolumeRootsSeparationError::FirstRootUnavailableOrChanged,
            ),
            (
                RecoveryVolumeRootProductionSeparationError::SamePhysicalDevice,
                TwoRecoveryVolumeRootsSeparationError::SamePhysicalDevice,
            ),
            (
                RecoveryVolumeRootProductionSeparationError::TopologyChangedOrInconsistent,
                TwoRecoveryVolumeRootsSeparationError::TopologyChangedOrInconsistent,
            ),
        ] {
            assert_eq!(map_two_root_first_revalidation_error(input), expected);
        }
        for (input, expected) in [
            (
                PhysicalDeviceSeparationError::ProductionStorageObservationUnavailable,
                TwoRecoveryVolumeRootsSeparationError::ProductionObservationUnavailable,
            ),
            (
                PhysicalDeviceSeparationError::RecoveryDeviceObservationUnavailable,
                TwoRecoveryVolumeRootsSeparationError::TopologyChangedOrInconsistent,
            ),
            (
                PhysicalDeviceSeparationError::SamePhysicalDevice,
                TwoRecoveryVolumeRootsSeparationError::SamePhysicalDevice,
            ),
            (
                PhysicalDeviceSeparationError::TopologyChangedOrInconsistent,
                TwoRecoveryVolumeRootsSeparationError::TopologyChangedOrInconsistent,
            ),
        ] {
            assert_eq!(map_two_root_separation_error(input), expected);
        }
    }

    #[test]
    fn two_root_owner_retains_both_exact_roots_and_generic_separation_ownership() {
        assert!(needs_drop::<
            TwoRecoveryVolumeRootsSeparatedFromProductionStorage,
        >());
        let source = include_str!("windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        let owner = production
            .split_once("struct TwoRecoveryVolumeRootsSeparatedFromProductionStorage {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        for retained in [
            "first_selected_root: File",
            "first_initial_root: RootFacts",
            "second_selected_root: File",
            "second_initial_root: RootFacts",
            "separation: TwoRecoveryDevicesSeparatedFromProductionStorage",
        ] {
            assert!(owner.contains(retained));
        }
        for forbidden in ["pub ", "pub(crate)", "Serialize", "Deserialize"] {
            assert!(!owner.contains(forbidden));
        }
    }

    #[test]
    fn two_root_composition_revalidates_both_inputs_then_reuses_generic_transition() {
        let source = include_str!("windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        let composition = production
            .split_once("fn separate_two_recovery_volume_roots_from_production_storage(")
            .unwrap()
            .1
            .split_once("impl TwoRecoveryVolumeRootsSeparatedFromProductionStorage")
            .unwrap()
            .0;
        let first_revalidation = composition
            .find("first_root\n        .revalidate()")
            .unwrap();
        let second_revalidation = composition
            .find("second_root\n        .revalidate()")
            .unwrap();
        let generic_transition = composition
            .find(".separate_second_recovery_device(second_eligible_device)")
            .unwrap();
        assert!(first_revalidation < second_revalidation);
        assert!(second_revalidation < generic_transition);
        assert!(!composition.contains("same_accepted_physical_device"));
        assert!(!composition.contains("accepted_disk_number"));
    }

    #[test]
    fn two_root_revalidation_checks_both_roots_before_all_device_distinctions() {
        let source = include_str!("windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        let revalidation = production
            .split_once("impl TwoRecoveryVolumeRootsSeparatedFromProductionStorage")
            .unwrap()
            .1;
        let first_root = revalidation.find("&self.first_selected_root").unwrap();
        let second_root = revalidation.find("&self.second_selected_root").unwrap();
        let generic_revalidation = revalidation
            .find("self.separation\n            .revalidate()")
            .unwrap();
        assert!(first_root < second_root);
        assert!(second_root < generic_revalidation);

        let eligibility = include_str!("windows_external_recovery_device_eligibility.rs");
        let generic_revalidation = eligibility
            .split_once("impl TwoRecoveryDevicesSeparatedFromProductionStorage")
            .unwrap()
            .1
            .split_once("#[cfg(test)]")
            .unwrap()
            .0;
        for required in [
            "self._production_topology",
            "self._first_recovery_device",
            "self._second_recovery_device",
            "same_accepted_physical_device(&self._first_recovery_device.topology)",
            "same_accepted_physical_device(&self._second_recovery_device.topology)",
        ] {
            assert!(generic_revalidation.contains(required));
        }
    }

    #[test]
    fn two_root_surface_is_redacted_and_exposes_no_identity_or_mutation_api() {
        for (error, expected) in [
            (
                TwoRecoveryVolumeRootsSeparationError::FirstRootUnavailableOrChanged,
                "FirstRootUnavailableOrChanged",
            ),
            (
                TwoRecoveryVolumeRootsSeparationError::SecondRootUnavailableOrChanged,
                "SecondRootUnavailableOrChanged",
            ),
            (
                TwoRecoveryVolumeRootsSeparationError::ProductionObservationUnavailable,
                "ProductionObservationUnavailable",
            ),
            (
                TwoRecoveryVolumeRootsSeparationError::SamePhysicalDevice,
                "SamePhysicalDevice",
            ),
            (
                TwoRecoveryVolumeRootsSeparationError::TopologyChangedOrInconsistent,
                "TopologyChangedOrInconsistent",
            ),
        ] {
            assert_eq!(format!("{error:?}"), expected);
        }

        let source = include_str!("windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        let debug = production
            .split_once("impl fmt::Debug for TwoRecoveryVolumeRootsSeparatedFromProductionStorage")
            .unwrap()
            .1
            .split_once("#[derive(Clone, Copy, Eq, PartialEq)]")
            .unwrap()
            .0;
        assert!(debug.contains("([REDACTED])"));
        for forbidden in [
            "first_selected_root",
            "second_selected_root",
            "first_initial_root",
            "second_initial_root",
            "separation:",
        ] {
            assert!(!debug.contains(forbidden));
        }
        for forbidden in [
            "fn eligible_device(",
            "fn topology(",
            "fn retained_root(",
            "fn first_root(",
            "fn second_root(",
            "fn handle(",
            "fn path(",
            "fn disk_number(",
            "fn filesystem(",
            "fn capacity(",
            "Serialize",
            "Deserialize",
            "tauri",
            "CreateDirectoryW",
            "WriteFile",
            "church-app-recovery-set",
        ] {
            assert!(!production.contains(forbidden));
        }
    }

    #[test]
    fn production_separated_root_owner_retains_root_and_existing_separation_ownership() {
        assert!(needs_drop::<RecoveryVolumeRootSeparatedFromProductionStorage>());
        let source = include_str!("windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        let owner = production
            .split_once("struct RecoveryVolumeRootSeparatedFromProductionStorage {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert!(owner.contains("selected_root: File"));
        assert!(owner.contains("initial_root: RootFacts"));
        assert!(owner.contains("separation: RecoveryDeviceSeparatedFromProductionStorage"));
        for forbidden in ["pub ", "pub(crate)", "Serialize", "Deserialize"] {
            assert!(!owner.contains(forbidden));
        }
    }

    #[test]
    fn composition_and_revalidation_preserve_locked_order_and_reuse_separation() {
        let source = include_str!("windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        let composition = production
            .split_once("fn separate_recovery_volume_root_from_production_storage(")
            .unwrap()
            .1
            .split_once("impl RecoveryVolumeRootSeparatedFromProductionStorage")
            .unwrap()
            .0;
        let production_revalidation = composition
            .find("production_topology\n        .revalidate()")
            .unwrap();
        let root_revalidation = composition
            .find("recovery_root.revalidate().map_err(")
            .unwrap();
        let comparison = composition
            .find("separate_recovery_device_from_production_storage(")
            .unwrap();
        assert!(production_revalidation < root_revalidation);
        assert!(root_revalidation < comparison);
        assert!(!composition.contains("same_accepted_physical_device"));

        let revalidation = production
            .split_once("impl RecoveryVolumeRootSeparatedFromProductionStorage")
            .unwrap()
            .1;
        let production_revalidation = revalidation
            .find("self.separation\n            .revalidate_production_topology()")
            .unwrap();
        let root_revalidation = revalidation
            .find("revalidate_root_identity_and_filesystem(")
            .unwrap();
        let separation_revalidation = revalidation.find("self.separation.revalidate()").unwrap();
        assert!(production_revalidation < root_revalidation);
        assert!(root_revalidation < separation_revalidation);
    }

    #[test]
    fn separated_root_surface_is_redacted_and_exposes_no_identity_or_mutation_api() {
        for (error, expected) in [
            (
                RecoveryVolumeRootProductionSeparationError::ProductionObservationUnavailable,
                "ProductionObservationUnavailable",
            ),
            (
                RecoveryVolumeRootProductionSeparationError::RecoveryRootUnavailableOrChanged,
                "RecoveryRootUnavailableOrChanged",
            ),
            (
                RecoveryVolumeRootProductionSeparationError::SamePhysicalDevice,
                "SamePhysicalDevice",
            ),
            (
                RecoveryVolumeRootProductionSeparationError::TopologyChangedOrInconsistent,
                "TopologyChangedOrInconsistent",
            ),
        ] {
            assert_eq!(format!("{error:?}"), expected);
        }

        let source = include_str!("windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        let debug = production
            .split_once("impl fmt::Debug for RecoveryVolumeRootSeparatedFromProductionStorage")
            .unwrap()
            .1
            .split_once("#[derive(Clone, Copy, Eq, PartialEq)]")
            .unwrap()
            .0;
        assert!(debug.contains("([REDACTED])"));
        for forbidden in ["selected_root", "initial_root", "separation:"] {
            assert!(!debug.contains(forbidden));
        }
        for forbidden in [
            "fn eligible_device(",
            "fn topology(",
            "fn retained_root(",
            "fn handle(",
            "fn path(",
            "fn disk_number(",
            "Serialize",
            "Deserialize",
            "tauri",
            "CreateDirectoryW",
            "WriteFile",
            "church-app-recovery-set",
        ] {
            assert!(!production.contains(forbidden));
        }
        assert!(!production.contains("same_accepted_physical_device"));
        assert!(!production.contains("IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS"));
        assert!(!production.contains("IOCTL_STORAGE_GET_DEVICE_NUMBER"));
    }

    #[test]
    fn errors_and_owners_are_redacted() {
        for (error, expected) in [
            (
                RetainedEligibleNtfsRecoveryVolumeRootError::RootObservationUnavailable,
                "RootObservationUnavailable",
            ),
            (
                RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot,
                "InvalidOrUnsupportedRoot",
            ),
            (
                RetainedEligibleNtfsRecoveryVolumeRootError::UnsupportedFilesystem,
                "UnsupportedFilesystem",
            ),
            (
                RetainedEligibleNtfsRecoveryVolumeRootError::EligibilityUnavailableOrChanged,
                "EligibilityUnavailableOrChanged",
            ),
        ] {
            assert_eq!(format!("{error:?}"), expected);
        }
        assert_eq!(
            format!(
                "{:?}",
                NativeSelectedRecoveryVolumeRoot::from_test_path(PathBuf::from(
                    r"X:\sensitive-selection"
                ))
            ),
            "NativeSelectedRecoveryVolumeRoot([REDACTED])"
        );

        let source = include_str!("windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let owner_debug = source
            .split_once("impl fmt::Debug for RetainedEligibleNtfsRecoveryVolumeRoot")
            .unwrap()
            .1
            .split_once("#[derive(Clone, Copy, Eq, PartialEq)]")
            .unwrap()
            .0;
        assert!(owner_debug.contains("([REDACTED])"));
        for forbidden in ["selected_root", "initial_root", "eligible_device"] {
            assert!(!owner_debug.contains(forbidden));
        }
    }

    #[test]
    fn temporary_child_directory_is_rejected_without_weakening_exact_root_policy() {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "church-app-retained-recovery-root-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("unique exact test directory should be created");
        let result = retain_eligible_ntfs_recovery_volume_root(
            NativeSelectedRecoveryVolumeRoot::from_test_path(root.clone()),
        );
        assert!(matches!(
            result,
            Err(RetainedEligibleNtfsRecoveryVolumeRootError::InvalidOrUnsupportedRoot)
        ));
        fs::remove_dir(&root).expect("exact test directory should be removed");
    }

    #[test]
    fn source_boundary_is_private_non_serializable_and_reuses_existing_proofs() {
        let source = include_str!("windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let production = source.split_once("#[cfg(test)]\nmod tests").unwrap().0;
        let primitive = production
            .split_once("pub(super) struct RetainedEligibleNtfsRecoveryVolumeRoot")
            .unwrap()
            .1
            .split_once("pub(crate) fn retain_and_separate_first_recovery_volume")
            .unwrap()
            .0;
        let eligibility = include_str!("windows_external_recovery_device_eligibility.rs");
        let topology = include_str!("windows_retained_volume_topology.rs");

        assert!(production.contains("selection: NativeSelectedRecoveryVolumeRoot"));
        assert!(production.contains("observe_retained_volume_single_physical_device("));
        assert!(production.contains("observe_retained_external_disconnectable_recovery_device("));
        assert!(production.contains("self.eligible_device.revalidate()"));
        assert!(
            eligibility.contains(
                "pub(super) fn observe_retained_external_disconnectable_recovery_device("
            )
        );
        assert!(
            topology
                .contains("#[path = \"windows_retained_eligible_ntfs_recovery_volume_root.rs\"]")
        );
        for forbidden in [
            "pub fn ",
            "Serialize",
            "Deserialize",
            "serde",
            "tauri",
            "CreateDirectoryW",
            "WriteFile",
            "remove_dir",
            "read_dir",
            "IFileOpenDialog",
            "SHBrowseForFolderW",
            "PhysicalDrive",
        ] {
            assert!(
                !primitive.contains(forbidden),
                "unexpected production surface: {forbidden}"
            );
        }
        for forbidden_getter in [
            "fn path(",
            "fn handle(",
            "fn filesystem(",
            "fn disk_number(",
            "fn topology(",
            "fn device(",
        ] {
            assert!(!production.contains(forbidden_getter));
        }
        assert!(!production.contains("IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS"));
        assert!(!production.contains("IOCTL_STORAGE_GET_DEVICE_NUMBER"));
        assert!(!production.contains("IOCTL_STORAGE_QUERY_PROPERTY"));
        assert!(!production.contains("IOCTL_STORAGE_GET_HOTPLUG_INFO"));
        for approved in [
            "pub(crate) struct NativeSelectedRecoveryVolumeRoot",
            "pub(crate) struct RecoveryVolumeRootSeparatedFromProductionStorage",
            "pub(crate) struct TwoRecoveryVolumeRootsSeparatedFromProductionStorage",
            "pub(crate) struct TwoCapacityValidatedRecoveryVolumeRoots",
            "pub(crate) fn retain_and_separate_first_recovery_volume",
            "pub(crate) fn retain_and_separate_second_recovery_volume",
            "pub(crate) fn validate_recovery_volume_capacities_for_lifecycle",
            "pub(crate) fn create_recovery_set_directories_for_lifecycle",
            "pub(crate) fn publish_first_recovery_database_artifact",
        ] {
            assert!(
                production.contains(approved),
                "missing approved facade: {approved}"
            );
        }
    }
}
