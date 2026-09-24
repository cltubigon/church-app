use std::{
    ffi::c_void,
    fmt,
    fs::File,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
};

use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_NAME_NORMALIZED, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GETFINALPATHNAMEBYHANDLE_FLAGS, GetFinalPathNameByHandleW,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING, VOLUME_NAME_GUID,
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{
            DISK_EXTENT, IOCTL_STORAGE_GET_DEVICE_NUMBER, STORAGE_DEVICE_NUMBER,
            VOLUME_DISK_EXTENTS,
        },
    },
};

#[path = "windows_external_recovery_device_eligibility.rs"]
mod windows_external_recovery_device_eligibility;
#[path = "windows_retained_eligible_ntfs_recovery_volume_root.rs"]
mod windows_retained_eligible_ntfs_recovery_volume_root;

pub(crate) use windows_retained_eligible_ntfs_recovery_volume_root::{
    NativeRecoveryVolumeSelectionOutcome, RecoveryVolumeRootSeparatedFromProductionStorage,
    retain_and_separate_first_recovery_volume, select_native_recovery_volume_root,
};

const FINAL_PATH_FLAGS: GETFINALPATHNAMEBYHANDLE_FLAGS = FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;
const MAXIMUM_FINAL_PATH_UNITS: usize = 32_767;
const VOLUME_GUID_ROOT_UNITS: usize = 49;
const MAXIMUM_EXTENT_BUFFER_LENGTH: usize = 65_536;
const EXTENT_COUNT_OFFSET: usize = offset_of!(VOLUME_DISK_EXTENTS, NumberOfDiskExtents);
const EXTENTS_OFFSET: usize = offset_of!(VOLUME_DISK_EXTENTS, Extents);
const DISK_NUMBER_OFFSET: usize = offset_of!(DISK_EXTENT, DiskNumber);
const STARTING_OFFSET_OFFSET: usize = offset_of!(DISK_EXTENT, StartingOffset);
const EXTENT_LENGTH_OFFSET: usize = offset_of!(DISK_EXTENT, ExtentLength);

const _: () = {
    assert!(EXTENT_COUNT_OFFSET == 0);
    assert!(EXTENTS_OFFSET == 8);
    assert!(size_of::<DISK_EXTENT>() == 24);
    assert!(DISK_NUMBER_OFFSET == 0);
    assert!(STARTING_OFFSET_OFFSET == 8);
    assert!(EXTENT_LENGTH_OFFSET == 16);
    assert!(size_of::<STORAGE_DEVICE_NUMBER>() == 12);
    assert!(MAXIMUM_EXTENT_BUFFER_LENGTH <= u32::MAX as usize);
};

pub(crate) struct RetainedVolumeSinglePhysicalDeviceObservation {
    retained_source: File,
    retained_volume: OwnedHandle,
    accepted_volume_root: [u16; VOLUME_GUID_ROOT_UNITS],
    accepted_disk_number: u32,
}

impl fmt::Debug for RetainedVolumeSinglePhysicalDeviceObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedVolumeSinglePhysicalDeviceObservation([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RetainedVolumeTopologyError {
    VolumeObservationUnavailable,
    MalformedOrUnsupportedTopology,
    MultiplePhysicalDisks,
    TopologyChangedOrInconsistent,
}

impl fmt::Debug for RetainedVolumeTopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::VolumeObservationUnavailable => "VolumeObservationUnavailable",
            Self::MalformedOrUnsupportedTopology => "MalformedOrUnsupportedTopology",
            Self::MultiplePhysicalDisks => "MultiplePhysicalDisks",
            Self::TopologyChangedOrInconsistent => "TopologyChangedOrInconsistent",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SingleDiskNumber(u32);

impl fmt::Debug for SingleDiskNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SingleDiskNumber([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExtentParseError {
    MalformedOrUnsupported,
    ZeroExtents,
    MultiplePhysicalDisks,
}

fn checked_field_end(offset: usize, width: usize) -> Option<usize> {
    offset.checked_add(width)
}

fn read_u32(bytes: &[u8], returned_bytes: usize, offset: usize) -> Option<u32> {
    let end = checked_field_end(offset, size_of::<u32>())?;
    if end > returned_bytes || end > bytes.len() {
        return None;
    }
    Some(u32::from_le_bytes(bytes[offset..end].try_into().ok()?))
}

fn read_i64(bytes: &[u8], returned_bytes: usize, offset: usize) -> Option<i64> {
    let end = checked_field_end(offset, size_of::<i64>())?;
    if end > returned_bytes || end > bytes.len() {
        return None;
    }
    Some(i64::from_le_bytes(bytes[offset..end].try_into().ok()?))
}

fn expected_extent_bytes_for_layout(
    extent_offset: usize,
    extent_size: usize,
    count: usize,
) -> Option<usize> {
    extent_size.checked_mul(count)?.checked_add(extent_offset)
}

fn expected_extent_bytes(count: u32) -> Option<usize> {
    expected_extent_bytes_for_layout(
        EXTENTS_OFFSET,
        size_of::<DISK_EXTENT>(),
        usize::try_from(count).ok()?,
    )
}

fn parse_complete_disk_extents(
    bytes: &[u8],
    returned_bytes: usize,
) -> Result<SingleDiskNumber, ExtentParseError> {
    if returned_bytes > bytes.len() || returned_bytes > MAXIMUM_EXTENT_BUFFER_LENGTH {
        return Err(ExtentParseError::MalformedOrUnsupported);
    }
    let count = read_u32(bytes, returned_bytes, EXTENT_COUNT_OFFSET)
        .ok_or(ExtentParseError::MalformedOrUnsupported)?;
    if count == 0 {
        return Err(ExtentParseError::ZeroExtents);
    }
    let expected = expected_extent_bytes(count).ok_or(ExtentParseError::MalformedOrUnsupported)?;
    if expected != returned_bytes
        || expected > bytes.len()
        || expected > MAXIMUM_EXTENT_BUFFER_LENGTH
    {
        return Err(ExtentParseError::MalformedOrUnsupported);
    }

    let mut first_disk = None;
    let mut multiple_disks = false;
    for index in 0..usize::try_from(count).map_err(|_| ExtentParseError::MalformedOrUnsupported)? {
        let extent_offset = size_of::<DISK_EXTENT>()
            .checked_mul(index)
            .and_then(|offset| EXTENTS_OFFSET.checked_add(offset))
            .ok_or(ExtentParseError::MalformedOrUnsupported)?;
        let disk_number = read_u32(
            bytes,
            returned_bytes,
            extent_offset
                .checked_add(DISK_NUMBER_OFFSET)
                .ok_or(ExtentParseError::MalformedOrUnsupported)?,
        )
        .ok_or(ExtentParseError::MalformedOrUnsupported)?;
        let starting_offset = read_i64(
            bytes,
            returned_bytes,
            extent_offset
                .checked_add(STARTING_OFFSET_OFFSET)
                .ok_or(ExtentParseError::MalformedOrUnsupported)?,
        )
        .ok_or(ExtentParseError::MalformedOrUnsupported)?;
        let extent_length = read_i64(
            bytes,
            returned_bytes,
            extent_offset
                .checked_add(EXTENT_LENGTH_OFFSET)
                .ok_or(ExtentParseError::MalformedOrUnsupported)?,
        )
        .ok_or(ExtentParseError::MalformedOrUnsupported)?;
        if starting_offset < 0
            || extent_length <= 0
            || starting_offset.checked_add(extent_length).is_none()
        {
            return Err(ExtentParseError::MalformedOrUnsupported);
        }
        if let Some(first) = first_disk {
            multiple_disks |= first != disk_number;
        } else {
            first_disk = Some(disk_number);
        }
    }
    if multiple_disks {
        return Err(ExtentParseError::MultiplePhysicalDisks);
    }
    first_disk
        .map(SingleDiskNumber)
        .ok_or(ExtentParseError::ZeroExtents)
}

fn parse_device_number(bytes: &[u8], returned_bytes: usize) -> Option<u32> {
    if returned_bytes != size_of::<STORAGE_DEVICE_NUMBER>() || returned_bytes > bytes.len() {
        return None;
    }
    read_u32(
        bytes,
        returned_bytes,
        offset_of!(STORAGE_DEVICE_NUMBER, DeviceNumber),
    )
}

fn require_matching_device_number(
    disk: SingleDiskNumber,
    device_number: Option<u32>,
) -> Result<(), RetainedVolumeTopologyError> {
    match device_number {
        Some(device_number) if device_number == disk.0 => Ok(()),
        Some(_) => Err(RetainedVolumeTopologyError::TopologyChangedOrInconsistent),
        None => Err(RetainedVolumeTopologyError::VolumeObservationUnavailable),
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
        unit + 32
    } else {
        unit
    }
}

fn query_final_path(file: &File) -> Result<Vec<u16>, RetainedVolumeTopologyError> {
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: this is a documented size query on the caller-retained live handle.
    let required =
        unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, FINAL_PATH_FLAGS) };
    let capacity = usize::try_from(required)
        .map_err(|_| RetainedVolumeTopologyError::VolumeObservationUnavailable)?;
    if capacity == 0 || capacity > MAXIMUM_FINAL_PATH_UNITS {
        return Err(RetainedVolumeTopologyError::VolumeObservationUnavailable);
    }
    let mut output = vec![0_u16; capacity];
    // SAFETY: output is writable for exactly the checked capacity and the handle remains live.
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, output.as_mut_ptr(), required, FINAL_PATH_FLAGS)
    };
    let written = usize::try_from(written)
        .map_err(|_| RetainedVolumeTopologyError::VolumeObservationUnavailable)?;
    if written == 0 || written >= output.len() || written > MAXIMUM_FINAL_PATH_UNITS {
        return Err(RetainedVolumeTopologyError::VolumeObservationUnavailable);
    }
    output.truncate(written);
    Ok(output)
}

fn strict_volume_root(
    file: &File,
) -> Result<[u16; VOLUME_GUID_ROOT_UNITS], RetainedVolumeTopologyError> {
    let path = query_final_path(file)?;
    parse_strict_volume_root(&path)
}

fn parse_strict_volume_root(
    path: &[u16],
) -> Result<[u16; VOLUME_GUID_ROOT_UNITS], RetainedVolumeTopologyError> {
    let prefix = ascii_units(r"\\?\Volume{");
    if path.len() < VOLUME_GUID_ROOT_UNITS
        || path.len() > MAXIMUM_FINAL_PATH_UNITS
        || path.contains(&0)
        || path.get(..prefix.len()) != Some(prefix.as_slice())
        || path[47] != b'}' as u16
        || path[48] != b'\\' as u16
    {
        return Err(RetainedVolumeTopologyError::MalformedOrUnsupportedTopology);
    }
    for (offset, unit) in path[11..47].iter().copied().enumerate() {
        let valid = if matches!(offset, 8 | 13 | 18 | 23) {
            unit == b'-' as u16
        } else {
            is_ascii_hex(unit)
        };
        if !valid {
            return Err(RetainedVolumeTopologyError::MalformedOrUnsupportedTopology);
        }
    }
    path[..VOLUME_GUID_ROOT_UNITS]
        .try_into()
        .map_err(|_| RetainedVolumeTopologyError::MalformedOrUnsupportedTopology)
}

fn same_volume_root(
    left: &[u16; VOLUME_GUID_ROOT_UNITS],
    right: &[u16; VOLUME_GUID_ROOT_UNITS],
) -> bool {
    left.iter()
        .zip(right)
        .all(|(left, right)| fold_ascii(*left) == fold_ascii(*right))
}

fn open_exact_volume(
    root: &[u16; VOLUME_GUID_ROOT_UNITS],
) -> Result<OwnedHandle, RetainedVolumeTopologyError> {
    let mut device_name = root[..VOLUME_GUID_ROOT_UNITS - 1].to_vec();
    device_name.push(0);
    // SAFETY: the device name is derived only from the strict handle-derived
    // volume root, has its trailing separator removed, and is NUL-terminated.
    // The open requests no access, read/write sharing, OPEN_EXISTING, and no flags.
    let raw = unsafe {
        CreateFileW(
            device_name.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut::<c_void>(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(RetainedVolumeTopologyError::VolumeObservationUnavailable);
    }
    // SAFETY: ownership of the fresh successful handle is transferred exactly once.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
}

fn query_single_disk(
    volume: &OwnedHandle,
) -> Result<SingleDiskNumber, RetainedVolumeTopologyError> {
    let mut bytes = vec![0_u8; MAXIMUM_EXTENT_BUFFER_LENGTH];
    let mut returned = 0_u32;
    // SAFETY: the retained volume handle is live, there is no input, and the
    // fixed bounded output allocation is writable for the supplied length.
    let succeeded = unsafe {
        DeviceIoControl(
            volume.as_raw_handle() as HANDLE,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            std::ptr::null(),
            0,
            bytes.as_mut_ptr().cast::<c_void>(),
            MAXIMUM_EXTENT_BUFFER_LENGTH as u32,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(RetainedVolumeTopologyError::VolumeObservationUnavailable);
    }
    match parse_complete_disk_extents(&bytes, returned as usize) {
        Ok(disk) => Ok(disk),
        Err(ExtentParseError::MultiplePhysicalDisks) => {
            Err(RetainedVolumeTopologyError::MultiplePhysicalDisks)
        }
        Err(ExtentParseError::MalformedOrUnsupported | ExtentParseError::ZeroExtents) => {
            Err(RetainedVolumeTopologyError::MalformedOrUnsupportedTopology)
        }
    }
}

fn query_device_number(volume: &OwnedHandle) -> Result<u32, RetainedVolumeTopologyError> {
    let mut bytes = [0_u8; size_of::<STORAGE_DEVICE_NUMBER>()];
    let mut returned = 0_u32;
    // SAFETY: the retained volume handle is live, there is no input, and the
    // exact-size initialized output remains writable for this synchronous call.
    let succeeded = unsafe {
        DeviceIoControl(
            volume.as_raw_handle() as HANDLE,
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            std::ptr::null(),
            0,
            bytes.as_mut_ptr().cast::<c_void>(),
            bytes.len() as u32,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(RetainedVolumeTopologyError::VolumeObservationUnavailable);
    }
    parse_device_number(&bytes, returned as usize)
        .ok_or(RetainedVolumeTopologyError::MalformedOrUnsupportedTopology)
}

fn observe_volume(volume: &OwnedHandle) -> Result<SingleDiskNumber, RetainedVolumeTopologyError> {
    let disk = query_single_disk(volume)?;
    require_matching_device_number(disk, Some(query_device_number(volume)?))?;
    Ok(disk)
}

pub(crate) fn observe_retained_volume_single_physical_device(
    trusted_retained_source: &File,
) -> Result<RetainedVolumeSinglePhysicalDeviceObservation, RetainedVolumeTopologyError> {
    let retained_source = trusted_retained_source
        .try_clone()
        .map_err(|_| RetainedVolumeTopologyError::VolumeObservationUnavailable)?;
    let accepted_volume_root = strict_volume_root(&retained_source)?;
    let retained_volume = open_exact_volume(&accepted_volume_root)?;
    let accepted_disk_number = observe_volume(&retained_volume)?.0;
    let confirmed_root = strict_volume_root(&retained_source)?;
    if !same_volume_root(&accepted_volume_root, &confirmed_root) {
        return Err(RetainedVolumeTopologyError::TopologyChangedOrInconsistent);
    }
    Ok(RetainedVolumeSinglePhysicalDeviceObservation {
        retained_source,
        retained_volume,
        accepted_volume_root,
        accepted_disk_number,
    })
}

impl RetainedVolumeSinglePhysicalDeviceObservation {
    pub(crate) fn revalidate(&self) -> Result<(), RetainedVolumeTopologyError> {
        let current_root = strict_volume_root(&self.retained_source)?;
        if !same_volume_root(&self.accepted_volume_root, &current_root) {
            return Err(RetainedVolumeTopologyError::TopologyChangedOrInconsistent);
        }
        let current_disk = observe_volume(&self.retained_volume).map_err(|error| match error {
            RetainedVolumeTopologyError::VolumeObservationUnavailable => error,
            RetainedVolumeTopologyError::MalformedOrUnsupportedTopology
            | RetainedVolumeTopologyError::MultiplePhysicalDisks
            | RetainedVolumeTopologyError::TopologyChangedOrInconsistent => {
                RetainedVolumeTopologyError::TopologyChangedOrInconsistent
            }
        })?;
        if current_disk.0 != self.accepted_disk_number {
            return Err(RetainedVolumeTopologyError::TopologyChangedOrInconsistent);
        }
        Ok(())
    }

    fn same_accepted_physical_device(&self, other: &Self) -> bool {
        self.accepted_disk_number == other.accepted_disk_number
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::windows::ffi::OsStrExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn raw_extents(extents: &[(u32, i64, i64)]) -> Vec<u8> {
        let length = expected_extent_bytes(extents.len() as u32).unwrap();
        let mut bytes = vec![0_u8; length];
        bytes[..4].copy_from_slice(&(extents.len() as u32).to_le_bytes());
        for (index, (disk, start, length)) in extents.iter().copied().enumerate() {
            let offset = EXTENTS_OFFSET + index * size_of::<DISK_EXTENT>();
            bytes[offset + DISK_NUMBER_OFFSET..offset + DISK_NUMBER_OFFSET + 4]
                .copy_from_slice(&disk.to_le_bytes());
            bytes[offset + STARTING_OFFSET_OFFSET..offset + STARTING_OFFSET_OFFSET + 8]
                .copy_from_slice(&start.to_le_bytes());
            bytes[offset + EXTENT_LENGTH_OFFSET..offset + EXTENT_LENGTH_OFFSET + 8]
                .copy_from_slice(&length.to_le_bytes());
        }
        bytes
    }

    fn device_number_bytes(number: u32) -> [u8; size_of::<STORAGE_DEVICE_NUMBER>()] {
        let mut bytes = [0_u8; size_of::<STORAGE_DEVICE_NUMBER>()];
        let offset = offset_of!(STORAGE_DEVICE_NUMBER, DeviceNumber);
        bytes[offset..offset + 4].copy_from_slice(&number.to_le_bytes());
        bytes
    }

    #[test]
    fn complete_extent_parser_rejects_zero_and_accepts_one_or_same_disk_many() {
        let zero = raw_extents(&[]);
        assert_eq!(
            parse_complete_disk_extents(&zero, zero.len()),
            Err(ExtentParseError::ZeroExtents)
        );

        let one = raw_extents(&[(7, 0, 4096)]);
        assert_eq!(
            parse_complete_disk_extents(&one, one.len()),
            Ok(SingleDiskNumber(7))
        );

        let many = raw_extents(&[(12, 0, 4096), (12, 8192, 2048), (12, 16384, 1024)]);
        assert_eq!(
            parse_complete_disk_extents(&many, many.len()),
            Ok(SingleDiskNumber(12))
        );
    }

    #[test]
    fn complete_extent_parser_inspects_all_extents_and_rejects_multiple_disks() {
        let bytes = raw_extents(&[(3, 0, 4096), (3, 8192, 2048), (9, 16384, 1024)]);
        assert_eq!(
            parse_complete_disk_extents(&bytes, bytes.len()),
            Err(ExtentParseError::MultiplePhysicalDisks)
        );
    }

    #[test]
    fn complete_extent_parser_rejects_truncation_at_every_structural_boundary() {
        let bytes = raw_extents(&[(4, 0, 4096), (4, 8192, 2048)]);
        for returned in 0..bytes.len() {
            assert_eq!(
                parse_complete_disk_extents(&bytes, returned),
                Err(ExtentParseError::MalformedOrUnsupported)
            );
        }
    }

    #[test]
    fn complete_extent_parser_rejects_inconsistent_lengths_and_extreme_counts() {
        let mut bytes = raw_extents(&[(5, 0, 4096)]);
        bytes.push(0);
        assert_eq!(
            parse_complete_disk_extents(&bytes, bytes.len()),
            Err(ExtentParseError::MalformedOrUnsupported)
        );
        assert_eq!(
            parse_complete_disk_extents(&bytes, bytes.len() + 1),
            Err(ExtentParseError::MalformedOrUnsupported)
        );

        let mut extreme = vec![0_u8; EXTENTS_OFFSET];
        extreme[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            parse_complete_disk_extents(&extreme, extreme.len()),
            Err(ExtentParseError::MalformedOrUnsupported)
        );
        assert_eq!(expected_extent_bytes_for_layout(1, usize::MAX, 2), None);
        assert_eq!(expected_extent_bytes_for_layout(usize::MAX, 1, 1), None);
    }

    #[test]
    fn complete_extent_parser_rejects_malformed_extent_values() {
        for extents in [
            vec![(1, -1, 4096)],
            vec![(1, 0, 0)],
            vec![(1, 0, -1)],
            vec![(1, i64::MAX, 1)],
        ] {
            let bytes = raw_extents(&extents);
            assert_eq!(
                parse_complete_disk_extents(&bytes, bytes.len()),
                Err(ExtentParseError::MalformedOrUnsupported)
            );
        }
    }

    #[test]
    fn device_number_parser_and_cross_check_are_exact_and_fail_closed() {
        let bytes = device_number_bytes(21);
        assert_eq!(parse_device_number(&bytes, bytes.len()), Some(21));
        assert_eq!(parse_device_number(&bytes, bytes.len() - 1), None);
        assert_eq!(parse_device_number(&bytes, bytes.len() + 1), None);
        assert_eq!(
            require_matching_device_number(SingleDiskNumber(21), Some(21)),
            Ok(())
        );
        assert_eq!(
            require_matching_device_number(SingleDiskNumber(21), Some(22)),
            Err(RetainedVolumeTopologyError::TopologyChangedOrInconsistent)
        );
        assert_eq!(
            require_matching_device_number(SingleDiskNumber(21), None),
            Err(RetainedVolumeTopologyError::VolumeObservationUnavailable)
        );
    }

    #[test]
    fn strict_volume_root_rejects_non_volume_forms_without_exposing_them() {
        let valid = ascii_units(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\leaf");
        let root = parse_strict_volume_root(&valid).unwrap();
        assert!(same_volume_root(&root, &root));

        for malformed in [
            r"\\server\share\leaf",
            r"\\?\UNC\server\share\leaf",
            r"\\.\C:\leaf",
            r"\\?\Volume{g1234567-89ab-cdef-0123-456789abcdef}\leaf",
        ] {
            let units = ascii_units(malformed);
            assert_eq!(
                parse_strict_volume_root(&units),
                Err(RetainedVolumeTopologyError::MalformedOrUnsupportedTopology)
            );
        }
    }

    #[test]
    fn topology_errors_and_success_proof_debug_are_redacted() {
        for (error, expected) in [
            (
                RetainedVolumeTopologyError::VolumeObservationUnavailable,
                "VolumeObservationUnavailable",
            ),
            (
                RetainedVolumeTopologyError::MalformedOrUnsupportedTopology,
                "MalformedOrUnsupportedTopology",
            ),
            (
                RetainedVolumeTopologyError::MultiplePhysicalDisks,
                "MultiplePhysicalDisks",
            ),
            (
                RetainedVolumeTopologyError::TopologyChangedOrInconsistent,
                "TopologyChangedOrInconsistent",
            ),
        ] {
            assert_eq!(format!("{error:?}"), expected);
        }
        let source = include_str!("windows_retained_volume_topology.rs");
        let debug = source
            .split_once("impl fmt::Debug for RetainedVolumeSinglePhysicalDeviceObservation")
            .unwrap()
            .1
            .split_once("#[derive(Clone, Copy, Eq, PartialEq)]")
            .unwrap()
            .0;
        assert!(debug.contains("([REDACTED])"));
        for forbidden in [
            "accepted_disk_number",
            "accepted_volume_root",
            "retained_volume",
        ] {
            assert!(!debug.contains(forbidden));
        }
    }

    struct RuntimeFixture {
        root: std::path::PathBuf,
    }

    impl RuntimeFixture {
        fn create() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "church-app-retained-volume-topology-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("unique topology test root should be created");
            Self { root }
        }

        fn open_directory(&self) -> File {
            let mut encoded: Vec<u16> = self.root.as_os_str().encode_wide().collect();
            encoded.push(0);
            // SAFETY: the exact unique test path is NUL-terminated and live;
            // ownership of a successful fresh handle is transferred once.
            let raw = unsafe {
                CreateFileW(
                    encoded.as_ptr(),
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null::<SECURITY_ATTRIBUTES>(),
                    OPEN_EXISTING,
                    windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS,
                    std::ptr::null_mut::<c_void>(),
                )
            };
            assert_ne!(raw, INVALID_HANDLE_VALUE, "test directory should open");
            // SAFETY: ownership of the fresh successful handle moves exactly once.
            File::from(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
        }
    }

    impl Drop for RuntimeFixture {
        fn drop(&mut self) {
            fs::remove_dir(&self.root).expect("exact topology test root should be removed");
        }
    }

    #[test]
    fn retained_temporary_directory_volume_can_be_observed_or_fails_coarsely() {
        let fixture = RuntimeFixture::create();
        let directory = fixture.open_directory();
        match observe_retained_volume_single_physical_device(&directory) {
            Ok(proof) => {
                proof
                    .revalidate()
                    .expect("successful proof should revalidate");
                eprintln!("retained volume topology runtime observation: success");
            }
            Err(error) => {
                eprintln!("retained volume topology runtime observation: {error:?}");
            }
        }
    }

    #[test]
    fn two_retained_temporary_directory_handles_observe_the_same_device() {
        let fixture = RuntimeFixture::create();
        let first_directory = fixture.open_directory();
        let second_directory = fixture.open_directory();
        let first = observe_retained_volume_single_physical_device(&first_directory)
            .expect("first retained temporary-directory handle should produce a topology proof");
        let second = observe_retained_volume_single_physical_device(&second_directory)
            .expect("second retained temporary-directory handle should produce a topology proof");
        first.revalidate().expect("first proof should revalidate");
        second.revalidate().expect("second proof should revalidate");
        assert!(first.same_accepted_physical_device(&second));
    }

    #[test]
    fn source_surface_is_private_non_authorizing_and_uses_no_physical_drive_open() {
        let source = include_str!("windows_retained_volume_topology.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        assert!(production.contains("trusted_retained_source: &File"));
        assert!(
            production.contains("#[path = \"windows_external_recovery_device_eligibility.rs\"]")
        );
        assert!(production.contains("mod windows_external_recovery_device_eligibility;"));
        assert!(!production.contains("pub fn "));
        assert!(!production.contains("fn retained_volume("));
        let proof_impl = production
            .split_once("impl RetainedVolumeSinglePhysicalDeviceObservation {")
            .unwrap()
            .1;
        assert_eq!(proof_impl.matches("pub(crate) fn ").count(), 1);
        assert!(proof_impl.contains("pub(crate) fn revalidate(&self)"));
        assert!(proof_impl.contains("fn same_accepted_physical_device(&self, other: &Self)"));
        assert!(!proof_impl.contains("-> &OwnedHandle"));
        assert!(!proof_impl.contains("-> OwnedHandle"));
        assert!(!proof_impl.contains("RawHandle"));
        assert!(!proof_impl.contains("HANDLE"));
        assert!(!proof_impl.contains("FnOnce"));
        assert!(!proof_impl.contains("FnMut"));
        assert!(!proof_impl.contains("Fn("));
        assert!(!production.contains("serde"));
        assert!(!production.contains("tauri"));
        assert!(!production.contains("PhysicalDrive"));
        assert!(!production.contains("std::path::Path"));
        for forbidden in [
            "removable",
            "disconnect",
            "publication",
            "migration",
            "restore",
        ] {
            assert!(!production.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn production_database_projection_reuses_the_topology_primitive_without_exposing_a_handle() {
        let production_file = include_str!("production_database_file.rs");
        let projection = production_file
            .split_once("pub(crate) fn observe_retained_single_physical_device(")
            .unwrap()
            .1
            .split_once("\n    }")
            .unwrap()
            .0;
        assert!(projection.contains("observe_retained_volume_single_physical_device("));
        assert!(projection.contains("&self._retained_file"));
        assert!(!projection.contains("IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS"));
        assert!(!projection.contains("IOCTL_STORAGE_GET_DEVICE_NUMBER"));
        assert!(!production_file.contains("fn retained_file("));
        assert!(!production_file.contains("fn raw_handle("));
    }
}
