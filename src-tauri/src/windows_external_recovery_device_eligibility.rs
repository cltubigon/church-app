use std::{
    ffi::c_void,
    fmt,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, OwnedHandle},
};

use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        BusType1394, BusTypeAta, BusTypeAtapi, BusTypeFibre, BusTypeFileBackedVirtual, BusTypeMax,
        BusTypeMmc, BusTypeNvme, BusTypeRAID, BusTypeSCM, BusTypeSas, BusTypeSata, BusTypeScsi,
        BusTypeSd, BusTypeSpaces, BusTypeSsa, BusTypeUfs, BusTypeUnknown, BusTypeUsb,
        BusTypeVirtual, BusTypeiScsi,
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{
            IOCTL_STORAGE_GET_HOTPLUG_INFO, IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery,
            STORAGE_DESCRIPTOR_HEADER, STORAGE_DEVICE_DESCRIPTOR, STORAGE_HOTPLUG_INFO,
            STORAGE_PROPERTY_QUERY, StorageDeviceProperty,
        },
    },
};

use super::{RetainedVolumeSinglePhysicalDeviceObservation, RetainedVolumeTopologyError};

const MAXIMUM_DESCRIPTOR_LENGTH: usize = 65_536;
const DESCRIPTOR_HEADER_LENGTH: usize = size_of::<STORAGE_DESCRIPTOR_HEADER>();
const DESCRIPTOR_LAYOUT_LENGTH: usize = size_of::<STORAGE_DEVICE_DESCRIPTOR>();
const VERSION_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, Version);
const SIZE_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, Size);
const REMOVABLE_MEDIA_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, RemovableMedia);
const VENDOR_ID_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, VendorIdOffset);
const PRODUCT_ID_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, ProductIdOffset);
const PRODUCT_REVISION_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, ProductRevisionOffset);
const SERIAL_NUMBER_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset);
const BUS_TYPE_OFFSET: usize = offset_of!(STORAGE_DEVICE_DESCRIPTOR, BusType);
const REQUIRED_DESCRIPTOR_PREFIX_LENGTH: usize = BUS_TYPE_OFFSET + size_of::<i32>();
const HOTPLUG_SIZE_OFFSET: usize = offset_of!(STORAGE_HOTPLUG_INFO, Size);
const MEDIA_REMOVABLE_OFFSET: usize = offset_of!(STORAGE_HOTPLUG_INFO, MediaRemovable);
const MEDIA_HOTPLUG_OFFSET: usize = offset_of!(STORAGE_HOTPLUG_INFO, MediaHotplug);
const DEVICE_HOTPLUG_OFFSET: usize = offset_of!(STORAGE_HOTPLUG_INFO, DeviceHotplug);
const HOTPLUG_INFO_LENGTH: usize = size_of::<STORAGE_HOTPLUG_INFO>();

const _: () = {
    assert!(DESCRIPTOR_HEADER_LENGTH == 8);
    assert!(size_of::<STORAGE_PROPERTY_QUERY>() == 12);
    assert!(DESCRIPTOR_LAYOUT_LENGTH == 40);
    assert!(VERSION_OFFSET == 0);
    assert!(SIZE_OFFSET == 4);
    assert!(REMOVABLE_MEDIA_OFFSET == 10);
    assert!(BUS_TYPE_OFFSET == 28);
    assert!(REQUIRED_DESCRIPTOR_PREFIX_LENGTH == 32);
    assert!(HOTPLUG_SIZE_OFFSET == 0);
    assert!(MEDIA_REMOVABLE_OFFSET == 4);
    assert!(MEDIA_HOTPLUG_OFFSET == 5);
    assert!(DEVICE_HOTPLUG_OFFSET == 6);
    assert!(HOTPLUG_INFO_LENGTH == 8);
    assert!(MAXIMUM_DESCRIPTOR_LENGTH <= u32::MAX as usize);
};

struct RetainedExternalDisconnectableRecoveryDeviceObservation {
    topology: RetainedVolumeSinglePhysicalDeviceObservation,
}

impl fmt::Debug for RetainedExternalDisconnectableRecoveryDeviceObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedExternalDisconnectableRecoveryDeviceObservation([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RecoveryDeviceEligibilityError {
    ObservationUnavailable,
    MalformedOrUnsupportedDeviceFacts,
    NotEligible,
    EligibilityChangedOrInconsistent,
}

impl fmt::Debug for RecoveryDeviceEligibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ObservationUnavailable => "ObservationUnavailable",
            Self::MalformedOrUnsupportedDeviceFacts => "MalformedOrUnsupportedDeviceFacts",
            Self::NotEligible => "NotEligible",
            Self::EligibilityChangedOrInconsistent => "EligibilityChangedOrInconsistent",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeviceFactError {
    Unavailable,
    MalformedOrUnsupported,
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
struct ParsedDescriptor {
    bus_type: i32,
    _removable_media: bool,
}

impl fmt::Debug for ParsedDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParsedDescriptor([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ParsedHotplugInfo {
    device_hotplug: bool,
    _media_removable: bool,
    _media_hotplug: bool,
}

impl fmt::Debug for ParsedHotplugInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParsedHotplugInfo([REDACTED])")
    }
}

fn checked_field_end(offset: usize, width: usize) -> Option<usize> {
    offset.checked_add(width)
}

fn read_u32(bytes: &[u8], returned: usize, offset: usize) -> Result<u32, DeviceFactError> {
    let end = checked_field_end(offset, size_of::<u32>())
        .ok_or(DeviceFactError::MalformedOrUnsupported)?;
    if returned > bytes.len() || end > returned {
        return Err(DeviceFactError::MalformedOrUnsupported);
    }
    Ok(u32::from_le_bytes(
        bytes[offset..end]
            .try_into()
            .map_err(|_| DeviceFactError::MalformedOrUnsupported)?,
    ))
}

fn read_i32(bytes: &[u8], returned: usize, offset: usize) -> Result<i32, DeviceFactError> {
    Ok(i32::from_le_bytes(
        read_u32(bytes, returned, offset)?.to_le_bytes(),
    ))
}

fn parse_descriptor_header(
    bytes: &[u8],
    returned: usize,
) -> Result<DescriptorHeader, DeviceFactError> {
    if returned != DESCRIPTOR_HEADER_LENGTH || returned > bytes.len() {
        return Err(DeviceFactError::MalformedOrUnsupported);
    }
    let version = read_u32(bytes, returned, VERSION_OFFSET)?;
    let size = usize::try_from(read_u32(bytes, returned, SIZE_OFFSET)?)
        .map_err(|_| DeviceFactError::MalformedOrUnsupported)?;
    if version != DESCRIPTOR_LAYOUT_LENGTH as u32
        || size < REQUIRED_DESCRIPTOR_PREFIX_LENGTH
        || size < usize::try_from(version).map_err(|_| DeviceFactError::MalformedOrUnsupported)?
        || size > MAXIMUM_DESCRIPTOR_LENGTH
    {
        return Err(DeviceFactError::MalformedOrUnsupported);
    }
    Ok(DescriptorHeader { version, size })
}

fn validate_unfollowed_offsets(
    bytes: &[u8],
    returned: usize,
    descriptor_size: usize,
) -> Result<(), DeviceFactError> {
    for offset_location in [
        VENDOR_ID_OFFSET,
        PRODUCT_ID_OFFSET,
        PRODUCT_REVISION_OFFSET,
        SERIAL_NUMBER_OFFSET,
    ] {
        let offset = usize::try_from(read_u32(bytes, returned, offset_location)?)
            .map_err(|_| DeviceFactError::MalformedOrUnsupported)?;
        if offset != 0 && offset >= descriptor_size {
            return Err(DeviceFactError::MalformedOrUnsupported);
        }
    }
    Ok(())
}

fn parse_full_descriptor(
    bytes: &[u8],
    returned: usize,
    expected_header: DescriptorHeader,
) -> Result<ParsedDescriptor, DeviceFactError> {
    if returned != bytes.len()
        || returned != expected_header.size
        || returned < REQUIRED_DESCRIPTOR_PREFIX_LENGTH
    {
        return Err(DeviceFactError::MalformedOrUnsupported);
    }
    let repeated_header =
        parse_descriptor_header(&bytes[..DESCRIPTOR_HEADER_LENGTH], DESCRIPTOR_HEADER_LENGTH)?;
    if repeated_header != expected_header {
        return Err(DeviceFactError::MalformedOrUnsupported);
    }
    validate_unfollowed_offsets(bytes, returned, repeated_header.size)?;
    Ok(ParsedDescriptor {
        bus_type: read_i32(bytes, returned, BUS_TYPE_OFFSET)?,
        _removable_media: bytes[REMOVABLE_MEDIA_OFFSET] != 0,
    })
}

fn parse_hotplug_info(bytes: &[u8], returned: usize) -> Result<ParsedHotplugInfo, DeviceFactError> {
    if returned != HOTPLUG_INFO_LENGTH || bytes.len() != HOTPLUG_INFO_LENGTH {
        return Err(DeviceFactError::MalformedOrUnsupported);
    }
    let declared_size = usize::try_from(read_u32(bytes, returned, HOTPLUG_SIZE_OFFSET)?)
        .map_err(|_| DeviceFactError::MalformedOrUnsupported)?;
    if declared_size != HOTPLUG_INFO_LENGTH {
        return Err(DeviceFactError::MalformedOrUnsupported);
    }
    Ok(ParsedHotplugInfo {
        device_hotplug: bytes[DEVICE_HOTPLUG_OFFSET] != 0,
        _media_removable: bytes[MEDIA_REMOVABLE_OFFSET] != 0,
        _media_hotplug: bytes[MEDIA_HOTPLUG_OFFSET] != 0,
    })
}

fn property_query() -> STORAGE_PROPERTY_QUERY {
    STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    }
}

fn query_device_descriptor(volume: &OwnedHandle) -> Result<ParsedDescriptor, DeviceFactError> {
    let query = property_query();
    let query_length = u32::try_from(size_of::<STORAGE_PROPERTY_QUERY>())
        .map_err(|_| DeviceFactError::Unavailable)?;
    let handle = volume.as_raw_handle() as HANDLE;
    let mut header_bytes = [0_u8; DESCRIPTOR_HEADER_LENGTH];
    let mut header_returned = 0_u32;
    // SAFETY: the initialized query and exact writable header buffer remain live
    // for this synchronous call, and every supplied length is checked.
    let header_succeeded = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            (&raw const query).cast::<c_void>(),
            query_length,
            header_bytes.as_mut_ptr().cast::<c_void>(),
            DESCRIPTOR_HEADER_LENGTH as u32,
            &raw mut header_returned,
            std::ptr::null_mut(),
        )
    };
    if header_succeeded == 0 {
        return Err(DeviceFactError::Unavailable);
    }
    let header = parse_descriptor_header(&header_bytes, header_returned as usize)?;
    let mut descriptor_bytes = vec![0_u8; header.size];
    let descriptor_capacity = u32::try_from(descriptor_bytes.len())
        .map_err(|_| DeviceFactError::MalformedOrUnsupported)?;
    let mut descriptor_returned = 0_u32;
    // SAFETY: the same initialized query and the exactly bounded writable
    // descriptor allocation remain live for this synchronous call.
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
        return Err(DeviceFactError::Unavailable);
    }
    parse_full_descriptor(&descriptor_bytes, descriptor_returned as usize, header)
}

fn query_hotplug_info(volume: &OwnedHandle) -> Result<ParsedHotplugInfo, DeviceFactError> {
    let mut bytes = [0_u8; HOTPLUG_INFO_LENGTH];
    bytes[HOTPLUG_SIZE_OFFSET..HOTPLUG_SIZE_OFFSET + size_of::<u32>()]
        .copy_from_slice(&(HOTPLUG_INFO_LENGTH as u32).to_le_bytes());
    let mut returned = 0_u32;
    // SAFETY: the retained volume handle is live; this IOCTL has no input, and
    // the exact writable C-layout byte buffer has its documented Size member
    // initialized using offsets and length derived from the current binding.
    let succeeded = unsafe {
        DeviceIoControl(
            volume.as_raw_handle() as HANDLE,
            IOCTL_STORAGE_GET_HOTPLUG_INFO,
            std::ptr::null(),
            0,
            bytes.as_mut_ptr().cast::<c_void>(),
            HOTPLUG_INFO_LENGTH as u32,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(DeviceFactError::Unavailable);
    }
    parse_hotplug_info(&bytes, returned as usize)
}

#[allow(non_upper_case_globals)]
fn is_exactly_usb(bus_type: i32) -> bool {
    match bus_type {
        BusTypeUsb => true,
        BusTypeUnknown
        | BusTypeScsi
        | BusTypeAtapi
        | BusTypeAta
        | BusType1394
        | BusTypeSsa
        | BusTypeFibre
        | BusTypeRAID
        | BusTypeiScsi
        | BusTypeSas
        | BusTypeSata
        | BusTypeSd
        | BusTypeMmc
        | BusTypeVirtual
        | BusTypeFileBackedVirtual
        | BusTypeSpaces
        | BusTypeNvme
        | BusTypeSCM
        | BusTypeUfs
        | BusTypeMax => false,
        _ => false,
    }
}

fn require_eligible_facts(
    descriptor: Result<ParsedDescriptor, DeviceFactError>,
    hotplug: Result<ParsedHotplugInfo, DeviceFactError>,
) -> Result<(), RecoveryDeviceEligibilityError> {
    let descriptor = descriptor.map_err(|error| match error {
        DeviceFactError::Unavailable => RecoveryDeviceEligibilityError::ObservationUnavailable,
        DeviceFactError::MalformedOrUnsupported => {
            RecoveryDeviceEligibilityError::MalformedOrUnsupportedDeviceFacts
        }
    })?;
    let hotplug = hotplug.map_err(|error| match error {
        DeviceFactError::Unavailable => RecoveryDeviceEligibilityError::ObservationUnavailable,
        DeviceFactError::MalformedOrUnsupported => {
            RecoveryDeviceEligibilityError::MalformedOrUnsupportedDeviceFacts
        }
    })?;
    if !is_exactly_usb(descriptor.bus_type) || !hotplug.device_hotplug {
        return Err(RecoveryDeviceEligibilityError::NotEligible);
    }
    Ok(())
}

fn observe_eligible_facts(volume: &OwnedHandle) -> Result<(), RecoveryDeviceEligibilityError> {
    require_eligible_facts(query_device_descriptor(volume), query_hotplug_info(volume))
}

fn map_topology_initial_error(
    error: RetainedVolumeTopologyError,
) -> RecoveryDeviceEligibilityError {
    match error {
        RetainedVolumeTopologyError::VolumeObservationUnavailable => {
            RecoveryDeviceEligibilityError::ObservationUnavailable
        }
        RetainedVolumeTopologyError::MalformedOrUnsupportedTopology
        | RetainedVolumeTopologyError::MultiplePhysicalDisks => {
            RecoveryDeviceEligibilityError::MalformedOrUnsupportedDeviceFacts
        }
        RetainedVolumeTopologyError::TopologyChangedOrInconsistent => {
            RecoveryDeviceEligibilityError::EligibilityChangedOrInconsistent
        }
    }
}

fn require_revalidated_eligibility(
    topology: Result<(), RetainedVolumeTopologyError>,
    facts: impl FnOnce() -> Result<(), RecoveryDeviceEligibilityError>,
) -> Result<(), RecoveryDeviceEligibilityError> {
    topology.map_err(|_| RecoveryDeviceEligibilityError::EligibilityChangedOrInconsistent)?;
    facts().map_err(|error| match error {
        RecoveryDeviceEligibilityError::NotEligible
        | RecoveryDeviceEligibilityError::EligibilityChangedOrInconsistent => {
            RecoveryDeviceEligibilityError::EligibilityChangedOrInconsistent
        }
        RecoveryDeviceEligibilityError::ObservationUnavailable
        | RecoveryDeviceEligibilityError::MalformedOrUnsupportedDeviceFacts => error,
    })
}

fn observe_retained_external_disconnectable_recovery_device(
    topology: RetainedVolumeSinglePhysicalDeviceObservation,
) -> Result<RetainedExternalDisconnectableRecoveryDeviceObservation, RecoveryDeviceEligibilityError>
{
    topology.revalidate().map_err(map_topology_initial_error)?;
    observe_eligible_facts(&topology.retained_volume)?;
    Ok(RetainedExternalDisconnectableRecoveryDeviceObservation { topology })
}

impl RetainedExternalDisconnectableRecoveryDeviceObservation {
    fn revalidate(&self) -> Result<(), RecoveryDeviceEligibilityError> {
        require_revalidated_eligibility(self.topology.revalidate(), || {
            observe_eligible_facts(&self.topology.retained_volume)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, File},
        os::windows::{
            ffi::OsStrExt,
            io::{FromRawHandle, RawHandle},
        },
        sync::atomic::{AtomicU64, Ordering},
    };
    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE,
            OPEN_EXISTING,
        },
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn descriptor_bytes(bus_type: i32, removable_media: bool) -> Vec<u8> {
        let mut bytes = vec![0_u8; DESCRIPTOR_LAYOUT_LENGTH];
        bytes[VERSION_OFFSET..VERSION_OFFSET + 4]
            .copy_from_slice(&(DESCRIPTOR_LAYOUT_LENGTH as u32).to_le_bytes());
        bytes[SIZE_OFFSET..SIZE_OFFSET + 4]
            .copy_from_slice(&(DESCRIPTOR_LAYOUT_LENGTH as u32).to_le_bytes());
        bytes[REMOVABLE_MEDIA_OFFSET] = u8::from(removable_media);
        bytes[BUS_TYPE_OFFSET..BUS_TYPE_OFFSET + 4].copy_from_slice(&bus_type.to_le_bytes());
        bytes
    }

    fn parsed_descriptor(bus_type: i32, removable_media: bool) -> ParsedDescriptor {
        let bytes = descriptor_bytes(bus_type, removable_media);
        let header =
            parse_descriptor_header(&bytes[..DESCRIPTOR_HEADER_LENGTH], DESCRIPTOR_HEADER_LENGTH)
                .unwrap();
        parse_full_descriptor(&bytes, bytes.len(), header).unwrap()
    }

    fn hotplug_bytes(
        media_removable: bool,
        media_hotplug: bool,
        device_hotplug: bool,
    ) -> [u8; HOTPLUG_INFO_LENGTH] {
        let mut bytes = [0_u8; HOTPLUG_INFO_LENGTH];
        bytes[..4].copy_from_slice(&(HOTPLUG_INFO_LENGTH as u32).to_le_bytes());
        bytes[MEDIA_REMOVABLE_OFFSET] = u8::from(media_removable);
        bytes[MEDIA_HOTPLUG_OFFSET] = u8::from(media_hotplug);
        bytes[DEVICE_HOTPLUG_OFFSET] = u8::from(device_hotplug);
        bytes
    }

    fn parsed_hotplug(device_hotplug: bool) -> ParsedHotplugInfo {
        let bytes = hotplug_bytes(false, false, device_hotplug);
        parse_hotplug_info(&bytes, bytes.len()).unwrap()
    }

    #[test]
    fn usb_and_device_hotplug_are_both_required() {
        assert_eq!(
            require_eligible_facts(
                Ok(parsed_descriptor(BusTypeUsb, false)),
                Ok(parsed_hotplug(true))
            ),
            Ok(())
        );
        assert_eq!(
            require_eligible_facts(
                Ok(parsed_descriptor(BusTypeUsb, false)),
                Ok(parsed_hotplug(false))
            ),
            Err(RecoveryDeviceEligibilityError::NotEligible)
        );
    }

    #[test]
    fn removable_media_does_not_change_usb_hotplug_eligibility() {
        for removable_media in [false, true] {
            assert_eq!(
                require_eligible_facts(
                    Ok(parsed_descriptor(BusTypeUsb, removable_media)),
                    Ok(parsed_hotplug(true))
                ),
                Ok(())
            );
        }
    }

    #[test]
    #[allow(non_upper_case_globals)]
    fn every_named_non_usb_bus_and_unknown_value_are_rejected() {
        for bus_type in [
            BusTypeUnknown,
            BusTypeScsi,
            BusTypeAtapi,
            BusTypeAta,
            BusType1394,
            BusTypeSsa,
            BusTypeFibre,
            BusTypeRAID,
            BusTypeiScsi,
            BusTypeSas,
            BusTypeSata,
            BusTypeSd,
            BusTypeMmc,
            BusTypeVirtual,
            BusTypeFileBackedVirtual,
            BusTypeSpaces,
            BusTypeNvme,
            BusTypeSCM,
            BusTypeUfs,
            BusTypeMax,
            i32::MAX,
        ] {
            assert_eq!(
                require_eligible_facts(
                    Ok(parsed_descriptor(bus_type, false)),
                    Ok(parsed_hotplug(true))
                ),
                Err(RecoveryDeviceEligibilityError::NotEligible)
            );
        }
    }

    #[test]
    fn descriptor_parser_rejects_truncation_and_malformed_sizes() {
        let valid = descriptor_bytes(BusTypeUsb, false);
        for returned in 0..DESCRIPTOR_HEADER_LENGTH {
            assert_eq!(
                parse_descriptor_header(&valid[..DESCRIPTOR_HEADER_LENGTH], returned),
                Err(DeviceFactError::MalformedOrUnsupported)
            );
        }
        let header =
            parse_descriptor_header(&valid[..DESCRIPTOR_HEADER_LENGTH], DESCRIPTOR_HEADER_LENGTH)
                .unwrap();
        for returned in 0..valid.len() {
            assert_eq!(
                parse_full_descriptor(&valid, returned, header),
                Err(DeviceFactError::MalformedOrUnsupported)
            );
        }
        for size in [
            0_u32,
            (REQUIRED_DESCRIPTOR_PREFIX_LENGTH - 1) as u32,
            (MAXIMUM_DESCRIPTOR_LENGTH + 1) as u32,
        ] {
            let mut malformed = valid.clone();
            malformed[SIZE_OFFSET..SIZE_OFFSET + 4].copy_from_slice(&size.to_le_bytes());
            assert_eq!(
                parse_descriptor_header(
                    &malformed[..DESCRIPTOR_HEADER_LENGTH],
                    DESCRIPTOR_HEADER_LENGTH
                ),
                Err(DeviceFactError::MalformedOrUnsupported)
            );
        }
    }

    #[test]
    fn hotplug_parser_rejects_truncation_and_malformed_size() {
        let valid = hotplug_bytes(false, false, true);
        for returned in 0..HOTPLUG_INFO_LENGTH {
            assert_eq!(
                parse_hotplug_info(&valid, returned),
                Err(DeviceFactError::MalformedOrUnsupported)
            );
        }
        let mut malformed = valid;
        malformed[..4].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            parse_hotplug_info(&malformed, malformed.len()),
            Err(DeviceFactError::MalformedOrUnsupported)
        );
    }

    #[test]
    fn unavailable_descriptor_or_hotplug_fails_closed() {
        assert_eq!(
            require_eligible_facts(Err(DeviceFactError::Unavailable), Ok(parsed_hotplug(true))),
            Err(RecoveryDeviceEligibilityError::ObservationUnavailable)
        );
        assert_eq!(
            require_eligible_facts(
                Ok(parsed_descriptor(BusTypeUsb, false)),
                Err(DeviceFactError::Unavailable)
            ),
            Err(RecoveryDeviceEligibilityError::ObservationUnavailable)
        );
    }

    #[test]
    fn revalidation_preserves_success_and_rejects_changed_eligibility() {
        assert_eq!(require_revalidated_eligibility(Ok(()), || Ok(())), Ok(()));
        assert_eq!(
            require_revalidated_eligibility(Ok(()), || Err(
                RecoveryDeviceEligibilityError::NotEligible
            )),
            Err(RecoveryDeviceEligibilityError::EligibilityChangedOrInconsistent)
        );
        assert_eq!(
            require_revalidated_eligibility(
                Err(RetainedVolumeTopologyError::TopologyChangedOrInconsistent),
                || Ok(())
            ),
            Err(RecoveryDeviceEligibilityError::EligibilityChangedOrInconsistent)
        );
    }

    #[test]
    fn errors_and_success_owner_debug_are_fixed_and_redacted() {
        for (error, expected) in [
            (
                RecoveryDeviceEligibilityError::ObservationUnavailable,
                "ObservationUnavailable",
            ),
            (
                RecoveryDeviceEligibilityError::MalformedOrUnsupportedDeviceFacts,
                "MalformedOrUnsupportedDeviceFacts",
            ),
            (RecoveryDeviceEligibilityError::NotEligible, "NotEligible"),
            (
                RecoveryDeviceEligibilityError::EligibilityChangedOrInconsistent,
                "EligibilityChangedOrInconsistent",
            ),
        ] {
            assert_eq!(format!("{error:?}"), expected);
        }
        let source = include_str!("windows_external_recovery_device_eligibility.rs");
        let debug = source
            .split_once(
                "impl fmt::Debug for RetainedExternalDisconnectableRecoveryDeviceObservation",
            )
            .unwrap()
            .1
            .split_once("#[derive(Clone, Copy, Eq, PartialEq)]")
            .unwrap()
            .0;
        assert!(debug.contains("([REDACTED])"));
        assert!(!debug.contains("topology:"));
    }

    struct RuntimeFixture {
        root: std::path::PathBuf,
    }

    impl RuntimeFixture {
        fn create() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "church-app-external-recovery-device-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("unique eligibility test root should be created");
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
                    FILE_FLAG_BACKUP_SEMANTICS,
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
            fs::remove_dir(&self.root).expect("exact eligibility test root should be removed");
        }
    }

    #[test]
    fn exact_temporary_directory_volume_cannot_bypass_eligibility_policy() {
        let fixture = RuntimeFixture::create();
        let directory = fixture.open_directory();
        let topology =
            match super::super::observe_retained_volume_single_physical_device(&directory) {
                Ok(topology) => topology,
                Err(error) => {
                    eprintln!(
                        "external recovery eligibility runtime topology observation: {error:?}"
                    );
                    return;
                }
            };
        match observe_retained_external_disconnectable_recovery_device(topology) {
            Ok(proof) => {
                proof
                    .revalidate()
                    .expect("a qualifying host volume should revalidate");
                eprintln!(
                    "external recovery eligibility runtime observation: eligible USB hotplug volume"
                );
            }
            Err(RecoveryDeviceEligibilityError::NotEligible) => {
                eprintln!("external recovery eligibility runtime observation: not eligible");
            }
            Err(error) => {
                eprintln!("external recovery eligibility runtime observation: {error:?}");
            }
        }
    }

    #[test]
    fn source_surface_is_private_non_authorizing_and_excludes_deferred_authority() {
        let source = include_str!("windows_external_recovery_device_eligibility.rs");
        let production = source.split_once("#[cfg(test)]").unwrap().0;
        let library = include_str!("lib.rs");
        let topology = include_str!("windows_retained_volume_topology.rs");
        assert!(!library.contains("mod windows_external_recovery_device_eligibility;"));
        assert!(topology.contains("#[path = \"windows_external_recovery_device_eligibility.rs\"]"));
        assert!(topology.contains("mod windows_external_recovery_device_eligibility;"));
        assert!(production.contains("use super::{"));
        assert!(production.contains("observe_eligible_facts(&topology.retained_volume)?;"));
        assert!(production.contains("observe_eligible_facts(&self.topology.retained_volume)"));
        assert!(!production.contains("retained_volume()"));
        assert!(!production.contains("pub(crate)"));
        assert!(!production.contains("pub fn "));
        assert!(!production.contains("FnOnce(&OwnedHandle"));
        assert!(!production.contains("FnMut(&OwnedHandle"));
        assert!(!production.contains("Fn(&OwnedHandle"));
        assert!(!production.contains("serde"));
        assert!(!production.contains("tauri"));
        assert!(!production.contains("IOCTL_STORAGE_SET_HOTPLUG_INFO"));
        assert!(!production.contains("PhysicalDrive"));
        for forbidden in [
            "CreateDirectory",
            "WriteFile",
            "publication_authority",
            "restore_authority",
            "migration_authority",
        ] {
            assert!(!production.contains(forbidden));
        }
    }
}
