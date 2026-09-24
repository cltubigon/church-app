//! Private Windows Common Item Dialog adapter for selecting one exact volume root.

use std::{ffi::c_void, fmt};

use windows::{
    Win32::{
        Foundation::{ERROR_CANCELLED, HWND, RPC_E_CHANGED_MODE, S_FALSE, S_OK},
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
            CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize,
        },
        UI::Shell::{
            FILEOPENDIALOGOPTIONS, FOS_DONTADDTORECENT, FOS_FORCEFILESYSTEM, FOS_PATHMUSTEXIST,
            FOS_PICKFOLDERS, FileOpenDialog, IFileOpenDialog, SIGDN_FILESYSPATH,
        },
    },
    core::{HRESULT, PWSTR},
};
use windows_sys::Win32::Storage::FileSystem::GetVolumeNameForVolumeMountPointW;

use super::{NativeSelectedRecoveryVolumeRoot, VOLUME_GUID_ROOT_UNITS, parse_exact_volume_root};

const VOLUME_GUID_ROOT_BUFFER_UNITS: usize = VOLUME_GUID_ROOT_UNITS + 1;
const PICKER_OPTIONS: FILEOPENDIALOGOPTIONS = FILEOPENDIALOGOPTIONS(
    FOS_PICKFOLDERS.0 | FOS_FORCEFILESYSTEM.0 | FOS_PATHMUSTEXIST.0 | FOS_DONTADDTORECENT.0,
);
const STANDARD_DIALOG_CANCELLATION: HRESULT = HRESULT::from_win32(ERROR_CANCELLED.0);

#[must_use = "the native selection outcome must be handled"]
pub(super) enum NativeRecoveryVolumeSelectionOutcome {
    Selected(NativeSelectedRecoveryVolumeRoot),
    Cancelled,
    Unavailable,
}

impl fmt::Debug for NativeRecoveryVolumeSelectionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Selected(_) => "NativeRecoveryVolumeSelectionOutcome::Selected([REDACTED])",
            Self::Cancelled => "NativeRecoveryVolumeSelectionOutcome::Cancelled",
            Self::Unavailable => "NativeRecoveryVolumeSelectionOutcome::Unavailable",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ComInitializationClassification {
    Initialized,
    ChangedMode,
    Failed,
}

fn classify_com_initialization(result: HRESULT) -> ComInitializationClassification {
    if result == S_OK || result == S_FALSE {
        ComInitializationClassification::Initialized
    } else if result == RPC_E_CHANGED_MODE {
        ComInitializationClassification::ChangedMode
    } else {
        ComInitializationClassification::Failed
    }
}

struct InitializedComApartment;

impl Drop for InitializedComApartment {
    fn drop(&mut self) {
        // SAFETY: this guard exists only after this thread's successful CoInitializeEx call.
        unsafe { CoUninitialize() };
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DialogResultClassification {
    Shown,
    Cancelled,
    Failed,
}

fn classify_dialog_result(result: HRESULT) -> DialogResultClassification {
    if result == S_OK {
        DialogResultClassification::Shown
    } else if result == STANDARD_DIALOG_CANCELLATION {
        DialogResultClassification::Cancelled
    } else {
        DialogResultClassification::Failed
    }
}

struct ShellAllocatedPath(PWSTR);

impl Drop for ShellAllocatedPath {
    fn drop(&mut self) {
        // SAFETY: GetDisplayName transfers this allocation under the COM task allocator.
        unsafe { CoTaskMemFree(Some(self.0.as_ptr().cast::<c_void>())) };
    }
}

pub(super) fn select_native_recovery_volume_root(
    parent: HWND,
) -> NativeRecoveryVolumeSelectionOutcome {
    // SAFETY: the call supplies the required null reserved pointer and fixed approved flags.
    let initialization =
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
    let _apartment = match classify_com_initialization(initialization) {
        ComInitializationClassification::Initialized => InitializedComApartment,
        ComInitializationClassification::ChangedMode | ComInitializationClassification::Failed => {
            return NativeRecoveryVolumeSelectionOutcome::Unavailable;
        }
    };

    run_initialized_picker(parent)
}

fn run_initialized_picker(parent: HWND) -> NativeRecoveryVolumeSelectionOutcome {
    // SAFETY: COM is initialized for this thread, aggregation is not requested, and the typed
    // return owns the acquired IFileOpenDialog reference.
    let dialog: IFileOpenDialog =
        match unsafe { CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) } {
            Ok(dialog) => dialog,
            Err(_) => return NativeRecoveryVolumeSelectionOutcome::Unavailable,
        };
    // SAFETY: dialog is a live typed COM interface and the options are fixed constants.
    if unsafe { dialog.SetOptions(PICKER_OPTIONS) }.is_err() {
        return NativeRecoveryVolumeSelectionOutcome::Unavailable;
    }

    // SAFETY: parent is borrowed from the caller and dialog owns no HWND; Show is synchronous.
    match unsafe { dialog.Show(Some(parent)) } {
        Ok(()) => {}
        Err(error) => {
            return match classify_dialog_result(error.code()) {
                DialogResultClassification::Cancelled => {
                    NativeRecoveryVolumeSelectionOutcome::Cancelled
                }
                DialogResultClassification::Shown | DialogResultClassification::Failed => {
                    NativeRecoveryVolumeSelectionOutcome::Unavailable
                }
            };
        }
    }

    // SAFETY: successful single-select Show permits exactly one typed result retrieval.
    let shell_item = match unsafe { dialog.GetResult() } {
        Ok(shell_item) => shell_item,
        Err(_) => return NativeRecoveryVolumeSelectionOutcome::Unavailable,
    };
    // SAFETY: the live shell item returns a task-allocator-owned NUL-terminated filesystem path.
    let selected_path = match unsafe { shell_item.GetDisplayName(SIGDN_FILESYSPATH) } {
        Ok(selected_path) if !selected_path.is_null() => ShellAllocatedPath(selected_path),
        Ok(_) | Err(_) => return NativeRecoveryVolumeSelectionOutcome::Unavailable,
    };
    // SAFETY: the allocation is live, NUL-terminated by the shell contract, and copied only for
    // the immediately following exact mount-point-root query.
    let selected_units = unsafe { selected_path.0.as_wide() };
    let Some(volume_guid_root) = exact_volume_guid_root_for_selected_path(selected_units) else {
        return NativeRecoveryVolumeSelectionOutcome::Unavailable;
    };

    NativeRecoveryVolumeSelectionOutcome::Selected(
        NativeSelectedRecoveryVolumeRoot::from_native_volume_guid_root(volume_guid_root),
    )
}

fn exact_volume_guid_root_for_selected_path(
    selected_path: &[u16],
) -> Option<[u16; VOLUME_GUID_ROOT_UNITS]> {
    let mount_point = mount_point_query_path(selected_path)?;

    let mut volume_name = [0_u16; VOLUME_GUID_ROOT_BUFFER_UNITS];
    // SAFETY: both buffers are live and NUL-terminated/capacity-described. The selected path is
    // passed directly (with only the API-required trailing separator), never replaced by an
    // ancestor or containing-volume lookup.
    let recognized = unsafe {
        GetVolumeNameForVolumeMountPointW(
            mount_point.as_ptr(),
            volume_name.as_mut_ptr(),
            VOLUME_GUID_ROOT_BUFFER_UNITS as u32,
        )
    } != 0;
    if !recognized || volume_name[VOLUME_GUID_ROOT_UNITS] != 0 {
        return None;
    }
    parse_exact_volume_root(&volume_name[..VOLUME_GUID_ROOT_UNITS]).ok()
}

fn mount_point_query_path(selected_path: &[u16]) -> Option<Vec<u16>> {
    if selected_path.is_empty() || selected_path.contains(&0) {
        return None;
    }
    let mut mount_point = Vec::with_capacity(selected_path.len().checked_add(2)?);
    mount_point.extend_from_slice(selected_path);
    if mount_point.last() != Some(&(b'\\' as u16)) {
        mount_point.push(b'\\' as u16);
    }
    mount_point.push(0);
    Some(mount_point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::needs_drop;

    fn valid_root() -> [u16; VOLUME_GUID_ROOT_UNITS] {
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\"
            .encode_utf16()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    #[test]
    fn com_initialization_classification_balances_only_successful_calls() {
        assert!(matches!(
            classify_com_initialization(S_OK),
            ComInitializationClassification::Initialized
        ));
        assert!(matches!(
            classify_com_initialization(S_FALSE),
            ComInitializationClassification::Initialized
        ));
        assert!(matches!(
            classify_com_initialization(RPC_E_CHANGED_MODE),
            ComInitializationClassification::ChangedMode
        ));
        assert!(matches!(
            classify_com_initialization(HRESULT(0x8000_4005_u32 as i32)),
            ComInitializationClassification::Failed
        ));

        let source = include_str!("native_windows_selection.rs")
            .split_once("#[cfg(test)]")
            .unwrap()
            .0;
        assert!(source.contains("S_OK || result == S_FALSE"));
        assert!(source.contains("Initialized => InitializedComApartment"));
        assert!(source.contains("impl Drop for InitializedComApartment"));
        assert!(source.contains("CoUninitialize()"));
    }

    #[test]
    fn only_standard_dialog_cancellation_is_cancelled() {
        assert!(matches!(
            classify_dialog_result(S_OK),
            DialogResultClassification::Shown
        ));
        assert!(matches!(
            classify_dialog_result(STANDARD_DIALOG_CANCELLATION),
            DialogResultClassification::Cancelled
        ));
        assert!(matches!(
            classify_dialog_result(HRESULT(0x8000_4005_u32 as i32)),
            DialogResultClassification::Failed
        ));
    }

    #[test]
    fn picker_contract_is_exact_private_and_policy_free() {
        let source = include_str!("native_windows_selection.rs")
            .split_once("#[cfg(test)]")
            .unwrap()
            .0;
        for required in [
            "FOS_PICKFOLDERS.0",
            "FOS_FORCEFILESYSTEM.0",
            "FOS_PATHMUSTEXIST.0",
            "FOS_DONTADDTORECENT.0",
            "COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE",
            "dialog.Show(Some(parent))",
            "dialog.GetResult()",
            "GetDisplayName(SIGDN_FILESYSPATH)",
            "GetVolumeNameForVolumeMountPointW",
            "parse_exact_volume_root",
        ] {
            assert!(
                source.contains(required),
                "missing picker contract: {required}"
            );
        }
        for forbidden in [
            "FOS_ALLOWMULTISELECT",
            "GetVolumePathNameW",
            "canonicalize(",
            "parent()",
            "retain_eligible_ntfs_recovery_volume_root(",
            "NTFS",
            "BusTypeUsb",
            "DeviceHotplug",
            "run_on_main_thread",
            "AppHandle",
            "tauri::command",
            "publish",
            "migration",
        ] {
            assert!(
                !source.contains(forbidden),
                "unexpected picker policy: {forbidden}"
            );
        }
    }

    #[test]
    fn exact_selected_path_is_preserved_for_mount_root_recognition() {
        let root = r"E:\".encode_utf16().collect::<Vec<_>>();
        let child = r"E:\ordinary-child".encode_utf16().collect::<Vec<_>>();
        assert_eq!(
            mount_point_query_path(&root).unwrap(),
            r"E:\".encode_utf16().chain([0]).collect::<Vec<_>>()
        );
        assert_eq!(
            mount_point_query_path(&child).unwrap(),
            r"E:\ordinary-child\"
                .encode_utf16()
                .chain([0])
                .collect::<Vec<_>>()
        );
        assert_eq!(mount_point_query_path(&[]), None);
        assert_eq!(mount_point_query_path(&[b'E' as u16, 0]), None);
        assert!(parse_exact_volume_root(&valid_root()).is_ok());
        assert!(
            parse_exact_volume_root(
                &r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\child"
                    .encode_utf16()
                    .collect::<Vec<_>>()
            )
            .is_err()
        );
    }

    #[test]
    fn selection_owner_and_outcome_are_opaque_fixed_and_redacted() {
        assert!(needs_drop::<NativeSelectedRecoveryVolumeRoot>());
        let selected = NativeSelectedRecoveryVolumeRoot::from_native_volume_guid_root(valid_root());
        assert_eq!(
            format!(
                "{:?}",
                NativeRecoveryVolumeSelectionOutcome::Selected(selected)
            ),
            "NativeRecoveryVolumeSelectionOutcome::Selected([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", NativeRecoveryVolumeSelectionOutcome::Cancelled),
            "NativeRecoveryVolumeSelectionOutcome::Cancelled"
        );
        assert_eq!(
            format!("{:?}", NativeRecoveryVolumeSelectionOutcome::Unavailable),
            "NativeRecoveryVolumeSelectionOutcome::Unavailable"
        );

        let parent = include_str!("../windows_retained_eligible_ntfs_recovery_volume_root.rs");
        let production = parent.split_once("#[cfg(test)]").unwrap().0;
        let constructor = production
            .split_once("fn from_native_volume_guid_root(")
            .unwrap()
            .1
            .split_once("impl fmt::Debug")
            .unwrap()
            .0;
        assert!(constructor.contains("[u16; VOLUME_GUID_ROOT_UNITS]"));
        for forbidden in ["PathBuf", "Path", "String", "OsString", "&str", "Vec<u16>"] {
            assert!(
                !constructor
                    .split_once(") -> Self")
                    .unwrap()
                    .0
                    .contains(forbidden)
            );
        }
        assert!(!production.contains("from_test_path"));
        let owner_declaration = production
            .split_once("pub(super) struct NativeSelectedRecoveryVolumeRoot")
            .unwrap()
            .0
            .lines()
            .rev()
            .take(2)
            .collect::<Vec<_>>();
        assert!(
            owner_declaration
                .iter()
                .all(|line| !line.contains("derive"))
        );
        assert!(
            parent
                .split_once("#[cfg(test)]")
                .unwrap()
                .1
                .contains("from_test_path(selected: PathBuf)")
        );
    }
}
