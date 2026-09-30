//! Trusted Win32 confirmation for an Exact-V1 migration opportunity.

use windows_sys::Win32::{
    Foundation::HWND,
    UI::WindowsAndMessaging::{
        IDCANCEL, IDOK, IsWindow, MB_APPLMODAL, MB_DEFBUTTON2, MB_ICONWARNING, MB_OKCANCEL,
        MessageBoxW,
    },
};

const TITLE: &str = "Prepare database upgrade";
const MESSAGE: &str = "The installed Church App database is an older supported version.\n\nContinuing begins the protected migration-preparation process. Church App will first create and verify the required recovery protection before any database schema change.\n\nYou can cancel and keep using the current safe database state.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeProductionDatabaseMigrationConfirmationOutcome {
    Confirmed,
    Cancelled,
    Unavailable,
}

pub(crate) fn request_native_production_database_migration_confirmation(
    parent: HWND,
) -> NativeProductionDatabaseMigrationConfirmationOutcome {
    if parent.is_null() || unsafe { IsWindow(parent) } == 0 {
        return NativeProductionDatabaseMigrationConfirmationOutcome::Unavailable;
    }

    let title = wide(TITLE);
    let message = wide(MESSAGE);
    // SAFETY: both strings are live, NUL-terminated UTF-16 buffers for the synchronous call,
    // and `parent` was verified as a live window above.
    let result = unsafe {
        MessageBoxW(
            parent,
            message.as_ptr(),
            title.as_ptr(),
            MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_APPLMODAL,
        )
    };

    match result {
        IDOK => NativeProductionDatabaseMigrationConfirmationOutcome::Confirmed,
        IDCANCEL => NativeProductionDatabaseMigrationConfirmationOutcome::Cancelled,
        _ => NativeProductionDatabaseMigrationConfirmationOutcome::Unavailable,
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_describes_preparation_without_claiming_immediate_mutation() {
        assert!(MESSAGE.contains("older supported version"));
        assert!(MESSAGE.contains("protected migration-preparation process"));
        assert!(MESSAGE.contains("first create and verify the required recovery protection"));
        assert!(MESSAGE.contains("before any database schema change"));
        assert!(MESSAGE.contains("cancel"));
        for forbidden in ["key", "digest", "SQL", "path", "device identity"] {
            assert!(!MESSAGE.contains(forbidden));
        }
    }

    #[test]
    fn adapter_accepts_only_the_real_parent_handle_and_returns_a_rust_decision() {
        let source = include_str!("native_production_database_migration_confirmation.rs");
        let signature = source
            .split_once("pub(crate) fn request_native_production_database_migration_confirmation(")
            .unwrap()
            .1
            .split_once(") -> NativeProductionDatabaseMigrationConfirmationOutcome")
            .unwrap()
            .0;
        assert!(signature.contains("parent: HWND"));
        for forbidden in ["bool", "String", "Path", "schema", "key", "opportunity"] {
            assert!(!signature.contains(forbidden));
        }
        assert!(source.contains("IsWindow(parent)"));
        assert!(
            source.contains(
                "IDOK => NativeProductionDatabaseMigrationConfirmationOutcome::Confirmed"
            )
        );
    }
}
