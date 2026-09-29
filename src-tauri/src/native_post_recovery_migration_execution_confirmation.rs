//! Trusted Win32 confirmation for fresh post-recovery migration execution consent.

use std::fmt;

use windows_sys::Win32::{
    Foundation::HWND,
    UI::WindowsAndMessaging::{
        IDCANCEL, IDOK, IsWindow, MB_APPLMODAL, MB_DEFBUTTON2, MB_ICONWARNING, MB_OKCANCEL,
        MessageBoxW,
    },
};

use crate::windows_retained_volume_topology::TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup;

const TITLE: &str = "Confirm database migration authorization";
const MESSAGE: &str = "Both recovery sets are complete and verified.\n\nContinuing authorizes a future step to modify the local Church App database to the new schema. Recovery copies will remain untouched. A restart will be required after a successful future migration.\n\nThis confirmation does not start migration now.";

#[must_use = "the native confirmation outcome retains migration ownership"]
pub(crate) enum NativePostRecoveryMigrationExecutionConfirmationOutcome {
    Confirmed(TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup),
    Cancelled(TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup),
    Unavailable(TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup),
}

impl fmt::Debug for NativePostRecoveryMigrationExecutionConfirmationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Confirmed(_) => {
                "NativePostRecoveryMigrationExecutionConfirmationOutcome::Confirmed([REDACTED])"
            }
            Self::Cancelled(_) => {
                "NativePostRecoveryMigrationExecutionConfirmationOutcome::Cancelled([REDACTED])"
            }
            Self::Unavailable(_) => {
                "NativePostRecoveryMigrationExecutionConfirmationOutcome::Unavailable([REDACTED])"
            }
        })
    }
}

pub(crate) fn request_native_post_recovery_migration_execution_confirmation(
    owner: TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup,
    parent: HWND,
) -> NativePostRecoveryMigrationExecutionConfirmationOutcome {
    if parent.is_null() || unsafe { IsWindow(parent) } == 0 {
        return NativePostRecoveryMigrationExecutionConfirmationOutcome::Unavailable(owner);
    }

    let title = wide(TITLE);
    let message = wide(MESSAGE);
    // SAFETY: both strings are live, NUL-terminated UTF-16 buffers for the duration of the
    // synchronous call, and `parent` was verified as a live window above.
    let result = unsafe {
        MessageBoxW(
            parent,
            message.as_ptr(),
            title.as_ptr(),
            MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_APPLMODAL,
        )
    };

    match result {
        IDOK => NativePostRecoveryMigrationExecutionConfirmationOutcome::Confirmed(owner),
        IDCANCEL => NativePostRecoveryMigrationExecutionConfirmationOutcome::Cancelled(owner),
        _ => NativePostRecoveryMigrationExecutionConfirmationOutcome::Unavailable(owner),
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_states_the_bounded_future_authorization_truthfully() {
        assert!(MESSAGE.contains("Both recovery sets are complete and verified"));
        assert!(MESSAGE.contains("authorizes a future step"));
        assert!(MESSAGE.contains("Recovery copies will remain untouched"));
        assert!(MESSAGE.contains("restart will be required"));
        assert!(MESSAGE.contains("does not start migration now"));
        for forbidden in ["key", "digest", "SQL", "HRESULT", "path"] {
            assert!(!MESSAGE.contains(forbidden));
        }
    }

    #[test]
    fn adapter_accepts_only_exact_owner_and_real_parent_handle() {
        let source = include_str!("native_post_recovery_migration_execution_confirmation.rs");
        let signature = source
            .split_once(
                "pub(crate) fn request_native_post_recovery_migration_execution_confirmation(",
            )
            .unwrap()
            .1
            .split_once(") -> NativePostRecoveryMigrationExecutionConfirmationOutcome")
            .unwrap()
            .0;
        assert!(
            signature.contains("TwoCompleteRecoverySetsVerifiedProductionDatabaseMigrationBackup")
        );
        assert!(signature.contains("parent: HWND"));
        for forbidden in ["bool", "String", "Path", "schema", "key"] {
            assert!(!signature.contains(forbidden));
        }
        assert!(source.contains("IsWindow(parent)"));
        assert!(source.contains(
            "IDOK => NativePostRecoveryMigrationExecutionConfirmationOutcome::Confirmed(owner)"
        ));
    }
}
