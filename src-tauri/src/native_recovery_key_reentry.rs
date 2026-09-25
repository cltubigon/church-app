//! Private Win32 adapter for one complete recovery-key custody-record re-entry.

use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr::{null, null_mut},
};

use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, WPARAM},
    UI::{
        Controls::EM_SETLIMITTEXT,
        Input::KeyboardAndMouse::{
            GetKeyState, SetFocus, VK_C, VK_CONTROL, VK_DELETE, VK_INSERT, VK_SHIFT, VK_V, VK_X,
        },
        WindowsAndMessaging::{
            BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CallWindowProcW, CreateWindowExW, DS_CENTER,
            DS_MODALFRAME, DestroyWindow, DialogBoxIndirectParamW, ES_AUTOVSCROLL, ES_MULTILINE,
            ES_WANTRETURN, EndDialog, GWLP_USERDATA, GWLP_WNDPROC, GetWindowLongPtrW,
            GetWindowTextLengthW, GetWindowTextW, IDCANCEL, IDOK, IsWindow, SendMessageW,
            SetWindowLongPtrW, SetWindowTextW, WM_CLOSE, WM_COMMAND, WM_CONTEXTMENU, WM_COPY,
            WM_CUT, WM_INITDIALOG, WM_KEYDOWN, WM_NCDESTROY, WM_PASTE, WNDPROC, WS_BORDER,
            WS_CAPTION, WS_CHILD, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
        },
    },
};
use zeroize::{Zeroize, Zeroizing};

use crate::production_database_migration_recovery_envelope::ReenteredMigrationRecoveryKeyCustodyV1;

const NATIVE_TEXT_LIMIT: usize = 200;
const NATIVE_BUFFER_LENGTH: usize = NATIVE_TEXT_LIMIT + 1;
const CONTROL_PROMPT: i32 = 1001;
const CONTROL_ENTRY: i32 = 1002;
const DIALOG_FINISHED: isize = 1;
const STATIC_NO_PREFIX: u32 = 0x80;
const WM_DROPFILES: u32 = 0x0233;

#[must_use = "the native re-entry outcome may own a recovery-key custody record"]
#[allow(clippy::large_enum_variant)]
pub(crate) enum NativeRecoveryKeyReentryOutcome {
    Submitted(ReenteredMigrationRecoveryKeyCustodyV1),
    Cancelled,
    Unavailable,
}

impl fmt::Debug for NativeRecoveryKeyReentryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Submitted(_) => "NativeRecoveryKeyReentryOutcome::Submitted([REDACTED])",
            Self::Cancelled => "NativeRecoveryKeyReentryOutcome::Cancelled",
            Self::Unavailable => "NativeRecoveryKeyReentryOutcome::Unavailable",
        })
    }
}

struct NativeEntryCapture {
    bytes: [u8; NATIVE_TEXT_LIMIT],
    used: usize,
}

impl NativeEntryCapture {
    fn from_utf16(units: &[u16]) -> Result<Self, ()> {
        if units.len() > NATIVE_TEXT_LIMIT {
            return Err(());
        }
        let mut capture = Self {
            bytes: [0; NATIVE_TEXT_LIMIT],
            used: units.len(),
        };
        for (index, unit) in units.iter().copied().enumerate() {
            if unit > 0x7f {
                capture.zeroize();
                return Err(());
            }
            capture.bytes[index] = unit as u8;
        }
        Ok(capture)
    }

    fn submit(&mut self) -> Result<ReenteredMigrationRecoveryKeyCustodyV1, ()> {
        let result =
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&self.bytes[..self.used])
                .map_err(|_| ());
        self.zeroize();
        result
    }

    fn cancel(&mut self) {
        self.zeroize();
    }

    fn zeroize(&mut self) {
        self.bytes.zeroize();
        self.used.zeroize();
    }
}

impl Drop for NativeEntryCapture {
    fn drop(&mut self) {
        self.zeroize();
    }
}

struct DialogContext {
    dialog: HWND,
    prompt: HWND,
    entry: HWND,
    entry_previous: WNDPROC,
    outcome: Option<NativeRecoveryKeyReentryOutcome>,
}

impl DialogContext {
    fn new() -> Self {
        Self {
            dialog: null_mut(),
            prompt: null_mut(),
            entry: null_mut(),
            entry_previous: None,
            outcome: None,
        }
    }

    fn finish(&mut self, outcome: NativeRecoveryKeyReentryOutcome) {
        self.outcome = Some(outcome);
        if !self.dialog.is_null() {
            // SAFETY: `dialog` is the active synchronous modal dialog.
            unsafe { EndDialog(self.dialog, DIALOG_FINISHED) };
        }
    }

    fn unavailable(&mut self) {
        clear_and_destroy_best_effort(&mut self.entry);
        self.finish(NativeRecoveryKeyReentryOutcome::Unavailable);
    }

    fn cancel(&mut self) {
        clear_and_destroy_best_effort(&mut self.entry);
        self.finish(NativeRecoveryKeyReentryOutcome::Cancelled);
    }

    fn submit(&mut self) {
        let mut capture = match capture_entry(self.entry) {
            Ok(capture) => capture,
            Err(CaptureError::Rejected) => {
                if clear_entry_for_retry(self.entry) {
                    self.set_rejected_prompt();
                } else {
                    self.unavailable();
                }
                return;
            }
            Err(CaptureError::Unavailable) => {
                self.unavailable();
                return;
            }
        };
        match capture.submit() {
            Ok(entered) => {
                clear_and_destroy_best_effort(&mut self.entry);
                self.finish(NativeRecoveryKeyReentryOutcome::Submitted(entered));
            }
            Err(()) => {
                if clear_entry_for_retry(self.entry) {
                    self.set_rejected_prompt();
                } else {
                    self.unavailable();
                }
            }
        }
    }

    fn set_rejected_prompt(&self) {
        // SAFETY: prompt is a live STATIC and the text is static NUL-terminated UTF-16.
        unsafe {
            SetWindowTextW(
                self.prompt,
                windows_sys::w!("The complete record was not accepted. Re-enter it from paper."),
            )
        };
    }
}

#[repr(align(4))]
struct DialogTemplateBuffer([u16; 128]);

impl DialogTemplateBuffer {
    fn new() -> Result<Self, ()> {
        let mut result = Self([0; 128]);
        let style = WS_CAPTION | WS_SYSMENU | (DS_MODALFRAME as u32) | (DS_CENTER as u32);
        let mut cursor = 0;
        write_u32(&mut result.0, &mut cursor, style)?;
        write_u32(&mut result.0, &mut cursor, 0)?;
        write_u16(&mut result.0, &mut cursor, 0)?;
        for value in [0_i16, 0, 330, 235] {
            write_u16(&mut result.0, &mut cursor, value as u16)?;
        }
        write_u16(&mut result.0, &mut cursor, 0)?;
        write_u16(&mut result.0, &mut cursor, 0)?;
        write_ascii_wide(&mut result.0, &mut cursor, b"Recovery key re-entry")?;
        Ok(result)
    }

    fn as_ptr(&self) -> *const windows_sys::Win32::UI::WindowsAndMessaging::DLGTEMPLATE {
        self.0.as_ptr().cast()
    }
}

pub(crate) fn request_native_recovery_key_reentry(parent: HWND) -> NativeRecoveryKeyReentryOutcome {
    let template = match DialogTemplateBuffer::new() {
        Ok(template) => template,
        Err(()) => return NativeRecoveryKeyReentryOutcome::Unavailable,
    };
    // SAFETY: this only checks whether the proposed owner is a live window.
    if parent.is_null() || unsafe { IsWindow(parent) } == 0 {
        return NativeRecoveryKeyReentryOutcome::Unavailable;
    }
    let mut context = DialogContext::new();
    // SAFETY: the template is aligned and valid, and context outlives the synchronous modal call.
    let result = unsafe {
        DialogBoxIndirectParamW(
            null_mut(),
            template.as_ptr(),
            parent,
            Some(dialog_proc),
            (&mut context as *mut DialogContext) as LPARAM,
        )
    };
    context.outcome.unwrap_or_else(|| {
        let _ = result;
        clear_and_destroy_best_effort(&mut context.entry);
        NativeRecoveryKeyReentryOutcome::Unavailable
    })
}

unsafe extern "system" fn dialog_proc(
    dialog: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    let context_pointer = if message == WM_INITDIALOG {
        lparam as *mut DialogContext
    } else {
        // SAFETY: USER32 supplies a dialog HWND.
        unsafe { GetWindowLongPtrW(dialog, GWLP_USERDATA) as *mut DialogContext }
    };
    match catch_unwind(AssertUnwindSafe(|| unsafe {
        dialog_proc_inner(dialog, message, wparam, context_pointer)
    })) {
        Ok(value) => value,
        Err(_) => {
            // SAFETY: a non-null pointer refers to the synchronous caller-owned context.
            if let Some(context) = unsafe { context_pointer.as_mut() } {
                context.unavailable();
            } else {
                // A panic before context installation cannot safely resume through USER32.
                std::process::abort();
            }
            1
        }
    }
}

unsafe fn dialog_proc_inner(
    dialog: HWND,
    message: u32,
    wparam: WPARAM,
    context_pointer: *mut DialogContext,
) -> isize {
    let Some(context) = (unsafe { context_pointer.as_mut() }) else {
        return 0;
    };
    match message {
        WM_INITDIALOG => {
            context.dialog = dialog;
            // SAFETY: context remains valid for the synchronous modal lifetime.
            unsafe { SetWindowLongPtrW(dialog, GWLP_USERDATA, context_pointer as isize) };
            if unsafe { create_controls(context) }.is_err() {
                context.unavailable();
            }
            1
        }
        WM_COMMAND => {
            let identifier = (wparam & 0xffff) as i32;
            if identifier == IDOK {
                context.submit();
                1
            } else if identifier == IDCANCEL {
                context.cancel();
                1
            } else {
                0
            }
        }
        WM_CLOSE => {
            context.cancel();
            1
        }
        WM_NCDESTROY => {
            // SAFETY: remove the borrowed pointer before destruction completes.
            unsafe { SetWindowLongPtrW(dialog, GWLP_USERDATA, 0) };
            0
        }
        _ => 0,
    }
}

unsafe fn create_controls(context: &mut DialogContext) -> Result<(), ()> {
    context.prompt = unsafe {
        create_control(
            windows_sys::w!("STATIC"),
            windows_sys::w!(
                "Enter one complete recovery key record from paper. Clipboard operations are disabled."
            ),
            WS_CHILD | WS_VISIBLE | STATIC_NO_PREFIX,
            (16, 14, 448, 36),
            context.dialog,
            CONTROL_PROMPT,
        )?
    };
    context.entry = unsafe {
        create_control(
            windows_sys::w!("EDIT"),
            windows_sys::w!(""),
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | WS_BORDER
                | WS_VSCROLL
                | (ES_MULTILINE as u32)
                | (ES_AUTOVSCROLL as u32)
                | (ES_WANTRETURN as u32),
            (16, 54, 448, 190),
            context.dialog,
            CONTROL_ENTRY,
        )?
    };
    unsafe {
        create_control(
            windows_sys::w!("BUTTON"),
            windows_sys::w!("Submit"),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_DEFPUSHBUTTON as u32),
            (272, 258, 92, 28),
            context.dialog,
            IDOK,
        )?;
        create_control(
            windows_sys::w!("BUTTON"),
            windows_sys::w!("Cancel"),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_PUSHBUTTON as u32),
            (372, 258, 92, 28),
            context.dialog,
            IDCANCEL,
        )?;
        SendMessageW(context.entry, EM_SETLIMITTEXT, NATIVE_TEXT_LIMIT, 0);
    }
    context.entry_previous = unsafe { subclass_entry(context.entry, context)? };
    // SAFETY: entry is a live visible child of the modal dialog.
    unsafe { SetFocus(context.entry) };
    Ok(())
}

unsafe fn create_control(
    class: *const u16,
    text: *const u16,
    style: u32,
    bounds: (i32, i32, i32, i32),
    parent: HWND,
    identifier: i32,
) -> Result<HWND, ()> {
    let (x, y, width, height) = bounds;
    // SAFETY: strings are static NUL-terminated UTF-16 and parent is the live dialog.
    let control = unsafe {
        CreateWindowExW(
            0,
            class,
            text,
            style,
            x,
            y,
            width,
            height,
            parent,
            identifier as usize as *mut core::ffi::c_void,
            null_mut(),
            null(),
        )
    };
    (!control.is_null()).then_some(control).ok_or(())
}

unsafe fn subclass_entry(control: HWND, context: &mut DialogContext) -> Result<WNDPROC, ()> {
    // SAFETY: attach context before replacing the window procedure.
    unsafe {
        SetWindowLongPtrW(
            control,
            GWLP_USERDATA,
            context as *mut DialogContext as isize,
        )
    };
    // SAFETY: the replacement has the required Win32 callback ABI.
    let previous = unsafe {
        SetWindowLongPtrW(
            control,
            GWLP_WNDPROC,
            entry_proc as *const () as usize as isize,
        )
    };
    if previous == 0 {
        Err(())
    } else {
        // SAFETY: USER32 returned the prior WNDPROC address for this exact control.
        Ok(unsafe { std::mem::transmute::<isize, WNDPROC>(previous) })
    }
}

unsafe extern "system" fn entry_proc(
    control: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let context_pointer =
        unsafe { GetWindowLongPtrW(control, GWLP_USERDATA) as *mut DialogContext };
    match catch_unwind(AssertUnwindSafe(|| unsafe {
        entry_proc_inner(control, message, wparam, lparam, context_pointer)
    })) {
        Ok(value) => value,
        Err(_) => {
            if let Some(context) = unsafe { context_pointer.as_mut() } {
                context.unavailable();
            } else {
                std::process::abort();
            }
            0
        }
    }
}

unsafe fn entry_proc_inner(
    control: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    context_pointer: *mut DialogContext,
) -> LRESULT {
    let Some(context) = (unsafe { context_pointer.as_ref() }) else {
        return 0;
    };
    if should_suppress_entry_message(message, wparam) {
        return 0;
    }
    // SAFETY: this procedure was returned by USER32 for this exact live control.
    unsafe { CallWindowProcW(context.entry_previous, control, message, wparam, lparam) }
}

fn should_suppress_entry_message(message: u32, wparam: WPARAM) -> bool {
    if matches!(
        message,
        WM_COPY | WM_CUT | WM_PASTE | WM_CONTEXTMENU | WM_DROPFILES
    ) {
        return true;
    }
    if message != WM_KEYDOWN {
        return false;
    }
    let key = wparam as u16;
    // SAFETY: these calls only inspect the calling UI thread keyboard-message state.
    let control = unsafe { GetKeyState(VK_CONTROL as i32) } < 0;
    let shift = unsafe { GetKeyState(VK_SHIFT as i32) } < 0;
    (control && matches!(key, VK_C | VK_V | VK_X | VK_INSERT))
        || (shift && matches!(key, VK_INSERT | VK_DELETE))
}

enum CaptureError {
    Rejected,
    Unavailable,
}

fn capture_entry(control: HWND) -> Result<NativeEntryCapture, CaptureError> {
    if control.is_null() {
        return Err(CaptureError::Unavailable);
    }
    // SAFETY: control is a live EDIT.
    let reported = unsafe { GetWindowTextLengthW(control) };
    if reported < 0 || reported as usize > NATIVE_TEXT_LIMIT {
        return Err(CaptureError::Unavailable);
    }
    let mut units = Zeroizing::new([0_u16; NATIVE_BUFFER_LENGTH]);
    // SAFETY: the fixed buffer includes the advertised terminator capacity.
    let copied =
        unsafe { GetWindowTextW(control, units.as_mut_ptr(), NATIVE_BUFFER_LENGTH as i32) };
    if copied < 0 || copied != reported || units[copied as usize] != 0 {
        return Err(CaptureError::Unavailable);
    }
    NativeEntryCapture::from_utf16(&units[..copied as usize]).map_err(|()| CaptureError::Rejected)
}

fn clear_entry_for_retry(control: HWND) -> bool {
    !control.is_null()
        // SAFETY: control is a live EDIT and the replacement is an empty static string.
        && unsafe { SetWindowTextW(control, windows_sys::w!("")) } != 0
}

fn clear_and_destroy_best_effort(control: &mut HWND) {
    if control.is_null() {
        return;
    }
    // SAFETY: the control is a dialog child. Clearing happens before destruction.
    unsafe {
        SetWindowTextW(*control, windows_sys::w!(""));
        DestroyWindow(*control);
    }
    *control = null_mut();
}

fn write_u16(buffer: &mut [u16], cursor: &mut usize, value: u16) -> Result<(), ()> {
    let slot = buffer.get_mut(*cursor).ok_or(())?;
    *slot = value;
    *cursor += 1;
    Ok(())
}

fn write_u32(buffer: &mut [u16], cursor: &mut usize, value: u32) -> Result<(), ()> {
    write_u16(buffer, cursor, value as u16)?;
    write_u16(buffer, cursor, (value >> 16) as u16)
}

fn write_ascii_wide(buffer: &mut [u16], cursor: &mut usize, value: &[u8]) -> Result<(), ()> {
    if !value.is_ascii() {
        return Err(());
    }
    for byte in value {
        write_u16(buffer, cursor, *byte as u16)?;
    }
    write_u16(buffer, cursor, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    const GOLDEN: &[u8; 196] = b"CHURCH-MIGRATION-RECOVERY-KEY-V1\nGEN-000G-40R4-0M30-E209-185G-R38E-1W\nSET-208H-44RM-2MB1-E60S-38DH-R78Y-3W\nKEY-40GJ-48S4-4MK2-EA19-58NJ-RB9E-5WR3-2CHK-6GTK-CDSR-74X3-PF1X-7RZG\nCHK-0G5D-X575-NG3C-8";

    fn capture(input: &[u8]) -> NativeEntryCapture {
        NativeEntryCapture::from_utf16(&input.iter().copied().map(u16::from).collect::<Vec<_>>())
            .unwrap()
    }

    #[test]
    fn canonical_and_crlf_records_submit_as_one_exact_typed_owner_and_clear_capture() {
        let mut canonical = capture(GOLDEN);
        let entered = canonical.submit().unwrap();
        assert!(entered.matches_bounded_entry_for_test(GOLDEN));
        assert_eq!(canonical.used, 0);
        assert!(canonical.bytes.iter().all(|byte| *byte == 0));

        let crlf = String::from_utf8(GOLDEN.to_vec())
            .unwrap()
            .replace('\n', "\r\n");
        let mut crlf_capture = capture(crlf.as_bytes());
        let entered = crlf_capture.submit().unwrap();
        assert!(entered.matches_bounded_entry_for_test(crlf.as_bytes()));
        assert_eq!(crlf_capture.used, 0);
        assert!(crlf_capture.bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn malformed_submission_and_cancellation_clear_the_bounded_capture() {
        let mut malformed = capture(b"short");
        assert!(malformed.submit().is_err());
        assert_eq!(malformed.used, 0);
        assert!(malformed.bytes.iter().all(|byte| *byte == 0));

        let mut cancelled = capture(GOLDEN);
        cancelled.cancel();
        assert_eq!(cancelled.used, 0);
        assert!(cancelled.bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn outcomes_are_opaque_redacted_and_non_owning_when_not_submitted() {
        let submitted =
            NativeRecoveryKeyReentryOutcome::Submitted(capture(GOLDEN).submit().unwrap());
        assert_eq!(
            format!("{submitted:?}"),
            "NativeRecoveryKeyReentryOutcome::Submitted([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", NativeRecoveryKeyReentryOutcome::Cancelled),
            "NativeRecoveryKeyReentryOutcome::Cancelled"
        );
        assert_eq!(
            format!("{:?}", NativeRecoveryKeyReentryOutcome::Unavailable),
            "NativeRecoveryKeyReentryOutcome::Unavailable"
        );
    }

    #[test]
    fn native_adapter_is_bounded_clipboard_blocked_and_has_no_frontend_surface() {
        for message in [WM_COPY, WM_CUT, WM_PASTE, WM_CONTEXTMENU, WM_DROPFILES] {
            assert!(should_suppress_entry_message(message, 0));
        }
        assert_eq!(NATIVE_TEXT_LIMIT, 200);
        let source = include_str!("native_recovery_key_reentry.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(production.contains("ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry"));
        for forbidden in [
            "validate_checksum",
            "into_recovery_key_material",
            "serde::",
            "Serialize",
            "tauri::command",
            "invoke_handler",
            "clipboard",
            "println!",
            "dbg!",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden adapter token: {forbidden}"
            );
        }
        assert!(!production.contains("WS_EX_ACCEPTFILES"));
        let lifecycle = include_str!("application_lifecycle.rs");
        assert!(!lifecycle.contains("request_native_recovery_key_reentry"));
        assert!(!lifecycle.contains("NativeRecoveryKeyReentryOutcome"));
    }
}
