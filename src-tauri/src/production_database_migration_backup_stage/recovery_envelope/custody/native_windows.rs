//! Private Win32 adapter for the unwired migration recovery-key custody ceremony.

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
            GetKeyState, SetFocus, VK_C, VK_CONTROL, VK_INSERT, VK_SHIFT, VK_V, VK_X,
        },
        WindowsAndMessaging::{
            BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CallWindowProcW, CreateWindowExW, DS_CENTER,
            DS_MODALFRAME, DestroyWindow, DialogBoxIndirectParamW, ES_AUTOVSCROLL, ES_MULTILINE,
            ES_WANTRETURN, EndDialog, GWLP_USERDATA, GWLP_WNDPROC, GetWindowLongPtrW,
            GetWindowTextLengthW, GetWindowTextW, IDCANCEL, IDOK, IsWindow, SW_HIDE, SW_SHOW,
            SendMessageW, SetWindowLongPtrW, SetWindowTextW, ShowWindow, WM_CLOSE, WM_COMMAND,
            WM_CONTEXTMENU, WM_COPY, WM_CUT, WM_INITDIALOG, WM_KEYDOWN, WM_NCDESTROY, WM_PASTE,
            WNDPROC, WS_BORDER, WS_CAPTION, WS_CHILD, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
            WS_VSCROLL,
        },
    },
};
use zeroize::{Zeroize, Zeroizing};

use super::{
    DisclosedMigrationRecoveryKeyCustody, FirstCopyVerifiedMigrationRecoveryKeyCustody,
    MigrationRecoveryKeyCustodyError, PossiblyExposedMigrationRecoveryKeyCustodyFailure,
    PreparedUndisclosedMigrationRecoveryKeyCustody,
    RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup,
    UndisclosedMigrationRecoveryKeyCustodyInterruption, terminal_failure,
};

const DISPLAY_SOURCE_LENGTH: usize = 196;
const NATIVE_TEXT_LIMIT: usize = 200;
const NATIVE_BUFFER_LENGTH: usize = NATIVE_TEXT_LIMIT + 1;
const CONTROL_PROMPT: i32 = 1001;
const CONTROL_DISPLAY_ONE: i32 = 1002;
const CONTROL_READBACK_ONE: i32 = 1003;
const CONTROL_DISPLAY_TWO: i32 = 1004;
const CONTROL_READBACK_TWO: i32 = 1005;
const DIALOG_FINISHED: isize = 1;
const STATIC_NO_PREFIX: u32 = 0x80;

#[must_use = "the native custody outcome owns migration custody state"]
pub(crate) enum NativeMigrationRecoveryKeyCustodyOutcome {
    Verified(RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup),
    InterruptedBeforeExposure(UndisclosedMigrationRecoveryKeyCustodyInterruption),
    UnavailableBeforeExposure(PreparedUndisclosedMigrationRecoveryKeyCustody),
    FailedAfterExposure(PossiblyExposedMigrationRecoveryKeyCustodyFailure),
}

impl fmt::Debug for NativeMigrationRecoveryKeyCustodyOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Verified(_) => "NativeMigrationRecoveryKeyCustodyOutcome::Verified([REDACTED])",
            Self::InterruptedBeforeExposure(_) => {
                "NativeMigrationRecoveryKeyCustodyOutcome::InterruptedBeforeExposure([REDACTED])"
            }
            Self::UnavailableBeforeExposure(_) => {
                "NativeMigrationRecoveryKeyCustodyOutcome::UnavailableBeforeExposure([REDACTED])"
            }
            Self::FailedAfterExposure(_) => {
                "NativeMigrationRecoveryKeyCustodyOutcome::FailedAfterExposure([REDACTED])"
            }
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CeremonyPage {
    Intro,
    RevealOne,
    ReadbackOne,
    RevealTwo,
    ReadbackTwo,
    Success,
}

enum CustodyOwner {
    Prepared(PreparedUndisclosedMigrationRecoveryKeyCustody),
    Disclosed(DisclosedMigrationRecoveryKeyCustody),
    FirstCopyVerified(FirstCopyVerifiedMigrationRecoveryKeyCustody),
    Empty,
}

struct DialogControls {
    prompt: HWND,
    display_one: HWND,
    readback_one: HWND,
    display_two: HWND,
    readback_two: HWND,
    primary: HWND,
    cancel: HWND,
    display_one_previous: WNDPROC,
    readback_one_previous: WNDPROC,
    display_two_previous: WNDPROC,
    readback_two_previous: WNDPROC,
}

impl DialogControls {
    fn empty() -> Self {
        Self {
            prompt: null_mut(),
            display_one: null_mut(),
            readback_one: null_mut(),
            display_two: null_mut(),
            readback_two: null_mut(),
            primary: null_mut(),
            cancel: null_mut(),
            display_one_previous: None,
            readback_one_previous: None,
            display_two_previous: None,
            readback_two_previous: None,
        }
    }
}

struct DialogContext {
    dialog: HWND,
    page: CeremonyPage,
    owner: CustodyOwner,
    outcome: Option<NativeMigrationRecoveryKeyCustodyOutcome>,
    controls: DialogControls,
}

impl DialogContext {
    fn new(prepared: PreparedUndisclosedMigrationRecoveryKeyCustody) -> Self {
        Self {
            dialog: null_mut(),
            page: CeremonyPage::Intro,
            owner: CustodyOwner::Prepared(prepared),
            outcome: None,
            controls: DialogControls::empty(),
        }
    }

    fn finish(&mut self, outcome: NativeMigrationRecoveryKeyCustodyOutcome) {
        self.outcome = Some(outcome);
        self.owner = CustodyOwner::Empty;
        if !self.dialog.is_null() {
            // SAFETY: `dialog` is the active modal dialog owned by this callback context.
            unsafe { EndDialog(self.dialog, DIALOG_FINISHED) };
        }
    }

    fn fail_native_after_exposure(&mut self) {
        let owner = std::mem::replace(&mut self.owner, CustodyOwner::Empty);
        let failure = match owner {
            CustodyOwner::Disclosed(owner) => terminal_failure(
                owner.backup,
                owner.encoded,
                MigrationRecoveryKeyCustodyError::NativeCeremonyFailedAfterCustodyExposure,
            ),
            CustodyOwner::FirstCopyVerified(owner) => terminal_failure(
                owner.backup,
                owner.encoded,
                MigrationRecoveryKeyCustodyError::NativeCeremonyFailedAfterCustodyExposure,
            ),
            CustodyOwner::Prepared(owner) => {
                self.finish(
                    NativeMigrationRecoveryKeyCustodyOutcome::UnavailableBeforeExposure(owner),
                );
                return;
            }
            CustodyOwner::Empty => return,
        };
        self.finish(NativeMigrationRecoveryKeyCustodyOutcome::FailedAfterExposure(failure));
    }

    fn cancel(&mut self) {
        if self.page == CeremonyPage::Success && self.outcome.is_some() {
            // SAFETY: success retains only the keyless verified outcome in the active dialog.
            unsafe { EndDialog(self.dialog, DIALOG_FINISHED) };
            return;
        }
        let owner = std::mem::replace(&mut self.owner, CustodyOwner::Empty);
        let outcome = match owner {
            CustodyOwner::Prepared(owner) => {
                NativeMigrationRecoveryKeyCustodyOutcome::InterruptedBeforeExposure(
                    owner.cancel_before_exposure(),
                )
            }
            CustodyOwner::Disclosed(owner) => {
                NativeMigrationRecoveryKeyCustodyOutcome::FailedAfterExposure(owner.cancel())
            }
            CustodyOwner::FirstCopyVerified(owner) => {
                NativeMigrationRecoveryKeyCustodyOutcome::FailedAfterExposure(owner.cancel())
            }
            CustodyOwner::Empty => return,
        };
        self.finish(outcome);
    }

    fn handle_primary(&mut self) {
        let result = match self.page {
            CeremonyPage::Intro => self.begin_first_reveal(),
            CeremonyPage::RevealOne => self.begin_first_readback(),
            CeremonyPage::ReadbackOne => self.verify_first_readback(),
            CeremonyPage::RevealTwo => self.begin_second_readback(),
            CeremonyPage::ReadbackTwo => self.verify_second_readback(),
            CeremonyPage::Success => {
                // SAFETY: the verified outcome is already stored and the dialog is active.
                unsafe { EndDialog(self.dialog, DIALOG_FINISHED) };
                Ok(())
            }
        };
        if result.is_err() {
            self.fail_native_after_exposure();
        }
    }

    fn begin_first_reveal(&mut self) -> Result<(), ()> {
        let prepared = match std::mem::replace(&mut self.owner, CustodyOwner::Empty) {
            CustodyOwner::Prepared(owner) => owner,
            other => {
                self.owner = other;
                return Err(());
            }
        };
        self.owner = CustodyOwner::Disclosed(prepared.disclose());
        self.page = CeremonyPage::RevealOne;
        self.set_nonsecret_text(
            windows_sys::w!("Write the complete recovery key record on paper copy 1."),
            windows_sys::w!("Paper copy 1 written"),
        )?;
        self.display_current_record(self.controls.display_one)?;
        show_and_focus(self.controls.display_one, self.controls.primary)
    }

    fn begin_first_readback(&mut self) -> Result<(), ()> {
        clear_and_destroy(&mut self.controls.display_one)?;
        self.page = CeremonyPage::ReadbackOne;
        self.set_nonsecret_text(
            windows_sys::w!("Enter paper copy 1 exactly. Clipboard operations are disabled."),
            windows_sys::w!("Verify paper copy 1"),
        )?;
        show_and_focus(self.controls.readback_one, self.controls.readback_one)
    }

    fn verify_first_readback(&mut self) -> Result<(), ()> {
        let readback = capture_readback(self.controls.readback_one)?;
        clear_and_destroy(&mut self.controls.readback_one)?;
        let disclosed = match std::mem::replace(&mut self.owner, CustodyOwner::Empty) {
            CustodyOwner::Disclosed(owner) => owner,
            other => {
                self.owner = other;
                return Err(());
            }
        };
        match disclosed.verify_first_copy(readback.as_bytes()) {
            Ok(first) => self.owner = CustodyOwner::FirstCopyVerified(first),
            Err(failure) => {
                self.finish(NativeMigrationRecoveryKeyCustodyOutcome::FailedAfterExposure(failure));
                return Ok(());
            }
        }
        self.page = CeremonyPage::RevealTwo;
        self.set_nonsecret_text(
            windows_sys::w!("Write the complete recovery key record on independent paper copy 2."),
            windows_sys::w!("Paper copy 2 written"),
        )?;
        self.display_current_record(self.controls.display_two)?;
        show_and_focus(self.controls.display_two, self.controls.primary)
    }

    fn begin_second_readback(&mut self) -> Result<(), ()> {
        clear_and_destroy(&mut self.controls.display_two)?;
        self.page = CeremonyPage::ReadbackTwo;
        self.set_nonsecret_text(
            windows_sys::w!("Enter paper copy 2 exactly. Clipboard operations are disabled."),
            windows_sys::w!("Verify paper copy 2"),
        )?;
        show_and_focus(self.controls.readback_two, self.controls.readback_two)
    }

    fn verify_second_readback(&mut self) -> Result<(), ()> {
        let readback = capture_readback(self.controls.readback_two)?;
        clear_and_destroy(&mut self.controls.readback_two)?;
        let first = match std::mem::replace(&mut self.owner, CustodyOwner::Empty) {
            CustodyOwner::FirstCopyVerified(owner) => owner,
            other => {
                self.owner = other;
                return Err(());
            }
        };
        match first.verify_second_copy(readback.as_bytes()) {
            Ok(verified) => {
                self.page = CeremonyPage::Success;
                self.owner = CustodyOwner::Empty;
                self.outcome = Some(NativeMigrationRecoveryKeyCustodyOutcome::Verified(verified));
                let presented = self
                    .set_nonsecret_text(
                        windows_sys::w!("Both complete paper copies were independently verified."),
                        windows_sys::w!("Finish"),
                    )
                    .and_then(|()| show_and_focus(self.controls.primary, self.controls.primary));
                // SAFETY: cancel is a live non-secret dialog control.
                unsafe { ShowWindow(self.controls.cancel, SW_HIDE) };
                if presented.is_err() {
                    // Verification is already complete and keyless; confirmation rendering cannot
                    // turn that result back into an exposed custody owner.
                    unsafe { EndDialog(self.dialog, DIALOG_FINISHED) };
                }
            }
            Err(failure) => {
                self.finish(NativeMigrationRecoveryKeyCustodyOutcome::FailedAfterExposure(failure))
            }
        }
        Ok(())
    }

    fn display_current_record(&self, control: HWND) -> Result<(), ()> {
        let operation = |bytes: &[u8; DISPLAY_SOURCE_LENGTH]| {
            let display = NativeDisplayBuffer::from_canonical(bytes)?;
            // SAFETY: `control` is a live STATIC and `display` is explicitly NUL-terminated.
            let changed = unsafe { SetWindowTextW(control, display.as_ptr()) } != 0;
            drop(display);
            changed.then_some(()).ok_or(())
        };
        match &self.owner {
            CustodyOwner::Disclosed(owner) => owner.encoded.with_native_display_bytes(operation),
            CustodyOwner::FirstCopyVerified(owner) => {
                owner.encoded.with_native_display_bytes(operation)
            }
            CustodyOwner::Prepared(_) | CustodyOwner::Empty => Err(()),
        }
    }

    fn set_nonsecret_text(&self, prompt: *const u16, primary: *const u16) -> Result<(), ()> {
        // SAFETY: the handles are live controls and both pointers address static NUL-terminated text.
        let prompt_set = unsafe { SetWindowTextW(self.controls.prompt, prompt) } != 0;
        // SAFETY: same as above.
        let primary_set = unsafe { SetWindowTextW(self.controls.primary, primary) } != 0;
        (prompt_set && primary_set).then_some(()).ok_or(())
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
        write_ascii_wide(
            &mut result.0,
            &mut cursor,
            b"Recovery key paper-copy ceremony",
        )?;
        Ok(result)
    }

    fn as_ptr(&self) -> *const windows_sys::Win32::UI::WindowsAndMessaging::DLGTEMPLATE {
        self.0.as_ptr().cast()
    }
}

struct NativeDisplayBuffer {
    units: [u16; NATIVE_BUFFER_LENGTH],
}

impl NativeDisplayBuffer {
    fn from_canonical(source: &[u8; DISPLAY_SOURCE_LENGTH]) -> Result<Self, ()> {
        let mut result = Self {
            units: [0; NATIVE_BUFFER_LENGTH],
        };
        let mut target = 0;
        let mut line_feeds = 0;
        for byte in source {
            if !byte.is_ascii() {
                return Err(());
            }
            if *byte == b'\n' {
                if target + 2 > NATIVE_TEXT_LIMIT {
                    return Err(());
                }
                result.units[target] = b'\r' as u16;
                target += 1;
                line_feeds += 1;
            }
            if target >= NATIVE_TEXT_LIMIT {
                return Err(());
            }
            result.units[target] = *byte as u16;
            target += 1;
        }
        if line_feeds != 4 || target != NATIVE_TEXT_LIMIT {
            return Err(());
        }
        result.units[NATIVE_TEXT_LIMIT] = 0;
        Ok(result)
    }

    fn as_ptr(&self) -> *const u16 {
        self.units.as_ptr()
    }
}

impl Drop for NativeDisplayBuffer {
    fn drop(&mut self) {
        self.units.zeroize();
    }
}

struct ReadbackAscii {
    bytes: Zeroizing<[u8; NATIVE_TEXT_LIMIT]>,
    used: usize,
}

impl ReadbackAscii {
    fn from_utf16(units: &[u16]) -> Result<Self, ()> {
        if units.len() > NATIVE_TEXT_LIMIT {
            return Err(());
        }
        let mut bytes = Zeroizing::new([0; NATIVE_TEXT_LIMIT]);
        for (index, unit) in units.iter().copied().enumerate() {
            if unit > 0x7f {
                return Err(());
            }
            bytes[index] = unit as u8;
        }
        Ok(Self {
            bytes,
            used: units.len(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.used]
    }
}

pub(crate) fn run_migration_recovery_key_custody_native_ceremony(
    prepared: PreparedUndisclosedMigrationRecoveryKeyCustody,
    parent: HWND,
) -> NativeMigrationRecoveryKeyCustodyOutcome {
    let template = match DialogTemplateBuffer::new() {
        Ok(template) => template,
        Err(()) => {
            return NativeMigrationRecoveryKeyCustodyOutcome::UnavailableBeforeExposure(prepared);
        }
    };
    // SAFETY: this is a read-only validity check of the caller-supplied proposed owner HWND.
    if parent.is_null() || unsafe { IsWindow(parent) } == 0 {
        return NativeMigrationRecoveryKeyCustodyOutcome::UnavailableBeforeExposure(prepared);
    }
    let mut context = DialogContext::new(prepared);
    // SAFETY: the aligned template is valid; context outlives the synchronous modal call; every
    // callback contains unwinding before returning to USER32.
    let modal_result = unsafe {
        DialogBoxIndirectParamW(
            null_mut(),
            template.as_ptr(),
            parent,
            Some(dialog_proc),
            (&mut context as *mut DialogContext) as LPARAM,
        )
    };
    if let Some(outcome) = context.outcome {
        return outcome;
    }
    let owner = std::mem::replace(&mut context.owner, CustodyOwner::Empty);
    match owner {
        CustodyOwner::Prepared(owner) => {
            NativeMigrationRecoveryKeyCustodyOutcome::UnavailableBeforeExposure(owner)
        }
        CustodyOwner::Disclosed(owner) => {
            let category =
                MigrationRecoveryKeyCustodyError::NativeCeremonyFailedAfterCustodyExposure;
            NativeMigrationRecoveryKeyCustodyOutcome::FailedAfterExposure(terminal_failure(
                owner.backup,
                owner.encoded,
                category,
            ))
        }
        CustodyOwner::FirstCopyVerified(owner) => {
            let category =
                MigrationRecoveryKeyCustodyError::NativeCeremonyFailedAfterCustodyExposure;
            NativeMigrationRecoveryKeyCustodyOutcome::FailedAfterExposure(terminal_failure(
                owner.backup,
                owner.encoded,
                category,
            ))
        }
        CustodyOwner::Empty => {
            let _ = modal_result;
            std::process::abort()
        }
    }
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
        // SAFETY: USER32 calls this function only with a dialog HWND.
        unsafe { GetWindowLongPtrW(dialog, GWLP_USERDATA) as *mut DialogContext }
    };
    let processed = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the pointer comes from the synchronous caller and is installed at WM_INITDIALOG.
        unsafe { dialog_proc_inner(dialog, message, wparam, context_pointer) }
    }));
    match processed {
        Ok(value) => value,
        Err(_) => {
            // SAFETY: a non-null pointer still refers to the live synchronous dialog context.
            unsafe { recover_callback_panic(context_pointer) };
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
            // SAFETY: the pointer remains valid for the synchronous modal dialog lifetime.
            unsafe { SetWindowLongPtrW(dialog, GWLP_USERDATA, context_pointer as isize) };
            if unsafe { create_controls(context) }.is_err() {
                context.fail_native_after_exposure();
            }
            1
        }
        WM_COMMAND => {
            let identifier = (wparam & 0xffff) as i32;
            if identifier == IDOK {
                context.handle_primary();
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
            // SAFETY: clear the borrowed pointer before the native window ceases to exist.
            unsafe { SetWindowLongPtrW(dialog, GWLP_USERDATA, 0) };
            0
        }
        _ => 0,
    }
}

unsafe fn create_controls(context: &mut DialogContext) -> Result<(), ()> {
    let dialog = context.dialog;
    context.controls.prompt = unsafe {
        create_control(
            windows_sys::w!("STATIC"),
            windows_sys::w!("This ceremony requires two independent complete paper copies."),
            WS_CHILD | WS_VISIBLE | STATIC_NO_PREFIX,
            (16, 14, 448, 36),
            dialog,
            CONTROL_PROMPT,
        )?
    };
    context.controls.display_one = unsafe {
        create_control(
            windows_sys::w!("STATIC"),
            windows_sys::w!(""),
            WS_CHILD | STATIC_NO_PREFIX,
            (16, 54, 448, 190),
            dialog,
            CONTROL_DISPLAY_ONE,
        )?
    };
    context.controls.readback_one = unsafe {
        create_control(
            windows_sys::w!("EDIT"),
            windows_sys::w!(""),
            edit_style(),
            (16, 54, 448, 190),
            dialog,
            CONTROL_READBACK_ONE,
        )?
    };
    context.controls.display_two = unsafe {
        create_control(
            windows_sys::w!("STATIC"),
            windows_sys::w!(""),
            WS_CHILD | STATIC_NO_PREFIX,
            (16, 54, 448, 190),
            dialog,
            CONTROL_DISPLAY_TWO,
        )?
    };
    context.controls.readback_two = unsafe {
        create_control(
            windows_sys::w!("EDIT"),
            windows_sys::w!(""),
            edit_style(),
            (16, 54, 448, 190),
            dialog,
            CONTROL_READBACK_TWO,
        )?
    };
    context.controls.primary = unsafe {
        create_control(
            windows_sys::w!("BUTTON"),
            windows_sys::w!("Begin"),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_DEFPUSHBUTTON as u32),
            (272, 258, 92, 28),
            dialog,
            IDOK,
        )?
    };
    context.controls.cancel = unsafe {
        create_control(
            windows_sys::w!("BUTTON"),
            windows_sys::w!("Cancel"),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_PUSHBUTTON as u32),
            (372, 258, 92, 28),
            dialog,
            IDCANCEL,
        )?
    };
    for edit in [context.controls.readback_one, context.controls.readback_two] {
        // SAFETY: each handle is a live EDIT; this sets its hard UTF-16 input cap.
        unsafe { SendMessageW(edit, EM_SETLIMITTEXT, NATIVE_TEXT_LIMIT, 0) };
    }
    context.controls.display_one_previous = unsafe {
        subclass_control(
            context.controls.display_one,
            context,
            Some(display_control_proc),
        )?
    };
    context.controls.readback_one_previous = unsafe {
        subclass_control(
            context.controls.readback_one,
            context,
            Some(readback_control_proc),
        )?
    };
    context.controls.display_two_previous = unsafe {
        subclass_control(
            context.controls.display_two,
            context,
            Some(display_control_proc),
        )?
    };
    context.controls.readback_two_previous = unsafe {
        subclass_control(
            context.controls.readback_two,
            context,
            Some(readback_control_proc),
        )?
    };
    // SAFETY: primary is a visible child of this dialog.
    unsafe { SetFocus(context.controls.primary) };
    Ok(())
}

fn edit_style() -> u32 {
    WS_CHILD
        | WS_TABSTOP
        | WS_BORDER
        | WS_VSCROLL
        | (ES_MULTILINE as u32)
        | (ES_AUTOVSCROLL as u32)
        | (ES_WANTRETURN as u32)
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

unsafe fn subclass_control(
    control: HWND,
    context: &mut DialogContext,
    procedure: WNDPROC,
) -> Result<WNDPROC, ()> {
    // SAFETY: attach context before replacing the procedure.
    unsafe {
        SetWindowLongPtrW(
            control,
            GWLP_USERDATA,
            context as *mut DialogContext as isize,
        )
    };
    // SAFETY: the replacement has the Win32 callback ABI.
    let previous = unsafe {
        SetWindowLongPtrW(
            control,
            GWLP_WNDPROC,
            procedure.map(|value| value as usize as isize).unwrap_or(0),
        )
    };
    if previous == 0 {
        Err(())
    } else {
        // SAFETY: USER32 returned the previous WNDPROC address for this control.
        Ok(unsafe { std::mem::transmute::<isize, WNDPROC>(previous) })
    }
}

unsafe extern "system" fn display_control_proc(
    control: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe { guarded_control_proc(control, message, wparam, lparam, false) }
}

unsafe extern "system" fn readback_control_proc(
    control: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe { guarded_control_proc(control, message, wparam, lparam, true) }
}

unsafe fn guarded_control_proc(
    control: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    readback: bool,
) -> LRESULT {
    // SAFETY: userdata was installed before subclassing.
    let context_pointer =
        unsafe { GetWindowLongPtrW(control, GWLP_USERDATA) as *mut DialogContext };
    match catch_unwind(AssertUnwindSafe(|| unsafe {
        control_proc_inner(control, message, wparam, lparam, context_pointer, readback)
    })) {
        Ok(value) => value,
        Err(_) => {
            // SAFETY: pointer refers to the live synchronous context.
            unsafe { recover_callback_panic(context_pointer) };
            0
        }
    }
}

unsafe fn recover_callback_panic(context_pointer: *mut DialogContext) {
    let recovery = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller obtained this pointer from the live synchronous dialog/control.
        if let Some(context) = unsafe { context_pointer.as_mut() } {
            context.fail_native_after_exposure();
        }
    }));
    if recovery.is_err() {
        std::process::abort();
    }
}

unsafe fn control_proc_inner(
    control: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    context_pointer: *mut DialogContext,
    readback: bool,
) -> LRESULT {
    let Some(context) = (unsafe { context_pointer.as_ref() }) else {
        return 0;
    };
    if should_suppress_control_message(message, wparam, readback) {
        return 0;
    }
    let previous = if control == context.controls.display_one {
        context.controls.display_one_previous
    } else if control == context.controls.readback_one {
        context.controls.readback_one_previous
    } else if control == context.controls.display_two {
        context.controls.display_two_previous
    } else if control == context.controls.readback_two {
        context.controls.readback_two_previous
    } else {
        None
    };
    // SAFETY: previous was returned by USER32 for this exact control.
    unsafe { CallWindowProcW(previous, control, message, wparam, lparam) }
}

fn should_suppress_control_message(message: u32, wparam: WPARAM, readback: bool) -> bool {
    if matches!(message, WM_COPY | WM_CUT | WM_CONTEXTMENU) {
        return true;
    }
    if readback && message == WM_PASTE {
        return true;
    }
    if !readback || message != WM_KEYDOWN {
        return false;
    }
    let key = wparam as u16;
    // SAFETY: reads only the calling UI thread keyboard-message state.
    let control = unsafe { GetKeyState(VK_CONTROL as i32) } < 0;
    // SAFETY: same as above.
    let shift = unsafe { GetKeyState(VK_SHIFT as i32) } < 0;
    should_suppress_readback_key(key, control, shift)
}

fn should_suppress_readback_key(key: u16, control: bool, shift: bool) -> bool {
    (control && matches!(key, VK_V | VK_C | VK_X)) || (shift && key == VK_INSERT)
}

fn capture_readback(control: HWND) -> Result<ReadbackAscii, ()> {
    // SAFETY: control is a live EDIT.
    let reported = unsafe { GetWindowTextLengthW(control) };
    if reported < 0 || reported as usize > NATIVE_TEXT_LIMIT {
        return Err(());
    }
    let mut units = Zeroizing::new([0_u16; NATIVE_BUFFER_LENGTH]);
    // SAFETY: fixed buffer includes the advertised terminator capacity.
    let copied =
        unsafe { GetWindowTextW(control, units.as_mut_ptr(), NATIVE_BUFFER_LENGTH as i32) };
    if copied < 0 || copied != reported || units[copied as usize] != 0 {
        return Err(());
    }
    ReadbackAscii::from_utf16(&units[..copied as usize])
}

fn clear_and_destroy(control: &mut HWND) -> Result<(), ()> {
    if control.is_null() {
        return Err(());
    }
    // SAFETY: pointer is static empty UTF-16 and control is live at entry.
    let cleared = unsafe { SetWindowTextW(*control, windows_sys::w!("")) } != 0;
    // SAFETY: ceremony no longer uses this secret-bearing control.
    let destroyed = unsafe { DestroyWindow(*control) } != 0;
    *control = null_mut();
    (cleared && destroyed).then_some(()).ok_or(())
}

fn show_and_focus(control: HWND, focus: HWND) -> Result<(), ()> {
    if control.is_null() || focus.is_null() {
        return Err(());
    }
    // SAFETY: handles are live children of the active dialog.
    unsafe {
        ShowWindow(control, SW_SHOW);
        SetFocus(focus);
    }
    Ok(())
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
pub(super) fn contain_pre_exposure_panic_for_test(
    prepared: PreparedUndisclosedMigrationRecoveryKeyCustody,
) -> NativeMigrationRecoveryKeyCustodyOutcome {
    let mut context = DialogContext::new(prepared);
    let context_pointer = &mut context as *mut DialogContext;
    let caught = catch_unwind(AssertUnwindSafe(|| panic!("synthetic callback panic")));
    assert!(caught.is_err());
    // SAFETY: the pointer refers to the live local context.
    unsafe { recover_callback_panic(context_pointer) };
    context.outcome.unwrap_or_else(|| std::process::abort())
}

#[cfg(test)]
pub(super) fn contain_post_exposure_panic_for_test(
    prepared: PreparedUndisclosedMigrationRecoveryKeyCustody,
) -> NativeMigrationRecoveryKeyCustodyOutcome {
    let mut context = DialogContext::new(prepared);
    let prepared = match std::mem::replace(&mut context.owner, CustodyOwner::Empty) {
        CustodyOwner::Prepared(prepared) => prepared,
        _ => std::process::abort(),
    };
    context.owner = CustodyOwner::Disclosed(prepared.disclose());
    let context_pointer = &mut context as *mut DialogContext;
    let caught = catch_unwind(AssertUnwindSafe(|| panic!("synthetic callback panic")));
    assert!(caught.is_err());
    // SAFETY: the pointer refers to the live local context.
    unsafe { recover_callback_panic(context_pointer) };
    context.outcome.unwrap_or_else(|| std::process::abort())
}

#[cfg(test)]
mod tests {
    use std::mem::{needs_drop, size_of};

    use super::*;

    fn canonical_record() -> [u8; DISPLAY_SOURCE_LENGTH] {
        let mut record = [b'A'; DISPLAY_SOURCE_LENGTH];
        for index in [32, 69, 106, 175] {
            record[index] = b'\n';
        }
        record
    }

    #[test]
    fn display_conversion_is_exact_fixed_crlf_and_zeroizable() {
        let source = canonical_record();
        let display = NativeDisplayBuffer::from_canonical(&source).unwrap();
        assert_eq!(size_of::<NativeDisplayBuffer>(), NATIVE_BUFFER_LENGTH * 2);
        assert!(needs_drop::<NativeDisplayBuffer>());
        assert_eq!(display.units[NATIVE_TEXT_LIMIT], 0);
        let mut expected = Vec::with_capacity(NATIVE_TEXT_LIMIT);
        for byte in source {
            if byte == b'\n' {
                expected.push(b'\r' as u16);
            }
            expected.push(byte as u16);
        }
        assert_eq!(&display.units[..NATIVE_TEXT_LIMIT], expected.as_slice());
        assert_eq!(
            display
                .units
                .iter()
                .filter(|unit| **unit == b'\r' as u16)
                .count(),
            4
        );
        assert_eq!(
            display
                .units
                .iter()
                .filter(|unit| **unit == b'\n' as u16)
                .count(),
            4
        );
    }

    #[test]
    fn display_conversion_rejects_impossible_noncanonical_shapes() {
        let mut wrong_separator_count = canonical_record();
        wrong_separator_count[32] = b'A';
        assert!(NativeDisplayBuffer::from_canonical(&wrong_separator_count).is_err());
        let mut non_ascii = canonical_record();
        non_ascii[0] = 0xff;
        assert!(NativeDisplayBuffer::from_canonical(&non_ascii).is_err());
    }

    #[test]
    fn readback_conversion_is_bounded_ascii_and_preserves_exact_units() {
        let lf = vec![b'A' as u16; 196];
        assert_eq!(
            ReadbackAscii::from_utf16(&lf).unwrap().as_bytes(),
            vec![b'A'; 196]
        );
        let mut crlf = vec![b'A' as u16; 200];
        crlf[32] = b'\r' as u16;
        crlf[33] = b'\n' as u16;
        let converted = ReadbackAscii::from_utf16(&crlf).unwrap();
        assert_eq!(converted.as_bytes()[32..34], *b"\r\n");
        assert!(ReadbackAscii::from_utf16(&[b'A' as u16; 201]).is_err());
        assert!(ReadbackAscii::from_utf16(&[0x80]).is_err());
        assert_eq!(
            ReadbackAscii::from_utf16(&[b'a' as u16, b' ' as u16, b'\r' as u16])
                .unwrap()
                .as_bytes(),
            b"a \r"
        );
    }

    #[test]
    fn direct_clipboard_messages_are_suppressed_without_clipboard_access() {
        for message in [WM_COPY, WM_CUT, WM_CONTEXTMENU] {
            assert!(should_suppress_control_message(message, 0, false));
            assert!(should_suppress_control_message(message, 0, true));
        }
        assert!(should_suppress_control_message(WM_PASTE, 0, true));
        assert!(!should_suppress_control_message(WM_PASTE, 0, false));
        assert!(!should_suppress_control_message(
            WM_KEYDOWN,
            b'A' as usize,
            true
        ));
        for key in [VK_V, VK_C, VK_X] {
            assert!(should_suppress_readback_key(key, true, false));
        }
        assert!(should_suppress_readback_key(VK_INSERT, false, true));
        for key in [b'A' as u16, VK_INSERT, VK_V, VK_C, VK_X] {
            assert!(!should_suppress_readback_key(key, false, false));
        }
        assert!(!should_suppress_readback_key(b'A' as u16, true, true));
    }

    #[test]
    fn source_has_required_native_shape_redaction_and_exclusions() {
        let source = include_str!("native_windows.rs")
            .split_once("#[cfg(test)]")
            .unwrap()
            .0;
        for required in [
            "VK_V | VK_C | VK_X",
            "shift && key == VK_INSERT",
            "DialogBoxIndirectParamW",
            "catch_unwind",
            "EM_SETLIMITTEXT, NATIVE_TEXT_LIMIT",
            "STATIC",
            "EDIT",
            "BUTTON",
        ] {
            assert!(source.contains(required), "missing {required}");
        }
        for excluded in [
            "OpenClipboard",
            "SetClipboardData",
            "GetClipboardData",
            "SetWindowDisplayAffinity",
            "WDA_EXCLUDEFROMCAPTURE",
            "tauri::command",
            "invoke_handler",
            "std::fs",
            "OpenOptions",
            "println!",
            "eprintln!",
            "generate_migration_recovery_key_material",
            "seal_migration_recovery_envelope_v1",
            "ApplicationLifecycle",
        ] {
            assert!(!source.contains(excluded), "excluded surface: {excluded}");
        }
    }

    #[test]
    fn template_control_order_and_focus_encode_keyboard_semantics() {
        let source = include_str!("native_windows.rs");
        let prompt = source.find("context.controls.prompt =").unwrap();
        let display_one = source.find("context.controls.display_one =").unwrap();
        let readback_one = source.find("context.controls.readback_one =").unwrap();
        let display_two = source.find("context.controls.display_two =").unwrap();
        let readback_two = source.find("context.controls.readback_two =").unwrap();
        let primary = source.find("context.controls.primary =").unwrap();
        let cancel = source.find("context.controls.cancel =").unwrap();
        assert!(prompt < display_one);
        assert!(display_one < readback_one);
        assert!(readback_one < display_two);
        assert!(display_two < readback_two);
        assert!(readback_two < primary);
        assert!(primary < cancel);
        assert!(source.contains("BS_DEFPUSHBUTTON"));
        assert!(source.contains("IDOK"));
        assert!(source.contains("IDCANCEL"));
        assert!(source.contains("SetFocus"));
    }

    #[test]
    fn callback_unwind_is_contained_at_every_native_abi_boundary() {
        let source = include_str!("native_windows.rs");
        assert!(source.matches("catch_unwind").count() >= 3);
        assert!(source.contains("unsafe extern \"system\" fn dialog_proc"));
        assert!(source.contains("unsafe extern \"system\" fn display_control_proc"));
        assert!(source.contains("unsafe extern \"system\" fn readback_control_proc"));
    }

    #[test]
    fn production_source_locks_disclosure_and_terminal_ownership_ordering() {
        let source = include_str!("native_windows.rs")
            .split_once("#[cfg(test)]")
            .unwrap()
            .0;
        let first_reveal = source
            .split_once("fn begin_first_reveal")
            .unwrap()
            .1
            .split_once("fn begin_first_readback")
            .unwrap()
            .0;
        assert!(
            first_reveal.find("prepared.disclose()").unwrap()
                < first_reveal.find("display_current_record").unwrap()
        );
        assert!(first_reveal.contains("CustodyOwner::Disclosed"));

        let display_borrow = source
            .split_once("fn display_current_record")
            .unwrap()
            .1
            .split_once("fn set_nonsecret_text")
            .unwrap()
            .0;
        assert!(display_borrow.contains("CustodyOwner::Disclosed(owner)"));
        assert!(display_borrow.contains("CustodyOwner::FirstCopyVerified(owner)"));
        assert!(display_borrow.contains("CustodyOwner::Prepared(_) | CustodyOwner::Empty => Err"));

        let native_failure = source
            .split_once("fn fail_native_after_exposure")
            .unwrap()
            .1
            .split_once("fn cancel")
            .unwrap()
            .0;
        assert!(native_failure.contains("terminal_failure"));
        assert!(native_failure.contains("NativeCeremonyFailedAfterCustodyExposure"));
        assert!(!native_failure.contains("prepared.disclose()"));
    }

    #[test]
    fn native_outcome_debug_is_fixed_and_carries_no_native_payload() {
        let source = include_str!("native_windows.rs")
            .split_once("#[cfg(test)]")
            .unwrap()
            .0;
        let outcome = source
            .split_once("pub(crate) enum NativeMigrationRecoveryKeyCustodyOutcome")
            .unwrap()
            .1
            .split_once("impl fmt::Debug")
            .unwrap()
            .0;
        for forbidden in ["HWND", "u32", "i32", "String", "message", "control"] {
            assert!(!outcome.contains(forbidden), "native payload: {forbidden}");
        }
        let debug = source
            .split_once("impl fmt::Debug for NativeMigrationRecoveryKeyCustodyOutcome")
            .unwrap()
            .1
            .split_once("enum CeremonyPage")
            .unwrap()
            .0;
        assert_eq!(debug.matches("[REDACTED]").count(), 4);
    }
}
