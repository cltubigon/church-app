use std::{
    fmt,
    marker::PhantomData,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};

use windows_sys::Win32::{
    Foundation::{FALSE, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
};

const PRODUCTION_DATABASE_MIGRATION_EXCLUSIVITY_MUTEX_NAME: &str =
    "Global\\io.github.cltubigon.churchapp.ProductionDatabaseMigrationExclusivity";
const NON_BLOCKING_WAIT_MILLISECONDS: u32 = 0;

static PROCESS_LOCAL_MIGRATION_RESERVATION: AtomicBool = AtomicBool::new(false);

pub(crate) enum ProductionDatabaseMigrationCrossProcessExclusivityOutcome {
    Acquired(ProductionDatabaseMigrationCrossProcessExclusivity),
    AlreadyHeld,
    Unavailable,
}

impl fmt::Debug for ProductionDatabaseMigrationCrossProcessExclusivityOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acquired(_) => formatter.write_str("Acquired([REDACTED])"),
            Self::AlreadyHeld => formatter.write_str("AlreadyHeld"),
            Self::Unavailable => formatter.write_str("Unavailable"),
        }
    }
}

pub(crate) struct ProductionDatabaseMigrationCrossProcessExclusivity {
    mutex: OwnedHandle,
    process_local_reservation: ProcessLocalMigrationReservation,
    thread_affinity: PhantomData<Rc<()>>,
}

impl fmt::Debug for ProductionDatabaseMigrationCrossProcessExclusivity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProductionDatabaseMigrationCrossProcessExclusivity([REDACTED])")
    }
}

impl Drop for ProductionDatabaseMigrationCrossProcessExclusivity {
    fn drop(&mut self) {
        // SAFETY: this owner can neither move to nor be shared with another
        // thread, and it represents one successful wait on this live mutex.
        let _released = unsafe { ReleaseMutex(self.mutex.as_raw_handle() as HANDLE) };
        self.process_local_reservation.release();
    }
}

struct ProcessLocalMigrationReservation {
    active: bool,
}

impl ProcessLocalMigrationReservation {
    fn reserve() -> Option<Self> {
        PROCESS_LOCAL_MIGRATION_RESERVATION
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self { active: true })
    }

    fn release(&mut self) {
        if self.active {
            PROCESS_LOCAL_MIGRATION_RESERVATION.store(false, Ordering::Release);
            self.active = false;
        }
    }
}

impl Drop for ProcessLocalMigrationReservation {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaitDisposition {
    Acquired,
    AbandonedAndAcquired,
    AlreadyHeld,
    Unavailable,
}

fn classify_wait_result(wait_result: u32) -> WaitDisposition {
    match wait_result {
        WAIT_OBJECT_0 => WaitDisposition::Acquired,
        WAIT_ABANDONED => WaitDisposition::AbandonedAndAcquired,
        WAIT_TIMEOUT => WaitDisposition::AlreadyHeld,
        _ => WaitDisposition::Unavailable,
    }
}

pub(crate) fn acquire_production_database_migration_cross_process_exclusivity()
-> ProductionDatabaseMigrationCrossProcessExclusivityOutcome {
    let Some(mut reservation) = ProcessLocalMigrationReservation::reserve() else {
        return ProductionDatabaseMigrationCrossProcessExclusivityOutcome::AlreadyHeld;
    };
    let encoded_name: Vec<u16> = PRODUCTION_DATABASE_MIGRATION_EXCLUSIVITY_MUTEX_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: the fixed name is NUL-terminated and remains live for this
    // synchronous call. The security-attributes pointer is null, and
    // a successful fresh handle is transferred immediately to one Rust owner.
    let raw_mutex = unsafe { CreateMutexW(std::ptr::null(), FALSE, encoded_name.as_ptr()) };
    if raw_mutex.is_null() {
        reservation.release();
        return ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Unavailable;
    }
    // SAFETY: ownership of the successful fresh handle moves exactly once.
    let mutex = unsafe { OwnedHandle::from_raw_handle(raw_mutex as RawHandle) };
    // SAFETY: the handle is live and owned for this single non-blocking wait.
    let disposition = classify_wait_result(unsafe {
        WaitForSingleObject(
            mutex.as_raw_handle() as HANDLE,
            NON_BLOCKING_WAIT_MILLISECONDS,
        )
    });

    finish_acquisition(reservation, mutex, disposition).0
}

fn finish_acquisition(
    mut reservation: ProcessLocalMigrationReservation,
    mutex: OwnedHandle,
    disposition: WaitDisposition,
) -> (
    ProductionDatabaseMigrationCrossProcessExclusivityOutcome,
    Option<WaitDisposition>,
) {
    match disposition {
        WaitDisposition::Acquired | WaitDisposition::AbandonedAndAcquired => {
            // Abandonment grants only current exclusivity. It conveys no trust
            // about prior migration work and skips none of the later trust chain.
            (
                ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Acquired(
                    ProductionDatabaseMigrationCrossProcessExclusivity {
                        mutex,
                        process_local_reservation: reservation,
                        thread_affinity: PhantomData,
                    },
                ),
                Some(disposition),
            )
        }
        WaitDisposition::AlreadyHeld => {
            drop(mutex);
            reservation.release();
            (
                ProductionDatabaseMigrationCrossProcessExclusivityOutcome::AlreadyHeld,
                Some(disposition),
            )
        }
        WaitDisposition::Unavailable => {
            drop(mutex);
            reservation.release();
            (
                ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Unavailable,
                Some(disposition),
            )
        }
    }
}

#[cfg(test)]
static PROCESS_LOCAL_RESERVATION_TEST_SERIALIZATION: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        io::{BufRead, BufReader, Read, Write},
        process::{Child, Command, Stdio},
    };

    use super::*;
    use windows_sys::Win32::Foundation::WAIT_FAILED;

    const CHILD_MUTEX_NAME_ENV: &str = "CHURCH_APP_MIGRATION_EXCLUSIVITY_TEST_MUTEX_NAME";
    const CHILD_MODE_ENV: &str = "CHURCH_APP_MIGRATION_EXCLUSIVITY_TEST_CHILD_MODE";
    const CHILD_TEST_NAME: &str =
        "production_database_migration_exclusivity::tests::cross_process_helper_child";
    const CHILD_READY: &str = "PRODUCTION_DATABASE_MIGRATION_EXCLUSIVITY_ACQUIRED";
    const FIRST_TIME_SETUP_MUTEX_NAME: &str =
        "Global\\io.github.cltubigon.churchapp.FirstTimeSetupExclusivity";

    static TEST_NAME_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn serialize_tests() -> std::sync::MutexGuard<'static, ()> {
        PROCESS_LOCAL_RESERVATION_TEST_SERIALIZATION
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn unique_mutex_name(label: &str) -> String {
        let sequence = TEST_NAME_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        format!(
            "Global\\io.github.cltubigon.churchapp.ProductionDatabaseMigrationExclusivity.Test.{}.{}.{}",
            std::process::id(),
            sequence,
            label
        )
    }

    fn acquire_for_test(
        mutex_name: &str,
    ) -> (
        ProductionDatabaseMigrationCrossProcessExclusivityOutcome,
        Option<WaitDisposition>,
    ) {
        let Some(mut reservation) = ProcessLocalMigrationReservation::reserve() else {
            return (
                ProductionDatabaseMigrationCrossProcessExclusivityOutcome::AlreadyHeld,
                None,
            );
        };
        let encoded_name: Vec<u16> = mutex_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: the synthetic test name is NUL-terminated and remains live
        // for this synchronous call, then its fresh handle moves to one owner.
        let raw_mutex = unsafe { CreateMutexW(std::ptr::null(), FALSE, encoded_name.as_ptr()) };
        if raw_mutex.is_null() {
            reservation.release();
            return (
                ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Unavailable,
                None,
            );
        }
        // SAFETY: ownership of the successful fresh test handle moves once.
        let mutex = unsafe { OwnedHandle::from_raw_handle(raw_mutex as RawHandle) };
        // SAFETY: the handle is live and owned for this one zero-timeout wait.
        let disposition = classify_wait_result(unsafe {
            WaitForSingleObject(
                mutex.as_raw_handle() as HANDLE,
                NON_BLOCKING_WAIT_MILLISECONDS,
            )
        });
        finish_acquisition(reservation, mutex, disposition)
    }

    fn expect_acquired(
        outcome: ProductionDatabaseMigrationCrossProcessExclusivityOutcome,
    ) -> ProductionDatabaseMigrationCrossProcessExclusivity {
        match outcome {
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Acquired(owner) => owner,
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::AlreadyHeld => {
                panic!("mutex was unexpectedly held")
            }
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Unavailable => {
                panic!("mutex was unexpectedly unavailable")
            }
        }
    }

    struct HoldingChild {
        child: Child,
        stdout: BufReader<std::process::ChildStdout>,
    }

    impl HoldingChild {
        fn spawn(mutex_name: &str) -> Self {
            let mut child = Command::new(std::env::current_exe().expect("test executable path"))
                .arg("--exact")
                .arg(CHILD_TEST_NAME)
                .arg("--nocapture")
                .env(CHILD_MUTEX_NAME_ENV, mutex_name)
                .env(CHILD_MODE_ENV, "hold")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn exclusivity helper child");
            let mut stdout = BufReader::new(child.stdout.take().expect("child stdout"));
            loop {
                let mut line = String::new();
                let read = stdout.read_line(&mut line).expect("read child signal");
                assert_ne!(read, 0, "helper child exited before acquiring mutex");
                if line.trim_end() == CHILD_READY {
                    break;
                }
            }
            Self { child, stdout }
        }

        fn release_normally(mut self) {
            self.child
                .stdin
                .take()
                .expect("child stdin")
                .write_all(b"release\n")
                .expect("signal normal child release");
            let mut remaining_output = String::new();
            self.stdout
                .read_to_string(&mut remaining_output)
                .expect("drain helper child output");
            assert!(self.child.wait().expect("wait for helper child").success());
        }

        fn terminate(mut self) {
            self.child.kill().expect("terminate helper child");
            let _status = self.child.wait().expect("reap terminated helper child");
        }
    }

    impl Drop for HoldingChild {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn first_acquisition_succeeds_second_is_non_reentrant_and_drop_permits_later_acquisition() {
        let _serial = serialize_tests();
        let first =
            expect_acquired(acquire_production_database_migration_cross_process_exclusivity());
        assert!(matches!(
            acquire_production_database_migration_cross_process_exclusivity(),
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::AlreadyHeld
        ));
        drop(first);
        let later =
            expect_acquired(acquire_production_database_migration_cross_process_exclusivity());
        drop(later);
    }

    #[test]
    fn owner_is_thread_affine_sealed_and_redacted() {
        macro_rules! assert_not_impl {
            ($owner:ty, $bound:path) => {{
                trait AmbiguousIfImpl<A> {
                    fn check() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                struct Implemented;
                impl<T: ?Sized + $bound> AmbiguousIfImpl<Implemented> for T {}
                let _ = <$owner as AmbiguousIfImpl<_>>::check;
            }};
        }
        assert_not_impl!(ProductionDatabaseMigrationCrossProcessExclusivity, Send);
        assert_not_impl!(ProductionDatabaseMigrationCrossProcessExclusivity, Sync);
        assert_not_impl!(ProductionDatabaseMigrationCrossProcessExclusivity, Clone);
        assert_not_impl!(ProductionDatabaseMigrationCrossProcessExclusivity, Copy);
        assert_not_impl!(ProductionDatabaseMigrationCrossProcessExclusivity, Default);
        assert_not_impl!(
            ProductionDatabaseMigrationCrossProcessExclusivity,
            std::ops::Deref
        );
        assert_not_impl!(
            ProductionDatabaseMigrationCrossProcessExclusivity,
            serde::Serialize
        );
        assert_not_impl!(
            ProductionDatabaseMigrationCrossProcessExclusivity,
            serde::Deserialize<'static>
        );

        let _serial = serialize_tests();
        let owner =
            expect_acquired(acquire_production_database_migration_cross_process_exclusivity());
        assert_eq!(
            format!("{owner:?}"),
            "ProductionDatabaseMigrationCrossProcessExclusivity([REDACTED])"
        );
        drop(owner);
    }

    #[test]
    fn outcomes_are_coarse_and_redacted() {
        let _serial = serialize_tests();
        let owner =
            expect_acquired(acquire_production_database_migration_cross_process_exclusivity());
        assert_eq!(
            format!(
                "{:?}",
                ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Acquired(owner)
            ),
            "Acquired([REDACTED])"
        );
        assert_eq!(
            format!(
                "{:?}",
                ProductionDatabaseMigrationCrossProcessExclusivityOutcome::AlreadyHeld
            ),
            "AlreadyHeld"
        );
        assert_eq!(
            format!(
                "{:?}",
                ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Unavailable
            ),
            "Unavailable"
        );
    }

    #[test]
    fn classifier_maps_wait_results_exactly() {
        assert_eq!(
            classify_wait_result(WAIT_OBJECT_0),
            WaitDisposition::Acquired
        );
        assert_eq!(
            classify_wait_result(WAIT_ABANDONED),
            WaitDisposition::AbandonedAndAcquired
        );
        assert_eq!(
            classify_wait_result(WAIT_TIMEOUT),
            WaitDisposition::AlreadyHeld
        );
        assert_eq!(
            classify_wait_result(WAIT_FAILED),
            WaitDisposition::Unavailable
        );
        assert_eq!(classify_wait_result(17), WaitDisposition::Unavailable);
    }

    #[test]
    fn native_creation_failure_clears_process_local_reservation() {
        let _serial = serialize_tests();
        let invalid_name = unique_mutex_name("invalid\\child");
        assert!(matches!(
            acquire_for_test(&invalid_name).0,
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::Unavailable
        ));
        let owner = expect_acquired(acquire_for_test(&unique_mutex_name("after-failure")).0);
        drop(owner);
    }

    #[test]
    fn production_surface_remains_narrow_fixed_and_unwired() {
        const SOURCE: &str = include_str!("production_database_migration_exclusivity.rs");
        const LIB_SOURCE: &str = include_str!("lib.rs");
        const LIFECYCLE_SOURCE: &str = include_str!("application_lifecycle.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();

        assert_eq!(production.matches("CreateMutexW(").count(), 1);
        assert_eq!(production.matches("WaitForSingleObject(").count(), 1);
        assert_eq!(production.matches("ReleaseMutex(").count(), 1);
        assert!(production.contains("NON_BLOCKING_WAIT_MILLISECONDS: u32 = 0"));
        assert!(production.contains(
            r#"Global\\io.github.cltubigon.churchapp.ProductionDatabaseMigrationExclusivity"#
        ));
        assert_ne!(
            PRODUCTION_DATABASE_MIGRATION_EXCLUSIVITY_MUTEX_NAME,
            FIRST_TIME_SETUP_MUTEX_NAME
        );
        assert!(!production.contains("loop {"));
        assert!(!production.contains("while "));
        for forbidden in [
            "OpenMutexW",
            "GetLastError",
            "Sleep(",
            "SECURITY_DESCRIPTOR",
            "Authorization",
            "InstallationEvidence",
            "ApplicationLifecycle",
            "PathBuf",
            "AsHandle",
            "IntoRawHandle",
            "rusqlite",
            "full_integrity",
            "backup",
            "schema",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }

        let owner = production
            .split_once("pub(crate) struct ProductionDatabaseMigrationCrossProcessExclusivity {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        for field in [
            "mutex: OwnedHandle",
            "process_local_reservation: ProcessLocalMigrationReservation",
            "thread_affinity: PhantomData<Rc<()>>",
        ] {
            assert_eq!(owner.matches(field).count(), 1, "{field}");
        }
        assert_eq!(owner.lines().filter(|line| line.contains(':')).count(), 3);
        assert_eq!(
            LIB_SOURCE
                .matches("mod production_database_migration_exclusivity;")
                .count(),
            1
        );
        assert!(!LIFECYCLE_SOURCE.contains("migration_exclusivity"));
    }

    #[test]
    fn cross_process_contention_then_normal_release_permits_acquisition() {
        let _serial = serialize_tests();
        let mutex_name = unique_mutex_name("normal-release");
        let child = HoldingChild::spawn(&mutex_name);
        let (contended, disposition) = acquire_for_test(&mutex_name);
        assert!(matches!(
            contended,
            ProductionDatabaseMigrationCrossProcessExclusivityOutcome::AlreadyHeld
        ));
        assert_eq!(disposition, Some(WaitDisposition::AlreadyHeld));
        child.release_normally();
        let later = expect_acquired(acquire_for_test(&mutex_name).0);
        drop(later);
    }

    #[test]
    fn terminated_owner_is_acquired_only_as_the_ordinary_owner_type() {
        let _serial = serialize_tests();
        let mutex_name = unique_mutex_name("abandoned");
        let child = HoldingChild::spawn(&mutex_name);
        let encoded_name: Vec<u16> = mutex_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: this handle deliberately does not acquire ownership; it keeps
        // the kernel object alive across termination of the owning child.
        let retained_raw = unsafe { CreateMutexW(std::ptr::null(), FALSE, encoded_name.as_ptr()) };
        assert!(!retained_raw.is_null());
        // SAFETY: ownership of the successful fresh test handle moves once.
        let retained = unsafe { OwnedHandle::from_raw_handle(retained_raw as RawHandle) };
        child.terminate();
        let (outcome, disposition) = acquire_for_test(&mutex_name);
        let owner: ProductionDatabaseMigrationCrossProcessExclusivity = expect_acquired(outcome);
        assert_eq!(disposition, Some(WaitDisposition::AbandonedAndAcquired));
        drop(owner);
        drop(retained);
    }

    #[test]
    fn cross_process_helper_child() {
        let Some(mutex_name) = std::env::var_os(CHILD_MUTEX_NAME_ENV) else {
            return;
        };
        assert_eq!(
            std::env::var_os(CHILD_MODE_ENV),
            Some(OsString::from("hold"))
        );
        let mutex_name = mutex_name.into_string().expect("Unicode test mutex name");
        let owner = expect_acquired(acquire_for_test(&mutex_name).0);
        println!("{CHILD_READY}");
        std::io::stdout().flush().expect("flush ownership signal");
        let mut release = String::new();
        std::io::stdin()
            .read_line(&mut release)
            .expect("read parent release signal");
        assert_eq!(release, "release\n");
        drop(owner);
    }
}
