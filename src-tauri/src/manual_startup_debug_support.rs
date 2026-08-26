//! Debug-only support for isolated, explicitly selected manual startup fixtures.

#![cfg(all(windows, debug_assertions))]

use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{self, BufRead},
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

const MANUAL_STARTUP_ROOT_ENVIRONMENT_VARIABLE: &str = "CHURCH_APP_MANUAL_STARTUP_ROOT";
const MANUAL_STARTUP_PAUSE_ENVIRONMENT_VARIABLE: &str = "CHURCH_APP_MANUAL_STARTUP_PAUSE";
const MANUAL_STARTUP_ROOT_PREFIX: &str = "church-app-manual-startup-";
const MANUAL_STARTUP_FIXTURE_MARKER: &str = ".church-app-manual-startup-fixture-v1";
const BEFORE_FINAL_INSTALLATION_OBSERVATION: &str = "before-final-installation-observation";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManualStartupDebugSupportUnavailable;

pub(crate) struct ManualStartupDebugSelection {
    root: PathBuf,
    pause_before_final_installation_observation: bool,
}

impl ManualStartupDebugSelection {
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn pause_before_final_installation_observation(&self) -> bool {
        self.pause_before_final_installation_observation
    }
}

pub(crate) fn select_startup_root(
    canonical_application_root: PathBuf,
) -> Result<ManualStartupDebugSelection, ManualStartupDebugSupportUnavailable> {
    select_startup_root_from_values(
        canonical_application_root,
        env::temp_dir(),
        env::var_os(MANUAL_STARTUP_ROOT_ENVIRONMENT_VARIABLE),
        env::var_os(MANUAL_STARTUP_PAUSE_ENVIRONMENT_VARIABLE),
    )
}

fn select_startup_root_from_values(
    canonical_application_root: PathBuf,
    temporary_directory: PathBuf,
    requested_root: Option<OsString>,
    requested_pause: Option<OsString>,
) -> Result<ManualStartupDebugSelection, ManualStartupDebugSupportUnavailable> {
    let Some(requested_root) = requested_root else {
        if requested_pause.is_some() {
            return Err(ManualStartupDebugSupportUnavailable);
        }
        return Ok(ManualStartupDebugSelection {
            root: canonical_application_root,
            pause_before_final_installation_observation: false,
        });
    };

    let root = validate_manual_startup_root(
        PathBuf::from(requested_root),
        &temporary_directory,
        &canonical_application_root,
    )?;
    let pause_before_final_installation_observation = match requested_pause {
        None => false,
        Some(value) if value == OsStr::new(BEFORE_FINAL_INSTALLATION_OBSERVATION) => true,
        Some(_) => return Err(ManualStartupDebugSupportUnavailable),
    };

    Ok(ManualStartupDebugSelection {
        root,
        pause_before_final_installation_observation,
    })
}

fn validate_manual_startup_root(
    requested_root: PathBuf,
    temporary_directory: &Path,
    canonical_application_root: &Path,
) -> Result<PathBuf, ManualStartupDebugSupportUnavailable> {
    validate_path_representation(&requested_root)?;
    if !requested_root.is_absolute() {
        return Err(ManualStartupDebugSupportUnavailable);
    }

    let root_metadata =
        fs::symlink_metadata(&requested_root).map_err(|_| ManualStartupDebugSupportUnavailable)?;
    if !root_metadata.file_type().is_dir() || is_reparse_point(&root_metadata) {
        return Err(ManualStartupDebugSupportUnavailable);
    }

    let normalized_temporary_directory =
        fs::canonicalize(temporary_directory).map_err(|_| ManualStartupDebugSupportUnavailable)?;
    let normalized_root =
        fs::canonicalize(&requested_root).map_err(|_| ManualStartupDebugSupportUnavailable)?;
    validate_path_representation(&normalized_root)?;
    let Some(parent) = normalized_root.parent() else {
        return Err(ManualStartupDebugSupportUnavailable);
    };
    if !windows_paths_equal(parent, &normalized_temporary_directory) {
        return Err(ManualStartupDebugSupportUnavailable);
    }
    let Some(name) = normalized_root.file_name().and_then(OsStr::to_str) else {
        return Err(ManualStartupDebugSupportUnavailable);
    };
    if !name.starts_with(MANUAL_STARTUP_ROOT_PREFIX) {
        return Err(ManualStartupDebugSupportUnavailable);
    }
    let normalized_canonical_application_root = fs::canonicalize(canonical_application_root)
        .unwrap_or_else(|_| canonical_application_root.to_path_buf());
    if windows_paths_equal(&normalized_root, &normalized_canonical_application_root) {
        return Err(ManualStartupDebugSupportUnavailable);
    }

    let marker = normalized_root.join(MANUAL_STARTUP_FIXTURE_MARKER);
    let marker_metadata =
        fs::symlink_metadata(marker).map_err(|_| ManualStartupDebugSupportUnavailable)?;
    if !marker_metadata.file_type().is_file() || is_reparse_point(&marker_metadata) {
        return Err(ManualStartupDebugSupportUnavailable);
    }

    Ok(normalized_root)
}

fn validate_path_representation(path: &Path) -> Result<(), ManualStartupDebugSupportUnavailable> {
    if path.to_str().is_none() || path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(ManualStartupDebugSupportUnavailable);
    }
    Ok(())
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn windows_paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManualStartupPauseOutcome {
    Resumed,
    Failed,
}

pub(crate) fn pause_before_final_installation_observation() -> ManualStartupPauseOutcome {
    let stdin = io::stdin();
    pause_before_final_installation_observation_with_reader(&mut stdin.lock())
}

fn pause_before_final_installation_observation_with_reader<R: BufRead>(
    reader: &mut R,
) -> ManualStartupPauseOutcome {
    eprintln!(r#"event="manual_startup_pause" outcome="reached""#);
    let mut token = String::new();
    match reader.read_line(&mut token) {
        Ok(0) | Err(_) => ManualStartupPauseOutcome::Failed,
        Ok(_) if token.trim() == "resume" => {
            eprintln!(r#"event="manual_startup_pause" outcome="resumed""#);
            ManualStartupPauseOutcome::Resumed
        }
        Ok(_) => ManualStartupPauseOutcome::Failed,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, BufRead, Cursor, Read},
        os::windows::{
            ffi::OsStringExt,
            fs::{symlink_dir, symlink_file},
        },
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestFixtureRoot {
        path: PathBuf,
    }

    impl TestFixtureRoot {
        fn marked() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock should follow the Unix epoch")
                .as_nanos();
            let path = env::temp_dir().join(format!(
                "{MANUAL_STARTUP_ROOT_PREFIX}debug-support-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            Self::marked_at(path)
        }

        fn marked_at(path: PathBuf) -> Self {
            fs::create_dir(&path).expect("isolated fixture root should be created");
            fs::write(
                path.join(MANUAL_STARTUP_FIXTURE_MARKER),
                b"synthetic marker\n",
            )
            .expect("marker should be created");
            Self { path }
        }
    }

    impl Drop for TestFixtureRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn select(
        canonical_root: PathBuf,
        requested_root: Option<OsString>,
        requested_pause: Option<OsString>,
    ) -> Result<ManualStartupDebugSelection, ManualStartupDebugSupportUnavailable> {
        select_startup_root_from_values(
            canonical_root,
            env::temp_dir(),
            requested_root,
            requested_pause,
        )
    }

    #[test]
    fn absent_override_uses_the_canonical_root_without_pause() {
        let canonical = PathBuf::from(r"C:\Users\synthetic\AppData\Local\ChurchApp");
        let selected = select(canonical.clone(), None, None).expect("default should succeed");
        assert_eq!(selected.root(), canonical);
        assert!(!selected.pause_before_final_installation_observation());
    }

    #[test]
    fn valid_marked_direct_temp_child_is_accepted() {
        let fixture = TestFixtureRoot::marked();
        let selected = select(
            PathBuf::from(r"C:\Users\synthetic\AppData\Local\ChurchApp"),
            Some(fixture.path.clone().into_os_string()),
            None,
        )
        .expect("valid fixture should be selected");
        assert_eq!(
            selected.root(),
            fs::canonicalize(&fixture.path).expect("fixture should canonicalize")
        );
    }

    #[test]
    fn relative_override_fails_closed() {
        assert!(
            select(
                PathBuf::from(r"C:\canonical"),
                Some("relative".into()),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn nul_and_malformed_path_representations_fail_closed() {
        let nul = OsString::from_wide(&[b'C' as u16, b':' as u16, b'\\' as u16, 0, b'x' as u16]);
        let malformed = OsString::from_wide(&[b'C' as u16, b':' as u16, b'\\' as u16, 0xd800]);

        for requested in [nul, malformed] {
            assert!(select(PathBuf::from(r"C:\canonical"), Some(requested), None).is_err());
        }
    }

    #[test]
    fn outside_temp_override_fails_closed() {
        let outside = env::current_dir().expect("test workspace should resolve");
        assert!(
            select(
                PathBuf::from(r"C:\canonical"),
                Some(outside.into_os_string()),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_prefix_fails_closed() {
        let wrong = TestFixtureRoot::marked_at(env::temp_dir().join(format!(
            "wrong-prefix-{}",
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        )));
        assert!(
            select(
                PathBuf::from(r"C:\canonical"),
                Some(wrong.path.clone().into_os_string()),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn missing_root_fails_closed() {
        let missing = env::temp_dir().join(format!(
            "{MANUAL_STARTUP_ROOT_PREFIX}missing-{}",
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(
            select(
                PathBuf::from(r"C:\canonical"),
                Some(missing.into_os_string()),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn missing_marker_fails_closed() {
        let fixture = TestFixtureRoot::marked();
        fs::remove_file(fixture.path.join(MANUAL_STARTUP_FIXTURE_MARKER)).unwrap();
        assert!(
            select(
                PathBuf::from(r"C:\canonical"),
                Some(fixture.path.clone().into_os_string()),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn marker_directory_fails_closed() {
        let fixture = TestFixtureRoot::marked();
        let marker = fixture.path.join(MANUAL_STARTUP_FIXTURE_MARKER);
        fs::remove_file(&marker).unwrap();
        fs::create_dir(&marker).unwrap();
        assert!(
            select(
                PathBuf::from(r"C:\canonical"),
                Some(fixture.path.clone().into_os_string()),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn root_reparse_point_fails_closed_when_symlinks_are_available() {
        let target = TestFixtureRoot::marked();
        let link = env::temp_dir().join(format!(
            "{MANUAL_STARTUP_ROOT_PREFIX}root-link-{}",
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        if symlink_dir(&target.path, &link).is_err() {
            return;
        }
        let result = select(
            PathBuf::from(r"C:\canonical"),
            Some(link.clone().into_os_string()),
            None,
        );
        fs::remove_dir(&link).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn marker_reparse_point_fails_closed_when_symlinks_are_available() {
        let fixture = TestFixtureRoot::marked();
        let marker = fixture.path.join(MANUAL_STARTUP_FIXTURE_MARKER);
        let target = fixture.path.join("marker-target");
        fs::write(&target, b"synthetic marker target\n").unwrap();
        fs::remove_file(&marker).unwrap();
        if symlink_file(&target, &marker).is_err() {
            return;
        }
        assert!(
            select(
                PathBuf::from(r"C:\canonical"),
                Some(fixture.path.clone().into_os_string()),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_root_equality_fails_closed() {
        let fixture = TestFixtureRoot::marked();
        assert!(
            select(
                fixture.path.clone(),
                Some(fixture.path.clone().into_os_string()),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_override_never_returns_the_canonical_root() {
        let canonical = PathBuf::from(r"C:\canonical-production-root");
        let result = select(canonical, Some("invalid-relative".into()), None);
        assert!(result.is_err());
    }

    #[test]
    fn pause_absent_is_a_no_op_and_exact_value_requires_a_valid_override() {
        let canonical = PathBuf::from(r"C:\canonical");
        assert!(
            !select(canonical.clone(), None, None)
                .unwrap()
                .pause_before_final_installation_observation()
        );
        assert!(
            select(
                canonical,
                None,
                Some(BEFORE_FINAL_INSTALLATION_OBSERVATION.into())
            )
            .is_err()
        );
    }

    #[test]
    fn exact_pause_value_is_accepted_only_with_a_valid_override() {
        let fixture = TestFixtureRoot::marked();
        let selected = select(
            PathBuf::from(r"C:\canonical"),
            Some(fixture.path.clone().into_os_string()),
            Some(BEFORE_FINAL_INSTALLATION_OBSERVATION.into()),
        )
        .unwrap();
        assert!(selected.pause_before_final_installation_observation());
    }

    #[test]
    fn wrong_pause_value_fails_closed() {
        let fixture = TestFixtureRoot::marked();
        assert!(
            select(
                PathBuf::from(r"C:\canonical"),
                Some(fixture.path.clone().into_os_string()),
                Some("wrong".into()),
            )
            .is_err()
        );
    }

    #[test]
    fn exact_trimmed_resume_continues_and_other_terminal_inputs_fail_closed() {
        for input in ["resume\n", "  resume \r\n"] {
            assert_eq!(
                pause_before_final_installation_observation_with_reader(&mut Cursor::new(input)),
                ManualStartupPauseOutcome::Resumed
            );
        }
        for input in ["", "continue\n", "resume-again\n"] {
            assert_eq!(
                pause_before_final_installation_observation_with_reader(&mut Cursor::new(input)),
                ManualStartupPauseOutcome::Failed
            );
        }
    }

    struct ReadFailure;

    impl Read for ReadFailure {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic read failure"))
        }
    }

    impl BufRead for ReadFailure {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::other("synthetic read failure"))
        }

        fn consume(&mut self, _: usize) {}
    }

    #[test]
    fn console_read_failure_fails_closed_without_retry() {
        assert_eq!(
            pause_before_final_installation_observation_with_reader(&mut ReadFailure),
            ManualStartupPauseOutcome::Failed
        );
    }

    #[test]
    fn support_contains_only_the_two_fixed_coarse_log_events() {
        const SOURCE: &str = include_str!("manual_startup_debug_support.rs");
        let production_source = SOURCE.split_once("#[cfg(test)]").unwrap().0;
        assert_eq!(production_source.matches("eprintln!(").count(), 2);
        assert_eq!(production_source.matches("manual_startup_pause").count(), 2);
        assert_eq!(production_source.matches("outcome=\"reached\"").count(), 1);
        assert_eq!(production_source.matches("outcome=\"resumed\"").count(), 1);
        for forbidden in ["eprintln!(requested", "eprintln!(root", "{:?}", "{error}"] {
            assert!(!production_source.contains(forbidden));
        }
    }

    #[test]
    fn pause_uses_one_blocking_line_read_without_wait_loop_or_retry() {
        const SOURCE: &str = include_str!("manual_startup_debug_support.rs");
        let production_source = SOURCE.split_once("#[cfg(test)]").unwrap().0;
        let pause = production_source
            .split_once("fn pause_before_final_installation_observation_with_reader")
            .unwrap()
            .1;

        assert_eq!(pause.matches("read_line(").count(), 1);
        for forbidden in ["loop {", "while ", "for ", "sleep(", "poll(", "read_to_"] {
            assert!(
                !pause.contains(forbidden),
                "unexpected pause behavior: {forbidden}"
            );
        }
    }
}
