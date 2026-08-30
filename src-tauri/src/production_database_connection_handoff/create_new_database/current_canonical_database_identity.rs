//! Setup-only historical native file-identity comparison.
//!
//! Success records one hardened current observation matching the supplied
//! historical proof. It says nothing about unchanged bytes, database validity,
//! key usability, artifact correspondence, setup completion, or operational
//! trust. No handle is retained, so it grants no continued path stability.

use std::fmt;

use crate::{
    production_database_file::{ProductionDatabaseInspection, inspect_production_database_file},
    storage_foundation::ProductionDatabasePath,
};

use super::SetupDatabaseIdentityProof;

/// Only a historical/current native identity match, with no retained resources.
pub(crate) struct CurrentCanonicalDatabaseIdentityMatchesSetupProof {
    _private: (),
}

impl fmt::Debug for CurrentCanonicalDatabaseIdentityMatchesSetupProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CurrentCanonicalDatabaseIdentityMatchesSetupProof([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CurrentCanonicalDatabaseIdentityComparisonError {
    CurrentDatabaseUnavailable,
    CurrentDatabaseUnsafe,
    IdentityMismatch,
}

/// Independently inspect the current canonical file before comparing exactly
/// the native identity captured by setup. The historical proof is only borrowed.
pub(crate) fn compare_current_canonical_database_identity(
    proof: &SetupDatabaseIdentityProof,
    path: &ProductionDatabasePath,
) -> Result<
    CurrentCanonicalDatabaseIdentityMatchesSetupProof,
    CurrentCanonicalDatabaseIdentityComparisonError,
> {
    let current = match inspect_production_database_file(path) {
        ProductionDatabaseInspection::Present(current) => current,
        ProductionDatabaseInspection::Missing | ProductionDatabaseInspection::Unavailable => {
            return Err(
                CurrentCanonicalDatabaseIdentityComparisonError::CurrentDatabaseUnavailable,
            );
        }
        ProductionDatabaseInspection::Invalid => {
            return Err(CurrentCanonicalDatabaseIdentityComparisonError::CurrentDatabaseUnsafe);
        }
    };
    if !current.has_native_identity(
        proof.created_leaf_identity.volume_serial,
        proof.created_leaf_identity.file_id,
    ) {
        return Err(CurrentCanonicalDatabaseIdentityComparisonError::IdentityMismatch);
    }
    Ok(CurrentCanonicalDatabaseIdentityMatchesSetupProof { _private: () })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::super::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, OPEN_EXISTING,
        open_native_handle, query_observation,
    };
    use super::*;
    use crate::storage_foundation::{
        production_database_path, production_database_path_from_synthetic_value,
    };

    struct Fixture {
        root: PathBuf,
        path: ProductionDatabasePath,
        proof: SetupDatabaseIdentityProof,
    }

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let temporary = std::env::temp_dir();
            let root = temporary.join(format!(
                "church-app-current-database-identity-{}-{nonce}",
                std::process::id()
            ));
            assert!(root.starts_with(&temporary));
            fs::create_dir(&root).unwrap();
            let path = production_database_path(root.clone());
            // Synthetic native-file provenance only: deliberately not a database.
            fs::write(path.as_path(), b"synthetic non-database bytes").unwrap();
            let handle = open_native_handle(
                path.as_path(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )
            .expect("synthetic historical handle should open");
            let proof = SetupDatabaseIdentityProof {
                created_leaf_identity: query_observation(&handle).unwrap().identity,
            };
            drop(handle);
            Self { root, path, proof }
        }

        fn compare(
            &self,
        ) -> Result<
            CurrentCanonicalDatabaseIdentityMatchesSetupProof,
            CurrentCanonicalDatabaseIdentityComparisonError,
        > {
            compare_current_canonical_database_identity(&self.proof, &self.path)
        }

        fn cleanup(self) {
            fs::remove_dir_all(&self.root).expect("exact synthetic root cleanup should succeed");
            assert!(!self.root.exists());
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn same_identity_succeeds_and_borrows_the_redacted_historical_proof() {
        let fixture = Fixture::new();
        let matched = fixture.compare().unwrap();
        assert_eq!(
            format!("{matched:?}"),
            "CurrentCanonicalDatabaseIdentityMatchesSetupProof([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", fixture.proof),
            "SetupDatabaseIdentityProof([REDACTED])"
        );
        fixture.compare().unwrap();
        assert_eq!(std::mem::size_of_val(&matched), 0);
        assert!(!std::mem::needs_drop::<
            CurrentCanonicalDatabaseIdentityMatchesSetupProof,
        >());
        fixture.cleanup();
    }

    #[test]
    fn changed_bytes_and_size_do_not_change_historical_identity_equality() {
        let fixture = Fixture::new();
        fixture.compare().unwrap();
        // Truncates the same file, after the historical capture and first comparison.
        fs::write(
            fixture.path.as_path(),
            b"different synthetic contents and size",
        )
        .unwrap();
        fixture.compare().unwrap();
        fixture.cleanup();
    }

    #[test]
    fn independently_observed_replacement_at_same_path_is_mismatch() {
        let fixture = Fixture::new();
        fixture.compare().unwrap();
        // Keep the old file alive under another name to prevent file-ID reuse.
        fs::rename(
            fixture.path.as_path(),
            fixture.root.join("displaced.synthetic"),
        )
        .unwrap();
        fs::write(fixture.path.as_path(), b"synthetic non-database bytes").unwrap();
        assert_eq!(
            fixture.compare().unwrap_err(),
            CurrentCanonicalDatabaseIdentityComparisonError::IdentityMismatch
        );
        assert!(fixture.root.join("displaced.synthetic").exists());
        assert!(fixture.path.as_path().exists());
        fixture.cleanup();
    }

    #[test]
    fn every_native_identity_component_is_compared_exactly() {
        let mut fixture = Fixture::new();
        fixture.proof.created_leaf_identity.volume_serial ^= 1;
        assert_eq!(
            fixture.compare().unwrap_err(),
            CurrentCanonicalDatabaseIdentityComparisonError::IdentityMismatch
        );
        fixture.proof.created_leaf_identity.volume_serial ^= 1;
        for offset in 0..16 {
            fixture.proof.created_leaf_identity.file_id[offset] ^= 1;
            assert_eq!(
                fixture.compare().unwrap_err(),
                CurrentCanonicalDatabaseIdentityComparisonError::IdentityMismatch
            );
            fixture.proof.created_leaf_identity.file_id[offset] ^= 1;
        }
        fixture.compare().unwrap();
        fixture.cleanup();
    }

    #[test]
    fn missing_current_database_fails_without_creation() {
        let fixture = Fixture::new();
        fs::remove_file(fixture.path.as_path()).unwrap();
        assert_eq!(
            fixture.compare().unwrap_err(),
            CurrentCanonicalDatabaseIdentityComparisonError::CurrentDatabaseUnavailable
        );
        assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 0);
        fixture.cleanup();
    }

    #[test]
    fn unavailable_current_database_parent_fails_without_creation() {
        let fixture = Fixture::new();
        let absent_parent = fixture.root.join("absent-parent.synthetic");
        let unavailable_path = production_database_path(absent_parent.clone());
        assert_eq!(
            compare_current_canonical_database_identity(&fixture.proof, &unavailable_path)
                .unwrap_err(),
            CurrentCanonicalDatabaseIdentityComparisonError::CurrentDatabaseUnavailable
        );
        assert!(!absent_parent.exists());
        fixture.compare().unwrap();
        fixture.cleanup();
    }

    #[test]
    fn directory_at_current_database_path_is_unsafe_and_preserved() {
        let fixture = Fixture::new();
        fs::remove_file(fixture.path.as_path()).unwrap();
        fs::create_dir(fixture.path.as_path()).unwrap();
        assert_eq!(
            fixture.compare().unwrap_err(),
            CurrentCanonicalDatabaseIdentityComparisonError::CurrentDatabaseUnsafe
        );
        assert!(fixture.path.as_path().is_dir());
        fixture.cleanup();
    }

    #[test]
    fn hard_link_is_unsafe_even_with_matching_native_identity() {
        let fixture = Fixture::new();
        let alias = fixture.root.join("alias.synthetic");
        fs::hard_link(fixture.path.as_path(), &alias).unwrap();
        assert_eq!(
            fixture.compare().unwrap_err(),
            CurrentCanonicalDatabaseIdentityComparisonError::CurrentDatabaseUnsafe
        );
        assert!(alias.exists());
        fs::remove_file(alias).unwrap();
        fixture.compare().unwrap();
        fixture.cleanup();
    }

    #[test]
    fn symlink_current_database_is_unsafe_where_supported() {
        let fixture = Fixture::new();
        let target = fixture.root.join("target.synthetic");
        fs::rename(fixture.path.as_path(), &target).unwrap();
        match std::os::windows::fs::symlink_file(&target, fixture.path.as_path()) {
            Ok(()) => {
                assert_eq!(
                    fixture.compare().unwrap_err(),
                    CurrentCanonicalDatabaseIdentityComparisonError::CurrentDatabaseUnsafe
                );
                assert!(
                    fs::symlink_metadata(fixture.path.as_path())
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
            }
            Err(error) if error.raw_os_error() == Some(1314) => {
                eprintln!("SYMLINK CASE NOT EXERCISED: creation privilege unavailable");
            }
            Err(_) => panic!("unexpected synthetic symlink creation failure"),
        }
        fixture.cleanup();
    }

    #[test]
    fn canonical_name_and_reserved_namespace_hardening_are_preserved() {
        let fixture = Fixture::new();
        let tampered = production_database_path_from_synthetic_value(fixture.root.join("alias.db"));
        assert_eq!(
            compare_current_canonical_database_identity(&fixture.proof, &tampered).unwrap_err(),
            CurrentCanonicalDatabaseIdentityComparisonError::CurrentDatabaseUnsafe
        );
        for suffix in ["-journal", "-wal", "-shm", ".stage"] {
            let sibling = fixture.root.join(format!("parish-data.db{suffix}"));
            fs::write(&sibling, b"synthetic").unwrap();
            assert_eq!(
                fixture.compare().unwrap_err(),
                CurrentCanonicalDatabaseIdentityComparisonError::CurrentDatabaseUnsafe
            );
            assert!(sibling.exists());
            fs::remove_file(sibling).unwrap();
        }
        fixture.compare().unwrap();
        fixture.cleanup();
    }

    #[test]
    fn error_debug_is_exact_and_payload_free() {
        use CurrentCanonicalDatabaseIdentityComparisonError::*;
        for (error, expected) in [
            (CurrentDatabaseUnavailable, "CurrentDatabaseUnavailable"),
            (CurrentDatabaseUnsafe, "CurrentDatabaseUnsafe"),
            (IdentityMismatch, "IdentityMismatch"),
        ] {
            assert_eq!(format!("{error:?}"), expected);
        }
    }

    #[test]
    fn proof_types_do_not_implement_clone_or_copy() {
        // Type inference is ambiguous (a compile failure) if either trait exists.
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
        assert_not_impl!(SetupDatabaseIdentityProof, Clone);
        assert_not_impl!(SetupDatabaseIdentityProof, Copy);
        assert_not_impl!(CurrentCanonicalDatabaseIdentityMatchesSetupProof, Clone);
        assert_not_impl!(CurrentCanonicalDatabaseIdentityMatchesSetupProof, Copy);
    }

    #[test]
    fn production_boundary_is_typed_sealed_and_has_no_later_capabilities() {
        let production = include_str!("current_canonical_database_identity.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(production.contains("proof: &SetupDatabaseIdentityProof,"));
        assert!(production.contains("path: &ProductionDatabasePath,"));
        assert_eq!(
            production
                .matches("inspect_production_database_file(path)")
                .count(),
            1
        );
        assert_eq!(
            production.matches("current.has_native_identity(").count(),
            1
        );
        let owner = production
            .split_once("pub(crate) struct CurrentCanonicalDatabaseIdentityMatchesSetupProof {")
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        assert_eq!(owner.trim(), "_private: (),");
        for forbidden in [
            "rusqlite",
            "sqlite3",
            "PRAGMA",
            "Connection",
            "DatabaseMetadata",
            "GenerationBoundDatabaseKey",
            "ReloadVerified",
            "ReloadedStaged",
            "AllStagedArtifactsReloadVerified",
            "FinalActiveArtifactsVerified",
            "FirstTimeSetupPublicationEvent",
            "first_time_setup_publication",
            "fs::",
            "File::",
            "OpenOptions",
            "PathBuf",
            "&Path",
            "unsafe",
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            "ReplaceFile",
            "MoveFile",
            "remove_",
            "rename",
            "retry",
            "cleanup",
            "Mutex",
            "LockFileEx",
            "SecurityDescriptor",
            "SetSecurity",
            "Serialize",
            "Deserialize",
            "pub fn",
            "Deref",
            "AsRef",
            "impl SetupDatabaseIdentityProof",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected capability: {forbidden}"
            );
        }
        let inspector = include_str!("../../production_database_file.rs");
        assert!(inspector.contains("const FILE_ACCESS: u32 = FILE_READ_ATTRIBUTES;"));
        assert!(inspector.contains("const FILE_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ;"));
        assert!(inspector.contains("const DIRECTORY_ACCESS: u32 = FILE_READ_ATTRIBUTES;"));
        assert!(inspector.contains("const DIRECTORY_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ;"));
    }
}
