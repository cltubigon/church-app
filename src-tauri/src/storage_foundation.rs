//! Rust-owned storage location and identity foundations.
//!
//! This module only resolves typed paths. It never creates, opens, reads, or writes them.

use std::fmt;
use std::path::{Path, PathBuf};

use tauri::Manager;

pub const PRODUCTION_DATABASE_FILENAME: &str = "parish-data.db";

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const PRODUCTION_DATABASE_STAGE_FILENAME: &str = "parish-data.db.stage";
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const INSTALLATION_EVIDENCE_DIRECTORY_NAME: &str = "installation-evidence";
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const ACTIVE_AUTHENTICATION_KEY_FILENAME: &str = "authentication-key.dpapi";
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME: &str = "authenticated-evidence.dpapi";
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const STAGED_AUTHENTICATION_KEY_FILENAME: &str = "authentication-key.dpapi.stage";
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const STAGED_AUTHENTICATED_EVIDENCE_FILENAME: &str =
    "authenticated-evidence.dpapi.stage";

const DEVELOPMENT_STORAGE_IDENTITY: &str = "io.github.cltubigon.churchapp.development";
const AUTOMATED_TEST_STORAGE_IDENTITY: &str = "church-app-automated-tests";
const RESTORE_STAGING_DIRECTORY: &str = "restore-staging";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationDatabaseFormatIdentity([u8; 16]);

pub const APPLICATION_DATABASE_FORMAT_IDENTITY: ApplicationDatabaseFormatIdentity =
    ApplicationDatabaseFormatIdentity([
        0x9c, 0x77, 0x5d, 0x40, 0x36, 0xb1, 0x4f, 0x31, 0xa8, 0x23, 0x6e, 0xd2, 0x58, 0x97, 0x0c,
        0x14,
    ]);

impl ApplicationDatabaseFormatIdentity {
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParishIdentifier([u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidParishIdentifier;

impl ParishIdentifier {
    pub fn parse(value: &str) -> Result<Self, InvalidParishIdentifier> {
        if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(InvalidParishIdentifier);
        }

        let mut bytes = [0_u8; 16];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
        }

        if bytes == [0; 16] {
            return Err(InvalidParishIdentifier);
        }

        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

fn hex_value(byte: u8) -> Result<u8, InvalidParishIdentifier> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(InvalidParishIdentifier),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionDatabasePath(PathBuf);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevelopmentDatabasePath(PathBuf);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomatedTestDatabasePath(PathBuf);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreStagingDatabasePath(PathBuf);

macro_rules! redacted_persistence_path {
    ($path_type:ident) => {
        #[cfg_attr(not(test), allow(dead_code))]
        #[derive(Clone, Eq, PartialEq)]
        pub(crate) struct $path_type(PathBuf);

        #[cfg_attr(not(test), allow(dead_code))]
        impl $path_type {
            pub(crate) fn as_path(&self) -> &Path {
                &self.0
            }
        }

        impl fmt::Debug for $path_type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($path_type), "([REDACTED])"))
            }
        }
    };
}

redacted_persistence_path!(InstallationEvidenceDirectoryPath);
redacted_persistence_path!(ActiveAuthenticationKeyPath);
redacted_persistence_path!(ActiveAuthenticatedEvidencePath);
redacted_persistence_path!(StagedAuthenticationKeyPath);
redacted_persistence_path!(StagedAuthenticatedEvidencePath);
redacted_persistence_path!(StagedDatabasePath);

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct InstallationEvidencePersistencePaths {
    pub(crate) active_database: ProductionDatabasePath,
    pub(crate) staged_database: StagedDatabasePath,
    pub(crate) evidence_directory: InstallationEvidenceDirectoryPath,
    pub(crate) active_authentication_key: ActiveAuthenticationKeyPath,
    pub(crate) active_authenticated_evidence: ActiveAuthenticatedEvidencePath,
    pub(crate) staged_authentication_key: StagedAuthenticationKeyPath,
    pub(crate) staged_authenticated_evidence: StagedAuthenticatedEvidencePath,
}

impl fmt::Debug for InstallationEvidencePersistencePaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstallationEvidencePersistencePaths([REDACTED])")
    }
}

macro_rules! path_access {
    ($path_type:ty) => {
        impl $path_type {
            pub fn as_path(&self) -> &Path {
                &self.0
            }
        }
    };
}

path_access!(ProductionDatabasePath);
path_access!(DevelopmentDatabasePath);
path_access!(AutomatedTestDatabasePath);
path_access!(RestoreStagingDatabasePath);

pub fn resolve_production_database_path(
    app: &tauri::AppHandle,
) -> Result<ProductionDatabasePath, tauri::Error> {
    let app_local_data_directory = app.path().app_local_data_dir()?;
    Ok(production_database_path(app_local_data_directory))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn resolve_installation_evidence_persistence_paths(
    app: &tauri::AppHandle,
) -> Result<InstallationEvidencePersistencePaths, tauri::Error> {
    let app_local_data_directory = app.path().app_local_data_dir()?;
    Ok(installation_evidence_persistence_paths(
        &app_local_data_directory,
    ))
}

pub fn resolve_development_database_path(base: &Path) -> DevelopmentDatabasePath {
    DevelopmentDatabasePath(
        base.join(DEVELOPMENT_STORAGE_IDENTITY)
            .join(PRODUCTION_DATABASE_FILENAME),
    )
}

pub fn resolve_automated_test_database_path(
    temporary_base: &Path,
    unique_test_id: &str,
) -> Result<AutomatedTestDatabasePath, InvalidTestStorageIdentifier> {
    if unique_test_id.is_empty()
        || !unique_test_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(InvalidTestStorageIdentifier);
    }

    Ok(AutomatedTestDatabasePath(
        temporary_base
            .join(AUTOMATED_TEST_STORAGE_IDENTITY)
            .join(unique_test_id)
            .join(PRODUCTION_DATABASE_FILENAME),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTestStorageIdentifier;

pub fn resolve_restore_staging_database_path(
    app: &tauri::AppHandle,
) -> Result<RestoreStagingDatabasePath, tauri::Error> {
    let app_local_data_directory = app.path().app_local_data_dir()?;
    Ok(restore_staging_database_path(app_local_data_directory))
}

fn production_database_path(app_local_data_directory: PathBuf) -> ProductionDatabasePath {
    ProductionDatabasePath(app_local_data_directory.join(PRODUCTION_DATABASE_FILENAME))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn installation_evidence_persistence_paths(
    synthetic_root: &Path,
) -> InstallationEvidencePersistencePaths {
    let evidence_directory = synthetic_root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME);

    InstallationEvidencePersistencePaths {
        active_database: production_database_path(synthetic_root.to_path_buf()),
        staged_database: StagedDatabasePath(
            synthetic_root.join(PRODUCTION_DATABASE_STAGE_FILENAME),
        ),
        evidence_directory: InstallationEvidenceDirectoryPath(evidence_directory.clone()),
        active_authentication_key: ActiveAuthenticationKeyPath(
            evidence_directory.join(ACTIVE_AUTHENTICATION_KEY_FILENAME),
        ),
        active_authenticated_evidence: ActiveAuthenticatedEvidencePath(
            evidence_directory.join(ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME),
        ),
        staged_authentication_key: StagedAuthenticationKeyPath(
            evidence_directory.join(STAGED_AUTHENTICATION_KEY_FILENAME),
        ),
        staged_authenticated_evidence: StagedAuthenticatedEvidencePath(
            evidence_directory.join(STAGED_AUTHENTICATED_EVIDENCE_FILENAME),
        ),
    }
}

fn restore_staging_database_path(app_local_data_directory: PathBuf) -> RestoreStagingDatabasePath {
    RestoreStagingDatabasePath(
        app_local_data_directory
            .join(RESTORE_STAGING_DIRECTORY)
            .join(PRODUCTION_DATABASE_FILENAME),
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn assert_persistence_paths(root: &Path) {
        let paths = installation_evidence_persistence_paths(root);
        let evidence_directory = root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME);

        assert_eq!(
            paths.active_database.as_path(),
            root.join(PRODUCTION_DATABASE_FILENAME)
        );
        assert_eq!(
            paths.staged_database.as_path(),
            root.join(PRODUCTION_DATABASE_STAGE_FILENAME)
        );
        assert_eq!(paths.evidence_directory.as_path(), evidence_directory);
        assert_eq!(
            paths.active_authentication_key.as_path(),
            evidence_directory.join(ACTIVE_AUTHENTICATION_KEY_FILENAME)
        );
        assert_eq!(
            paths.active_authenticated_evidence.as_path(),
            evidence_directory.join(ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME)
        );
        assert_eq!(
            paths.staged_authentication_key.as_path(),
            evidence_directory.join(STAGED_AUTHENTICATION_KEY_FILENAME)
        );
        assert_eq!(
            paths.staged_authenticated_evidence.as_path(),
            evidence_directory.join(STAGED_AUTHENTICATED_EVIDENCE_FILENAME)
        );
    }

    #[test]
    fn persistence_fixed_names_are_exact_and_database_name_remains_canonical() {
        assert_eq!(PRODUCTION_DATABASE_FILENAME, "parish-data.db");
        assert_eq!(PRODUCTION_DATABASE_STAGE_FILENAME, "parish-data.db.stage");
        assert_eq!(
            INSTALLATION_EVIDENCE_DIRECTORY_NAME,
            "installation-evidence"
        );
        assert_eq!(
            ACTIVE_AUTHENTICATION_KEY_FILENAME,
            "authentication-key.dpapi"
        );
        assert_eq!(
            ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME,
            "authenticated-evidence.dpapi"
        );
        assert_eq!(
            STAGED_AUTHENTICATION_KEY_FILENAME,
            "authentication-key.dpapi.stage"
        );
        assert_eq!(
            STAGED_AUTHENTICATED_EVIDENCE_FILENAME,
            "authenticated-evidence.dpapi.stage"
        );

        let paths = installation_evidence_persistence_paths(Path::new("synthetic-root"));
        assert_eq!(
            paths.active_database,
            production_database_path(PathBuf::from("synthetic-root"))
        );
    }

    #[test]
    fn persistence_paths_join_only_beneath_windows_like_and_portable_synthetic_roots() {
        assert_persistence_paths(Path::new(r"X:\synthetic-local-app-data\church-app"));
        assert_persistence_paths(Path::new("synthetic/portable/church-app"));
    }

    #[test]
    fn evidence_paths_are_nested_while_database_stage_is_directly_beneath_root() {
        let root = Path::new("synthetic-root");
        let paths = installation_evidence_persistence_paths(root);
        let evidence_directory = root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME);

        for evidence_path in [
            paths.active_authentication_key.as_path(),
            paths.active_authenticated_evidence.as_path(),
            paths.staged_authentication_key.as_path(),
            paths.staged_authenticated_evidence.as_path(),
        ] {
            assert!(evidence_path.starts_with(&evidence_directory));
        }
        assert_eq!(paths.staged_database.as_path().parent(), Some(root));
    }

    #[test]
    fn restore_staging_and_publication_staging_are_distinct() {
        let root = PathBuf::from("synthetic-root");
        let restore = restore_staging_database_path(root.clone());
        let publication = installation_evidence_persistence_paths(&root);

        assert_ne!(restore.as_path(), publication.staged_database.as_path());
        assert!(
            restore
                .as_path()
                .starts_with(root.join(RESTORE_STAGING_DIRECTORY))
        );
        assert_eq!(
            publication.staged_database.as_path().parent(),
            Some(root.as_path())
        );
    }

    #[test]
    fn persistence_path_debug_output_redacts_every_inner_path() {
        let paths = installation_evidence_persistence_paths(Path::new("sensitive-synthetic-root"));
        let debug_values = [
            format!("{:?}", paths.evidence_directory),
            format!("{:?}", paths.active_authentication_key),
            format!("{:?}", paths.active_authenticated_evidence),
            format!("{:?}", paths.staged_authentication_key),
            format!("{:?}", paths.staged_authenticated_evidence),
            format!("{:?}", paths.staged_database),
            format!("{paths:?}"),
        ];

        for debug in debug_values {
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("sensitive-synthetic-root"));
        }
    }

    #[test]
    fn persistence_path_construction_contains_only_path_operations() {
        const SOURCE: &str = include_str!("storage_foundation.rs");
        let constructor = SOURCE
            .split("pub(crate) fn installation_evidence_persistence_paths")
            .nth(1)
            .and_then(|tail| tail.split("fn restore_staging_database_path").next())
            .expect("persistence constructor should remain a distinct function");

        for excluded in ["std::fs", "File::", "create_dir", "app.path()", "std::env"] {
            assert!(!constructor.contains(excluded));
        }
        assert!(constructor.contains(".join("));
    }

    #[test]
    fn production_resolver_accepts_only_the_rust_application_handle() {
        let resolver: fn(&tauri::AppHandle) -> Result<ProductionDatabasePath, tauri::Error> =
            resolve_production_database_path;

        let _ = resolver;
    }

    #[test]
    fn installation_evidence_resolver_is_a_pure_canonical_tauri_path_boundary() {
        let resolver: fn(
            &tauri::AppHandle,
        ) -> Result<InstallationEvidencePersistencePaths, tauri::Error> =
            resolve_installation_evidence_persistence_paths;
        let _ = resolver;

        const SOURCE: &str = include_str!("storage_foundation.rs");
        let resolver_source = SOURCE
            .split("pub(crate) fn resolve_installation_evidence_persistence_paths")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub fn resolve_development_database_path")
                    .next()
            })
            .expect("installation-evidence resolver should remain a distinct function");

        assert_eq!(resolver_source.matches("app_local_data_dir()").count(), 1);
        assert!(resolver_source.contains("installation_evidence_persistence_paths("));
        for excluded in [
            "std::fs",
            "File::",
            "create_dir",
            ".exists()",
            ".open(",
            ".read(",
            ".write(",
        ] {
            assert!(!resolver_source.contains(excluded));
        }
    }

    #[test]
    fn production_path_uses_only_the_rust_resolved_application_directory_and_fixed_filename() {
        let application_directory = PathBuf::from(r"X:\synthetic-local-app-data\church-app");
        let path = production_database_path(application_directory.clone());

        assert_eq!(
            path.as_path(),
            application_directory.join(PRODUCTION_DATABASE_FILENAME)
        );
        assert_eq!(
            path.as_path().file_name().and_then(|name| name.to_str()),
            Some("parish-data.db")
        );
    }

    #[test]
    fn development_test_and_restore_paths_are_separate_from_production() {
        let synthetic_root = PathBuf::from(r"X:\synthetic-storage-root");
        let production_directory = synthetic_root.join("production");
        let production = production_database_path(production_directory.clone());
        let development = resolve_development_database_path(&synthetic_root);
        let automated_test =
            resolve_automated_test_database_path(&synthetic_root, "case-001").unwrap();
        let restore = restore_staging_database_path(synthetic_root.join("production"));

        assert_ne!(development.as_path(), production.as_path());
        assert_ne!(automated_test.as_path(), production.as_path());
        assert_ne!(restore.as_path(), production.as_path());
        assert!(!development.as_path().starts_with(&production_directory));
        assert!(!automated_test.as_path().starts_with(&production_directory));
        assert!(
            restore
                .as_path()
                .ends_with(Path::new(RESTORE_STAGING_DIRECTORY).join(PRODUCTION_DATABASE_FILENAME))
        );
    }

    #[test]
    fn automated_test_paths_require_explicit_unique_safe_identifiers() {
        let synthetic_temporary_root = PathBuf::from(r"X:\synthetic-temporary-root");
        let first =
            resolve_automated_test_database_path(&synthetic_temporary_root, "case-001").unwrap();
        let second =
            resolve_automated_test_database_path(&synthetic_temporary_root, "case-002").unwrap();

        assert_ne!(first, second);
        assert!(first.as_path().starts_with(&synthetic_temporary_root));
        assert!(
            resolve_automated_test_database_path(&synthetic_temporary_root, "../escape").is_err()
        );
        assert!(resolve_automated_test_database_path(&synthetic_temporary_root, "").is_err());
    }

    #[test]
    fn path_resolution_has_no_filesystem_side_effects() {
        let absent_root = std::env::temp_dir().join(format!(
            "church-app-path-resolution-no-side-effects-{}",
            std::process::id()
        ));
        assert!(!absent_root.exists());

        let production = production_database_path(absent_root.join("production"));
        let development = resolve_development_database_path(&absent_root);
        let automated_test =
            resolve_automated_test_database_path(&absent_root, "side-effect-check").unwrap();
        let restore = restore_staging_database_path(absent_root.join("production"));

        assert!(!absent_root.exists());
        assert!(!production.as_path().exists());
        assert!(!development.as_path().exists());
        assert!(!automated_test.as_path().exists());
        assert!(!restore.as_path().exists());
    }

    #[test]
    fn database_format_identity_is_fixed_and_independent() {
        assert_eq!(APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes().len(), 16);
        assert_ne!(
            APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            b"parish-data.db\0\0"
        );
    }

    #[test]
    fn parish_identifier_accepts_only_nonzero_opaque_128_bit_values() {
        let identifier = ParishIdentifier::parse("3f6a819cc2044ae3976c5e8b37d29140").unwrap();
        assert_eq!(identifier.as_bytes().len(), 16);

        assert!(ParishIdentifier::parse("").is_err());
        assert!(ParishIdentifier::parse("00000000000000000000000000000000").is_err());
        assert!(ParishIdentifier::parse("parish-name-should-never-be-an-id").is_err());
        assert!(ParishIdentifier::parse("3f6a819cc2044ae3976c5e8b37d2914g").is_err());
    }
}
