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
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const FRESHNESS_ANCHOR_DIRECTORY_NAME: &str = "freshness-anchor";
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME: &str =
    "anchor-authentication-key.dpapi";
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME: &str =
    "authenticated-freshness-anchor.dpapi";

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
    pub fn from_bytes(value: [u8; 16]) -> Result<Self, InvalidParishIdentifier> {
        if value == [0; 16] {
            return Err(InvalidParishIdentifier);
        }

        Ok(Self(value))
    }

    pub fn parse(value: &str) -> Result<Self, InvalidParishIdentifier> {
        if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(InvalidParishIdentifier);
        }

        let mut bytes = [0_u8; 16];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
        }

        Self::from_bytes(bytes)
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
redacted_persistence_path!(FreshnessAnchorDirectoryPath);
redacted_persistence_path!(ActiveAnchorAuthenticationKeyPath);
redacted_persistence_path!(ActiveAuthenticatedFreshnessAnchorPath);

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

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct FreshnessAnchorPersistencePaths {
    pub(crate) freshness_anchor_directory: FreshnessAnchorDirectoryPath,
    pub(crate) active_anchor_authentication_key: ActiveAnchorAuthenticationKeyPath,
    pub(crate) active_authenticated_freshness_anchor: ActiveAuthenticatedFreshnessAnchorPath,
}

impl fmt::Debug for FreshnessAnchorPersistencePaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshnessAnchorPersistencePaths([REDACTED])")
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

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn resolve_freshness_anchor_persistence_paths(
    app: &tauri::AppHandle,
) -> Result<FreshnessAnchorPersistencePaths, tauri::Error> {
    let app_local_data_directory = app.path().app_local_data_dir()?;
    Ok(freshness_anchor_persistence_paths(
        &app_local_data_directory,
    ))
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

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn freshness_anchor_persistence_paths(
    synthetic_root: &Path,
) -> FreshnessAnchorPersistencePaths {
    let freshness_anchor_directory = synthetic_root.join(FRESHNESS_ANCHOR_DIRECTORY_NAME);

    FreshnessAnchorPersistencePaths {
        freshness_anchor_directory: FreshnessAnchorDirectoryPath(
            freshness_anchor_directory.clone(),
        ),
        active_anchor_authentication_key: ActiveAnchorAuthenticationKeyPath(
            freshness_anchor_directory.join(ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME),
        ),
        active_authenticated_freshness_anchor: ActiveAuthenticatedFreshnessAnchorPath(
            freshness_anchor_directory.join(ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME),
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

    fn assert_freshness_anchor_paths(root: &Path) {
        let paths = freshness_anchor_persistence_paths(root);
        let anchor_directory = root.join(FRESHNESS_ANCHOR_DIRECTORY_NAME);

        assert_eq!(paths.freshness_anchor_directory.as_path(), anchor_directory);
        assert_eq!(
            paths.active_anchor_authentication_key.as_path(),
            anchor_directory.join(ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME)
        );
        assert_eq!(
            paths.active_authenticated_freshness_anchor.as_path(),
            anchor_directory.join(ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME)
        );
        assert_eq!(
            paths.freshness_anchor_directory.as_path().parent(),
            Some(root)
        );
        assert_eq!(
            paths.active_anchor_authentication_key.as_path().parent(),
            Some(anchor_directory.as_path())
        );
        assert_eq!(
            paths
                .active_authenticated_freshness_anchor
                .as_path()
                .parent(),
            Some(anchor_directory.as_path())
        );

        for active_path in [
            paths.active_anchor_authentication_key.as_path(),
            paths.active_authenticated_freshness_anchor.as_path(),
        ] {
            assert!(active_path.starts_with(root));
        }
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
    fn freshness_anchor_fixed_names_and_synthetic_layout_are_exact() {
        assert_eq!(FRESHNESS_ANCHOR_DIRECTORY_NAME, "freshness-anchor");
        assert_eq!(
            ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME,
            "anchor-authentication-key.dpapi"
        );
        assert_eq!(
            ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME,
            "authenticated-freshness-anchor.dpapi"
        );
        assert_ne!(
            ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME,
            ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME
        );

        assert_freshness_anchor_paths(Path::new(r"X:\synthetic-local-app-data\church-app"));
        assert_freshness_anchor_paths(Path::new("synthetic/portable/church-app"));
        assert_freshness_anchor_paths(Path::new("synthetic root/δοκιμή/教会-app"));
    }

    #[test]
    fn freshness_anchor_paths_are_structurally_independent_siblings() {
        let root = Path::new("synthetic-root");
        let anchor_paths = freshness_anchor_persistence_paths(root);
        let evidence_paths = installation_evidence_persistence_paths(root);
        let anchor_directory = root.join(FRESHNESS_ANCHOR_DIRECTORY_NAME);
        let evidence_directory = root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME);
        let database = root.join(PRODUCTION_DATABASE_FILENAME);
        let staged_database = root.join(PRODUCTION_DATABASE_STAGE_FILENAME);

        assert_eq!(anchor_directory.parent(), Some(root));
        assert_eq!(evidence_directory.parent(), Some(root));
        assert_ne!(anchor_directory, evidence_directory);
        assert_eq!(
            evidence_paths.evidence_directory.as_path(),
            evidence_directory
        );

        for active_path in [
            anchor_paths.active_anchor_authentication_key.as_path(),
            anchor_paths.active_authenticated_freshness_anchor.as_path(),
        ] {
            assert_eq!(active_path.parent(), Some(anchor_directory.as_path()));
            assert!(!active_path.starts_with(&evidence_directory));
            assert_ne!(active_path, database);
            assert_ne!(active_path, staged_database);
            assert!(active_path.starts_with(root));
        }
    }

    #[test]
    fn freshness_anchor_path_debug_output_redacts_every_inner_path_and_fixed_name() {
        let paths = freshness_anchor_persistence_paths(Path::new("sensitive-synthetic-root"));
        let debug_values = [
            format!("{:?}", paths.freshness_anchor_directory),
            format!("{:?}", paths.active_anchor_authentication_key),
            format!("{:?}", paths.active_authenticated_freshness_anchor),
            format!("{paths:?}"),
        ];

        for debug in debug_values {
            assert!(debug.contains("[REDACTED]"));
            for excluded in [
                "sensitive-synthetic-root",
                FRESHNESS_ANCHOR_DIRECTORY_NAME,
                ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME,
                ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME,
            ] {
                assert!(!debug.contains(excluded));
            }
        }
    }

    #[test]
    fn freshness_anchor_aggregate_has_exactly_the_three_approved_fields() {
        const SOURCE: &str = include_str!("storage_foundation.rs");
        let aggregate = SOURCE
            .split("pub(crate) struct FreshnessAnchorPersistencePaths")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl fmt::Debug for FreshnessAnchorPersistencePaths")
                    .next()
            })
            .expect("freshness-anchor aggregate should remain a distinct definition");

        assert_eq!(aggregate.matches("pub(crate)").count(), 3);
        for approved in [
            "freshness_anchor_directory: FreshnessAnchorDirectoryPath",
            "active_anchor_authentication_key: ActiveAnchorAuthenticationKeyPath",
            "active_authenticated_freshness_anchor: ActiveAuthenticatedFreshnessAnchorPath",
        ] {
            assert!(aggregate.contains(approved));
        }
        for excluded in [
            "database",
            "evidence",
            "stage",
            "previous",
            "retained",
            "intent",
            "backup",
            "recovery",
            "migration",
            "reset",
        ] {
            assert!(!aggregate.contains(excluded));
        }
    }

    #[test]
    fn freshness_anchor_contract_declares_only_the_three_approved_path_owners() {
        const SOURCE: &str = include_str!("storage_foundation.rs");
        let production_source = SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("module should contain a test boundary");

        for approved in [
            "redacted_persistence_path!(FreshnessAnchorDirectoryPath);",
            "redacted_persistence_path!(ActiveAnchorAuthenticationKeyPath);",
            "redacted_persistence_path!(ActiveAuthenticatedFreshnessAnchorPath);",
        ] {
            assert_eq!(production_source.matches(approved).count(), 1);
        }
        assert_eq!(
            production_source
                .lines()
                .filter(|line| line.contains("redacted_persistence_path!("))
                .filter(|line| {
                    line.contains("FreshnessAnchor") || line.contains("AnchorAuthenticationKeyPath")
                })
                .count(),
            3
        );
        for excluded in [
            "StagedFreshnessAnchor",
            "PreviousFreshnessAnchor",
            "RetainedFreshnessAnchor",
            "FreshnessAnchorPublicationIntent",
            "FreshnessAnchorBackup",
            "FreshnessAnchorRecovery",
            "FreshnessAnchorMigration",
            "FreshnessAnchorReset",
        ] {
            assert!(!production_source.contains(excluded));
        }
    }

    #[test]
    fn freshness_anchor_constructor_uses_only_path_joins() {
        const SOURCE: &str = include_str!("storage_foundation.rs");
        let constructor = SOURCE
            .split("pub(crate) fn freshness_anchor_persistence_paths")
            .nth(1)
            .and_then(|tail| tail.split("fn restore_staging_database_path").next())
            .expect("freshness-anchor constructor should remain a distinct function");

        assert!(constructor.contains(".join("));
        for excluded in [
            "std::fs",
            "File",
            "OpenOptions",
            "create_dir",
            ".read(",
            ".write(",
            "remove",
            "rename",
            "canonicalize",
            "metadata",
            "read_dir",
            "windows_sys",
            "app.path()",
            "std::env",
            "std::time",
            "getrandom",
        ] {
            assert!(!constructor.contains(excluded));
        }
    }

    #[test]
    fn freshness_anchor_resolver_is_a_single_canonical_tauri_path_boundary() {
        let resolver: fn(
            &tauri::AppHandle,
        ) -> Result<FreshnessAnchorPersistencePaths, tauri::Error> =
            resolve_freshness_anchor_persistence_paths;
        let _ = resolver;

        const SOURCE: &str = include_str!("storage_foundation.rs");
        let resolver_source = SOURCE
            .split("pub(crate) fn resolve_freshness_anchor_persistence_paths")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub fn resolve_automated_test_database_path")
                    .next()
            })
            .expect("freshness-anchor resolver should remain a distinct function");

        assert_eq!(resolver_source.matches("app_local_data_dir()").count(), 1);
        assert!(resolver_source.contains("freshness_anchor_persistence_paths("));
        for excluded in [
            "std::fs",
            "File::",
            "OpenOptions",
            "create_dir",
            ".exists()",
            ".open(",
            ".read(",
            ".write(",
            "std::env",
        ] {
            assert!(!resolver_source.contains(excluded));
        }
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

    #[test]
    fn parish_identifier_byte_construction_is_exact_and_rejects_zero() {
        let bytes = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];

        let identifier = ParishIdentifier::from_bytes(bytes)
            .expect("synthetic nonzero parish bytes should be valid");

        assert_eq!(identifier.as_bytes(), &bytes);
        assert_eq!(
            ParishIdentifier::from_bytes([0; 16]),
            Err(InvalidParishIdentifier)
        );
    }

    #[test]
    fn parish_identifier_text_and_bytes_construct_the_same_typed_value() {
        let bytes = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];

        assert_eq!(
            ParishIdentifier::from_bytes(bytes).unwrap(),
            ParishIdentifier::parse("101112131415161718191a1b1c1d1e1f").unwrap()
        );
    }

    #[test]
    fn parish_byte_constructor_has_no_text_bridge_or_broader_surface() {
        const SOURCE: &str = include_str!("storage_foundation.rs");
        let production_source = SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("module should contain a test boundary");
        let constructor = production_source
            .split_once("pub fn from_bytes(value: [u8; 16])")
            .expect("parish byte constructor should have one exact signature")
            .1
            .split_once("pub fn parse")
            .expect("text parser should remain separate")
            .0;

        assert_eq!(
            production_source
                .matches("pub fn from_bytes(value: [u8; 16])")
                .count(),
            1
        );
        for forbidden in [
            "parse",
            "hex",
            "str",
            "String",
            "format!",
            "getrandom",
            "rand::",
            "std::fs",
            "std::env",
            "std::time",
            "rusqlite",
            "sqlx",
            "windows::",
            "tauri::",
            "serde",
        ] {
            assert!(
                !constructor.contains(forbidden),
                "parish byte constructor unexpectedly contains {forbidden}"
            );
        }

        for forbidden in [
            "as_bytes_mut",
            "impl From<",
            "impl Into<",
            "Serialize",
            "Deserialize",
        ] {
            assert!(
                !production_source.contains(forbidden),
                "storage identity surface unexpectedly contains {forbidden}"
            );
        }
    }
}
