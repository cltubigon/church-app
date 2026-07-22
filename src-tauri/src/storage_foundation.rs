//! Rust-owned storage location and identity foundations.
//!
//! This module only resolves typed paths. It never creates, opens, reads, or writes them.

use std::path::{Path, PathBuf};

use tauri::Manager;

pub const PRODUCTION_DATABASE_FILENAME: &str = "parish-data.db";

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

    #[test]
    fn production_resolver_accepts_only_the_rust_application_handle() {
        let resolver: fn(&tauri::AppHandle) -> Result<ProductionDatabasePath, tauri::Error> =
            resolve_production_database_path;

        let _ = resolver;
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
