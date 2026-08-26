//! Windows-test-only exporter for one synthetic manual startup fixture.

#![cfg(all(test, windows))]

use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

use rusqlite::{Connection, OpenFlags, params_from_iter, types::Value};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

use crate::{
    database_freshness_classification::NormalizedFreshnessAnchorObservation,
    database_key::DatabaseKey,
    database_key_active_wrapper_loader::load_active_database_key_wrapper,
    database_key_presence::inspect_database_key_active_presence,
    database_metadata_contract::{DatabaseCreationTimestamp, DatabaseMetadataContractV1},
    freshness_anchor_authenticated_envelope::{
        AnchorAuthenticationKeyGenerationIdentifier, construct_authenticated_freshness_anchor_v1,
    },
    freshness_anchor_authentication_key::AnchorAuthenticationKey,
    freshness_anchor_contract::FreshnessAnchorContractV1,
    freshness_anchor_plaintext::EncodedFreshnessAnchorV1,
    installation_evidence_authenticated_envelope::{
        EvidenceAuthenticationKeyGenerationIdentifier, construct_authenticated_envelope_v1,
    },
    installation_evidence_authentication_key::EvidenceAuthenticationKey,
    installation_evidence_contract::{
        DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
        PERMANENT_APPLICATION_IDENTIFIER, PermanentApplicationIdentifier,
        RecoveryOrReplacementGeneration, SetupPublicationIdentifier,
        StructurallyValidatedInstallationEvidence, UnvalidatedInstallationEvidenceContract,
    },
    installation_evidence_persistence::observe_production_installation_evidence,
    installation_evidence_protection::{
        GenerationBoundDatabaseKey, bind_database_key_candidate_to_trusted_installation_evidence,
        load_trusted_current_installation_evidence_assessment,
        observe_normalized_current_freshness_anchor,
        protect_anchor_authentication_material_for_manual_startup_fixture,
        protect_authenticated_evidence,
        protect_authenticated_freshness_anchor_for_manual_startup_fixture,
        protect_authentication_material, protect_database_key_for_manual_startup_fixture,
        recover_database_key_candidate_from_loaded_wrapper,
    },
    installation_state::{ExpectedStorageEvidence, InstallationEvidence},
    production_database_connection_handoff::{
        DatabaseEvidenceCorrespondenceValidationOutcome, LiveMetadataAndHeaderValidationOutcome,
        ProductionDatabaseConnectionCloseOutcome, ProductionDatabaseFreshnessValidationOutcome,
        ProductionDatabaseValidationOutcome, open_keyed_production_database_read_only,
        validate_production_database_evidence_correspondence,
        validate_production_database_freshness,
        validate_production_database_live_metadata_and_headers,
        validate_production_database_readability_and_integrity,
    },
    production_database_file::{ProductionDatabaseInspection, inspect_production_database_file},
    sqlcipher_database_key_application::apply_generation_bound_database_key_to_handle,
    storage_foundation::{
        ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME, ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME,
        ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME, ACTIVE_AUTHENTICATION_KEY_FILENAME,
        ACTIVE_DATABASE_KEY_FILENAME, APPLICATION_DATABASE_FORMAT_IDENTITY,
        DATABASE_KEY_DIRECTORY_NAME, FRESHNESS_ANCHOR_DIRECTORY_NAME,
        INSTALLATION_EVIDENCE_DIRECTORY_NAME, PRODUCTION_DATABASE_FILENAME, ParishIdentifier,
        database_key_persistence_paths, freshness_anchor_persistence_paths,
        installation_evidence_persistence_paths, production_database_path,
    },
};

const MANUAL_ROOT_ENVIRONMENT_VARIABLE: &str = "CHURCH_APP_MANUAL_STARTUP_TEST_ROOT";
const MANUAL_ROOT_PREFIX: &str = "church-app-manual-startup-";
const FIXTURE_MARKER_NAME: &str = ".church-app-manual-startup-fixture-v1";
const FIXTURE_MARKER_CONTENT: &[u8] = b"synthetic Church App manual startup fixture v1\n";
const TAURI_APPLICATION_IDENTIFIER: &str = "io.github.cltubigon.churchapp";

const SYNTHETIC_PARISH_TEXT: &str = "101112131415161718191a1b1c1d1e1f";
const SYNTHETIC_INSTALLATION_IDENTIFIER: [u8; 16] = [0x21; 16];
const SYNTHETIC_DATABASE_KEY_GENERATION_IDENTIFIER: [u8; 16] = [0x43; 16];
const SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER: [u8; 16] = [0x65; 16];
const SYNTHETIC_DATABASE_KEY: [u8; 32] = [0x74; 32];
const SYNTHETIC_EVIDENCE_AUTHENTICATION_KEY: [u8; 32] = [0x52; 32];
const SYNTHETIC_EVIDENCE_AUTHENTICATION_KEY_GENERATION: [u8; 16] = [0x53; 16];
const SYNTHETIC_ANCHOR_AUTHENTICATION_KEY: [u8; 32] = [0x85; 32];
const SYNTHETIC_ANCHOR_AUTHENTICATION_KEY_GENERATION: [u8; 16] = [0x86; 16];
const SYNTHETIC_INSTALLATION_GENERATION: u64 = 7;
const SYNTHETIC_RECOVERY_REPLACEMENT_GENERATION: u64 = 11;
const SYNTHETIC_EVIDENCE_CREATED_AT_SECONDS: u64 = 1_798_000_000;
const SYNTHETIC_DATABASE_CREATED_AT_MILLISECONDS: u64 = 1_798_000_000_123;
const ACCEPTED_APPLICATION_ID: i32 = 0x4348_4150;
const ACCEPTED_USER_VERSION: i32 = 1;

const CREATE_METADATA_RELATION: &str = "CREATE TABLE church_app_database_metadata (
    singleton_id,
    metadata_contract_version,
    database_schema_version,
    permanent_application_identifier,
    database_format_identity,
    parish_identifier,
    installation_identifier,
    installation_generation,
    recovery_replacement_generation,
    database_key_generation_identifier,
    setup_publication_identifier,
    database_created_at
)";
const INSERT_METADATA_ROW: &str = "INSERT INTO church_app_database_metadata VALUES
    (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

#[derive(Clone, Copy, Eq, PartialEq)]
struct ManualStartupFixtureError;

impl fmt::Debug for ManualStartupFixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManualStartupFixtureError([REDACTED])")
    }
}

type FixtureResult<T> = Result<T, ManualStartupFixtureError>;

#[derive(Clone, Copy)]
struct SyntheticIdentityPackage {
    parish_identifier: ParishIdentifier,
    installation_identifier: InstallationIdentifier,
    installation_generation: InstallationGeneration,
    recovery_replacement_generation: RecoveryOrReplacementGeneration,
    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
    setup_publication_identifier: SetupPublicationIdentifier,
    evidence: StructurallyValidatedInstallationEvidence,
    database_metadata: DatabaseMetadataContractV1,
    freshness_anchor: FreshnessAnchorContractV1,
}

impl SyntheticIdentityPackage {
    fn fixed() -> FixtureResult<Self> {
        let parish_identifier = ParishIdentifier::parse(SYNTHETIC_PARISH_TEXT)
            .map_err(|_| ManualStartupFixtureError)?;
        let installation_identifier =
            InstallationIdentifier::from_bytes(SYNTHETIC_INSTALLATION_IDENTIFIER)
                .map_err(|_| ManualStartupFixtureError)?;
        let installation_generation =
            InstallationGeneration::new(SYNTHETIC_INSTALLATION_GENERATION)
                .map_err(|_| ManualStartupFixtureError)?;
        let recovery_replacement_generation =
            RecoveryOrReplacementGeneration::new(SYNTHETIC_RECOVERY_REPLACEMENT_GENERATION)
                .map_err(|_| ManualStartupFixtureError)?;
        let database_key_generation_identifier = DatabaseKeyGenerationIdentifier::from_bytes(
            SYNTHETIC_DATABASE_KEY_GENERATION_IDENTIFIER,
        )
        .map_err(|_| ManualStartupFixtureError)?;
        let setup_publication_identifier =
            SetupPublicationIdentifier::from_bytes(SYNTHETIC_SETUP_PUBLICATION_IDENTIFIER)
                .map_err(|_| ManualStartupFixtureError)?;

        let evidence = UnvalidatedInstallationEvidenceContract::new(
            *crate::installation_evidence_contract::INSTALLATION_EVIDENCE_FORMAT_IDENTITY
                .as_bytes(),
            crate::installation_evidence_contract::SUPPORTED_EVIDENCE_FORMAT_VERSION,
            PERMANENT_APPLICATION_IDENTIFIER,
            *APPLICATION_DATABASE_FORMAT_IDENTITY.as_bytes(),
            SYNTHETIC_PARISH_TEXT,
            installation_identifier_bytes(installation_identifier),
            installation_generation.get(),
            recovery_replacement_generation.get(),
            database_key_generation_identifier_bytes(database_key_generation_identifier),
            setup_publication_identifier_bytes(setup_publication_identifier),
            SYNTHETIC_EVIDENCE_CREATED_AT_SECONDS,
        )
        .validate()
        .map_err(|_| ManualStartupFixtureError)?;

        let database_metadata = DatabaseMetadataContractV1::new(
            PermanentApplicationIdentifier::canonical(),
            parish_identifier,
            installation_identifier,
            installation_generation,
            recovery_replacement_generation,
            database_key_generation_identifier,
            setup_publication_identifier,
            DatabaseCreationTimestamp::from_unix_milliseconds(
                SYNTHETIC_DATABASE_CREATED_AT_MILLISECONDS,
            ),
        );
        let freshness_anchor = FreshnessAnchorContractV1::new(
            installation_identifier,
            installation_generation,
            recovery_replacement_generation,
            database_key_generation_identifier,
            setup_publication_identifier,
        );

        Ok(Self {
            parish_identifier,
            installation_identifier,
            installation_generation,
            recovery_replacement_generation,
            database_key_generation_identifier,
            setup_publication_identifier,
            evidence,
            database_metadata,
            freshness_anchor,
        })
    }
}

fn installation_identifier_bytes(identifier: InstallationIdentifier) -> [u8; 16] {
    let mut bytes = [0; 16];
    identifier.write_bytes_into(&mut bytes);
    bytes
}

fn database_key_generation_identifier_bytes(
    identifier: DatabaseKeyGenerationIdentifier,
) -> [u8; 16] {
    let mut bytes = [0; 16];
    identifier.write_bytes_into(&mut bytes);
    bytes
}

fn setup_publication_identifier_bytes(identifier: SetupPublicationIdentifier) -> [u8; 16] {
    let mut bytes = [0; 16];
    identifier.write_bytes_into(&mut bytes);
    bytes
}

fn normalized_windows_disk_path(path: &Path) -> FixtureResult<String> {
    if path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(ManualStartupFixtureError);
    }
    let text = path.to_str().ok_or(ManualStartupFixtureError)?;
    let text = text.strip_prefix("\\\\?\\").unwrap_or(text);
    let text = text.replace('/', "\\");
    let bytes = text.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err(ManualStartupFixtureError);
    }

    let mut normalized = format!("{}:\\", char::from(bytes[0]).to_ascii_uppercase());
    let remainder = &text[3..];
    if !remainder.is_empty() {
        let components: Vec<_> = remainder.split('\\').collect();
        for (index, component) in components.iter().enumerate() {
            if component.is_empty() {
                if index + 1 == components.len() {
                    continue;
                }
                return Err(ManualStartupFixtureError);
            }
            if *component == "." || *component == ".." {
                return Err(ManualStartupFixtureError);
            }
            if !normalized.ends_with('\\') {
                normalized.push('\\');
            }
            normalized.push_str(&component.to_lowercase());
        }
    }
    Ok(normalized)
}

fn canonical_production_root() -> FixtureResult<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or(ManualStartupFixtureError)?;
    let root = PathBuf::from(local_app_data).join(TAURI_APPLICATION_IDENTIFIER);
    normalized_windows_disk_path(&root)?;
    Ok(root)
}

fn validate_requested_root_input(
    input: Option<OsString>,
    temporary_directory: &Path,
    production_root: &Path,
) -> FixtureResult<PathBuf> {
    let requested = PathBuf::from(input.ok_or(ManualStartupFixtureError)?);
    if !requested.is_absolute() {
        return Err(ManualStartupFixtureError);
    }
    let requested_key = normalized_windows_disk_path(&requested)?;
    let temporary_key = normalized_windows_disk_path(temporary_directory)?;
    let production_key = normalized_windows_disk_path(production_root)?;
    if requested_key == production_key {
        return Err(ManualStartupFixtureError);
    }

    let file_name = requested
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(ManualStartupFixtureError)?;
    if !file_name.starts_with(MANUAL_ROOT_PREFIX) || file_name == MANUAL_ROOT_PREFIX {
        return Err(ManualStartupFixtureError);
    }
    let parent = requested.parent().ok_or(ManualStartupFixtureError)?;
    if normalized_windows_disk_path(parent)? != temporary_key {
        return Err(ManualStartupFixtureError);
    }

    match fs::symlink_metadata(&requested) {
        Ok(_) => return Err(ManualStartupFixtureError),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ManualStartupFixtureError),
    }
    Ok(requested)
}

fn validate_requested_root_from_environment() -> FixtureResult<PathBuf> {
    let temporary_directory =
        fs::canonicalize(std::env::temp_dir()).map_err(|_| ManualStartupFixtureError)?;
    let temporary_metadata =
        fs::symlink_metadata(&temporary_directory).map_err(|_| ManualStartupFixtureError)?;
    if !temporary_metadata.is_dir()
        || temporary_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(ManualStartupFixtureError);
    }
    if normalized_windows_disk_path(&temporary_directory)?
        != normalized_windows_disk_path(
            &fs::canonicalize(&temporary_directory).map_err(|_| ManualStartupFixtureError)?,
        )?
    {
        return Err(ManualStartupFixtureError);
    }
    validate_requested_root_input(
        std::env::var_os(MANUAL_ROOT_ENVIRONMENT_VARIABLE),
        &temporary_directory,
        &canonical_production_root()?,
    )
}

fn verify_fresh_created_root(root: &Path) -> FixtureResult<()> {
    let metadata = fs::symlink_metadata(root).map_err(|_| ManualStartupFixtureError)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ManualStartupFixtureError);
    }
    let canonical = fs::canonicalize(root).map_err(|_| ManualStartupFixtureError)?;
    if normalized_windows_disk_path(&canonical)? != normalized_windows_disk_path(root)? {
        return Err(ManualStartupFixtureError);
    }
    Ok(())
}

fn create_directory(path: &Path) -> FixtureResult<()> {
    fs::create_dir(path).map_err(|_| ManualStartupFixtureError)
}

fn create_file_exact(path: &Path, bytes: &[u8]) -> FixtureResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ManualStartupFixtureError)?;
    file.write_all(bytes)
        .map_err(|_| ManualStartupFixtureError)?;
    file.flush().map_err(|_| ManualStartupFixtureError)?;
    drop(file);
    Ok(())
}

fn persist_installation_evidence(
    root: &Path,
    package: &SyntheticIdentityPackage,
) -> FixtureResult<()> {
    let paths = installation_evidence_persistence_paths(root);
    let key = EvidenceAuthenticationKey::from_bytes(SYNTHETIC_EVIDENCE_AUTHENTICATION_KEY);
    let generation = EvidenceAuthenticationKeyGenerationIdentifier::from_bytes(
        SYNTHETIC_EVIDENCE_AUTHENTICATION_KEY_GENERATION,
    )
    .map_err(|_| ManualStartupFixtureError)?;
    let (envelope, _) =
        construct_authenticated_envelope_v1(&key, generation, &package.evidence.encode_v1())
            .map_err(|_| ManualStartupFixtureError)?;
    let protected_key =
        protect_authentication_material(&key, generation).map_err(|_| ManualStartupFixtureError)?;
    let protected_evidence =
        protect_authenticated_evidence(&envelope).map_err(|_| ManualStartupFixtureError)?;
    create_file_exact(
        paths.active_authentication_key.as_path(),
        protected_key.as_bytes(),
    )?;
    create_file_exact(
        paths.active_authenticated_evidence.as_path(),
        protected_evidence.as_bytes(),
    )
}

fn persist_database_key(root: &Path, package: &SyntheticIdentityPackage) -> FixtureResult<()> {
    let paths = database_key_persistence_paths(root);
    let key = DatabaseKey::from_bytes(SYNTHETIC_DATABASE_KEY);
    let wrapper = protect_database_key_for_manual_startup_fixture(
        &key,
        package.database_key_generation_identifier,
    )
    .map_err(|_| ManualStartupFixtureError)?;
    create_file_exact(paths.active_database_key.as_path(), wrapper.as_bytes())
}

fn persist_freshness_anchor(root: &Path, package: &SyntheticIdentityPackage) -> FixtureResult<()> {
    let paths = freshness_anchor_persistence_paths(root);
    let key = AnchorAuthenticationKey::from_bytes(SYNTHETIC_ANCHOR_AUTHENTICATION_KEY);
    let generation = AnchorAuthenticationKeyGenerationIdentifier::from_bytes(
        SYNTHETIC_ANCHOR_AUTHENTICATION_KEY_GENERATION,
    )
    .map_err(|_| ManualStartupFixtureError)?;
    let plaintext = EncodedFreshnessAnchorV1::encode(&package.freshness_anchor);
    let envelope = construct_authenticated_freshness_anchor_v1(&key, generation, &plaintext)
        .map_err(|_| ManualStartupFixtureError)?;
    let protected_key =
        protect_anchor_authentication_material_for_manual_startup_fixture(&key, generation)
            .map_err(|_| ManualStartupFixtureError)?;
    let protected_anchor =
        protect_authenticated_freshness_anchor_for_manual_startup_fixture(&envelope)
            .map_err(|_| ManualStartupFixtureError)?;
    create_file_exact(
        paths.active_anchor_authentication_key.as_path(),
        protected_key.as_bytes(),
    )?;
    create_file_exact(
        paths.active_authenticated_freshness_anchor.as_path(),
        protected_anchor.as_bytes(),
    )
}

fn recover_generation_bound_database_key(
    root: &Path,
    assessment: &crate::installation_evidence_protection::TrustedCurrentInstallationEvidenceAssessment,
) -> FixtureResult<GenerationBoundDatabaseKey> {
    let paths = database_key_persistence_paths(root);
    let presence = inspect_database_key_active_presence(&paths);
    let loaded = load_active_database_key_wrapper(&paths, presence)
        .map_err(|_| ManualStartupFixtureError)?;
    let candidate = recover_database_key_candidate_from_loaded_wrapper(&loaded)
        .map_err(|_| ManualStartupFixtureError)?;
    bind_database_key_candidate_to_trusted_installation_evidence(candidate, assessment)
        .map_err(|_| ManualStartupFixtureError)
}

fn metadata_values(package: &SyntheticIdentityPackage) -> FixtureResult<[Value; 12]> {
    let metadata = package.database_metadata;
    let created_at = i64::try_from(metadata.database_created_at().unix_milliseconds())
        .map_err(|_| ManualStartupFixtureError)?;
    Ok([
        Value::Integer(i64::from(metadata.singleton_id().get())),
        Value::Integer(i64::from(metadata.metadata_contract_version().get())),
        Value::Integer(i64::from(metadata.database_schema_version().get())),
        Value::Text(
            metadata
                .permanent_application_identifier()
                .as_str()
                .to_owned(),
        ),
        Value::Blob(metadata.database_format_identity().as_bytes().to_vec()),
        Value::Blob(metadata.parish_identifier().as_bytes().to_vec()),
        Value::Blob(installation_identifier_bytes(metadata.installation_identifier()).to_vec()),
        Value::Blob(
            metadata
                .installation_generation()
                .get()
                .to_be_bytes()
                .to_vec(),
        ),
        Value::Blob(
            metadata
                .recovery_replacement_generation()
                .get()
                .to_be_bytes()
                .to_vec(),
        ),
        Value::Blob(
            database_key_generation_identifier_bytes(metadata.database_key_generation_identifier())
                .to_vec(),
        ),
        Value::Blob(
            setup_publication_identifier_bytes(metadata.setup_publication_identifier()).to_vec(),
        ),
        Value::Integer(created_at),
    ])
}

fn create_sqlcipher_database(root: &Path, package: &SyntheticIdentityPackage) -> FixtureResult<()> {
    let evidence_paths = installation_evidence_persistence_paths(root);
    let assessment = load_trusted_current_installation_evidence_assessment(&evidence_paths)
        .map_err(|_| ManualStartupFixtureError)?;
    let key = recover_generation_bound_database_key(root, &assessment)?;
    let database_path = root.join(PRODUCTION_DATABASE_FILENAME);
    create_file_exact(&database_path, &[])?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
    let mut connection = Connection::open_with_flags(&database_path, flags)
        .map_err(|_| ManualStartupFixtureError)?;
    // SAFETY: this is one newly created, exclusively owned live SQLCipher
    // connection, and the borrowed key remains live for the synchronous call.
    unsafe { apply_generation_bound_database_key_to_handle(connection.handle(), &key) }
        .map_err(|_| ManualStartupFixtureError)?;
    connection
        .execute_batch(&format!(
            "PRAGMA application_id = {ACCEPTED_APPLICATION_ID}; PRAGMA user_version = {ACCEPTED_USER_VERSION};"
        ))
        .map_err(|_| ManualStartupFixtureError)?;
    let transaction = connection
        .transaction()
        .map_err(|_| ManualStartupFixtureError)?;
    transaction
        .execute_batch(CREATE_METADATA_RELATION)
        .map_err(|_| ManualStartupFixtureError)?;
    let values = metadata_values(package)?;
    transaction
        .execute(INSERT_METADATA_ROW, params_from_iter(values.iter()))
        .map_err(|_| ManualStartupFixtureError)?;
    transaction
        .commit()
        .map_err(|_| ManualStartupFixtureError)?;
    connection.close().map_err(|_| ManualStartupFixtureError)
}

fn sorted_names(path: &Path) -> FixtureResult<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(path).map_err(|_| ManualStartupFixtureError)? {
        let name = entry
            .map_err(|_| ManualStartupFixtureError)?
            .file_name()
            .into_string()
            .map_err(|_| ManualStartupFixtureError)?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}

fn regular_non_reparse_file(path: &Path) -> FixtureResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ManualStartupFixtureError)?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ManualStartupFixtureError);
    }
    Ok(())
}

fn verify_exact_fixture_layout(root: &Path) -> FixtureResult<()> {
    let mut expected_root = vec![
        FIXTURE_MARKER_NAME.to_owned(),
        PRODUCTION_DATABASE_FILENAME.to_owned(),
        INSTALLATION_EVIDENCE_DIRECTORY_NAME.to_owned(),
        DATABASE_KEY_DIRECTORY_NAME.to_owned(),
        FRESHNESS_ANCHOR_DIRECTORY_NAME.to_owned(),
    ];
    expected_root.sort();
    if sorted_names(root)? != expected_root {
        return Err(ManualStartupFixtureError);
    }
    if sorted_names(&root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME))?
        != vec![
            ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME.to_owned(),
            ACTIVE_AUTHENTICATION_KEY_FILENAME.to_owned(),
        ]
    {
        return Err(ManualStartupFixtureError);
    }
    if sorted_names(&root.join(DATABASE_KEY_DIRECTORY_NAME))?
        != vec![ACTIVE_DATABASE_KEY_FILENAME.to_owned()]
    {
        return Err(ManualStartupFixtureError);
    }
    if sorted_names(&root.join(FRESHNESS_ANCHOR_DIRECTORY_NAME))?
        != vec![
            ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME.to_owned(),
            ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME.to_owned(),
        ]
    {
        return Err(ManualStartupFixtureError);
    }
    for path in [
        root.join(FIXTURE_MARKER_NAME),
        root.join(PRODUCTION_DATABASE_FILENAME),
        root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME)
            .join(ACTIVE_AUTHENTICATION_KEY_FILENAME),
        root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME)
            .join(ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME),
        root.join(DATABASE_KEY_DIRECTORY_NAME)
            .join(ACTIVE_DATABASE_KEY_FILENAME),
        root.join(FRESHNESS_ANCHOR_DIRECTORY_NAME)
            .join(ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME),
        root.join(FRESHNESS_ANCHOR_DIRECTORY_NAME)
            .join(ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME),
    ] {
        regular_non_reparse_file(&path)?;
    }
    Ok(())
}

fn self_verify_fixture(root: &Path) -> FixtureResult<()> {
    let evidence_paths = installation_evidence_persistence_paths(root);
    if observe_production_installation_evidence(&evidence_paths)
        != InstallationEvidence::Initialized(ExpectedStorageEvidence::Present)
    {
        return Err(ManualStartupFixtureError);
    }
    let assessment = load_trusted_current_installation_evidence_assessment(&evidence_paths)
        .map_err(|_| ManualStartupFixtureError)?;
    let anchor_observation = observe_normalized_current_freshness_anchor(
        &freshness_anchor_persistence_paths(root),
        assessment.trusted_identity(),
    );
    if !matches!(
        anchor_observation,
        NormalizedFreshnessAnchorObservation::Present(_)
    ) {
        return Err(ManualStartupFixtureError);
    }
    let key = recover_generation_bound_database_key(root, &assessment)?;
    let database_path = production_database_path(root.to_path_buf());
    let inspected = match inspect_production_database_file(&database_path) {
        ProductionDatabaseInspection::Present(inspected) => inspected,
        _ => return Err(ManualStartupFixtureError),
    };
    let keyed = open_keyed_production_database_read_only(database_path, inspected, key)
        .map_err(|_| ManualStartupFixtureError)?;
    let readable = match validate_production_database_readability_and_integrity(keyed) {
        ProductionDatabaseValidationOutcome::Validated(owner) => owner,
        _ => return Err(ManualStartupFixtureError),
    };
    let metadata = match validate_production_database_live_metadata_and_headers(readable) {
        LiveMetadataAndHeaderValidationOutcome::Validated(owner) => owner,
        _ => return Err(ManualStartupFixtureError),
    };
    let corresponding =
        match validate_production_database_evidence_correspondence(metadata, assessment) {
            DatabaseEvidenceCorrespondenceValidationOutcome::Validated(owner) => owner,
            _ => return Err(ManualStartupFixtureError),
        };
    let fresh = match validate_production_database_freshness(corresponding, anchor_observation) {
        ProductionDatabaseFreshnessValidationOutcome::Validated(owner) => owner,
        _ => return Err(ManualStartupFixtureError),
    };
    if !matches!(
        fresh.close(),
        ProductionDatabaseConnectionCloseOutcome::Closed
    ) {
        return Err(ManualStartupFixtureError);
    }
    Ok(())
}

fn export_fixture() -> FixtureResult<()> {
    let root = validate_requested_root_from_environment()?;
    create_directory(&root)?;
    verify_fresh_created_root(&root)?;
    create_file_exact(&root.join(FIXTURE_MARKER_NAME), FIXTURE_MARKER_CONTENT)?;
    create_directory(&root.join(INSTALLATION_EVIDENCE_DIRECTORY_NAME))?;
    create_directory(&root.join(DATABASE_KEY_DIRECTORY_NAME))?;
    create_directory(&root.join(FRESHNESS_ANCHOR_DIRECTORY_NAME))?;

    let package = SyntheticIdentityPackage::fixed()?;
    persist_installation_evidence(&root, &package)?;
    persist_database_key(&root, &package)?;
    create_sqlcipher_database(&root, &package)?;
    persist_freshness_anchor(&root, &package)?;
    verify_exact_fixture_layout(&root)?;
    self_verify_fixture(&root)?;
    verify_exact_fixture_layout(&root)
}

#[test]
#[ignore = "manual fixture export requires an explicitly reviewed isolated Windows temporary root"]
fn export_complete_manual_startup_fixture() {
    export_fixture().expect("manual startup fixture export failed");
    println!("Church App manual startup fixture exported successfully.");
}

#[cfg(test)]
mod tests {
    use std::{
        os::windows::ffi::OsStringExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

    fn canonical_temp() -> PathBuf {
        fs::canonicalize(std::env::temp_dir()).unwrap()
    }

    fn unique_requested(name: &str) -> PathBuf {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        canonical_temp().join(format!(
            "{MANUAL_ROOT_PREFIX}{name}-{}-{sequence}",
            std::process::id()
        ))
    }

    fn synthetic_production_root() -> PathBuf {
        canonical_temp().join("synthetic-production-root")
    }

    #[test]
    fn missing_environment_value_is_rejected_without_writes() {
        assert_eq!(
            validate_requested_root_input(None, &canonical_temp(), &synthetic_production_root()),
            Err(ManualStartupFixtureError)
        );
    }

    #[test]
    fn relative_path_is_rejected_without_writes() {
        let relative = PathBuf::from(format!("{MANUAL_ROOT_PREFIX}relative"));
        assert_eq!(
            validate_requested_root_input(
                Some(relative.clone().into_os_string()),
                &canonical_temp(),
                &synthetic_production_root(),
            ),
            Err(ManualStartupFixtureError)
        );
        assert!(!relative.exists());
    }

    #[test]
    fn path_outside_temporary_directory_is_rejected_without_writes() {
        let outside = std::env::current_dir()
            .unwrap()
            .join(format!("{MANUAL_ROOT_PREFIX}outside"));
        assert_eq!(
            validate_requested_root_input(
                Some(outside.clone().into_os_string()),
                &canonical_temp(),
                &synthetic_production_root(),
            ),
            Err(ManualStartupFixtureError)
        );
        assert!(!outside.exists());
    }

    #[test]
    fn wrong_prefix_is_rejected_without_writes() {
        let requested = canonical_temp().join("wrong-manual-startup-prefix");
        assert_eq!(
            validate_requested_root_input(
                Some(requested.clone().into_os_string()),
                &canonical_temp(),
                &synthetic_production_root(),
            ),
            Err(ManualStartupFixtureError)
        );
        assert!(!requested.exists());
    }

    #[test]
    fn existing_root_is_rejected_and_only_test_created_root_is_removed() {
        let requested = unique_requested("existing");
        fs::create_dir(&requested).unwrap();
        assert_eq!(
            validate_requested_root_input(
                Some(requested.clone().into_os_string()),
                &canonical_temp(),
                &synthetic_production_root(),
            ),
            Err(ManualStartupFixtureError)
        );
        fs::remove_dir(&requested).unwrap();
        assert!(!requested.exists());
    }

    #[test]
    fn canonical_production_root_equality_is_rejected_without_writes() {
        let requested = unique_requested("canonical-equality");
        assert_eq!(
            validate_requested_root_input(
                Some(requested.clone().into_os_string()),
                &canonical_temp(),
                &requested,
            ),
            Err(ManualStartupFixtureError)
        );
        assert!(!requested.exists());
    }

    #[test]
    fn embedded_nul_path_is_rejected_without_writes() {
        let malformed = OsString::from_wide(&[
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            b't' as u16,
            0,
            b'x' as u16,
        ]);
        assert_eq!(
            validate_requested_root_input(
                Some(malformed),
                &canonical_temp(),
                &synthetic_production_root(),
            ),
            Err(ManualStartupFixtureError)
        );
    }

    #[test]
    fn valid_root_validation_performs_no_writes() {
        let requested = unique_requested("no-writes");
        assert_eq!(
            validate_requested_root_input(
                Some(requested.clone().into_os_string()),
                &canonical_temp(),
                &synthetic_production_root(),
            ),
            Ok(requested.clone())
        );
        assert!(!requested.exists());
    }

    #[test]
    fn marker_and_complete_layout_names_are_exact() {
        assert_eq!(FIXTURE_MARKER_NAME, ".church-app-manual-startup-fixture-v1");
        assert_eq!(
            [
                FIXTURE_MARKER_NAME,
                PRODUCTION_DATABASE_FILENAME,
                ACTIVE_AUTHENTICATION_KEY_FILENAME,
                ACTIVE_AUTHENTICATED_EVIDENCE_FILENAME,
                ACTIVE_DATABASE_KEY_FILENAME,
                ACTIVE_ANCHOR_AUTHENTICATION_KEY_FILENAME,
                ACTIVE_AUTHENTICATED_FRESHNESS_ANCHOR_FILENAME,
            ],
            [
                ".church-app-manual-startup-fixture-v1",
                "parish-data.db",
                "authentication-key.dpapi",
                "authenticated-evidence.dpapi",
                "active-database-key.dpapi",
                "anchor-authentication-key.dpapi",
                "authenticated-freshness-anchor.dpapi",
            ]
        );
    }

    #[test]
    fn fixture_errors_are_exactly_redacted() {
        let debug = format!("{:?}", ManualStartupFixtureError);
        assert_eq!(debug, "ManualStartupFixtureError([REDACTED])");
        for excluded in ["path", "environment", "LOCALAPPDATA", "native", "sqlite"] {
            assert!(!debug.contains(excluded));
        }
    }

    #[test]
    fn synthetic_identity_package_is_internally_coordinated() {
        let package = SyntheticIdentityPackage::fixed().unwrap();
        assert_eq!(
            package.evidence.parish_identifier(),
            package.parish_identifier
        );
        assert_eq!(
            package.evidence.installation_identifier(),
            package.installation_identifier
        );
        assert_eq!(
            package.evidence.installation_generation(),
            package.installation_generation
        );
        assert_eq!(
            package.evidence.recovery_or_replacement_generation(),
            package.recovery_replacement_generation
        );
        assert_eq!(
            package.evidence.database_key_generation_identifier(),
            package.database_key_generation_identifier
        );
        assert_eq!(
            package.evidence.setup_publication_identifier(),
            package.setup_publication_identifier
        );
        assert_eq!(
            package.database_metadata.installation_identifier(),
            package.freshness_anchor.installation_identifier()
        );
        assert_eq!(
            package.database_metadata.installation_generation(),
            package.freshness_anchor.installation_generation()
        );
        assert_eq!(
            package.database_metadata.recovery_replacement_generation(),
            package
                .freshness_anchor
                .recovery_or_replacement_generation()
        );
        assert_eq!(
            package
                .database_metadata
                .database_key_generation_identifier(),
            package
                .freshness_anchor
                .database_key_generation_identifier()
        );
        assert_eq!(
            package.database_metadata.setup_publication_identifier(),
            package.freshness_anchor.setup_publication_identifier()
        );
    }

    #[test]
    fn source_proves_windows_test_only_registration_and_one_ignored_exporter() {
        const SOURCE: &str = include_str!("manual_startup_fixture.rs");
        const LIB: &str = include_str!("lib.rs");
        let exporter_source = SOURCE.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(SOURCE.contains("#![cfg(all(test, windows))]"));
        assert!(LIB.contains("#[cfg(all(test, windows))]\nmod manual_startup_fixture;"));
        assert_eq!(
            exporter_source
                .matches("fn export_complete_manual_startup_fixture()")
                .count(),
            1
        );
        assert_eq!(exporter_source.matches("#[ignore =").count(), 1);
        assert!(!LIB.contains("pub mod manual_startup_fixture"));
        assert!(!exporter_source.contains("tauri::command"));
    }
}
