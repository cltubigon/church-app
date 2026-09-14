use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{
    backup::{Backup, StepResult},
    config::DbConfig,
    params, Connection, OpenFlags,
};

use super::*;
use crate::{
    database_metadata_contract::{DatabaseCreationTimestamp, DatabaseMetadataContractV1},
    installation_evidence_contract::{
        DatabaseKeyGenerationIdentifier, InstallationGeneration, InstallationIdentifier,
        PermanentApplicationIdentifier, RecoveryOrReplacementGeneration,
        SetupPublicationIdentifier,
    },
    production_database_file::inspected_production_database_file_identities_match,
    storage_foundation::ParishIdentifier,
};

const CORRECT_KEY: [u8; 32] = [
    0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1,
    0xf2, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef,
    0xf0, 0x01,
];
const WRONG_KEY: [u8; 32] = [
    0xf1, 0xe0, 0xdf, 0xce, 0xbd, 0xac, 0x9b, 0x8a, 0x79, 0x68, 0x57, 0x46, 0x35, 0x24, 0x13,
    0x02, 0x11, 0x20, 0x3f, 0x4e, 0x5d, 0x6c, 0x7b, 0x8a, 0x99, 0xa8, 0xb7, 0xc6, 0xd5, 0xe4,
    0xf3, 0x02,
];
const PLAINTEXT_SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
const APPLICATION_ID: i32 = 0x4348_4150;
const USER_VERSION: i32 = 1;
const ROW_COUNT: i64 = 256;
const PAYLOAD_SIZE: usize = 4096;

#[derive(Debug, Eq, PartialEq)]
struct ContentObservation {
    row_count: i64,
    total_payload_bytes: i64,
    first_label: String,
    first_payload: Vec<u8>,
    middle_label: String,
    middle_payload: Vec<u8>,
    final_label: String,
    final_payload: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
struct FileObservation {
    length: u64,
    last_write_time: std::time::SystemTime,
}

fn expected_metadata() -> DatabaseMetadataContractV1 {
    DatabaseMetadataContractV1::new(
        PermanentApplicationIdentifier::canonical(),
        ParishIdentifier::from_bytes([0x11; 16]).expect("synthetic parish identifier is valid"),
        InstallationIdentifier::from_bytes([0x21; 16])
            .expect("synthetic installation identifier is valid"),
        InstallationGeneration::new(7).expect("synthetic installation generation is nonzero"),
        RecoveryOrReplacementGeneration::new(11)
            .expect("synthetic recovery generation is nonzero"),
        DatabaseKeyGenerationIdentifier::from_bytes(DATABASE_KEY_GENERATION)
            .expect("synthetic database-key generation identifier is valid"),
        SetupPublicationIdentifier::from_bytes([0x61; 16])
            .expect("synthetic setup publication identifier is valid"),
        DatabaseCreationTimestamp::from_unix_milliseconds(1_800_000_000_123),
    )
}

fn create_new_empty_file(path: &Path) -> std::io::Result<()> {
    OpenOptions::new().write(true).create_new(true).open(path)?;
    Ok(())
}

fn open_existing_writer(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
}

fn configure_destination(connection: &Connection) -> rusqlite::Result<String> {
    connection.busy_timeout(Duration::from_secs(5))?;
    // SAFETY: the handle is borrowed only for this synchronous configuration call.
    let extension_status = unsafe {
        rusqlite::ffi::sqlite3_enable_load_extension(connection.handle(), 0)
    };
    if extension_status != rusqlite::ffi::SQLITE_OK {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(extension_status),
            None,
        ));
    }
    for (config, expected) in [
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, false),
    ] {
        if connection.set_db_config(config, expected)? != expected
            || connection.db_config(config)? != expected
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    connection.pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
}

fn create_source(root: &TestRoot, expected: &DatabaseMetadataContractV1) -> Result<(), Box<dyn Error>> {
    let path = root.path().join(PRODUCTION_DATABASE_FILENAME);
    create_new_empty_file(&path)?;
    let mut connection = open_existing_writer(&path)?;
    let key = generation_bound_key(root, CORRECT_KEY);
    apply_key_once(&connection, &key).map_err(|_| "source key application failed")?;
    let journal_mode: String = connection.pragma_update_and_check(
        None,
        "journal_mode",
        "DELETE",
        |row| row.get(0),
    )?;
    assert_eq!(journal_mode.to_ascii_lowercase(), "delete");
    let transaction = connection.transaction()?;
    transaction.pragma_update(Some(MAIN_DATABASE_NAME), "application_id", APPLICATION_ID)?;
    transaction.pragma_update(Some(MAIN_DATABASE_NAME), "user_version", USER_VERSION)?;
    transaction.execute_batch(
        "CREATE TABLE church_app_database_metadata (
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
        );
        CREATE TABLE synthetic_backup_content (
            id INTEGER PRIMARY KEY,
            label TEXT NOT NULL,
            payload BLOB NOT NULL
        ) STRICT;",
    )?;
    let mut installation_identifier = [0_u8; 16];
    expected
        .installation_identifier()
        .write_bytes_into(&mut installation_identifier);
    let mut key_generation = [0_u8; 16];
    expected
        .database_key_generation_identifier()
        .write_bytes_into(&mut key_generation);
    let mut setup_publication = [0_u8; 16];
    expected
        .setup_publication_identifier()
        .write_bytes_into(&mut setup_publication);
    transaction.execute(
        "INSERT INTO church_app_database_metadata VALUES
         (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            i64::from(expected.singleton_id().get()),
            i64::from(expected.metadata_contract_version().get()),
            i64::from(expected.database_schema_version().get()),
            expected.permanent_application_identifier().as_str(),
            &expected.database_format_identity().as_bytes()[..],
            &expected.parish_identifier().as_bytes()[..],
            &installation_identifier[..],
            &expected.installation_generation().get().to_be_bytes()[..],
            &expected.recovery_replacement_generation().get().to_be_bytes()[..],
            &key_generation[..],
            &setup_publication[..],
            i64::try_from(expected.database_created_at().unix_milliseconds())?,
        ],
    )?;
    {
        let mut insert = transaction.prepare(
            "INSERT INTO synthetic_backup_content (id, label, payload) VALUES (?1, ?2, ?3)",
        )?;
        for id in 1..=ROW_COUNT {
            let payload = vec![(id % 251) as u8; PAYLOAD_SIZE];
            insert.execute(params![id, format!("synthetic-row-{id:03}"), payload])?;
        }
    }
    transaction.commit()?;
    connection.close().map_err(|(_, error)| error)?;
    Ok(())
}

fn observe_content(connection: &Connection) -> rusqlite::Result<ContentObservation> {
    let (row_count, total_payload_bytes) = connection.query_row(
        "SELECT count(*), sum(length(payload)) FROM synthetic_backup_content",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let row = |id| {
        connection.query_row(
            "SELECT label, payload FROM synthetic_backup_content WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
    };
    let (first_label, first_payload) = row(1)?;
    let (middle_label, middle_payload) = row(128)?;
    let (final_label, final_payload) = row(ROW_COUNT)?;
    Ok(ContentObservation {
        row_count,
        total_payload_bytes,
        first_label,
        first_payload,
        middle_label,
        middle_payload,
        final_label,
        final_payload,
    })
}

fn observe_file(path: &Path) -> std::io::Result<FileObservation> {
    let metadata = fs::metadata(path)?;
    Ok(FileObservation {
        length: metadata.len(),
        last_write_time: metadata.modified()?,
    })
}

fn assert_cipher_integrity(connection: &Connection) -> rusqlite::Result<()> {
    let mut statement = connection.prepare("PRAGMA cipher_integrity_check")?;
    assert_eq!(statement.column_count(), 1);
    let mut rows = statement.query([])?;
    assert!(rows.next()?.is_none(), "SQLCipher success must return no rows");
    Ok(())
}

fn assert_full_integrity(connection: &Connection) -> rusqlite::Result<()> {
    let mut statement = connection.prepare("PRAGMA main.integrity_check")?;
    assert_eq!(statement.column_count(), 1);
    let mut rows = statement.query([])?;
    let first = rows.next()?.expect("full integrity must return one row");
    assert_eq!(first.get_ref(0)?.as_str()?, "ok");
    assert!(rows.next()?.is_none(), "full integrity must return exactly one row");
    Ok(())
}

fn sidecars(path: &Path) -> [bool; 3] {
    let rendered = path.as_os_str().to_string_lossy();
    ["-journal", "-wal", "-shm"].map(|suffix| PathBuf::from(format!("{rendered}{suffix}")).exists())
}

fn open_correct_key_verifier(root: &TestRoot) -> Result<Connection, Box<dyn Error>> {
    let connection = Connection::open_with_flags(
        root.path().join(PRODUCTION_DATABASE_FILENAME),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let key = generation_bound_key(root, CORRECT_KEY);
    apply_key_once(&connection, &key).map_err(|_| "verifier key application failed")?;
    Ok(connection)
}

fn metadata_observation_fails(root: &TestRoot, key: Option<[u8; 32]>) -> Result<bool, Box<dyn Error>> {
    let connection = Connection::open_with_flags(
        root.path().join(PRODUCTION_DATABASE_FILENAME),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    if let Some(bytes) = key {
        let bound = generation_bound_key(root, bytes);
        apply_key_once(&connection, &bound).map_err(|_| "negative-case key application failed")?;
    }
    connection.pragma_update(None, "cipher_log_level", "NONE")?;
    let schema = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE name = 'church_app_database_metadata'",
        [],
        |row| row.get::<_, i64>(0),
    );
    let metadata = connection.query_row(
        "SELECT singleton_id FROM church_app_database_metadata",
        [],
        |row| row.get::<_, i64>(0),
    );
    connection.close().map_err(|(_, error)| error)?;
    Ok(schema.is_err() && metadata.is_err())
}

fn run_incomplete_copy(source: &Connection, root: &TestRoot) -> Result<(), Box<dyn Error>> {
    let path = root.path().join(PRODUCTION_DATABASE_FILENAME);
    create_new_empty_file(&path)?;
    let mut destination = open_existing_writer(&path)?;
    let key = generation_bound_key(root, CORRECT_KEY);
    apply_key_once(&destination, &key).map_err(|_| "incomplete destination keying failed")?;
    configure_destination(&destination)?;
    {
        let backup = Backup::new(source, &mut destination)?;
        assert_eq!(backup.step(1)?, StepResult::More);
        let progress = backup.progress();
        assert!(progress.pagecount > 1 && progress.remaining > 0);
    }
    destination.close().map_err(|(_, error)| error)?;
    assert_eq!(sidecars(&path), [false; 3]);
    let verifier = open_correct_key_verifier(root)?;
    let not_verified = fixed_metadata_and_header_observation::observe_fixed_metadata_and_headers(
        &verifier,
        Some(USER_VERSION),
    )
    .is_err()
        || observe_content(&verifier).is_err();
    verifier.close().map_err(|(_, error)| error)?;
    assert!(not_verified, "an incomplete copy must not satisfy verification");
    Ok(())
}

#[test]
fn sqlcipher_backup_feasibility_high_level_read_only_source_to_prekeyed_destination(
) -> Result<(), Box<dyn Error>> {
    let expected = expected_metadata();
    let source_root = TestRoot::create();
    let destination_root = TestRoot::create();
    let incomplete_root = TestRoot::create();
    let temporary = std::env::temp_dir();
    for root in [&source_root, &destination_root, &incomplete_root] {
        assert!(root.path().is_absolute());
        assert!(root.path().starts_with(&temporary));
        assert_ne!(root.path(), temporary);
    }

    create_source(&source_root, &expected)?;
    let source_path = source_root.path().join(PRODUCTION_DATABASE_FILENAME);
    let source_before_file = observe_file(&source_path)?;
    let source_before_identity = source_root.inspected();
    let source = actual_keyed_owner(
        &source_root,
        generation_bound_key(&source_root, CORRECT_KEY),
    );
    assert_eq!(source.owner.connection.is_readonly(MAIN_DATABASE_NAME), Ok(true));
    assert_eq!(
        source
            .owner
            .connection
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0)),
        Ok(true)
    );
    assert!(source.owner.connection.execute_batch("BEGIN IMMEDIATE").is_err());
    let source_journal: String = source.owner.connection.pragma_query_value(
        None,
        "journal_mode",
        |row| row.get(0),
    )?;
    let source_metadata =
        fixed_metadata_and_header_observation::observe_fixed_metadata_and_headers(
            &source.owner.connection,
            Some(USER_VERSION),
        )
        .map_err(|_| "source metadata observation failed")?;
    let source_content = observe_content(&source.owner.connection)?;

    run_incomplete_copy(&source.owner.connection, &incomplete_root)?;

    let destination_path = destination_root.path().join(PRODUCTION_DATABASE_FILENAME);
    create_new_empty_file(&destination_path)?;
    let mut destination = open_existing_writer(&destination_path)?;
    let destination_key = generation_bound_key(&destination_root, CORRECT_KEY);
    apply_key_once(&destination, &destination_key)
        .map_err(|_| "destination key application failed")?;
    let destination_journal_before = configure_destination(&destination)?;
    assert_eq!(destination_journal_before.to_ascii_lowercase(), "delete");
    let final_progress;
    {
        let backup = Backup::new(&source.owner.connection, &mut destination)?;
        loop {
            match backup.step(16)? {
                StepResult::Done => break,
                StepResult::More => {}
                StepResult::Busy | StepResult::Locked => {
                    return Err("unexpected lock while copying inactive synthetic source".into());
                }
                _ => return Err("unknown non-completion backup result".into()),
            }
        }
        final_progress = backup.progress();
        assert_eq!(final_progress.remaining, 0);
        assert!(final_progress.pagecount > 1);
    }
    destination.close().map_err(|(_, error)| error)?;
    assert_eq!(sidecars(&destination_path), [false; 3]);

    let verifier = open_correct_key_verifier(&destination_root)?;
    assert_cipher_integrity(&verifier)?;
    assert_full_integrity(&verifier)?;
    let destination_application_id: i32 = verifier.pragma_query_value(
        Some(MAIN_DATABASE_NAME),
        "application_id",
        |row| row.get(0),
    )?;
    let destination_user_version: i32 = verifier.pragma_query_value(
        Some(MAIN_DATABASE_NAME),
        "user_version",
        |row| row.get(0),
    )?;
    let destination_metadata =
        fixed_metadata_and_header_observation::observe_fixed_metadata_and_headers(
            &verifier,
            Some(USER_VERSION),
        )
        .map_err(|_| "destination metadata observation failed")?;
    let destination_content = observe_content(&verifier)?;
    let destination_journal_after: String = verifier.pragma_query_value(
        None,
        "journal_mode",
        |row| row.get(0),
    )?;
    assert_eq!(destination_journal_after.to_ascii_lowercase(), "delete");
    verifier.close().map_err(|(_, error)| error)?;

    assert_eq!(source_metadata, expected);
    assert_eq!(destination_metadata, source_metadata);
    assert_eq!(destination_application_id, APPLICATION_ID);
    assert_eq!(destination_user_version, USER_VERSION);
    assert_eq!(destination_content, source_content);
    assert_eq!(source_content.row_count, ROW_COUNT);
    assert_eq!(source_content.total_payload_bytes, ROW_COUNT * PAYLOAD_SIZE as i64);

    let mut header = [0_u8; 16];
    fs::File::open(&destination_path)?.read_exact(&mut header)?;
    assert_ne!(&header, PLAINTEXT_SQLITE_HEADER);
    assert!(metadata_observation_fails(&destination_root, None)?);
    assert!(metadata_observation_fails(&destination_root, Some(WRONG_KEY))?);

    assert_eq!(
        source
            .owner
            .connection
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0)),
        Ok(true)
    );
    let source_metadata_after =
        fixed_metadata_and_header_observation::observe_fixed_metadata_and_headers(
            &source.owner.connection,
            Some(USER_VERSION),
        )
        .map_err(|_| "post-backup source metadata observation failed")?;
    let source_content_after = observe_content(&source.owner.connection)?;
    assert_eq!(source_metadata_after, source_metadata);
    assert_eq!(source_content_after, source_content);
    assert_eq!(observe_file(&source_path)?, source_before_file);
    assert!(matches!(source.close(), ProductionDatabaseConnectionCloseOutcome::Closed));
    let source_after_identity = source_root.inspected();
    assert!(inspected_production_database_file_identities_match(
        &source_before_identity,
        &source_after_identity,
    ));
    assert_eq!(sidecars(&source_path), [false; 3]);

    println!(
        "event=\"sqlcipher_backup_feasibility\" completion=\"done\" remaining=\"{}\" pages=\"{}\" source_journal=\"{}\" destination_journal_before=\"{}\" destination_journal_after=\"{}\"",
        final_progress.remaining,
        final_progress.pagecount,
        source_journal,
        destination_journal_before,
        destination_journal_after,
    );

    let source_cleanup = source_root.path().to_path_buf();
    let destination_cleanup = destination_root.path().to_path_buf();
    let incomplete_cleanup = incomplete_root.path().to_path_buf();
    source_root.assert_exact_cleanup();
    destination_root.assert_exact_cleanup();
    incomplete_root.assert_exact_cleanup();
    assert!(!source_cleanup.exists());
    assert!(!destination_cleanup.exists());
    assert!(!incomplete_cleanup.exists());
    Ok(())
}

#[test]
fn sqlcipher_backup_feasibility_scope_and_pinned_api_are_test_only() {
    const CARGO: &str = include_str!("../Cargo.toml");
    const LIB: &str = include_str!("lib.rs");
    const HANDOFF: &str = include_str!("production_database_connection_handoff.rs");
    assert!(CARGO.contains(
        "rusqlite = { version = \"=0.39.0\", default-features = false, features = [\"backup\", \"bundled-sqlcipher-vendored-openssl\"] }"
    ));
    assert_eq!(CARGO.matches("rusqlite =").count(), 1);
    assert!(!CARGO.contains("libsqlite3-sys"));
    assert!(!LIB.contains("sqlcipher_backup_feasibility"));
    assert!(HANDOFF.contains(
        "#[cfg(test)]\nmod tests {\n    mod sqlcipher_backup_feasibility {\n        include!(\"sqlcipher_backup_feasibility.rs\");\n    }"
    ));
    for forbidden in [
        "pub fn create_backup",
        "pub(crate) fn create_backup",
        "sqlite3_backup_init(",
        "sqlcipher_export",
        "recovery envelope",
        "schema version 2",
    ] {
        assert!(!HANDOFF.split("#[cfg(test)]").next().unwrap().contains(forbidden));
    }
}
