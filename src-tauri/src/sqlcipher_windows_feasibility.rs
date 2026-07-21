use std::{
    error::Error,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use rusqlite::{Connection, params};

const SYNTHETIC_SENTINEL: &str = "SYNTHETIC_SQLCIPHER_FEASIBILITY_SENTINEL_7B91D2";
static TEMP_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> std::io::Result<Self> {
        let sequence = TEMP_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "church-app-sqlcipher-feasibility-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn raw_key_literal(key: &[u8; 32]) -> String {
    let mut literal = String::with_capacity(67);
    literal.push_str("x'");
    for byte in key {
        write!(&mut literal, "{byte:02X}").expect("writing to a String cannot fail");
    }
    literal.push('\'');
    literal
}

fn apply_test_key(connection: &Connection, key: &[u8; 32]) -> rusqlite::Result<()> {
    let key_literal = raw_key_literal(key);
    connection.pragma_update(None, "key", key_literal)?;
    connection.pragma_update(None, "cipher_compatibility", 4)?;
    connection.pragma_update(None, "cipher_log_level", "NONE")
}

fn pragma_text(connection: &Connection, pragma: &str) -> rusqlite::Result<String> {
    connection.query_row(pragma, [], |row| row.get(0))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn sqlcipher_windows_temporary_encryption_feasibility() -> Result<(), Box<dyn Error>> {
    let correct_key = std::array::from_fn(|index| (index as u8).wrapping_mul(7).wrapping_add(19));
    let wrong_key = std::array::from_fn(|index| (index as u8).wrapping_mul(11).wrapping_add(31));
    let test_directory = TestDirectory::create()?;
    let cleanup_path = test_directory.path().to_path_buf();
    let database_path = test_directory.path().join("feasibility.db");

    let mut create_connection = Connection::open(&database_path)?;
    apply_test_key(&create_connection, &correct_key)?;

    let sqlcipher_version = pragma_text(&create_connection, "PRAGMA cipher_version")?;
    let cipher_provider = pragma_text(&create_connection, "PRAGMA cipher_provider")?;
    let cipher_provider_version =
        pragma_text(&create_connection, "PRAGMA cipher_provider_version")?;
    let cipher_page_size = pragma_text(&create_connection, "PRAGMA cipher_page_size")?;
    let kdf_iterations = pragma_text(&create_connection, "PRAGMA kdf_iter")?;
    let kdf_algorithm = pragma_text(&create_connection, "PRAGMA cipher_kdf_algorithm")?;
    let hmac_algorithm = pragma_text(&create_connection, "PRAGMA cipher_hmac_algorithm")?;

    assert!(sqlcipher_version.contains("community"));
    assert_eq!(cipher_provider.to_ascii_lowercase(), "openssl");
    assert!(!cipher_provider_version.is_empty());
    assert!(!cipher_page_size.is_empty());
    assert!(!kdf_iterations.is_empty());
    assert!(!kdf_algorithm.is_empty());
    assert!(!hmac_algorithm.is_empty());

    let journal_mode: String =
        create_connection
            .pragma_update_and_check(None, "journal_mode", "PERSIST", |row| row.get(0))?;
    assert_eq!(journal_mode.to_ascii_lowercase(), "persist");

    let transaction = create_connection.transaction()?;
    transaction.execute_batch("CREATE TABLE feasibility_probe (sentinel TEXT NOT NULL);")?;
    transaction.execute(
        "INSERT INTO feasibility_probe (sentinel) VALUES (?1)",
        params![SYNTHETIC_SENTINEL],
    )?;
    transaction.commit()?;
    create_connection.close().map_err(|(_, error)| error)?;

    let correct_connection = Connection::open(&database_path)?;
    apply_test_key(&correct_connection, &correct_key)?;
    let reopened_sentinel: String =
        correct_connection.query_row("SELECT sentinel FROM feasibility_probe", [], |row| {
            row.get(0)
        })?;
    assert_eq!(reopened_sentinel, SYNTHETIC_SENTINEL);
    correct_connection.close().map_err(|(_, error)| error)?;

    let wrong_connection = Connection::open(&database_path)?;
    apply_test_key(&wrong_connection, &wrong_key)?;
    let wrong_key_schema_read =
        wrong_connection.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        });
    assert!(wrong_key_schema_read.is_err());
    drop(wrong_connection);

    let mut artifact_count = 0_u32;
    let mut sidecar_count = 0_u32;
    for entry in fs::read_dir(test_directory.path())? {
        let path = entry?.path();
        if !path.is_file() {
            continue;
        }
        artifact_count += 1;
        if path != database_path {
            sidecar_count += 1;
        }
        let bytes = fs::read(path)?;
        assert!(!contains_bytes(&bytes, SYNTHETIC_SENTINEL.as_bytes()));
    }
    assert!(artifact_count >= 1);
    assert!(sidecar_count >= 1);

    println!(
        "event=\"sqlcipher_feasibility\" check=\"native_identity\" sqlcipher_version=\"{sqlcipher_version}\" crypto_provider=\"{cipher_provider}\" crypto_provider_version=\"{cipher_provider_version}\""
    );
    println!(
        "event=\"sqlcipher_feasibility\" check=\"cipher_configuration\" compatibility=\"4\" page_size=\"{cipher_page_size}\" kdf_iterations=\"{kdf_iterations}\" kdf_algorithm=\"{kdf_algorithm}\" hmac_algorithm=\"{hmac_algorithm}\""
    );
    println!("event=\"sqlcipher_feasibility\" check=\"correct_key_reopen\" outcome=\"success\"");
    println!(
        "event=\"sqlcipher_feasibility\" check=\"wrong_key_schema_read\" outcome=\"safe_failure\""
    );
    println!(
        "event=\"sqlcipher_feasibility\" check=\"plaintext_scan\" outcome=\"absent\" artifacts_scanned=\"{artifact_count}\" sidecars_scanned=\"{sidecar_count}\""
    );

    drop(test_directory);
    assert!(!cleanup_path.exists());
    println!("event=\"sqlcipher_feasibility\" check=\"temporary_cleanup\" outcome=\"success\"");

    Ok(())
}
