use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use super::*;
use crate::{
    database_key::DatabaseKey,
    database_key_generation::generate_database_key_material,
    database_metadata_contract::DatabaseCreationTimestamp,
    installation_evidence_contract::{CreationTimestamp, SetupPublicationIdentifier},
    installation_evidence_protection::{
        bind_generated_database_key_for_first_time_setup, protect_database_key,
        protect_first_time_setup_database_key_binding,
    },
    installation_identifier_generation::generate_installation_identifier,
    installation_state::{
        InstallationEvidence, SetupAuthorizationState, authorize_first_time_setup,
    },
    production_database_connection_handoff as handoff,
    storage_foundation::{
        ParishIdentifier, database_key_persistence_paths, freshness_anchor_persistence_paths,
        installation_evidence_persistence_paths,
    },
};

pub(super) struct Fixture {
    root: PathBuf,
    pub(super) context: Option<FirstTimeSetupStagedVerificationContext>,
}

impl Fixture {
    // Shared real predecessor fixture; the bound-operation tests perform their
    // own production directory preparation and sealed five-write transition.
    pub(super) fn new_unstaged() -> Self {
        let temporary = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = temporary.join(format!(
            "church-app-common-context-{}-{nonce}",
            std::process::id()
        ));
        assert!(root.is_absolute() && root.starts_with(&temporary) && root != temporary);
        fs::create_dir(&root).unwrap();
        let evidence_paths = installation_evidence_persistence_paths(&root);
        let key_paths = database_key_persistence_paths(&root);
        let freshness_paths = freshness_anchor_persistence_paths(&root);
        let SetupAuthorizationState::Authorized(authorization) =
            authorize_first_time_setup(InstallationEvidence::NeverInitialized).unwrap()
        else {
            panic!("synthetic setup must be authorized")
        };
        let binding = bind_generated_database_key_for_first_time_setup(
            &authorization,
            generate_database_key_material().unwrap(),
            generate_installation_identifier().unwrap(),
        );
        let (key, publication) = protect_first_time_setup_database_key_binding(binding)
            .unwrap()
            .into_database_creation_key_and_publication_material();
        let (installation, generation) = publication.lineage_for_test();
        let created = handoff::create_new_keyed_production_database(
            authorization,
            evidence_paths.active_database.clone(),
            key,
        )
        .unwrap();
        let initialized = handoff::initialize_new_production_database(
            created,
            ParishIdentifier::from_bytes([0x11; 16]).unwrap(),
            installation,
            generation,
            SetupPublicationIdentifier::from_bytes([0x61; 16]).unwrap(),
            DatabaseCreationTimestamp::from_unix_milliseconds(1_800_000_000_000),
        )
        .unwrap();
        let validated = handoff::validate_initialized_new_production_database(initialized).unwrap();
        let integrity =
            handoff::validate_initialized_new_production_database_integrity(validated).unwrap();
        let handoff::NewProductionDatabaseCloseAndPreserveOutcome::Closed(closed) =
            handoff::close_and_preserve_integrity_validated_initialized_new_production_database(
                integrity,
            )
        else {
            panic!("fixture creation must close")
        };
        let materials = super::super::prepare_first_time_setup_publication_materials(
            closed,
            publication,
            CreationTimestamp::from_unix_seconds(42).unwrap(),
        )
        .unwrap();
        let context = prepare_first_time_setup_staged_verification_context(
            materials,
            evidence_paths,
            key_paths,
            freshness_paths,
        )
        .unwrap();
        let fixture = Self {
            root,
            context: Some(context),
        };
        fs::write(
            fixture.root.join("sentinel.synthetic"),
            b"unchanged synthetic sentinel",
        )
        .unwrap();
        fixture
    }

    fn new() -> Self {
        let fixture = Self::new_unstaged();
        let core = &fixture.context().verification_core;
        for directory in [
            core.installation_evidence_paths
                .evidence_directory
                .as_path(),
            core.database_key_paths.database_key_directory.as_path(),
            core.freshness_anchor_paths
                .freshness_anchor_directory
                .as_path(),
        ] {
            fs::create_dir(directory).unwrap();
        }
        // Only synthetic fixture preparation writes files; the operation under
        // test receives a sealed owner and independently reads these staged bytes.
        for (path, bytes) in fixture
            .staged_paths()
            .iter()
            .zip(payloads(&fixture.context().pending_publication))
        {
            fs::write(path, bytes).unwrap();
        }
        fixture
    }

    fn context(&self) -> &FirstTimeSetupStagedVerificationContext {
        self.context.as_ref().unwrap()
    }

    pub(super) fn staged_paths(&self) -> [PathBuf; 5] {
        let evidence = installation_evidence_persistence_paths(&self.root);
        let key = database_key_persistence_paths(&self.root);
        let freshness = freshness_anchor_persistence_paths(&self.root);
        [
            key.staged_database_key.as_path().to_owned(),
            evidence.staged_authentication_key.as_path().to_owned(),
            evidence.staged_authenticated_evidence.as_path().to_owned(),
            freshness
                .staged_anchor_authentication_key
                .as_path()
                .to_owned(),
            freshness
                .staged_authenticated_freshness_anchor
                .as_path()
                .to_owned(),
        ]
    }

    fn database_path(&self) -> PathBuf {
        installation_evidence_persistence_paths(&self.root)
            .active_database
            .as_path()
            .to_owned()
    }

    // Mirror the production API's intentionally ownership-bearing error.
    #[allow(clippy::result_large_err)]
    fn verify(
        &mut self,
    ) -> Result<
        CompletedFirstTimeSetupStagedVerificationContext,
        FirstTimeSetupStagedVerificationError,
    > {
        verify_first_time_setup_staged_context(self.context.take().unwrap())
    }

    fn mutate_database(&self, sql: &str) {
        let core = &self.context().verification_core;
        let key = verify_reloaded_staged_database_key_for_setup(
            &core.database_key_paths,
            &core.database_metadata,
        )
        .unwrap()
        .into_generation_bound_database_key();
        let connection = rusqlite::Connection::open(self.database_path()).unwrap();
        handoff::apply_key_once(&connection, &key).unwrap();
        connection.execute_batch(sql).unwrap();
        connection.close().map_err(|(_, error)| error).unwrap();
    }

    pub(super) fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fn collect(directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect(&path, files);
                } else {
                    files.insert(path.clone(), fs::read(path).unwrap());
                }
            }
        }
        let mut files = BTreeMap::new();
        collect(&self.root, &mut files);
        files
    }

    pub(super) fn assert_write_access(&self, permitted: bool) {
        assert_eq!(
            OpenOptions::new()
                .write(true)
                .open(self.database_path())
                .is_ok(),
            permitted
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let temporary = std::env::temp_dir();
        assert!(
            self.root.is_absolute() && self.root.starts_with(&temporary) && self.root != temporary
        );
        fs::remove_dir_all(&self.root).expect("exact synthetic fixture teardown must succeed");
    }
}

fn payloads(pending: &PendingSetupPublicationPayloads) -> [&[u8]; 5] {
    [
        pending.protected_database_key_wrapper.as_bytes(),
        pending
            .protected_evidence_authentication_key_wrapper
            .as_bytes(),
        pending.protected_authenticated_evidence_wrapper.as_bytes(),
        pending
            .protected_freshness_authentication_key_wrapper
            .as_bytes(),
        pending
            .protected_authenticated_freshness_anchor_wrapper
            .as_bytes(),
    ]
}

// RAII keeps injection isolated even if an assertion panics. It deliberately
// fails every attempted close while armed so automatic retries cannot hide.
pub(super) struct FailClose;
impl FailClose {
    pub(super) fn arm() -> Self {
        handoff::tests::COMMON_CONTEXT_CLOSE_FAILURE.with(|state| {
            assert_eq!(state.replace(Some(0)), None);
        });
        Self
    }
    pub(super) fn attempts(&self) -> usize {
        handoff::tests::COMMON_CONTEXT_CLOSE_FAILURE.with(|state| state.get().unwrap())
    }
}
impl Drop for FailClose {
    fn drop(&mut self) {
        handoff::tests::COMMON_CONTEXT_CLOSE_FAILURE.with(|state| state.set(None));
    }
}

#[test]
fn real_sealed_context_retains_exact_proofs_wrappers_paths_and_one_metadata_anchor() {
    let mut fixture = Fixture::new();
    let core = &fixture.context().verification_core;
    let metadata = core.database_metadata;
    let evidence_paths = core.installation_evidence_paths.clone();
    let key_paths = core.database_key_paths.clone();
    let freshness_paths = core.freshness_anchor_paths.clone();
    let wrappers = payloads(&fixture.context().pending_publication).map(<[u8]>::to_vec);
    let allocations = payloads(&fixture.context().pending_publication).map(|bytes| bytes.as_ptr());
    let before = fixture.snapshot();
    let completed = fixture.verify().unwrap();
    assert!(fixture.context.is_none());
    assert_eq!(
        format!("{completed:?}"),
        "CompletedFirstTimeSetupStagedVerificationContext([REDACTED])"
    );
    let _: &ReloadVerifiedStagedInstallationEvidenceForSetup = &completed.installation_evidence;
    let _: &ReloadVerifiedStagedFreshnessAnchorForSetup = &completed.freshness_anchor;
    let _: &ClosedPreparedMetadataValidatedProductionDatabaseForSetup = &completed.closed_database;
    assert_eq!(std::mem::size_of_val(&completed.closed_database), 0);
    assert_eq!(completed.database_metadata, metadata);
    assert_eq!(
        completed
            .installation_evidence
            .evidence()
            .installation_identifier(),
        metadata.installation_identifier()
    );
    assert_eq!(
        completed
            .freshness_anchor
            .contract()
            .installation_identifier(),
        metadata.installation_identifier()
    );
    assert_eq!(completed.installation_evidence_paths, evidence_paths);
    assert_eq!(completed.database_key_paths, key_paths);
    assert_eq!(completed.freshness_anchor_paths, freshness_paths);
    assert_eq!(
        payloads(&completed.pending_publication).map(<[u8]>::to_vec),
        wrappers
    );
    assert_eq!(
        payloads(&completed.pending_publication).map(|bytes| bytes.as_ptr()),
        allocations
    );
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
    assert_eq!(before.len(), 7); // Database, five staged wrappers, sentinel; no active wrappers.
}

#[test]
fn each_missing_staged_file_fails_at_its_branch_without_using_pending_wrappers() {
    for index in 0..5 {
        let mut fixture = Fixture::new();
        fs::remove_file(&fixture.staged_paths()[index]).unwrap();
        let before = fixture.snapshot();
        let error = fixture.verify().unwrap_err();
        match index {
            0 => assert!(matches!(
                error,
                FirstTimeSetupStagedVerificationError::DatabaseKey(
                    StagedDatabaseKeyVerificationError::Unavailable
                )
            )),
            1 | 2 => assert!(matches!(
                error,
                FirstTimeSetupStagedVerificationError::InstallationEvidence(
                    StagedInstallationEvidenceVerificationError::Malformed
                )
            )),
            3 | 4 => assert!(matches!(
                error,
                FirstTimeSetupStagedVerificationError::FreshnessAnchor(
                    StagedFreshnessAnchorVerificationError::Malformed
                )
            )),
            _ => unreachable!(),
        }
        fixture.assert_write_access(true);
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn evidence_failure_precedes_freshness_key_and_database_failures() {
    let mut fixture = Fixture::new();
    for path in fixture.staged_paths() {
        fs::write(path, b"malformed synthetic wrapper").unwrap();
    }
    fs::remove_file(fixture.database_path()).unwrap();
    let before = fixture.snapshot();
    assert!(matches!(
        fixture.verify(),
        Err(FirstTimeSetupStagedVerificationError::InstallationEvidence(
            StagedInstallationEvidenceVerificationError::Malformed
        ))
    ));
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn freshness_failure_precedes_key_and_database_failures() {
    let mut fixture = Fixture::new();
    for index in [0, 3, 4] {
        fs::write(
            &fixture.staged_paths()[index],
            b"malformed synthetic wrapper",
        )
        .unwrap();
    }
    fs::remove_file(fixture.database_path()).unwrap();
    let before = fixture.snapshot();
    assert!(matches!(
        fixture.verify(),
        Err(FirstTimeSetupStagedVerificationError::FreshnessAnchor(
            StagedFreshnessAnchorVerificationError::ProtectionOrAuthenticationFailed
        ))
    ));
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn database_key_failure_precedes_database_open() {
    let mut fixture = Fixture::new();
    fs::write(&fixture.staged_paths()[0], b"malformed synthetic wrapper").unwrap();
    fs::remove_file(fixture.database_path()).unwrap();
    let before = fixture.snapshot();
    assert!(matches!(
        fixture.verify(),
        Err(FirstTimeSetupStagedVerificationError::DatabaseKey(
            StagedDatabaseKeyVerificationError::Malformed
        ))
    ));
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn each_branch_binds_reloaded_files_to_the_context_metadata_and_path_family() {
    let donor = Fixture::new();
    for branch in 0..3 {
        let mut fixture = Fixture::new();
        let indexes: &[usize] = match branch {
            0 => &[1, 2],
            1 => &[3, 4],
            _ => &[0],
        };
        for &index in indexes {
            fs::write(
                &fixture.staged_paths()[index],
                fs::read(&donor.staged_paths()[index]).unwrap(),
            )
            .unwrap();
        }
        let before = fixture.snapshot();
        let error = fixture.verify().unwrap_err();
        match branch {
            0 => assert!(matches!(
                error,
                FirstTimeSetupStagedVerificationError::InstallationEvidence(
                    StagedInstallationEvidenceVerificationError::MetadataMismatch
                )
            )),
            1 => assert!(matches!(
                error,
                FirstTimeSetupStagedVerificationError::FreshnessAnchor(
                    StagedFreshnessAnchorVerificationError::LineageMismatch
                )
            )),
            _ => assert!(matches!(
                error,
                FirstTimeSetupStagedVerificationError::DatabaseKey(
                    StagedDatabaseKeyVerificationError::GenerationMismatch
                )
            )),
        }
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn missing_canonical_database_and_context_historical_identity_mismatch_preserve_open_errors() {
    for missing in [true, false] {
        let mut fixture = Fixture::new();
        if missing {
            fs::remove_file(fixture.database_path()).unwrap();
        } else {
            fixture
                .context
                .as_mut()
                .unwrap()
                .verification_core
                .database_identity_proof
                .created_leaf_identity
                .file_id[0] ^= 1;
        }
        let before = fixture.snapshot();
        let error = fixture.verify().unwrap_err();
        if missing {
            assert!(matches!(
                error,
                FirstTimeSetupStagedVerificationError::DatabaseOpen(
                    SetupProductionDatabaseOpenError::CurrentDatabaseUnavailable
                )
            ));
        } else {
            assert!(matches!(
                error,
                FirstTimeSetupStagedVerificationError::DatabaseOpen(
                    SetupProductionDatabaseOpenError::IdentityMismatch
                )
            ));
            fixture.assert_write_access(true);
        }
        assert_eq!(fixture.snapshot(), before);
    }
}

fn wrong_key(fixture: &Fixture) {
    let wrapper = protect_database_key(
        &DatabaseKey::from_bytes([0x82; 32]),
        fixture
            .context()
            .verification_core
            .database_metadata
            .database_key_generation_identifier(),
    )
    .unwrap();
    fs::write(&fixture.staged_paths()[0], wrapper.as_bytes()).unwrap();
}

#[test]
fn integrity_live_headers_live_metadata_and_prepared_mismatch_preserve_revalidation_errors() {
    for phase in 0..4 {
        let mut fixture = Fixture::new();
        match phase {
            0 => wrong_key(&fixture),
            1 => fixture.mutate_database("PRAGMA application_id = 0"),
            2 => fixture.mutate_database("UPDATE church_app_database_metadata SET singleton_id = 2"),
            _ => fixture.mutate_database("UPDATE church_app_database_metadata SET database_created_at = database_created_at + 1"),
        }
        let before = fixture.snapshot();
        let error = fixture.verify().unwrap_err();
        match phase {
            0 => assert!(matches!(
                error,
                FirstTimeSetupStagedVerificationError::DatabaseRevalidation(
                    SetupProductionDatabaseRevalidationError::Integrity(_)
                )
            )),
            1 | 2 => assert!(matches!(
                error,
                FirstTimeSetupStagedVerificationError::DatabaseRevalidation(
                    SetupProductionDatabaseRevalidationError::LiveMetadataAndHeaders(_)
                )
            )),
            _ => assert!(matches!(
                error,
                FirstTimeSetupStagedVerificationError::DatabaseRevalidation(
                    SetupProductionDatabaseRevalidationError::PreparedMetadataMismatch
                )
            )),
        }
        fixture.assert_write_access(true);
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn explicit_close_failure_returns_live_owner_without_completion_or_automatic_retry() {
    let mut fixture = Fixture::new();
    let before = fixture.snapshot();
    let injection = FailClose::arm();
    let error = fixture.verify().unwrap_err();
    assert_eq!(
        format!("{error:?}"),
        "DatabaseClose(SetupProductionDatabaseRevalidationCloseFailure([REDACTED]))"
    );
    let FirstTimeSetupStagedVerificationError::DatabaseClose(failure) = error else {
        panic!("close owner must survive")
    };
    assert_eq!(injection.attempts(), 1);
    fixture.assert_write_access(false);
    assert_eq!(fixture.snapshot(), before);
    drop(injection);
    // Explicit test disposal only, never a retry of setup verification.
    assert!(matches!(
        failure.retry_close(),
        SetupProductionDatabaseRevalidationCloseOutcome::Closed(_)
    ));
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn revalidation_close_failures_preserve_each_existing_live_failure_owner() {
    for phase in 0..3 {
        let mut fixture = Fixture::new();
        match phase {
            0 => wrong_key(&fixture),
            1 => fixture.mutate_database("PRAGMA application_id = 0"),
            _ => fixture.mutate_database("UPDATE church_app_database_metadata SET database_created_at = database_created_at + 1"),
        }
        let before = fixture.snapshot();
        let injection = FailClose::arm();
        let error = fixture.verify().unwrap_err();
        assert_eq!(injection.attempts(), 1);
        fixture.assert_write_access(false);
        assert_eq!(fixture.snapshot(), before);
        drop(injection);
        match error {
            FirstTimeSetupStagedVerificationError::DatabaseRevalidation(
                SetupProductionDatabaseRevalidationError::IntegrityCloseFailed(failure),
            ) if phase == 0 => {
                assert!(matches!(
                    failure.retry_close(),
                    handoff::ProductionDatabaseValidationCloseRetryOutcome::Closed(_)
                ));
            }
            FirstTimeSetupStagedVerificationError::DatabaseRevalidation(
                SetupProductionDatabaseRevalidationError::LiveMetadataAndHeadersCloseFailed(
                    failure,
                ),
            ) if phase == 1 => {
                assert!(matches!(
                    failure.retry_close(),
                    handoff::LiveMetadataAndHeaderValidationCloseRetryOutcome::Closed(_)
                ));
            }
            FirstTimeSetupStagedVerificationError::DatabaseRevalidation(
                SetupProductionDatabaseRevalidationError::PreparedMetadataMismatchCloseFailed(
                    failure,
                ),
            ) if phase == 2 => {
                assert!(matches!(
                    failure.retry_close(),
                    SetupProductionDatabaseRevalidationError::PreparedMetadataMismatch
                ));
            }
            _ => panic!("exact phase-specific close failure must survive"),
        }
        fixture.assert_write_access(true);
        assert_eq!(fixture.snapshot(), before);
    }
}

fn compact(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(str::split_whitespace)
        .collect::<String>()
        .replace(",)", ")")
        .replace(",}", "}")
}

#[test]
fn source_locks_only_consuming_entry_exact_branch_order_dataflow_and_terminal_close() {
    let production = include_str!("first_time_setup_staged_verification_context.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    let operation = production
        .split_once("pub(crate) fn verify_first_time_setup_staged_context(")
        .unwrap()
        .1;
    // This complete contract prevents independent branch-proof parameters,
    // key duplication/recovery, alternate metadata/path/identity inputs, retry,
    // raw opening, custom validation, or completion before successful close.
    assert_eq!(compact(operation), compact(
        "context: FirstTimeSetupStagedVerificationContext,
        ) -> Result<CompletedFirstTimeSetupStagedVerificationContext, FirstTimeSetupStagedVerificationError> {
            let FirstTimeSetupStagedVerificationContext { verification_core, pending_publication } = context;
            let installation_evidence = verify_reloaded_staged_installation_evidence_for_setup(
                &verification_core.installation_evidence_paths, &verification_core.database_metadata,
            ).map_err(FirstTimeSetupStagedVerificationError::InstallationEvidence)?;
            let freshness_anchor = verify_reloaded_staged_freshness_anchor_for_setup(
                &verification_core.freshness_anchor_paths, &verification_core.database_metadata,
            ).map_err(FirstTimeSetupStagedVerificationError::FreshnessAnchor)?;
            let staged_key = verify_reloaded_staged_database_key_for_setup(
                &verification_core.database_key_paths, &verification_core.database_metadata,
            ).map_err(FirstTimeSetupStagedVerificationError::DatabaseKey)?;
            let opened = open_identity_bound_staged_key_production_database_for_setup(
                &verification_core.database_identity_proof,
                verification_core.installation_evidence_paths.active_database.clone(), staged_key,
            ).map_err(FirstTimeSetupStagedVerificationError::DatabaseOpen)?;
            let validated = revalidate_identity_bound_staged_key_production_database_for_setup(
                opened, &verification_core.database_metadata,
            ).map_err(FirstTimeSetupStagedVerificationError::DatabaseRevalidation)?;
            let closed_database = match close_and_preserve_prepared_metadata_validated_production_database_for_setup(validated) {
                SetupProductionDatabaseRevalidationCloseOutcome::Closed(closed) => closed,
                SetupProductionDatabaseRevalidationCloseOutcome::Failed(failure) => {
                    return Err(FirstTimeSetupStagedVerificationError::DatabaseClose(failure));
                }
            };
            Ok(CompletedFirstTimeSetupStagedVerificationContext {
                installation_evidence, freshness_anchor, closed_database, pending_publication,
                database_metadata: verification_core.database_metadata,
                installation_evidence_paths: verification_core.installation_evidence_paths,
                database_key_paths: verification_core.database_key_paths,
                freshness_anchor_paths: verification_core.freshness_anchor_paths,
            })
        }"
    ));
    let _: fn(
        FirstTimeSetupStagedVerificationContext,
    ) -> Result<
        CompletedFirstTimeSetupStagedVerificationContext,
        FirstTimeSetupStagedVerificationError,
    > = handoff::verify_first_time_setup_staged_context;
    assert_eq!(production.matches("pub(crate) fn ").count(), 2);
    assert_eq!(production.matches("impl ").count(), 2); // Redacted Debug only; no owner methods.
    assert_eq!(
        production
            .matches("Ok(CompletedFirstTimeSetupStagedVerificationContext {")
            .count(),
        1
    );
    assert_eq!(operation.matches("staged_key,").count(), 1);
    assert_eq!(operation.matches(".clone()").count(), 1); // Only the canonical typed database path.
    assert_eq!(
        production
            .matches("publish_first_time_setup_database_key_wrapper")
            .count(),
        1
    ); // Re-export only; the verified operation body above remains publication-free.
    for forbidden in [
        "write_staged_",
        "load_active_",
        "retry_close",
        "std::fs",
        "remove_file",
        "remove_dir",
        "rename",
        "AllStagedArtifactsReloadVerified",
        "FirstTimeSetupPublicationState",
        "first_time_setup_publication",
        "CurrentCanonicalDatabaseIdentityMatchesSetupProof",
        "TrustedCurrentInstallation",
        "InstallationBoundAuthenticatedActiveFreshnessAnchor",
        "AssuredFreshnessAnchor",
        "DatabaseEvidenceCorrespondenceValidated",
        "DatabaseFreshnessValidated",
        "StartupAuthorized",
        "OperationalProductionDatabase",
        "Mutex",
        "LockFileEx",
        "unsafe",
        "context_id",
        "ContextId",
        "Serialize",
        "Deserialize",
        "Deref",
        "pub fn",
        "pub(super)",
    ] {
        assert!(
            !production.contains(forbidden),
            "excluded capability: {forbidden}"
        );
    }
}

#[test]
fn source_locks_completed_private_fields_no_key_or_identity_and_unchanged_branch_proofs() {
    let production = include_str!("first_time_setup_staged_verification_context.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    let fields = production
        .split_once("pub(crate) struct CompletedFirstTimeSetupStagedVerificationContext {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert_eq!(
        compact(fields),
        compact(
            "installation_evidence: ReloadVerifiedStagedInstallationEvidenceForSetup,
         freshness_anchor: ReloadVerifiedStagedFreshnessAnchorForSetup,
         closed_database: ClosedPreparedMetadataValidatedProductionDatabaseForSetup,
         pending_publication: PendingSetupPublicationPayloads,
         database_metadata: DatabaseMetadataContractV1,
         installation_evidence_paths: InstallationEvidencePersistencePaths,
         database_key_paths: DatabaseKeyPersistencePaths,
         freshness_anchor_paths: FreshnessAnchorPersistencePaths,"
        )
    );
    assert_eq!(fields.matches("DatabaseMetadataContractV1").count(), 1);
    for (source, name, fields) in [
        (
            include_str!(
                "../../installation_evidence_protection/staged_database_key_verification.rs"
            ),
            "ReloadedStagedGenerationBoundDatabaseKeyForSetup",
            "generation_bound_database_key: GenerationBoundDatabaseKey,",
        ),
        (
            include_str!(
                "../../installation_evidence_protection/staged_installation_evidence_verification.rs"
            ),
            "ReloadVerifiedStagedInstallationEvidenceForSetup",
            "evidence: StructurallyValidatedInstallationEvidence,",
        ),
        (
            include_str!(
                "../../installation_evidence_protection/staged_freshness_anchor_verification.rs"
            ),
            "ReloadVerifiedStagedFreshnessAnchorForSetup",
            "contract: FreshnessAnchorContractV1,",
        ),
        (
            include_str!("../live_metadata_and_header_validation/setup_database_revalidation.rs"),
            "ClosedPreparedMetadataValidatedProductionDatabaseForSetup",
            "_private: (),",
        ),
    ] {
        let marker = format!("pub(crate) struct {name} {{");
        let actual = source
            .split_once(&marker)
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        assert_eq!(compact(actual), compact(fields));
    }
}
