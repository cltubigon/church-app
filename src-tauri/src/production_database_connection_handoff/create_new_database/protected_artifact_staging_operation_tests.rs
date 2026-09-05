use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use super::*;
use crate::storage_foundation::{
    PRODUCTION_DATABASE_FILENAME, database_key_persistence_paths,
    freshness_anchor_persistence_paths, installation_evidence_persistence_paths,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = temporary.join(format!(
            "church-app-sealed-staging-{}-{nonce}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(root.is_absolute() && root.starts_with(&temporary) && root != temporary);
        fs::create_dir(&root).unwrap();
        // Deliberately not a database: this slice must never open or verify it.
        fs::write(
            root.join(PRODUCTION_DATABASE_FILENAME),
            b"synthetic-database-sentinel",
        )
        .unwrap();
        Self { root }
    }

    fn inputs(
        &self,
    ) -> (
        FirstTimeSetupStagedVerificationContext,
        PreparedFirstTimeSetupProtectedArtifactDirectories,
    ) {
        let key = database_key_persistence_paths(&self.root);
        let freshness = freshness_anchor_persistence_paths(&self.root);
        let evidence = installation_evidence_persistence_paths(&self.root);
        let directories = super::super::super::protected_artifact_directories::
            prepare_first_time_setup_protected_artifact_directories(&key, &freshness, &evidence)
            .unwrap();
        let context = super::super::prepare_first_time_setup_staged_verification_context(
            super::super::tests::prepared().0,
            evidence,
            key,
            freshness,
        )
        .unwrap();
        (context, directories)
    }

    fn staged_paths(&self) -> [PathBuf; 5] {
        let key = database_key_persistence_paths(&self.root);
        let freshness = freshness_anchor_persistence_paths(&self.root);
        let evidence = installation_evidence_persistence_paths(&self.root);
        [
            key.staged_database_key.as_path().to_owned(),
            freshness
                .staged_anchor_authentication_key
                .as_path()
                .to_owned(),
            freshness
                .staged_authenticated_freshness_anchor
                .as_path()
                .to_owned(),
            evidence.staged_authentication_key.as_path().to_owned(),
            evidence.staged_authenticated_evidence.as_path().to_owned(),
        ]
    }

    fn assert_active_unchanged(&self) {
        assert_eq!(
            fs::read(self.root.join(PRODUCTION_DATABASE_FILENAME)).unwrap(),
            b"synthetic-database-sentinel"
        );
        let key = database_key_persistence_paths(&self.root);
        let freshness = freshness_anchor_persistence_paths(&self.root);
        let evidence = installation_evidence_persistence_paths(&self.root);
        for path in [
            key.active_database_key.as_path(),
            freshness.active_anchor_authentication_key.as_path(),
            freshness.active_authenticated_freshness_anchor.as_path(),
            evidence.active_authentication_key.as_path(),
            evidence.active_authenticated_evidence.as_path(),
        ] {
            assert!(!path.exists());
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let temporary = std::env::temp_dir();
        assert!(
            self.root.is_absolute() && self.root.starts_with(&temporary) && self.root != temporary
        );
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn wrappers(context: &FirstTimeSetupStagedVerificationContext) -> [&[u8]; 5] {
    pending_wrappers(&context.pending_publication)
}

fn pending_wrappers(pending: &PendingSetupPublicationPayloads) -> [&[u8]; 5] {
    [
        pending.protected_database_key_wrapper.as_bytes(),
        pending
            .protected_freshness_authentication_key_wrapper
            .as_bytes(),
        pending
            .protected_authenticated_freshness_anchor_wrapper
            .as_bytes(),
        pending
            .protected_evidence_authentication_key_wrapper
            .as_bytes(),
        pending.protected_authenticated_evidence_wrapper.as_bytes(),
    ]
}

fn assert_boundary(machine: &FirstTimeSetupPublicationStateMachine, boundary: &str) {
    assert_eq!(
        format!("{machine:?}"),
        format!("FirstTimeSetupPublicationStateMachine {{ state: {boundary} }}")
    );
}

#[test]
fn binds_before_writing_and_retains_all_allocations_through_exact_final_boundary() {
    let fixture = Fixture::new();
    let (context, directories) = fixture.inputs();
    let allocations = wrappers(&context).map(|bytes| bytes.as_ptr());
    let expected = wrappers(&context).map(<[u8]>::to_vec);
    let operation =
        prepare_first_time_setup_protected_artifact_staging_operation(context, directories);
    assert_boundary(
        &operation.machine,
        "CanonicalDatabaseClosedAndMaterialsPrepared",
    );
    assert_eq!(
        format!("{operation:?}"),
        "FirstTimeSetupProtectedArtifactStagingOperation([REDACTED])"
    );
    assert_eq!(
        wrappers(&operation.context).map(|bytes| bytes.as_ptr()),
        allocations
    );
    assert!(fixture.staged_paths().iter().all(|path| !path.exists()));

    let staged = stage_first_time_setup_protected_artifacts(operation).unwrap();
    assert_boundary(&staged.machine, "AuthenticatedEvidenceStaged");
    assert_eq!(size_of_val(&staged.authority), 0);
    assert_eq!(
        format!("{staged:?}"),
        "AllProtectedArtifactsStagedFirstTimeSetupOperation([REDACTED])"
    );
    assert_eq!(
        wrappers(&staged.context).map(|bytes| bytes.as_ptr()),
        allocations
    );
    assert_eq!(
        format!("{:?}", staged.directories),
        "PreparedFirstTimeSetupProtectedArtifactDirectories([REDACTED])"
    );
    for (path, bytes) in fixture.staged_paths().iter().zip(expected) {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    fixture.assert_active_unchanged();
    drop(staged);
    // Dropping the success owner closes resources without deleting staged files.
    assert!(fixture.staged_paths().iter().all(|path| path.exists()));
}

#[test]
fn each_writer_failure_is_terminal_preserves_residue_and_never_runs_later_writers() {
    use FirstTimeSetupProtectedArtifactStagingError as Error;
    let errors = [
        Error::DatabaseKey(StagedProtectedWrapperWriteError::StageAlreadyExists),
        Error::FreshnessAuthenticationKey(StagedProtectedWrapperWriteError::StageAlreadyExists),
        Error::AuthenticatedFreshnessAnchor(StagedProtectedWrapperWriteError::StageAlreadyExists),
        Error::EvidenceAuthenticationKey(StagedProtectedWrapperWriteError::StageAlreadyExists),
        Error::AuthenticatedEvidence(StagedProtectedWrapperWriteError::StageAlreadyExists),
    ];
    for (failed, expected_error) in errors.into_iter().enumerate() {
        let fixture = Fixture::new();
        let (context, directories) = fixture.inputs();
        let expected_bytes = wrappers(&context).map(<[u8]>::to_vec);
        let operation =
            prepare_first_time_setup_protected_artifact_staging_operation(context, directories);
        let paths = fixture.staged_paths();
        fs::write(&paths[failed], b"synthetic-collision-sentinel").unwrap();
        let error = stage_first_time_setup_protected_artifacts(operation).unwrap_err();
        assert_eq!(error, expected_error);
        for (index, path) in paths.iter().enumerate() {
            if index < failed {
                assert_eq!(fs::read(path).unwrap(), expected_bytes[index]);
            } else if index == failed {
                assert_eq!(fs::read(path).unwrap(), b"synthetic-collision-sentinel");
            } else {
                assert!(!path.exists());
            }
        }
        fixture.assert_active_unchanged();
    }
}

#[test]
fn pre_active_publication_owners_are_non_clone_non_copy_non_serializable_and_have_no_deref() {
    macro_rules! assert_not_impl {
        ($owner:ty, $bound:path) => {{
            trait AmbiguousIfImplemented<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImplemented<()> for T {}
            struct HasForbiddenImpl;
            impl<T: ?Sized + $bound> AmbiguousIfImplemented<HasForbiddenImpl> for T {}
            let _ = <$owner as AmbiguousIfImplemented<_>>::check;
        }};
    }
    macro_rules! assert_sealed {
        ($owner:ty) => {
            assert_not_impl!($owner, Clone);
            assert_not_impl!($owner, Copy);
            assert_not_impl!($owner, serde::Serialize);
            assert_not_impl!($owner, serde::Deserialize<'static>);
            assert_not_impl!($owner, std::ops::Deref);
        };
    }
    assert_sealed!(ProtectedArtifactStagingAuthority);
    assert_not_impl!(ProtectedArtifactStagingAuthority, Default);
    assert_sealed!(FirstTimeSetupProtectedArtifactStagingOperation);
    assert_sealed!(AllProtectedArtifactsStagedFirstTimeSetupOperation);
    assert_sealed!(StagedVerificationCompletedFirstTimeSetupOperation);
    assert_not_impl!(StagedVerificationCompletedFirstTimeSetupOperation, Default);
    assert_sealed!(PreparedFirstTimeSetupActivePublicationOperation);
    assert_not_impl!(PreparedFirstTimeSetupActivePublicationOperation, Default);
    assert_sealed!(DatabaseKeyWrapperPublishedFirstTimeSetupOperation);
    assert_not_impl!(DatabaseKeyWrapperPublishedFirstTimeSetupOperation, Default);
}

fn production() -> &'static str {
    include_str!("protected_artifact_staging_operation.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap()
}

fn compact(source: &str) -> String {
    source.split_whitespace().collect()
}

#[test]
fn authority_is_zero_sized_private_and_bound_only_to_the_publication_machine() {
    assert_eq!(size_of::<ProtectedArtifactStagingAuthority>(), 0);
    let source = compact(production());
    assert!(source.contains("pub(crate)structProtectedArtifactStagingAuthority{_private:(),}"));
    assert!(source.contains(
        "implprotected_artifact_staging::AuthorityBindingforFirstTimeSetupPublicationStateMachine{typeAuthority=ProtectedArtifactStagingAuthority;}"
    ));
    // The declaration and the sole construction inside prepare are the only
    // struct forms. No factory, getter, conversion, or replacement impl exists.
    assert_eq!(
        source.matches("ProtectedArtifactStagingAuthority{").count(),
        2
    );
    assert!(!source.contains("implProtectedArtifactStagingAuthority"));
    assert!(!source.contains("Default"));

    let publication = include_str!("../../first_time_setup_publication.rs");
    let bridge = compact(
        publication
            .split_once("pub(crate) mod protected_artifact_staging {")
            .unwrap()
            .1
            .split("#[cfg(test)]")
            .next()
            .unwrap(),
    );
    // The private supertrait admits only the concrete machine; callers cannot
    // select a substitute binding with an independently constructible token.
    assert!(bridge.contains(
        "modsealed{pubtraitMachine{}implMachineforsuper::FirstTimeSetupPublicationStateMachine{}}"
    ));
    assert!(bridge.contains("traitAuthorityBinding:sealed::Machine{typeAuthority;}"));
    assert_eq!(bridge.matches("pub(crate)fn").count(), 8);
    assert_eq!(bridge.matches("<M:AuthorityBinding>(").count(), 8);
    assert_eq!(bridge.matches("_authority:&M::Authority,").count(), 8);
    assert!(!bridge.contains("pub(crate)modsealed"));
}

#[test]
fn pre_active_publication_bridges_require_authority_and_reject_wrong_order() {
    use protected_artifact_staging as staging;
    type Advance = fn(
        &ProtectedArtifactStagingAuthority,
        FirstTimeSetupPublicationStateMachine,
    ) -> Result<
        FirstTimeSetupPublicationStateMachine,
        crate::first_time_setup_publication::FirstTimeSetupPublicationTransitionError,
    >;
    let advances: [Advance; 6] = [
        staging::advance_database_key_staged::<FirstTimeSetupPublicationStateMachine>,
        staging::advance_freshness_authentication_key_staged::<FirstTimeSetupPublicationStateMachine>,
        staging::advance_authenticated_freshness_anchor_staged::<
            FirstTimeSetupPublicationStateMachine,
        >,
        staging::advance_evidence_authentication_key_staged::<FirstTimeSetupPublicationStateMachine>,
        staging::advance_authenticated_evidence_staged::<FirstTimeSetupPublicationStateMachine>,
        staging::advance_all_staged_artifacts_reload_verified::<
            FirstTimeSetupPublicationStateMachine,
        >,
    ];
    let boundaries = [
        "CanonicalDatabaseClosedAndMaterialsPrepared",
        "ProtectedDatabaseKeyWrapperStaged",
        "FreshnessAuthenticationKeyWrapperStaged",
        "AuthenticatedFreshnessAnchorStaged",
        "EvidenceAuthenticationKeyWrapperStaged",
        "AuthenticatedEvidenceStaged",
        "AllStagedArtifactsReloadVerified",
    ];
    // Tests are descendants of the sealed module; no production test factory
    // is needed to exercise the bridge's unchanged transition semantics.
    let authority = ProtectedArtifactStagingAuthority { _private: () };
    for completed in 0..=6 {
        for (index, advance) in advances.iter().enumerate() {
            let mut machine = staging::begin::<FirstTimeSetupPublicationStateMachine>(&authority);
            for preceding in &advances[..completed] {
                machine = preceding(&authority, machine).unwrap();
            }
            assert_boundary(&machine, boundaries[completed]);
            let outcome = advance(&authority, machine);
            if completed == index {
                assert_boundary(&outcome.unwrap(), boundaries[index + 1]);
            } else {
                assert_eq!(outcome.unwrap_err(), crate::first_time_setup_publication::FirstTimeSetupPublicationTransitionError::OutOfOrder);
            }
        }
    }
}

#[test]
fn source_seals_inputs_fields_and_construction_without_machine_pairing_or_replacement() {
    let source = production();
    for owner in [
        "FirstTimeSetupProtectedArtifactStagingOperation",
        "AllProtectedArtifactsStagedFirstTimeSetupOperation",
    ] {
        let fields = source
            .split_once(&format!("pub(crate) struct {owner} {{"))
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        assert_eq!(
            compact(&fields.lines().filter(|line| !line.trim_start().starts_with("//")).collect::<Vec<_>>().join(" ")),
            compact(
                "context: FirstTimeSetupStagedVerificationContext,
            directories: PreparedFirstTimeSetupProtectedArtifactDirectories,
            machine: FirstTimeSetupPublicationStateMachine, authority: ProtectedArtifactStagingAuthority,"
            )
        );
    }
    assert_eq!(source.matches("pub(crate) fn ").count(), 5);
    assert_eq!(source.matches("impl ").count(), 7); // Binding and redacted Debug only.
    let construction = source
        .split_once("pub(crate) fn prepare_")
        .unwrap()
        .1
        .split_once("/// Each write")
        .unwrap()
        .0;
    assert_eq!(
        compact(construction),
        compact(
            "first_time_setup_protected_artifact_staging_operation(
        context: FirstTimeSetupStagedVerificationContext,
        directories: PreparedFirstTimeSetupProtectedArtifactDirectories,
    ) -> FirstTimeSetupProtectedArtifactStagingOperation {
        let authority = ProtectedArtifactStagingAuthority { _private: () };
        let machine = protected_artifact_staging::begin::<FirstTimeSetupPublicationStateMachine>(&authority);
        FirstTimeSetupProtectedArtifactStagingOperation {
            context, directories, machine, authority,
        }
    }"
        )
    );
    let signature = source
        .split_once("pub(crate) fn stage_")
        .unwrap()
        .1
        .split_once('{')
        .unwrap()
        .0;
    assert_eq!(compact(signature), compact("first_time_setup_protected_artifacts(
        operation: FirstTimeSetupProtectedArtifactStagingOperation,
    ) -> Result<AllProtectedArtifactsStagedFirstTimeSetupOperation, FirstTimeSetupProtectedArtifactStagingError,>"));
}

#[test]
fn source_locks_every_borrow_write_success_then_advance_and_terminal_error() {
    let source = compact(production().split("/// Verify only").next().unwrap());
    let mut remaining = source
        .split_once("letcore=&context.verification_core;letpending=&context.pending_publication;")
        .unwrap()
        .1;
    for (writer, path, wrapper, error, advance) in [
        (
            "database_key",
            "database_key_paths.staged_database_key",
            "database_key",
            "DatabaseKey",
            "database_key",
        ),
        (
            "freshness_authentication_key",
            "freshness_anchor_paths.staged_anchor_authentication_key",
            "freshness_authentication_key",
            "FreshnessAuthenticationKey",
            "freshness_authentication_key",
        ),
        (
            "authenticated_freshness_anchor",
            "freshness_anchor_paths.staged_authenticated_freshness_anchor",
            "authenticated_freshness_anchor",
            "AuthenticatedFreshnessAnchor",
            "authenticated_freshness_anchor",
        ),
        (
            "evidence_authentication_key",
            "installation_evidence_paths.staged_authentication_key",
            "evidence_authentication_key",
            "EvidenceAuthenticationKey",
            "evidence_authentication_key",
        ),
        (
            "authenticated_evidence",
            "installation_evidence_paths.staged_authenticated_evidence",
            "authenticated_evidence",
            "AuthenticatedEvidence",
            "authenticated_evidence",
        ),
    ] {
        let expected = compact(&format!(
            "write_staged_{writer}_wrapper(
            &mut directories, &core.{path}, &pending.protected_{wrapper}_wrapper,
        ).map_err(FirstTimeSetupProtectedArtifactStagingError::{error})?;
        machine = protected_artifact_staging::advance_{advance}_staged::<FirstTimeSetupPublicationStateMachine,>(&authority, machine)
            .map_err(|_| FirstTimeSetupProtectedArtifactStagingError::InternalState)?;"
        ));
        remaining = remaining
            .strip_prefix(&expected)
            .expect("exact write-success-advance order");
    }
    assert_eq!(
        remaining,
        compact(
            "Ok(AllProtectedArtifactsStagedFirstTimeSetupOperation {
        context, directories, machine, authority,
    }) }"
        )
    );
}

#[test]
fn source_has_no_publication_retry_cleanup_or_detachable_authority() {
    let source = production();
    for forbidden in [
        "verify_reloaded_",
        "revalidate_",
        "open_identity_",
        "close_and_preserve_",
        "FreshnessAuthenticationKeyWrapperPublished",
        "AuthenticatedFreshnessAnchorPublished",
        "EvidenceAuthenticationKeyWrapperPublished",
        "AuthenticatedEvidencePublished",
        "FinalActiveArtifactsVerified",
        "FirstTimeSetupPublicationEvent",
        "ReadyForSetupCompletion",
        "std::fs",
        "rename(",
        "copy(",
        "remove_",
        "create_dir",
        "prepare_first_time_setup_protected_artifact_directories(",
        "load_active",
        "startup",
        "Operational",
        "Mutex",
        "LockFileEx",
        ".clone(",
        "as_bytes(",
        "into_parts",
        "Deref",
        "Serialize",
        "Deserialize",
        "replace(",
        "mem::",
        "context_id",
        "operation_id",
        "impl Drop",
        "loop {",
        "while ",
        "panic!",
        "unwrap(",
        "expect(",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden capability: {forbidden}"
        );
    }
}

#[test]
fn bound_verification_source_locks_single_input_single_call_and_unchanged_error_passthrough() {
    let source = production();
    let transition = source
        .split_once("pub(crate) fn verify_all_staged_first_time_setup_operation(")
        .unwrap()
        .1
        .split("/// Consume the bound verification success")
        .next()
        .unwrap();
    // The entire body locks moves of the original four fields. There is no
    // second verifier, state transition, error mapping, retry, or cleanup path.
    assert_eq!(
        compact(transition),
        compact(
            "operation: AllProtectedArtifactsStagedFirstTimeSetupOperation,
        ) -> Result<StagedVerificationCompletedFirstTimeSetupOperation,
                    FirstTimeSetupStagedVerificationError> {
            let AllProtectedArtifactsStagedFirstTimeSetupOperation {
                context, directories, machine, authority,
            } = operation;
            let completed_context = verify_first_time_setup_staged_context(context)?;
            Ok(StagedVerificationCompletedFirstTimeSetupOperation {
                completed_context, directories, machine, authority,
            })
        }"
        )
    );
    assert_eq!(
        source
            .matches("verify_first_time_setup_staged_context(")
            .count(),
        1
    );
    let _: fn(
        AllProtectedArtifactsStagedFirstTimeSetupOperation,
    ) -> Result<
        StagedVerificationCompletedFirstTimeSetupOperation,
        FirstTimeSetupStagedVerificationError,
    > = super::super::super::verify_all_staged_first_time_setup_operation;

    // The unchanged canonical error includes all three database error families;
    // the direct `?` above preserves every nested live owner, including open
    // construction failures, without wrapping or invoking disposal itself.
    let canonical = include_str!("first_time_setup_staged_verification_context.rs");
    let error = canonical
        .split_once("pub(crate) enum FirstTimeSetupStagedVerificationError {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert_eq!(
        compact(error),
        compact(
            "InstallationEvidence(StagedInstallationEvidenceVerificationError),
        FreshnessAnchor(StagedFreshnessAnchorVerificationError),
        DatabaseKey(StagedDatabaseKeyVerificationError),
        DatabaseOpen(SetupProductionDatabaseOpenError),
        DatabaseRevalidation(SetupProductionDatabaseRevalidationError),
        DatabaseClose(SetupProductionDatabaseRevalidationCloseFailure),"
        )
    );
}

#[test]
fn bound_verification_source_locks_exact_opaque_owner_and_only_success_construction() {
    let source = production();
    let fields = source
        .split_once("pub(crate) struct StagedVerificationCompletedFirstTimeSetupOperation {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert_eq!(
        compact(fields),
        compact(
            "completed_context: CompletedFirstTimeSetupStagedVerificationContext,
        directories: PreparedFirstTimeSetupProtectedArtifactDirectories,
        machine: FirstTimeSetupPublicationStateMachine,
        authority: ProtectedArtifactStagingAuthority,"
        )
    );
    assert_eq!(
        fields
            .matches("CompletedFirstTimeSetupStagedVerificationContext")
            .count(),
        1
    );
    assert_eq!(
        source
            .matches("Ok(StagedVerificationCompletedFirstTimeSetupOperation {")
            .count(),
        1
    );
    // Declaration, Debug, successful return, and consuming destructure; no
    // independent factory, Default, getters, conversions, or replacement API.
    assert_eq!(
        source
            .matches("StagedVerificationCompletedFirstTimeSetupOperation {")
            .count(),
        4
    );
    assert!(!source.contains("impl StagedVerificationCompletedFirstTimeSetupOperation"));
    assert_eq!(
        source
            .matches("ProtectedArtifactStagingAuthority { _private: () }")
            .count(),
        1
    );
}

use super::super::verification_tests::{FailClose, Fixture as VerificationFixture};
use crate::production_database_connection_handoff as handoff;

#[test]
fn pre_active_publication_source_locks_consumption_proof_retirement_and_only_one_advance() {
    let source = production();
    let transition = source
        .split_once("pub(crate) fn prepare_first_time_setup_active_publication(")
        .unwrap()
        .1
        .split("/// Publish exactly the staged database-key wrapper")
        .next()
        .unwrap();
    let without_comments = transition
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    // Lock the complete body: same authority/machine/directories, no second
    // construction, copied metadata, rebuilt payload/path family, I/O, verifier,
    // active loader/publication, observer, cleanup, or later trust boundary.
    assert_eq!(
        compact(&without_comments),
        compact(
            "operation: StagedVerificationCompletedFirstTimeSetupOperation,
        ) -> Result<PreparedFirstTimeSetupActivePublicationOperation, FirstTimeSetupPreActivePublicationError> {
            let StagedVerificationCompletedFirstTimeSetupOperation {
                completed_context, directories, machine, authority,
            } = operation;
            let CompletedFirstTimeSetupStagedVerificationContext {
                installation_evidence, freshness_anchor, closed_database,
                pending_publication, database_metadata, installation_evidence_paths,
                database_key_paths, freshness_anchor_paths,
            } = completed_context;
            {
                let _installation_evidence = installation_evidence;
                let _freshness_anchor = freshness_anchor;
                let _closed_database = closed_database;
            }
            let machine = protected_artifact_staging::advance_all_staged_artifacts_reload_verified::<
                FirstTimeSetupPublicationStateMachine,
            >(&authority, machine)
            .map_err(|_| FirstTimeSetupPreActivePublicationError::InternalState)?;
            Ok(PreparedFirstTimeSetupActivePublicationOperation {
                pending_publication, database_metadata, installation_evidence_paths,
                database_key_paths, freshness_anchor_paths, directories, machine, authority,
            })
        }"
        )
    );
    assert_eq!(
        source
            .matches("::advance_all_staged_artifacts_reload_verified::<")
            .count(),
        1
    );
    assert_eq!(
        source
            .matches("ProtectedArtifactStagingAuthority { _private: () }")
            .count(),
        1
    );
    // Also compile-check the narrow reexport and its single by-value input.
    let _: fn(
        StagedVerificationCompletedFirstTimeSetupOperation,
    ) -> Result<
        PreparedFirstTimeSetupActivePublicationOperation,
        FirstTimeSetupPreActivePublicationError,
    > = super::super::super::prepare_first_time_setup_active_publication;
}

#[test]
fn pre_active_publication_source_locks_exact_opaque_owner_and_coarse_error() {
    let source = production();
    let fields = source
        .split_once("pub(crate) struct PreparedFirstTimeSetupActivePublicationOperation {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert_eq!(
        compact(fields),
        compact(
            "pending_publication: PendingSetupPublicationPayloads,
        database_metadata: DatabaseMetadataContractV1,
        installation_evidence_paths: InstallationEvidencePersistencePaths,
        database_key_paths: DatabaseKeyPersistencePaths,
        freshness_anchor_paths: FreshnessAnchorPersistencePaths,
        directories: PreparedFirstTimeSetupProtectedArtifactDirectories,
        machine: FirstTimeSetupPublicationStateMachine,
        authority: ProtectedArtifactStagingAuthority,"
        )
    );
    assert_eq!(
        source
            .matches("PreparedFirstTimeSetupActivePublicationOperation {")
            .count(),
        4
    );
    assert!(!source.contains("impl PreparedFirstTimeSetupActivePublicationOperation"));
    let error = source
        .split_once("pub(crate) enum FirstTimeSetupPreActivePublicationError {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert_eq!(compact(error), "InternalState,");
}

#[test]
fn pre_active_publication_source_locks_internal_milestone_and_neutral_bridge() {
    let publication = include_str!("../../first_time_setup_publication.rs");
    let bridge = publication
        .split_once("pub(crate) fn advance_all_staged_artifacts_reload_verified")
        .unwrap()
        .1
        .split_once("pub(crate) fn advance_database_key_wrapper_published")
        .unwrap()
        .0;
    assert_eq!(compact(bridge), compact(
        "<M: AuthorityBinding>(
            _authority: &M::Authority,
            machine: FirstTimeSetupPublicationStateMachine,
        ) -> Result<FirstTimeSetupPublicationStateMachine, FirstTimeSetupPublicationTransitionError> {
            in_progress(machine.advance(
                FirstTimeSetupPublicationEvent::AllStagedArtifactsReloadVerified(
                    AllStagedArtifactsReloadVerified { _private: () },
                ),
            ))
        }"
    ));
    let pure_production = publication.split("#[cfg(test)]\nmod tests").next().unwrap();
    assert_eq!(
        pure_production
            .matches("AllStagedArtifactsReloadVerified { _private: () }")
            .count(),
        1
    );
    for forbidden in [
        "std::fs",
        "std::path",
        "windows_sys",
        "rusqlite",
        "Vec<",
        "PathBuf",
        "EncodedProtectedWrapper",
        "DatabaseMetadataContractV1",
        "PersistencePaths",
        "PreparedFirstTimeSetupProtectedArtifactDirectories",
        "ProtectedArtifactStagingAuthority",
        "impl AllStagedArtifactsReloadVerified",
        "-> AllStagedArtifactsReloadVerified",
    ] {
        assert!(
            !pure_production.contains(forbidden),
            "forbidden dependency: {forbidden}"
        );
    }
}

#[test]
fn pre_active_publication_real_chain_preserves_payload_allocations_paths_metadata_and_residue() {
    let mut fixture = VerificationFixture::new_unstaged();
    let staged = stage_real_fixture(&mut fixture);
    let completed = verify_all_staged_first_time_setup_operation(staged).unwrap();
    assert_boundary(&completed.machine, "AuthenticatedEvidenceStaged");
    let context = &completed.completed_context;
    let allocations = pending_wrappers(&context.pending_publication).map(|bytes| bytes.as_ptr());
    let bytes = pending_wrappers(&context.pending_publication).map(|bytes| bytes.to_vec());
    let metadata = context.database_metadata;
    // Test-only expected values; production moves all three families unchanged.
    let evidence_paths = context.installation_evidence_paths.clone();
    let key_paths = context.database_key_paths.clone();
    let freshness_paths = context.freshness_anchor_paths.clone();
    let before = fixture.snapshot();
    assert_eq!(before.len(), 7); // Canonical DB, five stages, sentinel; no active wrappers.

    let prepared = prepare_first_time_setup_active_publication(completed).unwrap();
    assert_boundary(&prepared.machine, "AllStagedArtifactsReloadVerified");
    assert_eq!(
        format!("{prepared:?}"),
        "PreparedFirstTimeSetupActivePublicationOperation([REDACTED])"
    );
    assert_eq!(
        pending_wrappers(&prepared.pending_publication).map(|bytes| bytes.as_ptr()),
        allocations
    );
    assert_eq!(
        pending_wrappers(&prepared.pending_publication).map(|bytes| bytes.to_vec()),
        bytes
    );
    assert_eq!(prepared.database_metadata, metadata);
    assert_eq!(prepared.installation_evidence_paths, evidence_paths);
    assert_eq!(prepared.database_key_paths, key_paths);
    assert_eq!(prepared.freshness_anchor_paths, freshness_paths);
    assert_eq!(
        format!("{:?}", prepared.directories),
        "PreparedFirstTimeSetupProtectedArtifactDirectories([REDACTED])"
    );
    // Zero-sized authority has no meaningful address identity: its exact move
    // and sole production constructor are enforced by the source contract.
    assert_eq!(size_of_val(&prepared.authority), 0);
    assert_eq!(fixture.snapshot(), before);
    drop(prepared);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn database_key_publication_real_chain_moves_only_key_and_preserves_sealed_ownership() {
    let mut fixture = VerificationFixture::new_unstaged();
    let staged = stage_real_fixture(&mut fixture);
    let completed = verify_all_staged_first_time_setup_operation(staged).unwrap();
    let prepared = prepare_first_time_setup_active_publication(completed).unwrap();
    let allocations = pending_wrappers(&prepared.pending_publication).map(|bytes| bytes.as_ptr());
    let expected_key = prepared
        .pending_publication
        .protected_database_key_wrapper
        .as_bytes()
        .to_vec();
    let metadata = prepared.database_metadata;
    let evidence_paths = prepared.installation_evidence_paths.clone();
    let key_paths = prepared.database_key_paths.clone();
    let freshness_paths = prepared.freshness_anchor_paths.clone();
    let other_staged = fixture.staged_paths()[1..]
        .iter()
        .map(|path| (path.clone(), fs::read(path).unwrap()))
        .collect::<Vec<_>>();

    let published = publish_first_time_setup_database_key_wrapper(prepared).unwrap();
    assert_boundary(&published.machine, "ProtectedDatabaseKeyWrapperPublished");
    assert_eq!(
        format!("{published:?}"),
        "DatabaseKeyWrapperPublishedFirstTimeSetupOperation([REDACTED])"
    );
    assert_eq!(
        pending_wrappers(&published.pending_publication).map(|bytes| bytes.as_ptr()),
        allocations
    );
    assert_eq!(published.database_metadata, metadata);
    assert_eq!(published.installation_evidence_paths, evidence_paths);
    assert_eq!(published.database_key_paths, key_paths);
    assert_eq!(published.freshness_anchor_paths, freshness_paths);
    assert_eq!(
        format!("{:?}", published.directories),
        "PreparedFirstTimeSetupProtectedArtifactDirectories([REDACTED])"
    );
    assert_eq!(size_of_val(&published.authority), 0);
    assert!(!key_paths.staged_database_key.as_path().exists());
    assert_eq!(
        fs::read(key_paths.active_database_key.as_path()).unwrap(),
        expected_key
    );
    for (path, bytes) in other_staged {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    for active in [
        freshness_paths.active_anchor_authentication_key.as_path(),
        freshness_paths
            .active_authenticated_freshness_anchor
            .as_path(),
        evidence_paths.active_authentication_key.as_path(),
        evidence_paths.active_authenticated_evidence.as_path(),
    ] {
        assert!(!active.exists());
    }
    fixture.assert_write_access(true);
}

#[test]
fn database_key_publication_machine_failure_is_post_mutation_and_does_not_rollback() {
    let mut fixture = VerificationFixture::new_unstaged();
    let staged = stage_real_fixture(&mut fixture);
    let completed = verify_all_staged_first_time_setup_operation(staged).unwrap();
    let mut prepared = prepare_first_time_setup_active_publication(completed).unwrap();
    let key_paths = prepared.database_key_paths.clone();
    prepared.machine = protected_artifact_staging::begin::<FirstTimeSetupPublicationStateMachine>(
        &prepared.authority,
    );
    assert_eq!(
        publish_first_time_setup_database_key_wrapper(prepared).unwrap_err(),
        FirstTimeSetupDatabaseKeyPublicationError::InternalStateAfterPublication
    );
    assert!(!key_paths.staged_database_key.as_path().exists());
    assert!(key_paths.active_database_key.as_path().exists());
}

#[test]
fn database_key_publication_maps_each_filesystem_phase_without_advancing() {
    use DatabaseKeyWrapperPublicationFilesystemError as Filesystem;
    for (filesystem, operation_error) in [
        (
            Filesystem::PrepublicationRejected,
            FirstTimeSetupDatabaseKeyPublicationError::PrepublicationRejected,
        ),
        (
            Filesystem::RenameOutcomeUnconfirmed,
            FirstTimeSetupDatabaseKeyPublicationError::RenameOutcomeUnconfirmed,
        ),
        (
            Filesystem::PostRenameFlushFailed,
            FirstTimeSetupDatabaseKeyPublicationError::PostRenameFlushFailed,
        ),
        (
            Filesystem::PostRenameValidationFailed,
            FirstTimeSetupDatabaseKeyPublicationError::PostRenameValidationFailed,
        ),
    ] {
        let mut fixture = VerificationFixture::new_unstaged();
        let staged = stage_real_fixture(&mut fixture);
        let completed = verify_all_staged_first_time_setup_operation(staged).unwrap();
        let prepared = prepare_first_time_setup_active_publication(completed).unwrap();
        let before = fixture.snapshot();
        assert_eq!(
            publish_first_time_setup_database_key_wrapper_using(prepared, |_, _, _| Err(
                filesystem
            ))
            .unwrap_err(),
            operation_error
        );
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn database_key_publication_owner_and_errors_are_sealed_and_redacted() {
    let source = production();
    let fields = source
        .split_once("pub(crate) struct DatabaseKeyWrapperPublishedFirstTimeSetupOperation {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    for field in [
        "pending_publication: PendingSetupPublicationPayloads",
        "database_metadata: DatabaseMetadataContractV1",
        "installation_evidence_paths: InstallationEvidencePersistencePaths",
        "database_key_paths: DatabaseKeyPersistencePaths",
        "freshness_anchor_paths: FreshnessAnchorPersistencePaths",
        "directories: PreparedFirstTimeSetupProtectedArtifactDirectories",
        "machine: FirstTimeSetupPublicationStateMachine",
        "authority: ProtectedArtifactStagingAuthority",
    ] {
        assert_eq!(fields.matches(field).count(), 1);
    }
    assert_eq!(
        source
            .matches("ProtectedArtifactStagingAuthority { _private: () }")
            .count(),
        1
    );
    for error in [
        FirstTimeSetupDatabaseKeyPublicationError::PrepublicationRejected,
        FirstTimeSetupDatabaseKeyPublicationError::RenameOutcomeUnconfirmed,
        FirstTimeSetupDatabaseKeyPublicationError::PostRenameFlushFailed,
        FirstTimeSetupDatabaseKeyPublicationError::PostRenameValidationFailed,
        FirstTimeSetupDatabaseKeyPublicationError::InternalStateAfterPublication,
    ] {
        let debug = format!("{error:?}");
        assert!(!debug.contains('\\'));
        assert!(!debug.contains("dpapi"));
    }
}

#[test]
fn pre_active_publication_internal_discrepancy_fails_without_cleanup() {
    let mut fixture = VerificationFixture::new_unstaged();
    let staged = stage_real_fixture(&mut fixture);
    let mut completed = verify_all_staged_first_time_setup_operation(staged).unwrap();
    // Descendant-test-only invariant corruption; no production replacement API.
    completed.machine = protected_artifact_staging::begin::<FirstTimeSetupPublicationStateMachine>(
        &completed.authority,
    );
    let before = fixture.snapshot();
    assert_eq!(
        prepare_first_time_setup_active_publication(completed).unwrap_err(),
        FirstTimeSetupPreActivePublicationError::InternalState,
    );
    assert_eq!(fixture.snapshot(), before);
    fixture.assert_write_access(true);
}

fn stage_real_fixture(
    fixture: &mut VerificationFixture,
) -> AllProtectedArtifactsStagedFirstTimeSetupOperation {
    let context = fixture.context.take().unwrap();
    let core = &context.verification_core;
    let directories = super::super::super::protected_artifact_directories::
        prepare_first_time_setup_protected_artifact_directories(
            &core.database_key_paths,
            &core.freshness_anchor_paths,
            &core.installation_evidence_paths,
        ).unwrap();
    stage_first_time_setup_protected_artifacts(
        prepare_first_time_setup_protected_artifact_staging_operation(context, directories),
    )
    .unwrap()
}

#[test]
fn bound_verification_real_success_retains_context_allocations_and_authenticated_evidence_boundary()
{
    let mut fixture = VerificationFixture::new_unstaged();
    let staged = stage_real_fixture(&mut fixture);
    let allocations = wrappers(&staged.context).map(|bytes| bytes.as_ptr());
    let metadata = staged.context.verification_core.database_metadata;
    let before = fixture.snapshot();
    assert_boundary(&staged.machine, "AuthenticatedEvidenceStaged");

    let completed = verify_all_staged_first_time_setup_operation(staged).unwrap();
    assert_eq!(
        format!("{completed:?}"),
        "StagedVerificationCompletedFirstTimeSetupOperation([REDACTED])"
    );
    assert_boundary(&completed.machine, "AuthenticatedEvidenceStaged");
    assert_eq!(size_of_val(&completed.authority), 0);
    assert_eq!(
        format!("{:?}", completed.directories),
        "PreparedFirstTimeSetupProtectedArtifactDirectories([REDACTED])"
    );
    let context: &CompletedFirstTimeSetupStagedVerificationContext = &completed.completed_context;
    assert_eq!(context.database_metadata, metadata);
    let pending = &context.pending_publication;
    assert_eq!(
        [
            pending.protected_database_key_wrapper.as_bytes().as_ptr(),
            pending
                .protected_freshness_authentication_key_wrapper
                .as_bytes()
                .as_ptr(),
            pending
                .protected_authenticated_freshness_anchor_wrapper
                .as_bytes()
                .as_ptr(),
            pending
                .protected_evidence_authentication_key_wrapper
                .as_bytes()
                .as_ptr(),
            pending
                .protected_authenticated_evidence_wrapper
                .as_bytes()
                .as_ptr(),
        ],
        allocations
    );
    assert!(fixture.context.is_none());
    fixture.assert_write_access(true); // Canonical explicit database close succeeded.
    assert_eq!(before.len(), 7); // DB, five stages, sentinel; no active wrappers.
    assert_eq!(fixture.snapshot(), before);
    drop(completed);
    assert_eq!(fixture.snapshot(), before); // No artifact cleanup on owner drop.
}

#[test]
fn bound_verification_missing_stages_preserve_each_canonical_error_and_residue() {
    use crate::installation_evidence_protection::{
        StagedDatabaseKeyVerificationError, StagedFreshnessAnchorVerificationError,
        StagedInstallationEvidenceVerificationError,
    };
    for index in 0..5 {
        let mut fixture = VerificationFixture::new_unstaged();
        let staged = stage_real_fixture(&mut fixture);
        fs::remove_file(&fixture.staged_paths()[index]).unwrap();
        let before = fixture.snapshot();
        let error = verify_all_staged_first_time_setup_operation(staged).unwrap_err();
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
fn bound_verification_preserves_database_open_identity_failure() {
    let mut fixture = VerificationFixture::new_unstaged();
    // Test-only historical identity corruption before sealing the operation.
    fixture
        .context
        .as_mut()
        .unwrap()
        .verification_core
        .database_identity_proof
        .created_leaf_identity
        .file_id[0] ^= 1;
    let staged = stage_real_fixture(&mut fixture);
    let before = fixture.snapshot();
    assert!(matches!(
        verify_all_staged_first_time_setup_operation(staged),
        Err(FirstTimeSetupStagedVerificationError::DatabaseOpen(
            handoff::SetupProductionDatabaseOpenError::IdentityMismatch
        ))
    ));
    fixture.assert_write_access(true);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn bound_verification_preserves_all_revalidation_and_final_close_owners_without_retry() {
    use crate::{
        database_key::DatabaseKey,
        installation_evidence_protection::{
            protect_database_key, verify_reloaded_staged_database_key_for_setup,
        },
    };
    use handoff::SetupProductionDatabaseRevalidationError as Revalidation;
    for phase in 0..4 {
        let mut fixture = VerificationFixture::new_unstaged();
        let staged = stage_real_fixture(&mut fixture);
        let core = &staged.context.verification_core;
        match phase {
            0 => {
                let wrong_key = protect_database_key(
                    &DatabaseKey::from_bytes([0x82; 32]),
                    core.database_metadata.database_key_generation_identifier(),
                )
                .unwrap();
                fs::write(&fixture.staged_paths()[0], wrong_key.as_bytes()).unwrap();
            }
            1 | 2 => {
                let key = verify_reloaded_staged_database_key_for_setup(
                    &core.database_key_paths,
                    &core.database_metadata,
                )
                .unwrap()
                .into_generation_bound_database_key();
                let connection = rusqlite::Connection::open(
                    core.installation_evidence_paths.active_database.as_path(),
                )
                .unwrap();
                handoff::apply_key_once(&connection, &key).unwrap();
                connection.execute_batch(if phase == 1 { "PRAGMA application_id = 0" } else {
                    "UPDATE church_app_database_metadata SET database_created_at = database_created_at + 1"
                }).unwrap();
                connection.close().map_err(|(_, error)| error).unwrap();
            }
            _ => {} // Successful verification followed by failed explicit close.
        }
        let before = fixture.snapshot();
        let injection = FailClose::arm();
        let error = verify_all_staged_first_time_setup_operation(staged).unwrap_err();
        assert_eq!(injection.attempts(), 1);
        fixture.assert_write_access(false); // Complete guard lifetime still owned.
        assert_eq!(fixture.snapshot(), before);
        drop(injection);
        // Explicit test disposal uses the original errors' existing capability;
        // the production operation never retries verification or close.
        match error {
            FirstTimeSetupStagedVerificationError::DatabaseRevalidation(
                Revalidation::IntegrityCloseFailed(failure),
            ) if phase == 0 => assert!(matches!(
                failure.retry_close(),
                handoff::ProductionDatabaseValidationCloseRetryOutcome::Closed(_)
            )),
            FirstTimeSetupStagedVerificationError::DatabaseRevalidation(
                Revalidation::LiveMetadataAndHeadersCloseFailed(failure),
            ) if phase == 1 => assert!(matches!(
                failure.retry_close(),
                handoff::LiveMetadataAndHeaderValidationCloseRetryOutcome::Closed(_)
            )),
            FirstTimeSetupStagedVerificationError::DatabaseRevalidation(
                Revalidation::PreparedMetadataMismatchCloseFailed(failure),
            ) if phase == 2 => assert!(matches!(
                failure.retry_close(),
                Revalidation::PreparedMetadataMismatch
            )),
            FirstTimeSetupStagedVerificationError::DatabaseClose(failure) if phase == 3 => {
                assert_eq!(
                    format!("{failure:?}"),
                    "SetupProductionDatabaseRevalidationCloseFailure([REDACTED])"
                );
                assert!(matches!(
                    failure.retry_close(),
                    handoff::SetupProductionDatabaseRevalidationCloseOutcome::Closed(_)
                ));
            }
            _ => panic!("the exact ownership-bearing error must survive"),
        }
        fixture.assert_write_access(true);
        assert_eq!(fixture.snapshot(), before);
    }
}
