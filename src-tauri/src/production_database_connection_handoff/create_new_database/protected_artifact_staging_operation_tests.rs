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
    let pending = &context.pending_publication;
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
fn owners_are_non_clone_non_copy_non_serializable_and_have_no_deref() {
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
    assert_eq!(bridge.matches("pub(crate)fn").count(), 6);
    assert_eq!(bridge.matches("<M:AuthorityBinding>(").count(), 6);
    assert_eq!(bridge.matches("_authority:&M::Authority,").count(), 6);
    assert!(!bridge.contains("pub(crate)modsealed"));
}

#[test]
fn protected_artifact_staging_operation_bridges_require_authority_and_reject_wrong_order() {
    use protected_artifact_staging as staging;
    type Advance = fn(
        &ProtectedArtifactStagingAuthority,
        FirstTimeSetupPublicationStateMachine,
    ) -> Result<
        FirstTimeSetupPublicationStateMachine,
        crate::first_time_setup_publication::FirstTimeSetupPublicationTransitionError,
    >;
    let advances: [Advance; 5] = [
        staging::advance_database_key_staged::<FirstTimeSetupPublicationStateMachine>,
        staging::advance_freshness_authentication_key_staged::<FirstTimeSetupPublicationStateMachine>,
        staging::advance_authenticated_freshness_anchor_staged::<
            FirstTimeSetupPublicationStateMachine,
        >,
        staging::advance_evidence_authentication_key_staged::<FirstTimeSetupPublicationStateMachine>,
        staging::advance_authenticated_evidence_staged::<FirstTimeSetupPublicationStateMachine>,
    ];
    let boundaries = [
        "CanonicalDatabaseClosedAndMaterialsPrepared",
        "ProtectedDatabaseKeyWrapperStaged",
        "FreshnessAuthenticationKeyWrapperStaged",
        "AuthenticatedFreshnessAnchorStaged",
        "EvidenceAuthenticationKeyWrapperStaged",
        "AuthenticatedEvidenceStaged",
    ];
    // Tests are descendants of the sealed module; no production test factory
    // is needed to exercise the bridge's unchanged transition semantics.
    let authority = ProtectedArtifactStagingAuthority { _private: () };
    for completed in 0..=5 {
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
    assert_eq!(source.matches("pub(crate) fn ").count(), 2);
    assert_eq!(source.matches("impl ").count(), 3); // Binding and redacted Debug only.
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
    let source = compact(production());
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
fn source_has_no_verification_publication_retry_cleanup_or_detachable_authority() {
    let source = production();
    for forbidden in [
        "verify_",
        "revalidate_",
        "open_identity_",
        "close_and_preserve_",
        "AllStagedArtifactsReloadVerified",
        "Published",
        "FirstTimeSetupPublicationEvent",
        "ReloadVerified",
        "CompletedFirstTimeSetup",
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
