//! Pure first-time-setup binding for freshly generated database-key material.
//!
//! This transition retains the exact generated installation and database-key
//! generation identities alongside the generated key. It grants no persistence,
//! publication, database, startup, setup-completion, or operational authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_key::DatabaseKey,
    database_key_generation::GeneratedDatabaseKeyMaterial,
    installation_evidence_contract::{DatabaseKeyGenerationIdentifier, InstallationIdentifier},
    installation_identifier_generation::GeneratedInstallationIdentifier,
    installation_state::FirstTimeSetupAuthorization,
};

use super::{EncodedProtectedWrapper, GenerationBoundDatabaseKey, ProtectionStageError};

pub(crate) struct FirstTimeSetupDatabaseKeyBinding {
    generation_bound_database_key: GenerationBoundDatabaseKey,
    installation_identifier: InstallationIdentifier,
    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
}

impl FirstTimeSetupDatabaseKeyBinding {
    pub(crate) fn into_parts(
        self,
    ) -> (
        GenerationBoundDatabaseKey,
        InstallationIdentifier,
        DatabaseKeyGenerationIdentifier,
    ) {
        (
            self.generation_bound_database_key,
            self.installation_identifier,
            self.database_key_generation_identifier,
        )
    }
}

impl fmt::Debug for FirstTimeSetupDatabaseKeyBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirstTimeSetupDatabaseKeyBinding([REDACTED])")
    }
}

/// Opaque setup-only owner proving that the exact generated database key was
/// protected before the still-owned generation-bound key is used to create the
/// database. This grants no persistence, publication, database, startup,
/// setup-completion, or operational authority.
pub(crate) struct ProtectedFirstTimeSetupDatabaseKeyBinding {
    generation_bound_database_key: GenerationBoundDatabaseKey,
    installation_identifier: InstallationIdentifier,
    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
    protected_database_key_wrapper: EncodedProtectedWrapper,
}

impl ProtectedFirstTimeSetupDatabaseKeyBinding {
    pub(crate) fn into_parts(
        self,
    ) -> (
        GenerationBoundDatabaseKey,
        InstallationIdentifier,
        DatabaseKeyGenerationIdentifier,
        EncodedProtectedWrapper,
    ) {
        (
            self.generation_bound_database_key,
            self.installation_identifier,
            self.database_key_generation_identifier,
            self.protected_database_key_wrapper,
        )
    }
}

impl fmt::Debug for ProtectedFirstTimeSetupDatabaseKeyBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedFirstTimeSetupDatabaseKeyBinding([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FirstTimeSetupDatabaseKeyProtectionError {
    ProtectionUnavailable,
}

impl fmt::Debug for FirstTimeSetupDatabaseKeyProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectionUnavailable")
    }
}

pub(crate) fn bind_generated_database_key_for_first_time_setup(
    authorization: &FirstTimeSetupAuthorization,
    material: GeneratedDatabaseKeyMaterial,
    installation: GeneratedInstallationIdentifier,
) -> FirstTimeSetupDatabaseKeyBinding {
    let _ = authorization;
    let (database_key, database_key_generation_identifier) = material.into_parts();
    let installation_identifier = installation.into_installation_identifier();
    let generation_bound_database_key =
        GenerationBoundDatabaseKey::from_first_time_setup_generated_key(database_key);

    FirstTimeSetupDatabaseKeyBinding {
        generation_bound_database_key,
        installation_identifier,
        database_key_generation_identifier,
    }
}

#[cfg(windows)]
pub(crate) fn protect_first_time_setup_database_key_binding(
    binding: FirstTimeSetupDatabaseKeyBinding,
) -> Result<ProtectedFirstTimeSetupDatabaseKeyBinding, FirstTimeSetupDatabaseKeyProtectionError> {
    protect_first_time_setup_database_key_binding_using(binding, super::protect_database_key)
}

fn protect_first_time_setup_database_key_binding_using(
    binding: FirstTimeSetupDatabaseKeyBinding,
    protect: impl FnOnce(
        &DatabaseKey,
        DatabaseKeyGenerationIdentifier,
    ) -> Result<EncodedProtectedWrapper, ProtectionStageError>,
) -> Result<ProtectedFirstTimeSetupDatabaseKeyBinding, FirstTimeSetupDatabaseKeyProtectionError> {
    let FirstTimeSetupDatabaseKeyBinding {
        generation_bound_database_key,
        installation_identifier,
        database_key_generation_identifier,
    } = binding;
    let protected_database_key_wrapper = generation_bound_database_key
        .expose_key(|database_key| protect(database_key, database_key_generation_identifier))
        .map_err(|_| FirstTimeSetupDatabaseKeyProtectionError::ProtectionUnavailable)?;

    Ok(ProtectedFirstTimeSetupDatabaseKeyBinding {
        generation_bound_database_key,
        installation_identifier,
        database_key_generation_identifier,
        protected_database_key_wrapper,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        mem::{needs_drop, size_of},
    };

    #[cfg(windows)]
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::{
        database_key_generation::generate_database_key_material,
        installation_identifier_generation::generate_installation_identifier,
        installation_state::{
            InstallationEvidence, SetupAuthorizationState, authorize_first_time_setup,
        },
    };

    #[cfg(windows)]
    use crate::{
        database_key_active_wrapper_loader::LoadedActiveDatabaseKeyWrapper,
        database_metadata_contract::DatabaseCreationTimestamp,
        installation_evidence_protection::recover_database_key_candidate_from_loaded_wrapper,
        parish_identifier_generation::generate_parish_identifier,
        production_database_connection_handoff::{
            NewProductionDatabaseConnectionCloseOutcome, create_new_keyed_production_database,
            initialize_new_production_database, validate_initialized_new_production_database,
            validate_initialized_new_production_database_integrity,
        },
        setup_publication_identifier_generation::generate_setup_publication_identifier,
        storage_foundation::{ProductionDatabasePath, production_database_path},
    };

    #[cfg(windows)]
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[cfg(windows)]
    struct TestRoot(PathBuf);

    #[cfg(windows)]
    impl TestRoot {
        fn create() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock should be after the Unix epoch")
                .as_nanos();
            let temporary_directory = std::env::temp_dir();
            let path = temporary_directory.join(format!(
                "church-app-protected-setup-key-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            assert!(path.starts_with(&temporary_directory));
            assert!(!path.exists());
            fs::create_dir(&path).expect("isolated test root creation should succeed");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn database_path(&self) -> ProductionDatabasePath {
            production_database_path(self.0.clone())
        }

        fn assert_exact_cleanup(self) {
            fs::remove_dir_all(&self.0).expect("exact test root cleanup should succeed");
            assert!(!self.0.exists());
        }
    }

    #[cfg(windows)]
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn authorization() -> FirstTimeSetupAuthorization {
        match authorize_first_time_setup(InstallationEvidence::NeverInitialized)
            .expect("never-initialized evidence should authorize first-time setup")
        {
            SetupAuthorizationState::Authorized(authorization) => authorization,
            SetupAuthorizationState::NotAuthorized => {
                panic!("successful setup authorization must contain its typed proof")
            }
        }
    }

    fn binding(authorization: &FirstTimeSetupAuthorization) -> FirstTimeSetupDatabaseKeyBinding {
        bind_generated_database_key_for_first_time_setup(
            authorization,
            generate_database_key_material()
                .expect("the supported test host should provide database-key randomness"),
            generate_installation_identifier().expect(
                "the supported test host should provide installation-identifier randomness",
            ),
        )
    }

    #[test]
    fn generated_values_move_into_the_exact_three_part_handoff_and_authorization_remains_borrowable()
     {
        let authorization = authorization();
        let material = generate_database_key_material()
            .expect("the supported test host should provide database-key randomness");
        let installation = generate_installation_identifier()
            .expect("the supported test host should provide installation-identifier randomness");

        let binding = bind_generated_database_key_for_first_time_setup(
            &authorization,
            material,
            installation,
        );

        fn require_authorization_borrow(_: &FirstTimeSetupAuthorization) {}
        require_authorization_borrow(&authorization);

        let (bound_key, installation_identifier, generation_identifier) = binding.into_parts();
        fn require_exact_parts(
            _: GenerationBoundDatabaseKey,
            _: InstallationIdentifier,
            _: DatabaseKeyGenerationIdentifier,
        ) {
        }
        bound_key.expose_key(|key| {
            key.expose_bytes(|bytes| assert_eq!(bytes.len(), 32));
        });
        require_exact_parts(bound_key, installation_identifier, generation_identifier);
    }

    #[test]
    fn handoff_surface_is_exact_private_owned_and_capability_narrow() {
        const SOURCE: &str = include_str!("first_time_setup_database_key_binding.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let declaration = production
            .split_once("pub(crate) struct FirstTimeSetupDatabaseKeyBinding {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let fields: Vec<_> = declaration
            .lines()
            .filter(|line| line.contains(':'))
            .collect();

        assert_eq!(
            fields,
            [
                "    generation_bound_database_key: GenerationBoundDatabaseKey,",
                "    installation_identifier: InstallationIdentifier,",
                "    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,",
            ]
        );
        assert!(!declaration.contains("pub"));
        assert!(needs_drop::<FirstTimeSetupDatabaseKeyBinding>());
        assert_eq!(
            size_of::<FirstTimeSetupDatabaseKeyBinding>(),
            size_of::<GenerationBoundDatabaseKey>()
                + size_of::<InstallationIdentifier>()
                + size_of::<DatabaseKeyGenerationIdentifier>()
        );
        let predecessor_surface = production
            .split_once("pub(crate) struct FirstTimeSetupDatabaseKeyBinding {")
            .unwrap()
            .1
            .split_once("pub(crate) struct ProtectedFirstTimeSetupDatabaseKeyBinding {")
            .unwrap()
            .0;

        for forbidden in [
            "#[derive(",
            "impl Clone",
            "impl Copy",
            "Serialize",
            "Deserialize",
            "impl Deref",
            "impl AsRef",
            "impl Index",
            "as_bytes",
            "into_bytes",
            "raw_bytes",
            "raw_key",
            "pub(crate) fn new",
            "pub fn",
        ] {
            assert!(
                !predecessor_surface.contains(forbidden),
                "handoff unexpectedly exposes forbidden surface: {forbidden}"
            );
        }
    }

    #[test]
    fn debug_is_exactly_redacted() {
        let authorization = authorization();
        let binding = bind_generated_database_key_for_first_time_setup(
            &authorization,
            generate_database_key_material().unwrap(),
            generate_installation_identifier().unwrap(),
        );
        let debug = format!("{binding:?}");

        assert_eq!(debug, "FirstTimeSetupDatabaseKeyBinding([REDACTED])");
        for excluded in [
            "DatabaseKey(",
            "InstallationIdentifier(",
            "DatabaseKeyGenerationIdentifier(",
            "path",
            "setup internals",
        ] {
            assert!(!debug.contains(excluded));
        }
    }

    #[test]
    fn production_binding_is_infallible_borrowed_and_typed_movement_only() {
        const SOURCE: &str = include_str!("first_time_setup_database_key_binding.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let signature = "pub(crate) fn bind_generated_database_key_for_first_time_setup(\n    authorization: &FirstTimeSetupAuthorization,\n    material: GeneratedDatabaseKeyMaterial,\n    installation: GeneratedInstallationIdentifier,\n) -> FirstTimeSetupDatabaseKeyBinding";
        let transition = production.split_once(signature).unwrap().1;

        assert_eq!(transition.matches("material.into_parts()").count(), 1);
        assert_eq!(
            transition
                .matches("installation.into_installation_identifier()")
                .count(),
            1
        );
        assert_eq!(
            transition
                .matches(
                    "GenerationBoundDatabaseKey::from_first_time_setup_generated_key(database_key)"
                )
                .count(),
            1
        );
        assert_eq!(transition.matches("let _ = authorization;").count(), 1);
        assert!(!signature.contains("Result<"));
        assert!(!signature.contains("Option<"));

        for forbidden in [
            "expose_bytes",
            "DatabaseKey::from_bytes",
            "[u8; 32]",
            "serialize",
            "hex",
            "base64",
            "DPAPI",
            "TrustedCurrentInstallationEvidenceAssessment",
            "load_trusted",
            "active_evidence",
            "SetupPublicationIdentifier",
            "InstallationGeneration",
            "RecoveryOrReplacementGeneration",
            "ParishIdentifier",
            "AuthenticationKeyGenerationIdentifier",
            "Timestamp",
        ] {
            assert!(
                !transition.contains(forbidden),
                "production transition contains excluded term: {forbidden}"
            );
        }
        for forbidden in [
            ["std", "::fs"].concat(),
            ["std", "::path"].concat(),
            ["std", "::env"].concat(),
            ["rusq", "lite"].concat(),
            ["PR", "AGMA"].concat(),
            ["tauri", "::"].concat(),
            ["serde", "::"].concat(),
            ["unsafe", " {"].concat(),
        ] {
            assert!(!production.contains(&forbidden));
        }
    }

    #[test]
    fn setup_seam_is_private_setup_named_and_startup_binding_remains_independent() {
        const SETUP_SOURCE: &str = include_str!("first_time_setup_database_key_binding.rs");
        const BOUND_SOURCE: &str = include_str!("generation_bound_database_key.rs");
        let setup_production = SETUP_SOURCE.split("#[cfg(test)]").next().unwrap();
        let bound_production = BOUND_SOURCE.split("#[cfg(test)]").next().unwrap();
        let seam = "pub(super) fn from_first_time_setup_generated_key(key: DatabaseKey) -> Self";
        let startup_signature = "pub(crate) fn bind_database_key_candidate_to_trusted_installation_evidence(\n    candidate: DecodedDatabaseKeyCandidate,\n    assessment: &TrustedCurrentInstallationEvidenceAssessment,\n) -> Result<GenerationBoundDatabaseKey, DatabaseKeyGenerationBindingError>";
        let startup = bound_production.split_once(startup_signature).unwrap().1;

        assert_eq!(bound_production.matches(seam).count(), 1);
        assert!(!bound_production.contains("pub(crate) fn from_first_time_setup_generated_key"));
        assert_eq!(
            setup_production
                .matches("GenerationBoundDatabaseKey::from_first_time_setup_generated_key(")
                .count(),
            1
        );
        assert!(!startup.contains("bind_generated_database_key_for_first_time_setup"));
        assert!(!startup.contains("from_first_time_setup_generated_key"));
        assert!(startup.contains("assessment.evidence().database_key_generation_identifier()"));
        assert!(
            startup.contains("candidate_generation_identifier == trusted_generation_identifier")
        );

        for generic in [
            "pub(crate) fn new(",
            "pub(super) fn new(",
            "pub(crate) fn from_parts(",
            "pub(super) fn from_parts(",
            "pub(crate) fn from_key(",
            "pub(super) fn from_key(",
        ] {
            assert!(!bound_production.contains(generic));
        }
    }

    #[test]
    fn protection_failure_is_single_attempt_coarse_and_ownerless() {
        let authorization = authorization();
        let calls = Cell::new(0);

        let error =
            protect_first_time_setup_database_key_binding_using(binding(&authorization), |_, _| {
                calls.set(calls.get() + 1);
                Err(ProtectionStageError::ProtectionUnavailable)
            })
            .expect_err("injected protection failure must not produce a protected handoff");

        assert_eq!(calls.get(), 1);
        assert_eq!(
            error,
            FirstTimeSetupDatabaseKeyProtectionError::ProtectionUnavailable
        );
        assert_eq!(format!("{error:?}"), "ProtectionUnavailable");
    }

    #[test]
    fn protected_handoff_surface_is_exact_owned_redacted_and_capability_narrow() {
        const SOURCE: &str = include_str!("first_time_setup_database_key_binding.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let declaration = production
            .split_once("pub(crate) struct ProtectedFirstTimeSetupDatabaseKeyBinding {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let fields: Vec<_> = declaration
            .lines()
            .filter(|line| line.contains(':'))
            .collect();

        assert_eq!(
            fields,
            [
                "    generation_bound_database_key: GenerationBoundDatabaseKey,",
                "    installation_identifier: InstallationIdentifier,",
                "    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,",
                "    protected_database_key_wrapper: EncodedProtectedWrapper,",
            ]
        );
        assert!(!declaration.contains("pub"));
        assert!(needs_drop::<ProtectedFirstTimeSetupDatabaseKeyBinding>());

        let protected_surface = production
            .split_once("pub(crate) struct ProtectedFirstTimeSetupDatabaseKeyBinding {")
            .unwrap()
            .1
            .split_once("#[derive(Clone, Copy, Eq, PartialEq)]")
            .unwrap()
            .0;
        for forbidden in [
            "#[derive(",
            "impl Clone",
            "impl Copy",
            "Serialize",
            "Deserialize",
            "impl Deref",
            "impl AsRef",
            "raw_key",
            "expose_key",
            "as_bytes",
            "into_bytes",
            "set_",
            "path:",
            "PathBuf",
            "File",
        ] {
            assert!(
                !protected_surface.contains(forbidden),
                "protected handoff unexpectedly exposes forbidden surface: {forbidden}"
            );
        }

        let signature = "pub(crate) fn into_parts(\n        self,\n    ) -> (\n        GenerationBoundDatabaseKey,\n        InstallationIdentifier,\n        DatabaseKeyGenerationIdentifier,\n        EncodedProtectedWrapper,\n    )";
        let decomposition = protected_surface.split_once(signature).unwrap().1;
        for field in [
            "self.generation_bound_database_key",
            "self.installation_identifier",
            "self.database_key_generation_identifier",
            "self.protected_database_key_wrapper",
        ] {
            assert_eq!(
                decomposition.matches(field).count(),
                1,
                "consuming decomposition must move {field} exactly once"
            );
        }
        for forbidden in [".clone()", "from_bytes", "protect_database_key"] {
            assert!(!decomposition.contains(forbidden));
        }

        assert!(production.contains(
            "formatter.write_str(\"ProtectedFirstTimeSetupDatabaseKeyBinding([REDACTED])\")"
        ));
    }

    #[test]
    fn production_transition_has_exact_input_and_one_canonical_protection_call() {
        const SOURCE: &str = include_str!("first_time_setup_database_key_binding.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let signature = "pub(crate) fn protect_first_time_setup_database_key_binding(\n    binding: FirstTimeSetupDatabaseKeyBinding,\n) -> Result<ProtectedFirstTimeSetupDatabaseKeyBinding, FirstTimeSetupDatabaseKeyProtectionError>";
        let transition = production.split_once(signature).unwrap().1;

        assert_eq!(production.matches("super::protect_database_key").count(), 1);
        assert!(transition.starts_with(" {\n    protect_first_time_setup_database_key_binding_using(binding, super::protect_database_key)\n}"));
        assert_eq!(
            production
                .matches(".expose_key(|database_key| protect(")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches("FirstTimeSetupDatabaseKeyProtectionError::ProtectionUnavailable")
                .count(),
            1
        );
        for forbidden in [
            "GeneratedDatabaseKeyMaterial",
            "GeneratedInstallationIdentifier",
            "ProductionDatabasePath",
            "SetupPublicationIdentifier",
            "FirstTimeSetupAuthorization",
        ] {
            assert!(!signature.contains(forbidden));
        }
    }

    #[cfg(windows)]
    #[test]
    fn real_windows_protection_preserves_exact_key_and_identifiers_before_create_new() {
        let authorization = authorization();
        let predecessor = binding(&authorization);
        let expected_installation_identifier = predecessor.installation_identifier;
        let expected_generation_identifier = predecessor.database_key_generation_identifier;

        let protected = protect_first_time_setup_database_key_binding(predecessor)
            .expect("CurrentUser DPAPI protection should succeed");
        assert_eq!(
            format!("{protected:?}"),
            "ProtectedFirstTimeSetupDatabaseKeyBinding([REDACTED])"
        );
        fn require_exact_protected_parts(
            parts: (
                GenerationBoundDatabaseKey,
                InstallationIdentifier,
                DatabaseKeyGenerationIdentifier,
                EncodedProtectedWrapper,
            ),
        ) -> (
            GenerationBoundDatabaseKey,
            InstallationIdentifier,
            DatabaseKeyGenerationIdentifier,
            EncodedProtectedWrapper,
        ) {
            parts
        }
        let (
            generation_bound_database_key,
            installation_identifier,
            database_key_generation_identifier,
            protected_database_key_wrapper,
        ) = require_exact_protected_parts(protected.into_parts());
        let loaded_wrapper = LoadedActiveDatabaseKeyWrapper::from_synthetic_wrapper_bytes(
            protected_database_key_wrapper.as_bytes().to_vec(),
        );
        let recovered = recover_database_key_candidate_from_loaded_wrapper(&loaded_wrapper)
            .expect("the canonical database-key wrapper should recover");
        let (recovered_key, recovered_generation_identifier) = recovered.into_parts();

        assert_eq!(installation_identifier, expected_installation_identifier);
        assert_eq!(
            database_key_generation_identifier,
            expected_generation_identifier
        );
        assert_eq!(
            recovered_generation_identifier,
            database_key_generation_identifier
        );
        generation_bound_database_key.expose_key(|retained_key| {
            retained_key.expose_bytes(|retained_bytes| {
                recovered_key.expose_bytes(|recovered_bytes| {
                    assert_eq!(recovered_bytes, retained_bytes);
                });
            });
        });

        let root = TestRoot::create();
        let created = create_new_keyed_production_database(
            authorization,
            root.database_path(),
            generation_bound_database_key,
        )
        .expect("the retained generation-bound key should create the database");
        let initialized = initialize_new_production_database(
            created,
            generate_parish_identifier()
                .expect("parish identifier randomness should be available")
                .into_parish_identifier(),
            installation_identifier,
            database_key_generation_identifier,
            generate_setup_publication_identifier()
                .expect("setup-publication identifier randomness should be available")
                .into_setup_publication_identifier(),
            DatabaseCreationTimestamp::from_unix_milliseconds(1_798_000_000_123),
        )
        .expect("real initialization should succeed");
        let validated = validate_initialized_new_production_database(initialized)
            .expect("immediate metadata read-back should match the retained generation");
        let integrity = validate_initialized_new_production_database_integrity(validated)
            .expect("fixed setup integrity validation should succeed");

        assert!(matches!(
            integrity.close(),
            NewProductionDatabaseConnectionCloseOutcome::Closed
        ));
        assert!(root.path().join("parish-data.db").is_file());
        drop(protected_database_key_wrapper);
        root.assert_exact_cleanup();
    }
}
