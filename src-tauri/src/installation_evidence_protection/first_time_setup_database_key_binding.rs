//! Pure first-time-setup binding for freshly generated database-key material.
//!
//! This transition retains the exact generated installation and database-key
//! generation identities alongside the generated key. It grants no persistence,
//! publication, database, startup, setup-completion, or operational authority.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use crate::{
    database_key_generation::GeneratedDatabaseKeyMaterial,
    installation_evidence_contract::{DatabaseKeyGenerationIdentifier, InstallationIdentifier},
    installation_identifier_generation::GeneratedInstallationIdentifier,
    installation_state::FirstTimeSetupAuthorization,
};

use super::GenerationBoundDatabaseKey;

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

#[cfg(test)]
mod tests {
    use std::mem::{needs_drop, size_of};

    use super::*;
    use crate::{
        database_key_generation::generate_database_key_material,
        installation_identifier_generation::generate_installation_identifier,
        installation_state::{
            InstallationEvidence, SetupAuthorizationState, authorize_first_time_setup,
        },
    };

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
                !production.contains(forbidden),
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
}
