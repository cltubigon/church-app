//! Operating-system-backed generation for database-key material.
//!
//! Generation produces only in-memory Rust-owned material. It does not protect,
//! persist, publish, activate, open or create a database, perform setup, or
//! assign operational authority to the result.

// These crate-private boundaries intentionally have no production caller until
// a separately approved setup stage exists.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use zeroize::Zeroize;

use crate::{
    database_key::DatabaseKey, installation_evidence_contract::DatabaseKeyGenerationIdentifier,
};

const DATABASE_KEY_LENGTH: usize = 32;
const GENERATION_IDENTIFIER_LENGTH: usize = 16;
const GENERATION_IDENTIFIER_FILL_ATTEMPTS: usize = 3;

pub(crate) struct GeneratedDatabaseKeyMaterial {
    database_key: DatabaseKey,
    generation_identifier: DatabaseKeyGenerationIdentifier,
}

impl GeneratedDatabaseKeyMaterial {
    pub(crate) fn into_parts(self) -> (DatabaseKey, DatabaseKeyGenerationIdentifier) {
        (self.database_key, self.generation_identifier)
    }
}

impl fmt::Debug for GeneratedDatabaseKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GeneratedDatabaseKeyMaterial([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum DatabaseKeyGenerationError {
    RandomnessUnavailable,
    NonzeroGenerationIdentifierUnavailable,
}

impl fmt::Debug for DatabaseKeyGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RandomnessUnavailable => "RandomnessUnavailable",
            Self::NonzeroGenerationIdentifierUnavailable => {
                "NonzeroGenerationIdentifierUnavailable"
            }
        })
    }
}

pub(crate) fn generate_database_key_material()
-> Result<GeneratedDatabaseKeyMaterial, DatabaseKeyGenerationError> {
    generate_database_key_material_with(|destination| {
        getrandom::fill(destination).map_err(|_| RandomFillError)
    })
}

#[derive(Clone, Copy)]
struct RandomFillError;

fn generate_database_key_material_with(
    mut fill_random_bytes: impl FnMut(&mut [u8]) -> Result<(), RandomFillError>,
) -> Result<GeneratedDatabaseKeyMaterial, DatabaseKeyGenerationError> {
    let mut database_key_bytes = [0_u8; DATABASE_KEY_LENGTH];
    if fill_random_bytes(&mut database_key_bytes).is_err() {
        database_key_bytes.zeroize();
        return Err(DatabaseKeyGenerationError::RandomnessUnavailable);
    }

    // Move the successful fill directly into the existing secret owner. Its
    // Drop path handles every later failure return. Compiler-created
    // temporaries and pre-move stack remnants remain outside that best-effort
    // guarantee.
    let database_key = DatabaseKey::from_bytes(database_key_bytes);

    for _ in 0..GENERATION_IDENTIFIER_FILL_ATTEMPTS {
        let mut generation_identifier_bytes = [0_u8; GENERATION_IDENTIFIER_LENGTH];
        fill_random_bytes(&mut generation_identifier_bytes)
            .map_err(|_| DatabaseKeyGenerationError::RandomnessUnavailable)?;

        if let Ok(generation_identifier) =
            DatabaseKeyGenerationIdentifier::from_bytes(generation_identifier_bytes)
        {
            return Ok(GeneratedDatabaseKeyMaterial {
                database_key,
                generation_identifier,
            });
        }
    }

    Err(DatabaseKeyGenerationError::NonzeroGenerationIdentifierUnavailable)
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, mem::size_of, rc::Rc};

    use super::*;

    const SYNTHETIC_KEY_BYTES: [u8; 32] = [0x5a; 32];
    const SYNTHETIC_GENERATION_IDENTIFIER_BYTES: [u8; 16] = [0xa5; 16];

    #[test]
    fn successful_generation_uses_one_exact_key_fill_then_one_exact_identifier_fill() {
        let observed_lengths = Rc::new(std::cell::RefCell::new(Vec::new()));
        let lengths_for_fill = Rc::clone(&observed_lengths);
        let mut fill_index = 0;

        let material = generate_database_key_material_with(|destination| {
            lengths_for_fill.borrow_mut().push(destination.len());
            match fill_index {
                0 => destination.copy_from_slice(&SYNTHETIC_KEY_BYTES),
                1 => destination.copy_from_slice(&SYNTHETIC_GENERATION_IDENTIFIER_BYTES),
                _ => panic!("successful generation must use exactly two fills"),
            }
            fill_index += 1;
            Ok(())
        })
        .expect("independent synthetic fills should generate database-key material");

        let expected_identifier =
            DatabaseKeyGenerationIdentifier::from_bytes(SYNTHETIC_GENERATION_IDENTIFIER_BYTES)
                .expect("synthetic identifier must pass the canonical nonzero boundary");
        let (key, identifier) = material.into_parts();

        assert_eq!(&*observed_lengths.borrow(), &[32, 16]);
        key.expose_bytes(|bytes| assert_eq!(bytes, &SYNTHETIC_KEY_BYTES));
        assert_eq!(identifier, expected_identifier);
    }

    #[test]
    fn key_randomness_failure_is_immediate_and_identifier_generation_does_not_start() {
        let fill_count = Cell::new(0);
        let result = generate_database_key_material_with(|destination| {
            fill_count.set(fill_count.get() + 1);
            assert_eq!(destination.len(), DATABASE_KEY_LENGTH);
            destination[..8].fill(0x7c);
            Err(RandomFillError)
        });

        assert!(matches!(
            result,
            Err(DatabaseKeyGenerationError::RandomnessUnavailable)
        ));
        assert_eq!(fill_count.get(), 1);

        let production = include_str!("database_key_generation.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(production.contains("database_key_bytes.zeroize();"));
    }

    #[test]
    fn identifier_randomness_failure_after_key_success_fails_closed_without_retry() {
        let fill_count = Cell::new(0);
        let result = generate_database_key_material_with(|destination| {
            let current = fill_count.get();
            fill_count.set(current + 1);
            if current == 0 {
                assert_eq!(destination.len(), DATABASE_KEY_LENGTH);
                destination.copy_from_slice(&SYNTHETIC_KEY_BYTES);
                Ok(())
            } else {
                assert_eq!(destination.len(), GENERATION_IDENTIFIER_LENGTH);
                Err(RandomFillError)
            }
        });

        assert!(matches!(
            result,
            Err(DatabaseKeyGenerationError::RandomnessUnavailable)
        ));
        assert_eq!(fill_count.get(), 2);
    }

    #[test]
    fn first_zero_identifier_retries_only_identifier_and_preserves_the_single_key_fill() {
        let observed_lengths = Rc::new(std::cell::RefCell::new(Vec::new()));
        let lengths_for_fill = Rc::clone(&observed_lengths);
        let mut fill_index = 0;
        let material = generate_database_key_material_with(|destination| {
            lengths_for_fill.borrow_mut().push(destination.len());
            match fill_index {
                0 => destination.copy_from_slice(&SYNTHETIC_KEY_BYTES),
                1 => destination.fill(0),
                2 => destination.copy_from_slice(&SYNTHETIC_GENERATION_IDENTIFIER_BYTES),
                _ => panic!("generation must stop after the valid identifier retry"),
            }
            fill_index += 1;
            Ok(())
        })
        .expect("the second identifier attempt should succeed");
        let (key, identifier) = material.into_parts();

        assert_eq!(&*observed_lengths.borrow(), &[32, 16, 16]);
        key.expose_bytes(|bytes| assert_eq!(bytes, &SYNTHETIC_KEY_BYTES));
        assert_eq!(
            identifier,
            DatabaseKeyGenerationIdentifier::from_bytes(SYNTHETIC_GENERATION_IDENTIFIER_BYTES)
                .unwrap()
        );
    }

    #[test]
    fn three_zero_identifiers_exhaust_the_bound_without_fallback_or_key_regeneration() {
        let observed_lengths = Rc::new(std::cell::RefCell::new(Vec::new()));
        let lengths_for_fill = Rc::clone(&observed_lengths);
        let result = generate_database_key_material_with(|destination| {
            lengths_for_fill.borrow_mut().push(destination.len());
            if destination.len() == DATABASE_KEY_LENGTH {
                destination.copy_from_slice(&SYNTHETIC_KEY_BYTES);
            } else {
                destination.fill(0);
            }
            Ok(())
        });

        assert!(matches!(
            result,
            Err(DatabaseKeyGenerationError::NonzeroGenerationIdentifierUnavailable)
        ));
        assert_eq!(&*observed_lengths.borrow(), &[32, 16, 16, 16]);
    }

    #[test]
    fn generated_value_and_errors_have_exact_coarse_redacted_debug_output() {
        let material = generate_database_key_material_with(|destination| {
            destination.fill(0x55);
            Ok(())
        })
        .unwrap();

        assert_eq!(
            format!("{material:?}"),
            "GeneratedDatabaseKeyMaterial([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", DatabaseKeyGenerationError::RandomnessUnavailable),
            "RandomnessUnavailable"
        );
        assert_eq!(
            format!(
                "{:?}",
                DatabaseKeyGenerationError::NonzeroGenerationIdentifierUnavailable
            ),
            "NonzeroGenerationIdentifierUnavailable"
        );
    }

    #[test]
    fn result_surface_is_owned_secret_bearing_and_exactly_two_part() {
        assert_eq!(
            size_of::<GeneratedDatabaseKeyMaterial>(),
            DATABASE_KEY_LENGTH + GENERATION_IDENTIFIER_LENGTH
        );
        assert!(std::mem::needs_drop::<GeneratedDatabaseKeyMaterial>());

        const SOURCE: &str = include_str!("database_key_generation.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let result_declaration = production
            .split("#[derive(Clone, Copy, Eq, PartialEq)]")
            .next()
            .unwrap();
        let result_fields = production
            .split_once("pub(crate) struct GeneratedDatabaseKeyMaterial {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0
            .lines()
            .filter(|line| line.contains(':'))
            .collect::<Vec<_>>();

        assert_eq!(
            result_fields,
            [
                "    database_key: DatabaseKey,",
                "    generation_identifier: DatabaseKeyGenerationIdentifier,",
            ]
        );
        assert!(!result_declaration.contains("#[derive("));
        for forbidden in [
            "impl Clone for GeneratedDatabaseKeyMaterial",
            "impl Copy for GeneratedDatabaseKeyMaterial",
            "Serialize",
            "Deserialize",
            "impl Deref",
            "impl AsRef",
            "impl Index",
            "as_bytes",
            "into_bytes",
            "pub(crate) fn bytes",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected result capability: {forbidden}"
            );
        }
    }

    #[test]
    fn production_boundary_uses_only_os_randomness_and_no_external_authority() {
        const SOURCE: &str = include_str!("database_key_generation.rs");
        const LIB_SOURCE: &str = include_str!("lib.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let excluded_fragments = [
            ["std", "::fs"].concat(),
            ["std", "::path"].concat(),
            ["std", "::env"].concat(),
            ["System", "Time"].concat(),
            ["Instant", "::now"].concat(),
            ["process", "::id"].concat(),
            ["thread", "::current"].concat(),
            ["rusqlite", "::"].concat(),
            ["PR", "AGMA"].concat(),
            ["SELECT", " "].concat(),
            ["dp", "api"].concat(),
            ["Crypt", "ProtectData"].concat(),
            ["tauri", "::command"].concat(),
            ["invoke", "_handler"].concat(),
            ["serde", "::"].concat(),
            ["hmac", "::"].concat(),
            ["rand", "::"].concat(),
            ["unwrap", "_or"].concat(),
            ["setup", "_authorization"].concat(),
            ["storage", "_foundation"].concat(),
            ["publication", "_state"].concat(),
            ["create", "_dir"].concat(),
            ["write", "_all"].concat(),
        ];

        assert_eq!(
            LIB_SOURCE.matches("mod database_key_generation;").count(),
            1
        );
        assert!(!LIB_SOURCE.contains("pub mod database_key_generation"));
        assert!(production.contains("getrandom::fill(destination)"));
        for fragment in excluded_fragments {
            assert!(
                !production.contains(&fragment),
                "production generation unexpectedly contains excluded source: {fragment}"
            );
        }
    }

    #[test]
    fn fill_provider_is_dropped_before_generated_material_is_returned() {
        let provider_was_dropped = Rc::new(Cell::new(false));
        struct ProviderDropObserver(Rc<Cell<bool>>);
        impl Drop for ProviderDropObserver {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let observer = ProviderDropObserver(Rc::clone(&provider_was_dropped));
        let material = generate_database_key_material_with(move |destination| {
            let _ = &observer;
            destination.fill(0x66);
            Ok(())
        })
        .unwrap();

        assert!(provider_was_dropped.get());
        assert_eq!(
            format!("{material:?}"),
            "GeneratedDatabaseKeyMaterial([REDACTED])"
        );
    }

    #[test]
    fn database_key_operating_system_randomness_generation_smoke_test() {
        let material = generate_database_key_material()
            .expect("the observed supported host should provide OS randomness");

        assert_eq!(
            format!("{material:?}"),
            "GeneratedDatabaseKeyMaterial([REDACTED])"
        );
        let (_, identifier) = material.into_parts();
        assert_eq!(
            format!("{identifier:?}"),
            "DatabaseKeyGenerationIdentifier([REDACTED])"
        );
    }
}
