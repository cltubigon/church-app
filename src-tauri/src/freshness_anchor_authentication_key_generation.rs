//! Operating-system-backed generation for freshness-anchor authentication material.
//!
//! Generation produces only in-memory Rust-owned material. It does not protect,
//! persist, activate, replace, or assign operational authority to it.

// These crate-private boundaries intentionally have no production caller until
// a separately approved orchestration stage exists.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use zeroize::Zeroize;

use crate::{
    freshness_anchor_authenticated_envelope::AnchorAuthenticationKeyGenerationIdentifier,
    freshness_anchor_authentication_key::AnchorAuthenticationKey,
};

const AUTHENTICATION_KEY_LENGTH: usize = 32;
const GENERATION_IDENTIFIER_LENGTH: usize = 16;
const GENERATION_IDENTIFIER_FILL_ATTEMPTS: usize = 3;

pub(crate) struct GeneratedAnchorAuthenticationMaterial {
    authentication_key: AnchorAuthenticationKey,
    generation_identifier: AnchorAuthenticationKeyGenerationIdentifier,
}

impl GeneratedAnchorAuthenticationMaterial {
    pub(crate) fn into_parts(
        self,
    ) -> (
        AnchorAuthenticationKey,
        AnchorAuthenticationKeyGenerationIdentifier,
    ) {
        (self.authentication_key, self.generation_identifier)
    }
}

impl fmt::Debug for GeneratedAnchorAuthenticationMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GeneratedAnchorAuthenticationMaterial([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AnchorAuthenticationKeyGenerationError {
    RandomnessUnavailable,
    NonzeroGenerationIdentifierUnavailable,
}

impl fmt::Debug for AnchorAuthenticationKeyGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessUnavailable => formatter.write_str("RandomnessUnavailable"),
            Self::NonzeroGenerationIdentifierUnavailable => {
                formatter.write_str("NonzeroGenerationIdentifierUnavailable")
            }
        }
    }
}

pub(crate) fn generate_anchor_authentication_material()
-> Result<GeneratedAnchorAuthenticationMaterial, AnchorAuthenticationKeyGenerationError> {
    generate_anchor_authentication_material_with(|destination| {
        getrandom::fill(destination).map_err(|_| RandomFillError)
    })
}

#[derive(Clone, Copy)]
struct RandomFillError;

fn generate_anchor_authentication_material_with(
    mut fill_random_bytes: impl FnMut(&mut [u8]) -> Result<(), RandomFillError>,
) -> Result<GeneratedAnchorAuthenticationMaterial, AnchorAuthenticationKeyGenerationError> {
    let mut authentication_key_bytes = [0_u8; AUTHENTICATION_KEY_LENGTH];
    if fill_random_bytes(&mut authentication_key_bytes).is_err() {
        authentication_key_bytes.zeroize();
        return Err(AnchorAuthenticationKeyGenerationError::RandomnessUnavailable);
    }

    // This constructor copies into the key owner and clears the successful
    // temporary. The owner's Drop path handles every later failure return.
    let authentication_key =
        AnchorAuthenticationKey::from_bytes_with_cleared_source(&mut authentication_key_bytes);

    for _ in 0..GENERATION_IDENTIFIER_FILL_ATTEMPTS {
        let mut generation_identifier_bytes = [0_u8; GENERATION_IDENTIFIER_LENGTH];
        fill_random_bytes(&mut generation_identifier_bytes)
            .map_err(|_| AnchorAuthenticationKeyGenerationError::RandomnessUnavailable)?;

        if let Ok(generation_identifier) =
            AnchorAuthenticationKeyGenerationIdentifier::from_bytes(generation_identifier_bytes)
        {
            return Ok(GeneratedAnchorAuthenticationMaterial {
                authentication_key,
                generation_identifier,
            });
        }
    }

    Err(AnchorAuthenticationKeyGenerationError::NonzeroGenerationIdentifierUnavailable)
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, mem::size_of, rc::Rc};

    use super::*;

    const SYNTHETIC_KEY_BYTES: [u8; 32] = [0x5a; 32];
    const SYNTHETIC_GENERATION_IDENTIFIER_BYTES: [u8; 16] = [0xa5; 16];

    #[test]
    fn successful_generation_uses_one_key_fill_then_one_identifier_fill() {
        let observed_lengths = Rc::new(std::cell::RefCell::new(Vec::new()));
        let lengths_for_fill = Rc::clone(&observed_lengths);
        let mut fill_index = 0;

        let material = generate_anchor_authentication_material_with(|destination| {
            lengths_for_fill.borrow_mut().push(destination.len());
            match fill_index {
                0 => destination.copy_from_slice(&SYNTHETIC_KEY_BYTES),
                1 => destination.copy_from_slice(&SYNTHETIC_GENERATION_IDENTIFIER_BYTES),
                _ => panic!("successful generation must use exactly two fills"),
            }
            fill_index += 1;
            Ok(())
        })
        .expect("synthetic independent fills should generate material");

        let (key, identifier) = material.into_parts();
        let mut identifier_bytes = [0_u8; 16];
        identifier.write_bytes_into(&mut identifier_bytes);

        assert_eq!(&*observed_lengths.borrow(), &[32, 16]);
        key.expose_bytes(|bytes| assert_eq!(bytes, &SYNTHETIC_KEY_BYTES));
        assert_eq!(identifier_bytes, SYNTHETIC_GENERATION_IDENTIFIER_BYTES);
    }

    #[test]
    fn all_zero_key_output_is_accepted() {
        let material = generate_anchor_authentication_material_with(|destination| {
            if destination.len() == AUTHENTICATION_KEY_LENGTH {
                destination.fill(0);
            } else {
                destination.copy_from_slice(&SYNTHETIC_GENERATION_IDENTIFIER_BYTES);
            }
            Ok(())
        })
        .expect("the key owner accepts every 32-byte pattern");
        let (key, _) = material.into_parts();

        key.expose_bytes(|bytes| assert_eq!(bytes, &[0; 32]));
    }

    #[test]
    fn one_zero_identifier_causes_one_retry() {
        let mut fill_index = 0;
        let material = generate_anchor_authentication_material_with(|destination| {
            match fill_index {
                0 => destination.fill(0x11),
                1 => destination.fill(0),
                2 => destination.fill(0x22),
                _ => panic!("generation should stop after the successful retry"),
            }
            fill_index += 1;
            Ok(())
        })
        .expect("the second identifier fill should succeed");
        let (_, identifier) = material.into_parts();
        let mut identifier_bytes = [0_u8; 16];
        identifier.write_bytes_into(&mut identifier_bytes);

        assert_eq!(fill_index, 3);
        assert_eq!(identifier_bytes, [0x22; 16]);
    }

    #[test]
    fn two_zero_identifiers_cause_two_retries() {
        let mut fill_index = 0;
        let material = generate_anchor_authentication_material_with(|destination| {
            match fill_index {
                0 => destination.fill(0x31),
                1 | 2 => destination.fill(0),
                3 => destination.fill(0x42),
                _ => panic!("generation must stop after the third identifier fill"),
            }
            fill_index += 1;
            Ok(())
        })
        .expect("the third identifier fill should succeed");
        let (_, identifier) = material.into_parts();
        let mut identifier_bytes = [0_u8; 16];
        identifier.write_bytes_into(&mut identifier_bytes);

        assert_eq!(fill_index, 4);
        assert_eq!(identifier_bytes, [0x42; 16]);
    }

    #[test]
    fn three_zero_identifiers_stop_without_a_fourth_attempt() {
        let fill_count = Cell::new(0);
        let result = generate_anchor_authentication_material_with(|destination| {
            let current = fill_count.get();
            fill_count.set(current + 1);
            match current {
                0 => destination.fill(0x33),
                1..=3 => destination.fill(0),
                _ => panic!("a fourth identifier fill must not occur"),
            }
            Ok(())
        });

        assert!(matches!(
            result,
            Err(AnchorAuthenticationKeyGenerationError::NonzeroGenerationIdentifierUnavailable)
        ));
        assert_eq!(fill_count.get(), 1 + GENERATION_IDENTIFIER_FILL_ATTEMPTS);
    }

    #[test]
    fn partially_written_key_provider_failure_is_immediate_and_payload_free() {
        let fill_count = Cell::new(0);
        let result = generate_anchor_authentication_material_with(|destination| {
            fill_count.set(fill_count.get() + 1);
            destination[..8].fill(0x7c);
            Err(RandomFillError)
        });

        assert!(matches!(
            result,
            Err(AnchorAuthenticationKeyGenerationError::RandomnessUnavailable)
        ));
        assert_eq!(fill_count.get(), 1);

        let production = include_str!("freshness_anchor_authentication_key_generation.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(production.contains("authentication_key_bytes.zeroize();"));
    }

    #[test]
    fn identifier_provider_failure_is_immediate_without_retry() {
        let fill_count = Cell::new(0);
        let result = generate_anchor_authentication_material_with(|destination| {
            let current = fill_count.get();
            fill_count.set(current + 1);
            if current == 0 {
                destination.fill(0x44);
                Ok(())
            } else {
                Err(RandomFillError)
            }
        });

        assert!(matches!(
            result,
            Err(AnchorAuthenticationKeyGenerationError::RandomnessUnavailable)
        ));
        assert_eq!(fill_count.get(), 2);
    }

    #[test]
    fn provider_failure_on_later_identifier_attempt_returns_immediately() {
        for failed_identifier_attempt in [2, 3] {
            let fill_count = Cell::new(0);
            let result = generate_anchor_authentication_material_with(|destination| {
                let current = fill_count.get();
                fill_count.set(current + 1);
                if current == 0 {
                    destination.fill(0x61);
                    return Ok(());
                }
                if current == failed_identifier_attempt {
                    return Err(RandomFillError);
                }
                destination.fill(0);
                Ok(())
            });

            assert!(matches!(
                result,
                Err(AnchorAuthenticationKeyGenerationError::RandomnessUnavailable)
            ));
            assert_eq!(fill_count.get(), failed_identifier_attempt + 1);
        }
    }

    #[test]
    fn key_ownership_uses_its_drop_zeroization_path_after_identifier_failure() {
        let result = generate_anchor_authentication_material_with(|destination| {
            destination.fill(if destination.len() == AUTHENTICATION_KEY_LENGTH {
                0x71
            } else {
                0
            });
            Ok(())
        });

        assert!(matches!(
            result,
            Err(AnchorAuthenticationKeyGenerationError::NonzeroGenerationIdentifierUnavailable)
        ));
        assert!(std::mem::needs_drop::<AnchorAuthenticationKey>());

        let production = include_str!("freshness_anchor_authentication_key_generation.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let ownership_transfer = production
            .find("let authentication_key =")
            .expect("key ownership transfer should remain explicit");
        let identifier_attempts = production
            .find("for _ in 0..GENERATION_IDENTIFIER_FILL_ATTEMPTS")
            .expect("identifier attempts should follow key ownership transfer");
        assert!(ownership_transfer < identifier_attempts);
    }

    #[test]
    fn material_and_errors_have_exact_redacted_payload_free_debug_output() {
        let material = generate_anchor_authentication_material_with(|destination| {
            destination.fill(0x55);
            Ok(())
        })
        .unwrap();

        assert_eq!(
            format!("{material:?}"),
            "GeneratedAnchorAuthenticationMaterial([REDACTED])"
        );
        assert_eq!(
            format!(
                "{:?}",
                AnchorAuthenticationKeyGenerationError::RandomnessUnavailable
            ),
            "RandomnessUnavailable"
        );
        assert_eq!(
            format!(
                "{:?}",
                AnchorAuthenticationKeyGenerationError::NonzeroGenerationIdentifierUnavailable
            ),
            "NonzeroGenerationIdentifierUnavailable"
        );
    }

    #[test]
    fn material_surface_is_owned_redacted_and_generation_only() {
        assert_eq!(
            size_of::<GeneratedAnchorAuthenticationMaterial>(),
            AUTHENTICATION_KEY_LENGTH + GENERATION_IDENTIFIER_LENGTH
        );

        const SOURCE: &str = include_str!("freshness_anchor_authentication_key_generation.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        let material_declaration = production
            .split("#[derive(Clone, Copy, Eq, PartialEq)]")
            .next()
            .unwrap();
        for forbidden in [
            "impl Clone for GeneratedAnchorAuthenticationMaterial",
            "impl Copy for GeneratedAnchorAuthenticationMaterial",
            "Serialize",
            "Deserialize",
            "impl Deref",
            "impl AsRef",
            "impl Index",
            "as_bytes",
            "into_bytes",
            "pub(crate) fn bytes",
            "std::fs",
            "std::env",
            "std::net",
            "SystemTime",
            "Instant::now",
            "process::id",
            "rusqlite",
            "tauri::command",
            "windows",
            "dpapi",
            "hmac",
            "protect(",
            "unwrap_or",
        ] {
            assert!(
                !production.contains(forbidden),
                "unexpected generation capability: {forbidden}"
            );
        }
        assert!(!material_declaration.contains("#[derive("));
        assert!(production.contains("getrandom::fill(destination)"));
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
        let material = generate_anchor_authentication_material_with(move |destination| {
            let _ = &observer;
            destination.fill(0x66);
            Ok(())
        })
        .unwrap();

        assert!(provider_was_dropped.get());
        assert_eq!(
            format!("{material:?}"),
            "GeneratedAnchorAuthenticationMaterial([REDACTED])"
        );
    }

    #[test]
    fn anchor_operating_system_randomness_generation_smoke_test() {
        let material = generate_anchor_authentication_material()
            .expect("the observed supported host should provide OS randomness");

        assert_eq!(
            format!("{material:?}"),
            "GeneratedAnchorAuthenticationMaterial([REDACTED])"
        );
        let (_, identifier) = material.into_parts();
        assert_eq!(
            format!("{identifier:?}"),
            "AnchorAuthenticationKeyGenerationIdentifier([REDACTED])"
        );
    }
}
