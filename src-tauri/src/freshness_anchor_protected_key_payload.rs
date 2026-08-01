//! Fixed plaintext payload for future protection of freshness-anchor key material.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use zeroize::Zeroize;

use crate::{
    freshness_anchor_authenticated_envelope::AnchorAuthenticationKeyGenerationIdentifier,
    freshness_anchor_authentication_key::AnchorAuthenticationKey,
};

pub(crate) const PROTECTED_KEY_PAYLOAD_LENGTH: usize = 49;
const VERSION: u8 = 1;
const IDENTIFIER_OFFSET: usize = 1;
const KEY_OFFSET: usize = 17;

pub(crate) struct EncodedProtectedAnchorKeyPayload {
    bytes: [u8; PROTECTED_KEY_PAYLOAD_LENGTH],
}

impl EncodedProtectedAnchorKeyPayload {
    pub(crate) fn encode(
        key: &AnchorAuthenticationKey,
        identifier: AnchorAuthenticationKeyGenerationIdentifier,
    ) -> Self {
        let mut bytes = [0_u8; PROTECTED_KEY_PAYLOAD_LENGTH];
        bytes[0] = VERSION;
        identifier.write_bytes_into(
            bytes[IDENTIFIER_OFFSET..KEY_OFFSET]
                .as_mut()
                .try_into()
                .expect("fixed identifier field has exact length"),
        );
        key.expose_bytes(|key_bytes| bytes[KEY_OFFSET..].copy_from_slice(key_bytes));
        Self { bytes }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; PROTECTED_KEY_PAYLOAD_LENGTH] {
        &self.bytes
    }

    fn zeroize_owned_bytes(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for EncodedProtectedAnchorKeyPayload {
    fn drop(&mut self) {
        self.zeroize_owned_bytes();
    }
}

impl fmt::Debug for EncodedProtectedAnchorKeyPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncodedProtectedAnchorKeyPayload([REDACTED])")
    }
}

pub(crate) struct DecodedProtectedAnchorKeyMaterial {
    authentication_key: AnchorAuthenticationKey,
    generation_identifier: AnchorAuthenticationKeyGenerationIdentifier,
}

impl DecodedProtectedAnchorKeyMaterial {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ProtectedAnchorKeyPayloadError> {
        if bytes.len() != PROTECTED_KEY_PAYLOAD_LENGTH {
            return Err(ProtectedAnchorKeyPayloadError::WrongTotalLength);
        }
        if bytes[0] != VERSION {
            return Err(ProtectedAnchorKeyPayloadError::UnsupportedVersion);
        }
        let generation_identifier = AnchorAuthenticationKeyGenerationIdentifier::from_bytes(
            bytes[IDENTIFIER_OFFSET..KEY_OFFSET]
                .try_into()
                .map_err(|_| ProtectedAnchorKeyPayloadError::InternalFieldBoundaryFailure)?,
        )
        .map_err(|_| ProtectedAnchorKeyPayloadError::InvalidGenerationIdentifier)?;
        let mut key_bytes = [0_u8; 32];
        key_bytes.copy_from_slice(&bytes[KEY_OFFSET..]);
        let authentication_key =
            AnchorAuthenticationKey::from_bytes_with_cleared_source(&mut key_bytes);
        Ok(Self {
            authentication_key,
            generation_identifier,
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        AnchorAuthenticationKey,
        AnchorAuthenticationKeyGenerationIdentifier,
    ) {
        (self.authentication_key, self.generation_identifier)
    }
}

impl fmt::Debug for DecodedProtectedAnchorKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecodedProtectedAnchorKeyMaterial([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProtectedAnchorKeyPayloadError {
    WrongTotalLength,
    UnsupportedVersion,
    InvalidGenerationIdentifier,
    InternalFieldBoundaryFailure,
}

impl fmt::Debug for ProtectedAnchorKeyPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongTotalLength => "WrongTotalLength",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::InvalidGenerationIdentifier => "InvalidGenerationIdentifier",
            Self::InternalFieldBoundaryFailure => "InternalFieldBoundaryFailure",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTIFIER: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];
    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const GOLDEN: [u8; 49] = [
        1, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
        0xae, 0xaf, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    ];

    fn identifier() -> AnchorAuthenticationKeyGenerationIdentifier {
        AnchorAuthenticationKeyGenerationIdentifier::from_bytes(IDENTIFIER).unwrap()
    }

    #[test]
    fn exact_golden_layout_round_trip_and_redaction() {
        let key = AnchorAuthenticationKey::from_bytes(KEY);
        let payload = EncodedProtectedAnchorKeyPayload::encode(&key, identifier());
        assert_eq!(PROTECTED_KEY_PAYLOAD_LENGTH, 49);
        assert_eq!(payload.as_bytes(), &GOLDEN);
        assert_eq!(&GOLDEN[0..1], &[1]);
        assert_eq!(&GOLDEN[1..17], &IDENTIFIER);
        assert_eq!(&GOLDEN[17..49], &KEY);
        let decoded = DecodedProtectedAnchorKeyMaterial::parse(&GOLDEN).unwrap();
        assert_eq!(
            format!("{payload:?}"),
            "EncodedProtectedAnchorKeyPayload([REDACTED])"
        );
        assert_eq!(
            format!("{decoded:?}"),
            "DecodedProtectedAnchorKeyMaterial([REDACTED])"
        );
        let (decoded_key, decoded_identifier) = decoded.into_parts();
        decoded_key.expose_bytes(|bytes| assert_eq!(bytes, &KEY));
        assert!(decoded_identifier.matches(&identifier()));
    }

    #[test]
    fn strict_lengths_versions_and_zero_identifier_are_rejected() {
        for length in 0..49 {
            assert!(DecodedProtectedAnchorKeyMaterial::parse(&GOLDEN[..length]).is_err());
        }
        for length in [50, 64, 256] {
            let mut input = GOLDEN.to_vec();
            input.resize(length, 0);
            assert_eq!(
                DecodedProtectedAnchorKeyMaterial::parse(&input).unwrap_err(),
                ProtectedAnchorKeyPayloadError::WrongTotalLength
            );
        }
        for version in [0, 2, 0xff] {
            let mut input = GOLDEN;
            input[0] = version;
            assert_eq!(
                DecodedProtectedAnchorKeyMaterial::parse(&input).unwrap_err(),
                ProtectedAnchorKeyPayloadError::UnsupportedVersion
            );
        }
        let mut input = GOLDEN;
        input[1..17].fill(0);
        assert_eq!(
            DecodedProtectedAnchorKeyMaterial::parse(&input).unwrap_err(),
            ProtectedAnchorKeyPayloadError::InvalidGenerationIdentifier
        );
    }

    #[test]
    fn key_mutations_are_candidates_and_identifier_mutations_follow_only_nonzero_invariant() {
        for offset in 17..49 {
            let mut input = GOLDEN;
            input[offset] ^= 0xff;
            assert!(DecodedProtectedAnchorKeyMaterial::parse(&input).is_ok());
        }
        for offset in 1..17 {
            let mut input = GOLDEN;
            input[offset] ^= 0xff;
            assert!(DecodedProtectedAnchorKeyMaterial::parse(&input).is_ok());
        }
    }

    #[test]
    fn owned_payload_and_decoding_use_the_approved_zeroization_paths() {
        let key = AnchorAuthenticationKey::from_bytes(KEY);
        let mut payload = EncodedProtectedAnchorKeyPayload::encode(&key, identifier());
        payload.zeroize_owned_bytes();
        assert_eq!(payload.as_bytes(), &[0; 49]);
        const SOURCE: &str = include_str!("freshness_anchor_protected_key_payload.rs");
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("from_bytes_with_cleared_source(&mut key_bytes)"));
        assert!(!production.contains("pub(crate) fn key_bytes"));
        assert!(!production.contains("pub(crate) fn identifier_bytes"));
    }
}
