//! Pure, memory-only Migration Recovery Envelope Format Version 1.
//!
//! This module owns recovery-key generation, fixed payload/framing codecs, and
//! XChaCha20-Poly1305 authentication. It does not perform persistence, database
//! access, migration authorization, custody, publication, restore, or lifecycle
//! work. Parsing never releases a database-key candidate; release is possible
//! only after recovery-key generation matching, AEAD authentication, structural
//! payload validation, and backup-set matching.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use chacha20poly1305::{
    Key, Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInOut, KeyInit},
};
use zeroize::Zeroize;

use crate::{
    database_key::DatabaseKey, database_key_protected_payload::DecodedDatabaseKeyCandidate,
    installation_evidence_contract::DatabaseKeyGenerationIdentifier,
};

#[path = "production_database_migration_recovery_envelope/custody.rs"]
mod custody;

pub(crate) use custody::{
    EncodedMigrationRecoveryKeyCustodyV1, encode_migration_recovery_key_custody_v1,
    validate_migration_recovery_key_custody_v1,
};

pub(crate) const MIGRATION_RECOVERY_PAYLOAD_V1_LENGTH: usize = 96;
pub(crate) const MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH: usize = 182;
pub(crate) const MIGRATION_RECOVERY_AAD_V1_LENGTH: usize = 44;

const MAGIC: [u8; 8] = *b"CHMRECV\0";
const FORMAT_VERSION: u16 = 1;
const XCHACHA20_POLY1305_ALGORITHM_IDENTIFIER: u16 = 1;
const RECOVERY_KEY_LENGTH: usize = 32;
const IDENTIFIER_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24;
const TAG_LENGTH: usize = 16;
const IDENTIFIER_FILL_ATTEMPTS: usize = 3;
const DECLARED_CIPHERTEXT_LENGTH: u16 = 96;

const VERSION_OFFSET: usize = 8;
const ALGORITHM_OFFSET: usize = 10;
const RECOVERY_KEY_GENERATION_IDENTIFIER_OFFSET: usize = 12;
const BACKUP_SET_IDENTIFIER_OFFSET: usize = 28;
const NONCE_OFFSET: usize = 44;
const CIPHERTEXT_LENGTH_OFFSET: usize = 68;
const CIPHERTEXT_OFFSET: usize = 70;
const TAG_OFFSET: usize = 166;

const DATABASE_KEY_OFFSET: usize = 0;
const DATABASE_KEY_GENERATION_IDENTIFIER_OFFSET: usize = 32;
const PAYLOAD_BACKUP_SET_IDENTIFIER_OFFSET: usize = 48;
const STAGE_DIGEST_OFFSET: usize = 64;

pub(crate) struct MigrationRecoveryKey {
    bytes: [u8; RECOVERY_KEY_LENGTH],
}

impl MigrationRecoveryKey {
    fn from_bytes(bytes: [u8; RECOVERY_KEY_LENGTH]) -> Self {
        Self { bytes }
    }

    fn expose_bytes<R>(&self, operation: impl FnOnce(&[u8; RECOVERY_KEY_LENGTH]) -> R) -> R {
        operation(&self.bytes)
    }

    fn zeroize_owned_bytes(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for MigrationRecoveryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MigrationRecoveryKey([REDACTED])")
    }
}

impl Drop for MigrationRecoveryKey {
    fn drop(&mut self) {
        self.zeroize_owned_bytes();
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct MigrationRecoveryKeyGenerationIdentifier([u8; IDENTIFIER_LENGTH]);

impl MigrationRecoveryKeyGenerationIdentifier {
    fn from_bytes(bytes: [u8; IDENTIFIER_LENGTH]) -> Result<Self, IdentifierValidationError> {
        if bytes == [0; IDENTIFIER_LENGTH] {
            return Err(IdentifierValidationError::AllZero);
        }
        Ok(Self(bytes))
    }

    fn write_bytes_into(&self, destination: &mut [u8; IDENTIFIER_LENGTH]) {
        destination.copy_from_slice(&self.0);
    }
}

impl fmt::Debug for MigrationRecoveryKeyGenerationIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MigrationRecoveryKeyGenerationIdentifier([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct MigrationBackupSetIdentifier([u8; IDENTIFIER_LENGTH]);

impl MigrationBackupSetIdentifier {
    fn from_bytes(bytes: [u8; IDENTIFIER_LENGTH]) -> Result<Self, IdentifierValidationError> {
        if bytes == [0; IDENTIFIER_LENGTH] {
            return Err(IdentifierValidationError::AllZero);
        }
        Ok(Self(bytes))
    }

    fn write_bytes_into(&self, destination: &mut [u8; IDENTIFIER_LENGTH]) {
        destination.copy_from_slice(&self.0);
    }
}

impl fmt::Debug for MigrationBackupSetIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MigrationBackupSetIdentifier([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct MigrationBackupStageSha256Digest([u8; 32]);

impl MigrationBackupStageSha256Digest {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for MigrationBackupStageSha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MigrationBackupStageSha256Digest([REDACTED])")
    }
}

struct MigrationRecoveryNonce([u8; NONCE_LENGTH]);

impl fmt::Debug for MigrationRecoveryNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MigrationRecoveryNonce([REDACTED])")
    }
}

pub(crate) struct GeneratedMigrationRecoveryKeyMaterial {
    recovery_key: MigrationRecoveryKey,
    generation_identifier: MigrationRecoveryKeyGenerationIdentifier,
}

impl GeneratedMigrationRecoveryKeyMaterial {
    pub(crate) fn generation_identifier(&self) -> MigrationRecoveryKeyGenerationIdentifier {
        self.generation_identifier
    }
}

impl fmt::Debug for GeneratedMigrationRecoveryKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GeneratedMigrationRecoveryKeyMaterial([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IdentifierValidationError {
    AllZero,
}

impl fmt::Debug for IdentifierValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AllZero")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MigrationRecoveryGenerationError {
    RandomnessUnavailable,
    NonzeroIdentifierUnavailable,
}

impl fmt::Debug for MigrationRecoveryGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RandomnessUnavailable => "RandomnessUnavailable",
            Self::NonzeroIdentifierUnavailable => "NonzeroIdentifierUnavailable",
        })
    }
}

#[derive(Clone, Copy)]
struct RandomFillError;

pub(crate) fn generate_migration_recovery_key_material()
-> Result<GeneratedMigrationRecoveryKeyMaterial, MigrationRecoveryGenerationError> {
    generate_migration_recovery_key_material_with(|destination| {
        getrandom::fill(destination).map_err(|_| RandomFillError)
    })
}

fn generate_migration_recovery_key_material_with(
    mut fill_random_bytes: impl FnMut(&mut [u8]) -> Result<(), RandomFillError>,
) -> Result<GeneratedMigrationRecoveryKeyMaterial, MigrationRecoveryGenerationError> {
    let mut key_bytes = [0_u8; RECOVERY_KEY_LENGTH];
    if fill_random_bytes(&mut key_bytes).is_err() {
        key_bytes.zeroize();
        return Err(MigrationRecoveryGenerationError::RandomnessUnavailable);
    }
    let recovery_key = MigrationRecoveryKey::from_bytes(key_bytes);
    let generation_identifier = generate_nonzero_identifier_with(
        &mut fill_random_bytes,
        MigrationRecoveryKeyGenerationIdentifier::from_bytes,
    )?;
    Ok(GeneratedMigrationRecoveryKeyMaterial {
        recovery_key,
        generation_identifier,
    })
}

pub(crate) fn generate_migration_backup_set_identifier()
-> Result<MigrationBackupSetIdentifier, MigrationRecoveryGenerationError> {
    generate_migration_backup_set_identifier_with(|destination| {
        getrandom::fill(destination).map_err(|_| RandomFillError)
    })
}

fn generate_migration_backup_set_identifier_with(
    mut fill_random_bytes: impl FnMut(&mut [u8]) -> Result<(), RandomFillError>,
) -> Result<MigrationBackupSetIdentifier, MigrationRecoveryGenerationError> {
    generate_nonzero_identifier_with(
        &mut fill_random_bytes,
        MigrationBackupSetIdentifier::from_bytes,
    )
}

fn generate_nonzero_identifier_with<T>(
    fill_random_bytes: &mut impl FnMut(&mut [u8]) -> Result<(), RandomFillError>,
    validate: impl Fn([u8; IDENTIFIER_LENGTH]) -> Result<T, IdentifierValidationError>,
) -> Result<T, MigrationRecoveryGenerationError> {
    for _ in 0..IDENTIFIER_FILL_ATTEMPTS {
        let mut bytes = [0_u8; IDENTIFIER_LENGTH];
        fill_random_bytes(&mut bytes)
            .map_err(|_| MigrationRecoveryGenerationError::RandomnessUnavailable)?;
        if let Ok(identifier) = validate(bytes) {
            return Ok(identifier);
        }
    }
    Err(MigrationRecoveryGenerationError::NonzeroIdentifierUnavailable)
}

struct PlaintextMigrationRecoveryPayloadV1 {
    bytes: [u8; MIGRATION_RECOVERY_PAYLOAD_V1_LENGTH],
}

impl PlaintextMigrationRecoveryPayloadV1 {
    fn encode(
        database_key: &DatabaseKey,
        database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
        backup_set_identifier: MigrationBackupSetIdentifier,
        stage_digest: MigrationBackupStageSha256Digest,
    ) -> Self {
        let mut bytes = [0_u8; MIGRATION_RECOVERY_PAYLOAD_V1_LENGTH];
        database_key.expose_bytes(|key_bytes| {
            bytes[DATABASE_KEY_OFFSET..DATABASE_KEY_GENERATION_IDENTIFIER_OFFSET]
                .copy_from_slice(key_bytes)
        });
        database_key_generation_identifier.write_bytes_into(
            (&mut bytes
                [DATABASE_KEY_GENERATION_IDENTIFIER_OFFSET..PAYLOAD_BACKUP_SET_IDENTIFIER_OFFSET])
                .try_into()
                .expect("fixed database-key-generation field has exact length"),
        );
        backup_set_identifier.write_bytes_into(
            (&mut bytes[PAYLOAD_BACKUP_SET_IDENTIFIER_OFFSET..STAGE_DIGEST_OFFSET])
                .try_into()
                .expect("fixed backup-set field has exact length"),
        );
        bytes[STAGE_DIGEST_OFFSET..].copy_from_slice(&stage_digest.0);
        Self { bytes }
    }

    fn zeroize_owned_bytes(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for PlaintextMigrationRecoveryPayloadV1 {
    fn drop(&mut self) {
        self.zeroize_owned_bytes();
    }
}

impl fmt::Debug for PlaintextMigrationRecoveryPayloadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlaintextMigrationRecoveryPayloadV1([REDACTED])")
    }
}

struct ParsedUntrustedMigrationRecoveryPayloadV1 {
    bytes: [u8; MIGRATION_RECOVERY_PAYLOAD_V1_LENGTH],
}

impl ParsedUntrustedMigrationRecoveryPayloadV1 {
    fn parse(bytes: &[u8]) -> Result<Self, MigrationRecoveryPayloadValidationError> {
        let bytes = bytes
            .try_into()
            .map_err(|_| MigrationRecoveryPayloadValidationError::MalformedPayload)?;
        Ok(Self { bytes })
    }

    fn validate_structure(
        self,
    ) -> Result<ValidatedMigrationRecoveryPayloadV1, MigrationRecoveryPayloadValidationError> {
        let database_key_generation_identifier = DatabaseKeyGenerationIdentifier::from_bytes(
            read_payload_array(&self.bytes, DATABASE_KEY_GENERATION_IDENTIFIER_OFFSET)?,
        )
        .map_err(|_| {
            MigrationRecoveryPayloadValidationError::InvalidDatabaseKeyGenerationIdentifier
        })?;
        let backup_set_identifier = MigrationBackupSetIdentifier::from_bytes(read_payload_array(
            &self.bytes,
            PAYLOAD_BACKUP_SET_IDENTIFIER_OFFSET,
        )?)
        .map_err(|_| MigrationRecoveryPayloadValidationError::InvalidBackupSetIdentifier)?;
        Ok(ValidatedMigrationRecoveryPayloadV1 {
            bytes: self.bytes,
            database_key_generation_identifier,
            backup_set_identifier,
        })
    }
}

impl Drop for ParsedUntrustedMigrationRecoveryPayloadV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for ParsedUntrustedMigrationRecoveryPayloadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParsedUntrustedMigrationRecoveryPayloadV1([REDACTED])")
    }
}

struct ValidatedMigrationRecoveryPayloadV1 {
    bytes: [u8; MIGRATION_RECOVERY_PAYLOAD_V1_LENGTH],
    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
    backup_set_identifier: MigrationBackupSetIdentifier,
}

impl ValidatedMigrationRecoveryPayloadV1 {
    fn release(
        self,
    ) -> (
        DecodedDatabaseKeyCandidate,
        MigrationBackupStageSha256Digest,
    ) {
        let mut database_key_bytes = read_payload_array(&self.bytes, DATABASE_KEY_OFFSET)
            .expect("validated fixed payload retains its exact key field");
        let database_key = DatabaseKey::from_bytes_with_cleared_source(&mut database_key_bytes);
        let digest = MigrationBackupStageSha256Digest(
            read_payload_array(&self.bytes, STAGE_DIGEST_OFFSET)
                .expect("validated fixed payload retains its exact digest field"),
        );
        (
            DecodedDatabaseKeyCandidate::from_authenticated_parts(
                database_key,
                self.database_key_generation_identifier,
            ),
            digest,
        )
    }
}

impl Drop for ValidatedMigrationRecoveryPayloadV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for ValidatedMigrationRecoveryPayloadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedMigrationRecoveryPayloadV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MigrationRecoveryPayloadValidationError {
    MalformedPayload,
    InvalidDatabaseKeyGenerationIdentifier,
    InvalidBackupSetIdentifier,
}

impl fmt::Debug for MigrationRecoveryPayloadValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MalformedPayload => "MalformedPayload",
            Self::InvalidDatabaseKeyGenerationIdentifier => {
                "InvalidDatabaseKeyGenerationIdentifier"
            }
            Self::InvalidBackupSetIdentifier => "InvalidBackupSetIdentifier",
        })
    }
}

pub(crate) struct EncodedMigrationRecoveryEnvelopeV1 {
    bytes: [u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH],
}

impl EncodedMigrationRecoveryEnvelopeV1 {
    pub(crate) const fn as_bytes(&self) -> &[u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH] {
        &self.bytes
    }
}

impl fmt::Debug for EncodedMigrationRecoveryEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncodedMigrationRecoveryEnvelopeV1([REDACTED])")
    }
}

pub(crate) struct ParsedUntrustedMigrationRecoveryEnvelopeV1 {
    recovery_key_generation_identifier: MigrationRecoveryKeyGenerationIdentifier,
    backup_set_identifier: MigrationBackupSetIdentifier,
    aad: [u8; MIGRATION_RECOVERY_AAD_V1_LENGTH],
    nonce: [u8; NONCE_LENGTH],
    ciphertext: [u8; MIGRATION_RECOVERY_PAYLOAD_V1_LENGTH],
    tag: [u8; TAG_LENGTH],
}

impl ParsedUntrustedMigrationRecoveryEnvelopeV1 {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, MigrationRecoveryEnvelopeFramingError> {
        if bytes.len() != MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH {
            return Err(MigrationRecoveryEnvelopeFramingError::WrongTotalLength);
        }
        if read_envelope_array::<8>(bytes, 0)? != MAGIC {
            return Err(MigrationRecoveryEnvelopeFramingError::WrongMagic);
        }
        if read_u16(bytes, VERSION_OFFSET)? != FORMAT_VERSION {
            return Err(MigrationRecoveryEnvelopeFramingError::UnsupportedVersion);
        }
        if read_u16(bytes, ALGORITHM_OFFSET)? != XCHACHA20_POLY1305_ALGORITHM_IDENTIFIER {
            return Err(MigrationRecoveryEnvelopeFramingError::UnsupportedAlgorithm);
        }
        let recovery_key_generation_identifier =
            MigrationRecoveryKeyGenerationIdentifier::from_bytes(read_envelope_array(
                bytes,
                RECOVERY_KEY_GENERATION_IDENTIFIER_OFFSET,
            )?)
            .map_err(|_| {
                MigrationRecoveryEnvelopeFramingError::InvalidRecoveryKeyGenerationIdentifier
            })?;
        let backup_set_identifier = MigrationBackupSetIdentifier::from_bytes(read_envelope_array(
            bytes,
            BACKUP_SET_IDENTIFIER_OFFSET,
        )?)
        .map_err(|_| MigrationRecoveryEnvelopeFramingError::InvalidBackupSetIdentifier)?;
        if read_u16(bytes, CIPHERTEXT_LENGTH_OFFSET)? != DECLARED_CIPHERTEXT_LENGTH {
            return Err(MigrationRecoveryEnvelopeFramingError::WrongCiphertextLength);
        }
        Ok(Self {
            recovery_key_generation_identifier,
            backup_set_identifier,
            aad: read_envelope_array(bytes, 0)?,
            nonce: read_envelope_array(bytes, NONCE_OFFSET)?,
            ciphertext: read_envelope_array(bytes, CIPHERTEXT_OFFSET)?,
            tag: read_envelope_array(bytes, TAG_OFFSET)?,
        })
    }

    pub(crate) fn recovery_key_generation_identifier(
        &self,
    ) -> MigrationRecoveryKeyGenerationIdentifier {
        self.recovery_key_generation_identifier
    }

    pub(crate) fn backup_set_identifier(&self) -> MigrationBackupSetIdentifier {
        self.backup_set_identifier
    }
}

impl fmt::Debug for ParsedUntrustedMigrationRecoveryEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParsedUntrustedMigrationRecoveryEnvelopeV1([REDACTED])")
    }
}

pub(crate) struct CryptographicallyAuthenticatedMigrationRecoveryEnvelopeV1 {
    backup_set_identifier: MigrationBackupSetIdentifier,
    plaintext: [u8; MIGRATION_RECOVERY_PAYLOAD_V1_LENGTH],
}

impl CryptographicallyAuthenticatedMigrationRecoveryEnvelopeV1 {
    pub(crate) fn validate_payload_and_match_backup_set(
        self,
    ) -> Result<
        GenerationAndSetMatchedMigrationRecoveryEnvelopeV1,
        MigrationRecoveryPayloadMatchError,
    > {
        let parsed = ParsedUntrustedMigrationRecoveryPayloadV1::parse(&self.plaintext)
            .map_err(|_| MigrationRecoveryPayloadMatchError::InvalidAuthenticatedPayload)?;
        let validated = parsed
            .validate_structure()
            .map_err(|_| MigrationRecoveryPayloadMatchError::InvalidAuthenticatedPayload)?;
        if validated.backup_set_identifier != self.backup_set_identifier {
            return Err(MigrationRecoveryPayloadMatchError::BackupSetMismatch);
        }
        Ok(GenerationAndSetMatchedMigrationRecoveryEnvelopeV1 { payload: validated })
    }
}

impl Drop for CryptographicallyAuthenticatedMigrationRecoveryEnvelopeV1 {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}

impl fmt::Debug for CryptographicallyAuthenticatedMigrationRecoveryEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CryptographicallyAuthenticatedMigrationRecoveryEnvelopeV1([REDACTED])")
    }
}

pub(crate) struct GenerationAndSetMatchedMigrationRecoveryEnvelopeV1 {
    payload: ValidatedMigrationRecoveryPayloadV1,
}

impl GenerationAndSetMatchedMigrationRecoveryEnvelopeV1 {
    pub(crate) fn release_database_key_candidate(
        self,
    ) -> (
        DecodedDatabaseKeyCandidate,
        MigrationBackupStageSha256Digest,
    ) {
        self.payload.release()
    }
}

impl fmt::Debug for GenerationAndSetMatchedMigrationRecoveryEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenerationAndSetMatchedMigrationRecoveryEnvelopeV1([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MigrationRecoveryEnvelopeFramingError {
    WrongTotalLength,
    WrongMagic,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    InvalidRecoveryKeyGenerationIdentifier,
    InvalidBackupSetIdentifier,
    WrongCiphertextLength,
    InternalFieldBoundaryFailure,
}

impl fmt::Debug for MigrationRecoveryEnvelopeFramingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongTotalLength => "WrongTotalLength",
            Self::WrongMagic => "WrongMagic",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::UnsupportedAlgorithm => "UnsupportedAlgorithm",
            Self::InvalidRecoveryKeyGenerationIdentifier => {
                "InvalidRecoveryKeyGenerationIdentifier"
            }
            Self::InvalidBackupSetIdentifier => "InvalidBackupSetIdentifier",
            Self::WrongCiphertextLength => "WrongCiphertextLength",
            Self::InternalFieldBoundaryFailure => "InternalFieldBoundaryFailure",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MigrationRecoverySealingError {
    RandomnessUnavailable,
    EncryptionFailed,
}

impl fmt::Debug for MigrationRecoverySealingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RandomnessUnavailable => "RandomnessUnavailable",
            Self::EncryptionFailed => "EncryptionFailed",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MigrationRecoveryOpeningError {
    RecoveryKeyGenerationMismatch,
    AuthenticationFailed,
}

impl fmt::Debug for MigrationRecoveryOpeningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RecoveryKeyGenerationMismatch => "RecoveryKeyGenerationMismatch",
            Self::AuthenticationFailed => "AuthenticationFailed",
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MigrationRecoveryPayloadMatchError {
    InvalidAuthenticatedPayload,
    BackupSetMismatch,
}

impl fmt::Debug for MigrationRecoveryPayloadMatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAuthenticatedPayload => "InvalidAuthenticatedPayload",
            Self::BackupSetMismatch => "BackupSetMismatch",
        })
    }
}

pub(crate) fn seal_migration_recovery_envelope_v1(
    recovery_key_material: &GeneratedMigrationRecoveryKeyMaterial,
    database_key: &DatabaseKey,
    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
    backup_set_identifier: MigrationBackupSetIdentifier,
    stage_digest: MigrationBackupStageSha256Digest,
) -> Result<EncodedMigrationRecoveryEnvelopeV1, MigrationRecoverySealingError> {
    seal_migration_recovery_envelope_v1_with_random_fill(
        recovery_key_material,
        database_key,
        database_key_generation_identifier,
        backup_set_identifier,
        stage_digest,
        |destination| getrandom::fill(destination).map_err(|_| RandomFillError),
    )
}

fn seal_migration_recovery_envelope_v1_with_random_fill(
    recovery_key_material: &GeneratedMigrationRecoveryKeyMaterial,
    database_key: &DatabaseKey,
    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
    backup_set_identifier: MigrationBackupSetIdentifier,
    stage_digest: MigrationBackupStageSha256Digest,
    mut fill_random_bytes: impl FnMut(&mut [u8]) -> Result<(), RandomFillError>,
) -> Result<EncodedMigrationRecoveryEnvelopeV1, MigrationRecoverySealingError> {
    let mut nonce = MigrationRecoveryNonce([0; NONCE_LENGTH]);
    fill_random_bytes(&mut nonce.0)
        .map_err(|_| MigrationRecoverySealingError::RandomnessUnavailable)?;
    seal_migration_recovery_envelope_v1_with_nonce(
        recovery_key_material,
        database_key,
        database_key_generation_identifier,
        backup_set_identifier,
        stage_digest,
        nonce,
    )
}

fn seal_migration_recovery_envelope_v1_with_nonce(
    recovery_key_material: &GeneratedMigrationRecoveryKeyMaterial,
    database_key: &DatabaseKey,
    database_key_generation_identifier: DatabaseKeyGenerationIdentifier,
    backup_set_identifier: MigrationBackupSetIdentifier,
    stage_digest: MigrationBackupStageSha256Digest,
    nonce: MigrationRecoveryNonce,
) -> Result<EncodedMigrationRecoveryEnvelopeV1, MigrationRecoverySealingError> {
    let mut plaintext = PlaintextMigrationRecoveryPayloadV1::encode(
        database_key,
        database_key_generation_identifier,
        backup_set_identifier,
        stage_digest,
    );
    let aad = construct_aad(
        recovery_key_material.generation_identifier,
        backup_set_identifier,
    );
    let cipher = initialize_aead(&recovery_key_material.recovery_key);
    let tag = cipher
        .encrypt_inout_detached(
            &XNonce::from(nonce.0),
            &aad,
            plaintext.bytes.as_mut_slice().into(),
        )
        .map_err(|_| MigrationRecoverySealingError::EncryptionFailed)?;

    let mut bytes = [0_u8; MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH];
    bytes[..MIGRATION_RECOVERY_AAD_V1_LENGTH].copy_from_slice(&aad);
    bytes[NONCE_OFFSET..CIPHERTEXT_LENGTH_OFFSET].copy_from_slice(&nonce.0);
    bytes[CIPHERTEXT_LENGTH_OFFSET..CIPHERTEXT_OFFSET]
        .copy_from_slice(&DECLARED_CIPHERTEXT_LENGTH.to_be_bytes());
    bytes[CIPHERTEXT_OFFSET..TAG_OFFSET].copy_from_slice(&plaintext.bytes);
    bytes[TAG_OFFSET..].copy_from_slice(tag.as_slice());
    Ok(EncodedMigrationRecoveryEnvelopeV1 { bytes })
}

pub(crate) fn open_migration_recovery_envelope_v1(
    parsed: ParsedUntrustedMigrationRecoveryEnvelopeV1,
    recovery_key_material: &GeneratedMigrationRecoveryKeyMaterial,
) -> Result<CryptographicallyAuthenticatedMigrationRecoveryEnvelopeV1, MigrationRecoveryOpeningError>
{
    if parsed.recovery_key_generation_identifier != recovery_key_material.generation_identifier {
        return Err(MigrationRecoveryOpeningError::RecoveryKeyGenerationMismatch);
    }
    let cipher = initialize_aead(&recovery_key_material.recovery_key);
    let mut plaintext = parsed.ciphertext;
    cipher
        .decrypt_inout_detached(
            &XNonce::from(parsed.nonce),
            &parsed.aad,
            plaintext.as_mut_slice().into(),
            &Tag::from(parsed.tag),
        )
        .map_err(|_| {
            plaintext.zeroize();
            MigrationRecoveryOpeningError::AuthenticationFailed
        })?;
    Ok(CryptographicallyAuthenticatedMigrationRecoveryEnvelopeV1 {
        backup_set_identifier: parsed.backup_set_identifier,
        plaintext,
    })
}

fn initialize_aead(recovery_key: &MigrationRecoveryKey) -> XChaCha20Poly1305 {
    recovery_key.expose_bytes(|bytes| XChaCha20Poly1305::new(&Key::from(*bytes)))
}

fn construct_aad(
    recovery_key_generation_identifier: MigrationRecoveryKeyGenerationIdentifier,
    backup_set_identifier: MigrationBackupSetIdentifier,
) -> [u8; MIGRATION_RECOVERY_AAD_V1_LENGTH] {
    let mut aad = [0_u8; MIGRATION_RECOVERY_AAD_V1_LENGTH];
    aad[..VERSION_OFFSET].copy_from_slice(&MAGIC);
    aad[VERSION_OFFSET..ALGORITHM_OFFSET].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad[ALGORITHM_OFFSET..RECOVERY_KEY_GENERATION_IDENTIFIER_OFFSET]
        .copy_from_slice(&XCHACHA20_POLY1305_ALGORITHM_IDENTIFIER.to_be_bytes());
    recovery_key_generation_identifier.write_bytes_into(
        (&mut aad[RECOVERY_KEY_GENERATION_IDENTIFIER_OFFSET..BACKUP_SET_IDENTIFIER_OFFSET])
            .try_into()
            .expect("fixed recovery-key-generation field has exact length"),
    );
    backup_set_identifier.write_bytes_into(
        (&mut aad[BACKUP_SET_IDENTIFIER_OFFSET..])
            .try_into()
            .expect("fixed backup-set field has exact length"),
    );
    aad
}

fn read_envelope_array<const LENGTH: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; LENGTH], MigrationRecoveryEnvelopeFramingError> {
    bytes
        .get(offset..offset + LENGTH)
        .and_then(|field| field.try_into().ok())
        .ok_or(MigrationRecoveryEnvelopeFramingError::InternalFieldBoundaryFailure)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, MigrationRecoveryEnvelopeFramingError> {
    Ok(u16::from_be_bytes(read_envelope_array(bytes, offset)?))
}

fn read_payload_array<const LENGTH: usize>(
    bytes: &[u8; MIGRATION_RECOVERY_PAYLOAD_V1_LENGTH],
    offset: usize,
) -> Result<[u8; LENGTH], MigrationRecoveryPayloadValidationError> {
    bytes
        .get(offset..offset + LENGTH)
        .and_then(|field| field.try_into().ok())
        .ok_or(MigrationRecoveryPayloadValidationError::MalformedPayload)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        mem::{needs_drop, size_of},
        rc::Rc,
    };

    use super::*;

    const RECOVERY_KEY: [u8; 32] = [0x11; 32];
    const RECOVERY_GENERATION: [u8; 16] = [0x22; 16];
    const BACKUP_SET: [u8; 16] = [0x33; 16];
    const DATABASE_KEY: [u8; 32] = [0x44; 32];
    const DATABASE_GENERATION: [u8; 16] = [0x55; 16];
    const DIGEST: [u8; 32] = [0x66; 32];
    const NONCE: [u8; 24] = [0x77; 24];

    fn recovery_material() -> GeneratedMigrationRecoveryKeyMaterial {
        GeneratedMigrationRecoveryKeyMaterial {
            recovery_key: MigrationRecoveryKey::from_bytes(RECOVERY_KEY),
            generation_identifier: MigrationRecoveryKeyGenerationIdentifier::from_bytes(
                RECOVERY_GENERATION,
            )
            .unwrap(),
        }
    }

    fn database_generation() -> DatabaseKeyGenerationIdentifier {
        DatabaseKeyGenerationIdentifier::from_bytes(DATABASE_GENERATION).unwrap()
    }

    fn backup_set() -> MigrationBackupSetIdentifier {
        MigrationBackupSetIdentifier::from_bytes(BACKUP_SET).unwrap()
    }

    fn seal_fixture() -> EncodedMigrationRecoveryEnvelopeV1 {
        seal_migration_recovery_envelope_v1_with_nonce(
            &recovery_material(),
            &DatabaseKey::from_bytes(DATABASE_KEY),
            database_generation(),
            backup_set(),
            MigrationBackupStageSha256Digest::from_bytes(DIGEST),
            MigrationRecoveryNonce(NONCE),
        )
        .unwrap()
    }

    fn open_fixture(
        bytes: &[u8],
        material: &GeneratedMigrationRecoveryKeyMaterial,
    ) -> Result<
        CryptographicallyAuthenticatedMigrationRecoveryEnvelopeV1,
        MigrationRecoveryOpeningError,
    > {
        let parsed = ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(bytes)
            .expect("fixture framing must be valid");
        open_migration_recovery_envelope_v1(parsed, material)
    }

    #[test]
    fn key_generation_uses_exact_independent_fills_and_bounded_zero_retry() {
        let lengths = Rc::new(RefCell::new(Vec::new()));
        let observed = Rc::clone(&lengths);
        let mut call = 0;
        let material = generate_migration_recovery_key_material_with(|destination| {
            observed.borrow_mut().push(destination.len());
            match call {
                0 => destination.copy_from_slice(&RECOVERY_KEY),
                1 => destination.fill(0),
                2 => destination.copy_from_slice(&RECOVERY_GENERATION),
                _ => panic!("unexpected fill"),
            }
            call += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(&*lengths.borrow(), &[32, 16, 16]);
        assert_eq!(
            material.generation_identifier(),
            recovery_material().generation_identifier()
        );
        assert_eq!(size_of::<MigrationRecoveryKey>(), 32);
        assert!(needs_drop::<MigrationRecoveryKey>());
    }

    #[test]
    fn backup_set_generation_is_independent_and_random_failures_do_not_retry() {
        let mut fills = 0;
        let result = generate_migration_backup_set_identifier_with(|destination| {
            fills += 1;
            assert_eq!(destination.len(), 16);
            Err(RandomFillError)
        });
        assert_eq!(
            result.unwrap_err(),
            MigrationRecoveryGenerationError::RandomnessUnavailable
        );
        assert_eq!(fills, 1);

        let mut zero_fills = 0;
        let exhausted = generate_migration_backup_set_identifier_with(|destination| {
            zero_fills += 1;
            destination.fill(0);
            Ok(())
        });
        assert_eq!(
            exhausted.unwrap_err(),
            MigrationRecoveryGenerationError::NonzeroIdentifierUnavailable
        );
        assert_eq!(zero_fills, 3);
    }

    #[test]
    fn recovery_key_randomness_failure_is_immediate_and_clears_the_temporary_path() {
        let mut fills = 0;
        let result = generate_migration_recovery_key_material_with(|destination| {
            fills += 1;
            assert_eq!(destination.len(), 32);
            destination[..8].fill(0xa5);
            Err(RandomFillError)
        });
        assert_eq!(
            result.unwrap_err(),
            MigrationRecoveryGenerationError::RandomnessUnavailable
        );
        assert_eq!(fills, 1);
    }

    #[test]
    fn nonce_generation_uses_one_exact_fill_and_failure_stops_before_encryption() {
        let material = recovery_material();
        let key = DatabaseKey::from_bytes(DATABASE_KEY);
        let mut successful_fills = 0;
        let envelope = seal_migration_recovery_envelope_v1_with_random_fill(
            &material,
            &key,
            database_generation(),
            backup_set(),
            MigrationBackupStageSha256Digest(DIGEST),
            |destination| {
                successful_fills += 1;
                assert_eq!(destination.len(), 24);
                destination.copy_from_slice(&NONCE);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(successful_fills, 1);
        assert_eq!(&envelope.as_bytes()[44..68], &NONCE);

        let mut failed_fills = 0;
        let result = seal_migration_recovery_envelope_v1_with_random_fill(
            &material,
            &key,
            database_generation(),
            backup_set(),
            MigrationBackupStageSha256Digest(DIGEST),
            |destination| {
                failed_fills += 1;
                assert_eq!(destination.len(), 24);
                Err(RandomFillError)
            },
        );
        assert_eq!(
            result.unwrap_err(),
            MigrationRecoverySealingError::RandomnessUnavailable
        );
        assert_eq!(failed_fills, 1);
    }

    #[test]
    fn production_os_random_boundaries_construct_the_unwired_memory_only_values() {
        let material = generate_migration_recovery_key_material().unwrap();
        let backup_set = generate_migration_backup_set_identifier().unwrap();
        let envelope = seal_migration_recovery_envelope_v1(
            &material,
            &DatabaseKey::from_bytes(DATABASE_KEY),
            database_generation(),
            backup_set,
            MigrationBackupStageSha256Digest(DIGEST),
        )
        .unwrap();
        assert_eq!(envelope.as_bytes().len(), 182);
    }

    #[test]
    fn secret_owners_zeroize_through_the_drop_helpers_and_debug_is_redacted() {
        let mut key = MigrationRecoveryKey::from_bytes(RECOVERY_KEY);
        key.zeroize_owned_bytes();
        key.expose_bytes(|bytes| assert_eq!(bytes, &[0; 32]));
        assert_eq!(
            format!("{:?}", recovery_material()),
            "GeneratedMigrationRecoveryKeyMaterial([REDACTED])"
        );
        assert_eq!(format!("{key:?}"), "MigrationRecoveryKey([REDACTED])");
        assert_eq!(
            format!("{:?}", backup_set()),
            "MigrationBackupSetIdentifier([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", MigrationBackupStageSha256Digest(DIGEST)),
            "MigrationBackupStageSha256Digest([REDACTED])"
        );
    }

    #[test]
    fn payload_codec_has_exact_offsets_and_separate_structural_validation() {
        let payload = PlaintextMigrationRecoveryPayloadV1::encode(
            &DatabaseKey::from_bytes(DATABASE_KEY),
            database_generation(),
            backup_set(),
            MigrationBackupStageSha256Digest(DIGEST),
        );
        assert_eq!(payload.bytes.len(), 96);
        assert_eq!(&payload.bytes[0..32], &DATABASE_KEY);
        assert_eq!(&payload.bytes[32..48], &DATABASE_GENERATION);
        assert_eq!(&payload.bytes[48..64], &BACKUP_SET);
        assert_eq!(&payload.bytes[64..96], &DIGEST);
        ParsedUntrustedMigrationRecoveryPayloadV1::parse(&payload.bytes)
            .unwrap()
            .validate_structure()
            .unwrap();
        assert_eq!(
            ParsedUntrustedMigrationRecoveryPayloadV1::parse(&payload.bytes[..95]).unwrap_err(),
            MigrationRecoveryPayloadValidationError::MalformedPayload
        );
    }

    #[test]
    fn payload_validation_rejects_each_zero_identifier() {
        let payload = PlaintextMigrationRecoveryPayloadV1::encode(
            &DatabaseKey::from_bytes(DATABASE_KEY),
            database_generation(),
            backup_set(),
            MigrationBackupStageSha256Digest(DIGEST),
        );
        let mut zero_database_generation = payload.bytes;
        zero_database_generation[32..48].fill(0);
        assert_eq!(
            ParsedUntrustedMigrationRecoveryPayloadV1::parse(&zero_database_generation)
                .unwrap()
                .validate_structure()
                .unwrap_err(),
            MigrationRecoveryPayloadValidationError::InvalidDatabaseKeyGenerationIdentifier
        );
        let mut zero_backup_set = payload.bytes;
        zero_backup_set[48..64].fill(0);
        assert_eq!(
            ParsedUntrustedMigrationRecoveryPayloadV1::parse(&zero_backup_set)
                .unwrap()
                .validate_structure()
                .unwrap_err(),
            MigrationRecoveryPayloadValidationError::InvalidBackupSetIdentifier
        );
    }

    #[test]
    fn framing_is_exact_and_strict() {
        let envelope = seal_fixture();
        let bytes = envelope.as_bytes();
        assert_eq!(bytes.len(), 182);
        assert_eq!(&bytes[0..8], &MAGIC);
        assert_eq!(&bytes[8..10], &1_u16.to_be_bytes());
        assert_eq!(&bytes[10..12], &1_u16.to_be_bytes());
        assert_eq!(&bytes[12..28], &RECOVERY_GENERATION);
        assert_eq!(&bytes[28..44], &BACKUP_SET);
        assert_eq!(&bytes[44..68], &NONCE);
        assert_eq!(&bytes[68..70], &96_u16.to_be_bytes());
        assert_eq!(bytes[70..166].len(), 96);
        assert_eq!(bytes[166..182].len(), 16);
        assert_eq!(
            ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&bytes[..181]).unwrap_err(),
            MigrationRecoveryEnvelopeFramingError::WrongTotalLength
        );
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(
            ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&trailing).unwrap_err(),
            MigrationRecoveryEnvelopeFramingError::WrongTotalLength
        );
    }

    #[test]
    fn framing_rejects_each_invalid_fixed_field() {
        let canonical = *seal_fixture().as_bytes();
        for (offset, expected) in [
            (0, MigrationRecoveryEnvelopeFramingError::WrongMagic),
            (9, MigrationRecoveryEnvelopeFramingError::UnsupportedVersion),
            (
                11,
                MigrationRecoveryEnvelopeFramingError::UnsupportedAlgorithm,
            ),
            (
                69,
                MigrationRecoveryEnvelopeFramingError::WrongCiphertextLength,
            ),
        ] {
            let mut changed = canonical;
            changed[offset] ^= 1;
            assert_eq!(
                ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&changed).unwrap_err(),
                expected
            );
        }
        let mut zero_generation = canonical;
        zero_generation[12..28].fill(0);
        assert_eq!(
            ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&zero_generation).unwrap_err(),
            MigrationRecoveryEnvelopeFramingError::InvalidRecoveryKeyGenerationIdentifier
        );
        let mut zero_set = canonical;
        zero_set[28..44].fill(0);
        assert_eq!(
            ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&zero_set).unwrap_err(),
            MigrationRecoveryEnvelopeFramingError::InvalidBackupSetIdentifier
        );
    }

    #[test]
    fn aad_is_exactly_the_immutable_identity_and_identifier_header() {
        let aad = construct_aad(recovery_material().generation_identifier(), backup_set());
        assert_eq!(aad.len(), 44);
        assert_eq!(&aad[0..8], b"CHMRECV\0");
        assert_eq!(&aad[8..10], &1_u16.to_be_bytes());
        assert_eq!(&aad[10..12], &1_u16.to_be_bytes());
        assert_eq!(&aad[12..28], &RECOVERY_GENERATION);
        assert_eq!(&aad[28..44], &BACKUP_SET);
    }

    #[test]
    fn valid_open_releases_only_the_existing_unbound_candidate_and_digest() {
        let material = recovery_material();
        let authenticated = open_fixture(seal_fixture().as_bytes(), &material).unwrap();
        let matched = authenticated
            .validate_payload_and_match_backup_set()
            .unwrap();
        let (candidate, digest) = matched.release_database_key_candidate();
        let (key, generation) = candidate.into_parts();
        key.expose_bytes(|bytes| assert_eq!(bytes, &DATABASE_KEY));
        assert_eq!(generation, database_generation());
        assert_eq!(digest, MigrationBackupStageSha256Digest(DIGEST));
    }

    #[test]
    fn wrong_key_and_generation_fail_before_any_candidate_release() {
        let envelope = seal_fixture();
        let mut wrong_key = recovery_material();
        wrong_key.recovery_key = MigrationRecoveryKey::from_bytes([0x99; 32]);
        assert_eq!(
            open_fixture(envelope.as_bytes(), &wrong_key).unwrap_err(),
            MigrationRecoveryOpeningError::AuthenticationFailed
        );
        let mut wrong_generation = recovery_material();
        wrong_generation.generation_identifier =
            MigrationRecoveryKeyGenerationIdentifier::from_bytes([0x88; 16]).unwrap();
        assert_eq!(
            open_fixture(envelope.as_bytes(), &wrong_generation).unwrap_err(),
            MigrationRecoveryOpeningError::RecoveryKeyGenerationMismatch
        );
    }

    #[test]
    fn every_nonce_ciphertext_and_tag_byte_is_authenticated() {
        let canonical = *seal_fixture().as_bytes();
        let material = recovery_material();
        for offset in NONCE_OFFSET..MIGRATION_RECOVERY_ENVELOPE_V1_LENGTH {
            if (CIPHERTEXT_LENGTH_OFFSET..CIPHERTEXT_OFFSET).contains(&offset) {
                continue;
            }
            let mut changed = canonical;
            changed[offset] ^= 1;
            assert_eq!(
                open_fixture(&changed, &material).unwrap_err(),
                MigrationRecoveryOpeningError::AuthenticationFailed,
                "offset {offset}"
            );
        }
    }

    #[test]
    fn every_aad_field_mutation_is_rejected_by_framing_or_authentication() {
        let canonical = *seal_fixture().as_bytes();
        let material = recovery_material();
        for offset in 0..MIGRATION_RECOVERY_AAD_V1_LENGTH {
            let mut changed = canonical;
            changed[offset] ^= 1;
            match ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(&changed) {
                Err(_) => {}
                Ok(parsed) => {
                    assert!(open_migration_recovery_envelope_v1(parsed, &material).is_err())
                }
            }
        }
    }

    #[test]
    fn authenticated_inner_set_mismatch_and_invalid_generation_fail_before_release() {
        fn custom_payload(mut payload: [u8; 96]) -> EncodedMigrationRecoveryEnvelopeV1 {
            let material = recovery_material();
            let aad = construct_aad(material.generation_identifier(), backup_set());
            let cipher = initialize_aead(&material.recovery_key);
            let tag = cipher
                .encrypt_inout_detached(&XNonce::from(NONCE), &aad, payload.as_mut_slice().into())
                .unwrap();
            let mut bytes = [0_u8; 182];
            bytes[..44].copy_from_slice(&aad);
            bytes[44..68].copy_from_slice(&NONCE);
            bytes[68..70].copy_from_slice(&96_u16.to_be_bytes());
            bytes[70..166].copy_from_slice(&payload);
            bytes[166..].copy_from_slice(tag.as_slice());
            payload.zeroize();
            EncodedMigrationRecoveryEnvelopeV1 { bytes }
        }

        let canonical_payload = PlaintextMigrationRecoveryPayloadV1::encode(
            &DatabaseKey::from_bytes(DATABASE_KEY),
            database_generation(),
            backup_set(),
            MigrationBackupStageSha256Digest(DIGEST),
        );
        let mut wrong_set = canonical_payload.bytes;
        wrong_set[48..64].fill(0x88);
        assert_eq!(
            open_fixture(custom_payload(wrong_set).as_bytes(), &recovery_material())
                .unwrap()
                .validate_payload_and_match_backup_set()
                .unwrap_err(),
            MigrationRecoveryPayloadMatchError::BackupSetMismatch
        );
        let mut zero_generation = canonical_payload.bytes;
        zero_generation[32..48].fill(0);
        assert_eq!(
            open_fixture(
                custom_payload(zero_generation).as_bytes(),
                &recovery_material()
            )
            .unwrap()
            .validate_payload_and_match_backup_set()
            .unwrap_err(),
            MigrationRecoveryPayloadMatchError::InvalidAuthenticatedPayload
        );
    }

    #[test]
    fn encoded_and_state_debug_never_prints_owned_material() {
        let envelope = seal_fixture();
        let parsed =
            ParsedUntrustedMigrationRecoveryEnvelopeV1::parse(envelope.as_bytes()).unwrap();
        assert_eq!(
            format!("{envelope:?}"),
            "EncodedMigrationRecoveryEnvelopeV1([REDACTED])"
        );
        assert_eq!(
            format!("{parsed:?}"),
            "ParsedUntrustedMigrationRecoveryEnvelopeV1([REDACTED])"
        );
    }

    #[test]
    fn xchacha20_poly1305_matches_the_upstream_draft_vector() {
        // RustCrypto chacha20poly1305 0.11.0 tests, sourced from
        // draft-irtf-cfrg-xchacha Appendix A.1.
        const KEY_BYTES: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        const VECTOR_NONCE: [u8; 24] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        ];
        const VECTOR_AAD: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let mut plaintext = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ciphertext: [u8; 114] = [
            0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0,
            0xe9, 0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c,
            0x21, 0x39, 0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3,
            0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
            0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5,
            0xd9, 0x45, 0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b,
            0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9,
            0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
            0xb5, 0x2e,
        ];
        let expected_tag = [
            0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a,
            0xcf, 0x49,
        ];
        let cipher = XChaCha20Poly1305::new(&Key::from(KEY_BYTES));
        let tag = cipher
            .encrypt_inout_detached(
                &XNonce::from(VECTOR_NONCE),
                &VECTOR_AAD,
                plaintext.as_mut_slice().into(),
            )
            .unwrap();
        assert_eq!(plaintext, expected_ciphertext);
        assert_eq!(tag.as_slice(), &expected_tag);
        plaintext.zeroize();
    }

    #[test]
    fn production_source_stays_pure_and_uses_detached_aead_without_candidate_shortcuts() {
        let production = include_str!("production_database_migration_recovery_envelope.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "std::fs",
            "std::path",
            "rusqlite",
            "tauri",
            "serde",
            "DPAPI",
            "GenerationBoundDatabaseKey",
            "Vec<",
            "encrypt_in_place(",
            "decrypt_in_place(",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden production capability: {forbidden}"
            );
        }
        assert!(production.contains("encrypt_inout_detached"));
        assert!(production.contains("decrypt_inout_detached"));
        assert_eq!(
            production
                .matches("DecodedDatabaseKeyCandidate::from_authenticated_parts")
                .count(),
            1
        );
    }
}
