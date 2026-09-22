//! Pure, fixed-size Migration Recovery Key Custody Format Version 1 codec.

use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::{
    GeneratedMigrationRecoveryKeyMaterial, MigrationBackupSetIdentifier,
    MigrationRecoveryKeyGenerationIdentifier,
};

pub(crate) const MIGRATION_RECOVERY_KEY_CUSTODY_V1_LENGTH: usize = 196;
const CRLF_RECORD_LENGTH: usize = 200;
const PREFIX: &[u8; 32] = b"CHURCH-MIGRATION-RECOVERY-KEY-V1";
const CHECKSUM_DOMAIN: &[u8; 38] = b"CHURCH-MIGRATION-RECOVERY-KEY-CHECKSUM";
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CHECKSUM_INPUT_LENGTH: usize = 105;
const GENERATION_SYMBOLS: usize = 26;
const BACKUP_SET_SYMBOLS: usize = 26;
const KEY_SYMBOLS: usize = 52;
const CHECKSUM_SYMBOLS: usize = 13;

pub(crate) struct EncodedMigrationRecoveryKeyCustodyV1 {
    bytes: [u8; MIGRATION_RECOVERY_KEY_CUSTODY_V1_LENGTH],
}

pub(crate) struct ReenteredMigrationRecoveryKeyCustodyV1 {
    bytes: [u8; CRLF_RECORD_LENGTH],
    length: usize,
}

pub(crate) struct AssociationValidatedReenteredMigrationRecoveryKeyCustodyV1 {
    recovery_key: [u8; 32],
    generation_identifier: MigrationRecoveryKeyGenerationIdentifier,
}

impl fmt::Debug for ReenteredMigrationRecoveryKeyCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReenteredMigrationRecoveryKeyCustodyV1([REDACTED])")
    }
}

impl Drop for ReenteredMigrationRecoveryKeyCustodyV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.length.zeroize();
    }
}

impl ReenteredMigrationRecoveryKeyCustodyV1 {
    pub(crate) fn from_bounded_entry(
        input: &[u8],
    ) -> Result<Self, MigrationRecoveryKeyCustodyValidationError> {
        if input.len() != MIGRATION_RECOVERY_KEY_CUSTODY_V1_LENGTH
            && input.len() != CRLF_RECORD_LENGTH
        {
            return Err(MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText);
        }
        let mut bytes = [0_u8; CRLF_RECORD_LENGTH];
        bytes[..input.len()].copy_from_slice(input);
        Ok(Self {
            bytes,
            length: input.len(),
        })
    }

    pub(crate) fn validate_checksum_and_association(
        self,
        expected_generation_identifier: MigrationRecoveryKeyGenerationIdentifier,
        expected_backup_set_identifier: MigrationBackupSetIdentifier,
    ) -> Result<
        AssociationValidatedReenteredMigrationRecoveryKeyCustodyV1,
        MigrationRecoveryKeyCustodyValidationError,
    > {
        let mut validated =
            ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(&self.bytes[..self.length])?
                .validate_checksum()?;
        if validated.generation_identifier != expected_generation_identifier {
            return Err(MigrationRecoveryKeyCustodyValidationError::RecoveryKeyGenerationMismatch);
        }
        if validated.backup_set_identifier != expected_backup_set_identifier {
            return Err(MigrationRecoveryKeyCustodyValidationError::BackupSetMismatch);
        }
        Ok(AssociationValidatedReenteredMigrationRecoveryKeyCustodyV1 {
            recovery_key: std::mem::take(&mut validated.recovery_key),
            generation_identifier: expected_generation_identifier,
        })
    }
}

impl fmt::Debug for AssociationValidatedReenteredMigrationRecoveryKeyCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("AssociationValidatedReenteredMigrationRecoveryKeyCustodyV1([REDACTED])")
    }
}

impl Drop for AssociationValidatedReenteredMigrationRecoveryKeyCustodyV1 {
    fn drop(&mut self) {
        self.recovery_key.zeroize();
    }
}

impl AssociationValidatedReenteredMigrationRecoveryKeyCustodyV1 {
    pub(crate) fn into_recovery_key_material(mut self) -> GeneratedMigrationRecoveryKeyMaterial {
        let recovery_key =
            super::MigrationRecoveryKey::from_bytes(std::mem::take(&mut self.recovery_key));
        GeneratedMigrationRecoveryKeyMaterial {
            recovery_key,
            generation_identifier: self.generation_identifier,
        }
    }
}

impl fmt::Debug for EncodedMigrationRecoveryKeyCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncodedMigrationRecoveryKeyCustodyV1([REDACTED])")
    }
}

impl Drop for EncodedMigrationRecoveryKeyCustodyV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl EncodedMigrationRecoveryKeyCustodyV1 {
    pub(crate) fn with_native_display_bytes<R>(
        &self,
        operation: impl FnOnce(&[u8; MIGRATION_RECOVERY_KEY_CUSTODY_V1_LENGTH]) -> R,
    ) -> R {
        operation(&self.bytes)
    }

    #[cfg(test)]
    pub(crate) fn bytes_for_test(&self) -> &[u8; MIGRATION_RECOVERY_KEY_CUSTODY_V1_LENGTH] {
        &self.bytes
    }
}

pub(crate) struct ParsedUntrustedMigrationRecoveryKeyCustodyV1 {
    generation_identifier: [u8; 16],
    backup_set_identifier: [u8; 16],
    recovery_key: [u8; 32],
    checksum: [u8; 8],
}

impl fmt::Debug for ParsedUntrustedMigrationRecoveryKeyCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParsedUntrustedMigrationRecoveryKeyCustodyV1([REDACTED])")
    }
}

impl Drop for ParsedUntrustedMigrationRecoveryKeyCustodyV1 {
    fn drop(&mut self) {
        self.recovery_key.zeroize();
        self.checksum.zeroize();
    }
}

pub(crate) struct ChecksumValidatedMigrationRecoveryKeyCustodyV1 {
    generation_identifier: MigrationRecoveryKeyGenerationIdentifier,
    backup_set_identifier: MigrationBackupSetIdentifier,
    recovery_key: [u8; 32],
}

impl fmt::Debug for ChecksumValidatedMigrationRecoveryKeyCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChecksumValidatedMigrationRecoveryKeyCustodyV1([REDACTED])")
    }
}

impl Drop for ChecksumValidatedMigrationRecoveryKeyCustodyV1 {
    fn drop(&mut self) {
        self.recovery_key.zeroize();
    }
}

impl ChecksumValidatedMigrationRecoveryKeyCustodyV1 {
    #[cfg(test)]
    fn canonicalize_for_test(&self) -> EncodedMigrationRecoveryKeyCustodyV1 {
        encode_fields(
            self.generation_identifier,
            self.backup_set_identifier,
            &self.recovery_key,
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MigrationRecoveryKeyCustodyValidationError {
    MalformedCustodyText,
    CustodyChecksumMismatch,
    RecoveryKeyGenerationMismatch,
    BackupSetMismatch,
    RecoveryKeyMismatch,
}

impl fmt::Debug for MigrationRecoveryKeyCustodyValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MalformedCustodyText => "MalformedCustodyText",
            Self::CustodyChecksumMismatch => "CustodyChecksumMismatch",
            Self::RecoveryKeyGenerationMismatch => "RecoveryKeyGenerationMismatch",
            Self::BackupSetMismatch => "BackupSetMismatch",
            Self::RecoveryKeyMismatch => "RecoveryKeyMismatch",
        })
    }
}

pub(crate) fn encode_migration_recovery_key_custody_v1(
    material: &GeneratedMigrationRecoveryKeyMaterial,
    backup_set_identifier: MigrationBackupSetIdentifier,
) -> EncodedMigrationRecoveryKeyCustodyV1 {
    material.recovery_key.expose_bytes(|recovery_key| {
        encode_fields(
            material.generation_identifier,
            backup_set_identifier,
            recovery_key,
        )
    })
}

#[cfg(test)]
pub(crate) fn correctly_associated_wrong_key_record_for_test(
    input: &[u8],
) -> ReenteredMigrationRecoveryKeyCustodyV1 {
    let validated = ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(input)
        .and_then(ParsedUntrustedMigrationRecoveryKeyCustodyV1::validate_checksum)
        .unwrap();
    let wrong_key = [0xa5_u8; 32];
    assert_ne!(validated.recovery_key, wrong_key);
    let encoded = encode_fields(
        validated.generation_identifier,
        validated.backup_set_identifier,
        &wrong_key,
    );
    ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(encoded.bytes_for_test()).unwrap()
}

pub(crate) fn validate_migration_recovery_key_custody_v1(
    input: &[u8],
    expected_generation_identifier: MigrationRecoveryKeyGenerationIdentifier,
    expected_backup_set_identifier: MigrationBackupSetIdentifier,
    expected_material: &GeneratedMigrationRecoveryKeyMaterial,
) -> Result<(), MigrationRecoveryKeyCustodyValidationError> {
    let validated =
        ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(input)?.validate_checksum()?;
    if validated.generation_identifier != expected_generation_identifier {
        return Err(MigrationRecoveryKeyCustodyValidationError::RecoveryKeyGenerationMismatch);
    }
    if validated.backup_set_identifier != expected_backup_set_identifier {
        return Err(MigrationRecoveryKeyCustodyValidationError::BackupSetMismatch);
    }
    let matches = expected_material
        .recovery_key
        .expose_bytes(|expected| expected == &validated.recovery_key);
    if !matches {
        return Err(MigrationRecoveryKeyCustodyValidationError::RecoveryKeyMismatch);
    }
    Ok(())
}

impl ParsedUntrustedMigrationRecoveryKeyCustodyV1 {
    pub(crate) fn parse(input: &[u8]) -> Result<Self, MigrationRecoveryKeyCustodyValidationError> {
        let canonical = Zeroizing::new(normalize_line_endings(input)?);
        require_ascii_case_insensitive(&canonical[0..32], PREFIX)?;
        let generation_identifier = decode_grouped::<16, GENERATION_SYMBOLS>(
            &canonical[33..69],
            b"GEN-",
            &[4, 4, 4, 4, 4, 4, 2],
        )?;
        let backup_set_identifier = decode_grouped::<16, BACKUP_SET_SYMBOLS>(
            &canonical[70..106],
            b"SET-",
            &[4, 4, 4, 4, 4, 4, 2],
        )?;
        let recovery_key = Zeroizing::new(decode_grouped::<32, KEY_SYMBOLS>(
            &canonical[107..175],
            b"KEY-",
            &[4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4],
        )?);
        let checksum =
            decode_grouped::<8, CHECKSUM_SYMBOLS>(&canonical[176..196], b"CHK-", &[4, 4, 4, 1])?;
        if MigrationRecoveryKeyGenerationIdentifier::from_bytes(generation_identifier).is_err()
            || MigrationBackupSetIdentifier::from_bytes(backup_set_identifier).is_err()
        {
            return Err(MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText);
        }
        Ok(Self {
            generation_identifier,
            backup_set_identifier,
            recovery_key: *recovery_key,
            checksum,
        })
    }

    pub(crate) fn validate_checksum(
        self,
    ) -> Result<
        ChecksumValidatedMigrationRecoveryKeyCustodyV1,
        MigrationRecoveryKeyCustodyValidationError,
    > {
        let expected = checksum(
            &self.generation_identifier,
            &self.backup_set_identifier,
            &self.recovery_key,
        );
        if self.checksum != expected {
            return Err(MigrationRecoveryKeyCustodyValidationError::CustodyChecksumMismatch);
        }
        let generation_identifier =
            MigrationRecoveryKeyGenerationIdentifier::from_bytes(self.generation_identifier)
                .map_err(|_| MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText)?;
        let backup_set_identifier =
            MigrationBackupSetIdentifier::from_bytes(self.backup_set_identifier)
                .map_err(|_| MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText)?;
        Ok(ChecksumValidatedMigrationRecoveryKeyCustodyV1 {
            generation_identifier,
            backup_set_identifier,
            recovery_key: self.recovery_key,
        })
    }
}

fn encode_fields(
    generation_identifier: MigrationRecoveryKeyGenerationIdentifier,
    backup_set_identifier: MigrationBackupSetIdentifier,
    recovery_key: &[u8; 32],
) -> EncodedMigrationRecoveryKeyCustodyV1 {
    let mut generation = [0_u8; 16];
    generation_identifier.write_bytes_into(&mut generation);
    let mut backup_set = [0_u8; 16];
    backup_set_identifier.write_bytes_into(&mut backup_set);
    let checksum = checksum(&generation, &backup_set, recovery_key);
    let mut output = [0_u8; MIGRATION_RECOVERY_KEY_CUSTODY_V1_LENGTH];
    output[0..32].copy_from_slice(PREFIX);
    output[32] = b'\n';
    encode_grouped(
        &generation,
        b"GEN-",
        &[4, 4, 4, 4, 4, 4, 2],
        &mut output[33..69],
    );
    output[69] = b'\n';
    encode_grouped(
        &backup_set,
        b"SET-",
        &[4, 4, 4, 4, 4, 4, 2],
        &mut output[70..106],
    );
    output[106] = b'\n';
    encode_grouped(recovery_key, b"KEY-", &[4; 13], &mut output[107..175]);
    output[175] = b'\n';
    encode_grouped(&checksum, b"CHK-", &[4, 4, 4, 1], &mut output[176..196]);
    EncodedMigrationRecoveryKeyCustodyV1 { bytes: output }
}

fn checksum(generation: &[u8; 16], backup_set: &[u8; 16], key: &[u8; 32]) -> [u8; 8] {
    let mut input = checksum_input(generation, backup_set, key);
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    input.zeroize();
    let mut selected = [0_u8; 8];
    selected.copy_from_slice(&digest[..8]);
    selected
}

fn checksum_input(
    generation: &[u8; 16],
    backup_set: &[u8; 16],
    key: &[u8; 32],
) -> [u8; CHECKSUM_INPUT_LENGTH] {
    let mut input = [0_u8; CHECKSUM_INPUT_LENGTH];
    input[..38].copy_from_slice(CHECKSUM_DOMAIN);
    input[38] = 0;
    input[39..41].copy_from_slice(&1_u16.to_be_bytes());
    input[41..57].copy_from_slice(generation);
    input[57..73].copy_from_slice(backup_set);
    input[73..105].copy_from_slice(key);
    input
}

fn normalize_line_endings(
    input: &[u8],
) -> Result<
    [u8; MIGRATION_RECOVERY_KEY_CUSTODY_V1_LENGTH],
    MigrationRecoveryKeyCustodyValidationError,
> {
    if !input.is_ascii() {
        return Err(MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText);
    }
    if input.len() == MIGRATION_RECOVERY_KEY_CUSTODY_V1_LENGTH {
        let bytes: [u8; MIGRATION_RECOVERY_KEY_CUSTODY_V1_LENGTH] = input
            .try_into()
            .map_err(|_| MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText)?;
        if [32, 69, 106, 175]
            .iter()
            .all(|&index| bytes[index] == b'\n')
            && !bytes.contains(&b'\r')
        {
            return Ok(bytes);
        }
        return Err(MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText);
    }
    if input.len() != CRLF_RECORD_LENGTH {
        return Err(MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText);
    }
    let mut output = [0_u8; MIGRATION_RECOVERY_KEY_CUSTODY_V1_LENGTH];
    let lengths = [32_usize, 36, 36, 68, 20];
    let mut source = 0;
    let mut destination = 0;
    for (line_index, length) in lengths.into_iter().enumerate() {
        output[destination..destination + length].copy_from_slice(&input[source..source + length]);
        source += length;
        destination += length;
        if line_index < 4 {
            if input.get(source..source + 2) != Some(b"\r\n") {
                return Err(MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText);
            }
            output[destination] = b'\n';
            source += 2;
            destination += 1;
        }
    }
    Ok(output)
}

fn require_ascii_case_insensitive(
    actual: &[u8],
    expected: &[u8],
) -> Result<(), MigrationRecoveryKeyCustodyValidationError> {
    if actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    {
        Ok(())
    } else {
        Err(MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText)
    }
}

fn encode_grouped(input: &[u8], label: &[u8; 4], groups: &[usize], output: &mut [u8]) {
    output[..4].copy_from_slice(label);
    let mut symbols = [0_u8; KEY_SYMBOLS];
    let symbol_count = (input.len() * 8).div_ceil(5);
    encode_base32(input, &mut symbols[..symbol_count]);
    let mut symbol = 0;
    let mut position = 4;
    for (group_index, &length) in groups.iter().enumerate() {
        output[position..position + length].copy_from_slice(&symbols[symbol..symbol + length]);
        position += length;
        symbol += length;
        if group_index + 1 < groups.len() {
            output[position] = b'-';
            position += 1;
        }
    }
    symbols.zeroize();
}

fn encode_base32(input: &[u8], output: &mut [u8]) {
    for (symbol_index, output_symbol) in output.iter_mut().enumerate() {
        let bit_offset = symbol_index * 5;
        let mut value = 0_u8;
        for bit in 0..5 {
            value <<= 1;
            let input_bit = bit_offset + bit;
            if input_bit < input.len() * 8 {
                value |= (input[input_bit / 8] >> (7 - input_bit % 8)) & 1;
            }
        }
        *output_symbol = ALPHABET[value as usize];
    }
}

fn decode_grouped<const BYTE_COUNT: usize, const SYMBOL_COUNT: usize>(
    input: &[u8],
    label: &[u8; 4],
    groups: &[usize],
) -> Result<[u8; BYTE_COUNT], MigrationRecoveryKeyCustodyValidationError> {
    require_ascii_case_insensitive(&input[..4], label)?;
    let expected_length = 4 + SYMBOL_COUNT + groups.len() - 1;
    if input.len() != expected_length {
        return Err(MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText);
    }
    let mut values = Zeroizing::new([0_u8; SYMBOL_COUNT]);
    let mut position = 4;
    let mut symbol = 0;
    for (group_index, &length) in groups.iter().enumerate() {
        for _ in 0..length {
            values[symbol] = decode_symbol(input[position])?;
            symbol += 1;
            position += 1;
        }
        if group_index + 1 < groups.len() {
            if input[position] != b'-' {
                return Err(MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText);
            }
            position += 1;
        }
    }
    let unused_bits = SYMBOL_COUNT * 5 - BYTE_COUNT * 8;
    if unused_bits != 0 && values[SYMBOL_COUNT - 1] & ((1 << unused_bits) - 1) != 0 {
        return Err(MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText);
    }
    let mut output = [0_u8; BYTE_COUNT];
    for output_bit in 0..BYTE_COUNT * 8 {
        let value = values[output_bit / 5];
        let bit = (value >> (4 - output_bit % 5)) & 1;
        output[output_bit / 8] |= bit << (7 - output_bit % 8);
    }
    Ok(output)
}

fn decode_symbol(symbol: u8) -> Result<u8, MigrationRecoveryKeyCustodyValidationError> {
    let upper = symbol.to_ascii_uppercase();
    ALPHABET
        .iter()
        .position(|candidate| *candidate == upper)
        .map(|value| value as u8)
        .ok_or(MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText)
}

#[cfg(test)]
mod tests {
    use std::mem::{needs_drop, size_of};

    use super::*;
    use crate::production_database_migration_recovery_envelope::MigrationRecoveryKey;

    const GENERATION: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const SET: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const KEY: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    const GOLDEN: &[u8; 196] = b"CHURCH-MIGRATION-RECOVERY-KEY-V1\nGEN-000G-40R4-0M30-E209-185G-R38E-1W\nSET-208H-44RM-2MB1-E60S-38DH-R78Y-3W\nKEY-40GJ-48S4-4MK2-EA19-58NJ-RB9E-5WR3-2CHK-6GTK-CDSR-74X3-PF1X-7RZG\nCHK-0G5D-X575-NG3C-8";

    fn fields() -> (
        MigrationRecoveryKeyGenerationIdentifier,
        MigrationBackupSetIdentifier,
        MigrationRecoveryKey,
    ) {
        (
            MigrationRecoveryKeyGenerationIdentifier::from_bytes(GENERATION).unwrap(),
            MigrationBackupSetIdentifier::from_bytes(SET).unwrap(),
            MigrationRecoveryKey::from_bytes(KEY),
        )
    }

    fn raw_record(generation: &[u8; 16], backup_set: &[u8; 16], key: &[u8; 32]) -> [u8; 196] {
        let mut output = [0_u8; 196];
        output[..32].copy_from_slice(PREFIX);
        output[32] = b'\n';
        encode_grouped(
            generation,
            b"GEN-",
            &[4, 4, 4, 4, 4, 4, 2],
            &mut output[33..69],
        );
        output[69] = b'\n';
        encode_grouped(
            backup_set,
            b"SET-",
            &[4, 4, 4, 4, 4, 4, 2],
            &mut output[70..106],
        );
        output[106] = b'\n';
        encode_grouped(key, b"KEY-", &[4; 13], &mut output[107..175]);
        output[175] = b'\n';
        encode_grouped(
            &checksum(generation, backup_set, key),
            b"CHK-",
            &[4, 4, 4, 1],
            &mut output[176..196],
        );
        output
    }

    fn crlf_record(record: &[u8; 196]) -> Vec<u8> {
        let mut output = Vec::with_capacity(200);
        for (index, line) in record.split(|byte| *byte == b'\n').enumerate() {
            if index != 0 {
                output.extend_from_slice(b"\r\n");
            }
            output.extend_from_slice(line);
        }
        output
    }

    fn assert_malformed(input: &[u8]) {
        assert_eq!(
            ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(input).unwrap_err(),
            MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText
        );
    }

    fn production_region(source: &str) -> &str {
        source.split("#[cfg(test)]\nmod tests").next().unwrap()
    }

    fn declaration_region<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        source
            .split_once(start)
            .unwrap()
            .1
            .split_once(end)
            .unwrap()
            .0
    }

    #[test]
    fn golden_record_checksum_and_fixed_sizes_are_exact() {
        let (generation_identifier, backup_set_identifier, recovery_key) = fields();
        let encoded = recovery_key
            .expose_bytes(|key| encode_fields(generation_identifier, backup_set_identifier, key));
        assert_eq!(encoded.bytes_for_test(), GOLDEN);
        let input = checksum_input(&GENERATION, &SET, &KEY);
        assert_eq!(input.len(), 105);
        assert_eq!(&input[..38], CHECKSUM_DOMAIN);
        assert_eq!(&input[38..41], &[0, 0, 1]);
        assert_eq!(
            Sha256::digest(input).as_slice(),
            &[
                0x04, 0x0a, 0xde, 0x94, 0xe5, 0xac, 0x06, 0xc4, 0xe0, 0x47, 0xdb, 0x0e, 0xd1, 0x54,
                0x4f, 0x7c, 0xde, 0xa1, 0xce, 0xf3, 0x16, 0xd5, 0xc4, 0xd0, 0x3e, 0x02, 0xf2, 0x66,
                0xe8, 0xaf, 0x08, 0x49,
            ]
        );
        assert_eq!(
            checksum(&GENERATION, &SET, &KEY),
            [0x04, 0x0a, 0xde, 0x94, 0xe5, 0xac, 0x06, 0xc4]
        );
        assert_eq!(size_of::<EncodedMigrationRecoveryKeyCustodyV1>(), 196);
        assert!(needs_drop::<EncodedMigrationRecoveryKeyCustodyV1>());
        let lines: Vec<_> = GOLDEN.split(|byte| *byte == b'\n').collect();
        assert_eq!(
            lines.iter().map(|line| line.len()).collect::<Vec<_>>(),
            [32, 36, 36, 68, 20]
        );
        assert_eq!(lines.iter().map(|line| line.len()).sum::<usize>(), 192);
        assert_eq!(GOLDEN.iter().filter(|byte| **byte == b'\n').count(), 4);
        assert_ne!(GOLDEN.last(), Some(&b'\n'));
        assert_eq!(GOLDEN.len(), 196);
        let symbol_count = lines
            .iter()
            .skip(1)
            .map(|line| line.iter().skip(4).filter(|byte| **byte != b'-').count())
            .sum::<usize>();
        assert_eq!(symbol_count, 26 + 26 + 52 + 13);
        assert_eq!(symbol_count, 117);
        assert_eq!(
            lines
                .iter()
                .skip(1)
                .map(|line| { line.iter().skip(4).filter(|byte| **byte == b'-').count() })
                .sum::<usize>(),
            27
        );
    }

    #[test]
    fn parser_accepts_only_uniform_exact_forms_and_canonicalizes() {
        let parsed = ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(GOLDEN).unwrap();
        assert!(parsed.validate_checksum().is_ok());
        let lowercase = GOLDEN.map(|byte| byte.to_ascii_lowercase());
        let lowercase_validated = ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(&lowercase)
            .unwrap()
            .validate_checksum()
            .unwrap();
        assert_eq!(
            lowercase_validated.canonicalize_for_test().bytes_for_test(),
            GOLDEN
        );
        let crlf = crlf_record(GOLDEN);
        assert_eq!(crlf.len(), 200);
        let crlf_validated = ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(&crlf)
            .unwrap()
            .validate_checksum()
            .unwrap();
        assert_eq!(
            crlf_validated.canonicalize_for_test().bytes_for_test(),
            GOLDEN
        );
        for bad in [
            [&GOLDEN[..], b"\n"].concat(),
            [&GOLDEN[..], b"X"].concat(),
            GOLDEN[..195].to_vec(),
            [b"\xef\xbb\xbf".as_slice(), GOLDEN.as_slice()].concat(),
            [&GOLDEN[..40], b"\t", &GOLDEN[41..]].concat(),
            [&GOLDEN[..69], b"\r", &GOLDEN[69..]].concat(),
        ] {
            assert_eq!(
                ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(&bad).unwrap_err(),
                MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText
            );
        }
        let mut zero_generation = *GOLDEN;
        for byte in &mut zero_generation[37..69] {
            if *byte != b'-' {
                *byte = b'0';
            }
        }
        assert_eq!(
            ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(&zero_generation).unwrap_err(),
            MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText
        );
    }

    #[test]
    fn excluded_symbols_separators_unused_bits_and_mutations_are_rejected() {
        for excluded in b"ILOUilou" {
            let mut bad = *GOLDEN;
            bad[37] = *excluded;
            assert!(ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(&bad).is_err());
        }
        for index in [32, 36, 41, 69, 73, 78, 106, 110, 115, 175, 179, 184] {
            let mut bad = *GOLDEN;
            bad[index] = b'X';
            assert!(ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(&bad).is_err());
        }
        for index in [68, 105, 174, 195] {
            let mut bad = *GOLDEN;
            bad[index] = ALPHABET[(decode_symbol(bad[index]).unwrap() as usize) ^ 1];
            assert!(ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(&bad).is_err());
        }
        for index in [37, 74, 111, 180] {
            let mut bad = *GOLDEN;
            bad[index] = if bad[index] == b'0' { b'1' } else { b'0' };
            let parsed = ParsedUntrustedMigrationRecoveryKeyCustodyV1::parse(&bad).unwrap();
            assert_eq!(
                parsed.validate_checksum().unwrap_err(),
                MigrationRecoveryKeyCustodyValidationError::CustodyChecksumMismatch
            );
        }
    }

    #[test]
    fn base32_is_msb_first_unpadded_and_has_exact_alphabet() {
        let mut symbols = [0_u8; 8];
        encode_base32(&[0x00, 0x44, 0x32, 0x14, 0xc7], &mut symbols);
        assert_eq!(&symbols, b"01234567");
        let mut one = [0_u8; 2];
        encode_base32(&[0xff], &mut one);
        assert_eq!(&one, b"ZW");
        assert_eq!(ALPHABET, b"0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    }

    #[test]
    fn checksum_and_association_validation_are_distinct() {
        let (generation_identifier, backup_set_identifier, recovery_key) = fields();
        let material = GeneratedMigrationRecoveryKeyMaterial {
            recovery_key,
            generation_identifier,
        };
        assert_eq!(
            validate_migration_recovery_key_custody_v1(
                GOLDEN,
                MigrationRecoveryKeyGenerationIdentifier::from_bytes([0x51; 16]).unwrap(),
                backup_set_identifier,
                &material,
            ),
            Err(MigrationRecoveryKeyCustodyValidationError::RecoveryKeyGenerationMismatch)
        );
        assert_eq!(
            validate_migration_recovery_key_custody_v1(
                GOLDEN,
                generation_identifier,
                MigrationBackupSetIdentifier::from_bytes([0x52; 16]).unwrap(),
                &material,
            ),
            Err(MigrationRecoveryKeyCustodyValidationError::BackupSetMismatch)
        );
        let wrong_key_material = GeneratedMigrationRecoveryKeyMaterial {
            recovery_key: MigrationRecoveryKey::from_bytes([0x53; 32]),
            generation_identifier,
        };
        assert_eq!(
            validate_migration_recovery_key_custody_v1(
                GOLDEN,
                generation_identifier,
                backup_set_identifier,
                &wrong_key_material,
            ),
            Err(MigrationRecoveryKeyCustodyValidationError::RecoveryKeyMismatch)
        );
        let mut checksum_mutation = *GOLDEN;
        checksum_mutation[180] = if checksum_mutation[180] == b'0' {
            b'1'
        } else {
            b'0'
        };
        assert_eq!(
            validate_migration_recovery_key_custody_v1(
                &checksum_mutation,
                generation_identifier,
                backup_set_identifier,
                &material,
            ),
            Err(MigrationRecoveryKeyCustodyValidationError::CustodyChecksumMismatch)
        );
    }

    #[test]
    fn checksum_domain_and_version_are_separated() {
        let canonical = checksum_input(&GENERATION, &SET, &KEY);
        let mut wrong_domain = canonical;
        wrong_domain[0] ^= 1;
        let mut wrong_version = canonical;
        wrong_version[40] = 2;
        let digest = Sha256::digest(canonical);
        assert_ne!(Sha256::digest(wrong_domain), digest);
        assert_ne!(Sha256::digest(wrong_version), digest);
    }

    #[test]
    fn redaction_contains_no_secret() {
        let (generation_identifier, backup_set_identifier, recovery_key) = fields();
        let encoded = recovery_key
            .expose_bytes(|key| encode_fields(generation_identifier, backup_set_identifier, key));
        assert_eq!(
            format!("{encoded:?}"),
            "EncodedMigrationRecoveryKeyCustodyV1([REDACTED])"
        );
    }

    #[test]
    fn every_mixed_line_ending_form_is_rejected() {
        let lines: Vec<_> = GOLDEN.split(|byte| *byte == b'\n').collect();
        for crlf_mask in 1_u8..15 {
            let mut mixed = Vec::new();
            for (line_index, line) in lines.iter().enumerate() {
                mixed.extend_from_slice(line);
                if line_index < 4 {
                    if crlf_mask & (1 << line_index) == 0 {
                        mixed.push(b'\n');
                    } else {
                        mixed.extend_from_slice(b"\r\n");
                    }
                }
            }
            assert_malformed(&mixed);
        }
    }

    #[test]
    fn every_semantic_field_rejects_boundary_truncation() {
        let cases: &[(&str, &[usize])] = &[
            ("prefix", &[0, 1, 16, 31]),
            ("GEN", &[33, 34, 37, 41, 53, 64, 68]),
            ("SET", &[70, 71, 74, 78, 90, 101, 105]),
            ("KEY", &[107, 108, 111, 115, 139, 171, 174]),
            ("CHK", &[176, 177, 180, 184, 188, 194, 195]),
        ];
        for (field, positions) in cases {
            for &position in *positions {
                let mut truncated = GOLDEN.to_vec();
                truncated.remove(position);
                assert_malformed(&truncated);
            }
            assert!(
                !positions.is_empty(),
                "missing truncation cases for {field}"
            );
        }
    }

    #[test]
    fn trailing_input_matrix_is_rejected() {
        for suffix in [
            b"0".as_slice(),
            b"-",
            b" ",
            b"\t",
            b"\n",
            b"\r\n",
            b"\0",
            b"!",
        ] {
            let mut input = GOLDEN.to_vec();
            input.extend_from_slice(suffix);
            assert_malformed(&input);
        }
    }

    #[test]
    fn labels_order_and_duplicate_semantic_lines_are_rejected() {
        for (offset, replacement) in [
            (0, b"XHUR".as_slice()),
            (33, b"BAD-"),
            (70, b"BAD-"),
            (107, b"BAD-"),
            (176, b"BAD-"),
        ] {
            let mut bad = *GOLDEN;
            bad[offset..offset + 4].copy_from_slice(replacement);
            assert_malformed(&bad);
        }

        let mut swapped_generation_and_set = *GOLDEN;
        swapped_generation_and_set[33..69].copy_from_slice(&GOLDEN[70..106]);
        swapped_generation_and_set[70..106].copy_from_slice(&GOLDEN[33..69]);
        assert_malformed(&swapped_generation_and_set);

        let mut reordered_key_and_checksum = GOLDEN.to_vec();
        reordered_key_and_checksum.splice(
            107..196,
            [&GOLDEN[176..196], b"\n".as_slice(), &GOLDEN[107..175]].concat(),
        );
        assert_malformed(&reordered_key_and_checksum);

        let mut duplicate_generation = *GOLDEN;
        duplicate_generation[70..106].copy_from_slice(&GOLDEN[33..69]);
        assert_malformed(&duplicate_generation);
    }

    #[test]
    fn grouping_policy_is_exact_for_every_encoded_field_class() {
        let fields: &[(&str, usize, usize, usize)] = &[
            ("GEN", 37, 41, 68),
            ("SET", 74, 78, 105),
            ("KEY", 111, 115, 174),
            ("CHK", 180, 184, 195),
        ];
        for (name, first_symbol, first_hyphen, final_symbol) in fields {
            let mut missing = *GOLDEN;
            missing[*first_hyphen] = b'0';
            assert_malformed(&missing);

            let mut extra = *GOLDEN;
            extra[*first_symbol] = b'-';
            assert_malformed(&extra);

            let mut moved = *GOLDEN;
            moved[*first_hyphen - 1] = b'-';
            moved[*first_hyphen] = b'0';
            assert_malformed(&moved);

            let mut wrong_final_group = *GOLDEN;
            wrong_final_group[*final_symbol] = b'-';
            assert_malformed(&wrong_final_group);
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn every_excluded_alphabet_character_is_rejected_in_every_field_class() {
        for excluded in b"ILOUilou" {
            for position in [37, 74, 111, 180] {
                let mut bad = *GOLDEN;
                bad[position] = *excluded;
                assert_malformed(&bad);
            }
        }
    }

    #[test]
    fn representative_non_ascii_inputs_are_rejected_without_normalization() {
        for replacement in [
            "é".as_bytes(),
            "\u{00a0}".as_bytes(),
            "Ａ".as_bytes(),
            b"\xef\xbb\xbf".as_slice(),
        ] {
            let input = [replacement, GOLDEN.as_slice()].concat();
            assert_malformed(&input);
        }
    }

    #[test]
    fn unused_bit_widths_are_enforced_independently() {
        for (field, position, unused_bits) in [
            ("GEN", 68, 2_u8),
            ("SET", 105, 2_u8),
            ("KEY", 174, 4_u8),
            ("CHK", 195, 1_u8),
        ] {
            let canonical_value = decode_symbol(GOLDEN[position]).unwrap();
            assert_eq!(canonical_value & ((1 << unused_bits) - 1), 0);
            for bit in 0..unused_bits {
                let mut bad = *GOLDEN;
                bad[position] = ALPHABET[(canonical_value | (1 << bit)) as usize];
                assert_malformed(&bad);
            }
            assert!(!field.is_empty());
        }
    }

    #[test]
    fn deterministic_base32_boundary_vectors_are_exact() {
        let vectors: &[(&[u8], &[u8])] = &[
            (&[0x00], b"00"),
            (&[0xf8], b"Z0"),
            (&[0xff], b"ZW"),
            (&[0x08, 0x86], b"1230"),
            (&[0x00, 0x44, 0x32, 0x14, 0xc7], b"01234567"),
        ];
        for (input, expected) in vectors {
            let mut output = vec![0_u8; expected.len()];
            encode_base32(input, &mut output);
            assert_eq!(&output, expected);
            assert!(!output.contains(&b'='));
        }
        assert_eq!(ALPHABET[0], b'0');
        assert_eq!(ALPHABET[31], b'Z');
    }

    #[test]
    fn checksum_input_offsets_and_length_are_exact() {
        let input = checksum_input(&GENERATION, &SET, &KEY);
        assert_eq!(CHECKSUM_DOMAIN.len(), 38);
        assert_eq!(input.len(), 105);
        assert_eq!(&input[0..38], CHECKSUM_DOMAIN);
        assert_eq!(input[38], 0);
        assert_eq!(&input[39..41], &1_u16.to_be_bytes());
        assert_eq!(&input[41..57], &GENERATION);
        assert_eq!(&input[57..73], &SET);
        assert_eq!(&input[73..105], &KEY);
    }

    #[test]
    fn checksum_mutations_and_association_mutations_reach_separate_gates() {
        let (generation_identifier, backup_set_identifier, recovery_key) = fields();
        let material = GeneratedMigrationRecoveryKeyMaterial {
            recovery_key,
            generation_identifier,
        };
        for position in [37, 74, 111, 180] {
            let mut stale_checksum = *GOLDEN;
            let value = decode_symbol(stale_checksum[position]).unwrap();
            stale_checksum[position] = ALPHABET[(value ^ 1) as usize];
            assert_eq!(
                validate_migration_recovery_key_custody_v1(
                    &stale_checksum,
                    generation_identifier,
                    backup_set_identifier,
                    &material,
                ),
                Err(MigrationRecoveryKeyCustodyValidationError::CustodyChecksumMismatch)
            );
        }

        let changed_generation = [0x61; 16];
        assert_eq!(
            validate_migration_recovery_key_custody_v1(
                &raw_record(&changed_generation, &SET, &KEY),
                generation_identifier,
                backup_set_identifier,
                &material,
            ),
            Err(MigrationRecoveryKeyCustodyValidationError::RecoveryKeyGenerationMismatch)
        );
        let changed_set = [0x62; 16];
        assert_eq!(
            validate_migration_recovery_key_custody_v1(
                &raw_record(&GENERATION, &changed_set, &KEY),
                generation_identifier,
                backup_set_identifier,
                &material,
            ),
            Err(MigrationRecoveryKeyCustodyValidationError::BackupSetMismatch)
        );
        let changed_key = [0x63; 32];
        assert_eq!(
            validate_migration_recovery_key_custody_v1(
                &raw_record(&GENERATION, &SET, &changed_key),
                generation_identifier,
                backup_set_identifier,
                &material,
            ),
            Err(MigrationRecoveryKeyCustodyValidationError::RecoveryKeyMismatch)
        );
    }

    #[test]
    fn zero_generation_and_zero_backup_set_are_rejected_with_consistent_checksums() {
        assert_malformed(&raw_record(&[0; 16], &SET, &KEY));
        assert_malformed(&raw_record(&GENERATION, &[0; 16], &KEY));
    }

    #[test]
    fn every_validation_error_debug_value_is_fixed_and_redacted() {
        for (error, expected) in [
            (
                MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText,
                "MalformedCustodyText",
            ),
            (
                MigrationRecoveryKeyCustodyValidationError::CustodyChecksumMismatch,
                "CustodyChecksumMismatch",
            ),
            (
                MigrationRecoveryKeyCustodyValidationError::RecoveryKeyGenerationMismatch,
                "RecoveryKeyGenerationMismatch",
            ),
            (
                MigrationRecoveryKeyCustodyValidationError::BackupSetMismatch,
                "BackupSetMismatch",
            ),
            (
                MigrationRecoveryKeyCustodyValidationError::RecoveryKeyMismatch,
                "RecoveryKeyMismatch",
            ),
        ] {
            let debug = format!("{error:?}");
            assert_eq!(debug, expected);
            for secret in ["40GJ", "0G5D", "00010203", "position"] {
                assert!(!debug.contains(secret));
            }
        }
    }

    #[test]
    fn secret_owner_surfaces_and_raw_key_api_remain_narrow() {
        let custody_source = include_str!("custody.rs");
        let custody_production = production_region(custody_source);
        let envelope_source = include_str!("../production_database_migration_recovery_envelope.rs");
        for (start, end) in [
            (
                "pub(crate) struct EncodedMigrationRecoveryKeyCustodyV1",
                "pub(crate) struct ParsedUntrustedMigrationRecoveryKeyCustodyV1",
            ),
            (
                "pub(crate) struct ParsedUntrustedMigrationRecoveryKeyCustodyV1",
                "pub(crate) struct ChecksumValidatedMigrationRecoveryKeyCustodyV1",
            ),
            (
                "pub(crate) struct ChecksumValidatedMigrationRecoveryKeyCustodyV1",
                "#[derive(Clone, Copy, Eq, PartialEq)]",
            ),
        ] {
            let region = declaration_region(custody_production, start, end);
            for forbidden in [
                "derive(Clone",
                "impl Clone",
                "impl Copy",
                "Serialize",
                "Deserialize",
                "impl fmt::Display",
                "impl Deref",
                "impl AsRef",
                "Into<String>",
                "-> String",
                "-> &[u8]",
                "recovery_key(&self)",
            ] {
                assert!(!region.contains(forbidden), "{start}: {forbidden}");
            }
        }
        let key_region = declaration_region(
            envelope_source,
            "pub(crate) struct MigrationRecoveryKey",
            "#[derive(Clone, Copy, Eq, PartialEq)]\npub(crate) struct MigrationRecoveryKeyGenerationIdentifier",
        );
        for forbidden in [
            "pub(crate) fn expose_bytes",
            "pub(crate) fn as_bytes",
            "fn into_bytes",
            "derive(Clone",
            "impl Clone",
            "impl Copy",
        ] {
            assert!(
                !key_region.contains(forbidden),
                "raw key surface: {forbidden}"
            );
        }
        assert!(key_region.contains("fn expose_bytes<R>"));
        assert!(key_region.contains("fn from_bytes"));
    }

    #[test]
    fn native_display_seam_is_scoped_closure_only_and_does_not_widen_access() {
        let source = production_region(include_str!("custody.rs"));
        let implementation = source
            .split_once("impl EncodedMigrationRecoveryKeyCustodyV1")
            .unwrap()
            .1
            .split_once("pub(crate) struct ParsedUntrustedMigrationRecoveryKeyCustodyV1")
            .unwrap()
            .0;
        assert!(implementation.contains("pub(crate) fn with_native_display_bytes<R>("));
        assert!(implementation.contains("operation: impl FnOnce("));
        assert!(implementation.contains("operation(&self.bytes)"));
        for forbidden in [
            "fn as_bytes",
            "fn as_str",
            "-> String",
            "-> Vec",
            "-> &[u8]",
            "impl Clone",
            "impl Copy",
        ] {
            assert!(
                !implementation.contains(forbidden),
                "widened seam: {forbidden}"
            );
        }
    }

    #[test]
    fn secret_temporaries_have_explicit_zeroization_evidence() {
        let source = production_region(include_str!("custody.rs"));
        for evidence in [
            "impl Drop for EncodedMigrationRecoveryKeyCustodyV1",
            "self.bytes.zeroize();",
            "Zeroizing::new(normalize_line_endings(input)?)",
            "let mut values = Zeroizing::new([0_u8; SYMBOL_COUNT]);",
            "let recovery_key = Zeroizing::new(decode_grouped",
            "self.recovery_key.zeroize();",
            "self.checksum.zeroize();",
            "input.zeroize();",
            "impl Drop for ChecksumValidatedMigrationRecoveryKeyCustodyV1",
        ] {
            assert!(
                source.contains(evidence),
                "missing zeroization evidence: {evidence}"
            );
        }
        let mut representative = [0xa5_u8; 196];
        representative.zeroize();
        assert_eq!(representative, [0; 196]);
        assert!(needs_drop::<EncodedMigrationRecoveryKeyCustodyV1>());
        assert!(needs_drop::<ParsedUntrustedMigrationRecoveryKeyCustodyV1>());
        assert!(needs_drop::<ChecksumValidatedMigrationRecoveryKeyCustodyV1>());
    }

    #[test]
    fn custody_sources_exclude_unapproved_surfaces_and_regeneration() {
        let codec = production_region(include_str!("custody.rs"));
        let states = production_region(include_str!(
            "../production_database_migration_backup_stage/recovery_envelope/custody.rs"
        ))
        .replace("stream_stage_for_recovery_database_publication", "");
        for source in [codec, states.as_str()] {
            for excluded in [
                "tauri",
                "invoke_handler",
                "React",
                "frontend",
                "clipboard",
                "std::fs",
                "std::path",
                "File",
                "OpenOptions",
                "Path",
                "PathBuf",
                "print",
                "spooler",
                "qrcode",
                "QrCode",
                "qr::",
                "DPAPI",
                "CryptProtect",
                "password",
                "KDF",
                "Argon2",
                "scrypt",
                "PBKDF",
                "secret sharing",
                "SecretSharing",
                "Shamir",
                "publication",
                "publish",
                "restore",
                "execute_production_database_migration",
                "ProductionDatabaseMigrationCrossProcessExclusivity",
                "schema V2",
                "migration SQL",
                "generate_migration_recovery_key_material",
                "generate_migration_backup_set_identifier",
                "seal_migration_recovery_envelope_v1",
            ] {
                assert!(
                    !source.contains(excluded),
                    "excluded custody source token: {excluded}"
                );
            }
        }
        for excluded_api in ["publish", "restore", "execute_migration"] {
            assert!(!states.contains(excluded_api));
        }
    }

    #[test]
    fn custody_codec_uses_only_existing_dependencies() {
        let source = production_region(include_str!("custody.rs"));
        assert!(source.contains("use std::fmt;"));
        assert!(source.contains("use sha2::{Digest, Sha256};"));
        assert!(source.contains("use zeroize::{Zeroize, Zeroizing};"));
        for external in ["base32::", "data_encoding::", "serde::", "hex::"] {
            assert!(!source.contains(external));
        }
        let cargo_toml = include_str!("../../Cargo.toml");
        let cargo_lock = include_str!("../../Cargo.lock");
        assert!(!cargo_toml.to_ascii_lowercase().contains("custody"));
        assert!(!cargo_lock.to_ascii_lowercase().contains("custody"));
    }

    #[test]
    fn reentered_owner_validates_checksum_and_association_before_material_release() {
        let (generation_identifier, backup_set_identifier, _) = fields();
        let entered = ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(GOLDEN).unwrap();
        let validated = entered
            .validate_checksum_and_association(generation_identifier, backup_set_identifier)
            .unwrap();
        assert!(needs_drop::<
            AssociationValidatedReenteredMigrationRecoveryKeyCustodyV1,
        >());
        assert_eq!(
            format!("{validated:?}"),
            "AssociationValidatedReenteredMigrationRecoveryKeyCustodyV1([REDACTED])"
        );
        let material = validated.into_recovery_key_material();
        assert_eq!(material.generation_identifier(), generation_identifier);
        assert!(material.recovery_key.expose_bytes(|key| key == &KEY));

        let wrong_generation =
            MigrationRecoveryKeyGenerationIdentifier::from_bytes([0x55; 16]).unwrap();
        assert_eq!(
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(GOLDEN)
                .unwrap()
                .validate_checksum_and_association(wrong_generation, backup_set_identifier,)
                .unwrap_err(),
            MigrationRecoveryKeyCustodyValidationError::RecoveryKeyGenerationMismatch
        );
        let wrong_set = MigrationBackupSetIdentifier::from_bytes([0x66; 16]).unwrap();
        assert_eq!(
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(GOLDEN)
                .unwrap()
                .validate_checksum_and_association(generation_identifier, wrong_set,)
                .unwrap_err(),
            MigrationRecoveryKeyCustodyValidationError::BackupSetMismatch
        );
    }

    #[test]
    fn reentered_owner_is_bounded_redacted_and_rejects_malformed_or_bad_checksum() {
        assert!(needs_drop::<ReenteredMigrationRecoveryKeyCustodyV1>());
        assert_eq!(size_of::<ReenteredMigrationRecoveryKeyCustodyV1>(), 208);
        let entered = ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(GOLDEN).unwrap();
        assert_eq!(
            format!("{entered:?}"),
            "ReenteredMigrationRecoveryKeyCustodyV1([REDACTED])"
        );
        assert_eq!(
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(b"short").unwrap_err(),
            MigrationRecoveryKeyCustodyValidationError::MalformedCustodyText
        );
        let mut bad_checksum = *GOLDEN;
        bad_checksum[195] = if bad_checksum[195] == b'0' {
            b'1'
        } else {
            b'0'
        };
        let (generation_identifier, backup_set_identifier, _) = fields();
        assert_eq!(
            ReenteredMigrationRecoveryKeyCustodyV1::from_bounded_entry(&bad_checksum)
                .unwrap()
                .validate_checksum_and_association(generation_identifier, backup_set_identifier,)
                .unwrap_err(),
            MigrationRecoveryKeyCustodyValidationError::CustodyChecksumMismatch
        );
    }
}
