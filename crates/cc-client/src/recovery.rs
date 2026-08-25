//! Запись и разбор ключа восстановления.
//!
//! Ключ показывается пользователю один раз и переписывается от руки, поэтому
//! запись рассчитана на человека: только различимые символы, группы по четыре и
//! контрольная сумма, ловящая опечатку до попытки восстановления.

use crate::error::{Error, Result};
use cc_crypto::{CiphertextHash, RecoveryKey, Secret};

/// Алфавит записи — Crockford Base32.
///
/// Из него исключены `I`, `L`, `O` и `U`: первые три путаются с единицей и
/// нулём, последняя — с `V`. Ровно тридцать два символа, поэтому пять бит
/// материала ложатся в один символ без потерь.
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Число символов в группе.
const GROUP: usize = 4;

/// Число символов ключевого материала до контрольной суммы.
const BODY: usize = 52;

/// Число символов контрольной суммы.
const CHECK: usize = 4;

/// Отпечаток ключа восстановления.
///
/// На сервере хранится он, а не ключ: по отпечатку можно убедиться, что
/// пользователь ввёл именно свой ключ, но нельзя развернуть ключ учётной записи.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Вычисляет отпечаток ключа.
    #[must_use]
    pub fn of(key: &RecoveryKey) -> Self {
        Self(*CiphertextHash::of(key.expose()).as_bytes())
    }

    /// Отдаёт отпечаток для хранения.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Записывает ключ восстановления в человекочитаемом виде.
///
/// Возвращает строку вида `ABCD-EFGH-…` из четырнадцати групп: пятьдесят два
/// символа материала и четыре символа контрольной суммы.
#[must_use]
pub fn write(key: &RecoveryKey) -> String {
    let mut symbols = encode(key.expose());
    symbols.extend_from_slice(&checksum(&symbols));
    let mut text = String::with_capacity(symbols.len() + symbols.len() / GROUP);
    for (index, symbol) in symbols.iter().enumerate() {
        if index > 0 && index % GROUP == 0 {
            text.push('-');
        }
        text.push(char::from(*symbol));
    }
    text
}

/// Разбирает запись ключа восстановления.
///
/// Разделители и регистр не важны: пользователь переписывает ключ от руки.
///
/// # Errors
///
/// [`Error::Recovery`], если запись содержит посторонние символы, имеет не ту
/// длину либо не сходится контрольная сумма.
pub fn read(text: &str) -> Result<RecoveryKey> {
    let symbols: Vec<u8> = text
        .bytes()
        .filter(|byte| !matches!(byte, b'-' | b' '))
        .map(normalize)
        .collect();
    if symbols.len() != BODY + CHECK {
        return Err(Error::Recovery);
    }
    if !symbols.iter().all(|byte| ALPHABET.contains(byte)) {
        return Err(Error::Recovery);
    }
    let (body, check) = symbols.split_at(BODY);
    if checksum(body) != check {
        return Err(Error::Recovery);
    }
    Ok(RecoveryKey::from_secret(Secret::new(decode(body))))
}

/// Приводит символ к алфавиту, исправляя привычные подмены.
///
/// Crockford допускает читать `O` как ноль, а `I` и `L` — как единицу: именно
/// так их и записывают от руки.
const fn normalize(byte: u8) -> u8 {
    match byte.to_ascii_uppercase() {
        b'O' => b'0',
        b'I' | b'L' => b'1',
        other => other,
    }
}

/// Переводит ключевой материал в символы алфавита.
fn encode(bytes: &[u8; 32]) -> Vec<u8> {
    let mut symbols = Vec::with_capacity(BODY);
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::try_from((accumulator >> bits) & 0x1f).unwrap_or(0);
            symbols.push(ALPHABET[index]);
        }
    }
    if bits > 0 {
        let index = usize::try_from((accumulator << (5 - bits)) & 0x1f).unwrap_or(0);
        symbols.push(ALPHABET[index]);
    }
    symbols
}

/// Восстанавливает ключевой материал из символов алфавита.
fn decode(symbols: &[u8]) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    let mut written = 0_usize;
    for symbol in symbols {
        let index = ALPHABET
            .iter()
            .position(|value| value == symbol)
            .unwrap_or(0);
        accumulator = (accumulator << 5) | (u32::try_from(index).unwrap_or(0) & 0x1f);
        bits += 5;
        while bits >= 8 && written < bytes.len() {
            bits -= 8;
            bytes[written] = u8::try_from((accumulator >> bits) & 0xff).unwrap_or(0);
            written += 1;
        }
    }
    bytes
}

/// Вычисляет контрольную сумму записи.
fn checksum(symbols: &[u8]) -> Vec<u8> {
    let digest = CiphertextHash::of(symbols);
    digest
        .as_bytes()
        .iter()
        .take(CHECK)
        .map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{read, write, Fingerprint, ALPHABET};
    use cc_crypto::RecoveryKey;

    #[test]
    fn key_survives_write_and_read() {
        let key = RecoveryKey::generate();
        assert_eq!(
            read(&write(&key)).unwrap(),
            key,
            "прочитанный ключ разошёлся с записанным"
        );
    }

    #[test]
    fn record_is_split_into_groups() {
        assert!(
            write(&RecoveryKey::generate()).contains('-'),
            "запись не разбита на группы и потому неудобна для переписывания"
        );
    }

    #[test]
    fn record_avoids_confusable_symbols() {
        let text = write(&RecoveryKey::generate());
        assert!(
            !text
                .bytes()
                .any(|byte| matches!(byte, b'I' | b'L' | b'O' | b'U')),
            "в записи встретился символ, неразличимый при переписывании от руки"
        );
    }

    #[test]
    fn lower_case_record_is_accepted() {
        let key = RecoveryKey::generate();
        assert_eq!(
            read(&write(&key).to_lowercase()).unwrap(),
            key,
            "запись в нижнем регистре отвергнута"
        );
    }

    #[test]
    fn record_without_separators_is_accepted() {
        let key = RecoveryKey::generate();
        assert_eq!(
            read(&write(&key).replace('-', "")).unwrap(),
            key,
            "запись без разделителей отвергнута"
        );
    }

    #[test]
    fn single_symbol_typo_is_caught() {
        let text = write(&RecoveryKey::generate());
        let mut broken: Vec<char> = text.chars().collect();
        let position = broken.iter().position(|c| *c != '-').unwrap_or(0);
        let replacement = ALPHABET
            .iter()
            .map(|byte| char::from(*byte))
            .find(|c| *c != broken[position])
            .unwrap_or('Z');
        broken[position] = replacement;
        assert!(
            read(&broken.into_iter().collect::<String>()).is_err(),
            "опечатка в одном символе не поймана контрольной суммой"
        );
    }

    #[test]
    fn truncated_record_is_rejected() {
        let text = write(&RecoveryKey::generate());
        assert!(
            read(&text[..text.len() - 2]).is_err(),
            "усечённая запись принята"
        );
    }

    #[test]
    fn fingerprint_identifies_key() {
        let key = RecoveryKey::generate();
        assert_eq!(
            Fingerprint::of(&key),
            Fingerprint::of(&key),
            "отпечаток одного ключа оказался разным"
        );
    }

    #[test]
    fn fingerprint_distinguishes_keys() {
        assert!(
            Fingerprint::of(&RecoveryKey::generate()) != Fingerprint::of(&RecoveryKey::generate()),
            "отпечатки разных ключей совпали"
        );
    }

    #[test]
    fn fingerprint_does_not_reveal_key() {
        let key = RecoveryKey::generate();
        assert!(
            Fingerprint::of(&key).as_bytes() != key.expose(),
            "отпечаток совпал с ключом: его хранение равносильно хранению ключа"
        );
    }
}
