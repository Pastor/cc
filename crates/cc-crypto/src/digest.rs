//! Хеширование и детерминированные метки.

use crate::keys::TagKey;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

/// Длина хеша SHA-256.
pub const HASH_LEN: usize = 32;

/// Метка формата в вычислении метки тега.
const DOMAIN_TAG: &[u8] = b"cStore.tag.v1";

/// Хеш шифротекста.
///
/// Считается именно от шифротекста: хеш открытого текста позволил бы
/// подтвердить наличие известного файла у пользователя (`TODO.md`, раздел 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CiphertextHash([u8; HASH_LEN]);

impl CiphertextHash {
    /// Вычисляет хеш готового шифротекста.
    #[must_use]
    pub fn of(ciphertext: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(ciphertext);
        Self(hasher.finalize().into())
    }

    /// Отдаёт хеш: он не секретен.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

/// Детерминированная метка тега.
///
/// Позволяет серверу группировать файлы по равенству тега, не зная его
/// значения. Известное ограничение — частотный анализ (`TODO.md`, раздел 4.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TagLabel([u8; HASH_LEN]);

impl TagLabel {
    /// Вычисляет метку нормализованного значения тега.
    ///
    /// Нормализация — забота вызывающего: «Отчёты» и «отчёты» обязаны прийти
    /// сюда одинаковыми, иначе окажутся разными тегами.
    ///
    /// # Panics
    ///
    /// Не паникует: HMAC принимает ключ любой длины, поэтому проверка длины
    /// внутри отказать не может.
    #[allow(
        clippy::expect_used,
        reason = "HMAC принимает ключ любой длины: InvalidLength для него недостижим"
    )]
    #[must_use]
    pub fn of(key: &TagKey, normalized: &[u8]) -> Self {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.expose())
            .expect("INVARIANT: HMAC принимает ключ любой длины");
        mac.update(DOMAIN_TAG);
        mac.update(normalized);
        Self(mac.finalize().into_bytes().into())
    }

    /// Отдаёт метку: она хранится на сервере.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

/// Вычисляет SHA-256.
///
/// Примитив нужен там, где хеш задан чужим протоколом и доменную метку в него
/// добавить нельзя: PKCE считает `code_challenge`, Telegram выводит ключ
/// подписи из токена бота.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Код подлинности сообщения — HMAC-SHA256 с заданным ключом.
///
/// В отличие от [`TagLabel`], доменной метки не добавляет: формат сообщения
/// задан чужим протоколом.
#[derive(Clone, Copy, Debug)]
pub struct Signature([u8; HASH_LEN]);

impl Signature {
    /// Вычисляет код подлинности сообщения.
    ///
    /// # Panics
    ///
    /// Не паникует: HMAC принимает ключ любой длины, поэтому проверка длины
    /// внутри отказать не может.
    #[allow(
        clippy::expect_used,
        reason = "HMAC принимает ключ любой длины: InvalidLength для него недостижим"
    )]
    #[must_use]
    pub fn of(key: &[u8], message: &[u8]) -> Self {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
            .expect("INVARIANT: HMAC принимает ключ любой длины");
        mac.update(message);
        Self(mac.finalize().into_bytes().into())
    }

    /// Сравнивает с предъявленным значением в постоянном времени.
    ///
    /// Сравнение байт за байтом с ранним выходом выдаёт длину совпавшего
    /// префикса и позволяет подобрать подпись за линейное число попыток.
    #[must_use]
    pub fn matches(&self, presented: &[u8]) -> bool {
        presented.len() == HASH_LEN && self.0.ct_eq(presented).into()
    }

    /// Отдаёт код подлинности.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{CiphertextHash, TagLabel};
    use crate::keys::{AccountKey, TagKey};

    #[test]
    fn hash_is_reproducible() {
        assert_eq!(
            CiphertextHash::of(b"payload"),
            CiphertextHash::of(b"payload"),
            "хеш одного и того же шифротекста оказался разным"
        );
    }

    #[test]
    fn hash_distinguishes_data() {
        assert!(
            CiphertextHash::of(b"payload") != CiphertextHash::of(b"payloae"),
            "хеш не различает данные, отличающиеся одним байтом"
        );
    }

    #[test]
    fn tag_label_is_reproducible() {
        let key = AccountKey::new([1; 32]).tags();
        assert_eq!(
            TagLabel::of(&key, "отчёты".as_bytes()),
            TagLabel::of(&key, "отчёты".as_bytes()),
            "метка одного и того же тега оказалась разной"
        );
    }

    #[test]
    fn tag_label_distinguishes_values() {
        let key = AccountKey::new([1; 32]).tags();
        assert!(
            TagLabel::of(&key, "отчёты".as_bytes()) != TagLabel::of(&key, "счета".as_bytes()),
            "разные теги дали одинаковую метку"
        );
    }

    #[test]
    fn tag_label_depends_on_key() {
        let first = TagLabel::of(&TagKey::new([1; 32]), b"tag");
        assert!(
            first != TagLabel::of(&TagKey::new([2; 32]), b"tag"),
            "метка тега не зависит от ключа: она сравнима между пользователями"
        );
    }
}
