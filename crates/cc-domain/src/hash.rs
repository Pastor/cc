//! Хеш содержимого.

use crate::error::{Error, Result};
use core::fmt;

/// Длина текстовой записи хеша SHA-256.
const HEX_LEN: usize = 64;

/// Хеш шифротекста в шестнадцатеричной записи нижнего регистра.
///
/// Тип существует не ради удобства, а ради безопасности: в прежней реализации
/// присланное клиентом значение хеша попадало прямо в имя файла на диске, и
/// запись вида `../../etc/passwd` уводила чтение и запись за пределы хранилища.
/// Значение этого типа заведомо состоит только из шестнадцатеричных цифр.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash(String);

impl ContentHash {
    /// Проверяет запись и принимает хеш.
    ///
    /// # Errors
    ///
    /// [`Error::ContentHash`], если запись не состоит ровно из
    /// шестидесяти четырёх шестнадцатеричных цифр нижнего регистра.
    pub fn new(text: impl Into<String>) -> Result<Self> {
        let text = text.into();
        if text.len() != HEX_LEN {
            return Err(Error::ContentHash);
        }
        if !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::ContentHash);
        }
        Ok(Self(text))
    }

    /// Строит хеш из вычисленных байтов.
    #[must_use]
    pub fn of(bytes: &[u8; 32]) -> Self {
        let mut text = String::with_capacity(HEX_LEN);
        for byte in bytes {
            let high = byte >> 4;
            let low = byte & 0x0f;
            text.push(digit(high));
            text.push(digit(low));
        }
        Self(text)
    }

    /// Отдаёт запись хеша.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Превращает полубайт в шестнадцатеричную цифру нижнего регистра.
const fn digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + nibble - 10) as char,
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{ContentHash, HEX_LEN};

    fn valid() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[test]
    fn hexadecimal_record_of_exact_length_is_accepted() {
        assert!(
            ContentHash::new(valid()).is_ok(),
            "корректная запись хеша отвергнута"
        );
    }

    #[test]
    fn path_traversal_record_is_rejected() {
        assert!(
            ContentHash::new("../../etc/passwd").is_err(),
            "запись с переходом по каталогам принята"
        );
    }

    #[test]
    fn record_with_separator_is_rejected() {
        let mut text = valid();
        text.replace_range(0..1, "/");
        assert!(
            ContentHash::new(text).is_err(),
            "запись с разделителем пути принята"
        );
    }

    #[test]
    fn upper_case_record_is_rejected() {
        assert!(
            ContentHash::new(valid().to_uppercase()).is_err(),
            "запись верхнего регистра принята: одно значение получило две формы"
        );
    }

    #[test]
    fn short_record_is_rejected() {
        assert!(
            ContentHash::new(&valid()[..HEX_LEN - 1]).is_err(),
            "усечённая запись принята"
        );
    }

    #[test]
    fn computed_hash_matches_expected_record() {
        assert_eq!(
            ContentHash::of(&[0xab; 32]).as_str(),
            "ab".repeat(32),
            "вычисленный хеш записан неверно"
        );
    }
}
