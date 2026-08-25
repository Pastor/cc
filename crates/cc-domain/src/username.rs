//! Имя пользователя.

use crate::error::{Error, Result};
use core::fmt;

/// Наибольшая допустимая длина адреса электронной почты.
const MAX_LEN: usize = 254;

/// Имя пользователя: адрес электронной почты.
///
/// Инвариант проверяется в конструкторе, поэтому значение этого типа заведомо
/// пригодно для отправки письма подтверждения.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Username(String);

impl Username {
    /// Проверяет запись и принимает имя.
    ///
    /// Проверка намеренно грубая: полная грамматика RFC 5322 допускает записи,
    /// которые не примет ни один почтовый сервер, а строгая проверка отвергнет
    /// действующие адреса. Настоящей проверкой остаётся письмо подтверждения.
    ///
    /// # Errors
    ///
    /// [`Error::Username`], если запись пуста, длиннее двухсот пятидесяти
    /// четырёх байт, не содержит ровно одного знака `@`, имеет пустую локальную
    /// часть или домен без точки.
    pub fn new(text: impl Into<String>) -> Result<Self> {
        let text = text.into();
        if text.is_empty() || text.len() > MAX_LEN {
            return Err(Error::Username);
        }
        if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(Error::Username);
        }
        let mut parts = text.split('@');
        let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(Error::Username);
        };
        if local.is_empty() || domain.is_empty() {
            return Err(Error::Username);
        }
        if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
            return Err(Error::Username);
        }
        Ok(Self(text))
    }

    /// Отдаёт запись имени.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Username {
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

    use super::{Username, MAX_LEN};

    #[test]
    fn ordinary_address_is_accepted() {
        assert!(
            Username::new("user@example.com").is_ok(),
            "обычный адрес отвергнут"
        );
    }

    #[test]
    fn address_without_at_is_rejected() {
        assert!(
            Username::new("example.com").is_err(),
            "запись без знака @ принята"
        );
    }

    #[test]
    fn address_with_two_at_signs_is_rejected() {
        assert!(
            Username::new("a@b@example.com").is_err(),
            "запись с двумя знаками @ принята"
        );
    }

    #[test]
    fn empty_local_part_is_rejected() {
        assert!(
            Username::new("@example.com").is_err(),
            "запись с пустой локальной частью принята"
        );
    }

    #[test]
    fn domain_without_dot_is_rejected() {
        assert!(
            Username::new("user@localhost").is_err(),
            "домен без точки принят"
        );
    }

    #[test]
    fn whitespace_is_rejected() {
        assert!(
            Username::new("user name@example.com").is_err(),
            "запись с пробелом принята"
        );
    }

    #[test]
    fn overlong_address_is_rejected() {
        let local = "a".repeat(MAX_LEN);
        assert!(
            Username::new(format!("{local}@example.com")).is_err(),
            "адрес длиннее предела принят"
        );
    }

    #[test]
    fn empty_address_is_rejected() {
        assert!(Username::new("").is_err(), "пустая запись принята");
    }
}
