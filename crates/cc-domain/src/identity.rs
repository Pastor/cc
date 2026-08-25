//! Внешняя личность пользователя.
//!
//! Личность у внешнего провайдера — способ войти в **уже существующую** учётную
//! запись, а не завести новую: без пароля не из чего вывести мастер-ключ
//! (`TODO.md`, раздел 4.3).

use crate::error::{Error, Result};
use core::fmt;

/// Внешний провайдер входа.
///
/// Провайдеров ровно два, и общего протокола у них нет: VK работает по OAuth
/// 2.1 с PKCE, Telegram подписывает данные виджета.
///
/// Перечисление намеренно закрыто: появление третьего провайдера должно
/// ломать сборку всюду, где выбор разбирается, а не проваливаться в ветку
/// «прочее».
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Provider {
    /// VK ID.
    Vk,
    /// Telegram.
    Telegram,
}

impl Provider {
    /// Разбирает название провайдера.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownProvider`], если название не распознано.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "vk" => Ok(Self::Vk),
            "telegram" => Ok(Self::Telegram),
            other => Err(Error::UnknownProvider {
                name: other.to_owned(),
            }),
        }
    }

    /// Название провайдера.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vk => "vk",
            Self::Telegram => "telegram",
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Личность пользователя у внешнего провайдера.
///
/// Пара «провайдер и его идентификатор» — единственное, что сервер принимает от
/// провайдера как признак личности. Почта в этой роли запрещена: провайдер,
/// не подтверждающий владение ею, позволил бы захватить чужую учётную запись.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExternalIdentity {
    provider: Provider,
    subject: String,
}

impl ExternalIdentity {
    /// Заводит личность, проверяя, что идентификатор не пуст.
    ///
    /// # Errors
    ///
    /// [`Error::EmptySubject`], если идентификатор пуст: пустая строка от
    /// провайдера означает отказ разбора, а не личность.
    pub fn new(provider: Provider, subject: impl Into<String>) -> Result<Self> {
        let subject = subject.into();
        if subject.is_empty() {
            return Err(Error::EmptySubject);
        }
        Ok(Self { provider, subject })
    }

    /// Провайдер.
    #[must_use]
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    /// Идентификатор у провайдера.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

impl fmt::Display for ExternalIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.provider, self.subject)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{ExternalIdentity, Provider};
    use crate::error::Error;

    #[test]
    fn known_provider_is_parsed() {
        assert_eq!(
            Provider::parse("telegram").unwrap(),
            Provider::Telegram,
            "название известного провайдера не распознано"
        );
    }

    #[test]
    fn unknown_provider_is_rejected() {
        assert!(
            matches!(
                Provider::parse("facebook"),
                Err(Error::UnknownProvider { .. })
            ),
            "неизвестный провайдер принят за известного"
        );
    }

    #[test]
    fn provider_name_survives_parsing() {
        assert_eq!(
            Provider::parse(Provider::Vk.name()).unwrap(),
            Provider::Vk,
            "название провайдера не переживает разбор"
        );
    }

    #[test]
    fn empty_subject_is_rejected() {
        assert!(
            matches!(
                ExternalIdentity::new(Provider::Vk, ""),
                Err(Error::EmptySubject)
            ),
            "пустой идентификатор принят за личность"
        );
    }

    #[test]
    fn identity_keeps_its_subject() {
        assert_eq!(
            ExternalIdentity::new(Provider::Telegram, "168123456")
                .unwrap()
                .subject(),
            "168123456",
            "идентификатор личности искажён при создании"
        );
    }

    #[test]
    fn identities_of_different_providers_differ() {
        assert_ne!(
            ExternalIdentity::new(Provider::Vk, "42").unwrap(),
            ExternalIdentity::new(Provider::Telegram, "42").unwrap(),
            "личности разных провайдеров с одним идентификатором признаны равными"
        );
    }
}
