//! Типизированные идентификаторы.
//!
//! Голый `Uuid` позволяет передать идентификатор файла туда, где ожидается
//! идентификатор директории. Отдельный тип на каждую сущность закрывает эту
//! возможность на этапе компиляции.

use crate::error::{Error, Result};
use core::fmt;
use uuid::Uuid;

macro_rules! identifier {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uuid);

        impl $name {
            /// Порождает новый идентификатор.
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// Восстанавливает идентификатор из текстовой записи.
            ///
            /// # Errors
            ///
            /// [`Error::Identifier`], если запись не является UUID.
            pub fn parse(text: &str) -> Result<Self> {
                Uuid::parse_str(text)
                    .map(Self)
                    .map_err(|_| Error::Identifier)
            }

            /// Отдаёт идентификатор в виде байтов — для связанных данных AEAD.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

identifier!(UserId, "Идентификатор пользователя.");
identifier!(FileId, "Идентификатор логического файла.");
identifier!(ContentId, "Идентификатор физического содержимого.");
identifier!(DirectoryId, "Идентификатор логической директории.");
identifier!(LinkId, "Идентификатор публичной ссылки.");
identifier!(GrantId, "Идентификатор выданного доступа.");
identifier!(TagId, "Идентификатор тега.");
identifier!(SessionId, "Идентификатор сессии.");

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{FileId, UserId};

    #[test]
    fn generated_identifiers_differ() {
        assert!(
            FileId::generate() != FileId::generate(),
            "порождение вернуло совпадающие идентификаторы"
        );
    }

    #[test]
    fn identifier_survives_display_and_parse() {
        let id = UserId::generate();
        assert_eq!(
            UserId::parse(&id.to_string()).unwrap(),
            id,
            "разбор текстовой записи вернул другой идентификатор"
        );
    }

    #[test]
    fn malformed_identifier_is_rejected() {
        assert!(
            UserId::parse("не-uuid").is_err(),
            "запись, не являющаяся UUID, принята"
        );
    }
}
