//! Сессия пользователя.

use crate::id::{SessionId, UserId};
use crate::rights::Rights;
use time::OffsetDateTime;

/// Времена жизни сессии.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    created: OffsetDateTime,
    deadline: OffsetDateTime,
    last_seen: OffsetDateTime,
}

impl Timing {
    /// Заводит времена для новой сессии.
    #[must_use]
    pub const fn new(created_at: OffsetDateTime, expires_at: OffsetDateTime) -> Self {
        Self {
            created: created_at,
            deadline: expires_at,
            last_seen: created_at,
        }
    }

    /// Возвращает времена с отмеченным обращением.
    #[must_use]
    pub const fn touched(self, moment: OffsetDateTime) -> Self {
        Self {
            last_seen: moment,
            ..self
        }
    }

    /// Отвечает, истекла ли сессия к указанному моменту.
    #[must_use]
    pub fn expired_at(self, moment: OffsetDateTime) -> bool {
        moment >= self.deadline
    }

    /// Время создания.
    #[must_use]
    pub const fn created_at(self) -> OffsetDateTime {
        self.created
    }

    /// Время истечения.
    #[must_use]
    pub const fn expires_at(self) -> OffsetDateTime {
        self.deadline
    }

    /// Время последнего обращения.
    #[must_use]
    pub const fn seen_at(self) -> OffsetDateTime {
        self.last_seen
    }
}

/// Доступность ключей в сессии.
///
/// Признак отличает вход по паролю от входа через внешнего провайдера: во
/// втором случае у клиента нет ключа шифрования, и содержимое файлов ему
/// недоступно (`TODO.md`, раздел 4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keys {
    /// Ключи не развёрнуты: доступны профиль и перечень, но не содержимое.
    Sealed,
    /// Ключи развёрнуты: клиент предъявил пароль либо ключ восстановления.
    Unwrapped,
}

impl Keys {
    /// Отвечает, развёрнуты ли ключи.
    #[must_use]
    pub const fn unwrapped(self) -> bool {
        matches!(self, Self::Unwrapped)
    }
}

/// Объём полномочий сессии: права и доступность ключей.
///
/// Два измерения разделены намеренно: право читать файл и способность его
/// расшифровать — разные вещи, и внешний вход даёт первое без второго.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    rights: Rights,
    keys: Keys,
}

impl Scope {
    /// Заводит объём полномочий.
    #[must_use]
    pub const fn new(rights: Rights, keys: Keys) -> Self {
        Self { rights, keys }
    }

    /// Полномочия входа по паролю: все права при развёрнутых ключах.
    #[must_use]
    pub const fn full() -> Self {
        Self::new(Rights::all(), Keys::Unwrapped)
    }

    /// Полномочия внешнего входа: все права при неразвёрнутых ключах.
    #[must_use]
    pub const fn external() -> Self {
        Self::new(Rights::all(), Keys::Sealed)
    }

    /// Права.
    #[must_use]
    pub const fn rights(self) -> Rights {
        self.rights
    }

    /// Доступность ключей.
    #[must_use]
    pub const fn keys(self) -> Keys {
        self.keys
    }
}

/// Сессия.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    id: SessionId,
    user: UserId,
    scope: Scope,
    timing: Timing,
}

impl Session {
    /// Заводит сессию.
    #[must_use]
    pub const fn new(id: SessionId, user: UserId, scope: Scope, timing: Timing) -> Self {
        Self {
            id,
            user,
            scope,
            timing,
        }
    }

    /// Возвращает сессию с отмеченным обращением.
    #[must_use]
    pub const fn touched(self, moment: OffsetDateTime) -> Self {
        Self {
            timing: self.timing.touched(moment),
            ..self
        }
    }

    /// Идентификатор.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// Пользователь.
    #[must_use]
    pub const fn user(&self) -> UserId {
        self.user
    }

    /// Объём полномочий сессии.
    #[must_use]
    pub const fn scope(&self) -> Scope {
        self.scope
    }

    /// Времена.
    #[must_use]
    pub const fn timing(&self) -> Timing {
        self.timing
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{Keys, Scope, Session, Timing};
    use crate::id::{SessionId, UserId};
    use time::{Duration, OffsetDateTime};

    fn timing() -> Timing {
        Timing::new(
            OffsetDateTime::UNIX_EPOCH,
            OffsetDateTime::UNIX_EPOCH + Duration::hours(1),
        )
    }

    fn session() -> Session {
        Session::new(
            SessionId::generate(),
            UserId::generate(),
            Scope::full(),
            timing(),
        )
    }

    #[test]
    fn fresh_session_is_not_expired() {
        assert!(
            !session().timing().expired_at(OffsetDateTime::UNIX_EPOCH),
            "только что заведённая сессия признана истёкшей"
        );
    }

    #[test]
    fn session_past_deadline_is_expired() {
        assert!(
            session()
                .timing()
                .expired_at(OffsetDateTime::UNIX_EPOCH + Duration::hours(2)),
            "сессия за пределом срока не признана истёкшей"
        );
    }

    #[test]
    fn touching_records_the_moment() {
        let moment = OffsetDateTime::UNIX_EPOCH + Duration::minutes(5);
        assert_eq!(
            session().touched(moment).timing().seen_at(),
            moment,
            "обращение не отмечено во временах сессии"
        );
    }

    #[test]
    fn password_entry_unwraps_keys() {
        assert!(
            Scope::full().keys().unwrapped(),
            "вход по паролю оставил ключи не развёрнутыми"
        );
    }

    #[test]
    fn external_entry_leaves_keys_sealed() {
        assert!(
            !Scope::external().keys().unwrapped(),
            "внешний вход развернул ключи, которых у него нет"
        );
    }

    #[test]
    fn external_entry_keeps_rights() {
        assert_eq!(
            Scope::external().rights(),
            Scope::full().rights(),
            "внешний вход урезал права вместо доступности ключей"
        );
    }

    #[test]
    fn sealed_keys_are_not_unwrapped() {
        assert!(
            !Keys::Sealed.unwrapped(),
            "нераскрытые ключи признаны развёрнутыми"
        );
    }

    #[test]
    fn touching_keeps_identity() {
        let subject = session();
        assert_eq!(
            subject.touched(OffsetDateTime::UNIX_EPOCH).id(),
            subject.id(),
            "обращение изменило идентификатор сессии"
        );
    }
}
