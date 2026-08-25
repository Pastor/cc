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

/// Сессия.
///
/// Признак «ключи развёрнуты» отличает вход по паролю от входа через внешнего
/// провайдера: во втором случае у клиента нет ключа шифрования, и содержимое
/// файлов ему недоступно (`TODO.md`, раздел 4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    id: SessionId,
    user: UserId,
    rights: Rights,
    timing: Timing,
}

impl Session {
    /// Заводит сессию.
    #[must_use]
    pub const fn new(id: SessionId, user: UserId, rights: Rights, timing: Timing) -> Self {
        Self {
            id,
            user,
            rights,
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

    /// Права сессии.
    #[must_use]
    pub const fn rights(&self) -> Rights {
        self.rights
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

    use super::{Session, Timing};
    use crate::id::{SessionId, UserId};
    use crate::rights::Rights;
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
            Rights::all(),
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
    fn touching_keeps_identity() {
        let subject = session();
        assert_eq!(
            subject.touched(OffsetDateTime::UNIX_EPOCH).id(),
            subject.id(),
            "обращение изменило идентификатор сессии"
        );
    }
}
