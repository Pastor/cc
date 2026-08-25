//! Пользователь и его учётные данные.
//!
//! Сервер хранит здесь только то, чем расшифровать содержимое невозможно
//! (`TODO.md`, раздел 3). Пароля тут нет и быть не может.

use crate::id::UserId;
use crate::username::Username;
use time::OffsetDateTime;

/// Состояние учётной записи.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum State {
    /// Почта не подтверждена: возможности ограничены.
    Pending,
    /// Учётная запись действует.
    Active,
    /// Учётная запись заблокирована.
    Blocked,
}

impl State {
    /// Отвечает, разрешены ли учётной записи операции с файлами.
    #[must_use]
    pub const fn operational(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Пользователь.
///
/// Тип сведён к четырём полям: всё, что относится к криптографии, вынесено в
/// отдельные типы, потому что живёт по своим правилам и меняется отдельно.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    id: UserId,
    login: Username,
    state: State,
    registered_at: OffsetDateTime,
}

impl User {
    /// Заводит учётную запись, ожидающую подтверждения почты.
    #[must_use]
    pub const fn new(id: UserId, login: Username, registered_at: OffsetDateTime) -> Self {
        Self {
            id,
            login,
            state: State::Pending,
            registered_at,
        }
    }

    /// Возвращает учётную запись в новом состоянии.
    #[must_use]
    pub fn in_state(self, state: State) -> Self {
        Self { state, ..self }
    }

    /// Идентификатор.
    #[must_use]
    pub const fn id(&self) -> UserId {
        self.id
    }

    /// Логин.
    #[must_use]
    pub const fn login(&self) -> &Username {
        &self.login
    }

    /// Состояние.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// Время регистрации.
    #[must_use]
    pub const fn registered_at(&self) -> OffsetDateTime {
        self.registered_at
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{State, User};
    use crate::id::UserId;
    use crate::username::Username;
    use time::OffsetDateTime;

    fn user() -> User {
        User::new(
            UserId::generate(),
            Username::new("user@example.com").unwrap(),
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn new_account_awaits_confirmation() {
        assert_eq!(
            user().state(),
            State::Pending,
            "только что заведённая учётная запись сразу действует"
        );
    }

    #[test]
    fn pending_account_is_not_operational() {
        assert!(
            !user().state().operational(),
            "неподтверждённой учётной записи разрешены операции с файлами"
        );
    }

    #[test]
    fn active_account_is_operational() {
        assert!(
            user().in_state(State::Active).state().operational(),
            "действующей учётной записи запрещены операции с файлами"
        );
    }

    #[test]
    fn blocked_account_is_not_operational() {
        assert!(
            !user().in_state(State::Blocked).state().operational(),
            "заблокированной учётной записи разрешены операции с файлами"
        );
    }

    #[test]
    fn state_change_keeps_identity() {
        let subject = user();
        assert_eq!(
            subject.clone().in_state(State::Active).id(),
            subject.id(),
            "смена состояния изменила идентификатор"
        );
    }
}
