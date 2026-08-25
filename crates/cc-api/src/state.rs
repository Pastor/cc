//! Разделяемое состояние приложения.

use cc_storage::{Blobs, Confirmations, Sessions, Throttle, Users};
use std::sync::Arc;

/// То, что обработчики получают от приложения.
///
/// Состояние передаётся явно: глобальных изменяемых значений в проекте нет.
#[derive(Clone, Debug)]
pub struct State {
    users: Arc<Users>,
    sessions: Arc<Sessions>,
    blobs: Arc<Blobs>,
    guards: Arc<Guards>,
}

/// Всё, что защищает сервис от злоупотреблений.
#[derive(Debug)]
pub struct Guards {
    confirmations: Confirmations,
    throttle: Throttle,
}

impl Guards {
    /// Собирает защиту.
    #[must_use]
    pub const fn new(confirmations: Confirmations, throttle: Throttle) -> Self {
        Self {
            confirmations,
            throttle,
        }
    }

    /// Коды подтверждения почты.
    #[must_use]
    pub const fn confirmations(&self) -> &Confirmations {
        &self.confirmations
    }

    /// Учёт неудачных попыток.
    #[must_use]
    pub const fn throttle(&self) -> &Throttle {
        &self.throttle
    }
}

impl State {
    /// Собирает состояние.
    #[must_use]
    pub const fn new(
        users: Arc<Users>,
        sessions: Arc<Sessions>,
        blobs: Arc<Blobs>,
        guards: Arc<Guards>,
    ) -> Self {
        Self {
            users,
            sessions,
            blobs,
            guards,
        }
    }

    /// Пользователи.
    #[must_use]
    pub fn users(&self) -> &Users {
        &self.users
    }

    /// Сессии.
    #[must_use]
    pub fn sessions(&self) -> &Sessions {
        &self.sessions
    }

    /// Шифротекст.
    #[must_use]
    pub fn blobs(&self) -> &Blobs {
        &self.blobs
    }

    /// Защита от злоупотреблений.
    #[must_use]
    pub fn guards(&self) -> &Guards {
        &self.guards
    }
}
