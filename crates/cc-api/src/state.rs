//! Разделяемое состояние приложения.

use cc_storage::{Blobs, Confirmations, Sessions, Users};
use std::sync::Arc;

/// То, что обработчики получают от приложения.
///
/// Состояние передаётся явно: глобальных изменяемых значений в проекте нет.
#[derive(Clone, Debug)]
pub struct State {
    users: Arc<Users>,
    sessions: Arc<Sessions>,
    blobs: Arc<Blobs>,
    confirmations: Arc<Confirmations>,
}

impl State {
    /// Собирает состояние.
    #[must_use]
    pub const fn new(
        users: Arc<Users>,
        sessions: Arc<Sessions>,
        blobs: Arc<Blobs>,
        confirmations: Arc<Confirmations>,
    ) -> Self {
        Self {
            users,
            sessions,
            blobs,
            confirmations,
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

    /// Коды подтверждения почты.
    #[must_use]
    pub fn confirmations(&self) -> &Confirmations {
        &self.confirmations
    }
}
