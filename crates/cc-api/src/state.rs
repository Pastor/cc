//! Разделяемое состояние приложения.

use cc_domain::Provider;
use cc_storage::{
    Authorizations, Blobs, Confirmations, Identities, Postbox, Sessions, Telegram, Throttle, Users,
    Vk,
};
use std::sync::Arc;

/// То, что обработчики получают от приложения.
///
/// Состояние передаётся явно: глобальных изменяемых значений в проекте нет.
#[derive(Clone, Debug)]
pub struct State {
    stores: Arc<Stores>,
    guards: Arc<Guards>,
    federation: Arc<Federation>,
}

/// Хранилища сервиса.
#[derive(Debug)]
pub struct Stores {
    users: Users,
    sessions: Arc<Sessions>,
    blobs: Blobs,
}

impl Stores {
    /// Собирает хранилища.
    ///
    /// Сессии приходят разделяемыми: их же убирает по расписанию отдельная
    /// задача сервера.
    #[must_use]
    pub const fn new(users: Users, sessions: Arc<Sessions>, blobs: Blobs) -> Self {
        Self {
            users,
            sessions,
            blobs,
        }
    }
}

/// Внешний вход: провайдеры, их запросы авторизации и привязки личностей.
///
/// Провайдер, не настроенный конфигурацией, отсутствует: маршрут отвечает так
/// же, как на неизвестного, и о настройке сервера наружу ничего не сообщает.
#[derive(Debug)]
pub struct Federation {
    authorizations: Authorizations,
    identities: Identities,
    telegram: Option<Telegram>,
    vk: Option<Vk>,
}

impl Federation {
    /// Собирает внешний вход из настроенных провайдеров.
    #[must_use]
    pub fn new(authorizations: Authorizations, telegram: Option<Telegram>, vk: Option<Vk>) -> Self {
        Self {
            authorizations,
            identities: Identities::new(),
            telegram,
            vk,
        }
    }

    /// Запросы авторизации.
    #[must_use]
    pub const fn authorizations(&self) -> &Authorizations {
        &self.authorizations
    }

    /// Привязки внешних личностей.
    #[must_use]
    pub const fn identities(&self) -> &Identities {
        &self.identities
    }

    /// Вход через Telegram, если провайдер настроен.
    #[must_use]
    pub const fn telegram(&self) -> Option<&Telegram> {
        self.telegram.as_ref()
    }

    /// Вход через VK, если провайдер настроен.
    #[must_use]
    pub const fn vk(&self) -> Option<&Vk> {
        self.vk.as_ref()
    }

    /// Отвечает, настроен ли провайдер.
    #[must_use]
    pub const fn knows(&self, provider: Provider) -> bool {
        match provider {
            Provider::Vk => self.vk.is_some(),
            Provider::Telegram => self.telegram.is_some(),
        }
    }
}

/// Всё, что защищает сервис от злоупотреблений.
#[derive(Debug)]
pub struct Guards {
    confirmations: Confirmations,
    throttle: Throttle,
    postbox: Postbox,
}

impl Guards {
    /// Собирает защиту.
    #[must_use]
    pub const fn new(confirmations: Confirmations, throttle: Throttle, postbox: Postbox) -> Self {
        Self {
            confirmations,
            throttle,
            postbox,
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

    /// Очередь писем подтверждения.
    #[must_use]
    pub const fn postbox(&self) -> &Postbox {
        &self.postbox
    }
}

impl State {
    /// Собирает состояние.
    #[must_use]
    pub const fn new(
        stores: Arc<Stores>,
        guards: Arc<Guards>,
        federation: Arc<Federation>,
    ) -> Self {
        Self {
            stores,
            guards,
            federation,
        }
    }

    /// Пользователи.
    #[must_use]
    pub fn users(&self) -> &Users {
        &self.stores.users
    }

    /// Сессии.
    #[must_use]
    pub fn sessions(&self) -> &Sessions {
        &self.stores.sessions
    }

    /// Шифротекст.
    #[must_use]
    pub fn blobs(&self) -> &Blobs {
        &self.stores.blobs
    }

    /// Защита от злоупотреблений.
    #[must_use]
    pub fn guards(&self) -> &Guards {
        &self.guards
    }

    /// Внешний вход.
    #[must_use]
    pub fn federation(&self) -> &Federation {
        &self.federation
    }
}
