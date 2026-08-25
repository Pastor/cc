//! Конфигурация сервера.
//!
//! Секреты не имеют значений по умолчанию: отсутствие обязательного параметра —
//! отказ при старте с внятным сообщением. Прежняя реализация зашивала пароль
//! хранилища ключей прямо в код и писала его в текущий рабочий каталог.

use anyhow::Context as _;
use figment::providers::{Env, Format as _, Toml};
use figment::Figment;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Настройки сервера.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    listen: SocketAddr,
    storage: PathBuf,
    secrets: Secrets,
    limits: Limits,
}

/// Приложение VK ID.
#[derive(Clone, Deserialize)]
pub struct VkApp {
    client: String,
    secret: String,
    redirect: String,
}

impl core::fmt::Debug for VkApp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VkApp([REDACTED])")
    }
}

impl VkApp {
    /// Идентификатор приложения.
    #[must_use]
    pub fn client(&self) -> &str {
        &self.client
    }

    /// Секрет приложения: на клиент не попадает никогда.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Адрес возврата, зарегистрированный у провайдера.
    #[must_use]
    pub fn redirect(&self) -> &str {
        &self.redirect
    }
}

/// Бот Telegram.
#[derive(Clone, Deserialize)]
pub struct TelegramBot {
    token: String,
}

impl core::fmt::Debug for TelegramBot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TelegramBot([REDACTED])")
    }
}

impl TelegramBot {
    /// Токен бота — секрет уровня закрытого ключа.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl Config {
    /// Читает конфигурацию из файла и переменных окружения.
    ///
    /// Переменные окружения с префиксом `CC_` перекрывают файл. Значения по
    /// умолчанию есть только у того, что секретом не является.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку, если обязательный параметр отсутствует либо значение
    /// не разбирается.
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let mut figment = Figment::new();
        if let Some(path) = path {
            figment = figment.merge(Toml::file(path));
        }
        figment
            .merge(Env::prefixed("CC_").split("__"))
            .extract()
            .context("чтение конфигурации: проверьте файл и переменные окружения CC_")
    }

    /// Адрес, на котором слушает сервер.
    ///
    /// Порт `0` означает эфемерный: он нужен тестам, чтобы не занимать
    /// фиксированный порт.
    #[must_use]
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Корень хранилища шифротекста.
    #[must_use]
    pub const fn storage(&self) -> &PathBuf {
        &self.storage
    }

    /// Секреты.
    #[must_use]
    pub const fn secrets(&self) -> &Secrets {
        &self.secrets
    }

    /// Пределы.
    #[must_use]
    pub const fn limits(&self) -> &Limits {
        &self.limits
    }
}

/// Секреты сервера.
///
/// Тип не выводит `Debug` через `derive`: значения не должны попасть в журнал.
#[derive(Clone, Deserialize)]
pub struct Secrets {
    server: String,
    vk: Option<VkApp>,
    telegram: Option<TelegramBot>,
}

impl core::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secrets([REDACTED])")
    }
}

impl Secrets {
    /// Серверный секрет: из него выводится правдоподобная соль и им укрепляется
    /// аутентификационный хеш.
    #[must_use]
    pub const fn server(&self) -> &[u8] {
        self.server.as_bytes()
    }

    /// Приложение VK ID, если оно настроено.
    ///
    /// Провайдера может не быть вовсе: тогда внешний вход через него не
    /// работает, и наружу это выглядит как неизвестный провайдер.
    #[must_use]
    pub const fn vk(&self) -> Option<&VkApp> {
        self.vk.as_ref()
    }

    /// Бот Telegram, если он настроен.
    #[must_use]
    pub const fn telegram(&self) -> Option<&TelegramBot> {
        self.telegram.as_ref()
    }
}

/// Пределы, применяемые к запросам.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct Limits {
    body_bytes: usize,
    request_seconds: u64,
    session_hours: i64,
    authorization_minutes: i64,
}

impl Limits {
    /// Наибольший размер тела запроса.
    #[must_use]
    pub const fn body_bytes(self) -> usize {
        self.body_bytes
    }

    /// Таймаут обработки запроса.
    #[must_use]
    pub const fn request(self) -> core::time::Duration {
        core::time::Duration::from_secs(self.request_seconds)
    }

    /// Срок жизни сессии.
    #[must_use]
    pub const fn session(self) -> time::Duration {
        time::Duration::hours(self.session_hours)
    }

    /// Срок жизни запроса авторизации и подписанных данных виджета.
    ///
    /// Запрос живёт минуты: чем короче окно, тем меньше проку от перехваченных
    /// данных (`TODO.md`, раздел 4.3).
    #[must_use]
    pub const fn authorization(self) -> time::Duration {
        time::Duration::minutes(self.authorization_minutes)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::result_large_err,
        reason = "в тесте отказ обязан ронять тест; размер ошибки figment::Jail нам не подконтролен"
    )]

    use super::{Config, Secrets, TelegramBot, VkApp};

    #[test]
    fn missing_configuration_is_refused() {
        figment::Jail::expect_with(|_| {
            assert!(
                Config::load(None).is_err(),
                "сервер согласился запуститься без конфигурации"
            );
            Ok(())
        });
    }

    #[test]
    fn missing_secret_is_refused() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "cc.toml",
                r#"
                listen = "127.0.0.1:0"
                storage = "./data"
                [limits]
                body_bytes = 1024
                request_seconds = 30
                session_hours = 1
                authorization_minutes = 5
                "#,
            )?;
            assert!(
                Config::load(Some("cc.toml")).is_err(),
                "сервер согласился запуститься без серверного секрета"
            );
            Ok(())
        });
    }

    #[test]
    fn complete_configuration_is_accepted() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "cc.toml",
                r#"
                listen = "127.0.0.1:0"
                storage = "./data"
                [secrets]
                server = "s3cret"
                [limits]
                body_bytes = 1024
                request_seconds = 30
                session_hours = 1
                authorization_minutes = 5
                "#,
            )?;
            assert!(
                Config::load(Some("cc.toml")).is_ok(),
                "полная конфигурация отвергнута"
            );
            Ok(())
        });
    }

    #[test]
    fn environment_overrides_the_file() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "cc.toml",
                r#"
                listen = "127.0.0.1:1234"
                storage = "./data"
                [secrets]
                server = "from-file"
                [limits]
                body_bytes = 1024
                request_seconds = 30
                session_hours = 1
                authorization_minutes = 5
                "#,
            )?;
            jail.set_env("CC_LISTEN", "127.0.0.1:4321");
            assert_eq!(
                Config::load(Some("cc.toml")).unwrap().listen().port(),
                4321,
                "переменная окружения не перекрыла значение из файла"
            );
            Ok(())
        });
    }

    #[test]
    fn file_supplies_what_environment_omits() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "cc.toml",
                r#"
                listen = "127.0.0.1:1234"
                storage = "./data"
                [secrets]
                server = "from-file"
                [limits]
                body_bytes = 1024
                request_seconds = 30
                session_hours = 1
                authorization_minutes = 5
                "#,
            )?;
            jail.set_env("CC_LISTEN", "127.0.0.1:4321");
            assert_eq!(
                Config::load(Some("cc.toml")).unwrap().limits().body_bytes(),
                1024,
                "значение, заданное только в файле, потеряно"
            );
            Ok(())
        });
    }

    #[test]
    fn provider_settings_are_not_printed() {
        let app = VkApp {
            client: "52000000".to_owned(),
            secret: "s3cret".to_owned(),
            redirect: "https://cstore.example/auth/vk/callback".to_owned(),
        };
        assert_eq!(
            format!("{app:?}"),
            "VkApp([REDACTED])",
            "отладочный вывод раскрыл секрет приложения провайдера"
        );
    }

    #[test]
    fn bot_token_is_not_printed() {
        let bot = TelegramBot {
            token: "123456:ABC".to_owned(),
        };
        assert_eq!(
            format!("{bot:?}"),
            "TelegramBot([REDACTED])",
            "отладочный вывод раскрыл токен бота"
        );
    }

    #[test]
    fn secrets_are_not_printed() {
        let secrets = Secrets {
            server: "s3cret".to_owned(),
            vk: None,
            telegram: None,
        };
        assert_eq!(
            format!("{secrets:?}"),
            "Secrets([REDACTED])",
            "отладочный вывод раскрыл серверный секрет"
        );
    }
}
