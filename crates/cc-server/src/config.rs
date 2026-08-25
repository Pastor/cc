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
}

/// Пределы, применяемые к запросам.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct Limits {
    body_bytes: usize,
    request_seconds: u64,
    session_hours: i64,
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
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::result_large_err,
        reason = "в тесте отказ обязан ронять тест; размер ошибки figment::Jail нам не подконтролен"
    )]

    use super::{Config, Secrets};

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
    fn secrets_are_not_printed() {
        let secrets = Secrets {
            server: "s3cret".to_owned(),
        };
        assert_eq!(
            format!("{secrets:?}"),
            "Secrets([REDACTED])",
            "отладочный вывод раскрыл серверный секрет"
        );
    }
}
