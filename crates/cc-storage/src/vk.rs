//! Вход через VK ID.
//!
//! Порядок — authorization code с PKCE `S256` по OAuth 2.1: implicit и вход по
//! паролю запрещены моделью (`TODO.md`, раздел 4.3). Обмен кода на токен
//! выполняется только сервером, секрет приложения на клиент не попадает.

use crate::authorizations::Pkce;
use crate::entrance::Entrance;
use crate::error::{Error, Result};
use cc_domain::{ExternalIdentity, Provider};
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;
use time::OffsetDateTime;

/// Адрес, по которому VK ID принимает запрос авторизации.
pub const AUTHORIZE: &str = "https://id.vk.com/authorize";

/// Адрес, по которому VK ID меняет код на токен.
pub const TOKEN: &str = "https://id.vk.com/oauth2/auth";

/// Ответ провайдера на обмен кода.
///
/// Наружу из обмена нужен только идентификатор пользователя: токен доступа
/// сервер не хранит и не использует — файлы он выдаёт по своей сессии, а не по
/// чужому токену.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject(String);

impl Subject {
    /// Принимает идентификатор, проверяя, что он не пуст.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если провайдер вернул пустой идентификатор.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self(value))
    }

    /// Отдаёт идентификатор.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// Обмен кода авторизации на идентификатор пользователя.
///
/// Отделён от проверок, чтобы сетевой обмен подменялся в тестах: интернета у
/// них нет, а проверить надо именно проверки.
pub trait Exchange: fmt::Debug + Send + Sync {
    /// Меняет код авторизации на идентификатор пользователя.
    ///
    /// # Errors
    ///
    /// Отказ провайдера либо неразбираемый ответ.
    fn exchange<'a>(
        &'a self,
        code: &'a str,
        pkce: &'a Pkce,
    ) -> Pin<Box<dyn Future<Output = Result<Subject>> + Send + 'a>>;
}

/// Код авторизации, вернувшийся от провайдера.
#[derive(Clone, Debug)]
pub struct Code {
    code: String,
    pkce: Pkce,
}

impl Code {
    /// Собирает артефакты обмена: код от провайдера и секрет своего запроса.
    #[must_use]
    pub const fn new(code: String, pkce: Pkce) -> Self {
        Self { code, pkce }
    }
}

/// Вход через VK ID.
#[derive(Clone, Debug)]
pub struct Vk {
    client: String,
    redirect: String,
    exchange: Arc<dyn Exchange>,
}

impl Vk {
    /// Заводит вход с идентификатором приложения, адресом возврата и обменом.
    ///
    /// Адрес возврата хранится здесь, а не в запросе авторизации: сравнивать
    /// его надо с тем, что задано конфигурацией, а не с тем, что вернулось.
    #[must_use]
    pub fn new(
        client: impl Into<String>,
        redirect: impl Into<String>,
        exchange: Arc<dyn Exchange>,
    ) -> Self {
        Self {
            client: client.into(),
            redirect: redirect.into(),
            exchange,
        }
    }

    /// Собирает адрес, по которому клиент проходит процедуру провайдера.
    #[must_use]
    pub fn authorization(&self, ticket: &str, pkce: &Pkce) -> String {
        let query = [
            ("response_type", "code"),
            ("client_id", &self.client),
            ("redirect_uri", &self.redirect),
            ("state", ticket),
            ("code_challenge", &pkce.challenge()),
            ("code_challenge_method", "S256"),
        ]
        .iter()
        .map(|(name, value)| format!("{name}={}", escape(value)))
        .collect::<Vec<_>>()
        .join("&");
        format!("{AUTHORIZE}?{query}")
    }

    /// Сверяет адрес возврата, вернувшийся от провайдера, с заданным.
    ///
    /// Сравнение целиком и посимвольно: сравнение по префиксу — известный
    /// способ увести код авторизации на чужой адрес.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если адрес отличается хоть одним символом.
    pub fn redirected(&self, presented: &str) -> Result<()> {
        if presented == self.redirect {
            return Ok(());
        }
        Err(Error::Malformed)
    }
}

impl Entrance for Vk {
    type Artifacts = Code;

    /// Меняет код авторизации на личность пользователя у провайдера.
    ///
    /// # Errors
    ///
    /// Отказ провайдера, неразбираемый ответ либо пустой идентификатор.
    async fn identity(&self, artifacts: Code, _now: OffsetDateTime) -> Result<ExternalIdentity> {
        let subject = self
            .exchange
            .exchange(&artifacts.code, &artifacts.pkce)
            .await?;
        ExternalIdentity::new(Provider::Vk, subject.expose()).map_err(|_| Error::Malformed)
    }
}

/// Кодирует значение для строки запроса.
///
/// Множество незакодированных символов — `unreserved` из RFC 3986: всё
/// остальное уходит в проценты, включая двоеточие и косую черту адреса
/// возврата.
fn escape(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}
