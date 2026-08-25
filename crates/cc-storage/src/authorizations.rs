//! Запросы авторизации у внешнего провайдера.
//!
//! Запрос одноразовый, живёт минуты и привязан к клиенту, начавшему процедуру
//! (`TODO.md`, раздел 4.3). Секрет PKCE и признак запроса сервер не отдаёт
//! никому: наружу уходит только билет, по которому провайдер вернёт ответ.

use crate::error::{Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cc_crypto::{sha256, ContentKey};
use cc_domain::Provider;
use std::collections::HashMap;
use time::{Duration, OffsetDateTime};
use tokio::sync::RwLock;

/// Наименьшая длина секрета PKCE, RFC 7636, раздел 4.1.
const VERIFIER_MIN: usize = 43;

/// Наибольшая длина секрета PKCE, RFC 7636, раздел 4.1.
const VERIFIER_MAX: usize = 128;

/// Секрет PKCE.
///
/// Значение остаётся на сервере: провайдеру уходит только его хеш, и код
/// авторизации, перехваченный по дороге, без секрета обменять нельзя.
#[derive(Clone)]
pub struct Pkce(String);

impl core::fmt::Debug for Pkce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Pkce([REDACTED])")
    }
}

impl Pkce {
    /// Принимает готовый секрет, проверяя его на соответствие RFC 7636.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если длина вне предела либо встретился символ вне
    /// множества `unreserved`.
    pub fn new(verifier: impl Into<String>) -> Result<Self> {
        let verifier = verifier.into();
        let allowed = |symbol: char| {
            symbol.is_ascii_alphanumeric() || matches!(symbol, '-' | '.' | '_' | '~')
        };
        if !(VERIFIER_MIN..=VERIFIER_MAX).contains(&verifier.len())
            || !verifier.chars().all(allowed)
        {
            return Err(Error::Malformed);
        }
        Ok(Self(verifier))
    }

    /// Порождает секрет из источника случайности операционной системы.
    ///
    /// # Panics
    ///
    /// Не паникует: 32 случайных байта в записи `base64url` дают ровно 43
    /// допустимых символа.
    #[allow(
        clippy::expect_used,
        reason = "длина и алфавит результата base64url заданы длиной входа"
    )]
    #[must_use]
    pub fn generate() -> Self {
        Self::new(URL_SAFE_NO_PAD.encode(ContentKey::generate().expose()))
            .expect("INVARIANT: 32 байта в записи base64url дают 43 допустимых символа")
    }

    /// Отдаёт секрет — только для обмена кода на токен, только на сервере.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Вычисляет `code_challenge` метода `S256`, RFC 7636, раздел 4.2.
    #[must_use]
    pub fn challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(sha256(self.0.as_bytes()))
    }
}

/// Билет запроса авторизации — параметр `state`.
///
/// Случайный, одноразовый и с коротким сроком жизни: ответ провайдера без
/// совпадения билета отвергается.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ticket(String);

impl Ticket {
    /// Порождает билет.
    #[must_use]
    pub fn generate() -> Self {
        Self(URL_SAFE_NO_PAD.encode(ContentKey::generate().expose()))
    }

    /// Восстанавливает билет из предъявленного значения.
    #[must_use]
    pub fn presented(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Отдаёт билет: он уходит провайдеру и возвращается от него.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Ticket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Начатый запрос авторизации.
#[derive(Clone, Debug)]
pub struct Authorization {
    provider: Provider,
    pkce: Pkce,
    client: String,
    deadline: OffsetDateTime,
}

impl Authorization {
    /// Провайдер, у которого начата процедура.
    #[must_use]
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    /// Секрет PKCE запроса.
    #[must_use]
    pub const fn pkce(&self) -> &Pkce {
        &self.pkce
    }

    /// Отпечаток клиента, начавшего процедуру.
    #[must_use]
    pub fn client(&self) -> &str {
        &self.client
    }

    /// Момент, после которого запрос недействителен.
    #[must_use]
    pub const fn deadline(&self) -> OffsetDateTime {
        self.deadline
    }
}

/// Запросы авторизации, хранимые в памяти процесса.
///
/// Реализация временная: данные не переживают перезапуск. Постоянное хранилище
/// вводит TASK-018.
#[derive(Debug)]
pub struct Authorizations {
    by_ticket: RwLock<HashMap<Ticket, Authorization>>,
    lifetime: Duration,
}

impl Authorizations {
    /// Заводит пустое хранилище с заданным сроком жизни запроса.
    #[must_use]
    pub fn new(lifetime: Duration) -> Self {
        Self {
            by_ticket: RwLock::new(HashMap::new()),
            lifetime,
        }
    }

    /// Начинает запрос авторизации и возвращает его билет.
    pub async fn start(
        &self,
        provider: Provider,
        client: impl Into<String>,
        now: OffsetDateTime,
    ) -> (Ticket, Authorization) {
        let ticket = Ticket::generate();
        let authorization = Authorization {
            provider,
            pkce: Pkce::generate(),
            client: client.into(),
            deadline: now + self.lifetime,
        };
        let mut requests = self.by_ticket.write().await;
        requests.insert(ticket.clone(), authorization.clone());
        drop(requests);
        (ticket, authorization)
    }

    /// Изымает запрос по билету.
    ///
    /// Запрос одноразовый: удачное изъятие удаляет его, и повторный ответ
    /// провайдера с тем же билетом уже ничего не найдёт.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`], если билет неизвестен, просрочен либо предъявлен не
    /// тем клиентом. Различать эти случаи наружу нельзя: ответ работал бы
    /// оракулом чужих запросов.
    pub async fn claim(
        &self,
        ticket: &Ticket,
        client: &str,
        now: OffsetDateTime,
    ) -> Result<Authorization> {
        let mut requests = self.by_ticket.write().await;
        let found = requests.remove(ticket);
        drop(requests);
        let Some(authorization) = found else {
            return Err(Error::Missing);
        };
        if authorization.deadline <= now || authorization.client != client {
            return Err(Error::Missing);
        }
        Ok(authorization)
    }

    /// Убирает просроченные запросы.
    pub async fn sweep(&self, now: OffsetDateTime) {
        self.by_ticket
            .write()
            .await
            .retain(|_, request| request.deadline > now);
    }
}
