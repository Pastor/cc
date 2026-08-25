//! Хранилище сессий.
//!
//! Сессии индексируются по отпечатку токена: проверка — одно обращение к карте,
//! а не три линейных прохода, как в прежней реализации.

use crate::error::{Error, Result};
use cc_crypto::CiphertextHash;
use cc_domain::{Scope, Session, SessionId, Timing, UserId};
use std::collections::HashMap;
use subtle::ConstantTimeEq as _;
use time::{Duration, OffsetDateTime};
use tokio::sync::RwLock;

/// Длина токена в байтах.
const TOKEN_LEN: usize = 32;

/// Сессионный токен.
///
/// Значение существует только в ответе на вход: сервер хранит его отпечаток и
/// вернуть токен не может.
#[derive(Clone)]
pub struct Token([u8; TOKEN_LEN]);

impl core::fmt::Debug for Token {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Token([REDACTED])")
    }
}

impl Token {
    /// Порождает токен.
    #[must_use]
    pub fn generate() -> Self {
        Self(*cc_crypto::ContentKey::generate().expose())
    }

    /// Восстанавливает токен из предъявленного значения.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`], если длина значения не та: подробности наружу не
    /// раскрываются.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: [u8; TOKEN_LEN] = bytes.try_into().map_err(|_| Error::Missing)?;
        Ok(Self(value))
    }

    /// Отдаёт токен — единственный раз, в ответе на вход.
    #[must_use]
    pub const fn expose(&self) -> &[u8; TOKEN_LEN] {
        &self.0
    }

    /// Вычисляет отпечаток для хранения.
    #[must_use]
    fn digest(&self) -> [u8; 32] {
        *CiphertextHash::of(&self.0).as_bytes()
    }
}

/// Сессии, хранимые в памяти процесса.
///
/// Реализация временная — постоянное хранилище вводит TASK-018.
#[derive(Debug)]
pub struct Sessions {
    by_digest: RwLock<HashMap<[u8; 32], Session>>,
    lifetime: Duration,
}

impl Sessions {
    /// Заводит пустое хранилище с заданным сроком жизни сессии.
    ///
    /// Срок задаётся вызывающим, а не константой в коде.
    #[must_use]
    pub fn new(lifetime: Duration) -> Self {
        Self {
            by_digest: RwLock::new(HashMap::new()),
            lifetime,
        }
    }

    /// Открывает сессию и возвращает токен вместе с ней.
    ///
    /// Каждый вход выпускает новую сессию: прежняя реализация возвращала старый
    /// токен, игнорируя запрошенный набор прав.
    pub async fn open(&self, user: UserId, scope: Scope, now: OffsetDateTime) -> (Token, Session) {
        let token = Token::generate();
        let session = Session::new(
            SessionId::generate(),
            user,
            scope,
            Timing::new(now, now + self.lifetime),
        );
        let mut sessions = self.by_digest.write().await;
        sessions.insert(token.digest(), session);
        drop(sessions);
        (token, session)
    }

    /// Находит действующую сессию по предъявленному токену.
    ///
    /// Одно обращение вместо трёх проверок подряд: между ними состояние могло
    /// измениться, и прежняя реализация отвечала на это `500`.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] — токен неизвестен либо сессия истекла. Причина
    /// наружу не раскрывается.
    pub async fn resolve(&self, token: &Token, now: OffsetDateTime) -> Result<Session> {
        let digest = token.digest();
        let mut sessions = self.by_digest.write().await;
        let Some(session) = sessions.get(&digest).copied() else {
            return Err(Error::Missing);
        };
        if session.timing().expired_at(now) {
            sessions.remove(&digest);
            drop(sessions);
            return Err(Error::Missing);
        }
        let touched = session.touched(now);
        sessions.insert(digest, touched);
        drop(sessions);
        Ok(touched)
    }

    /// Закрывает сессию по токену.
    ///
    /// Идемпотентно: повторный выход успешен.
    pub async fn close(&self, token: &Token) {
        let mut sessions = self.by_digest.write().await;
        sessions.remove(&token.digest());
        drop(sessions);
    }

    /// Закрывает конкретную сессию пользователя.
    ///
    /// Чужую сессию закрыть нельзя: проверка по пользователю обязательна.
    pub async fn close_by_id(&self, user: UserId, target: SessionId) {
        let mut sessions = self.by_digest.write().await;
        sessions.retain(|_, session| session.user() != user || session.id() != target);
        drop(sessions);
    }

    /// Закрывает все сессии пользователя, кроме указанной.
    ///
    /// Применяется при смене пароля: прочие устройства обязаны войти заново.
    pub async fn close_others(&self, user: UserId, keep: SessionId) {
        let mut sessions = self.by_digest.write().await;
        sessions.retain(|_, session| session.user() != user || session.id() == keep);
        drop(sessions);
    }

    /// Удаляет истёкшие сессии и возвращает их число.
    ///
    /// Вызывается фоновой задачей: чистка не должна быть потоком со `sleep`,
    /// который никто не останавливает.
    pub async fn sweep(&self, now: OffsetDateTime) -> usize {
        let mut sessions = self.by_digest.write().await;
        let before = sessions.len();
        sessions.retain(|_, session| !session.timing().expired_at(now));
        let removed = before - sessions.len();
        drop(sessions);
        removed
    }

    /// Число хранимых сессий.
    pub async fn count(&self) -> usize {
        let sessions = self.by_digest.read().await;
        sessions.len()
    }

    /// Запускает фоновую чистку истёкших сессий.
    ///
    /// Задача уважает отмену: получив сигнал, она завершается, а не остаётся
    /// висеть до конца процесса. Прежняя реализация крутила поток со `sleep`,
    /// который никто не останавливал.
    ///
    /// Возвращённый `JoinHandle` обязан быть дождан при остановке сервера:
    /// брошенная задача переживает graceful shutdown.
    #[must_use]
    pub fn sweeper(
        store: std::sync::Arc<Self>,
        period: Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let period = period
            .try_into()
            .unwrap_or(core::time::Duration::from_secs(60));
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(period);
            loop {
                tokio::select! {
                    _ = ticks.tick() => {
                        store.sweep(OffsetDateTime::now_utc()).await;
                    }
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Сверяет два токена в постоянном времени.
    #[must_use]
    pub fn same(left: &Token, right: &Token) -> bool {
        left.0.ct_eq(&right.0).into()
    }
}
