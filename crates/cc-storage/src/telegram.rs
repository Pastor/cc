//! Вход через Telegram.
//!
//! `OAuth2` у Telegram нет: виджет отдаёт набор полей, подписанных ключом,
//! выведенным из токена бота. Порядок проверки задан документацией провайдера
//! и повторён здесь дословно (`TODO.md`, раздел 4.3).

use crate::entrance::Entrance;
use crate::error::{Error, Result};
use cc_crypto::{sha256, Signature};
use cc_domain::{ExternalIdentity, Provider};
use std::collections::{BTreeMap, HashSet};
use time::{Duration, OffsetDateTime};
use tokio::sync::RwLock;

/// Поле с идентификатором пользователя.
const ID: &str = "id";

/// Поле с моментом входа.
const AUTH_DATE: &str = "auth_date";

/// Поле с подписью.
const HASH: &str = "hash";

/// Подписанные данные виджета.
///
/// Хранится всё присланное: подпись считается по всем полям, кроме самой
/// подписи, и выбрасывание незнакомого поля её сломает.
#[derive(Clone, Debug)]
pub struct Widget {
    fields: BTreeMap<String, String>,
}

impl Widget {
    /// Принимает поля виджета, проверяя обязательные.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если нет идентификатора, момента входа или
    /// подписи, либо момент входа не число.
    pub fn new(fields: BTreeMap<String, String>) -> Result<Self> {
        let required = [ID, AUTH_DATE, HASH]
            .iter()
            .all(|name| fields.contains_key(*name));
        let widget = Self { fields };
        if !required || widget.moment().is_err() {
            return Err(Error::Malformed);
        }
        Ok(widget)
    }

    /// Идентификатор пользователя у провайдера.
    fn subject(&self) -> &str {
        self.fields.get(ID).map_or("", String::as_str)
    }

    /// Момент, которым провайдер датировал вход.
    fn moment(&self) -> Result<OffsetDateTime> {
        let seconds: i64 = self
            .fields
            .get(AUTH_DATE)
            .ok_or(Error::Malformed)?
            .parse()
            .map_err(|_| Error::Malformed)?;
        OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| Error::Malformed)
    }

    /// Предъявленная подпись.
    fn presented(&self) -> Result<[u8; 32]> {
        let text = self.fields.get(HASH).ok_or(Error::Malformed)?;
        let mut bytes = [0_u8; 32];
        if text.len() != bytes.len() * 2 {
            return Err(Error::Malformed);
        }
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = u8::from_str_radix(
                text.get(index * 2..index * 2 + 2).ok_or(Error::Malformed)?,
                16,
            )
            .map_err(|_| Error::Malformed)?;
        }
        Ok(bytes)
    }

    /// Собирает строку проверки: поля, кроме подписи, отсортированные по имени.
    ///
    /// Порядок обеспечен самим хранилищем полей, а не сортировкой на месте:
    /// забытая сортировка ломает проверку молча.
    fn checked(&self) -> String {
        self.fields
            .iter()
            .filter(|(name, _)| name.as_str() != HASH)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Вход через Telegram.
///
/// Токен бота — секрет уровня закрытого ключа: сюда он приходит из
/// конфигурации и наружу не отдаётся ни в каком виде.
#[derive(Debug)]
pub struct Telegram {
    secret: [u8; 32],
    window: Duration,
    seen: RwLock<HashSet<(String, i64)>>,
}

impl Telegram {
    /// Заводит вход с токеном бота и окном свежести данных.
    #[must_use]
    pub fn new(token: &str, window: Duration) -> Self {
        Self {
            secret: sha256(token.as_bytes()),
            window,
            seen: RwLock::new(HashSet::new()),
        }
    }

    /// Запоминает предъявленные данные, отвечая, встречались ли они раньше.
    async fn remember(&self, subject: &str, moment: OffsetDateTime) -> bool {
        let mut seen = self.seen.write().await;
        let fresh = seen.insert((subject.to_owned(), moment.unix_timestamp()));
        drop(seen);
        fresh
    }

    /// Забывает данные, вышедшие из окна свежести.
    pub async fn sweep(&self, now: OffsetDateTime) {
        let horizon = (now - self.window).unix_timestamp();
        self.seen.write().await.retain(|(_, at)| *at > horizon);
    }
}

impl Entrance for Telegram {
    type Artifacts = Widget;

    /// Проверяет подпись, свежесть и неповторность данных виджета.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] — подпись не сошлась;
    /// - [`Error::Stale`] — данные старше окна свежести либо датированы будущим;
    /// - [`Error::Replay`] — те же данные уже предъявлялись;
    /// - [`Error::Malformed`] — обязательных полей нет.
    async fn identity(&self, widget: Widget, now: OffsetDateTime) -> Result<ExternalIdentity> {
        let presented = widget.presented()?;
        if !Signature::of(&self.secret, widget.checked().as_bytes()).matches(&presented) {
            return Err(Error::Signature);
        }
        let moment = widget.moment()?;
        if moment > now || now - moment > self.window {
            return Err(Error::Stale);
        }
        if !self.remember(widget.subject(), moment).await {
            return Err(Error::Replay);
        }
        ExternalIdentity::new(Provider::Telegram, widget.subject()).map_err(|_| Error::Malformed)
    }
}
