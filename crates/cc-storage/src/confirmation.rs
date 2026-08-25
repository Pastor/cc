//! Подтверждение почты одноразовым кодом.

use crate::error::{Error, Result};
use cc_crypto::CiphertextHash;
use cc_domain::Username;
use std::collections::HashMap;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

/// Наибольшее число попыток ввести код.
pub const MAX_ATTEMPTS: u8 = 5;

/// Срок жизни кода подтверждения.
pub const LIFETIME: Duration = Duration::minutes(30);

/// Ожидающее подтверждение.
#[derive(Clone, Debug)]
struct Pending {
    digest: [u8; 32],
    expires_at: OffsetDateTime,
    attempts: u8,
}

/// Коды подтверждения почты.
///
/// Код хранится хешем: утечка базы не должна давать возможность подтвердить
/// чужую почту. Число попыток ограничено, иначе шестизначный код подбирается
/// перебором за минуты.
#[derive(Debug)]
pub struct Confirmations {
    pending: Mutex<HashMap<Username, Pending>>,
}

impl Confirmations {
    /// Заводит пустой набор.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Запоминает код, вытесняя прежний для того же логина.
    ///
    /// Сам код не хранится: вызывающий отправляет его пользователю и забывает.
    pub async fn issue(&self, login: Username, code: &str, now: OffsetDateTime) {
        let pending = Pending {
            digest: *CiphertextHash::of(code.as_bytes()).as_bytes(),
            expires_at: now + LIFETIME,
            attempts: 0,
        };
        let mut codes = self.pending.lock().await;
        codes.insert(login, pending);
        drop(codes);
    }

    /// Сверяет предъявленный код.
    ///
    /// Успешная сверка удаляет запись: код одноразовый.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] — кода нет, он истёк, попытки исчерпаны либо код не
    /// совпал. Причина наружу не раскрывается: различие подсказывало бы
    /// подбирающему, насколько он близок.
    pub async fn confirm(&self, login: &Username, code: &str, now: OffsetDateTime) -> Result<()> {
        let digest = *CiphertextHash::of(code.as_bytes()).as_bytes();
        let mut codes = self.pending.lock().await;
        let Some(pending) = codes.get_mut(login) else {
            return Err(Error::Missing);
        };
        if now >= pending.expires_at || pending.attempts >= MAX_ATTEMPTS {
            codes.remove(login);
            drop(codes);
            return Err(Error::Missing);
        }
        if pending.digest != digest {
            pending.attempts += 1;
            drop(codes);
            return Err(Error::Missing);
        }
        codes.remove(login);
        drop(codes);
        Ok(())
    }
}

impl Default for Confirmations {
    fn default() -> Self {
        Self::new()
    }
}
