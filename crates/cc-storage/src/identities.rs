//! Привязки внешних личностей к учётным записям.
//!
//! Личность привязывается только из уже аутентифицированной сессии: связывание
//! по совпадению почты запрещено моделью (`TODO.md`, раздел 4.3). Учётная
//! запись через внешний вход не создаётся — здесь хранится лишь соответствие
//! уже существующей записи и личности у провайдера.

use crate::error::{Error, Result};
use cc_domain::{ExternalIdentity, UserId};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Привязки, хранимые в памяти процесса.
///
/// Реализация временная: данные не переживают перезапуск. Постоянное хранилище
/// вводит TASK-018.
#[derive(Debug, Default)]
pub struct Identities {
    by_identity: RwLock<HashMap<ExternalIdentity, UserId>>,
}

impl Identities {
    /// Заводит пустое хранилище.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Привязывает личность к учётной записи.
    ///
    /// Повторная привязка той же личности к той же записи успешна: операция
    /// идемпотентна. Проверка занятости и вставка идут под одной блокировкой,
    /// поэтому две одновременные привязки не разойдутся.
    ///
    /// # Errors
    ///
    /// [`Error::IdentityTaken`], если личность уже привязана к другой записи.
    #[tracing::instrument(skip(self), fields(identity = %identity, user = %user), err)]
    pub async fn link(&self, identity: ExternalIdentity, user: UserId) -> Result<()> {
        let mut links = self.by_identity.write().await;
        let outcome = match links.get(&identity) {
            Some(owner) if *owner == user => Ok(()),
            Some(_) => Err(Error::IdentityTaken),
            None => {
                links.insert(identity, user);
                Ok(())
            }
        };
        drop(links);
        outcome
    }

    /// Находит учётную запись по внешней личности.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`], если личность никому не привязана. Отличить её от
    /// личности, привязанной к чужой записи, отсюда нельзя — и не нужно.
    pub async fn resolve(&self, identity: &ExternalIdentity) -> Result<UserId> {
        self.by_identity
            .read()
            .await
            .get(identity)
            .copied()
            .ok_or(Error::Missing)
    }

    /// Снимает привязку личности с учётной записи.
    ///
    /// Пароль остаётся способом входа при любой отвязке: учётная запись без
    /// пароля не заводится вовсе, поэтому снятие внешней личности не может
    /// оставить запись без входа (`TODO.md`, раздел 4.3).
    ///
    /// # Errors
    ///
    /// [`Error::Missing`], если личность не привязана к этой записи.
    #[tracing::instrument(skip(self), fields(identity = %identity, user = %user), err)]
    pub async fn unlink(&self, identity: &ExternalIdentity, user: UserId) -> Result<()> {
        let mut links = self.by_identity.write().await;
        let outcome = match links.get(identity) {
            Some(owner) if *owner == user => {
                links.remove(identity);
                Ok(())
            }
            _ => Err(Error::Missing),
        };
        drop(links);
        outcome
    }

    /// Перечисляет личности учётной записи.
    pub async fn of(&self, user: UserId) -> Vec<ExternalIdentity> {
        let links = self.by_identity.read().await;
        let mut found: Vec<ExternalIdentity> = links
            .iter()
            .filter(|(_, owner)| **owner == user)
            .map(|(identity, _)| identity.clone())
            .collect();
        drop(links);
        found.sort();
        found
    }
}
