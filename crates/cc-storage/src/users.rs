//! Хранилище пользователей.

use crate::credentials::{Challenge, Credentials, Registration, Wrapped};
use crate::error::{Error, Result};
use cc_crypto::{decoy_salt, AuthHash, KdfParams, Salt, StoredAuth};
use cc_domain::{User, UserId, Username};
use std::collections::HashMap;
use time::OffsetDateTime;
use tokio::sync::RwLock;

/// Запись о пользователе: учётная запись и её учётные данные.
#[derive(Clone, Debug)]
struct Record {
    user: User,
    credentials: Credentials,
}

/// Пользователи, хранимые в памяти процесса.
///
/// Реализация временная: данные не переживают перезапуск. Постоянное хранилище
/// вводит TASK-018 — до тех пор этот тип позволяет собрать и проверить всё
/// остальное.
///
/// В отличие от прежней реализации, где пользователи лежали в незащищённой
/// `HashMap`, проверка занятости логина и вставка выполняются под одной
/// блокировкой и потому атомарны.
#[derive(Debug)]
pub struct Users {
    records: RwLock<HashMap<Username, Record>>,
    secret: Vec<u8>,
    hardening: KdfParams,
}

impl Users {
    /// Заводит пустое хранилище.
    ///
    /// `secret` — серверный секрет, из которого выводится правдоподобная соль
    /// для неизвестных логинов. `hardening` — параметры Argon2id, которыми
    /// сервер укрепляет аутентификационный хеш перед хранением.
    #[must_use]
    pub fn new(secret: Vec<u8>, hardening: KdfParams) -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            secret,
            hardening,
        }
    }

    /// Регистрирует пользователя.
    ///
    /// Сервер не интерпретирует присланное: соль, параметры, обёртки и открытый
    /// ключ он сохраняет как есть. Требования к паролю проверяет клиент — сервер
    /// пароля не видит и проверить их не может.
    ///
    /// # Errors
    ///
    /// - [`Error::LoginTaken`] — логин уже занят;
    /// - [`Error::Crypto`] — укрепление аутентификационного хеша не удалось.
    pub async fn register(
        &self,
        login: Username,
        auth: &AuthHash,
        registration: Registration,
        now: OffsetDateTime,
    ) -> Result<User> {
        let stored = self.harden(auth)?;
        let user = User::new(UserId::generate(), login.clone(), now);
        let record = Record {
            user: user.clone(),
            credentials: Credentials::new(
                registration.challenge().clone(),
                stored,
                *registration.public(),
                registration.wrapped().clone(),
                *registration.recovery(),
            ),
        };
        {
            let mut records = self.records.write().await;
            if records.contains_key(&login) {
                return Err(Error::LoginTaken);
            }
            records.insert(login, record);
        }
        Ok(user)
    }

    /// Отдаёт параметры выведения ключа по логину.
    ///
    /// Для неизвестного логина возвращает правдоподобные детерминированные
    /// значения: ответ обязан быть неотличим от ответа по существующему логину.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`], если вывести правдоподобную соль не удалось.
    pub async fn challenge(&self, login: &Username) -> Result<Challenge> {
        let known = {
            let records = self.records.read().await;
            records
                .get(login)
                .map(|record| record.credentials.challenge().clone())
        };
        if let Some(challenge) = known {
            return Ok(challenge);
        }
        let salt = decoy_salt(&self.secret, login.as_str().as_bytes())?;
        Ok(Challenge::new(salt, self.hardening))
    }

    /// Сверяет аутентификационный хеш и возвращает пользователя с обёртками.
    ///
    /// Отказ единообразен для неизвестного логина и неверного хеша: различие
    /// сделало бы API оракулом существования учётных записей.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] — логин неизвестен либо хеш не сошёлся.
    pub async fn authenticate(&self, login: &Username, auth: &AuthHash) -> Result<(User, Wrapped)> {
        let presented = self.harden(auth)?;
        let found = {
            let records = self.records.read().await;
            records.get(login).and_then(|record| {
                record
                    .credentials
                    .stored()
                    .matches(&presented)
                    .then(|| (record.user.clone(), record.credentials.wrapped().clone()))
            })
        };
        found.ok_or(Error::Missing)
    }

    /// Меняет пароль: заменяет соль, хранимый хеш и парольную обёртку.
    ///
    /// Подтверждается прежним аутентификационным хешем.
    ///
    /// # Errors
    ///
    /// - [`Error::Missing`] — логин неизвестен либо прежний хеш не сошёлся;
    /// - [`Error::Crypto`] — укрепление нового хеша не удалось.
    pub async fn change_password(
        &self,
        login: &Username,
        current: &AuthHash,
        challenge: Challenge,
        next: &AuthHash,
        account_by_password: Vec<u8>,
    ) -> Result<()> {
        let presented = self.harden(current)?;
        let stored = self.harden(next)?;
        let mut records = self.records.write().await;
        let Some(record) = records.get_mut(login) else {
            return Err(Error::Missing);
        };
        if !record.credentials.stored().matches(&presented) {
            return Err(Error::Missing);
        }
        let wrapped = record
            .credentials
            .wrapped()
            .clone()
            .rewrapped(account_by_password);
        record.credentials = record
            .credentials
            .clone()
            .with_password(challenge, stored, wrapped);
        drop(records);
        Ok(())
    }

    /// Находит пользователя по идентификатору.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`], если такого пользователя нет.
    pub async fn by_id(&self, id: cc_domain::UserId) -> Result<User> {
        let found = {
            let records = self.records.read().await;
            records
                .values()
                .find(|record| record.user.id() == id)
                .map(|record| record.user.clone())
        };
        found.ok_or(Error::Missing)
    }

    /// Гасит использованный ключ восстановления, принимая новый.
    ///
    /// Ключ восстановления одноразовый: он мог быть подсмотрен в момент ввода,
    /// поэтому после успешного восстановления выдаётся новый.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] — логин неизвестен либо предъявлен не тот отпечаток.
    pub async fn rotate_recovery(
        &self,
        login: &Username,
        presented: &[u8; 32],
        account_by_recovery: Vec<u8>,
        recovery: [u8; 32],
    ) -> Result<()> {
        let mut records = self.records.write().await;
        let Some(record) = records.get_mut(login) else {
            return Err(Error::Missing);
        };
        if record.credentials.recovery() != presented {
            return Err(Error::Missing);
        }
        let wrapped = record
            .credentials
            .wrapped()
            .clone()
            .re_recovered(account_by_recovery);
        record.credentials = record.credentials.clone().with_recovery(wrapped, recovery);
        drop(records);
        Ok(())
    }

    /// Отдаёт открытый ключ пользователя — по нему выдают ему доступ.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`], если логин неизвестен.
    pub async fn public_key(&self, login: &Username) -> Result<cc_crypto::PublicKey> {
        let found = {
            let records = self.records.read().await;
            records
                .get(login)
                .map(|record| *record.credentials.public())
        };
        found.ok_or(Error::Missing)
    }

    /// Число зарегистрированных пользователей.
    pub async fn count(&self) -> usize {
        let records = self.records.read().await;
        records.len()
    }

    /// Укрепляет аутентификационный хеш серверной солью.
    fn harden(&self, auth: &AuthHash) -> Result<StoredAuth> {
        let salt = Salt::new(self.secret.clone())?;
        Ok(StoredAuth::of(auth, &salt, self.hardening)?)
    }
}
