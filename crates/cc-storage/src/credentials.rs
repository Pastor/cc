//! Учётные данные, хранимые сервером.

use cc_crypto::{KdfParams, PublicKey, Salt, StoredAuth};

/// Параметры выведения ключа, отдаваемые клиенту перед входом.
///
/// Отдаются по любому логину — и существующему, и нет: иначе метод работает
/// оракулом существования учётных записей (`TODO.md`, раздел 4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    salt: Salt,
    params: KdfParams,
}

impl Challenge {
    /// Собирает параметры.
    #[must_use]
    pub const fn new(salt: Salt, params: KdfParams) -> Self {
        Self { salt, params }
    }

    /// Соль пользователя.
    #[must_use]
    pub const fn salt(&self) -> &Salt {
        &self.salt
    }

    /// Параметры Argon2id.
    #[must_use]
    pub const fn params(&self) -> KdfParams {
        self.params
    }
}

/// Обёртки ключей, хранимые сервером.
///
/// Развернуть их сервер не может: ключей у него нет.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wrapped {
    account_by_password: Vec<u8>,
    account_by_recovery: Vec<u8>,
    private_by_account: Vec<u8>,
}

impl Wrapped {
    /// Собирает обёртки, присланные клиентом.
    #[must_use]
    pub const fn new(
        account_by_password: Vec<u8>,
        account_by_recovery: Vec<u8>,
        private_by_account: Vec<u8>,
    ) -> Self {
        Self {
            account_by_password,
            account_by_recovery,
            private_by_account,
        }
    }

    /// Ключ учётной записи под ключом шифрования, выведенным из пароля.
    #[must_use]
    pub fn account_by_password(&self) -> &[u8] {
        &self.account_by_password
    }

    /// Ключ учётной записи под ключом восстановления.
    #[must_use]
    pub fn account_by_recovery(&self) -> &[u8] {
        &self.account_by_recovery
    }

    /// Закрытый ключ пользователя под ключом учётной записи.
    #[must_use]
    pub fn private_by_account(&self) -> &[u8] {
        &self.private_by_account
    }

    /// Возвращает обёртки с заменённой парольной обёрткой — смена пароля.
    #[must_use]
    pub fn rewrapped(self, account_by_password: Vec<u8>) -> Self {
        Self {
            account_by_password,
            ..self
        }
    }
}

/// Всё, что сервер хранит о способе входа пользователя.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    challenge: Challenge,
    stored: StoredAuth,
    public: PublicKey,
    wrapped: Wrapped,
}

impl Credentials {
    /// Собирает учётные данные.
    #[must_use]
    pub const fn new(
        challenge: Challenge,
        stored: StoredAuth,
        public: PublicKey,
        wrapped: Wrapped,
    ) -> Self {
        Self {
            challenge,
            stored,
            public,
            wrapped,
        }
    }

    /// Параметры выведения ключа.
    #[must_use]
    pub const fn challenge(&self) -> &Challenge {
        &self.challenge
    }

    /// Хранимая форма аутентификационного хеша.
    #[must_use]
    pub const fn stored(&self) -> &StoredAuth {
        &self.stored
    }

    /// Открытый ключ пользователя.
    #[must_use]
    pub const fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Обёртки ключей.
    #[must_use]
    pub const fn wrapped(&self) -> &Wrapped {
        &self.wrapped
    }

    /// Возвращает учётные данные после смены пароля.
    #[must_use]
    pub fn with_password(self, challenge: Challenge, stored: StoredAuth, wrapped: Wrapped) -> Self {
        Self {
            challenge,
            stored,
            wrapped,
            ..self
        }
    }
}
