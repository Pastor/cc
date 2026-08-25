//! Операции учётной записи, выполняемые на клиенте.
//!
//! Пароль не покидает эту машину. На сервер уходит только аутентификационный
//! хеш и обёртки ключей — материала для расшифровки у сервера нет ни в покое,
//! ни во время работы (`TODO.md`, раздел 1).

use crate::error::{Error, Result};
use cc_crypto::{
    derive_master_key, open, open_for, seal, seal_for, AccountKey, AuthHash, KdfParams, KeyPair,
    PublicKey, RecoveryKey, Salt, TagKey,
};

/// То, что уходит на сервер при создании учётной записи.
///
/// Ни одного значения, пригодного для расшифровки содержимого, здесь нет.
#[derive(Clone, Debug)]
pub struct Enrollment {
    auth: AuthHash,
    public: PublicKey,
    wrapped: WrappedKeys,
}

impl Enrollment {
    /// Аутентификационный хеш — то, что сервер хранит вместо пароля.
    #[must_use]
    pub const fn auth(&self) -> &AuthHash {
        &self.auth
    }

    /// Открытый ключ: по нему другие выдают доступ владельцу.
    #[must_use]
    pub const fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Обёртки ключей, хранимые сервером.
    #[must_use]
    pub const fn wrapped(&self) -> &WrappedKeys {
        &self.wrapped
    }
}

/// Обёртки ключей, которые сервер хранит и вернуть в открытом виде не может.
#[derive(Clone, Debug)]
pub struct WrappedKeys {
    account_by_password: Vec<u8>,
    account_by_recovery: Vec<u8>,
    private_by_account: Vec<u8>,
}

impl WrappedKeys {
    /// Собирает обёртки, полученные от сервера.
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
}

/// Развёрнутые ключи: живут в памяти, пока идёт сессия.
///
/// Тип не выводит `Clone` намеренно: чем меньше копий ключевого материала
/// разбросано по программе, тем меньше мест, где его нужно затирать.
#[derive(Debug)]
pub struct Identity {
    account: AccountKey,
    pair: KeyPair,
}

impl Identity {
    /// Ключ учётной записи: им обёрнуты имена и закрытый ключ.
    #[must_use]
    pub const fn account(&self) -> &AccountKey {
        &self.account
    }

    /// Пара ключей пользователя.
    #[must_use]
    pub const fn pair(&self) -> &KeyPair {
        &self.pair
    }

    /// Ключ тегов: выводится из ключа учётной записи, поэтому смену пароля
    /// переживает и переиндексации не требует.
    #[must_use]
    pub fn tags(&self) -> TagKey {
        self.account.tags()
    }
}

/// Создаёт учётную запись: порождает ключи и оборачивает их по иерархии.
///
/// Возвращает то, что уходит на сервер, и ключ восстановления, который
/// показывается пользователю **один раз** и на сервере не хранится.
///
/// # Errors
///
/// - [`Error::Crypto`] — отказ криптографического примитива;
/// - [`Error::Kdf`] — выведение ключа из пароля не удалось.
///
/// # Examples
///
/// ```
/// use cc_client::enroll;
/// use cc_crypto::{KdfParams, Salt};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let salt = Salt::new(vec![7; 16])?;
/// let (enrollment, _recovery) = enroll("пароль".as_bytes(), &salt, KdfParams::new(8, 1, 1)?)?;
/// assert_eq!(enrollment.wrapped().private_by_account().len(), 24 + 16 + 32);
/// # Ok(())
/// # }
/// ```
pub fn enroll(
    password: &[u8],
    salt: &Salt,
    params: KdfParams,
) -> Result<(Enrollment, RecoveryKey)> {
    let master = derive_master_key(password, salt, params).map_err(|_| Error::Kdf)?;
    let account = AccountKey::generate();
    let recovery = RecoveryKey::generate();
    let pair = KeyPair::generate();
    let wrapped = WrappedKeys {
        account_by_password: seal(master.encryption().as_secret(), account.as_secret())?,
        account_by_recovery: seal(recovery.as_secret(), account.as_secret())?,
        private_by_account: seal(account.as_secret(), &pair.secret())?,
    };
    Ok((
        Enrollment {
            auth: master.authentication(),
            public: pair.public(),
            wrapped,
        },
        recovery,
    ))
}

/// Разворачивает ключи после успешного входа по паролю.
///
/// # Errors
///
/// - [`Error::Kdf`] — выведение ключа из пароля не удалось;
/// - [`Error::Crypto`] — обёртка не снимается: пароль не тот либо данные
///   искажены.
pub fn unlock(
    password: &[u8],
    salt: &Salt,
    params: KdfParams,
    wrapped: &WrappedKeys,
) -> Result<Identity> {
    let master = derive_master_key(password, salt, params).map_err(|_| Error::Kdf)?;
    let account = AccountKey::from_secret(open(
        master.encryption().as_secret(),
        &wrapped.account_by_password,
    )?);
    unwrap_pair(account, wrapped)
}

/// Разворачивает ключи по ключу восстановления.
///
/// # Errors
///
/// [`Error::Crypto`], если обёртка не снимается ключом восстановления.
pub fn recover(recovery: &RecoveryKey, wrapped: &WrappedKeys) -> Result<Identity> {
    let account =
        AccountKey::from_secret(open(recovery.as_secret(), &wrapped.account_by_recovery)?);
    unwrap_pair(account, wrapped)
}

/// Меняет пароль, перешифровывая **только** ключ учётной записи.
///
/// Закрытый ключ, имена файлов и все ключи содержимого остаются нетронутыми:
/// промежуточный ключ учётной записи существует ровно ради этого.
///
/// # Errors
///
/// - [`Error::Kdf`] — выведение ключа из нового пароля не удалось;
/// - [`Error::Crypto`] — обёртывание не удалось.
pub fn change_password(
    identity: &Identity,
    password: &[u8],
    salt: &Salt,
    params: KdfParams,
) -> Result<(AuthHash, Vec<u8>)> {
    let master = derive_master_key(password, salt, params).map_err(|_| Error::Kdf)?;
    let wrapped = seal(
        master.encryption().as_secret(),
        identity.account.as_secret(),
    )?;
    Ok((master.authentication(), wrapped))
}

/// Разворачивает пару ключей ключом учётной записи.
fn unwrap_pair(account: AccountKey, wrapped: &WrappedKeys) -> Result<Identity> {
    let secret = open(account.as_secret(), &wrapped.private_by_account)?;
    Ok(Identity {
        account,
        pair: KeyPair::from_secret(*secret.expose()),
    })
}

/// Оборачивает ключ под открытый ключ получателя — выдача доступа.
///
/// # Errors
///
/// [`Error::Crypto`], если обёртывание не удалось.
pub fn grant(recipient: &PublicKey, key: &cc_crypto::Secret<32>) -> Result<Vec<u8>> {
    Ok(seal_for(recipient, key)?)
}

/// Разворачивает ключ, выданный владельцем, — приём доступа.
///
/// # Errors
///
/// [`Error::Crypto`], если обёртка предназначена не этой паре ключей.
pub fn accept(identity: &Identity, wrapped: &[u8]) -> Result<cc_crypto::Secret<32>> {
    Ok(open_for(&identity.pair, wrapped)?)
}
