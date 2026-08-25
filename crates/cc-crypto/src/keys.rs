//! Ключевая иерархия.
//!
//! Каждая ступень иерархии — отдельный тип: система типов не позволяет передать
//! ключ шифрования туда, где ожидается ключ содержимого. Иерархия описана в
//! `TODO.md`, раздел 1.2.

use crate::error::{Error, Result};
use crate::secret::Secret;
use hkdf::Hkdf;
use sha2::Sha256;

/// Длина ключа в байтах для всех ступеней иерархии.
pub const KEY_LEN: usize = 32;

/// Наименьшая допустимая длина соли.
pub const SALT_MIN_LEN: usize = 16;

macro_rules! key {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name(Secret<KEY_LEN>);

        impl $name {
            /// Принимает готовый материал во владение.
            #[must_use]
            pub const fn new(bytes: [u8; KEY_LEN]) -> Self {
                Self(Secret::new(bytes))
            }

            /// Открывает материал для передачи в криптографический примитив.
            #[must_use]
            pub const fn expose(&self) -> &[u8; KEY_LEN] {
                self.0.expose()
            }
        }
    };
}

key!(
    MasterKey,
    "Мастер-ключ: выводится из пароля и не покидает клиента."
);
key!(
    EncryptionKey,
    "Ключ шифрования: ветвь мастер-ключа, которой оборачивается ключ учётной записи."
);
key!(
    AuthHash,
    "Аутентификационный хеш: единственная ветвь мастер-ключа, уходящая на сервер."
);
key!(
    AccountKey,
    "Ключ учётной записи: оборачивает закрытый ключ, имена и служит корнем для ключа тегов."
);
key!(ContentKey, "Ключ содержимого файла: свой у каждого файла.");
key!(
    MetadataKey,
    "Ключ публичной метаинформации файла: отделён от ключа содержимого намеренно."
);
key!(
    TagKey,
    "Ключ тегов: выводится из ключа учётной записи, поэтому переживает смену пароля."
);
key!(
    RecoveryKey,
    "Ключ восстановления: вторая обёртка ключа учётной записи."
);

/// Соль выведения ключа из пароля.
///
/// Инвариант: не короче [`SALT_MIN_LEN`] байт.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Salt(Vec<u8>);

impl Salt {
    /// Проверяет длину и принимает соль во владение.
    ///
    /// # Errors
    ///
    /// [`Error::SaltTooShort`], если соль короче [`SALT_MIN_LEN`] байт.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < SALT_MIN_LEN {
            return Err(Error::SaltTooShort {
                expected: SALT_MIN_LEN,
            });
        }
        Ok(Self(bytes))
    }

    /// Открывает соль: она не секретна и хранится рядом с пользователем.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Метка ветви HKDF.
///
/// Версия входит в метку, чтобы смена схемы выведения не давала совпадающих
/// ключей со старой.
const BRANCH_AUTH: &[u8] = b"cstorage.branch.auth.v1";
const BRANCH_ENCRYPTION: &[u8] = b"cstorage.branch.enc.v1";
const BRANCH_TAGS: &[u8] = b"cstorage.branch.tags.v1";

impl MasterKey {
    /// Выводит аутентификационный хеш — единственное, что уходит на сервер.
    ///
    #[must_use]
    pub fn authentication(&self) -> AuthHash {
        AuthHash::new(branch(self.expose(), BRANCH_AUTH))
    }

    /// Выводит ключ шифрования, который остаётся у клиента.
    ///
    #[must_use]
    pub fn encryption(&self) -> EncryptionKey {
        EncryptionKey::new(branch(self.expose(), BRANCH_ENCRYPTION))
    }
}

impl AccountKey {
    /// Выводит ключ тегов.
    ///
    #[must_use]
    pub fn tags(&self) -> TagKey {
        TagKey::new(branch(self.expose(), BRANCH_TAGS))
    }
}

/// Выводит ветвь фиксированной длины из корневого материала.
#[allow(
    clippy::expect_used,
    reason = "HKDF-Expand отказывает только при выводе длиннее 255 блоков хеша; \
              здесь длина равна KEY_LEN и проверяется утверждением ниже"
)]
fn branch(root: &[u8; KEY_LEN], info: &[u8]) -> [u8; KEY_LEN] {
    const _: () = assert!(KEY_LEN <= 255 * 32, "длина ветви превышает предел HKDF");
    let mut output = [0_u8; KEY_LEN];
    Hkdf::<Sha256>::new(None, root)
        .expand(info, &mut output)
        .expect("INVARIANT: длина ветви не превышает предела HKDF");
    output
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{AccountKey, MasterKey, Salt, SALT_MIN_LEN};

    #[test]
    fn master_key_branches_differ() {
        let master = MasterKey::new([1; 32]);
        assert!(
            master.authentication().expose() != master.encryption().expose(),
            "ветвь аутентификации совпала с ветвью шифрования"
        );
    }

    #[test]
    fn branch_is_reproducible() {
        let expected = MasterKey::new([2; 32]).encryption();
        assert_eq!(
            MasterKey::new([2; 32]).encryption(),
            expected,
            "повторное выведение дало другой ключ"
        );
    }

    #[test]
    fn distinct_master_keys_give_distinct_branches() {
        let first = MasterKey::new([3; 32]).authentication();
        assert!(
            first != MasterKey::new([4; 32]).authentication(),
            "разные мастер-ключи дали одинаковую ветвь аутентификации"
        );
    }

    #[test]
    fn tag_key_derives_from_account_key() {
        let expected = AccountKey::new([5; 32]).tags();
        assert_eq!(
            AccountKey::new([5; 32]).tags(),
            expected,
            "ключ тегов оказался невоспроизводимым"
        );
    }

    #[test]
    fn short_salt_is_rejected() {
        assert!(
            Salt::new(vec![0; SALT_MIN_LEN - 1]).is_err(),
            "соль короче предела принята"
        );
    }

    #[test]
    fn salt_of_allowed_length_is_accepted() {
        assert!(
            Salt::new(vec![0; SALT_MIN_LEN]).is_ok(),
            "соль допустимой длины отвергнута"
        );
    }
}
