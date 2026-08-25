//! Хранимая форма аутентификационного хеша.
//!
//! Аутентификационный хеш — то единственное, что клиент присылает вместо
//! пароля. Хранить его как есть нельзя: утечка базы дала бы возможность войти
//! под любым пользователем. Поэтому сервер хранит `Argon2id` от него со своей
//! солью (`TODO.md`, раздел 1.2).

use crate::error::{Error, Result};
use crate::keys::{AuthHash, Salt, KEY_LEN};
use crate::password::KdfParams;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

/// Хранимая форма аутентификационного хеша.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAuth([u8; KEY_LEN]);

impl StoredAuth {
    /// Вычисляет хранимую форму.
    ///
    /// # Errors
    ///
    /// - [`Error::KdfParameters`] — параметры отвергнуты Argon2;
    /// - [`Error::KeyDerivation`] — выведение не удалось.
    pub fn of(auth: &AuthHash, salt: &Salt, params: KdfParams) -> Result<Self> {
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                params.memory_kib(),
                params.iterations(),
                params.parallelism(),
                Some(KEY_LEN),
            )
            .map_err(|_| Error::KdfParameters)?,
        );
        let mut output = [0_u8; KEY_LEN];
        argon
            .hash_password_into(auth.expose(), salt.as_bytes(), &mut output)
            .map_err(|_| Error::KeyDerivation)?;
        Ok(Self(output))
    }

    /// Принимает хранимую форму из базы.
    #[must_use]
    pub const fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Отдаёт хранимую форму для записи в базу.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Сверяет предъявленную форму с хранимой в постоянном времени.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// Метка ветви для правдоподобной соли.
const BRANCH_DECOY: &[u8] = b"cStore.decoy.salt.v1";

/// Выводит правдоподобную соль для неизвестного логина.
///
/// Метод выдачи соли обязан отвечать одинаково для существующего и
/// несуществующего логина, иначе он работает оракулом существования учётных
/// записей (`TODO.md`, раздел 4.2). Значение детерминировано, поэтому повторный
/// запрос по тому же логину даёт ту же соль — как и для настоящей записи.
///
/// # Errors
///
/// [`Error::SaltTooShort`] не возвращается: длина вывода фиксирована и
/// заведомо достаточна. Вариант оставлен ради единообразия сигнатуры.
///
/// # Panics
///
/// Не паникует: длина вывода фиксирована и допустима для HKDF.
#[allow(
    clippy::expect_used,
    reason = "HKDF-Expand отказывает только при выводе длиннее 255 блоков хеша"
)]
pub fn decoy_salt(server_secret: &[u8], login: &[u8]) -> Result<Salt> {
    let mut output = [0_u8; KEY_LEN];
    let mut info = Vec::with_capacity(BRANCH_DECOY.len() + login.len());
    info.extend_from_slice(BRANCH_DECOY);
    info.extend_from_slice(login);
    Hkdf::<Sha256>::new(None, server_secret)
        .expand(&info, &mut output)
        .expect("INVARIANT: длина правдоподобной соли не превышает предела HKDF");
    Salt::new(output.to_vec())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{decoy_salt, StoredAuth};
    use crate::keys::{AuthHash, Salt};
    use crate::password::KdfParams;

    fn params() -> KdfParams {
        KdfParams::new(8, 1, 1).unwrap()
    }

    fn salt() -> Salt {
        Salt::new(vec![3; 16]).unwrap()
    }

    #[test]
    fn stored_form_differs_from_authentication_hash() {
        let auth = AuthHash::new([1; 32]);
        assert!(
            StoredAuth::of(&auth, &salt(), params()).unwrap().as_bytes() != auth.expose(),
            "хранимая форма совпала с аутентификационным хешем: утечка базы даёт вход"
        );
    }

    #[test]
    fn matching_hash_is_accepted() {
        let auth = AuthHash::new([1; 32]);
        let stored = StoredAuth::of(&auth, &salt(), params()).unwrap();
        assert!(
            stored.matches(&StoredAuth::of(&auth, &salt(), params()).unwrap()),
            "верный аутентификационный хеш отвергнут"
        );
    }

    #[test]
    fn foreign_hash_is_rejected() {
        let stored = StoredAuth::of(&AuthHash::new([1; 32]), &salt(), params()).unwrap();
        let other = StoredAuth::of(&AuthHash::new([2; 32]), &salt(), params()).unwrap();
        assert!(
            !stored.matches(&other),
            "чужой аутентификационный хеш принят"
        );
    }

    #[test]
    fn decoy_salt_is_deterministic() {
        assert_eq!(
            decoy_salt(b"secret", b"user@example.com").unwrap(),
            decoy_salt(b"secret", b"user@example.com").unwrap(),
            "правдоподобная соль невоспроизводима: повторный запрос выдаёт подделку"
        );
    }

    #[test]
    fn decoy_salt_differs_per_login() {
        assert!(
            decoy_salt(b"secret", b"a@example.com").unwrap()
                != decoy_salt(b"secret", b"b@example.com").unwrap(),
            "правдоподобная соль одинакова для разных логинов"
        );
    }

    #[test]
    fn decoy_salt_depends_on_server_secret() {
        assert!(
            decoy_salt(b"one", b"user@example.com").unwrap()
                != decoy_salt(b"two", b"user@example.com").unwrap(),
            "правдоподобная соль не зависит от серверного секрета: её можно предсказать"
        );
    }
}
