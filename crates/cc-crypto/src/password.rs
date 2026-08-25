//! Выведение мастер-ключа из пароля.
//!
//! Единственная функция выведения — Argon2id (`TODO.md`, раздел 2). Параметры
//! хранятся вместе с пользователем, чтобы их можно было усилить, не ломая
//! существующие учётные записи.

use crate::error::{Error, Result};
use crate::keys::{MasterKey, Salt, KEY_LEN};
use argon2::{Algorithm, Argon2, Params, Version};

/// Параметры Argon2id.
///
/// Значения по умолчанию рассчитаны на **серверное укрепление** уже полученного
/// аутентификационного хеша: тридцать два байта высокой энтропии, перебор
/// которых невозможен независимо от параметров. Клиент, выводящий ключ из
/// пароля, обязан задавать параметры выше — не меньше сорока семи мебибайт
/// (`TODO.md`, раздел 12.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl KdfParams {
    /// Проверяет параметры и принимает их.
    ///
    /// # Errors
    ///
    /// [`Error::KdfParameters`], если сочетание значений отвергнуто Argon2.
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self> {
        Params::new(memory_kib, iterations, parallelism, Some(KEY_LEN))
            .map_err(|_| Error::KdfParameters)?;
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// Объём памяти в кибибайтах.
    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    /// Число итераций.
    #[must_use]
    pub const fn iterations(self) -> u32 {
        self.iterations
    }

    /// Степень параллелизма.
    #[must_use]
    pub const fn parallelism(self) -> u32 {
        self.parallelism
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 19 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }
}

/// Выводит мастер-ключ из пароля.
///
/// Пароль принимается целиком и не усекается: усечение прежней реализации до
/// шестнадцати символов делало длинные пароли бесполезными.
///
/// # Errors
///
/// - [`Error::KdfParameters`] — параметры отвергнуты Argon2;
/// - [`Error::KeyDerivation`] — выведение не удалось.
///
/// # Examples
///
/// ```
/// use cc_crypto::{derive_master_key, KdfParams, Salt};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let salt = Salt::new(vec![7; 16])?;
/// let params = KdfParams::new(8, 1, 1)?;
/// let key = derive_master_key("пароль".as_bytes(), &salt, params)?;
/// assert_eq!(key, derive_master_key("пароль".as_bytes(), &salt, params)?);
/// # Ok(())
/// # }
/// ```
pub fn derive_master_key(password: &[u8], salt: &Salt, params: KdfParams) -> Result<MasterKey> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| Error::KdfParameters)?,
    );
    let mut output = [0_u8; KEY_LEN];
    argon
        .hash_password_into(password, salt.as_bytes(), &mut output)
        .map_err(|_| Error::KeyDerivation)?;
    Ok(MasterKey::new(output))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{derive_master_key, KdfParams};
    use crate::keys::Salt;

    fn params() -> KdfParams {
        KdfParams::new(8, 1, 1).unwrap_or_default()
    }

    fn salt() -> Salt {
        Salt::new(vec![0x5a; 16]).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn passwords_differing_past_sixteenth_character_give_distinct_keys() {
        let first = derive_master_key(b"0123456789abcdefA", &salt(), params());
        assert!(
            first.ok() != derive_master_key(b"0123456789abcdefB", &salt(), params()).ok(),
            "длинные пароли усекаются: различие после шестнадцатого символа потеряно"
        );
    }

    #[test]
    fn non_ascii_password_is_accepted() {
        assert!(
            derive_master_key("пароль".as_bytes(), &salt(), params()).is_ok(),
            "пароль вне ASCII отвергнут"
        );
    }

    #[test]
    fn distinct_salts_give_distinct_keys() {
        let other = Salt::new(vec![0x5b; 16]).unwrap_or_else(|_| unreachable!());
        let first = derive_master_key("пароль".as_bytes(), &salt(), params());
        assert!(
            first.ok() != derive_master_key("пароль".as_bytes(), &other, params()).ok(),
            "соль не влияет на выведенный ключ"
        );
    }

    #[test]
    fn derivation_is_reproducible() {
        let expected = derive_master_key("пароль".as_bytes(), &salt(), params());
        assert!(
            expected.ok() == derive_master_key("пароль".as_bytes(), &salt(), params()).ok(),
            "повторное выведение с теми же входными данными дало другой ключ"
        );
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        assert!(
            KdfParams::new(0, 0, 0).is_err(),
            "нулевые параметры Argon2id приняты"
        );
    }
}
