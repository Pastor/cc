//! Обёртывание ключей.
//!
//! Симметричная обёртка применяется там, где обе стороны знают один ключ:
//! ключ учётной записи под ключом шифрования и под ключом восстановления.
//! Асимметричная — там, где ключ передаётся другому: ключ содержимого и ключ
//! метаданных под открытым ключом получателя (`TODO.md`, раздел 1.2).

use crate::error::{Error, Result};
use crate::keys::KEY_LEN;
use crate::secret::Secret;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// Длина nonce XChaCha20-Poly1305.
const NONCE_LEN: usize = 24;

/// Длина тега Poly1305.
const TAG_LEN: usize = 16;

/// Длина открытого ключа X25519.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Метка симметричной обёртки в связанных данных.
const DOMAIN_SYMMETRIC: &[u8] = b"cStore.wrap.symmetric.v1";

/// Метка асимметричной обёртки в связанных данных.
const DOMAIN_ASYMMETRIC: &[u8] = b"cStore.wrap.asymmetric.v1";

/// Открытый ключ пользователя.
///
/// Хранится на сервере в открытом виде: по нему выдают доступ к файлам.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    /// Принимает открытый ключ.
    #[must_use]
    pub const fn new(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Отдаёт открытый ключ: он не секретен.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }
}

/// Пара ключей пользователя.
///
/// Закрытая часть существует только в памяти клиента; на сервере хранится её
/// обёрнутая форма.
pub struct KeyPair {
    secret: StaticSecret,
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyPair([REDACTED])")
    }
}

impl KeyPair {
    /// Порождает новую пару ключей.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Восстанавливает пару из закрытой части.
    #[must_use]
    pub fn from_secret(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    /// Открытая часть пары.
    #[must_use]
    pub fn public(&self) -> PublicKey {
        PublicKey::new(X25519Public::from(&self.secret).to_bytes())
    }

    /// Закрытая часть пары — для обёртывания на хранение.
    #[must_use]
    pub fn secret(&self) -> Secret<KEY_LEN> {
        Secret::new(self.secret.to_bytes())
    }
}

/// Оборачивает ключ другим ключом.
///
/// # Errors
///
/// [`Error::Decryption`], если примитив отказал.
pub fn seal(kek: &Secret<KEY_LEN>, key: &Secret<KEY_LEN>) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(kek.expose().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let sealed = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: key.expose(),
                aad: DOMAIN_SYMMETRIC,
            },
        )
        .map_err(|_| Error::Decryption)?;
    let mut wrapped = Vec::with_capacity(NONCE_LEN + sealed.len());
    wrapped.extend_from_slice(nonce.as_slice());
    wrapped.extend_from_slice(&sealed);
    Ok(wrapped)
}

/// Разворачивает ключ, обёрнутый [`seal`].
///
/// # Errors
///
/// - [`Error::BlockTooShort`] — обёртка короче служебной части;
/// - [`Error::Decryption`] — ключ не тот либо обёртка искажена.
pub fn open(kek: &Secret<KEY_LEN>, wrapped: &[u8]) -> Result<Secret<KEY_LEN>> {
    let Some((nonce, sealed)) = wrapped.split_at_checked(NONCE_LEN) else {
        return Err(Error::BlockTooShort {
            expected: NONCE_LEN + TAG_LEN + KEY_LEN,
        });
    };
    let cipher = XChaCha20Poly1305::new(kek.expose().into());
    let plain = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: DOMAIN_SYMMETRIC,
            },
        )
        .map_err(|_| Error::Decryption)?;
    into_key(plain)
}

/// Оборачивает ключ открытым ключом получателя.
///
/// Порождается эфемерная пара, общий секрет выводится X25519, из него HKDF даёт
/// ключ обёртки. Эфемерный открытый ключ передаётся вместе с обёрткой.
///
/// # Errors
///
/// [`Error::Decryption`], если примитив отказал.
pub fn seal_for(recipient: &PublicKey, key: &Secret<KEY_LEN>) -> Result<Vec<u8>> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519Public::from(&ephemeral).to_bytes();
    let kek = agree(
        &ephemeral,
        &X25519Public::from(*recipient.as_bytes()),
        &ephemeral_public,
        recipient.as_bytes(),
    );
    let cipher = XChaCha20Poly1305::new(kek.expose().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let sealed = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: key.expose(),
                aad: DOMAIN_ASYMMETRIC,
            },
        )
        .map_err(|_| Error::Decryption)?;
    let mut wrapped = Vec::with_capacity(PUBLIC_KEY_LEN + NONCE_LEN + sealed.len());
    wrapped.extend_from_slice(&ephemeral_public);
    wrapped.extend_from_slice(nonce.as_slice());
    wrapped.extend_from_slice(&sealed);
    Ok(wrapped)
}

/// Разворачивает ключ, обёрнутый [`seal_for`].
///
/// # Errors
///
/// - [`Error::BlockTooShort`] — обёртка короче служебной части;
/// - [`Error::Decryption`] — пара не та либо обёртка искажена.
pub fn open_for(pair: &KeyPair, wrapped: &[u8]) -> Result<Secret<KEY_LEN>> {
    let expected = PUBLIC_KEY_LEN + NONCE_LEN + TAG_LEN + KEY_LEN;
    let Some((ephemeral, rest)) = wrapped.split_at_checked(PUBLIC_KEY_LEN) else {
        return Err(Error::BlockTooShort { expected });
    };
    let Some((nonce, sealed)) = rest.split_at_checked(NONCE_LEN) else {
        return Err(Error::BlockTooShort { expected });
    };
    let mut ephemeral_bytes = [0_u8; PUBLIC_KEY_LEN];
    ephemeral_bytes.copy_from_slice(ephemeral);
    let recipient = pair.public();
    let kek = agree(
        &pair.secret,
        &X25519Public::from(ephemeral_bytes),
        &ephemeral_bytes,
        recipient.as_bytes(),
    );
    let cipher = XChaCha20Poly1305::new(kek.expose().into());
    let plain = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: DOMAIN_ASYMMETRIC,
            },
        )
        .map_err(|_| Error::Decryption)?;
    into_key(plain)
}

/// Выводит ключ обёртки из общего секрета X25519.
///
/// Оба открытых ключа входят в метку, иначе обёртка, снятая для одного
/// получателя, годилась бы для другого.
#[allow(
    clippy::expect_used,
    reason = "HKDF-Expand отказывает только при выводе длиннее 255 блоков хеша; \
              здесь длина равна KEY_LEN"
)]
fn agree(
    secret: &StaticSecret,
    peer: &X25519Public,
    ephemeral_public: &[u8; PUBLIC_KEY_LEN],
    recipient_public: &[u8; PUBLIC_KEY_LEN],
) -> Secret<KEY_LEN> {
    let shared = secret.diffie_hellman(peer);
    let mut info = Vec::with_capacity(DOMAIN_ASYMMETRIC.len() + 2 * PUBLIC_KEY_LEN);
    info.extend_from_slice(DOMAIN_ASYMMETRIC);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_public);
    let mut output = [0_u8; KEY_LEN];
    Hkdf::<Sha256>::new(None, shared.as_bytes())
        .expand(&info, &mut output)
        .expect("INVARIANT: длина ключа обёртки не превышает предела HKDF");
    Secret::new(output)
}

/// Превращает развёрнутые байты в ключ, проверяя длину.
fn into_key(plain: Vec<u8>) -> Result<Secret<KEY_LEN>> {
    let bytes: [u8; KEY_LEN] = plain.try_into().map_err(|_| Error::Decryption)?;
    Ok(Secret::new(bytes))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{open, open_for, seal, seal_for, KeyPair};
    use crate::secret::Secret;

    #[test]
    fn symmetric_wrapping_opens() {
        let kek = Secret::new([1; 32]);
        let key = Secret::new([2; 32]);
        let wrapped = seal(&kek, &key).unwrap();
        assert_eq!(
            open(&kek, &wrapped).unwrap(),
            key,
            "симметричная обёртка вернула не тот ключ"
        );
    }

    #[test]
    fn symmetric_wrapping_resists_foreign_key() {
        let wrapped = seal(&Secret::new([1; 32]), &Secret::new([2; 32])).unwrap();
        assert!(
            open(&Secret::new([3; 32]), &wrapped).is_err(),
            "обёртка снята чужим ключом"
        );
    }

    #[test]
    fn symmetric_wrapping_repeats_differently() {
        let kek = Secret::new([1; 32]);
        let key = Secret::new([2; 32]);
        let first = seal(&kek, &key).unwrap();
        assert!(
            first != seal(&kek, &key).unwrap(),
            "обёртывание детерминировано: nonce повторяется"
        );
    }

    #[test]
    fn asymmetric_wrapping_opens_for_recipient() {
        let pair = KeyPair::generate();
        let key = Secret::new([5; 32]);
        let wrapped = seal_for(&pair.public(), &key).unwrap();
        assert_eq!(
            open_for(&pair, &wrapped).unwrap(),
            key,
            "получатель развернул не тот ключ"
        );
    }

    #[test]
    fn asymmetric_wrapping_resists_foreign_pair() {
        let wrapped = seal_for(&KeyPair::generate().public(), &Secret::new([5; 32])).unwrap();
        assert!(
            open_for(&KeyPair::generate(), &wrapped).is_err(),
            "чужая пара развернула обёртку"
        );
    }

    #[test]
    fn corrupted_wrapping_is_rejected() {
        let pair = KeyPair::generate();
        let mut wrapped = seal_for(&pair.public(), &Secret::new([5; 32])).unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 1;
        assert!(
            open_for(&pair, &wrapped).is_err(),
            "искажение обёртки осталось незамеченным"
        );
    }

    #[test]
    fn short_wrapping_is_rejected() {
        assert!(
            open(&Secret::new([1; 32]), &[0; 4]).is_err(),
            "обёртка короче служебной части принята"
        );
    }

    #[test]
    fn pair_restores_from_secret_part() {
        let pair = KeyPair::generate();
        let restored = KeyPair::from_secret(*pair.secret().expose());
        assert_eq!(
            restored.public(),
            pair.public(),
            "восстановленная пара дала другой открытый ключ"
        );
    }
}
