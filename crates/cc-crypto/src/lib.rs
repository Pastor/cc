//! Криптографические примитивы, разделяемые клиентом и сервером.
//!
//! Крейт не содержит ни политики доступа, ни знаний о транспорте: только
//! выведение ключей, шифрование с аутентификацией и обёртывание ключей.
//! Алгоритмы зафиксированы в `TODO.md`, раздел 2, и здесь не выбираются.
//!
//! Модель безопасности гибридная: криптография выполняется на клиенте, сервер
//! хранит шифротекст и обёрнутые ключи. Поэтому крейт используют обе стороны.

mod content;
mod digest;
mod error;
mod keys;
mod password;
mod secret;
mod stored;
mod vectors;
mod wrap;

pub use content::{
    plaintext_len, BlockSize, Cipher, Header, BLOCK_SIZE_MAX, BLOCK_SIZE_MIN, FORMAT_VERSION,
    HEADER_LEN,
};
pub use digest::{CiphertextHash, TagLabel, HASH_LEN};
pub use error::{Error, Result};
pub use keys::{
    AccountKey, AuthHash, ContentKey, EncryptionKey, MasterKey, MetadataKey, RecoveryKey, Salt,
    TagKey, KEY_LEN, SALT_MIN_LEN,
};
pub use password::{derive_master_key, KdfParams};
pub use secret::Secret;
pub use stored::{decoy_salt, StoredAuth};
pub use wrap::{open, open_for, seal, seal_for, KeyPair, PublicKey, PUBLIC_KEY_LEN};
