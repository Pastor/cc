//! Шифрование содержимого и имён на клиенте.

use crate::error::Result;
use cc_crypto::{open, seal, AccountKey, BlockSize, Cipher, ContentKey, Header, Secret};

/// Запись содержимого: режет открытый текст на блоки и шифрует каждый.
///
/// Пиковая память не зависит от размера файла: блок обрабатывается и сразу
/// отдаётся вызывающему.
#[derive(Debug)]
pub struct Writer {
    cipher: Cipher,
}

impl Writer {
    /// Готовит запись содержимого файла.
    #[must_use]
    pub const fn new(key: ContentKey, block_size: BlockSize, file: Vec<u8>) -> Self {
        Self {
            cipher: Cipher::new(key, Header::new(block_size), file),
        }
    }

    /// Заголовок, который пишется в начало файла.
    #[must_use]
    pub fn header(&self) -> [u8; cc_crypto::HEADER_LEN] {
        self.cipher.header().to_bytes()
    }

    /// Шифрует блок с указанным номером.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Crypto`], если блок длиннее размера из заголовка.
    pub fn block(&self, index: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.cipher.seal(index, plaintext)?)
    }
}

/// Чтение содержимого: расшифровывает произвольный блок.
///
/// Блочный формат позволяет прочитать отрезок файла, не читая файл целиком, —
/// это нужно и для докачки по диапазону, и для монтирования (`TODO.md` 4.15).
#[derive(Debug)]
pub struct Reader {
    cipher: Cipher,
}

impl Reader {
    /// Готовит чтение содержимого по заголовку из начала файла.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Crypto`], если заголовок усечён, версия формата не
    /// поддерживается либо размер блока недопустим.
    pub fn new(key: ContentKey, header: &[u8], file: Vec<u8>) -> Result<Self> {
        Ok(Self {
            cipher: Cipher::new(key, Header::parse(header)?, file),
        })
    }

    /// Размер блока открытого текста.
    #[must_use]
    pub const fn block_size(&self) -> BlockSize {
        self.cipher.header().block_size()
    }

    /// Расшифровывает блок с указанным номером.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Crypto`], если тег не сошёлся: блок принадлежит другому
    /// файлу, стоит на другом месте либо искажён.
    pub fn block(&self, index: u64, sealed: &[u8]) -> Result<Vec<u8>> {
        Ok(self.cipher.open(index, sealed)?)
    }
}

/// Шифрует имя файла или директории ключом учётной записи.
///
/// Имена шифруются потому, что серверу их видеть не положено (`TODO.md`,
/// раздел 1.4).
///
/// # Errors
///
/// [`crate::Error::Crypto`], если примитив отказал.
pub fn encrypt_name(account: &AccountKey, name: &str) -> Result<Vec<u8>> {
    let mut padded = [0_u8; 32];
    let source = name.as_bytes();
    let length = source.len().min(padded.len());
    padded[..length].copy_from_slice(&source[..length]);
    Ok(seal(account.as_secret(), &Secret::new(padded))?)
}

/// Расшифровывает имя файла или директории.
///
/// # Errors
///
/// [`crate::Error::Crypto`], если обёртка не снимается ключом учётной записи.
pub fn decrypt_name(account: &AccountKey, sealed: &[u8]) -> Result<String> {
    let secret = open(account.as_secret(), sealed)?;
    let bytes = secret.expose();
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}
