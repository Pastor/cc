//! Блочное шифрование содержимого файла.
//!
//! Формат зафиксирован в `TODO.md`, раздел 2.1: содержимое режется на блоки
//! фиксированного размера, каждый шифруется своим nonce и проверяется своим
//! тегом. Блочность продиктована монтированием: файловая система пишет в
//! середину файла, и потоковый формат потребовал бы перешифрования целиком.

use crate::error::{Error, Result};
use crate::keys::ContentKey;
use chacha20poly1305::aead::{Aead, Generate as _, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// Версия формата шифрования содержимого.
pub const FORMAT_VERSION: u8 = 1;

/// Длина заголовка файла в байтах: версия и размер блока.
pub const HEADER_LEN: usize = 5;

/// Длина nonce XChaCha20-Poly1305.
const NONCE_LEN: usize = 24;

/// Длина тега Poly1305.
const TAG_LEN: usize = 16;

/// Наименьший допустимый размер блока.
pub const BLOCK_SIZE_MIN: u32 = 4 * 1024;

/// Наибольший допустимый размер блока.
pub const BLOCK_SIZE_MAX: u32 = 1024 * 1024;

/// Метка формата в связанных данных.
const DOMAIN: &[u8] = b"cStore.content.v1";

/// Размер блока открытого текста.
///
/// Инвариант: степень двойки в пределах от [`BLOCK_SIZE_MIN`] до
/// [`BLOCK_SIZE_MAX`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockSize(u32);

impl BlockSize {
    /// Проверяет инвариант и принимает размер.
    ///
    /// # Errors
    ///
    /// [`Error::BlockSize`], если размер вне диапазона или не степень двойки.
    pub const fn new(bytes: u32) -> Result<Self> {
        if bytes < BLOCK_SIZE_MIN || bytes > BLOCK_SIZE_MAX || !bytes.is_power_of_two() {
            return Err(Error::BlockSize {
                min: BLOCK_SIZE_MIN,
                max: BLOCK_SIZE_MAX,
            });
        }
        Ok(Self(bytes))
    }

    /// Размер в байтах.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Размер зашифрованного блока: nonce, шифротекст и тег.
    #[must_use]
    pub const fn sealed(self) -> usize {
        self.0 as usize + NONCE_LEN + TAG_LEN
    }
}

impl Default for BlockSize {
    fn default() -> Self {
        Self(32 * 1024)
    }
}

/// Заголовок зашифрованного файла.
///
/// Не шифруется и ключей не содержит; целостность обеспечивается вхождением в
/// связанные данные каждого блока.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    version: u8,
    block_size: BlockSize,
}

impl Header {
    /// Заголовок текущей версии формата с заданным размером блока.
    #[must_use]
    pub const fn new(block_size: BlockSize) -> Self {
        Self {
            version: FORMAT_VERSION,
            block_size,
        }
    }

    /// Разбирает заголовок из начала файла.
    ///
    /// # Errors
    ///
    /// - [`Error::HeaderTooShort`] — данных меньше [`HEADER_LEN`];
    /// - [`Error::UnsupportedFormat`] — версия формата не поддерживается;
    /// - [`Error::BlockSize`] — записанный размер блока недопустим.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let Some(head) = bytes.get(..HEADER_LEN) else {
            return Err(Error::HeaderTooShort {
                expected: HEADER_LEN,
            });
        };
        let version = head[0];
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedFormat { found: version });
        }
        let mut size = [0_u8; 4];
        size.copy_from_slice(&head[1..HEADER_LEN]);
        Ok(Self {
            version,
            block_size: BlockSize::new(u32::from_le_bytes(size))?,
        })
    }

    /// Записывает заголовок в виде, пригодном для начала файла.
    #[must_use]
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[0] = self.version;
        bytes[1..HEADER_LEN].copy_from_slice(&self.block_size.get().to_le_bytes());
        bytes
    }

    /// Размер блока открытого текста.
    #[must_use]
    pub const fn block_size(self) -> BlockSize {
        self.block_size
    }

    /// Версия формата.
    #[must_use]
    pub const fn version(self) -> u8 {
        self.version
    }
}

/// Шифрование и расшифровка блоков одного файла.
///
/// Идентификатор файла входит в связанные данные, поэтому блок, перенесённый в
/// другой файл, расшифровку не пройдёт.
pub struct Cipher {
    key: ContentKey,
    header: Header,
    file: Vec<u8>,
}

impl core::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cipher")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

impl Cipher {
    /// Собирает шифровальщик для одного файла.
    #[must_use]
    pub const fn new(key: ContentKey, header: Header, file: Vec<u8>) -> Self {
        Self { key, header, file }
    }

    /// Заголовок файла.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// Шифрует один блок открытого текста.
    ///
    /// # Errors
    ///
    /// - [`Error::BlockTooShort`] — блок длиннее размера, заданного заголовком;
    /// - [`Error::Randomness`] — не удалось получить nonce;
    /// - [`Error::Decryption`] — примитив отказал.
    pub fn seal(&self, index: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > self.header.block_size().get() as usize {
            return Err(Error::BlockTooShort {
                expected: self.header.block_size().get() as usize,
            });
        }
        let cipher = XChaCha20Poly1305::new(self.key.expose().into());
        let nonce = XNonce::try_generate().map_err(|_| Error::Randomness)?;
        let aad = self.aad(index);
        let sealed = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Decryption)?;
        let mut block = Vec::with_capacity(NONCE_LEN + sealed.len());
        block.extend_from_slice(nonce.as_slice());
        block.extend_from_slice(&sealed);
        Ok(block)
    }

    /// Расшифровывает один блок.
    ///
    /// # Errors
    ///
    /// - [`Error::BlockTooShort`] — блок короче служебной части;
    /// - [`Error::Decryption`] — тег не сошёлся: ключ не тот, номер блока не
    ///   тот, файл не тот либо данные искажены.
    pub fn open(&self, index: u64, block: &[u8]) -> Result<Vec<u8>> {
        let Some((nonce, sealed)) = block.split_at_checked(NONCE_LEN) else {
            return Err(Error::BlockTooShort {
                expected: NONCE_LEN + TAG_LEN,
            });
        };
        if sealed.len() < TAG_LEN {
            return Err(Error::BlockTooShort {
                expected: NONCE_LEN + TAG_LEN,
            });
        }
        let Ok(nonce) = XNonce::try_from(nonce) else {
            return Err(Error::BlockTooShort {
                expected: NONCE_LEN + TAG_LEN,
            });
        };
        let cipher = XChaCha20Poly1305::new(self.key.expose().into());
        let aad = self.aad(index);
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: sealed,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Decryption)
    }

    /// Собирает связанные данные блока: метка формата, заголовок, файл и номер.
    fn aad(&self, index: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(DOMAIN.len() + HEADER_LEN + self.file.len() + 8);
        aad.extend_from_slice(DOMAIN);
        aad.extend_from_slice(&self.header.to_bytes());
        aad.extend_from_slice(&self.file);
        aad.extend_from_slice(&index.to_le_bytes());
        aad
    }
}

/// Вычисляет длину открытого текста по длине шифротекста.
///
/// Отдельного поля с длиной нет намеренно: полю, которое можно подменить, нельзя
/// доверять.
///
/// # Errors
///
/// [`Error::HeaderTooShort`], если шифротекст короче заголовка, и
/// [`Error::BlockTooShort`], если хвостовой блок короче служебной части.
pub fn plaintext_len(ciphertext_len: u64, block_size: BlockSize) -> Result<u64> {
    let header = HEADER_LEN as u64;
    let Some(body) = ciphertext_len.checked_sub(header) else {
        return Err(Error::HeaderTooShort {
            expected: HEADER_LEN,
        });
    };
    let sealed = block_size.sealed() as u64;
    let overhead = (NONCE_LEN + TAG_LEN) as u64;
    let full = body / sealed;
    let tail = body % sealed;
    if tail == 0 {
        return Ok(full * u64::from(block_size.get()));
    }
    let Some(tail_plain) = tail.checked_sub(overhead) else {
        return Err(Error::BlockTooShort {
            expected: NONCE_LEN + TAG_LEN,
        });
    };
    Ok(full * u64::from(block_size.get()) + tail_plain)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{plaintext_len, BlockSize, Cipher, Header, BLOCK_SIZE_MIN, HEADER_LEN};
    use crate::keys::ContentKey;

    fn cipher() -> Cipher {
        Cipher::new(
            ContentKey::new([9; 32]),
            Header::new(BlockSize::new(BLOCK_SIZE_MIN).unwrap()),
            b"file-1".to_vec(),
        )
    }

    #[test]
    fn block_opens_to_original_plaintext() {
        let subject = cipher();
        let sealed = subject.seal(0, b"secret").unwrap();
        assert_eq!(
            subject.open(0, &sealed).unwrap(),
            b"secret",
            "расшифровка вернула не исходный текст"
        );
    }

    #[test]
    fn resealing_gives_distinct_ciphertext() {
        let subject = cipher();
        let first = subject.seal(0, b"secret").unwrap();
        assert!(
            first != subject.seal(0, b"secret").unwrap(),
            "шифрование детерминировано: nonce повторяется"
        );
    }

    #[test]
    fn corrupted_byte_breaks_opening() {
        let subject = cipher();
        let mut sealed = subject.seal(0, b"secret").unwrap();
        sealed[30] ^= 1;
        assert!(
            subject.open(0, &sealed).is_err(),
            "искажение шифротекста осталось незамеченным"
        );
    }

    #[test]
    fn block_does_not_open_under_foreign_index() {
        let subject = cipher();
        let sealed = subject.seal(0, b"secret").unwrap();
        assert!(
            subject.open(1, &sealed).is_err(),
            "перестановка блоков внутри файла осталась незамеченной"
        );
    }

    #[test]
    fn block_does_not_open_in_foreign_file() {
        let sealed = cipher().seal(0, b"secret").unwrap();
        let other = Cipher::new(
            ContentKey::new([9; 32]),
            Header::new(BlockSize::new(BLOCK_SIZE_MIN).unwrap()),
            b"file-2".to_vec(),
        );
        assert!(
            other.open(0, &sealed).is_err(),
            "перенос блока в другой файл остался незамеченным"
        );
    }

    #[test]
    fn block_does_not_open_with_foreign_key() {
        let sealed = cipher().seal(0, b"secret").unwrap();
        let other = Cipher::new(
            ContentKey::new([8; 32]),
            Header::new(BlockSize::new(BLOCK_SIZE_MIN).unwrap()),
            b"file-1".to_vec(),
        );
        assert!(
            other.open(0, &sealed).is_err(),
            "блок расшифрован ключом другого файла"
        );
    }

    #[test]
    fn substituted_block_size_breaks_opening() {
        let sealed = cipher().seal(0, b"secret").unwrap();
        let other = Cipher::new(
            ContentKey::new([9; 32]),
            Header::new(BlockSize::new(BLOCK_SIZE_MIN * 2).unwrap()),
            b"file-1".to_vec(),
        );
        assert!(
            other.open(0, &sealed).is_err(),
            "подмена размера блока в заголовке осталась незамеченной"
        );
    }

    #[test]
    fn oversized_block_is_rejected() {
        let subject = cipher();
        assert!(
            subject
                .seal(0, &vec![0; BLOCK_SIZE_MIN as usize + 1])
                .is_err(),
            "блок длиннее заявленного размера принят"
        );
    }

    #[test]
    fn header_survives_write_and_parse() {
        let header = Header::new(BlockSize::default());
        assert_eq!(
            Header::parse(&header.to_bytes()).unwrap(),
            header,
            "разбор заголовка вернул не то, что было записано"
        );
    }

    #[test]
    fn short_header_is_rejected() {
        assert!(
            Header::parse(&[1, 0, 0]).is_err(),
            "усечённый заголовок принят"
        );
    }

    #[test]
    fn foreign_format_version_is_rejected() {
        assert!(
            Header::parse(&[2, 0, 16, 0, 0]).is_err(),
            "неподдерживаемая версия формата принята"
        );
    }

    #[test]
    fn block_size_not_power_of_two_is_rejected() {
        assert!(
            BlockSize::new(BLOCK_SIZE_MIN + 1).is_err(),
            "размер блока, не являющийся степенью двойки, принят"
        );
    }

    #[test]
    fn undersized_block_size_is_rejected() {
        assert!(
            BlockSize::new(BLOCK_SIZE_MIN / 2).is_err(),
            "размер блока ниже предела принят"
        );
    }

    #[test]
    fn plaintext_length_counts_full_blocks() {
        let size = BlockSize::new(BLOCK_SIZE_MIN).unwrap();
        let ciphertext = HEADER_LEN as u64 + 2 * size.sealed() as u64;
        assert_eq!(
            plaintext_len(ciphertext, size).unwrap(),
            2 * u64::from(size.get()),
            "длина открытого текста посчитана неверно для полных блоков"
        );
    }

    #[test]
    fn plaintext_length_counts_partial_tail() {
        let size = BlockSize::new(BLOCK_SIZE_MIN).unwrap();
        let ciphertext = HEADER_LEN as u64 + size.sealed() as u64 + (24 + 16 + 7);
        assert_eq!(
            plaintext_len(ciphertext, size).unwrap(),
            u64::from(size.get()) + 7,
            "длина открытого текста посчитана неверно для неполного хвоста"
        );
    }

    #[test]
    fn ciphertext_shorter_than_header_is_rejected() {
        assert!(
            plaintext_len(3, BlockSize::default()).is_err(),
            "шифротекст короче заголовка принят"
        );
    }
}
