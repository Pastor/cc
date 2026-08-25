//! Сценарии работы с содержимым и именами целиком, через публичный API ядра.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_client::{accept, decrypt_name, encrypt_name, enroll, grant, unlock, Reader, Writer};
use cc_crypto::{BlockSize, ContentKey, KdfParams, Salt, Secret};

fn identity() -> cc_client::Identity {
    let salt = Salt::new(vec![1; 16]).unwrap();
    let params = KdfParams::new(8, 1, 1).unwrap();
    let (enrollment, _) = enroll("пароль".as_bytes(), &salt, params).unwrap();
    unlock("пароль".as_bytes(), &salt, params, enrollment.wrapped()).unwrap()
}

fn payload() -> Vec<u8> {
    (0..10_000_u32).map(|value| (value % 251) as u8).collect()
}

/// Шифрует содержимое поблочно и возвращает заголовок вместе с блоками.
fn seal_all(writer: &Writer, plaintext: &[u8], block: usize) -> Vec<Vec<u8>> {
    plaintext
        .chunks(block)
        .enumerate()
        .map(|(index, chunk)| writer.block(index as u64, chunk).unwrap())
        .collect()
}

#[test]
fn content_survives_encryption_and_decryption() {
    let key = ContentKey::generate();
    let size = BlockSize::new(4096).unwrap();
    let writer = Writer::new(key.clone(), size, b"file".to_vec());
    let blocks = seal_all(&writer, &payload(), size.get() as usize);
    let reader = Reader::new(key, &writer.header(), b"file".to_vec()).unwrap();
    let restored: Vec<u8> = blocks
        .iter()
        .enumerate()
        .flat_map(|(index, block)| reader.block(index as u64, block).unwrap())
        .collect();
    assert_eq!(
        restored,
        payload(),
        "расшифрованное содержимое разошлось с исходным"
    );
}

#[test]
fn arbitrary_block_reads_without_reading_the_whole_file() {
    let key = ContentKey::generate();
    let size = BlockSize::new(4096).unwrap();
    let writer = Writer::new(key.clone(), size, b"file".to_vec());
    let blocks = seal_all(&writer, &payload(), size.get() as usize);
    let reader = Reader::new(key, &writer.header(), b"file".to_vec()).unwrap();
    let expected: Vec<u8> = payload()
        .chunks(size.get() as usize)
        .nth(1)
        .unwrap()
        .to_vec();
    assert_eq!(
        reader.block(1, &blocks[1]).unwrap(),
        expected,
        "чтение отдельного блока вернуло не тот отрезок"
    );
}

#[test]
fn foreign_key_does_not_read_content() {
    let size = BlockSize::new(4096).unwrap();
    let writer = Writer::new(ContentKey::generate(), size, b"file".to_vec());
    let sealed = writer.block(0, b"secret").unwrap();
    let reader = Reader::new(ContentKey::generate(), &writer.header(), b"file".to_vec()).unwrap();
    assert!(
        reader.block(0, &sealed).is_err(),
        "содержимое прочитано чужим ключом"
    );
}

#[test]
fn name_survives_encryption_and_decryption() {
    let subject = identity();
    let sealed = encrypt_name(subject.account(), "отчёт.pdf").unwrap();
    assert_eq!(
        decrypt_name(subject.account(), &sealed).unwrap(),
        "отчёт.pdf",
        "расшифрованное имя разошлось с исходным"
    );
}

#[test]
fn encrypted_name_does_not_leak_plaintext() {
    let subject = identity();
    let sealed = encrypt_name(subject.account(), "отчёт.pdf").unwrap();
    assert!(
        !sealed
            .windows("отчёт.pdf".len())
            .any(|window| window == "отчёт.pdf".as_bytes()),
        "имя видно в шифротексте"
    );
}

#[test]
fn foreign_account_key_does_not_read_name() {
    let sealed = encrypt_name(identity().account(), "отчёт.pdf").unwrap();
    assert!(
        decrypt_name(identity().account(), &sealed).is_err(),
        "имя прочитано чужим ключом учётной записи"
    );
}

#[test]
fn granted_key_opens_for_recipient() {
    let recipient = identity();
    let key = Secret::new([42_u8; 32]);
    let wrapped = grant(&recipient.pair().public(), &key).unwrap();
    assert_eq!(
        accept(&recipient, &wrapped).unwrap(),
        key,
        "получатель развернул не тот ключ, который ему выдали"
    );
}

#[test]
fn granted_key_stays_closed_for_others() {
    let wrapped = grant(&identity().pair().public(), &Secret::new([42_u8; 32])).unwrap();
    assert!(
        accept(&identity(), &wrapped).is_err(),
        "выданный ключ развернул посторонний"
    );
}
