//! Свойства криптографических преобразований на случайных входных данных.
//!
//! Написанные вручную тесты проверяют случаи, которые автор предвидел. Свойства
//! проверяют то, о чём он не подумал: усечение пароля до шестнадцати символов в
//! прежней реализации ни один пример не поймал бы.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_crypto::{
    derive_master_key, open, open_for, plaintext_len, seal, seal_for, AccountKey, BlockSize,
    Cipher, ContentKey, Header, KdfParams, KeyPair, RecoveryKey, Salt, Secret, TagKey, TagLabel,
    BLOCK_SIZE_MIN, HEADER_LEN,
};
use proptest::prelude::*;

/// Дешёвые параметры: свойства проверяют поведение, а не стойкость.
fn params() -> KdfParams {
    KdfParams::new(8, 1, 1).unwrap()
}

/// Собирает шифровальщик содержимого.
fn cipher(key: [u8; 32], file: Vec<u8>) -> Cipher {
    Cipher::new(
        ContentKey::new(key),
        Header::new(BlockSize::new(BLOCK_SIZE_MIN).unwrap()),
        file,
    )
}

proptest! {
    #[test]
    fn content_survives_round_trip(
        plaintext in proptest::collection::vec(any::<u8>(), 0..BLOCK_SIZE_MIN as usize),
        key in any::<[u8; 32]>(),
    ) {
        let subject = cipher(key, b"file".to_vec());
        let sealed = subject.seal(0, &plaintext).unwrap();
        prop_assert_eq!(
            subject.open(0, &sealed).unwrap(),
            plaintext,
            "расшифрованное содержимое разошлось с исходным"
        );
    }

    #[test]
    fn sealing_is_never_deterministic(
        plaintext in proptest::collection::vec(any::<u8>(), 1..256),
        key in any::<[u8; 32]>(),
    ) {
        let subject = cipher(key, b"file".to_vec());
        prop_assert!(
            subject.seal(0, &plaintext).unwrap() != subject.seal(0, &plaintext).unwrap(),
            "два шифрования одного содержимого совпали: nonce повторяется"
        );
    }

    #[test]
    fn corrupting_any_byte_breaks_opening(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        key in any::<[u8; 32]>(),
        position in 0_usize..64,
    ) {
        let subject = cipher(key, b"file".to_vec());
        let mut sealed = subject.seal(0, &plaintext).unwrap();
        let at = position % sealed.len();
        sealed[at] ^= 1;
        prop_assert!(
            subject.open(0, &sealed).is_err(),
            "искажение байта осталось незамеченным"
        );
    }

    #[test]
    fn block_never_opens_under_another_index(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        key in any::<[u8; 32]>(),
        index in 1_u64..1000,
    ) {
        let subject = cipher(key, b"file".to_vec());
        let sealed = subject.seal(0, &plaintext).unwrap();
        prop_assert!(
            subject.open(index, &sealed).is_err(),
            "блок расшифрован под чужим номером: их можно переставлять"
        );
    }

    #[test]
    fn block_never_opens_in_another_file(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        key in any::<[u8; 32]>(),
        other in proptest::collection::vec(any::<u8>(), 1..32),
    ) {
        prop_assume!(other != b"file".to_vec());
        let sealed = cipher(key, b"file".to_vec()).seal(0, &plaintext).unwrap();
        prop_assert!(
            cipher(key, other).open(0, &sealed).is_err(),
            "блок расшифрован в другом файле: его можно перенести"
        );
    }

    #[test]
    fn distinct_passwords_give_distinct_keys(
        first in ".{1,64}",
        second in ".{1,64}",
    ) {
        prop_assume!(first != second);
        let salt = Salt::new(vec![1; 16]).unwrap();
        let one = derive_master_key(first.as_bytes(), &salt, params()).unwrap();
        let two = derive_master_key(second.as_bytes(), &salt, params()).unwrap();
        prop_assert!(
            one.expose() != two.expose(),
            "разные пароли дали один ключ: {:?} и {:?}",
            first,
            second
        );
    }

    #[test]
    fn distinct_salts_give_distinct_keys(
        password in ".{1,64}",
        first in proptest::collection::vec(any::<u8>(), 16..32),
        second in proptest::collection::vec(any::<u8>(), 16..32),
    ) {
        prop_assume!(first != second);
        let one = derive_master_key(
            password.as_bytes(),
            &Salt::new(first).unwrap(),
            params(),
        )
        .unwrap();
        let two = derive_master_key(
            password.as_bytes(),
            &Salt::new(second).unwrap(),
            params(),
        )
        .unwrap();
        prop_assert!(
            one.expose() != two.expose(),
            "разные соли дали один ключ"
        );
    }

    #[test]
    fn any_password_is_accepted(password in ".{0,256}") {
        let salt = Salt::new(vec![1; 16]).unwrap();
        prop_assert!(
            derive_master_key(password.as_bytes(), &salt, params()).is_ok(),
            "пароль отвергнут: {:?}",
            password
        );
    }

    #[test]
    fn symmetric_wrapping_survives_round_trip(
        kek in any::<[u8; 32]>(),
        key in any::<[u8; 32]>(),
    ) {
        let kek = Secret::new(kek);
        let key = Secret::new(key);
        let wrapped = seal(&kek, &key).unwrap();
        prop_assert_eq!(
            open(&kek, &wrapped).unwrap(),
            key,
            "симметричная обёртка вернула не тот ключ"
        );
    }

    #[test]
    fn symmetric_wrapping_resists_foreign_key(
        kek in any::<[u8; 32]>(),
        other in any::<[u8; 32]>(),
        key in any::<[u8; 32]>(),
    ) {
        prop_assume!(kek != other);
        let wrapped = seal(&Secret::new(kek), &Secret::new(key)).unwrap();
        prop_assert!(
            open(&Secret::new(other), &wrapped).is_err(),
            "обёртка снята чужим ключом"
        );
    }

    #[test]
    fn asymmetric_wrapping_survives_round_trip(key in any::<[u8; 32]>()) {
        let pair = KeyPair::generate();
        let key = Secret::new(key);
        let wrapped = seal_for(&pair.public(), &key).unwrap();
        prop_assert_eq!(
            open_for(&pair, &wrapped).unwrap(),
            key,
            "получатель развернул не тот ключ"
        );
    }

    #[test]
    fn tag_label_is_stable_and_key_bound(
        value in ".{0,64}",
        first in any::<[u8; 32]>(),
        second in any::<[u8; 32]>(),
    ) {
        prop_assume!(first != second);
        let one = TagLabel::of(&TagKey::new(first), value.as_bytes());
        prop_assert_eq!(
            one,
            TagLabel::of(&TagKey::new(first), value.as_bytes()),
            "метка тега оказалась невоспроизводимой"
        );
        prop_assert!(
            one != TagLabel::of(&TagKey::new(second), value.as_bytes()),
            "метка тега не зависит от ключа: она сравнима между пользователями"
        );
    }

    #[test]
    fn tag_key_follows_from_account_key(account in any::<[u8; 32]>()) {
        prop_assert_eq!(
            AccountKey::new(account).tags(),
            AccountKey::new(account).tags(),
            "ключ тегов невоспроизводим: смена пароля потребует переиндексации"
        );
    }

    #[test]
    fn plaintext_length_matches_sealed_content(
        blocks in 0_usize..4,
        tail in 0_u64..1000,
    ) {
        let size = BlockSize::new(BLOCK_SIZE_MIN).unwrap();
        let full = blocks as u64 * size.sealed() as u64;
        let ciphertext = HEADER_LEN as u64 + full + if tail == 0 { 0 } else { tail + 24 + 16 };
        let expected = blocks as u64 * u64::from(size.get()) + tail;
        prop_assert_eq!(
            plaintext_len(ciphertext, size).unwrap(),
            expected,
            "длина открытого текста посчитана неверно"
        );
    }

    #[test]
    fn recovery_keys_are_distinct(count in 2_usize..8) {
        let keys: Vec<[u8; 32]> = (0..count)
            .map(|_| *RecoveryKey::generate().expose())
            .collect();
        let unique: std::collections::BTreeSet<_> = keys.iter().collect();
        prop_assert_eq!(
            unique.len(),
            keys.len(),
            "порождение ключей восстановления повторяется"
        );
    }
}
