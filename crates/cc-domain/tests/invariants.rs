//! Проверка инвариантов значимых типов на случайных входных данных.
//!
//! Тесты, написанные вручную, проверяют случаи, которые автор предвидел.
//! Свойства проверяют то, о чём он не подумал.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_domain::{ByteSize, ContentHash, Quota, Right, Rights, Username};
use proptest::prelude::*;

proptest! {
    #[test]
    fn content_hash_accepts_only_sixty_four_hexadecimal_digits(text in ".*") {
        let accepted = ContentHash::new(text.clone()).is_ok();
        let expected = text.len() == 64
            && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        prop_assert_eq!(
            accepted,
            expected,
            "хеш принят вопреки требованию к записи: {:?}",
            text
        );
    }

    #[test]
    fn content_hash_rejects_path_separators(prefix in "[a-f0-9]{0,63}") {
        let text = format!("{prefix}/");
        prop_assert!(
            ContentHash::new(text).is_err(),
            "запись с разделителем пути принята"
        );
    }

    #[test]
    fn computed_hash_is_always_accepted(bytes in any::<[u8; 32]>()) {
        let computed = ContentHash::of(&bytes);
        prop_assert!(
            ContentHash::new(computed.as_str()).is_ok(),
            "вычисленный хеш не прошёл собственную проверку"
        );
    }

    #[test]
    fn username_never_contains_whitespace(text in ".*") {
        let Ok(name) = Username::new(text) else {
            return Ok(());
        };
        prop_assert!(
            !name.as_str().chars().any(char::is_whitespace),
            "принятое имя содержит пробельный символ"
        );
    }

    #[test]
    fn quota_never_exceeds_its_limit(limit in 0_u64..1_000_000, taken in 0_u64..2_000_000) {
        let quota = Quota::empty(ByteSize::new(limit));
        let Ok(after) = quota.take(ByteSize::new(taken)) else {
            return Ok(());
        };
        prop_assert!(
            after.used().get() <= after.limit().get(),
            "занятие увело израсходованный объём за предел"
        );
    }

    #[test]
    fn quota_release_never_underflows(limit in 0_u64..1_000, released in 0_u64..10_000) {
        let quota = Quota::empty(ByteSize::new(limit));
        prop_assert_eq!(
            quota.release(ByteSize::new(released)).used(),
            ByteSize::new(0),
            "освобождение из пустой квоты дало ненулевой расход"
        );
    }

    #[test]
    fn granted_rights_never_exceed_grantor(bits in 0_u8..32, grantor_bits in 0_u8..32) {
        let rights = rights_from(bits);
        let grantor = rights_from(grantor_bits);
        let Ok(granted) = rights.granted_by(grantor) else {
            return Ok(());
        };
        prop_assert!(
            granted.within(grantor),
            "выданные права оказались шире прав выдающего"
        );
    }
}

/// Собирает набор прав из битовой маски — proptest порождает числа, а не права.
fn rights_from(bits: u8) -> Rights {
    [
        Right::Read,
        Right::Write,
        Right::Delete,
        Right::Grant,
        Right::Publish,
    ]
    .into_iter()
    .enumerate()
    .filter(|(index, _)| bits & (1 << index) != 0)
    .map(|(_, right)| right)
    .collect()
}
