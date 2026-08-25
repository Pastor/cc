//! Сценарии учётной записи целиком, через публичный API ядра.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_client::{change_password, enroll, recover, unlock, Enrollment, Identity, WrappedKeys};
use cc_crypto::{KdfParams, RecoveryKey, Salt};

fn params() -> KdfParams {
    KdfParams::new(8, 1, 1).unwrap()
}

fn salt(byte: u8) -> Salt {
    Salt::new(vec![byte; 16]).unwrap()
}

fn account() -> (Enrollment, RecoveryKey) {
    enroll("пароль".as_bytes(), &salt(1), params()).unwrap()
}

#[test]
fn correct_password_unlocks_keys() {
    let (enrollment, _) = account();
    assert!(
        unlock(
            "пароль".as_bytes(),
            &salt(1),
            params(),
            enrollment.wrapped()
        )
        .is_ok(),
        "верный пароль не развернул ключи"
    );
}

#[test]
fn wrong_password_does_not_unlock_keys() {
    let (enrollment, _) = account();
    assert!(
        unlock(
            "другой".as_bytes(),
            &salt(1),
            params(),
            enrollment.wrapped()
        )
        .is_err(),
        "неверный пароль развернул ключи"
    );
}

#[test]
fn recovery_key_unlocks_keys() {
    let (enrollment, recovery) = account();
    assert!(
        recover(&recovery, enrollment.wrapped()).is_ok(),
        "ключ восстановления не развернул ключи"
    );
}

#[test]
fn foreign_recovery_key_does_not_unlock_keys() {
    let (enrollment, _) = account();
    assert!(
        recover(&RecoveryKey::generate(), enrollment.wrapped()).is_err(),
        "чужой ключ восстановления развернул ключи"
    );
}

#[test]
fn recovery_gives_the_same_account_key_as_password() {
    let (enrollment, recovery) = account();
    let by_password = unlock(
        "пароль".as_bytes(),
        &salt(1),
        params(),
        enrollment.wrapped(),
    )
    .unwrap();
    assert_eq!(
        recover(&recovery, enrollment.wrapped()).unwrap().account(),
        by_password.account(),
        "восстановление дало не тот ключ учётной записи, что вход по паролю"
    );
}

#[test]
fn enrollment_does_not_expose_account_key() {
    let (enrollment, _) = account();
    let identity = unlock(
        "пароль".as_bytes(),
        &salt(1),
        params(),
        enrollment.wrapped(),
    )
    .unwrap();
    assert!(
        !enrollment
            .wrapped()
            .account_by_password()
            .windows(32)
            .any(|window| window == identity.account().expose()),
        "ключ учётной записи виден в обёртке, уходящей на сервер"
    );
}

#[test]
fn password_change_keeps_account_key_intact() {
    let (enrollment, _) = account();
    let identity = unlock(
        "пароль".as_bytes(),
        &salt(1),
        params(),
        enrollment.wrapped(),
    )
    .unwrap();
    let (_, rewrapped) =
        change_password(&identity, "новый".as_bytes(), &salt(2), params()).unwrap();
    let updated = WrappedKeys::new(
        rewrapped,
        enrollment.wrapped().account_by_recovery().to_vec(),
        enrollment.wrapped().private_by_account().to_vec(),
    );
    let after = unlock("новый".as_bytes(), &salt(2), params(), &updated).unwrap();
    assert_eq!(
        after.account(),
        identity.account(),
        "смена пароля изменила ключ учётной записи: старые файлы стали нечитаемы"
    );
}

#[test]
fn password_change_invalidates_old_password() {
    let (enrollment, _) = account();
    let identity = unlock(
        "пароль".as_bytes(),
        &salt(1),
        params(),
        enrollment.wrapped(),
    )
    .unwrap();
    let (_, rewrapped) =
        change_password(&identity, "новый".as_bytes(), &salt(2), params()).unwrap();
    let updated = WrappedKeys::new(
        rewrapped,
        enrollment.wrapped().account_by_recovery().to_vec(),
        enrollment.wrapped().private_by_account().to_vec(),
    );
    assert!(
        unlock("пароль".as_bytes(), &salt(1), params(), &updated).is_err(),
        "старый пароль продолжает разворачивать ключи после смены"
    );
}

#[test]
fn tag_key_survives_password_change() {
    let (enrollment, _) = account();
    let identity: Identity = unlock(
        "пароль".as_bytes(),
        &salt(1),
        params(),
        enrollment.wrapped(),
    )
    .unwrap();
    let before = identity.tags();
    let (_, rewrapped) =
        change_password(&identity, "новый".as_bytes(), &salt(2), params()).unwrap();
    let updated = WrappedKeys::new(
        rewrapped,
        enrollment.wrapped().account_by_recovery().to_vec(),
        enrollment.wrapped().private_by_account().to_vec(),
    );
    let after = unlock("новый".as_bytes(), &salt(2), params(), &updated).unwrap();
    assert_eq!(
        after.tags(),
        before,
        "смена пароля изменила ключ тегов: потребовалась бы переиндексация"
    );
}
