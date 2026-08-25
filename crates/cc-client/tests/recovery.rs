//! Сценарий восстановления доступа целиком.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_client::{
    change_password, decrypt_name, encrypt_name, enroll, read, recover, unlock, write, Fingerprint,
    WrappedKeys,
};
use cc_crypto::{KdfParams, Salt};

fn params() -> KdfParams {
    KdfParams::new(8, 1, 1).unwrap()
}

fn salt(byte: u8) -> Salt {
    Salt::new(vec![byte; 16]).unwrap()
}

#[test]
fn forgotten_password_is_recovered_by_key() {
    let (enrollment, recovery) = enroll("пароль".as_bytes(), &salt(1), params()).unwrap();
    let written = write(&recovery);
    let restored = read(&written).unwrap();
    assert!(
        recover(&restored, enrollment.wrapped()).is_ok(),
        "переписанный ключ восстановления не открыл доступ"
    );
}

#[test]
fn files_stay_readable_after_recovery() {
    let (enrollment, recovery) = enroll("пароль".as_bytes(), &salt(1), params()).unwrap();
    let before = unlock(
        "пароль".as_bytes(),
        &salt(1),
        params(),
        enrollment.wrapped(),
    )
    .unwrap();
    let sealed = encrypt_name(before.account(), "отчёт.pdf").unwrap();
    let after = recover(&recovery, enrollment.wrapped()).unwrap();
    assert_eq!(
        decrypt_name(after.account(), &sealed).unwrap(),
        "отчёт.pdf",
        "после восстановления прежние файлы перестали читаться"
    );
}

#[test]
fn recovery_leads_to_password_change() {
    let (enrollment, recovery) = enroll("пароль".as_bytes(), &salt(1), params()).unwrap();
    let identity = recover(&recovery, enrollment.wrapped()).unwrap();
    let (_, rewrapped) =
        change_password(&identity, "новый".as_bytes(), &salt(2), params()).unwrap();
    let updated = WrappedKeys::new(
        rewrapped,
        enrollment.wrapped().account_by_recovery().to_vec(),
        enrollment.wrapped().private_by_account().to_vec(),
    );
    assert!(
        unlock("новый".as_bytes(), &salt(2), params(), &updated).is_ok(),
        "после восстановления новый пароль не работает"
    );
}

#[test]
fn recovery_key_never_reaches_the_server() {
    let (enrollment, recovery) = enroll("пароль".as_bytes(), &salt(1), params()).unwrap();
    let outgoing = [
        enrollment.wrapped().account_by_password(),
        enrollment.wrapped().account_by_recovery(),
        enrollment.wrapped().private_by_account(),
        enrollment.auth().expose(),
    ]
    .concat();
    assert!(
        !outgoing
            .windows(32)
            .any(|window| window == recovery.expose()),
        "ключ восстановления встречается в том, что уходит на сервер"
    );
}

#[test]
fn fingerprint_identifies_the_key_without_revealing_it() {
    let (_, recovery) = enroll("пароль".as_bytes(), &salt(1), params()).unwrap();
    let fingerprint = Fingerprint::of(&recovery);
    assert_eq!(
        Fingerprint::of(&read(&write(&recovery)).unwrap()),
        fingerprint,
        "отпечаток переписанного ключа разошёлся с исходным"
    );
}
