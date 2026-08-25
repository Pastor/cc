//! Сценарии подтверждения почты.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_domain::Username;
use cc_storage::{Confirmations, LIFETIME, MAX_ATTEMPTS};
use time::{Duration, OffsetDateTime};

fn login() -> Username {
    Username::new("user@example.com").unwrap()
}

const fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

#[tokio::test]
async fn issued_code_confirms() {
    let codes = Confirmations::new();
    codes.issue(login(), "123456", now()).await;
    assert!(
        codes.confirm(&login(), "123456", now()).await.is_ok(),
        "верный код отвергнут"
    );
}

#[tokio::test]
async fn wrong_code_does_not_confirm() {
    let codes = Confirmations::new();
    codes.issue(login(), "123456", now()).await;
    assert!(
        codes.confirm(&login(), "654321", now()).await.is_err(),
        "неверный код принят"
    );
}

#[tokio::test]
async fn code_is_single_use() {
    let codes = Confirmations::new();
    codes.issue(login(), "123456", now()).await;
    codes.confirm(&login(), "123456", now()).await.unwrap();
    assert!(
        codes.confirm(&login(), "123456", now()).await.is_err(),
        "код сработал повторно"
    );
}

#[tokio::test]
async fn expired_code_does_not_confirm() {
    let codes = Confirmations::new();
    codes.issue(login(), "123456", now()).await;
    assert!(
        codes
            .confirm(&login(), "123456", now() + LIFETIME + Duration::seconds(1))
            .await
            .is_err(),
        "истёкший код принят"
    );
}

#[tokio::test]
async fn attempts_are_limited() {
    let codes = Confirmations::new();
    codes.issue(login(), "123456", now()).await;
    for _ in 0..MAX_ATTEMPTS {
        let _ = codes.confirm(&login(), "000000", now()).await;
    }
    assert!(
        codes.confirm(&login(), "123456", now()).await.is_err(),
        "код принят после исчерпания попыток: он подбирается перебором"
    );
}

#[tokio::test]
async fn reissue_replaces_previous_code() {
    let codes = Confirmations::new();
    codes.issue(login(), "111111", now()).await;
    codes.issue(login(), "222222", now()).await;
    assert!(
        codes.confirm(&login(), "111111", now()).await.is_err(),
        "прежний код действует после выпуска нового"
    );
}
