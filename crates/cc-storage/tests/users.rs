//! Сценарии учётной записи на стороне сервера.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_crypto::{AuthHash, KdfParams, KeyPair, Salt};
use cc_domain::Username;
use cc_storage::{Challenge, Users, Wrapped};
use std::sync::Arc;
use time::OffsetDateTime;

fn params() -> KdfParams {
    KdfParams::new(8, 1, 1).unwrap()
}

fn users() -> Users {
    Users::new(vec![0x5a; 16], params())
}

fn login(text: &str) -> Username {
    Username::new(text).unwrap()
}

fn challenge() -> Challenge {
    Challenge::new(Salt::new(vec![1; 16]).unwrap(), params())
}

fn wrapped() -> Wrapped {
    Wrapped::new(vec![1; 72], vec![2; 72], vec![3; 72])
}

async fn registered(store: &Users, name: &str, auth: &AuthHash) {
    store
        .register(
            login(name),
            challenge(),
            auth,
            KeyPair::generate().public(),
            wrapped(),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn fresh_store_has_no_users() {
    assert_eq!(
        users().count().await,
        0,
        "в только что заведённом хранилище уже есть пользователи"
    );
}

#[tokio::test]
async fn registration_creates_account() {
    let store = users();
    registered(&store, "user@example.com", &AuthHash::new([7; 32])).await;
    assert_eq!(
        store.count().await,
        1,
        "регистрация не создала учётную запись"
    );
}

#[tokio::test]
async fn taken_login_is_rejected() {
    let store = users();
    registered(&store, "user@example.com", &AuthHash::new([7; 32])).await;
    let again = store
        .register(
            login("user@example.com"),
            challenge(),
            &AuthHash::new([8; 32]),
            KeyPair::generate().public(),
            wrapped(),
            OffsetDateTime::UNIX_EPOCH,
        )
        .await;
    assert!(again.is_err(), "занятый логин зарегистрирован повторно");
}

#[tokio::test]
async fn concurrent_registration_succeeds_once() {
    let store = Arc::new(users());
    let attempts = (0..16).map(|index| {
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            store
                .register(
                    login("user@example.com"),
                    challenge(),
                    &AuthHash::new([index; 32]),
                    KeyPair::generate().public(),
                    wrapped(),
                    OffsetDateTime::UNIX_EPOCH,
                )
                .await
                .is_ok()
        })
    });
    let mut succeeded = 0;
    for attempt in attempts {
        if attempt.await.unwrap() {
            succeeded += 1;
        }
    }
    assert_eq!(
        succeeded, 1,
        "конкурентная регистрация одного логина прошла не ровно один раз"
    );
}

#[tokio::test]
async fn correct_hash_authenticates() {
    let store = users();
    let auth = AuthHash::new([7; 32]);
    registered(&store, "user@example.com", &auth).await;
    assert!(
        store
            .authenticate(&login("user@example.com"), &auth)
            .await
            .is_ok(),
        "верный аутентификационный хеш отвергнут"
    );
}

#[tokio::test]
async fn wrong_hash_does_not_authenticate() {
    let store = users();
    registered(&store, "user@example.com", &AuthHash::new([7; 32])).await;
    assert!(
        store
            .authenticate(&login("user@example.com"), &AuthHash::new([8; 32]))
            .await
            .is_err(),
        "неверный аутентификационный хеш принят"
    );
}

#[tokio::test]
async fn unknown_login_fails_like_wrong_hash() {
    let store = users();
    registered(&store, "user@example.com", &AuthHash::new([7; 32])).await;
    let unknown = store
        .authenticate(&login("nobody@example.com"), &AuthHash::new([7; 32]))
        .await
        .unwrap_err()
        .to_string();
    let wrong = store
        .authenticate(&login("user@example.com"), &AuthHash::new([8; 32]))
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        unknown, wrong,
        "отказы различимы: API работает оракулом существования учётных записей"
    );
}

#[tokio::test]
async fn challenge_is_returned_for_unknown_login() {
    assert!(
        users()
            .challenge(&login("nobody@example.com"))
            .await
            .is_ok(),
        "по неизвестному логину параметры не выданы: их отсутствие раскрывает регистрацию"
    );
}

#[tokio::test]
async fn challenge_for_unknown_login_is_stable() {
    let store = users();
    let first = store.challenge(&login("nobody@example.com")).await.unwrap();
    assert_eq!(
        store.challenge(&login("nobody@example.com")).await.unwrap(),
        first,
        "правдоподобные параметры меняются между запросами и потому распознаются"
    );
}

#[tokio::test]
async fn challenge_matches_registration_for_known_login() {
    let store = users();
    registered(&store, "user@example.com", &AuthHash::new([7; 32])).await;
    assert_eq!(
        store.challenge(&login("user@example.com")).await.unwrap(),
        challenge(),
        "по известному логину выданы не те параметры, что были при регистрации"
    );
}

#[tokio::test]
async fn password_change_invalidates_previous_hash() {
    let store = users();
    let current = AuthHash::new([7; 32]);
    registered(&store, "user@example.com", &current).await;
    store
        .change_password(
            &login("user@example.com"),
            &current,
            Challenge::new(Salt::new(vec![9; 16]).unwrap(), params()),
            &AuthHash::new([8; 32]),
            vec![4; 72],
        )
        .await
        .unwrap();
    assert!(
        store
            .authenticate(&login("user@example.com"), &current)
            .await
            .is_err(),
        "прежний аутентификационный хеш продолжает работать после смены пароля"
    );
}

#[tokio::test]
async fn password_change_requires_current_hash() {
    let store = users();
    registered(&store, "user@example.com", &AuthHash::new([7; 32])).await;
    let attempt = store
        .change_password(
            &login("user@example.com"),
            &AuthHash::new([0; 32]),
            challenge(),
            &AuthHash::new([8; 32]),
            vec![4; 72],
        )
        .await;
    assert!(
        attempt.is_err(),
        "пароль сменён без подтверждения прежним хешем"
    );
}

#[tokio::test]
async fn password_change_replaces_salt() {
    let store = users();
    let current = AuthHash::new([7; 32]);
    registered(&store, "user@example.com", &current).await;
    let next = Challenge::new(Salt::new(vec![9; 16]).unwrap(), params());
    store
        .change_password(
            &login("user@example.com"),
            &current,
            next.clone(),
            &AuthHash::new([8; 32]),
            vec![4; 72],
        )
        .await
        .unwrap();
    assert_eq!(
        store.challenge(&login("user@example.com")).await.unwrap(),
        next,
        "смена пароля не заменила соль"
    );
}

#[tokio::test]
async fn stored_form_differs_from_presented_hash() {
    let store = users();
    let auth = AuthHash::new([7; 32]);
    registered(&store, "user@example.com", &auth).await;
    let (_, keys) = store
        .authenticate(&login("user@example.com"), &auth)
        .await
        .unwrap();
    assert!(
        !keys
            .account_by_password()
            .windows(32)
            .any(|window| window == auth.expose()),
        "аутентификационный хеш встречается в хранимых данных в исходном виде"
    );
}
