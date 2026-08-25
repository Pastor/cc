//! Сценарии запросов авторизации у внешнего провайдера.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_domain::Provider;
use cc_storage::{Authorizations, Error, Pkce, Ticket};
use time::{Duration, OffsetDateTime};

const fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

fn requests() -> Authorizations {
    Authorizations::new(Duration::minutes(5))
}

#[tokio::test]
async fn started_request_is_claimed_by_its_ticket() {
    let store = requests();
    let (ticket, _) = store.start(Provider::Vk, "клиент", now()).await;
    assert_eq!(
        store
            .claim(&ticket, "клиент", now())
            .await
            .unwrap()
            .provider(),
        Provider::Vk,
        "запрос авторизации не нашёлся по собственному билету"
    );
}

#[tokio::test]
async fn ticket_serves_only_once() {
    let store = requests();
    let (ticket, _) = store.start(Provider::Vk, "клиент", now()).await;
    store.claim(&ticket, "клиент", now()).await.unwrap();
    assert!(
        matches!(
            store.claim(&ticket, "клиент", now()).await,
            Err(Error::Missing)
        ),
        "билет запроса авторизации сработал во второй раз"
    );
}

#[tokio::test]
async fn foreign_ticket_is_refused() {
    let store = requests();
    store.start(Provider::Vk, "клиент", now()).await;
    assert!(
        matches!(
            store
                .claim(&Ticket::presented("чужой"), "клиент", now())
                .await,
            Err(Error::Missing)
        ),
        "ответ с чужим билетом принят"
    );
}

#[tokio::test]
async fn request_of_another_client_is_refused() {
    let store = requests();
    let (ticket, _) = store.start(Provider::Vk, "клиент", now()).await;
    assert!(
        matches!(
            store.claim(&ticket, "посторонний", now()).await,
            Err(Error::Missing)
        ),
        "запрос авторизации изъят клиентом, который его не начинал"
    );
}

#[tokio::test]
async fn expired_request_is_refused() {
    let store = requests();
    let (ticket, _) = store.start(Provider::Vk, "клиент", now()).await;
    assert!(
        matches!(
            store
                .claim(&ticket, "клиент", now() + Duration::minutes(6))
                .await,
            Err(Error::Missing)
        ),
        "просроченный запрос авторизации всё ещё действителен"
    );
}

#[tokio::test]
async fn sweeping_removes_expired_requests() {
    let store = requests();
    let (ticket, _) = store.start(Provider::Vk, "клиент", now()).await;
    store.sweep(now() + Duration::minutes(6)).await;
    assert!(
        matches!(
            store.claim(&ticket, "клиент", now()).await,
            Err(Error::Missing)
        ),
        "уборка оставила просроченный запрос авторизации"
    );
}

#[tokio::test]
async fn sweeping_keeps_live_requests() {
    let store = requests();
    let (ticket, _) = store.start(Provider::Vk, "клиент", now()).await;
    store.sweep(now() + Duration::minutes(1)).await;
    assert!(
        store.claim(&ticket, "клиент", now()).await.is_ok(),
        "уборка выбросила действующий запрос авторизации"
    );
}

#[tokio::test]
async fn every_request_gets_its_own_secret() {
    let store = requests();
    let (_, first) = store.start(Provider::Vk, "клиент", now()).await;
    let (_, second) = store.start(Provider::Vk, "клиент", now()).await;
    assert_ne!(
        first.pkce().expose(),
        second.pkce().expose(),
        "два запроса авторизации получили один секрет PKCE"
    );
}

/// RFC 7636, приложение B: эталонная пара секрета и его хеша.
#[test]
fn challenge_matches_rfc7636() {
    assert_eq!(
        Pkce::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
            .unwrap()
            .challenge(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge разошёлся с вектором RFC 7636"
    );
}

#[test]
fn short_verifier_is_rejected() {
    assert!(
        matches!(Pkce::new("слишком-короткий"), Err(Error::Malformed)),
        "секрет короче предела RFC 7636 принят"
    );
}

#[test]
fn verifier_with_forbidden_symbol_is_rejected() {
    assert!(
        matches!(
            Pkce::new("dBjftJeZ4CVP+mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            Err(Error::Malformed)
        ),
        "секрет с символом вне множества unreserved принят"
    );
}

#[test]
fn generated_verifier_is_valid() {
    assert!(
        Pkce::new(Pkce::generate().expose()).is_ok(),
        "порождённый секрет PKCE не проходит собственную проверку"
    );
}
