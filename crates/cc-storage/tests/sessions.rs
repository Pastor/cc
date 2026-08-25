//! Сценарии сессий.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_domain::{Keys, Rights, Scope, UserId};
use cc_storage::{Sessions, Token};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

const fn read_only() -> Scope {
    Scope::new(Rights::read_only(), Keys::Unwrapped)
}

fn sessions() -> Sessions {
    Sessions::new(Duration::hours(1))
}

const fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

#[tokio::test]
async fn opened_session_resolves_by_token() {
    let store = sessions();
    let (token, _) = store.open(UserId::generate(), Scope::full(), now()).await;
    assert!(
        store.resolve(&token, now()).await.is_ok(),
        "выданный токен не опознан"
    );
}

#[tokio::test]
async fn unknown_token_does_not_resolve() {
    assert!(
        sessions().resolve(&Token::generate(), now()).await.is_err(),
        "неизвестный токен опознан"
    );
}

#[tokio::test]
async fn expired_session_does_not_resolve() {
    let store = sessions();
    let (token, _) = store.open(UserId::generate(), Scope::full(), now()).await;
    assert!(
        store
            .resolve(&token, now() + Duration::hours(2))
            .await
            .is_err(),
        "истёкшая сессия опознана"
    );
}

#[tokio::test]
async fn closed_session_does_not_resolve() {
    let store = sessions();
    let (token, _) = store.open(UserId::generate(), Scope::full(), now()).await;
    store.close(&token).await;
    assert!(
        store.resolve(&token, now()).await.is_err(),
        "закрытая сессия продолжает опознаваться"
    );
}

#[tokio::test]
async fn closing_is_idempotent() {
    let store = sessions();
    let (token, _) = store.open(UserId::generate(), Scope::full(), now()).await;
    store.close(&token).await;
    store.close(&token).await;
    assert_eq!(
        store.count().await,
        0,
        "повторный выход изменил состояние хранилища"
    );
}

#[tokio::test]
async fn repeated_login_issues_new_token() {
    let store = sessions();
    let user = UserId::generate();
    let (first, _) = store.open(user, Scope::full(), now()).await;
    let (second, _) = store.open(user, read_only(), now()).await;
    assert!(
        !Sessions::same(&first, &second),
        "повторный вход вернул прежний токен вместо нового"
    );
}

#[tokio::test]
async fn repeated_login_applies_requested_rights() {
    let store = sessions();
    let user = UserId::generate();
    let (_, _) = store.open(user, Scope::full(), now()).await;
    let (token, _) = store.open(user, read_only(), now()).await;
    assert_eq!(
        store.resolve(&token, now()).await.unwrap().scope().rights(),
        Rights::read_only(),
        "запрошенный набор прав проигнорирован при повторном входе"
    );
}

#[tokio::test]
async fn resolving_records_the_moment() {
    let store = sessions();
    let (token, _) = store.open(UserId::generate(), Scope::full(), now()).await;
    let moment = now() + Duration::minutes(5);
    assert_eq!(
        store
            .resolve(&token, moment)
            .await
            .unwrap()
            .timing()
            .seen_at(),
        moment,
        "обращение не отмечено во временах сессии"
    );
}

#[tokio::test]
async fn sweeping_removes_expired_sessions() {
    let store = sessions();
    let _ = store.open(UserId::generate(), Scope::full(), now()).await;
    store.sweep(now() + Duration::hours(2)).await;
    assert_eq!(store.count().await, 0, "истёкшая сессия пережила чистку");
}

#[tokio::test]
async fn sweeping_keeps_live_sessions() {
    let store = sessions();
    let _ = store.open(UserId::generate(), Scope::full(), now()).await;
    store.sweep(now()).await;
    assert_eq!(store.count().await, 1, "действующая сессия удалена чисткой");
}

#[tokio::test]
async fn closing_others_keeps_the_current_session() {
    let store = sessions();
    let user = UserId::generate();
    let (token, session) = store.open(user, Scope::full(), now()).await;
    let _ = store.open(user, Scope::full(), now()).await;
    store.close_others(user, session.id()).await;
    assert!(
        store.resolve(&token, now()).await.is_ok(),
        "текущая сессия закрыта вместе с остальными"
    );
}

#[tokio::test]
async fn closing_others_closes_the_rest() {
    let store = sessions();
    let user = UserId::generate();
    let (_, session) = store.open(user, Scope::full(), now()).await;
    let _ = store.open(user, Scope::full(), now()).await;
    store.close_others(user, session.id()).await;
    assert_eq!(
        store.count().await,
        1,
        "прочие сессии пользователя пережили завершение"
    );
}

#[tokio::test]
async fn closing_others_spares_other_users() {
    let store = sessions();
    let user = UserId::generate();
    let (token, _) = store.open(user, Scope::full(), now()).await;
    let other = UserId::generate();
    let (_, session) = store.open(other, Scope::full(), now()).await;
    store.close_others(other, session.id()).await;
    assert!(
        store.resolve(&token, now()).await.is_ok(),
        "завершение сессий одного пользователя затронуло другого"
    );
}

#[tokio::test]
async fn concurrent_close_and_resolve_never_panics() {
    let store = Arc::new(sessions());
    let user = UserId::generate();
    let (token, _) = store.open(user, Scope::full(), now()).await;
    let closing = {
        let store = Arc::clone(&store);
        let token = token.clone();
        tokio::spawn(async move { store.close(&token).await })
    };
    let resolving = {
        let store = Arc::clone(&store);
        let token = token.clone();
        tokio::spawn(async move { store.resolve(&token, now()).await.is_ok() })
    };
    closing.await.unwrap();
    assert!(
        resolving.await.is_ok(),
        "конкурентные выход и обращение уронили задачу вместо отказа"
    );
}

#[tokio::test]
async fn token_is_not_printed_in_debug_output() {
    assert_eq!(
        format!("{:?}", Token::generate()),
        "Token([REDACTED])",
        "отладочный вывод раскрыл сессионный токен"
    );
}

#[tokio::test]
async fn session_identifier_is_unique_per_login() {
    let store = sessions();
    let user = UserId::generate();
    let (_, first) = store.open(user, Scope::full(), now()).await;
    let (_, second) = store.open(user, Scope::full(), now()).await;
    assert!(
        first.id() != second.id(),
        "два входа получили одинаковый идентификатор сессии"
    );
}

#[tokio::test]
async fn parsed_token_matches_generated() {
    let token = Token::generate();
    assert!(
        Sessions::same(&Token::parse(token.expose()).unwrap(), &token),
        "разобранный токен не совпал с исходным"
    );
}

#[tokio::test]
async fn short_token_is_rejected() {
    assert!(
        Token::parse(&[0; 4]).is_err(),
        "токен неверной длины принят"
    );
}

#[tokio::test]
async fn sweeper_stops_on_shutdown() {
    let store = Arc::new(sessions());
    let (signal, watch) = tokio::sync::watch::channel(false);
    let handle = Sessions::sweeper(Arc::clone(&store), Duration::milliseconds(10), watch);
    signal.send(true).unwrap();
    let stopped = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
    assert!(
        stopped.is_ok(),
        "фоновая чистка не завершилась по сигналу остановки"
    );
}
