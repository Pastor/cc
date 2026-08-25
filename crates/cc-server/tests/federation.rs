//! Сценарии внешнего входа.
//!
//! Учётная запись через внешний вход не создаётся: он открывает доступ к уже
//! существующей записи с привязанной личностью (`TODO.md`, раздел 4.3).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

mod support;

use cc_crypto::{sha256, Signature};
use support::{unique_login, Instance};

/// Токен бота, которым настроен сервер в этих сценариях.
const TOKEN: &str = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11";

/// Собирает подписанные данные виджета для указанного пользователя.
///
/// Подпись считается так же, как её считает провайдер: HMAC-SHA256 строки
/// отсортированных полей ключом `SHA256(токен бота)`.
fn widget(subject: &str, moment: i64) -> String {
    let check = format!("auth_date={moment}\nid={subject}\nusername=ivan");
    let signature = Signature::of(&sha256(TOKEN.as_bytes()), check.as_bytes());
    let mut hash = String::new();
    for byte in signature.as_bytes() {
        use core::fmt::Write as _;
        write!(hash, "{byte:02x}").unwrap();
    }
    format!(
        r#"{{"telegram":{{"auth_date":"{moment}","id":"{subject}","username":"ivan","hash":"{hash}"}}}}"#
    )
}

/// Момент, которым датированы данные виджета: сервер сверяет его со своим
/// временем, поэтому берётся текущее.
fn moment() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[tokio::test]
async fn unlinked_identity_opens_no_session() {
    let server = Instance::with_telegram(TOKEN).await;
    let response = server
        .call(
            "POST",
            "/api/sessions",
            "",
            Some(&widget("168123456", moment())),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(
        status, 404,
        "внешний вход непривязанной личности открыл сессию"
    );
}

#[tokio::test]
async fn linked_identity_opens_a_session() {
    let server = Instance::with_telegram(TOKEN).await;
    let token = server.signed_in(&unique_login("telegram-linked")).await;
    server
        .call(
            "POST",
            "/api/users/me/external-identities",
            &token,
            Some(&widget("168000001", moment())),
        )
        .await;
    let response = server
        .call(
            "POST",
            "/api/sessions",
            "",
            Some(&widget("168000001", moment() - 1)),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 201, "привязанная личность не открыла сессию");
}

#[tokio::test]
async fn external_session_leaves_keys_sealed() {
    let server = Instance::with_telegram(TOKEN).await;
    let token = server.signed_in(&unique_login("telegram-sealed")).await;
    server
        .call(
            "POST",
            "/api/users/me/external-identities",
            &token,
            Some(&widget("168000002", moment())),
        )
        .await;
    let entry = server
        .call(
            "POST",
            "/api/sessions",
            "",
            Some(&widget("168000002", moment() - 1)),
        )
        .await;
    let external = format!("Authorization: Bearer {}\r\n", entry.field("token"));
    let current = server
        .call("GET", "/api/sessions/current", &external, None)
        .await;
    let keys = current.field("keys");
    server.stop().await;
    assert_eq!(
        keys, "sealed",
        "сессия внешнего входа объявила ключи развёрнутыми"
    );
}

#[tokio::test]
async fn password_session_unwraps_keys() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("password-unwrapped")).await;
    let current = server
        .call("GET", "/api/sessions/current", &token, None)
        .await;
    let keys = current.field("keys");
    server.stop().await;
    assert_eq!(
        keys, "unwrapped",
        "вход по паролю оставил ключи не развёрнутыми"
    );
}

#[tokio::test]
async fn external_session_carries_no_wrapped_keys() {
    let server = Instance::with_telegram(TOKEN).await;
    let token = server.signed_in(&unique_login("telegram-nokeys")).await;
    server
        .call(
            "POST",
            "/api/users/me/external-identities",
            &token,
            Some(&widget("168000003", moment())),
        )
        .await;
    let entry = server
        .call(
            "POST",
            "/api/sessions",
            "",
            Some(&widget("168000003", moment() - 1)),
        )
        .await;
    let body = entry.body().to_owned();
    server.stop().await;
    assert!(
        !body.contains("account_by_password"),
        "внешний вход отдал обёртки ключей, которых он не разворачивает"
    );
}

#[tokio::test]
async fn replayed_widget_is_refused() {
    let server = Instance::with_telegram(TOKEN).await;
    let token = server.signed_in(&unique_login("telegram-replay")).await;
    let data = widget("168000004", moment());
    server
        .call(
            "POST",
            "/api/users/me/external-identities",
            &token,
            Some(&data),
        )
        .await;
    let response = server.call("POST", "/api/sessions", "", Some(&data)).await;
    let status = response.status();
    server.stop().await;
    assert_eq!(
        status, 401,
        "повторно предъявленные данные виджета открыли сессию"
    );
}

#[tokio::test]
async fn forged_widget_is_refused() {
    let server = Instance::with_telegram(TOKEN).await;
    let forged = format!(
        r#"{{"telegram":{{"auth_date":"{}","id":"168000005","username":"ivan","hash":"{}"}}}}"#,
        moment(),
        "0".repeat(64)
    );
    let response = server
        .call("POST", "/api/sessions", "", Some(&forged))
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 401, "данные виджета с подделанной подписью приняты");
}

#[tokio::test]
async fn attaching_requires_a_session() {
    let server = Instance::with_telegram(TOKEN).await;
    let response = server
        .call(
            "POST",
            "/api/users/me/external-identities",
            "",
            Some(&widget("168000006", moment())),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(
        status, 401,
        "личность привязана без аутентифицированной сессии"
    );
}

#[tokio::test]
async fn attached_identity_is_listed() {
    let server = Instance::with_telegram(TOKEN).await;
    let token = server.signed_in(&unique_login("telegram-listed")).await;
    server
        .call(
            "POST",
            "/api/users/me/external-identities",
            &token,
            Some(&widget("168000007", moment())),
        )
        .await;
    let listed = server
        .call("GET", "/api/users/me/external-identities", &token, None)
        .await;
    let body = listed.body().to_owned();
    server.stop().await;
    assert!(
        body.contains("168000007"),
        "привязанная личность не попала в перечень учётной записи"
    );
}

#[tokio::test]
async fn identity_of_another_account_is_refused() {
    let server = Instance::with_telegram(TOKEN).await;
    let first = server.signed_in(&unique_login("telegram-owner")).await;
    let second = server.signed_in(&unique_login("telegram-stranger")).await;
    server
        .call(
            "POST",
            "/api/users/me/external-identities",
            &first,
            Some(&widget("168000008", moment())),
        )
        .await;
    let response = server
        .call(
            "POST",
            "/api/users/me/external-identities",
            &second,
            Some(&widget("168000008", moment() - 1)),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(
        status, 409,
        "чужая личность привязана ко второй учётной записи"
    );
}

#[tokio::test]
async fn detached_identity_opens_no_session() {
    let server = Instance::with_telegram(TOKEN).await;
    let token = server.signed_in(&unique_login("telegram-detached")).await;
    server
        .call(
            "POST",
            "/api/users/me/external-identities",
            &token,
            Some(&widget("168000009", moment())),
        )
        .await;
    server
        .call(
            "DELETE",
            "/api/users/me/external-identities/telegram:168000009",
            &token,
            None,
        )
        .await;
    let response = server
        .call(
            "POST",
            "/api/sessions",
            "",
            Some(&widget("168000009", moment() - 1)),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 404, "отвязанная личность всё ещё открывает сессию");
}

#[tokio::test]
async fn unknown_provider_is_refused() {
    let server = Instance::with_telegram(TOKEN).await;
    let response = server
        .call(
            "POST",
            "/api/sessions/authorizations",
            "",
            Some(r#"{"provider":"facebook"}"#),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 422, "неизвестный провайдер принят за известного");
}

#[tokio::test]
async fn unconfigured_provider_is_refused() {
    let server = Instance::with_telegram(TOKEN).await;
    let response = server
        .call(
            "POST",
            "/api/sessions/authorizations",
            "",
            Some(r#"{"provider":"vk"}"#),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(
        status, 404,
        "процедура начата у провайдера, который не настроен"
    );
}

#[tokio::test]
async fn foreign_state_is_refused() {
    let server = Instance::with_telegram(TOKEN).await;
    let response = server
        .call(
            "GET",
            "/auth/vk/callback?code=%D0%BA%D0%BE%D0%B4&state=%D1%87%D1%83%D0%B6%D0%BE%D0%B9",
            "",
            None,
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 404, "ответ провайдера с чужим state принят");
}

#[tokio::test]
async fn unfinished_authorization_opens_no_session() {
    let server = Instance::with_telegram(TOKEN).await;
    let response = server
        .call(
            "POST",
            "/api/sessions",
            "",
            Some(r#"{"authorization":"невыданный-билет"}"#),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(
        status, 404,
        "незавершённая процедура авторизации открыла сессию"
    );
}
