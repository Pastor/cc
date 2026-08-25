//! Сценарии из `TODO.md`, раздел 4, целиком через HTTP.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

mod support;

use support::{credentials, enrollment, unique_login, Instance};

#[tokio::test]
async fn registration_then_login_opens_a_session() {
    let server = Instance::start().await;
    let login = unique_login("flow");
    let auth = [7_u8; 32];
    server
        .call("POST", "/api/users", "", Some(&enrollment(&login, auth)))
        .await;
    let response = server
        .call(
            "POST",
            "/api/sessions",
            "",
            Some(&credentials(&login, auth)),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(
        status, 201,
        "полный путь от регистрации до входа не пройден"
    );
}

#[tokio::test]
async fn session_grants_access_to_own_account() {
    let server = Instance::start().await;
    let header = server.signed_in(&unique_login("own")).await;
    let response = server.call("GET", "/api/users/me", &header, None).await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 200, "вошедший не получил сведений о себе");
}

#[tokio::test]
async fn logout_ends_access() {
    let server = Instance::start().await;
    let header = server.signed_in(&unique_login("logout")).await;
    server
        .call("DELETE", "/api/sessions/current", &header, None)
        .await;
    let response = server.call("GET", "/api/users/me", &header, None).await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 401, "выход не прекратил доступ");
}

#[tokio::test]
async fn account_of_one_user_is_invisible_to_another() {
    let server = Instance::start().await;
    let stranger = server.signed_in(&unique_login("stranger")).await;
    let response = server
        .call(
            "GET",
            "/api/users/nobody-at-all@example.com/public-key",
            &stranger,
            None,
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(
        status, 404,
        "запрос ключа несуществующего пользователя ответил не отсутствием"
    );
}

#[tokio::test]
async fn recipient_public_key_is_available_for_granting() {
    let server = Instance::start().await;
    let owner = server.signed_in(&unique_login("owner")).await;
    let recipient = unique_login("recipient");
    server
        .call(
            "POST",
            "/api/users",
            "",
            Some(&enrollment(&recipient, [7; 32])),
        )
        .await;
    let response = server
        .call(
            "GET",
            &format!("/api/users/{recipient}/public-key"),
            &owner,
            None,
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(
        status, 200,
        "открытый ключ получателя недоступен: выдать ему доступ нечем"
    );
}

#[tokio::test]
async fn each_test_gets_its_own_storage() {
    let first = Instance::start().await;
    let login = unique_login("isolation");
    first
        .call("POST", "/api/users", "", Some(&enrollment(&login, [7; 32])))
        .await;
    first.stop().await;
    let second = Instance::start().await;
    let response = second
        .call("POST", "/api/users", "", Some(&enrollment(&login, [7; 32])))
        .await;
    let status = response.status();
    second.stop().await;
    assert_eq!(
        status, 201,
        "состояние пережило остановку сервера: тесты связаны через хранилище"
    );
}
