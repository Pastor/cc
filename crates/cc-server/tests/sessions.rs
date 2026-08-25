//! Сценарии ресурса сессий через HTTP.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use cc_server::{serve, Config, Server};
use std::io::Write as _;
use tempfile::TempDir;

fn config(root: &TempDir) -> Config {
    let path = root.path().join("cc.toml");
    let storage = root.path().join("data");
    let mut file = std::fs::File::create(&path).unwrap();
    write!(
        file,
        r#"
listen = "127.0.0.1:0"
storage = "{}"
[secrets]
server = "s3cret-value-for-tests"
[limits]
body_bytes = 1048576
request_seconds = 5
session_hours = 1
authorization_minutes = 5
trash_days = 30
metadata_bytes = 65536
"#,
        storage.display()
    )
    .unwrap();
    Config::load(Some(path.to_str().unwrap())).unwrap()
}

/// Выполняет запрос произвольным методом.
async fn call(
    server: &Server,
    method: &str,
    path: &str,
    headers: &str,
    body: Option<&str>,
) -> (u16, String) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(server.address())
        .await
        .unwrap();
    let request = body.map_or_else(
        || format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{headers}Connection: close\r\n\r\n"),
        |body| format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n{body}",
            body.len()
        ),
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, response)
}

/// Заявка на регистрацию с заданным аутентификационным хешем.
fn enrollment(login: &str, auth: [u8; 32]) -> String {
    let auth = STANDARD.encode(auth);
    let key = STANDARD.encode([7_u8; 32]);
    let wrapped = STANDARD.encode([1_u8; 72]);
    format!(
        r#"{{"login":"{login}","auth":"{auth}","salt":"{}","kdf":{{"memory_kib":8,"iterations":1,"parallelism":1}},"public_key":"{key}","wrapped":{{"account_by_password":"{wrapped}","account_by_recovery":"{wrapped}","private_by_account":"{wrapped}"}},"recovery_fingerprint":"{key}"}}"#,
        STANDARD.encode([9_u8; 16])
    )
}

/// Заявка на вход.
fn credentials(login: &str, auth: [u8; 32]) -> String {
    format!(
        r#"{{"login":"{login}","auth":"{}"}}"#,
        STANDARD.encode(auth)
    )
}

/// Извлекает тело ответа.
fn body(response: &str) -> &str {
    response.split("\r\n\r\n").nth(1).unwrap_or_default()
}

/// Достаёт токен из ответа на вход.
fn token(response: &str) -> String {
    let body = body(response);
    let start = body
        .find("\"token\":\"")
        .map(|at| at + 9)
        .unwrap_or_default();
    let rest = &body[start..];
    rest.find('"')
        .map(|end| rest[..end].to_owned())
        .unwrap_or_default()
}

/// Регистрирует пользователя и входит, возвращая заголовок с токеном.
async fn signed_in(server: &Server) -> String {
    let auth = [7_u8; 32];
    let _ = call(
        server,
        "POST",
        "/api/users",
        "",
        Some(&enrollment("user@example.com", auth)),
    )
    .await;
    let (_, response) = call(
        server,
        "POST",
        "/api/sessions",
        "",
        Some(&credentials("user@example.com", auth)),
    )
    .await;
    format!("Authorization: Bearer {}\r\n", token(&response))
}

#[tokio::test]
async fn correct_credentials_open_a_session() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let auth = [7_u8; 32];
    let _ = call(
        &server,
        "POST",
        "/api/users",
        "",
        Some(&enrollment("user@example.com", auth)),
    )
    .await;
    let (status, _) = call(
        &server,
        "POST",
        "/api/sessions",
        "",
        Some(&credentials("user@example.com", auth)),
    )
    .await;
    server.stop().await.unwrap();
    assert_eq!(status, 201, "верные учётные данные не открыли сессию");
}

#[tokio::test]
async fn wrong_hash_does_not_open_a_session() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let _ = call(
        &server,
        "POST",
        "/api/users",
        "",
        Some(&enrollment("user@example.com", [7; 32])),
    )
    .await;
    let (status, _) = call(
        &server,
        "POST",
        "/api/sessions",
        "",
        Some(&credentials("user@example.com", [8; 32])),
    )
    .await;
    server.stop().await.unwrap();
    assert_eq!(status, 404, "неверный аутентификационный хеш открыл сессию");
}

#[tokio::test]
async fn unknown_login_fails_like_wrong_hash() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let _ = call(
        &server,
        "POST",
        "/api/users",
        "",
        Some(&enrollment("user@example.com", [7; 32])),
    )
    .await;
    let (unknown, _) = call(
        &server,
        "POST",
        "/api/sessions",
        "",
        Some(&credentials("nobody@example.com", [7; 32])),
    )
    .await;
    let (wrong, _) = call(
        &server,
        "POST",
        "/api/sessions",
        "",
        Some(&credentials("user@example.com", [8; 32])),
    )
    .await;
    server.stop().await.unwrap();
    assert_eq!(
        unknown, wrong,
        "отказы различимы: ответ работает оракулом существования учётных записей"
    );
}

#[tokio::test]
async fn opened_session_reports_location() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let auth = [7_u8; 32];
    let _ = call(
        &server,
        "POST",
        "/api/users",
        "",
        Some(&enrollment("user@example.com", auth)),
    )
    .await;
    let (_, response) = call(
        &server,
        "POST",
        "/api/sessions",
        "",
        Some(&credentials("user@example.com", auth)),
    )
    .await;
    server.stop().await.unwrap();
    assert!(
        response.to_lowercase().contains("location: /api/sessions/"),
        "созданная сессия не сообщила своего расположения"
    );
}

#[tokio::test]
async fn entry_returns_wrapped_keys() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let auth = [7_u8; 32];
    let _ = call(
        &server,
        "POST",
        "/api/users",
        "",
        Some(&enrollment("user@example.com", auth)),
    )
    .await;
    let (_, response) = call(
        &server,
        "POST",
        "/api/sessions",
        "",
        Some(&credentials("user@example.com", auth)),
    )
    .await;
    server.stop().await.unwrap();
    assert!(
        body(&response).contains("private_by_account"),
        "вошедшему не отданы обёртки ключей: развернуть их без них он не сможет"
    );
}

#[tokio::test]
async fn token_grants_access_to_current_session() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let header = signed_in(&server).await;
    let (status, _) = call(&server, "GET", "/api/sessions/current", &header, None).await;
    server.stop().await.unwrap();
    assert_eq!(
        status, 200,
        "выданный токен не открыл доступ к своей сессии"
    );
}

#[tokio::test]
async fn current_session_hides_no_keys() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let header = signed_in(&server).await;
    let (_, response) = call(&server, "GET", "/api/sessions/current", &header, None).await;
    server.stop().await.unwrap();
    assert!(
        !body(&response).contains("token"),
        "сведения о сессии раскрывают её токен"
    );
}

#[tokio::test]
async fn closing_ends_the_session() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let header = signed_in(&server).await;
    let _ = call(&server, "DELETE", "/api/sessions/current", &header, None).await;
    let (status, _) = call(&server, "GET", "/api/sessions/current", &header, None).await;
    server.stop().await.unwrap();
    assert_eq!(status, 401, "закрытая сессия продолжает действовать");
}

#[tokio::test]
async fn closing_answers_without_content() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let header = signed_in(&server).await;
    let (status, _) = call(&server, "DELETE", "/api/sessions/current", &header, None).await;
    server.stop().await.unwrap();
    assert_eq!(status, 204, "выход ответил не отсутствием содержимого");
}

#[tokio::test]
async fn access_without_token_is_refused() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = call(&server, "GET", "/api/sessions/current", "", None).await;
    server.stop().await.unwrap();
    assert_eq!(status, 401, "сведения о сессии выданы без токена");
}

#[tokio::test]
async fn malformed_token_is_refused() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = call(
        &server,
        "GET",
        "/api/sessions/current",
        "Authorization: Bearer не-токен\r\n",
        None,
    )
    .await;
    server.stop().await.unwrap();
    assert_eq!(status, 401, "неразбираемый токен принят");
}

#[tokio::test]
async fn repeated_failures_are_throttled() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let _ = call(
        &server,
        "POST",
        "/api/users",
        "",
        Some(&enrollment("user@example.com", [7; 32])),
    )
    .await;
    let mut last = 0;
    for _ in 0..8 {
        let (status, _) = call(
            &server,
            "POST",
            "/api/sessions",
            "",
            Some(&credentials("user@example.com", [8; 32])),
        )
        .await;
        last = status;
    }
    server.stop().await.unwrap();
    assert_eq!(
        last, 429,
        "подбор аутентификационного хеша не ограничен по частоте"
    );
}

#[tokio::test]
async fn throttled_refusal_reports_retry_after() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let _ = call(
        &server,
        "POST",
        "/api/users",
        "",
        Some(&enrollment("user@example.com", [7; 32])),
    )
    .await;
    let mut response = String::new();
    for _ in 0..8 {
        let (_, body) = call(
            &server,
            "POST",
            "/api/sessions",
            "",
            Some(&credentials("user@example.com", [8; 32])),
        )
        .await;
        response = body;
    }
    server.stop().await.unwrap();
    assert!(
        response.to_lowercase().contains("retry-after"),
        "отказ по частоте не сообщил, когда повторять"
    );
}

#[tokio::test]
async fn successful_login_is_not_throttled() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let auth = [7_u8; 32];
    let _ = call(
        &server,
        "POST",
        "/api/users",
        "",
        Some(&enrollment("user@example.com", auth)),
    )
    .await;
    let mut last = 0;
    for _ in 0..8 {
        let (status, _) = call(
            &server,
            "POST",
            "/api/sessions",
            "",
            Some(&credentials("user@example.com", auth)),
        )
        .await;
        last = status;
    }
    server.stop().await.unwrap();
    assert_eq!(last, 201, "успешные входы подряд ограничены как подбор");
}
