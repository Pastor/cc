//! Сценарии ресурса учётных записей через HTTP.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

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
"#,
        storage.display()
    )
    .unwrap();
    Config::load(Some(path.to_str().unwrap())).unwrap()
}

/// Выполняет запрос с телом и возвращает код ответа вместе с ответом целиком.
async fn post(server: &Server, path: &str, body: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(server.address())
        .await
        .unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
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

/// Выполняет запрос без тела.
async fn get(server: &Server, path: &str, headers: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(server.address())
        .await
        .unwrap();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{headers}Connection: close\r\n\r\n");
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

/// Заявка на регистрацию с указанным логином.
fn enrollment(login: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let key = STANDARD.encode([7_u8; 32]);
    let wrapped = STANDARD.encode([1_u8; 72]);
    format!(
        r#"{{"login":"{login}","auth":"{key}","salt":"{}","kdf":{{"memory_kib":8,"iterations":1,"parallelism":1}},"public_key":"{key}","wrapped":{{"account_by_password":"{wrapped}","account_by_recovery":"{wrapped}","private_by_account":"{wrapped}"}},"recovery_fingerprint":"{key}"}}"#,
        STANDARD.encode([9_u8; 16])
    )
}

#[tokio::test]
async fn registration_creates_the_account() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = post(&server, "/api/users", &enrollment("user@example.com")).await;
    server.stop().await.unwrap();
    assert_eq!(status, 201, "регистрация не создала учётную запись");
}

#[tokio::test]
async fn registration_reports_location() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, response) = post(&server, "/api/users", &enrollment("user@example.com")).await;
    server.stop().await.unwrap();
    assert!(
        response.to_lowercase().contains("location: /api/users/"),
        "созданный ресурс не сообщил своего расположения"
    );
}

#[tokio::test]
async fn registration_does_not_return_keys() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, response) = post(&server, "/api/users", &enrollment("user@example.com")).await;
    server.stop().await.unwrap();
    assert!(
        !response.contains("wrapped") && !response.contains("auth"),
        "представление учётной записи содержит ключи"
    );
}

#[tokio::test]
async fn taken_login_is_a_conflict() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let _ = post(&server, "/api/users", &enrollment("user@example.com")).await;
    let (status, _) = post(&server, "/api/users", &enrollment("user@example.com")).await;
    server.stop().await.unwrap();
    assert_eq!(status, 409, "занятый логин зарегистрирован повторно");
}

#[tokio::test]
async fn malformed_login_is_unprocessable() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = post(&server, "/api/users", &enrollment("не-адрес")).await;
    server.stop().await.unwrap();
    assert_eq!(status, 422, "недопустимый логин принят");
}

#[tokio::test]
async fn malformed_body_is_a_bad_request() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = post(&server, "/api/users", "{").await;
    server.stop().await.unwrap();
    assert!(
        status == 400 || status == 422,
        "неразбираемое тело дало код {status} вместо отказа по вводу"
    );
}

#[tokio::test]
async fn me_requires_authentication() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = get(&server, "/api/users/me", "").await;
    server.stop().await.unwrap();
    assert_eq!(status, 401, "сведения о себе выданы без аутентификации");
}

#[tokio::test]
async fn public_key_requires_authentication() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = get(&server, "/api/users/user@example.com/public-key", "").await;
    server.stop().await.unwrap();
    assert_eq!(
        status, 401,
        "открытый ключ выдан без аутентификации: маршрут перечисляет зарегистрированных"
    );
}

#[tokio::test]
async fn prelude_answers_for_unknown_login() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = get(&server, "/api/users/nobody@example.com/prelude", "").await;
    server.stop().await.unwrap();
    assert_eq!(
        status, 200,
        "по неизвестному логину параметры не выданы: отказ раскрывает регистрацию"
    );
}

#[tokio::test]
async fn prelude_is_stable_for_unknown_login() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, first) = get(&server, "/api/users/nobody@example.com/prelude", "").await;
    let (_, second) = get(&server, "/api/users/nobody@example.com/prelude", "").await;
    server.stop().await.unwrap();
    let body = |response: &str| {
        response
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(
        body(&first),
        body(&second),
        "правдоподобные параметры меняются между запросами и потому распознаются"
    );
}

#[tokio::test]
async fn registration_does_not_wait_for_the_letter() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let before = std::time::Instant::now();
    let (status, _) = post(&server, "/api/users", &enrollment("letter@example.com")).await;
    let elapsed = before.elapsed();
    server.stop().await.unwrap();
    assert!(
        status == 201 && elapsed < std::time::Duration::from_secs(2),
        "регистрация ждала отправки письма: код {status}, время {elapsed:?}"
    );
}

#[tokio::test]
async fn registration_response_hides_the_confirmation_code() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, response) = post(&server, "/api/users", &enrollment("secret@example.com")).await;
    server.stop().await.unwrap();
    assert!(
        !response.contains("\"code\"") && !response.contains("\"confirmation\""),
        "код подтверждения виден в ответе: письмо становится ненужным"
    );
}
