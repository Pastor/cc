//! Жизненный цикл сервера: подъём, ответы и остановка.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_server::{serve, Config};
use std::io::Write as _;
use tempfile::TempDir;

/// Готовит конфигурацию с эфемерным портом и временным хранилищем.
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

/// Выполняет запрос и возвращает код ответа вместе с телом.
async fn request(address: std::net::SocketAddr, path: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
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

#[tokio::test]
async fn server_listens_on_ephemeral_port() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let port = server.address().port();
    server.stop().await.unwrap();
    assert!(port != 0, "сервер не сообщил выданный системой порт");
}

#[tokio::test]
async fn liveness_probe_answers() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = request(server.address(), "/health/live").await;
    server.stop().await.unwrap();
    assert_eq!(status, 200, "проба живости не ответила успехом");
}

#[tokio::test]
async fn version_is_reported() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, body) = request(server.address(), "/api/version").await;
    server.stop().await.unwrap();
    assert!(body.contains("version"), "версия сборки не сообщена");
}

#[tokio::test]
async fn security_headers_are_set() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, body) = request(server.address(), "/health/live").await;
    server.stop().await.unwrap();
    assert!(
        body.to_lowercase().contains("content-security-policy"),
        "ответ не несёт политики безопасности содержимого"
    );
}

#[tokio::test]
async fn request_identifier_is_returned() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, body) = request(server.address(), "/health/live").await;
    server.stop().await.unwrap();
    assert!(
        body.to_lowercase().contains("x-request-id"),
        "ответ не несёт идентификатора запроса"
    );
}

#[tokio::test]
async fn unknown_route_is_not_found() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = request(server.address(), "/nowhere").await;
    server.stop().await.unwrap();
    assert_eq!(status, 404, "неизвестный маршрут ответил не отсутствием");
}

#[tokio::test]
async fn server_stops_cleanly() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    assert!(
        server.stop().await.is_ok(),
        "остановка сервера завершилась отказом"
    );
}

#[tokio::test]
async fn storage_root_is_created() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    server.stop().await.unwrap();
    assert!(
        root.path().join("data").exists(),
        "корень хранилища не создан при запуске"
    );
}

/// Выполняет запрос с заголовками и возвращает код ответа вместе с телом.
async fn request_with(address: std::net::SocketAddr, path: &str, headers: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
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

#[tokio::test]
async fn request_without_version_is_served() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = request(server.address(), "/api/users/nobody@example.com/prelude").await;
    server.stop().await.unwrap();
    assert_eq!(
        status, 200,
        "запрос без заголовка версии отвергнут вместо обслуживания самой новой версией"
    );
}

#[tokio::test]
async fn request_without_version_gets_the_newest() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, body) = request(server.address(), "/api/users/nobody@example.com/prelude").await;
    server.stop().await.unwrap();
    let newest = cc_api::Version::SUPPORTED
        .iter()
        .map(|version| version.number())
        .max()
        .unwrap();
    assert!(
        body.to_lowercase()
            .contains(&format!("api-version: {newest}")),
        "запрос без заголовка обслужен не самой новой версией"
    );
}

#[tokio::test]
async fn supported_version_is_served() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = request_with(
        server.address(),
        "/api/users/nobody@example.com/prelude",
        "API-Version: 1\r\n",
    )
    .await;
    server.stop().await.unwrap();
    assert_eq!(status, 200, "поддерживаемая версия отвергнута");
}

#[tokio::test]
async fn unknown_version_is_refused() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = request_with(
        server.address(),
        "/api/users/nobody@example.com/prelude",
        "API-Version: 99\r\n",
    )
    .await;
    server.stop().await.unwrap();
    assert_eq!(status, 400, "неизвестная версия обслужена вместо отказа");
}

#[tokio::test]
async fn refusal_lists_supported_versions() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, body) = request_with(
        server.address(),
        "/api/users/nobody@example.com/prelude",
        "API-Version: 99\r\n",
    )
    .await;
    server.stop().await.unwrap();
    assert!(
        body.contains("supported"),
        "отказ по версии не перечислил поддерживаемые версии"
    );
}

#[tokio::test]
async fn refusal_uses_problem_json() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, body) = request_with(
        server.address(),
        "/api/users/nobody@example.com/prelude",
        "API-Version: 99\r\n",
    )
    .await;
    server.stop().await.unwrap();
    assert!(
        body.to_lowercase().contains("application/problem+json"),
        "отказ отдан не в формате problem+json"
    );
}

#[tokio::test]
async fn versioned_response_varies_by_version() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, body) = request(server.address(), "/api/users/nobody@example.com/prelude").await;
    server.stop().await.unwrap();
    assert!(
        body.to_lowercase().contains("vary: api-version"),
        "версионируемый ответ не запретил кэширование без учёта версии"
    );
}

#[tokio::test]
async fn versioned_response_echoes_applied_version() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, body) = request(server.address(), "/api/users/nobody@example.com/prelude").await;
    server.stop().await.unwrap();
    assert!(
        body.to_lowercase().contains("api-version: 1"),
        "ответ не сообщил применённую версию контракта"
    );
}

#[tokio::test]
async fn service_route_ignores_version_header() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = request_with(server.address(), "/health/live", "API-Version: 99\r\n").await;
    server.stop().await.unwrap();
    assert_eq!(
        status, 200,
        "служебный маршрут отверг запрос из-за версии контракта"
    );
}

#[tokio::test]
async fn refusal_carries_request_identifier() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, body) = request_with(
        server.address(),
        "/api/users/nobody@example.com/prelude",
        "API-Version: 99\r\n",
    )
    .await;
    server.stop().await.unwrap();
    assert!(
        body.contains("instance"),
        "отказ не сослался на идентификатор обращения: инженер не найдёт его в журнале"
    );
}

#[tokio::test]
async fn successful_response_is_not_rewritten() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, body) = request(server.address(), "/api/users/nobody@example.com/prelude").await;
    server.stop().await.unwrap();
    assert!(
        body.contains("\"salt\""),
        "успешный ответ изменён слоем отметки отказов"
    );
}

#[tokio::test]
async fn specification_is_published() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = request(server.address(), "/api/openapi.json").await;
    server.stop().await.unwrap();
    assert_eq!(status, 200, "спецификация не опубликована");
}

#[tokio::test]
async fn specification_describes_the_service() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (_, body) = request(server.address(), "/api/openapi.json").await;
    server.stop().await.unwrap();
    assert!(
        body.contains("/api/sessions"),
        "опубликованная спецификация не описывает маршрутов сервиса"
    );
}

#[tokio::test]
async fn documentation_is_served() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) = request(server.address(), "/api/docs/").await;
    server.stop().await.unwrap();
    assert_eq!(status, 200, "интерактивная документация не отдана");
}

#[tokio::test]
async fn specification_ignores_the_version_header() {
    let root = TempDir::new().unwrap();
    let server = serve(&config(&root)).await.unwrap();
    let (status, _) =
        request_with(server.address(), "/api/openapi.json", "API-Version: 99\r\n").await;
    server.stop().await.unwrap();
    assert_eq!(
        status, 200,
        "спецификация отвергнута из-за версии контракта, хотя вне её"
    );
}
