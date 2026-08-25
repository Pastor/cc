//! Обвязка интеграционных тестов.
//!
//! Здесь нет разделяемого состояния: каждый вызов поднимает свой сервер на
//! эфемерном порту и гасит его после себя. Прежние тесты держали один сервер на
//! всех, отчего проверка перечня файлов ломалась от любого соседнего теста.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_const_for_fn,
    reason = "обвязка тестов: часть помощников используется не каждым файлом, \
              а отказ обязан ронять тест"
)]

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use cc_server::{serve, Config, Server};
use std::io::Write as _;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Предел ожидания ответа.
///
/// `RULE.md` требует ограничивать каждое ожидание: без предела зависший сервер
/// останавливает весь прогон, а не один тест.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Поднятый сервер вместе с его временным хранилищем.
pub struct Instance {
    server: Server,
    _root: TempDir,
}

impl Instance {
    /// Поднимает сервер на эфемерном порту.
    pub async fn start() -> Self {
        let root = TempDir::new().unwrap();
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
        let config = Config::load(Some(path.to_str().unwrap())).unwrap();
        Self {
            server: serve(&config).await.unwrap(),
            _root: root,
        }
    }

    /// Останавливает сервер.
    pub async fn stop(self) {
        self.server.stop().await.unwrap();
    }

    /// Выполняет запрос и возвращает ответ.
    ///
    /// # Panics
    ///
    /// Паникует, если ответ не пришёл за отведённое время: зависший сервер
    /// обязан ронять свой тест, а не весь прогон.
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        headers: &str,
        body: Option<&str>,
    ) -> Response {
        let request = body.map_or_else(
            || format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{headers}Connection: close\r\n\r\n"),
            |body| {
                format!(
                    "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n{body}",
                    body.len()
                )
            },
        );
        let address = self.server.address();
        let exchange = async move {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut raw = String::new();
            stream.read_to_string(&mut raw).await.unwrap();
            raw
        };
        let raw = tokio::time::timeout(TIMEOUT, exchange)
            .await
            .expect("сервер не ответил за отведённое время");
        Response::new(raw)
    }

    /// Регистрирует пользователя и входит, возвращая заголовок с токеном.
    pub async fn signed_in(&self, login: &str) -> String {
        let auth = [7_u8; 32];
        self.call("POST", "/api/users", "", Some(&enrollment(login, auth)))
            .await;
        let response = self
            .call("POST", "/api/sessions", "", Some(&credentials(login, auth)))
            .await;
        format!("Authorization: Bearer {}\r\n", response.field("token"))
    }
}

/// Ответ сервера.
pub struct Response {
    raw: String,
}

impl Response {
    /// Разбирает ответ.
    fn new(raw: String) -> Self {
        Self { raw }
    }

    /// Код ответа.
    pub fn status(&self) -> u16 {
        self.raw
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    }

    /// Тело ответа.
    pub fn body(&self) -> &str {
        self.raw.split("\r\n\r\n").nth(1).unwrap_or_default()
    }

    /// Ответ целиком, включая заголовки.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Отвечает, несёт ли ответ указанный заголовок.
    pub fn has_header(&self, name: &str) -> bool {
        self.raw.to_lowercase().contains(&name.to_lowercase())
    }

    /// Достаёт строковое поле верхнего уровня из тела.
    pub fn field(&self, name: &str) -> String {
        let body = self.body();
        let needle = format!("\"{name}\":\"");
        let Some(start) = body.find(&needle).map(|at| at + needle.len()) else {
            return String::new();
        };
        let rest = &body[start..];
        rest.find('"')
            .map_or_else(String::new, |end| rest[..end].to_owned())
    }
}

/// Уникальный логин для теста.
///
/// Тесты не делят состояние, но делят время: одинаковый логин в двух тестах
/// связал бы их через ограничение частоты.
pub fn unique_login(hint: &str) -> String {
    format!("{hint}-{}@example.com", uuid())
}

/// Строит заявку на регистрацию.
pub fn enrollment(login: &str, auth: [u8; 32]) -> String {
    let auth = STANDARD.encode(auth);
    let key = STANDARD.encode([7_u8; 32]);
    let wrapped = STANDARD.encode([1_u8; 72]);
    format!(
        r#"{{"login":"{login}","auth":"{auth}","salt":"{}","kdf":{{"memory_kib":8,"iterations":1,"parallelism":1}},"public_key":"{key}","wrapped":{{"account_by_password":"{wrapped}","account_by_recovery":"{wrapped}","private_by_account":"{wrapped}"}},"recovery_fingerprint":"{key}"}}"#,
        STANDARD.encode([9_u8; 16])
    )
}

/// Строит заявку на вход.
pub fn credentials(login: &str, auth: [u8; 32]) -> String {
    format!(
        r#"{{"login":"{login}","auth":"{}"}}"#,
        STANDARD.encode(auth)
    )
}

/// Порождает уникальную часть имени.
fn uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or_default();
    format!("{nanos:x}")
}
