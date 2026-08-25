//! Сборка маршрутов и слоёв.

use crate::problem::stamp;
use crate::state::State;
use crate::version::negotiate;
use axum::routing::get;
use axum::Router;
use http::header::{HeaderName, HeaderValue};
use std::time::Duration;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// Пределы, применяемые к запросам.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    body: usize,
    request: Duration,
}

impl Limits {
    /// Собирает пределы.
    #[must_use]
    pub const fn new(body: usize, request: Duration) -> Self {
        Self { body, request }
    }
}

/// Имя заголовка идентификатора запроса.
const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Собирает приложение целиком.
///
/// Служебные маршруты — пробы и версия сборки — не участвуют в версионировании
/// контракта (`TODO.md`, раздел 10.1).
pub fn router(state: State, limits: Limits) -> Router {
    let versioned = Router::new()
        .route("/api/files", get(files))
        .layer(axum::middleware::from_fn(negotiate));
    let service = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/api/version", get(version));
    service
        .merge(versioned)
        .with_state(state)
        .layer(PropagateRequestIdLayer::new(REQUEST_ID))
        .layer(axum::middleware::from_fn(stamp))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            http::StatusCode::SERVICE_UNAVAILABLE,
            limits.request,
        ))
        .layer(RequestBodyLimitLayer::new(limits.body))
        .layer(SetResponseHeaderLayer::overriding(
            http::header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            http::header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetRequestIdLayer::new(REQUEST_ID, MakeRequestUuid))
}

/// Коллекция файлов.
///
/// Заглушка: наполняется в TASK-013. Здесь она нужна, чтобы слой согласования
/// версии имел, что защищать.
async fn files() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "items": [], "next": serde_json::Value::Null }))
}

/// Проба живости: процесс отвечает.
async fn live() -> &'static str {
    "ok"
}

/// Проба готовности: процесс готов принимать запросы.
async fn ready() -> &'static str {
    "ok"
}

/// Версия сборки сервиса.
///
/// Это диагностика, а не версия контракта: подменять одно другим нельзя.
async fn version() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION") }))
}
