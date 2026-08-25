//! Сборка маршрутов и слоёв.
//!
//! Маршруты и их описания регистрируются вместе: маршрут без описания в
//! спецификации и описание без маршрута невозможны по построению, а не
//! отлавливаются тестом задним числом.

use crate::identities;
use crate::observe::trace;
use crate::problem::stamp;
use crate::spec::Spec;
use crate::state::State;
use crate::version::negotiate;
use crate::{sessions, users};
use axum::routing::get;
use axum::{Json, Router};
use http::header::{HeaderName, HeaderValue};
use std::time::Duration;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use utoipa::OpenApi as _;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

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

/// Собирает версионируемую часть приложения вместе с её описанием.
fn versioned() -> (Router<State>, utoipa::openapi::OpenApi) {
    OpenApiRouter::with_openapi(Spec::openapi())
        .routes(routes!(users::enroll))
        .routes(routes!(users::me))
        .routes(routes!(users::public_key))
        .routes(routes!(users::prelude))
        .routes(routes!(sessions::open))
        .routes(routes!(identities::begin))
        .routes(routes!(identities::all, identities::attach))
        .routes(routes!(identities::detach))
        .routes(routes!(sessions::current, sessions::close))
        .routes(routes!(sessions::drop_one))
        .split_for_parts()
}

/// Строит спецификацию, не собирая приложение, — для проверок.
#[must_use]
pub fn describe() -> utoipa::openapi::OpenApi {
    versioned().1
}

/// Собирает приложение целиком.
///
/// Служебные маршруты — спецификация, документация, пробы и версия сборки — не
/// участвуют в версионировании контракта (`TODO.md`, раздел 10.1).
pub fn router(state: State, limits: Limits) -> Router {
    let (api, document) = versioned();
    // Документ публикует сам SwaggerUi по указанному ниже адресу: отдельный
    // маршрут для него привёл бы к двойной регистрации одного пути.
    let service = Router::new()
        // Обратный вызов провайдера вне версионируемого контракта: его
        // вызывает браузер, а не клиент (`TODO.md`, раздел 4.3).
        .route("/auth/{provider}/callback", get(identities::callback))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/api/version", get(version));
    service
        .merge(api.layer(axum::middleware::from_fn(negotiate)))
        .merge(utoipa_swagger_ui::SwaggerUi::new("/api/docs").url("/api/openapi.json", document))
        .with_state(state)
        .layer(PropagateRequestIdLayer::new(REQUEST_ID))
        .layer(axum::middleware::from_fn(stamp))
        .layer(axum::middleware::from_fn(trace))
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
async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION") }))
}
