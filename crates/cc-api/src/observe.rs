//! Наблюдаемость запросов.
//!
//! Что попадает в журнал, решается здесь. Секреты не попадают туда никогда:
//! ни пароли, ни токены, ни ключи, ни содержимое файлов — по ним журнал стал бы
//! вторым хранилищем, которое никто не защищает.

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use tracing::field::Empty;

/// Имя заголовка идентификатора запроса.
const REQUEST_ID: &str = "x-request-id";

/// Заводит на запрос span с полями, по которым его потом ищут.
///
/// Шаблон пути берётся вместо самой строки запроса: в строке стоят логины и
/// идентификаторы, а в шаблоне — только `/api/users/{login}`. Так журнал
/// остаётся пригодным для группировки и не превращается в перечень
/// пользователей.
pub async fn trace(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request.extensions().get::<MatchedPath>().map_or_else(
        || String::from("unmatched"),
        |path| path.as_str().to_owned(),
    );
    let identifier = request
        .headers()
        .get(REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let span = tracing::info_span!(
        "request",
        %method,
        route = %route,
        request_id = %identifier,
        api_version = Empty,
        status = Empty,
    );
    let response = tracing::Instrument::instrument(next.run(request), span.clone()).await;
    span.record("status", response.status().as_u16());
    if response.status().is_server_error() {
        tracing::error!(parent: &span, "запрос завершился внутренним отказом");
    } else if response.status().is_client_error() {
        tracing::debug!(parent: &span, "запрос отклонён");
    } else {
        tracing::info!(parent: &span, "запрос обслужен");
    }
    response
}
