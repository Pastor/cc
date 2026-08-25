//! Ответ об ошибке по RFC 9457.
//!
//! Единый формат для всего API: `application/problem+json`. Наружу не уходят ни
//! стек, ни пути файлов, ни запросы к хранилищу — только то, что вызывающему
//! нужно, чтобы понять отказ.

use axum::response::{IntoResponse, Response};
use http::header::CONTENT_TYPE;
use http::{HeaderValue, StatusCode};
use serde::Serialize;

/// Тип содержимого ответа об ошибке.
const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");

/// Описание отказа по RFC 9457.
#[derive(Clone, Debug, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    kind: &'static str,
    title: &'static str,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    supported: Vec<u16>,
}

impl Problem {
    /// Собирает описание отказа.
    #[must_use]
    pub const fn new(kind: &'static str, title: &'static str, status: StatusCode) -> Self {
        Self {
            kind,
            title,
            status: status.as_u16(),
            detail: None,
            supported: Vec::new(),
        }
    }

    /// Добавляет подробность, обращённую к вызывающему.
    #[must_use]
    pub fn detailed(self, detail: impl Into<String>) -> Self {
        Self {
            detail: Some(detail.into()),
            ..self
        }
    }

    /// Перечисляет поддерживаемые версии — для отказа по версии контракта.
    #[must_use]
    pub fn supporting(self, supported: Vec<u16>) -> Self {
        Self { supported, ..self }
    }

    /// Код ответа.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = serde_json::to_string(&self)
            .unwrap_or_else(|_| String::from(r#"{"title":"внутренний отказ","status":500}"#));
        let mut response = (status, body).into_response();
        response.headers_mut().insert(CONTENT_TYPE, PROBLEM_JSON);
        response
    }
}
