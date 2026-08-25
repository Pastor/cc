//! Ответ об ошибке по RFC 9457.
//!
//! Единый формат для всего API: `application/problem+json`. Наружу не уходят ни
//! стек, ни пути файлов, ни запросы к хранилищу — только то, что вызывающему
//! нужно, чтобы понять отказ.
//!
//! Отображение ошибок на коды собрано в одном месте: обработчики маршрутов
//! кодов не выбирают. Прежняя реализация решала это в каждом контроллере
//! по-своему — один заворачивал всё подряд в `401`, другой не обрабатывал
//! ничего и отвечал `500` на некорректный ввод.

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
    #[serde(skip_serializing_if = "Option::is_none")]
    instance: Option<String>,
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
            instance: None,
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

    /// Отмечает конкретное обращение — идентификатор запроса.
    ///
    /// По нему инженер находит в журнале подробности, которые наружу не ушли.
    #[must_use]
    pub fn at(self, instance: impl Into<String>) -> Self {
        Self {
            instance: Some(instance.into()),
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

    /// Отказ, о котором вызывающему знать нечего.
    ///
    /// Подробности остаются в журнале: наружу не уходят ни стек, ни пути, ни
    /// запросы к хранилищу.
    #[must_use]
    pub const fn internal() -> Self {
        Self::new(
            "about:blank",
            "внутренний отказ",
            StatusCode::INTERNAL_SERVER_ERROR,
        )
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

/// Отказ обработки запроса.
///
/// Единственный тип, который обработчики возвращают наружу. Соответствие кодам
/// собрано в одной реализации ниже и покрыто тестом.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Failure {
    /// Нарушен инвариант предметной области.
    #[error(transparent)]
    Domain(#[from] cc_domain::Error),
    /// Отказ хранилища.
    #[error(transparent)]
    Storage(#[from] cc_storage::Error),
    /// Тело запроса не разбирается.
    #[error("тело запроса не разбирается")]
    Malformed,
    /// Требуется аутентификация.
    #[error("требуется аутентификация")]
    Unauthenticated,
    /// Изменение требует условия `If-Match`.
    #[error("изменение требует заголовка If-Match")]
    ConditionRequired,
    /// Условие `If-Match` не выполнено.
    #[error("условие If-Match не выполнено")]
    ConditionFailed,
    /// Операция не разрешена, хотя ресурс виден.
    #[error("операция не разрешена")]
    Forbidden,
    /// Значение длиннее допустимого предела.
    #[error("значение длиннее допустимого предела")]
    TooLarge,
    /// Запрошенный диапазон вне содержимого.
    #[error("запрошенный диапазон вне содержимого")]
    Unsatisfiable,
    /// Превышено ограничение частоты.
    #[error("превышено ограничение частоты")]
    TooManyRequests,
    /// Попытка слишком рано после серии неудач.
    #[error("следующая попытка возможна через {seconds} с")]
    TooSoon {
        /// Сколько секунд ждать.
        seconds: i64,
    },
}

impl Failure {
    /// Код ответа для отказа.
    ///
    /// Отсутствие ресурса и отсутствие доступа неразличимы: иначе ответ
    /// подтверждает существование чужого ресурса.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Domain(cc_domain::Error::AccessDenied)
            | Self::Storage(cc_storage::Error::Missing) => StatusCode::NOT_FOUND,
            Self::Domain(cc_domain::Error::RightsEscalation) | Self::Forbidden => {
                StatusCode::FORBIDDEN
            }
            Self::Domain(cc_domain::Error::QuotaOverrun) => StatusCode::INSUFFICIENT_STORAGE,
            Self::Domain(_) | Self::Storage(cc_storage::Error::ContentMismatch) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            Self::Storage(cc_storage::Error::LoginTaken | cc_storage::Error::IdentityTaken) => {
                StatusCode::CONFLICT
            }
            // Данные провайдера проверяются криптографически: сказать, что они
            // не приняты, оракулом чужих записей не работает.
            Self::Storage(
                cc_storage::Error::Signature
                | cc_storage::Error::Expired
                | cc_storage::Error::Replay,
            )
            | Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Storage(cc_storage::Error::Malformed) | Self::Malformed => {
                StatusCode::BAD_REQUEST
            }
            Self::Storage(cc_storage::Error::Stale) | Self::ConditionFailed => {
                StatusCode::PRECONDITION_FAILED
            }
            Self::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ConditionRequired => StatusCode::PRECONDITION_REQUIRED,
            Self::Unsatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::TooManyRequests | Self::TooSoon { .. } => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    /// Отвечает, скрывается ли причина отказа от вызывающего.
    ///
    /// Скрывается всё, что относится к внутреннему устройству: путь в
    /// хранилище, отказ файловой системы, ошибка примитива.
    #[must_use]
    pub const fn opaque(&self) -> bool {
        matches!(self.status(), StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        if self.opaque() {
            tracing::error!(error = %self, "запрос отклонён внутренним отказом");
            return Problem::internal().into_response();
        }
        let status = self.status();
        let retry = match self {
            Self::TooSoon { seconds } => Some(seconds),
            _ => None,
        };
        let mut response = Problem::new("about:blank", "запрос отклонён", status)
            .detailed(self.to_string())
            .into_response();
        if let Some(seconds) = retry {
            if let Ok(value) = http::HeaderValue::from_str(&seconds.to_string()) {
                response
                    .headers_mut()
                    .insert(http::header::RETRY_AFTER, value);
            }
        }
        response
    }
}

/// Дописывает в тело отказа идентификатор запроса.
///
/// Обработчик строит отказ, не зная идентификатора: тот присваивается слоем.
/// Поэтому отметка ставится здесь — в единственном месте, через которое
/// проходят все ответы.
pub async fn stamp(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let response = next.run(request).await;
    let Some(identifier) = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
    else {
        return response;
    };
    if response.headers().get(CONTENT_TYPE) != Some(&PROBLEM_JSON) {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 64 * 1024).await else {
        return Problem::internal().into_response();
    };
    let Ok(mut document) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (parts, bytes).into_response();
    };
    if let Some(object) = document.as_object_mut() {
        object.insert("instance".to_owned(), serde_json::Value::String(identifier));
    }
    let Ok(updated) = serde_json::to_vec(&document) else {
        return (parts, bytes).into_response();
    };
    parts.headers.remove(http::header::CONTENT_LENGTH);
    (parts, updated).into_response()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::Failure;
    use http::StatusCode;

    #[test]
    fn denied_access_looks_like_absence() {
        assert_eq!(
            Failure::Domain(cc_domain::Error::AccessDenied).status(),
            StatusCode::NOT_FOUND,
            "отказ в доступе отличим от отсутствия ресурса и потому раскрывает его"
        );
    }

    #[test]
    fn missing_record_is_absence() {
        assert_eq!(
            Failure::Storage(cc_storage::Error::Missing).status(),
            StatusCode::NOT_FOUND,
            "отсутствующая запись отдана не как отсутствие"
        );
    }

    #[test]
    fn taken_login_is_a_conflict() {
        assert_eq!(
            Failure::Storage(cc_storage::Error::LoginTaken).status(),
            StatusCode::CONFLICT,
            "занятый логин отдан не как конфликт"
        );
    }

    #[test]
    fn invalid_value_is_unprocessable() {
        assert_eq!(
            Failure::Domain(cc_domain::Error::ContentHash).status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "недопустимое значение отдано не как необрабатываемое"
        );
    }

    #[test]
    fn malformed_body_is_a_bad_request() {
        assert_eq!(
            Failure::Malformed.status(),
            StatusCode::BAD_REQUEST,
            "неразбираемое тело отдано не как неверный запрос"
        );
    }

    #[test]
    fn quota_overrun_reports_storage_exhaustion() {
        assert_eq!(
            Failure::Domain(cc_domain::Error::QuotaOverrun).status(),
            StatusCode::INSUFFICIENT_STORAGE,
            "исчерпание квоты отдано не как нехватка места"
        );
    }

    #[test]
    fn escalation_is_forbidden() {
        assert_eq!(
            Failure::Domain(cc_domain::Error::RightsEscalation).status(),
            StatusCode::FORBIDDEN,
            "попытка расширить права отдана не как запрет"
        );
    }

    #[test]
    fn incorrect_input_never_yields_internal_error() {
        let inputs = [
            Failure::Malformed,
            Failure::Domain(cc_domain::Error::ContentHash),
            Failure::Domain(cc_domain::Error::Username),
            Failure::Domain(cc_domain::Error::Identifier),
            Failure::Storage(cc_storage::Error::ContentMismatch),
        ];
        assert!(
            !inputs
                .iter()
                .any(|failure| failure.status() == StatusCode::INTERNAL_SERVER_ERROR),
            "некорректный ввод отдан как внутренний отказ"
        );
    }

    #[test]
    fn internal_failure_hides_its_cause() {
        assert!(
            Failure::Storage(cc_storage::Error::PathEscape).opaque(),
            "внутренний отказ раскрывает причину вызывающему"
        );
    }
}
