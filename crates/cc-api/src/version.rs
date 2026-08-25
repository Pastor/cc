//! Версия контракта, передаваемая заголовком.
//!
//! Решение и правила — `TODO.md`, раздел 10.1. Версия относится к представлению,
//! а не к ресурсу, поэтому в пути её нет.

use crate::problem::Problem;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::header::{HeaderName, VARY};
use http::{HeaderValue, StatusCode};

/// Имя заголовка версии.
///
/// Без префикса `X-`: RFC 6648 объявляет его устаревшим.
pub const API_VERSION: HeaderName = HeaderName::from_static("api-version");

/// Отказ разобрать версию контракта.
#[derive(Debug, thiserror::Error)]
#[error("версия контракта не поддерживается")]
pub struct Unsupported;

/// Версия контракта.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u16);

impl Version {
    /// Поддерживаемые версии, от самой старой к самой новой.
    pub const SUPPORTED: [Self; 1] = [Self(1)];

    /// Версия, применяемая при отсутствии заголовка.
    ///
    /// Самая новая поддерживаемая. Следствие принято осознанно: клиент, не
    /// присылающий заголовок, переключается на новый контракт в день его
    /// выпуска. Закрепление версии — забота клиента: он обязан прислать
    /// заголовок, если хочет стабильности.
    #[must_use]
    pub const fn fallback() -> Self {
        Self::SUPPORTED[Self::SUPPORTED.len() - 1]
    }

    /// Разбирает значение заголовка.
    ///
    /// # Errors
    ///
    /// [`Unsupported`], если значение не является поддерживаемой версией:
    /// подробности для ответа собирает вызывающий.
    pub fn parse(value: &str) -> Result<Self, Unsupported> {
        let number: u16 = value.trim().parse().map_err(|_| Unsupported)?;
        let candidate = Self(number);
        if Self::SUPPORTED.contains(&candidate) {
            return Ok(candidate);
        }
        Err(Unsupported)
    }

    /// Номер версии.
    #[must_use]
    pub const fn number(self) -> u16 {
        self.0
    }

    /// Перечень поддерживаемых номеров — для ответа об отказе.
    #[must_use]
    pub fn supported() -> Vec<u16> {
        Self::SUPPORTED.iter().map(|version| version.0).collect()
    }
}

/// Разбирает версию контракта и отмечает её в запросе и в ответе.
///
/// Неизвестная версия отвергается до обработчика: обработчик не должен уметь
/// увидеть запрос, версию которого он не понимает.
pub async fn negotiate(mut request: Request, next: Next) -> Response {
    let header = request
        .headers()
        .get(API_VERSION)
        .map(|value| value.to_str().unwrap_or_default().to_owned());
    let version = match header {
        None => Version::fallback(),
        Some(value) => match Version::parse(&value) {
            Ok(version) => version,
            Err(_) => {
                return Problem::new(
                    "about:blank",
                    "версия контракта не поддерживается",
                    StatusCode::BAD_REQUEST,
                )
                .detailed(format!("значение заголовка API-Version: {value}"))
                .supporting(Version::supported())
                .into_response_with_vary()
            }
        },
    };
    request.extensions_mut().insert(version);
    tracing::Span::current().record("api_version", version.number());
    let mut response = next.run(request).await;
    mark(&mut response, version);
    response
}

/// Проставляет в ответе применённую версию и запрет на кэширование без её учёта.
fn mark(response: &mut Response, version: Version) {
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&version.number().to_string()) {
        headers.insert(API_VERSION, value);
    }
    headers.insert(VARY, HeaderValue::from_static("api-version"));
}

impl Problem {
    /// Отдаёт отказ, не забыв про `Vary`: иначе промежуточный кэш подменит
    /// представление версией другого клиента.
    fn into_response_with_vary(self) -> Response {
        use axum::response::IntoResponse as _;
        let mut response = self.into_response();
        response
            .headers_mut()
            .insert(VARY, HeaderValue::from_static("api-version"));
        response
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::Version;

    #[test]
    fn supported_version_is_parsed() {
        assert_eq!(
            Version::parse("1").unwrap(),
            Version::fallback(),
            "поддерживаемая версия разобрана неверно"
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        assert!(
            Version::parse("2").is_err(),
            "неподдерживаемая версия принята"
        );
    }

    #[test]
    fn non_numeric_version_is_rejected() {
        assert!(
            Version::parse("latest").is_err(),
            "нечисловое значение версии принято"
        );
    }

    #[test]
    fn fallback_is_the_newest_supported() {
        assert_eq!(
            Version::fallback(),
            *Version::SUPPORTED.iter().max().unwrap(),
            "умолчанием оказалась не самая новая поддерживаемая версия"
        );
    }
}
