//! Источник обращения.

use axum::extract::{ConnectInfo, FromRequestParts};
use core::future::Future;
use http::request::Parts;
use std::convert::Infallible;
use std::net::SocketAddr;

/// Откуда пришёл запрос.
///
/// Значение используется только для ограничения частоты и в журнал не пишется.
/// Заголовкам `X-Forwarded-For` доверия нет: без настройки доверенного прокси
/// их подделывает кто угодно, и ограничение обходится подстановкой чужого
/// адреса (`TODO.md`, раздел 10.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source(String);

impl Source {
    /// Отдаёт ключ источника для учёта попыток.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.0
    }
}

impl<S: Sync> FromRequestParts<S> for Source {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        let address = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map_or_else(
                || String::from("unknown"),
                |ConnectInfo(address)| address.ip().to_string(),
            );
        core::future::ready(Ok(Self(address)))
    }
}
