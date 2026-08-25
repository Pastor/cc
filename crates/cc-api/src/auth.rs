//! Извлечение аутентифицированной сессии из запроса.

use crate::problem::Failure;
use crate::state::State;
use axum::extract::FromRequestParts;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use cc_domain::Session;
use http::header::AUTHORIZATION;
use http::request::Parts;
use time::OffsetDateTime;

/// Действующая сессия запроса.
///
/// Извлекается из заголовка `Authorization: Bearer`. Отсутствие заголовка —
/// отказ, а не паника: прежняя реализация падала на отсутствии кук и отвечала
/// `500` там, где полагался `401`.
#[derive(Clone, Copy, Debug)]
pub struct Authenticated(Session);

impl Authenticated {
    /// Сессия.
    #[must_use]
    pub const fn session(&self) -> Session {
        self.0
    }
}

impl FromRequestParts<State> for Authenticated {
    type Rejection = Failure;

    async fn from_request_parts(parts: &mut Parts, state: &State) -> Result<Self, Self::Rejection> {
        let value = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(Failure::Unauthenticated)?;
        let encoded = value
            .strip_prefix("Bearer ")
            .ok_or(Failure::Unauthenticated)?;
        let bytes = STANDARD
            .decode(encoded.trim())
            .map_err(|_| Failure::Unauthenticated)?;
        let token = cc_storage::Token::parse(&bytes).map_err(|_| Failure::Unauthenticated)?;
        let session = state
            .sessions()
            .resolve(&token, OffsetDateTime::now_utc())
            .await
            .map_err(|_| Failure::Unauthenticated)?;
        Ok(Self(session))
    }
}
