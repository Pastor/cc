#![allow(
    clippy::redundant_pub_crate,
    reason = "обработчики видны только сборщику маршрутов: модуль приватный, а \
              публичными их делать нельзя — они не часть API крейта"
)]

//! Ресурс сессий.
//!
//! Вход выражен созданием ресурса, выход — его удалением. Прежняя реализация
//! имела для этого две несовместимые ручки с глаголами в пути и теряла причину
//! отказа, заворачивая всё подряд в один код.

use crate::auth::Authenticated;
use crate::bytes::Binary;
use crate::problem::Failure;
use crate::state::State;
use axum::extract::{Path, State as Extract};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use cc_crypto::{AuthHash, KEY_LEN};
use cc_domain::{Rights, Username};
use http::header::LOCATION;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Заявка на вход.
#[derive(Debug, Deserialize)]
pub struct Credentials {
    login: String,
    auth: Binary,
}

/// Выданная сессия.
///
/// Токен отдаётся один раз: сервер хранит его отпечаток и вернуть токен не
/// может.
#[derive(Debug, Serialize)]
pub struct Issued {
    id: String,
    token: String,
    expires_at: String,
}

/// Сведения о действующей сессии.
#[derive(Debug, Serialize)]
pub struct Current {
    id: String,
    user: String,
    created_at: String,
    expires_at: String,
    seen_at: String,
}

/// Обёртки ключей, отдаваемые вошедшему.
///
/// Развернуть их может только клиент: у сервера нет ни пароля, ни ключей.
#[derive(Debug, Serialize)]
pub struct WrappedKeys {
    account_by_password: Binary,
    account_by_recovery: Binary,
    private_by_account: Binary,
}

/// Ответ на успешный вход.
#[derive(Debug, Serialize)]
pub struct Entry {
    session: Issued,
    keys: WrappedKeys,
}

/// Открывает сессию по аутентификационному хешу.
///
/// # Errors
///
/// - `422` — логин недопустим;
/// - `404` — логин неизвестен либо хеш не сошёлся; различить эти случаи нельзя,
///   иначе ответ работает оракулом существования учётных записей.
pub(crate) async fn open(
    Extract(state): Extract<State>,
    Json(request): Json<Credentials>,
) -> Result<Response, Failure> {
    let login = Username::new(request.login)?;
    let auth = AuthHash::new(
        request
            .auth
            .into_array::<KEY_LEN>()
            .map_err(|_| Failure::Malformed)?,
    );
    let (user, wrapped) = state.users().authenticate(&login, &auth).await?;
    let (token, session) = state
        .sessions()
        .open(user.id(), Rights::all(), OffsetDateTime::now_utc())
        .await;
    let location = format!("/api/sessions/{}", session.id());
    let body = Entry {
        session: Issued {
            id: session.id().to_string(),
            token: STANDARD.encode(token.expose()),
            expires_at: crate::moment(session.timing().expires_at()),
        },
        keys: WrappedKeys {
            account_by_password: Binary::new(wrapped.account_by_password().to_vec()),
            account_by_recovery: Binary::new(wrapped.account_by_recovery().to_vec()),
            private_by_account: Binary::new(wrapped.private_by_account().to_vec()),
        },
    };
    Ok((StatusCode::CREATED, [(LOCATION, location)], Json(body)).into_response())
}

/// Отдаёт сведения о текущей сессии.
///
/// # Errors
///
/// `401` — сессия отсутствует либо истекла.
pub(crate) async fn current(session: Authenticated) -> Result<Json<Current>, Failure> {
    let session = session.session();
    Ok(Json(Current {
        id: session.id().to_string(),
        user: session.user().to_string(),
        created_at: crate::moment(session.timing().created_at()),
        expires_at: crate::moment(session.timing().expires_at()),
        seen_at: crate::moment(session.timing().seen_at()),
    }))
}

/// Завершает текущую сессию.
///
/// Идемпотентно: повторный выход тоже успешен. Прежняя реализация при выходе
/// стирала все куки запроса, а не только свою.
///
/// # Errors
///
/// `401` — сессия отсутствует либо истекла.
pub(crate) async fn close(
    Extract(state): Extract<State>,
    session: Authenticated,
) -> Result<StatusCode, Failure> {
    state
        .sessions()
        .close_by_id(session.session().user(), session.session().id())
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Завершает конкретную сессию пользователя.
///
/// # Errors
///
/// - `401` — сессия отсутствует;
/// - `422` — идентификатор недопустим.
pub(crate) async fn drop_one(
    Extract(state): Extract<State>,
    session: Authenticated,
    Path(id): Path<String>,
) -> Result<StatusCode, Failure> {
    let target = cc_domain::SessionId::parse(&id)?;
    state
        .sessions()
        .close_by_id(session.session().user(), target)
        .await;
    Ok(StatusCode::NO_CONTENT)
}
