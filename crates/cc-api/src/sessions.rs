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
use crate::source::Source;
use crate::state::State;
use axum::extract::{Path, State as Extract};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use cc_crypto::{AuthHash, KEY_LEN};
use cc_domain::{Scope, Username};
use http::header::LOCATION;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Заявка на вход.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct Credentials {
    login: String,
    auth: Binary,
}

/// Выданная сессия.
///
/// Токен отдаётся один раз: сервер хранит его отпечаток и вернуть токен не
/// может.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Issued {
    id: String,
    token: String,
    expires_at: String,
}

/// Сведения о действующей сессии.
#[derive(Debug, Serialize, utoipa::ToSchema)]
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
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct WrappedKeys {
    account_by_password: Binary,
    account_by_recovery: Binary,
    private_by_account: Binary,
}

/// Ответ на успешный вход.
#[derive(Debug, Serialize, utoipa::ToSchema)]
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
#[utoipa::path(
    post,
    path = "/api/sessions",
    tag = "sessions",
    request_body = Credentials,
    responses(
        (status = 201, description = "Сессия открыта", body = Entry),
        (status = 404, description = "Логин неизвестен либо хеш не сошёлся"),
        (status = 422, description = "Логин недопустим"),
    ),
    params(("API-Version" = Option<u16>, Header, description = "Версия контракта")),
)]
pub(crate) async fn open(
    Extract(state): Extract<State>,
    source: Source,
    Json(request): Json<Credentials>,
) -> Result<Response, Failure> {
    let login = Username::new(request.login)?;
    // Ограничение ведётся по двум измерениям сразу: только по источнику
    // обходится сменой адреса, только по учётной записи позволяет заблокировать
    // вход чужому человеку, зная его логин (`TODO.md`, раздел 8).
    let keys = [format!("login:{login}"), format!("source:{}", source.key())];
    let now = OffsetDateTime::now_utc();
    for key in &keys {
        state
            .guards()
            .throttle()
            .permit(key, now)
            .await
            .map_err(|wait| Failure::TooSoon {
                seconds: wait.seconds(),
            })?;
    }
    let auth = AuthHash::new(
        request
            .auth
            .into_array::<KEY_LEN>()
            .map_err(|_| Failure::Malformed)?,
    );
    let authenticated = state.users().authenticate(&login, &auth).await;
    let (user, wrapped) = match authenticated {
        Ok(pair) => {
            for key in &keys {
                state.guards().throttle().succeeded(key).await;
            }
            pair
        }
        Err(failure) => {
            for key in &keys {
                state.guards().throttle().failed(key, now).await;
            }
            return Err(failure.into());
        }
    };
    let (token, session) = state.sessions().open(user.id(), Scope::full(), now).await;
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
#[utoipa::path(
    get,
    path = "/api/sessions/current",
    tag = "sessions",
    responses(
        (status = 200, description = "Сведения о текущей сессии", body = Current),
        (status = 401, description = "Сессия отсутствует либо истекла"),
    ),
    params(("API-Version" = Option<u16>, Header, description = "Версия контракта")),
    security(("bearer" = [])),
)]
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
#[utoipa::path(
    delete,
    path = "/api/sessions/current",
    tag = "sessions",
    responses(
        (status = 204, description = "Сессия завершена"),
        (status = 401, description = "Сессия отсутствует либо истекла"),
    ),
    params(("API-Version" = Option<u16>, Header, description = "Версия контракта")),
    security(("bearer" = [])),
)]
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
#[utoipa::path(
    delete,
    path = "/api/sessions/{id}",
    tag = "sessions",
    responses(
        (status = 204, description = "Сессия завершена"),
        (status = 401, description = "Сессия отсутствует"),
        (status = 422, description = "Идентификатор недопустим"),
    ),
    params(
        ("id" = String, Path, description = "Идентификатор сессии"),
        ("API-Version" = Option<u16>, Header, description = "Версия контракта"),
    ),
    security(("bearer" = [])),
)]
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
