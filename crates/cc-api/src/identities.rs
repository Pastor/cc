#![allow(
    clippy::redundant_pub_crate,
    reason = "обработчики видны только сборщику маршрутов: модуль приватный, а \
              публичными их делать нельзя — они не часть API крейта"
)]

//! Ресурс внешних личностей и запросов авторизации.
//!
//! Учётная запись здесь не создаётся ни при каких условиях: внешний вход
//! открывает доступ к уже существующей записи с привязанной личностью
//! (`TODO.md`, раздел 4.3). Привязка выполняется только из аутентифицированной
//! сессии — связывание по совпадению почты запрещено.

use crate::auth::Authenticated;
use crate::problem::Failure;
use crate::source::Source;
use crate::state::State;
use axum::extract::{Path, Query, State as Extract};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cc_domain::{ExternalIdentity, Provider};
use cc_storage::{Code, Entrance as _, Ticket, Widget};
use http::header::LOCATION;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// Заявка на процедуру у внешнего провайдера.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct Requested {
    provider: String,
}

/// Начатая процедура.
///
/// Билет клиент хранит у себя и предъявляет, забирая сессию: код авторизации и
/// обмен остаются на сервере.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Started {
    ticket: String,
    address: String,
}

/// Ответ провайдера на обратном вызове.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct Returned {
    code: String,
    state: String,
}

/// Привязанная внешняя личность.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Linked {
    provider: String,
    subject: String,
}

/// Заявка на привязку личности к учётной записи.
///
/// Способа два, по числу протоколов: завершённая процедура у провайдера с
/// обменом кода и подписанные данные виджета Telegram, для которых процедуры
/// нет вовсе.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum Attachment {
    /// Привязка по завершённой процедуре: билет запроса.
    Authorized {
        /// Билет запроса авторизации.
        authorization: String,
    },
    /// Привязка по подписанным данным виджета Telegram.
    Signed {
        /// Поля виджета вместе с подписью.
        telegram: BTreeMap<String, String>,
    },
}

/// Начинает процедуру у внешнего провайдера.
///
/// # Errors
///
/// - `404` — провайдер неизвестен либо не настроен;
/// - `429` — попытки слишком часты.
#[utoipa::path(
    post,
    path = "/api/sessions/authorizations",
    tag = "sessions",
    request_body = Requested,
    responses(
        (status = 201, description = "Процедура начата", body = Started),
        (status = 404, description = "Провайдер неизвестен либо не настроен"),
        (status = 429, description = "Попытки слишком часты"),
    ),
    params(("API-Version" = Option<u16>, Header, description = "Версия контракта")),
)]
pub(crate) async fn begin(
    Extract(state): Extract<State>,
    source: Source,
    Json(request): Json<Requested>,
) -> Result<Response, Failure> {
    let provider = Provider::parse(&request.provider)?;
    let now = OffsetDateTime::now_utc();
    guard(&state, &source, now).await?;
    let vk = state
        .federation()
        .vk()
        .filter(|_| provider == Provider::Vk)
        .ok_or(Failure::Storage(cc_storage::Error::Missing))?;
    let (ticket, authorization) = state
        .federation()
        .authorizations()
        .start(provider, source.key(), now)
        .await;
    let address = vk.authorization(ticket.expose(), authorization.pkce());
    let location = format!("/api/sessions/authorizations/{ticket}");
    let body = Started {
        ticket: ticket.expose().to_owned(),
        address,
    };
    Ok((StatusCode::CREATED, [(LOCATION, location)], Json(body)).into_response())
}

/// Принимает ответ провайдера.
///
/// Маршрут служебный: он вне версионируемого контракта и вызывается браузером,
/// а не клиентом. Личность остаётся ждать того, кто начал процедуру.
///
/// # Errors
///
/// - `404` — билет неизвестен, просрочен либо провайдер не тот;
/// - `429` — попытки слишком часты.
#[allow(
    clippy::doc_markdown,
    reason = "текст описания читает человек, а не rustdoc"
)]
pub(crate) async fn callback(
    Extract(state): Extract<State>,
    source: Source,
    Path(provider): Path<String>,
    Query(returned): Query<Returned>,
) -> Result<StatusCode, Failure> {
    let provider = Provider::parse(&provider)?;
    let now = OffsetDateTime::now_utc();
    guard(&state, &source, now).await?;
    let ticket = Ticket::presented(returned.state);
    let authorization = state
        .federation()
        .authorizations()
        .redeem(&ticket, now)
        .await?;
    if authorization.provider() != provider {
        return Err(Failure::Storage(cc_storage::Error::Missing));
    }
    let vk = state
        .federation()
        .vk()
        .filter(|_| provider == Provider::Vk)
        .ok_or(Failure::Storage(cc_storage::Error::Missing))?;
    let identity = vk
        .identity(Code::new(returned.code, authorization.pkce().clone()), now)
        .await?;
    state
        .federation()
        .authorizations()
        .settle(&ticket, &authorization, identity)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Перечисляет внешние личности учётной записи.
///
/// # Errors
///
/// `401` — сессия отсутствует либо истекла.
#[utoipa::path(
    get,
    path = "/api/users/me/external-identities",
    tag = "users",
    responses(
        (status = 200, description = "Перечень привязанных личностей", body = Vec<Linked>),
        (status = 401, description = "Сессия отсутствует либо истекла"),
    ),
    params(("API-Version" = Option<u16>, Header, description = "Версия контракта")),
    security(("bearer" = [])),
)]
pub(crate) async fn all(
    Extract(state): Extract<State>,
    session: Authenticated,
) -> Result<Json<Vec<Linked>>, Failure> {
    let linked = state
        .federation()
        .identities()
        .of(session.session().user())
        .await
        .into_iter()
        .map(|identity| Linked {
            provider: identity.provider().name().to_owned(),
            subject: identity.subject().to_owned(),
        })
        .collect();
    Ok(Json(linked))
}

/// Привязывает внешнюю личность к учётной записи.
///
/// Личность берётся из завершённой процедуры, а не из тела запроса: клиент не
/// может назвать себя чужим идентификатором у провайдера.
///
/// # Errors
///
/// - `401` — сессия отсутствует либо истекла;
/// - `404` — билет неизвестен, просрочен либо процедура не завершена;
/// - `409` — личность уже привязана к другой учётной записи.
#[utoipa::path(
    post,
    path = "/api/users/me/external-identities",
    tag = "users",
    request_body = Attachment,
    responses(
        (status = 201, description = "Личность привязана", body = Linked),
        (status = 401, description = "Сессия отсутствует либо истекла"),
        (status = 404, description = "Процедура неизвестна либо не завершена"),
        (status = 409, description = "Личность уже привязана к другой записи"),
    ),
    params(("API-Version" = Option<u16>, Header, description = "Версия контракта")),
    security(("bearer" = [])),
)]
pub(crate) async fn attach(
    Extract(state): Extract<State>,
    session: Authenticated,
    source: Source,
    Json(request): Json<Attachment>,
) -> Result<Response, Failure> {
    let now = OffsetDateTime::now_utc();
    let identity = match request {
        Attachment::Authorized { authorization } => state
            .federation()
            .authorizations()
            .collect(&Ticket::presented(authorization), source.key(), now)
            .await?
            .identity()
            .clone(),
        Attachment::Signed { telegram } => {
            let provider = state
                .federation()
                .telegram()
                .ok_or(Failure::Storage(cc_storage::Error::Missing))?;
            provider.identity(Widget::new(telegram)?, now).await?
        }
    };
    state
        .federation()
        .identities()
        .link(identity.clone(), session.session().user())
        .await?;
    let location = format!("/api/users/me/external-identities/{}", identity.provider());
    let body = Linked {
        provider: identity.provider().name().to_owned(),
        subject: identity.subject().to_owned(),
    };
    Ok((StatusCode::CREATED, [(LOCATION, location)], Json(body)).into_response())
}

/// Отвязывает внешнюю личность от учётной записи.
///
/// Пароль остаётся способом входа при любой отвязке: учётная запись без пароля
/// не заводится, и остаться без входа она не может.
///
/// # Errors
///
/// - `401` — сессия отсутствует либо истекла;
/// - `404` — личность не привязана к этой записи.
#[utoipa::path(
    delete,
    path = "/api/users/me/external-identities/{id}",
    tag = "users",
    responses(
        (status = 204, description = "Личность отвязана"),
        (status = 401, description = "Сессия отсутствует либо истекла"),
        (status = 404, description = "Личность не привязана к этой записи"),
        (status = 422, description = "Запись личности неразбираема"),
    ),
    params(
        ("id" = String, Path, description = "Личность в записи «провайдер:идентификатор»"),
        ("API-Version" = Option<u16>, Header, description = "Версия контракта"),
    ),
    security(("bearer" = [])),
)]
pub(crate) async fn detach(
    Extract(state): Extract<State>,
    session: Authenticated,
    Path(id): Path<String>,
) -> Result<StatusCode, Failure> {
    let identity = ExternalIdentity::parse(&id)?;
    state
        .federation()
        .identities()
        .unlink(&identity, session.session().user())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Ограничивает частоту обращений к публичным маршрутам внешнего входа.
///
/// Обратные вызовы провайдеров ограничиваются наравне с входом по паролю: это
/// публичные маршруты (`TODO.md`, раздел 4.3).
async fn guard(state: &State, source: &Source, now: OffsetDateTime) -> Result<(), Failure> {
    state
        .guards()
        .throttle()
        .permit(&format!("source:{}", source.key()), now)
        .await
        .map_err(|wait| Failure::TooSoon {
            seconds: wait.seconds(),
        })
}
