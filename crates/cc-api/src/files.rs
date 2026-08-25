#![allow(
    clippy::redundant_pub_crate,
    reason = "обработчики видны только сборщику маршрутов: модуль приватный, а \
              публичными их делать нельзя — они не часть API крейта"
)]

//! Ресурс файлов и их содержимого.
//!
//! Открытого имени файла у сервера нет: оно зашифровано и живёт в публичной
//! метаинформации. Наружу отдаётся техническая метаинформация, права заявителя
//! и **его собственный** ключ доступа — чужие обёртки в представление не
//! попадают (`TODO.md`, раздел 3).

use crate::auth::Authenticated;
use crate::bytes::Binary;
use crate::problem::Failure;
use crate::ranges::span;
use crate::state::State;
use axum::body::Body;
use axum::extract::{Path, Query, State as Extract};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cc_domain::{
    ByteSize, Claimant, Content, ContentHash, ContentId, Envelope, File, FileId, Right, Rights,
    Stamps, Subject, Technical,
};
use cc_storage::{Listed, PAGE_DEFAULT};
use http::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, LOCATION, RANGE};
use http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Тип содержимого: сервер видит шифротекст и ничего о нём не знает.
const OCTET_STREAM: &str = "application/octet-stream";

/// Техническая метаинформация, заявленная клиентом при создании файла.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct Declared {
    hash: String,
    size: u64,
    format: u8,
}

/// Обёрнутые ключи субъекта.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct Wrapping {
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<Binary>,
    metadata: Binary,
}

/// Заявка на создание файла.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct Creation {
    #[serde(default)]
    directory: Option<String>,
    technical: Declared,
    keys: Wrapping,
}

/// Техническая метаинформация в ответе.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Recorded {
    content: String,
    hash: String,
    size: u64,
    format: u8,
    created_at: String,
    modified_at: String,
    uploaded: bool,
}

/// Файл в объёме прав заявителя.
///
/// Владельца здесь нет намеренно: получателю он не нужен, а раскрытие сверх
/// необходимого — то, чем страдала прежняя реализация.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Described {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    directory: Option<String>,
    technical: Recorded,
    rights: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Wrapping>,
}

/// Страница коллекции файлов.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Listing {
    files: Vec<Described>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<String>,
}

/// Пределы страницы коллекции.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct Paging {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    after: Option<String>,
}

/// Создаёт файл.
///
/// Содержимое приходит отдельным обращением: сервер уже знает его размер и хеш
/// и сверит их при приёме.
///
/// # Errors
///
/// - `401` — сессия отсутствует либо истекла;
/// - `422` — заявленная метаинформация недопустима.
#[utoipa::path(
    post,
    path = "/api/files",
    tag = "files",
    request_body = Creation,
    responses(
        (status = 201, description = "Файл заведён", body = Described),
        (status = 401, description = "Сессия отсутствует либо истекла"),
        (status = 422, description = "Заявленная метаинформация недопустима"),
    ),
    params(("API-Version" = Option<u16>, Header, description = "Версия контракта")),
    security(("bearer" = [])),
)]
pub(crate) async fn create(
    Extract(state): Extract<State>,
    session: Authenticated,
    Json(request): Json<Creation>,
) -> Result<Response, Failure> {
    let owner = session.session().user();
    let directory = request
        .directory
        .as_deref()
        .map(cc_domain::DirectoryId::parse)
        .transpose()?;
    let now = OffsetDateTime::now_utc();
    let technical = Technical::new(
        Content::new(
            ContentId::generate(),
            ContentHash::new(request.technical.hash)?,
            ByteSize::new(request.technical.size),
        ),
        request.technical.format,
        Stamps::new(now),
    )?;
    let file = File::new(FileId::generate(), owner, directory);
    let envelope = Envelope::new(
        Subject::User(owner),
        request.keys.content.map(Binary::into_inner),
        request.keys.metadata.into_inner(),
    )?;
    state
        .files()
        .create(file, technical.clone(), envelope.clone())
        .await;
    let body = described(&file, &technical, Rights::all(), Some(&envelope));
    let location = format!("/api/files/{}", file.id());
    Ok((StatusCode::CREATED, [(LOCATION, location)], Json(body)).into_response())
}

/// Отдаёт страницу коллекции файлов, видимых заявителю.
///
/// # Errors
///
/// `401` — сессия отсутствует либо истекла.
#[utoipa::path(
    get,
    path = "/api/files",
    tag = "files",
    responses(
        (status = 200, description = "Страница коллекции", body = Listing),
        (status = 401, description = "Сессия отсутствует либо истекла"),
        (status = 422, description = "Курсор недопустим"),
    ),
    params(
        Paging,
        ("API-Version" = Option<u16>, Header, description = "Версия контракта"),
    ),
    security(("bearer" = [])),
)]
pub(crate) async fn all(
    Extract(state): Extract<State>,
    session: Authenticated,
    Query(paging): Query<Paging>,
) -> Result<Json<Listing>, Failure> {
    let after = paging.after.as_deref().map(FileId::parse).transpose()?;
    let claimant = claimant(&session);
    let page = state
        .files()
        .all(&claimant, &[], after, paging.limit.unwrap_or(PAGE_DEFAULT))
        .await;
    let files = page
        .files()
        .iter()
        .map(|listed| listing(&claimant, listed))
        .collect();
    Ok(Json(Listing {
        files,
        next: page.next().map(|id| id.to_string()),
    }))
}

/// Отдаёт метаинформацию файла.
///
/// # Errors
///
/// - `401` — сессия отсутствует либо истекла;
/// - `404` — файла нет либо он заявителю не виден.
#[utoipa::path(
    get,
    path = "/api/files/{id}",
    tag = "files",
    responses(
        (status = 200, description = "Метаинформация файла", body = Described),
        (status = 401, description = "Сессия отсутствует либо истекла"),
        (status = 404, description = "Файла нет либо он не виден"),
        (status = 422, description = "Идентификатор недопустим"),
    ),
    params(
        ("id" = String, Path, description = "Идентификатор файла"),
        ("API-Version" = Option<u16>, Header, description = "Версия контракта"),
    ),
    security(("bearer" = [])),
)]
pub(crate) async fn one(
    Extract(state): Extract<State>,
    session: Authenticated,
    Path(id): Path<String>,
) -> Result<Json<Described>, Failure> {
    let claimant = claimant(&session);
    let listed = state
        .files()
        .one(&claimant, FileId::parse(&id)?, &[])
        .await?;
    Ok(Json(listing(&claimant, &listed)))
}

/// Помещает файл в корзину.
///
/// Содержимое стирается по истечении срока корзины вместе с ключами: без ключа
/// оно невосстановимо даже при сохранившихся блоках (`TODO.md`, раздел 4.12).
///
/// # Errors
///
/// - `401` — сессия отсутствует либо истекла;
/// - `404` — файла нет либо удалять его заявителю не разрешено.
#[utoipa::path(
    delete,
    path = "/api/files/{id}",
    tag = "files",
    responses(
        (status = 204, description = "Файл помещён в корзину"),
        (status = 401, description = "Сессия отсутствует либо истекла"),
        (status = 404, description = "Файла нет либо он не виден"),
        (status = 422, description = "Идентификатор недопустим"),
    ),
    params(
        ("id" = String, Path, description = "Идентификатор файла"),
        ("API-Version" = Option<u16>, Header, description = "Версия контракта"),
    ),
    security(("bearer" = [])),
)]
pub(crate) async fn discard(
    Extract(state): Extract<State>,
    session: Authenticated,
    Path(id): Path<String>,
) -> Result<StatusCode, Failure> {
    state
        .files()
        .discard(
            &claimant(&session),
            FileId::parse(&id)?,
            &[],
            OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Принимает шифротекст.
///
/// Операция идемпотентна: повторная загрузка того же шифротекста меняет только
/// время изменения. Фактические размер и хеш считаются при приёме и сверяются с
/// заявленными — заголовку `Content-Length` доверия нет.
///
/// # Errors
///
/// - `401` — сессия отсутствует либо истекла;
/// - `404` — файла нет либо записывать в него не разрешено;
/// - `422` — размер или хеш не совпали с заявленными.
#[utoipa::path(
    put,
    path = "/api/files/{id}/content",
    tag = "files",
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses(
        (status = 204, description = "Шифротекст принят"),
        (status = 401, description = "Сессия отсутствует либо истекла"),
        (status = 404, description = "Файла нет либо он не виден"),
        (status = 422, description = "Размер или хеш не совпали с заявленными"),
    ),
    params(
        ("id" = String, Path, description = "Идентификатор файла"),
        ("API-Version" = Option<u16>, Header, description = "Версия контракта"),
    ),
    security(("bearer" = [])),
)]
pub(crate) async fn upload(
    Extract(state): Extract<State>,
    session: Authenticated,
    Path(id): Path<String>,
    ciphertext: axum::body::Bytes,
) -> Result<StatusCode, Failure> {
    let id = FileId::parse(&id)?;
    let claimant = claimant(&session);
    let listed = state.files().one(&claimant, id, &[]).await?;
    cc_domain::permit(&claimant, listed.file(), &[], Right::Write)
        .map_err(|_| Failure::Storage(cc_storage::Error::Missing))?;
    let content = listed.technical().content();
    state
        .blobs()
        .put(content.id(), &ciphertext, content.hash(), content.size())
        .await?;
    state.files().attach(id, OffsetDateTime::now_utc()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Отдаёт шифротекст, поддерживая докачку по диапазону.
///
/// # Errors
///
/// - `401` — сессия отсутствует либо истекла;
/// - `404` — файла нет, содержимое не загружено либо читать его не разрешено;
/// - `416` — запрошенный диапазон вне содержимого.
#[utoipa::path(
    get,
    path = "/api/files/{id}/content",
    tag = "files",
    responses(
        (status = 200, description = "Шифротекст целиком", content_type = "application/octet-stream"),
        (status = 206, description = "Отрезок шифротекста", content_type = "application/octet-stream"),
        (status = 401, description = "Сессия отсутствует либо истекла"),
        (status = 404, description = "Файла нет либо содержимое не загружено"),
        (status = 416, description = "Запрошенный диапазон вне содержимого"),
    ),
    params(
        ("id" = String, Path, description = "Идентификатор файла"),
        ("Range" = Option<String>, Header, description = "Запрошенный отрезок"),
        ("API-Version" = Option<u16>, Header, description = "Версия контракта"),
    ),
    security(("bearer" = [])),
)]
pub(crate) async fn download(
    Extract(state): Extract<State>,
    session: Authenticated,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Failure> {
    let claimant = claimant(&session);
    let listed = state
        .files()
        .one(&claimant, FileId::parse(&id)?, &[])
        .await?;
    cc_domain::permit(&claimant, listed.file(), &[], Right::Read)
        .map_err(|_| Failure::Storage(cc_storage::Error::Missing))?;
    if listed.file().content().is_none() {
        return Err(Failure::Storage(cc_storage::Error::Missing));
    }
    let content = listed.technical().content();
    let size = content.size().get();
    let requested = headers
        .get(RANGE)
        .and_then(|value| value.to_str().ok())
        .map(|value| span(value, size).ok_or(Failure::Unsatisfiable))
        .transpose()?;
    let (offset, length) = requested.map_or((0, size), |span| (span.offset(), span.length()));
    let reader = state.blobs().reader(content.id(), offset, length).await?;
    let stream = tokio_util::io::ReaderStream::new(reader);
    let status = if requested.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut response = (status, Body::from_stream(stream)).into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, http::HeaderValue::from_static(OCTET_STREAM));
    headers.insert(ACCEPT_RANGES, http::HeaderValue::from_static("bytes"));
    if let Ok(value) = http::HeaderValue::from_str(&length.to_string()) {
        headers.insert(CONTENT_LENGTH, value);
    }
    if let Some(span) = requested {
        if let Ok(value) =
            http::HeaderValue::from_str(&format!("bytes {}-{}/{size}", span.offset(), span.last()))
        {
            headers.insert(CONTENT_RANGE, value);
        }
    }
    Ok(response)
}

// TODO: выданный доступ пока не хранится, поэтому проверкам передаётся пустой
// перечень: видит файл только владелец. Хранилище выданного доступа вводит
// TASK-014, и тогда сюда придут настоящие записи.

// TODO: квота при создании файла не проверяется — учёта израсходованного
// объёма ещё нет. Его вводит TASK-015 (`TODO.md`, раздел 4.6, пункт 4).

/// Собирает заявителя из сессии.
const fn claimant(session: &Authenticated) -> Claimant {
    Claimant::new(
        Subject::User(session.session().user()),
        session.session().scope().rights(),
    )
}

/// Собирает представление файла в объёме прав заявителя.
fn listing(claimant: &Claimant, listed: &Listed) -> Described {
    described(
        listed.file(),
        listed.technical(),
        cc_domain::rights(claimant, listed.file(), &[]),
        listed.envelope(),
    )
}

/// Собирает представление файла.
fn described(
    file: &File,
    technical: &Technical,
    rights: Rights,
    envelope: Option<&Envelope>,
) -> Described {
    Described {
        id: file.id().to_string(),
        directory: file.directory().map(|id| id.to_string()),
        technical: Recorded {
            content: technical.content().id().to_string(),
            hash: technical.content().hash().to_string(),
            size: technical.content().size().get(),
            format: technical.format(),
            created_at: crate::moment(technical.stamps().created_at()),
            modified_at: crate::moment(technical.stamps().modified_at()),
            uploaded: file.content().is_some(),
        },
        rights: rights.iter().map(|right| right.name().to_owned()).collect(),
        keys: envelope.map(|envelope| Wrapping {
            content: envelope.content().map(|bytes| Binary::new(bytes.to_vec())),
            metadata: Binary::new(envelope.metadata().to_vec()),
        }),
    }
}
