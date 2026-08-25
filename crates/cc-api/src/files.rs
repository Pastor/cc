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
    ByteSize, Claimant, Content, ContentHash, ContentId, Envelope, File, FileId, Metadata, Right,
    Rights, Stamps, Subject, Technical,
};
use cc_storage::{Listed, PAGE_DEFAULT};
use http::header::{
    ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, IF_MATCH, LOCATION, RANGE,
};
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

/// Зашифрованная метаинформация в запросе и в ответе.
///
/// Публичную разворачивает ключ метаданных файла, закрытую — ключ учётной
/// записи владельца. Сервер не понимает ни ту, ни другую (`TODO.md`, раздел 3).
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct Categories {
    public: Binary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private: Option<Binary>,
}

/// Заявка на замену публичной метаинформации.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct Publication {
    public: Binary,
}

/// Заявка на замену закрытой метаинформации.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct Concealment {
    #[serde(default)]
    private: Option<Binary>,
}

/// Заявка на создание файла.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct Creation {
    #[serde(default)]
    directory: Option<String>,
    technical: Declared,
    metadata: Categories,
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
    metadata: Categories,
    revision: u64,
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
    let limits = state.limits();
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
    let metadata = Metadata::new(
        sized(request.metadata.public, limits.metadata())?,
        request
            .metadata
            .private
            .map(|value| sized(value, limits.metadata()))
            .transpose()?,
    )?;
    state
        .files()
        .create(file, technical.clone(), metadata.clone(), envelope.clone())
        .await;
    let body = described(&file, &technical, &metadata, Rights::all(), Some(&envelope));
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
) -> Result<Response, Failure> {
    let claimant = claimant(&session);
    let listed = state
        .files()
        .one(&claimant, FileId::parse(&id)?, &[])
        .await?;
    let revision = listed.metadata().revision();
    let mut response = Json(listing(&claimant, &listed)).into_response();
    if let Ok(value) = http::HeaderValue::from_str(&tag(revision)) {
        response.headers_mut().insert(ETAG, value);
    }
    Ok(response)
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
        (status = 403, description = "Право записывать содержимое не выдано"),
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
        .map_err(|_| Failure::Forbidden)?;
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
    // Файл заявителю виден — значит право видеть метаинформацию у него есть, и
    // отказ в чтении содержимого не раскрывает существования ресурса
    // (`TODO.md`, раздел 4.10, шаг 3).
    cc_domain::permit(&claimant, listed.file(), &[], Right::Read)
        .map_err(|_| Failure::Forbidden)?;
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

// TODO: право видеть публичную метаинформацию отделено от права читать
// содержимое, но проверить это сценарием пока не на чем: выдать доступ без
// права чтения некому, пока нет хранилища выданного доступа. Тест появится
// вместе с TASK-014.

// TODO: выданный доступ пока не хранится, поэтому проверкам передаётся пустой
// перечень: видит файл только владелец. Хранилище выданного доступа вводит
// TASK-014, и тогда сюда придут настоящие записи.

// TODO: квота при создании файла не проверяется — учёта израсходованного
// объёма ещё нет. Его вводит TASK-015 (`TODO.md`, раздел 4.6, пункт 4).

/// Заменяет публичную метаинформацию.
///
/// Изменение условно: без совпадения редакции сервер отвечает `412`, и правка
/// с одного устройства не затирает правку с другого.
///
/// # Errors
///
/// - `401` — сессия отсутствует либо истекла;
/// - `404` — файла нет либо записывать в него не разрешено;
/// - `412` — предъявленная редакция разошлась с текущей;
/// - `413` — метаинформация длиннее предела;
/// - `428` — изменение требует заголовка `If-Match`.
#[utoipa::path(
    put,
    path = "/api/files/{id}/public-metadata",
    tag = "files",
    request_body = Publication,
    responses(
        (status = 204, description = "Публичная метаинформация заменена"),
        (status = 401, description = "Сессия отсутствует либо истекла"),
        (status = 404, description = "Файла нет либо он не виден"),
        (status = 412, description = "Редакция разошлась с текущей"),
        (status = 413, description = "Метаинформация длиннее предела"),
        (status = 428, description = "Изменение требует заголовка If-Match"),
    ),
    params(
        ("id" = String, Path, description = "Идентификатор файла"),
        ("If-Match" = String, Header, description = "Редакция метаинформации"),
        ("API-Version" = Option<u16>, Header, description = "Версия контракта"),
    ),
    security(("bearer" = [])),
)]
pub(crate) async fn publish(
    Extract(state): Extract<State>,
    session: Authenticated,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<Publication>,
) -> Result<Response, Failure> {
    let expected = expected(&headers)?;
    let public = sized(request.public, state.limits().metadata())?;
    let revision = state
        .files()
        .publish(
            &claimant(&session),
            FileId::parse(&id)?,
            &[],
            public,
            expected,
        )
        .await?;
    Ok(tagged(revision))
}

/// Заменяет закрытую метаинформацию.
///
/// Только владелец: закрытая категория зашифрована ключом его учётной записи,
/// и осмысленно переписать её больше некому.
///
/// # Errors
///
/// - `401` — сессия отсутствует либо истекла;
/// - `404` — файла нет либо заявитель не владелец;
/// - `412` — предъявленная редакция разошлась с текущей;
/// - `413` — метаинформация длиннее предела;
/// - `428` — изменение требует заголовка `If-Match`.
#[utoipa::path(
    put,
    path = "/api/files/{id}/private-metadata",
    tag = "files",
    request_body = Concealment,
    responses(
        (status = 204, description = "Закрытая метаинформация заменена"),
        (status = 401, description = "Сессия отсутствует либо истекла"),
        (status = 404, description = "Файла нет либо он не виден"),
        (status = 412, description = "Редакция разошлась с текущей"),
        (status = 413, description = "Метаинформация длиннее предела"),
        (status = 428, description = "Изменение требует заголовка If-Match"),
    ),
    params(
        ("id" = String, Path, description = "Идентификатор файла"),
        ("If-Match" = String, Header, description = "Редакция метаинформации"),
        ("API-Version" = Option<u16>, Header, description = "Версия контракта"),
    ),
    security(("bearer" = [])),
)]
pub(crate) async fn conceal(
    Extract(state): Extract<State>,
    session: Authenticated,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<Concealment>,
) -> Result<Response, Failure> {
    let expected = expected(&headers)?;
    let private = request
        .private
        .map(|value| sized(value, state.limits().metadata()))
        .transpose()?;
    let revision = state
        .files()
        .conceal(&claimant(&session), FileId::parse(&id)?, private, expected)
        .await?;
    Ok(tagged(revision))
}

/// Читает редакцию из заголовка `If-Match`.
///
/// Заголовок обязателен: безусловная запись метаинформации молча теряет чужие
/// изменения, а `RULE.md` требует немедленного отказа вместо молчаливого.
fn expected(headers: &HeaderMap) -> Result<u64, Failure> {
    let value = headers
        .get(IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or(Failure::ConditionRequired)?;
    value
        .trim()
        .trim_start_matches("W/")
        .trim_matches('"')
        .parse()
        .map_err(|_| Failure::ConditionFailed)
}

/// Отвечает без тела, объявляя новую редакцию метки.
fn tagged(revision: u64) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Ok(value) = http::HeaderValue::from_str(&tag(revision)) {
        response.headers_mut().insert(ETAG, value);
    }
    response
}

/// Записывает редакцию меткой сущности.
fn tag(revision: u64) -> String {
    format!("W/\"{revision}\"")
}

/// Проверяет, что значение укладывается в предел.
///
/// # Errors
///
/// [`Failure::TooLarge`], если значение длиннее предела.
fn sized(value: Binary, limit: usize) -> Result<Vec<u8>, Failure> {
    let bytes = value.into_inner();
    if bytes.len() > limit {
        return Err(Failure::TooLarge);
    }
    Ok(bytes)
}

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
        listed.metadata(),
        cc_domain::rights(claimant, listed.file(), &[]),
        listed.envelope(),
    )
}

/// Собирает представление файла.
fn described(
    file: &File,
    technical: &Technical,
    metadata: &Metadata,
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
        metadata: Categories {
            public: Binary::new(metadata.public().to_vec()),
            private: metadata.private().map(|bytes| Binary::new(bytes.to_vec())),
        },
        revision: metadata.revision(),
        rights: rights.iter().map(|right| right.name().to_owned()).collect(),
        keys: envelope.map(|envelope| Wrapping {
            content: envelope.content().map(|bytes| Binary::new(bytes.to_vec())),
            metadata: Binary::new(envelope.metadata().to_vec()),
        }),
    }
}
