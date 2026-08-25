#![allow(
    clippy::redundant_pub_crate,
    reason = "обработчики видны только сборщику маршрутов: модуль приватный, а \
              публичными их делать нельзя — они не часть API крейта"
)]

//! Ресурс учётных записей.
//!
//! Маршруты — `TODO.md`, раздел 10.3. Сервер сохраняет присланное и ничего в нём
//! не интерпретирует: пароля он не видит.

use crate::auth::Authenticated;
use crate::bytes::Binary;
use crate::problem::Failure;
use crate::state::State;
use axum::extract::{Path, State as Extract};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cc_crypto::{AuthHash, KdfParams, PublicKey, Salt, KEY_LEN, PUBLIC_KEY_LEN};
use cc_domain::Username;
use cc_storage::{Challenge, Registration, Wrapped};
use http::header::LOCATION;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Заявка на регистрацию.
///
/// Всё, кроме логина, сервер сохраняет как есть: разобрать это он не в
/// состоянии, потому что ключей у него нет.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct Enrollment {
    login: String,
    auth: Binary,
    salt: Binary,
    kdf: Kdf,
    public_key: Binary,
    wrapped: Keys,
    recovery_fingerprint: Binary,
}

/// Параметры выведения ключа, выбранные клиентом.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct Kdf {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

/// Обёртки ключей, присланные клиентом.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct Keys {
    account_by_password: Binary,
    account_by_recovery: Binary,
    private_by_account: Binary,
}

/// Представление учётной записи.
///
/// Ни ключей, ни солей, ни аутентификационного хеша здесь нет и быть не может.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct User {
    id: String,
    login: String,
    state: &'static str,
    registered_at: String,
}

/// Открытый ключ пользователя.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Key {
    public_key: Binary,
}

/// Параметры выведения ключа, отдаваемые перед входом.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Prelude {
    salt: Binary,
    kdf: Kdf,
}

/// Регистрирует учётную запись.
///
/// # Errors
///
/// - `422` — логин или присланные значения недопустимы;
/// - `409` — логин занят.
#[utoipa::path(
    post,
    path = "/api/users",
    tag = "users",
    request_body = Enrollment,
    responses(
        (status = 201, description = "Учётная запись создана", body = User),
        (status = 409, description = "Логин занят"),
        (status = 422, description = "Логин или присланные значения недопустимы"),
    ),
    params(("API-Version" = Option<u16>, Header, description = "Версия контракта")),
)]
pub(crate) async fn enroll(
    Extract(state): Extract<State>,
    Json(request): Json<Enrollment>,
) -> Result<Response, Failure> {
    let login = Username::new(request.login)?;
    let salt = Salt::new(request.salt.into_inner()).map_err(|_| Failure::Malformed)?;
    let params = KdfParams::new(
        request.kdf.memory_kib,
        request.kdf.iterations,
        request.kdf.parallelism,
    )
    .map_err(|_| Failure::Malformed)?;
    let auth = AuthHash::new(
        request
            .auth
            .into_array::<KEY_LEN>()
            .map_err(|_| Failure::Malformed)?,
    );
    let public = PublicKey::new(
        request
            .public_key
            .into_array::<PUBLIC_KEY_LEN>()
            .map_err(|_| Failure::Malformed)?,
    );
    let fingerprint = request
        .recovery_fingerprint
        .into_array::<32>()
        .map_err(|_| Failure::Malformed)?;
    let wrapped = Wrapped::new(
        request.wrapped.account_by_password.into_inner(),
        request.wrapped.account_by_recovery.into_inner(),
        request.wrapped.private_by_account.into_inner(),
    );
    let user = state
        .users()
        .register(
            login,
            &auth,
            Registration::new(Challenge::new(salt, params), public, wrapped, fingerprint),
            OffsetDateTime::now_utc(),
        )
        .await?;
    // Код подтверждения выпускается и уходит в очередь: регистрация отвечает,
    // не дожидаясь отправки.
    let code = confirmation_code();
    state
        .guards()
        .confirmations()
        .issue(user.login().clone(), &code, OffsetDateTime::now_utc())
        .await;
    state
        .guards()
        .postbox()
        .post(cc_storage::Letter::new(user.login().to_string(), code));
    let location = format!("/api/users/{}", user.id());
    Ok((
        StatusCode::CREATED,
        [(LOCATION, location)],
        Json(view(&user)),
    )
        .into_response())
}

/// Отдаёт сведения о текущем пользователе.
///
/// # Errors
///
/// `401` — сессия отсутствует либо истекла.
#[utoipa::path(
    get,
    path = "/api/users/me",
    tag = "users",
    responses(
        (status = 200, description = "Сведения о себе", body = User),
        (status = 401, description = "Сессия отсутствует либо истекла"),
    ),
    params(("API-Version" = Option<u16>, Header, description = "Версия контракта")),
    security(("bearer" = [])),
)]
pub(crate) async fn me(
    Extract(state): Extract<State>,
    session: Authenticated,
) -> Result<Json<User>, Failure> {
    let user = state.users().by_id(session.session().user()).await?;
    Ok(Json(view(&user)))
}

/// Отдаёт открытый ключ пользователя — по нему выдают ему доступ.
///
/// Маршрут требует аутентификации: без неё он работал бы перечислителем
/// зарегистрированных адресов.
///
/// # Errors
///
/// - `401` — сессия отсутствует;
/// - `404` — такого пользователя нет.
#[utoipa::path(
    get,
    path = "/api/users/{login}/public-key",
    tag = "users",
    responses(
        (status = 200, description = "Открытый ключ получателя", body = Key),
        (status = 401, description = "Сессия отсутствует"),
        (status = 404, description = "Такого пользователя нет"),
    ),
    params(
        ("login" = String, Path, description = "Логин пользователя"),
        ("API-Version" = Option<u16>, Header, description = "Версия контракта"),
    ),
    security(("bearer" = [])),
)]
pub(crate) async fn public_key(
    Extract(state): Extract<State>,
    _session: Authenticated,
    Path(login): Path<String>,
) -> Result<Json<Key>, Failure> {
    let login = Username::new(login)?;
    let key = state.users().public_key(&login).await?;
    Ok(Json(Key {
        public_key: Binary::new(key.as_bytes().to_vec()),
    }))
}

/// Отдаёт параметры выведения ключа по логину.
///
/// Отвечает и по неизвестному логину — правдоподобными значениями: иначе
/// маршрут работает оракулом существования учётных записей.
///
/// # Errors
///
/// `422` — логин недопустим.
#[utoipa::path(
    get,
    path = "/api/users/{login}/prelude",
    tag = "users",
    responses(
        (status = 200, description = "Соль и параметры выведения ключа", body = Prelude),
        (status = 422, description = "Логин недопустим"),
    ),
    params(
        ("login" = String, Path, description = "Логин пользователя"),
        ("API-Version" = Option<u16>, Header, description = "Версия контракта"),
    ),
)]
pub(crate) async fn prelude(
    Extract(state): Extract<State>,
    Path(login): Path<String>,
) -> Result<Json<Prelude>, Failure> {
    let login = Username::new(login)?;
    let challenge = state.users().challenge(&login).await?;
    Ok(Json(Prelude {
        salt: Binary::new(challenge.salt().as_bytes().to_vec()),
        kdf: Kdf {
            memory_kib: challenge.params().memory_kib(),
            iterations: challenge.params().iterations(),
            parallelism: challenge.params().parallelism(),
        },
    }))
}

/// Порождает код подтверждения.
///
/// Шесть цифр — компромисс между переписыванием вручную и стойкостью; перебор
/// закрывается ограничением числа попыток, а не длиной кода.
fn confirmation_code() -> String {
    let bytes = cc_crypto::ContentKey::generate();
    let number = u32::from_le_bytes([
        bytes.expose()[0],
        bytes.expose()[1],
        bytes.expose()[2],
        bytes.expose()[3],
    ]);
    format!("{:06}", number % 1_000_000)
}

/// Строит представление учётной записи.
fn view(user: &cc_domain::User) -> User {
    User {
        id: user.id().to_string(),
        login: user.login().to_string(),
        state: match user.state() {
            cc_domain::State::Pending => "pending",
            cc_domain::State::Active => "active",
            cc_domain::State::Blocked => "blocked",
            _ => "unknown",
        },
        registered_at: crate::moment(user.registered_at()),
    }
}
