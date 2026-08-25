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
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize, Serialize)]
pub struct Kdf {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

/// Обёртки ключей, присланные клиентом.
#[derive(Debug, Deserialize)]
pub struct Keys {
    account_by_password: Binary,
    account_by_recovery: Binary,
    private_by_account: Binary,
}

/// Представление учётной записи.
///
/// Ни ключей, ни солей, ни аутентификационного хеша здесь нет и быть не может.
#[derive(Debug, Serialize)]
pub struct User {
    id: String,
    login: String,
    state: &'static str,
    registered_at: String,
}

/// Открытый ключ пользователя.
#[derive(Debug, Serialize)]
pub struct Key {
    public_key: Binary,
}

/// Параметры выведения ключа, отдаваемые перед входом.
#[derive(Debug, Serialize)]
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
        registered_at: rfc3339(user.registered_at()),
    }
}

/// Записывает момент времени по RFC 3339.
///
/// Форматирование сделано вручную: крейт `time` в доступной версии тянет за
/// feature `formatting` макросы, которых нет в индексе.
fn rfc3339(moment: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        moment.year(),
        u8::from(moment.month()),
        moment.day(),
        moment.hour(),
        moment.minute(),
        moment.second()
    )
}
