//! Сценарии ресурса файлов.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

mod support;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use cc_crypto::CiphertextHash;
use cc_domain::ContentHash;
use support::{unique_login, Instance, Response};

/// Шифротекст, который тест загружает: серверу он непрозрачен.
const CIPHERTEXT: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

/// Считает хеш шифротекста так же, как его считает сервер при приёме.
fn hash(ciphertext: &str) -> String {
    ContentHash::of(CiphertextHash::of(ciphertext.as_bytes()).as_bytes()).to_string()
}

/// Строит заявку на создание файла.
fn creation(ciphertext: &str) -> String {
    let wrapped = STANDARD.encode([3_u8; 72]);
    let public = STANDARD.encode([4_u8; 48]);
    let private = STANDARD.encode([5_u8; 48]);
    format!(
        r#"{{"technical":{{"hash":"{}","size":{},"format":1}},"metadata":{{"public":"{public}","private":"{private}"}},"keys":{{"content":"{wrapped}","metadata":"{wrapped}"}}}}"#,
        hash(ciphertext),
        ciphertext.len()
    )
}

/// Заводит файл и возвращает его идентификатор.
async fn created(server: &Instance, token: &str, ciphertext: &str) -> String {
    server
        .call("POST", "/api/files", token, Some(&creation(ciphertext)))
        .await
        .field("id")
}

/// Заводит файл вместе с загруженным содержимым.
async fn uploaded(server: &Instance, token: &str, ciphertext: &str) -> String {
    let id = created(server, token, ciphertext).await;
    server
        .call(
            "PUT",
            &format!("/api/files/{id}/content"),
            token,
            Some(ciphertext),
        )
        .await;
    id
}

/// Тело ответа целиком, включая заголовки, — для проверок диапазона.
fn header(response: &Response, name: &str) -> String {
    response
        .raw()
        .lines()
        .find(|line| {
            line.to_lowercase()
                .starts_with(&format!("{name}:").to_lowercase())
        })
        .map(|line| line.split_once(':').unwrap().1.trim().to_owned())
        .unwrap_or_default()
}

#[tokio::test]
async fn created_file_reports_its_location() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("files-created")).await;
    let response = server
        .call("POST", "/api/files", &token, Some(&creation(CIPHERTEXT)))
        .await;
    let located = response.has_header("location");
    server.stop().await;
    assert!(located, "созданный файл не сообщил своего адреса");
}

#[tokio::test]
async fn creation_requires_a_session() {
    let server = Instance::start().await;
    let response = server
        .call("POST", "/api/files", "", Some(&creation(CIPHERTEXT)))
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 401, "файл заведён без аутентифицированной сессии");
}

#[tokio::test]
async fn created_file_is_listed() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("files-listed")).await;
    let id = created(&server, &token, CIPHERTEXT).await;
    let listing = server.call("GET", "/api/files", &token, None).await;
    let body = listing.body().to_owned();
    server.stop().await;
    assert!(
        body.contains(&id),
        "заведённый файл не попал в коллекцию владельца"
    );
}

#[tokio::test]
async fn collection_hides_foreign_files() {
    let server = Instance::start().await;
    let owner = server.signed_in(&unique_login("files-owner")).await;
    let stranger = server.signed_in(&unique_login("files-stranger")).await;
    let id = created(&server, &owner, CIPHERTEXT).await;
    let listing = server.call("GET", "/api/files", &stranger, None).await;
    let body = listing.body().to_owned();
    server.stop().await;
    assert!(
        !body.contains(&id),
        "в коллекции постороннего оказался чужой файл"
    );
}

#[tokio::test]
async fn collection_carries_no_foreign_keys() {
    let server = Instance::start().await;
    let owner = server.signed_in(&unique_login("files-keys")).await;
    let stranger = server.signed_in(&unique_login("files-nokeys")).await;
    created(&server, &owner, CIPHERTEXT).await;
    let listing = server.call("GET", "/api/files", &stranger, None).await;
    let body = listing.body().to_owned();
    server.stop().await;
    assert!(
        !body.contains(&STANDARD.encode([3_u8; 72])),
        "в коллекции постороннего оказался чужой ключ доступа"
    );
}

#[tokio::test]
async fn foreign_file_is_not_found() {
    let server = Instance::start().await;
    let owner = server.signed_in(&unique_login("files-hidden")).await;
    let stranger = server.signed_in(&unique_login("files-seeker")).await;
    let id = created(&server, &owner, CIPHERTEXT).await;
    let response = server
        .call("GET", &format!("/api/files/{id}"), &stranger, None)
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 404, "чужой файл виден постороннему");
}

#[tokio::test]
async fn uploaded_content_comes_back_whole() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("files-download")).await;
    let id = uploaded(&server, &token, CIPHERTEXT).await;
    let response = server
        .call("GET", &format!("/api/files/{id}/content"), &token, None)
        .await;
    let body = response.body().to_owned();
    server.stop().await;
    assert_eq!(
        body, CIPHERTEXT,
        "скачанный шифротекст отличается от загруженного"
    );
}

#[tokio::test]
async fn upload_of_mismatched_size_is_refused() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("files-mismatch")).await;
    let id = created(&server, &token, CIPHERTEXT).await;
    let response = server
        .call(
            "PUT",
            &format!("/api/files/{id}/content"),
            &token,
            Some("другой шифротекст"),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(
        status, 422,
        "шифротекст, не сошедшийся с заявленным, принят"
    );
}

#[tokio::test]
async fn repeated_upload_is_idempotent() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("files-idempotent")).await;
    let id = uploaded(&server, &token, CIPHERTEXT).await;
    let again = server
        .call(
            "PUT",
            &format!("/api/files/{id}/content"),
            &token,
            Some(CIPHERTEXT),
        )
        .await;
    let status = again.status();
    let response = server
        .call("GET", &format!("/api/files/{id}/content"), &token, None)
        .await;
    let body = response.body().to_owned();
    server.stop().await;
    assert_eq!(
        (status, body.as_str()),
        (204, CIPHERTEXT),
        "повторная загрузка того же шифротекста изменила состояние"
    );
}

#[tokio::test]
async fn content_of_a_foreign_file_is_not_served() {
    let server = Instance::start().await;
    let owner = server.signed_in(&unique_login("files-content-owner")).await;
    let stranger = server.signed_in(&unique_login("files-content-thief")).await;
    let id = uploaded(&server, &owner, CIPHERTEXT).await;
    let response = server
        .call("GET", &format!("/api/files/{id}/content"), &stranger, None)
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 404, "содержимое чужого файла отдано постороннему");
}

#[tokio::test]
async fn missing_content_is_not_served() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("files-empty")).await;
    let id = created(&server, &token, CIPHERTEXT).await;
    let response = server
        .call("GET", &format!("/api/files/{id}/content"), &token, None)
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 404, "незагруженное содержимое отдано как готовое");
}

#[tokio::test]
async fn range_request_returns_partial_content() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("files-range")).await;
    let id = uploaded(&server, &token, CIPHERTEXT).await;
    let whole = server
        .call("GET", &format!("/api/files/{id}/content"), &token, None)
        .await
        .status();
    let partial = server
        .call(
            "GET",
            &format!("/api/files/{id}/content"),
            &format!("{token}Range: bytes=0-9\r\n"),
            None,
        )
        .await;
    let status = partial.status();
    server.stop().await;
    assert_eq!(
        (whole, status),
        (200, 206),
        "запрос диапазона не отдал частичного содержимого"
    );
}

#[tokio::test]
async fn range_request_returns_the_requested_slice() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("files-slice")).await;
    let id = uploaded(&server, &token, CIPHERTEXT).await;
    let response = server
        .call(
            "GET",
            &format!("/api/files/{id}/content"),
            &format!("{token}Range: bytes=10-19\r\n"),
            None,
        )
        .await;
    let body = response.body().to_owned();
    server.stop().await;
    assert_eq!(
        body,
        &CIPHERTEXT[10..20],
        "запрос диапазона отдал не тот отрезок"
    );
}

#[tokio::test]
async fn range_response_reports_its_span() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("files-span")).await;
    let id = uploaded(&server, &token, CIPHERTEXT).await;
    let response = server
        .call(
            "GET",
            &format!("/api/files/{id}/content"),
            &format!("{token}Range: bytes=10-19\r\n"),
            None,
        )
        .await;
    let range = header(&response, "content-range");
    server.stop().await;
    assert_eq!(
        range,
        format!("bytes 10-19/{}", CIPHERTEXT.len()),
        "частичный ответ не описал отданного отрезка"
    );
}

#[tokio::test]
async fn range_past_the_end_is_refused() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("files-beyond")).await;
    let id = uploaded(&server, &token, CIPHERTEXT).await;
    let response = server
        .call(
            "GET",
            &format!("/api/files/{id}/content"),
            &format!("{token}Range: bytes=9000-9999\r\n"),
            None,
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 416, "диапазон за пределом содержимого принят");
}

#[tokio::test]
async fn discarded_file_leaves_the_collection() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("files-discard")).await;
    let id = uploaded(&server, &token, CIPHERTEXT).await;
    server
        .call("DELETE", &format!("/api/files/{id}"), &token, None)
        .await;
    let listing = server.call("GET", "/api/files", &token, None).await;
    let body = listing.body().to_owned();
    server.stop().await;
    assert!(
        !body.contains(&id),
        "удалённый файл остался в коллекции владельца"
    );
}

#[tokio::test]
async fn foreign_file_is_not_discarded() {
    let server = Instance::start().await;
    let owner = server.signed_in(&unique_login("files-keep")).await;
    let stranger = server.signed_in(&unique_login("files-vandal")).await;
    let id = created(&server, &owner, CIPHERTEXT).await;
    let response = server
        .call("DELETE", &format!("/api/files/{id}"), &stranger, None)
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 404, "чужой файл удалён посторонним");
}

#[tokio::test]
async fn collection_paginates() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("files-paging")).await;
    created(&server, &token, CIPHERTEXT).await;
    created(&server, &token, "другое содержимое").await;
    let page = server.call("GET", "/api/files?limit=1", &token, None).await;
    let body = page.body().to_owned();
    server.stop().await;
    assert!(
        body.contains("\"next\""),
        "страница коллекции не сообщила курсора следующей"
    );
}

#[tokio::test]
async fn owner_sees_the_private_metadata() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("meta-owner")).await;
    let id = created(&server, &token, CIPHERTEXT).await;
    let response = server
        .call("GET", &format!("/api/files/{id}"), &token, None)
        .await;
    let body = response.body().to_owned();
    server.stop().await;
    assert!(
        body.contains(&STANDARD.encode([5_u8; 48])),
        "владелец не увидел закрытой метаинформации своего файла"
    );
}

#[tokio::test]
async fn stranger_sees_no_metadata_at_all() {
    let server = Instance::start().await;
    let owner = server.signed_in(&unique_login("meta-hidden")).await;
    let stranger = server.signed_in(&unique_login("meta-seeker")).await;
    created(&server, &owner, CIPHERTEXT).await;
    let listing = server.call("GET", "/api/files", &stranger, None).await;
    let body = listing.body().to_owned();
    server.stop().await;
    assert!(
        !body.contains(&STANDARD.encode([4_u8; 48])),
        "постороннему видна публичная метаинформация чужого файла"
    );
}

#[tokio::test]
async fn published_metadata_replaces_the_public_part() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("meta-publish")).await;
    let id = created(&server, &token, CIPHERTEXT).await;
    let replacement = STANDARD.encode([6_u8; 24]);
    server
        .call(
            "PUT",
            &format!("/api/files/{id}/public-metadata"),
            &format!("{token}If-Match: W/\"1\"\r\n"),
            Some(&format!(r#"{{"public":"{replacement}"}}"#)),
        )
        .await;
    let response = server
        .call("GET", &format!("/api/files/{id}"), &token, None)
        .await;
    let body = response.body().to_owned();
    server.stop().await;
    assert!(
        body.contains(&replacement),
        "публичная метаинформация не заменилась"
    );
}

#[tokio::test]
async fn publishing_demands_a_condition() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("meta-unconditional")).await;
    let id = created(&server, &token, CIPHERTEXT).await;
    let response = server
        .call(
            "PUT",
            &format!("/api/files/{id}/public-metadata"),
            &token,
            Some(&format!(
                r#"{{"public":"{}"}}"#,
                STANDARD.encode([6_u8; 24])
            )),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(
        status, 428,
        "метаинформация переписана без условия If-Match"
    );
}

#[tokio::test]
async fn stale_revision_is_refused() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("meta-stale")).await;
    let id = created(&server, &token, CIPHERTEXT).await;
    let body = format!(r#"{{"public":"{}"}}"#, STANDARD.encode([6_u8; 24]));
    server
        .call(
            "PUT",
            &format!("/api/files/{id}/public-metadata"),
            &format!("{token}If-Match: W/\"1\"\r\n"),
            Some(&body),
        )
        .await;
    let again = server
        .call(
            "PUT",
            &format!("/api/files/{id}/public-metadata"),
            &format!("{token}If-Match: W/\"1\"\r\n"),
            Some(&body),
        )
        .await;
    let status = again.status();
    server.stop().await;
    assert_eq!(
        status, 412,
        "изменение по устаревшей редакции затёрло чужое"
    );
}

#[tokio::test]
async fn publishing_leaves_the_ciphertext_alone() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("meta-content")).await;
    let id = uploaded(&server, &token, CIPHERTEXT).await;
    server
        .call(
            "PUT",
            &format!("/api/files/{id}/public-metadata"),
            &format!("{token}If-Match: W/\"1\"\r\n"),
            Some(&format!(
                r#"{{"public":"{}"}}"#,
                STANDARD.encode([6_u8; 24])
            )),
        )
        .await;
    let response = server
        .call("GET", &format!("/api/files/{id}/content"), &token, None)
        .await;
    let content = response.body().to_owned();
    server.stop().await;
    assert_eq!(
        content, CIPHERTEXT,
        "замена метаинформации затронула шифротекст"
    );
}

#[tokio::test]
async fn oversized_metadata_is_refused() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("meta-oversized")).await;
    let id = created(&server, &token, CIPHERTEXT).await;
    let response = server
        .call(
            "PUT",
            &format!("/api/files/{id}/public-metadata"),
            &format!("{token}If-Match: W/\"1\"\r\n"),
            Some(&format!(
                r#"{{"public":"{}"}}"#,
                STANDARD.encode(vec![7_u8; 70_000])
            )),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 413, "метаинформация сверх предела принята");
}

#[tokio::test]
async fn foreign_metadata_is_not_published() {
    let server = Instance::start().await;
    let owner = server.signed_in(&unique_login("meta-owner-keep")).await;
    let stranger = server.signed_in(&unique_login("meta-vandal")).await;
    let id = created(&server, &owner, CIPHERTEXT).await;
    let response = server
        .call(
            "PUT",
            &format!("/api/files/{id}/public-metadata"),
            &format!("{stranger}If-Match: W/\"1\"\r\n"),
            Some(&format!(
                r#"{{"public":"{}"}}"#,
                STANDARD.encode([6_u8; 24])
            )),
        )
        .await;
    let status = response.status();
    server.stop().await;
    assert_eq!(status, 404, "метаинформация чужого файла переписана");
}

#[tokio::test]
async fn concealed_metadata_replaces_the_private_part() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("meta-conceal")).await;
    let id = created(&server, &token, CIPHERTEXT).await;
    let replacement = STANDARD.encode([8_u8; 24]);
    server
        .call(
            "PUT",
            &format!("/api/files/{id}/private-metadata"),
            &format!("{token}If-Match: W/\"1\"\r\n"),
            Some(&format!(r#"{{"private":"{replacement}"}}"#)),
        )
        .await;
    let response = server
        .call("GET", &format!("/api/files/{id}"), &token, None)
        .await;
    let body = response.body().to_owned();
    server.stop().await;
    assert!(
        body.contains(&replacement),
        "закрытая метаинформация не заменилась"
    );
}

#[tokio::test]
async fn server_writes_the_technical_metadata_itself() {
    let server = Instance::start().await;
    let token = server.signed_in(&unique_login("meta-technical")).await;
    let forged = format!(
        r#"{{"technical":{{"hash":"{}","size":{},"format":1,"content":"00000000-0000-0000-0000-000000000000","uploaded":true,"created_at":"1970-01-01T00:00:00Z"}},"metadata":{{"public":"{}"}},"keys":{{"content":"{}","metadata":"{}"}}}}"#,
        hash(CIPHERTEXT),
        CIPHERTEXT.len(),
        STANDARD.encode([4_u8; 48]),
        STANDARD.encode([3_u8; 72]),
        STANDARD.encode([3_u8; 72])
    );
    let response = server
        .call("POST", "/api/files", &token, Some(&forged))
        .await;
    let body = response.body().to_owned();
    server.stop().await;
    assert!(
        !body.contains("00000000-0000-0000-0000-000000000000")
            && body.contains("\"uploaded\":false"),
        "присланная клиентом техническая метаинформация принята за свою"
    );
}
