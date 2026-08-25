//! Сценарии хранилища шифротекста.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_crypto::CiphertextHash;
use cc_domain::{ByteSize, ContentHash, ContentId};
use cc_storage::Blobs;
use tempfile::TempDir;

async fn store() -> (TempDir, Blobs) {
    let root = TempDir::new().unwrap();
    let blobs = Blobs::open(root.path()).await.unwrap();
    (root, blobs)
}

fn hash(ciphertext: &[u8]) -> ContentHash {
    ContentHash::of(CiphertextHash::of(ciphertext).as_bytes())
}

const fn size(ciphertext: &[u8]) -> ByteSize {
    ByteSize::new(ciphertext.len() as u64)
}

#[tokio::test]
async fn stored_ciphertext_reads_back_identically() {
    let (_root, blobs) = store().await;
    let id = ContentId::generate();
    let payload = b"encrypted payload";
    blobs
        .put(id, payload, &hash(payload), size(payload))
        .await
        .unwrap();
    assert_eq!(
        blobs.get(id).await.unwrap(),
        payload,
        "прочитанный шифротекст разошёлся с записанным"
    );
}

#[tokio::test]
async fn mismatching_hash_is_rejected() {
    let (_root, blobs) = store().await;
    let payload = b"encrypted payload";
    let wrong = hash(b"something else");
    assert!(
        blobs
            .put(ContentId::generate(), payload, &wrong, size(payload))
            .await
            .is_err(),
        "шифротекст с несовпадающим хешем принят"
    );
}

#[tokio::test]
async fn rejected_ciphertext_leaves_no_file() {
    let (root, blobs) = store().await;
    let payload = b"encrypted payload";
    let _ = blobs
        .put(
            ContentId::generate(),
            payload,
            &hash(b"something else"),
            size(payload),
        )
        .await;
    let entries = std::fs::read_dir(root.path()).unwrap().count();
    assert_eq!(
        entries, 0,
        "отклонённый шифротекст остался на диске и занимает квоту"
    );
}

#[tokio::test]
async fn mismatching_size_is_rejected() {
    let (_root, blobs) = store().await;
    let payload = b"encrypted payload";
    assert!(
        blobs
            .put(
                ContentId::generate(),
                payload,
                &hash(payload),
                ByteSize::new(1)
            )
            .await
            .is_err(),
        "шифротекст с несовпадающим размером принят"
    );
}

#[tokio::test]
async fn identical_plaintext_yields_independent_blobs() {
    let (_root, blobs) = store().await;
    let first = ContentId::generate();
    let second = ContentId::generate();
    let one = b"ciphertext of alice";
    let two = b"ciphertext of bobby";
    blobs.put(first, one, &hash(one), size(one)).await.unwrap();
    blobs.put(second, two, &hash(two), size(two)).await.unwrap();
    blobs.remove(first).await.unwrap();
    assert_eq!(
        blobs.get(second).await.unwrap(),
        two,
        "удаление одним пользователем сломало чтение другому"
    );
}

#[tokio::test]
async fn range_reads_requested_segment() {
    let (_root, blobs) = store().await;
    let id = ContentId::generate();
    let payload: Vec<u8> = (0..=255_u8).collect();
    blobs
        .put(id, &payload, &hash(&payload), size(&payload))
        .await
        .unwrap();
    assert_eq!(
        blobs.range(id, 10, 5).await.unwrap(),
        payload[10..15],
        "чтение по диапазону вернуло не тот отрезок"
    );
}

#[tokio::test]
async fn range_past_end_is_truncated() {
    let (_root, blobs) = store().await;
    let id = ContentId::generate();
    let payload = b"short";
    blobs
        .put(id, payload, &hash(payload), size(payload))
        .await
        .unwrap();
    assert_eq!(
        blobs.range(id, 3, 100).await.unwrap(),
        b"rt",
        "диапазон за пределом файла вернул не усечённый отрезок"
    );
}

#[tokio::test]
async fn removal_is_idempotent() {
    let (_root, blobs) = store().await;
    let id = ContentId::generate();
    blobs.remove(id).await.unwrap();
    assert!(
        blobs.remove(id).await.is_ok(),
        "повторное удаление отсутствующего содержимого отвергнуто"
    );
}

#[tokio::test]
async fn missing_content_is_reported() {
    let (_root, blobs) = store().await;
    assert!(
        blobs.get(ContentId::generate()).await.is_err(),
        "чтение отсутствующего содержимого прошло успешно"
    );
}

#[tokio::test]
async fn stored_file_stays_inside_root() {
    let (root, blobs) = store().await;
    let id = ContentId::generate();
    let payload = b"payload";
    blobs
        .put(id, payload, &hash(payload), size(payload))
        .await
        .unwrap();
    let entry = std::fs::read_dir(root.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let actual = std::fs::canonicalize(entry.path()).unwrap();
    assert!(
        actual.starts_with(blobs.root()),
        "файл оказался за пределами корня хранилища"
    );
}

#[tokio::test]
async fn file_name_does_not_contain_hash() {
    let (root, blobs) = store().await;
    let id = ContentId::generate();
    let payload = b"payload";
    let digest = hash(payload);
    blobs
        .put(id, payload, &digest, size(payload))
        .await
        .unwrap();
    let entry = std::fs::read_dir(root.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert!(
        !entry
            .file_name()
            .to_string_lossy()
            .contains(digest.as_str()),
        "имя файла выводится из присланного клиентом хеша"
    );
}
