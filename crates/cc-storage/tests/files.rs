//! Сценарии хранилища файлов.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
)]

use cc_domain::{
    ByteSize, Claimant, Content, ContentHash, ContentId, Envelope, File, FileId, Grant, GrantId,
    Rights, Stamps, Subject, Technical, UserId,
};
use cc_storage::{Error, Files};
use time::{Duration, OffsetDateTime};

const fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

fn files() -> Files {
    Files::new(Duration::days(30))
}

fn hash(fill: &str) -> ContentHash {
    ContentHash::new(fill.repeat(64)).unwrap()
}

fn technical(fill: &str, at: OffsetDateTime) -> Technical {
    Technical::new(
        Content::new(ContentId::generate(), hash(fill), ByteSize::new(4096)),
        1,
        Stamps::new(at),
    )
    .unwrap()
}

fn envelope(subject: Subject) -> Envelope {
    Envelope::new(subject, Some(vec![2; 72]), vec![1; 72]).unwrap()
}

const fn claimant(user: UserId) -> Claimant {
    Claimant::new(Subject::User(user), Rights::all())
}

async fn created(store: &Files, owner: UserId, fill: &str, at: OffsetDateTime) -> FileId {
    let created = File::new(FileId::generate(), owner, None);
    store
        .create(created, technical(fill, at), envelope(Subject::User(owner)))
        .await;
    created.id()
}

#[tokio::test]
async fn created_file_is_found_by_its_owner() {
    let store = files();
    let owner = UserId::generate();
    let id = created(&store, owner, "a", now()).await;
    assert_eq!(
        store
            .one(&claimant(owner), id, &[])
            .await
            .unwrap()
            .file()
            .id(),
        id,
        "заведённый файл не нашёлся у своего владельца"
    );
}

#[tokio::test]
async fn foreign_file_is_missing() {
    let store = files();
    let id = created(&store, UserId::generate(), "a", now()).await;
    assert!(
        matches!(
            store.one(&claimant(UserId::generate()), id, &[]).await,
            Err(Error::Missing)
        ),
        "чужой файл виден постороннему"
    );
}

#[tokio::test]
async fn granted_file_is_visible_to_its_subject() {
    let store = files();
    let owner = UserId::generate();
    let guest = UserId::generate();
    let id = created(&store, owner, "a", now()).await;
    let grant = Grant::new(
        GrantId::generate(),
        id,
        Subject::User(guest),
        Rights::read_only(),
    );
    assert_eq!(
        store
            .one(&claimant(guest), id, &[grant])
            .await
            .unwrap()
            .file()
            .id(),
        id,
        "файл с выданным доступом не виден получателю"
    );
}

#[tokio::test]
async fn foreign_envelope_stays_hidden() {
    let store = files();
    let owner = UserId::generate();
    let guest = UserId::generate();
    let id = created(&store, owner, "a", now()).await;
    let grant = Grant::new(
        GrantId::generate(),
        id,
        Subject::User(guest),
        Rights::read_only(),
    );
    assert!(
        store
            .one(&claimant(guest), id, &[grant])
            .await
            .unwrap()
            .envelope()
            .is_none(),
        "получателю виден ключ доступа, выданный владельцу"
    );
}

#[tokio::test]
async fn owner_sees_their_own_envelope() {
    let store = files();
    let owner = UserId::generate();
    let id = created(&store, owner, "a", now()).await;
    assert!(
        store
            .one(&claimant(owner), id, &[])
            .await
            .unwrap()
            .envelope()
            .is_some(),
        "владелец не видит собственного ключа доступа"
    );
}

#[tokio::test]
async fn collection_lists_only_visible_files() {
    let store = files();
    let owner = UserId::generate();
    created(&store, owner, "a", now()).await;
    created(&store, UserId::generate(), "b", now()).await;
    assert_eq!(
        store
            .all(&claimant(owner), &[], None, 10)
            .await
            .files()
            .len(),
        1,
        "в коллекции оказался чужой файл"
    );
}

#[tokio::test]
async fn collection_is_ordered_by_creation() {
    let store = files();
    let owner = UserId::generate();
    let first = created(&store, owner, "a", now()).await;
    created(&store, owner, "b", now() + Duration::minutes(1)).await;
    let page = store.all(&claimant(owner), &[], None, 10).await;
    assert_eq!(
        page.files().first().unwrap().file().id(),
        first,
        "коллекция отдана не в порядке создания"
    );
}

#[tokio::test]
async fn page_reports_the_next_cursor() {
    let store = files();
    let owner = UserId::generate();
    created(&store, owner, "a", now()).await;
    created(&store, owner, "b", now() + Duration::minutes(1)).await;
    assert!(
        store
            .all(&claimant(owner), &[], None, 1)
            .await
            .next()
            .is_some(),
        "страница не сообщила курсор следующей"
    );
}

#[tokio::test]
async fn cursor_continues_the_collection() {
    let store = files();
    let owner = UserId::generate();
    created(&store, owner, "a", now()).await;
    let second = created(&store, owner, "b", now() + Duration::minutes(1)).await;
    let first = store.all(&claimant(owner), &[], None, 1).await;
    let page = store.all(&claimant(owner), &[], first.next(), 1).await;
    assert_eq!(
        page.files().first().unwrap().file().id(),
        second,
        "продолжение коллекции по курсору отдало не ту запись"
    );
}

#[tokio::test]
async fn last_page_reports_no_cursor() {
    let store = files();
    let owner = UserId::generate();
    created(&store, owner, "a", now()).await;
    assert!(
        store
            .all(&claimant(owner), &[], None, 10)
            .await
            .next()
            .is_none(),
        "последняя страница сообщила курсор следующей"
    );
}

#[tokio::test]
async fn attached_content_is_recorded() {
    let store = files();
    let owner = UserId::generate();
    let id = created(&store, owner, "a", now()).await;
    store.attach(id, now()).await.unwrap();
    assert!(
        store
            .one(&claimant(owner), id, &[])
            .await
            .unwrap()
            .file()
            .content()
            .is_some(),
        "загруженное содержимое не присоединилось к файлу"
    );
}

#[tokio::test]
async fn attaching_marks_the_modification() {
    let store = files();
    let owner = UserId::generate();
    let id = created(&store, owner, "a", now()).await;
    let moment = now() + Duration::hours(1);
    store.attach(id, moment).await.unwrap();
    assert_eq!(
        store
            .one(&claimant(owner), id, &[])
            .await
            .unwrap()
            .technical()
            .stamps()
            .modified_at(),
        moment,
        "загрузка содержимого не отметилась во временах файла"
    );
}

#[tokio::test]
async fn discarded_file_leaves_the_collection() {
    let store = files();
    let owner = UserId::generate();
    let id = created(&store, owner, "a", now()).await;
    store
        .discard(&claimant(owner), id, &[], now())
        .await
        .unwrap();
    assert!(
        store
            .all(&claimant(owner), &[], None, 10)
            .await
            .files()
            .is_empty(),
        "файл в корзине остался в коллекции"
    );
}

#[tokio::test]
async fn discarding_requires_the_right() {
    let store = files();
    let owner = UserId::generate();
    let id = created(&store, owner, "a", now()).await;
    assert!(
        matches!(
            store
                .discard(&claimant(UserId::generate()), id, &[], now())
                .await,
            Err(Error::Missing)
        ),
        "чужой файл удалён посторонним"
    );
}

#[tokio::test]
async fn purging_keeps_files_inside_the_term() {
    let store = files();
    let owner = UserId::generate();
    let id = created(&store, owner, "a", now()).await;
    store
        .discard(&claimant(owner), id, &[], now())
        .await
        .unwrap();
    assert!(
        store.purge(now() + Duration::days(29)).await.is_empty(),
        "файл стёрт раньше срока корзины"
    );
}

#[tokio::test]
async fn purging_removes_files_past_the_term() {
    let store = files();
    let owner = UserId::generate();
    let id = created(&store, owner, "a", now()).await;
    store
        .discard(&claimant(owner), id, &[], now())
        .await
        .unwrap();
    assert_eq!(
        store.purge(now() + Duration::days(31)).await.len(),
        1,
        "файл пережил срок корзины"
    );
}

#[tokio::test]
async fn purging_reports_the_freed_size() {
    let store = files();
    let owner = UserId::generate();
    let id = created(&store, owner, "a", now()).await;
    store
        .discard(&claimant(owner), id, &[], now())
        .await
        .unwrap();
    let purged = store.purge(now() + Duration::days(31)).await;
    assert_eq!(
        purged.first().unwrap().size().get(),
        4096,
        "уборка корзины не сообщила освобождаемый объём"
    );
}

#[tokio::test]
async fn purging_spares_live_files() {
    let store = files();
    let owner = UserId::generate();
    created(&store, owner, "a", now()).await;
    store.purge(now() + Duration::days(31)).await;
    assert_eq!(
        store
            .all(&claimant(owner), &[], None, 10)
            .await
            .files()
            .len(),
        1,
        "уборка корзины стёрла не удалённый файл"
    );
}
