//! Файл, его содержимое и выданный к нему доступ.
//!
//! Логический файл и физическое содержимое — разные сущности. Прежняя
//! реализация смешивала их в одном типе и именовала файл на диске хешем
//! содержимого, из-за чего файлы разных владельцев затирали друг друга.

use crate::error::{Error, Result};
use crate::hash::ContentHash;
use crate::id::{ContentId, DirectoryId, FileId, GrantId, LinkId, UserId};
use crate::quota::ByteSize;
use crate::rights::Rights;
use time::OffsetDateTime;

/// Физическое содержимое: шифротекст, лежащий в хранилище.
///
/// Хеш считается от шифротекста, а не от открытого текста (`TODO.md`,
/// раздел 2), поэтому дедупликация между пользователями невозможна и
/// содержимое принадлежит ровно одному файлу.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Content {
    id: ContentId,
    hash: ContentHash,
    size: ByteSize,
}

impl Content {
    /// Собирает описание содержимого.
    #[must_use]
    pub const fn new(id: ContentId, hash: ContentHash, size: ByteSize) -> Self {
        Self { id, hash, size }
    }

    /// Идентификатор содержимого.
    #[must_use]
    pub const fn id(&self) -> ContentId {
        self.id
    }

    /// Хеш шифротекста.
    #[must_use]
    pub const fn hash(&self) -> &ContentHash {
        &self.hash
    }

    /// Размер шифротекста.
    #[must_use]
    pub const fn size(&self) -> ByteSize {
        self.size
    }
}

/// Времена жизни файла.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamps {
    created: OffsetDateTime,
    modified: OffsetDateTime,
}

impl Stamps {
    /// Заводит времена для нового файла.
    #[must_use]
    pub const fn new(moment: OffsetDateTime) -> Self {
        Self {
            created: moment,
            modified: moment,
        }
    }

    /// Возвращает времена с отмеченным изменением.
    #[must_use]
    pub const fn touched(self, moment: OffsetDateTime) -> Self {
        Self {
            modified: moment,
            ..self
        }
    }

    /// Время создания.
    #[must_use]
    pub const fn created_at(self) -> OffsetDateTime {
        self.created
    }

    /// Время последнего изменения.
    #[must_use]
    pub const fn modified_at(self) -> OffsetDateTime {
        self.modified
    }
}

/// Техническая метаинформация файла.
///
/// Единственная категория, открытая серверу: он её и заполняет. Клиент
/// заявляет размер и хеш шифротекста при создании файла, а сервер сверяет их
/// при приёме содержимого (`TODO.md`, раздел 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Technical {
    content: Content,
    format: u8,
    stamps: Stamps,
}

impl Technical {
    /// Заводит техническую метаинформацию, проверяя версию формата.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedFormat`], если версия формата нулевая: формат
    /// шифрования начинается с первой версии.
    pub fn new(content: Content, format: u8, stamps: Stamps) -> Result<Self> {
        if format == 0 {
            return Err(Error::UnsupportedFormat);
        }
        Ok(Self {
            content,
            format,
            stamps,
        })
    }

    /// Возвращает метаинформацию с отмеченным изменением.
    #[must_use]
    pub fn touched(self, moment: OffsetDateTime) -> Self {
        Self {
            stamps: self.stamps.touched(moment),
            ..self
        }
    }

    /// Описание содержимого: идентификатор, хеш и размер шифротекста.
    #[must_use]
    pub const fn content(&self) -> &Content {
        &self.content
    }

    /// Версия формата шифрования содержимого.
    #[must_use]
    pub const fn format(&self) -> u8 {
        self.format
    }

    /// Времена создания и изменения.
    #[must_use]
    pub const fn stamps(&self) -> Stamps {
        self.stamps
    }
}

/// Зашифрованная метаинформация файла.
///
/// Две категории с разной видимостью защищены **разными ключами**, а не
/// проверкой прав: сервер физически не способен показать то, чего не может
/// расшифровать. Публичную разворачивает ключ метаданных файла — он же
/// оборачивается для каждого получателя; закрытую — ключ учётной записи
/// владельца, которого нет ни у кого другого (`TODO.md`, раздел 3).
///
/// Перевод сведения из закрытой категории в публичную — перешифрование на
/// клиенте, а не смена признака здесь. Обратный перевод конфиденциальности не
/// возвращает: получатели значение уже видели.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    public: Vec<u8>,
    private: Option<Vec<u8>>,
    revision: u64,
}

impl Metadata {
    /// Принимает метаинформацию, проверяя, что публичная часть не пуста.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyMetadata`], если публичная часть пуста: в ней лежит имя
    /// файла, и без неё получатель доступа не увидит даже названия.
    pub fn new(public: Vec<u8>, private: Option<Vec<u8>>) -> Result<Self> {
        if public.is_empty() {
            return Err(Error::EmptyMetadata);
        }
        Ok(Self {
            public,
            private,
            revision: 1,
        })
    }

    /// Возвращает метаинформацию с заменённой публичной частью.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyMetadata`], если новая публичная часть пуста.
    pub fn with_public(self, public: Vec<u8>) -> Result<Self> {
        if public.is_empty() {
            return Err(Error::EmptyMetadata);
        }
        Ok(Self {
            public,
            revision: self.revision + 1,
            ..self
        })
    }

    /// Возвращает метаинформацию с заменённой закрытой частью.
    #[must_use]
    pub fn with_private(self, private: Option<Vec<u8>>) -> Self {
        Self {
            private,
            revision: self.revision + 1,
            ..self
        }
    }

    /// Возвращает метаинформацию без закрытой части — для получателя доступа.
    ///
    /// Редакция при этом не меняется: сведения не переписаны, а лишь не
    /// показаны тому, кто и расшифровать их не смог бы.
    #[must_use]
    pub fn hidden(self) -> Self {
        Self {
            private: None,
            ..self
        }
    }

    /// Публичная часть: видна владельцу и всем, кому выдан доступ.
    #[must_use]
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// Закрытая часть: не передаётся никому, кроме владельца.
    #[must_use]
    pub fn private(&self) -> Option<&[u8]> {
        self.private.as_deref()
    }

    /// Номер редакции — им же условные запросы отличают версии.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// Ключ доступа: обёртки ключей для одного субъекта.
///
/// Ключ метаданных присутствует всегда, иначе получатель не увидит даже имени
/// файла. Ключ содержимого — только если выдано право читать содержимое
/// (`TODO.md`, раздел 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    subject: Subject,
    content: Option<Vec<u8>>,
    metadata: Vec<u8>,
}

impl Envelope {
    /// Собирает ключ доступа, проверяя, что ключ метаданных не пуст.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyEnvelope`], если обёртка ключа метаданных пуста: субъект
    /// без неё не увидит ничего и такой записи быть не должно.
    pub fn new(subject: Subject, content: Option<Vec<u8>>, metadata: Vec<u8>) -> Result<Self> {
        if metadata.is_empty() {
            return Err(Error::EmptyEnvelope);
        }
        Ok(Self {
            subject,
            content,
            metadata,
        })
    }

    /// Субъект, которому предназначены обёртки.
    #[must_use]
    pub const fn subject(&self) -> Subject {
        self.subject
    }

    /// Обёрнутый ключ содержимого, если право читать содержимое выдано.
    #[must_use]
    pub fn content(&self) -> Option<&[u8]> {
        self.content.as_deref()
    }

    /// Обёрнутый ключ метаданных.
    #[must_use]
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }
}

/// Логический файл.
///
/// Имени здесь нет намеренно: оно зашифровано и живёт в публичной
/// метаинформации, которой сервер не понимает.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct File {
    id: FileId,
    owner: UserId,
    directory: Option<DirectoryId>,
    content: Option<ContentId>,
}

impl File {
    /// Заводит файл без содержимого: оно загружается отдельным обращением.
    #[must_use]
    pub const fn new(id: FileId, owner: UserId, directory: Option<DirectoryId>) -> Self {
        Self {
            id,
            owner,
            directory,
            content: None,
        }
    }

    /// Возвращает файл с присоединённым содержимым.
    #[must_use]
    pub const fn with_content(self, content: ContentId) -> Self {
        Self {
            content: Some(content),
            ..self
        }
    }

    /// Возвращает файл, перемещённый в другую директорию.
    #[must_use]
    pub const fn moved_to(self, directory: Option<DirectoryId>) -> Self {
        Self { directory, ..self }
    }

    /// Идентификатор файла.
    #[must_use]
    pub const fn id(&self) -> FileId {
        self.id
    }

    /// Владелец файла.
    #[must_use]
    pub const fn owner(&self) -> UserId {
        self.owner
    }

    /// Директория, в которой лежит файл.
    #[must_use]
    pub const fn directory(&self) -> Option<DirectoryId> {
        self.directory
    }

    /// Присоединённое содержимое, если оно уже загружено.
    #[must_use]
    pub const fn content(&self) -> Option<ContentId> {
        self.content
    }
}

/// Тот, кому выдан доступ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Subject {
    /// Зарегистрированный пользователь.
    User(UserId),
    /// Публичная ссылка.
    Link(LinkId),
}

/// Выданный доступ к файлу.
///
/// Отзыв доступа запрещает новые обращения, но не отменяет знания ключа тем,
/// кто уже его развернул (`TODO.md`, раздел 1.5). Обещать иное запрещено.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    id: GrantId,
    file: FileId,
    subject: Subject,
    rights: Rights,
}

impl Grant {
    /// Собирает выданный доступ.
    #[must_use]
    pub const fn new(id: GrantId, file: FileId, subject: Subject, rights: Rights) -> Self {
        Self {
            id,
            file,
            subject,
            rights,
        }
    }

    /// Идентификатор выдачи.
    #[must_use]
    pub const fn id(&self) -> GrantId {
        self.id
    }

    /// Файл, к которому выдан доступ.
    #[must_use]
    pub const fn file(&self) -> FileId {
        self.file
    }

    /// Тот, кому выдан доступ.
    #[must_use]
    pub const fn subject(&self) -> Subject {
        self.subject
    }

    /// Выданные права.
    #[must_use]
    pub const fn rights(&self) -> Rights {
        self.rights
    }
}

/// Публичная ссылка на файл.
///
/// Ключ содержимого во ссылке не хранится: он передаётся во фрагменте адреса и
/// на сервер не попадает (`TODO.md`, раздел 4.10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    id: LinkId,
    file: FileId,
    rights: Rights,
    expires_at: Option<OffsetDateTime>,
}

impl Link {
    /// Собирает ссылку.
    #[must_use]
    pub const fn new(
        id: LinkId,
        file: FileId,
        rights: Rights,
        expires_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            id,
            file,
            rights,
            expires_at,
        }
    }

    /// Идентификатор ссылки.
    #[must_use]
    pub const fn id(&self) -> LinkId {
        self.id
    }

    /// Файл, на который указывает ссылка.
    #[must_use]
    pub const fn file(&self) -> FileId {
        self.file
    }

    /// Права, с которыми доступен файл по ссылке.
    #[must_use]
    pub const fn rights(&self) -> Rights {
        self.rights
    }

    /// Отвечает, истекла ли ссылка к указанному моменту.
    #[must_use]
    pub fn expired_at(&self, moment: OffsetDateTime) -> bool {
        self.expires_at.is_some_and(|deadline| moment >= deadline)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{Content, Envelope, File, Link, Metadata, Stamps, Subject, Technical};
    use crate::error::Error;
    use crate::hash::ContentHash;
    use crate::id::{ContentId, DirectoryId, FileId, LinkId, UserId};
    use crate::quota::ByteSize;
    use crate::rights::Rights;
    use time::{Duration, OffsetDateTime};

    fn file() -> File {
        File::new(FileId::generate(), UserId::generate(), None)
    }

    #[test]
    fn new_file_has_no_content() {
        assert!(
            file().content().is_none(),
            "только что заведённый файл уже имеет содержимое"
        );
    }

    #[test]
    fn attached_content_is_visible() {
        let content = ContentId::generate();
        assert_eq!(
            file().with_content(content).content(),
            Some(content),
            "присоединённое содержимое не видно в файле"
        );
    }

    #[test]
    fn moving_keeps_identity() {
        let subject = file();
        assert_eq!(
            subject.moved_to(Some(DirectoryId::generate())).id(),
            subject.id(),
            "перемещение изменило идентификатор файла"
        );
    }

    #[test]
    fn moving_changes_directory() {
        let directory = DirectoryId::generate();
        assert_eq!(
            file().moved_to(Some(directory)).directory(),
            Some(directory),
            "перемещение не изменило директорию"
        );
    }

    #[test]
    fn content_keeps_ciphertext_size() {
        let content = Content::new(
            ContentId::generate(),
            ContentHash::of(&[0; 32]),
            ByteSize::new(1024),
        );
        assert_eq!(
            content.size(),
            ByteSize::new(1024),
            "размер шифротекста искажён"
        );
    }

    #[test]
    fn link_without_deadline_never_expires() {
        let link = Link::new(
            LinkId::generate(),
            FileId::generate(),
            Rights::read_only(),
            None,
        );
        assert!(
            !link.expired_at(OffsetDateTime::UNIX_EPOCH + Duration::days(365 * 100)),
            "бессрочная ссылка признана истёкшей"
        );
    }

    #[test]
    fn link_past_deadline_is_expired() {
        let deadline = OffsetDateTime::UNIX_EPOCH + Duration::days(1);
        let link = Link::new(
            LinkId::generate(),
            FileId::generate(),
            Rights::read_only(),
            Some(deadline),
        );
        assert!(
            link.expired_at(deadline + Duration::seconds(1)),
            "ссылка за пределом срока не признана истёкшей"
        );
    }

    #[test]
    fn link_before_deadline_is_valid() {
        let deadline = OffsetDateTime::UNIX_EPOCH + Duration::days(1);
        let link = Link::new(
            LinkId::generate(),
            FileId::generate(),
            Rights::read_only(),
            Some(deadline),
        );
        assert!(
            !link.expired_at(deadline - Duration::seconds(1)),
            "действующая ссылка признана истёкшей"
        );
    }

    fn content() -> Content {
        Content::new(
            ContentId::generate(),
            ContentHash::new("a".repeat(64)).unwrap(),
            ByteSize::new(4096),
        )
    }

    fn stamps() -> Stamps {
        Stamps::new(OffsetDateTime::UNIX_EPOCH)
    }

    #[test]
    fn technical_metadata_keeps_the_format() {
        assert_eq!(
            Technical::new(content(), 1, stamps()).unwrap().format(),
            1,
            "версия формата шифрования искажена при создании"
        );
    }

    #[test]
    fn zero_format_is_rejected() {
        assert!(
            matches!(
                Technical::new(content(), 0, stamps()),
                Err(Error::UnsupportedFormat)
            ),
            "нулевая версия формата шифрования принята"
        );
    }

    #[test]
    fn touching_moves_the_modification_stamp() {
        let moment = OffsetDateTime::UNIX_EPOCH + Duration::hours(1);
        assert_eq!(
            Technical::new(content(), 1, stamps())
                .unwrap()
                .touched(moment)
                .stamps()
                .modified_at(),
            moment,
            "изменение не отмечено во временах файла"
        );
    }

    #[test]
    fn touching_keeps_the_creation_stamp() {
        assert_eq!(
            Technical::new(content(), 1, stamps())
                .unwrap()
                .touched(OffsetDateTime::UNIX_EPOCH + Duration::hours(1))
                .stamps()
                .created_at(),
            OffsetDateTime::UNIX_EPOCH,
            "изменение сдвинуло время создания файла"
        );
    }

    #[test]
    fn envelope_without_metadata_key_is_rejected() {
        assert!(
            matches!(
                Envelope::new(Subject::User(UserId::generate()), None, Vec::new()),
                Err(Error::EmptyEnvelope)
            ),
            "ключ доступа без обёртки ключа метаданных принят"
        );
    }

    #[test]
    fn envelope_without_content_key_is_allowed() {
        assert!(
            Envelope::new(Subject::User(UserId::generate()), None, vec![1; 72])
                .unwrap()
                .content()
                .is_none(),
            "ключ доступа без права читать содержимое всё же несёт ключ содержимого"
        );
    }

    #[test]
    fn envelope_keeps_its_content_key() {
        assert_eq!(
            Envelope::new(
                Subject::User(UserId::generate()),
                Some(vec![2; 72]),
                vec![1; 72]
            )
            .unwrap()
            .content(),
            Some(&[2_u8; 72][..]),
            "обёртка ключа содержимого искажена при создании"
        );
    }

    fn metadata() -> Metadata {
        Metadata::new(vec![1; 32], Some(vec![2; 32])).unwrap()
    }

    #[test]
    fn metadata_without_public_part_is_rejected() {
        assert!(
            matches!(
                Metadata::new(Vec::new(), Some(vec![2; 32])),
                Err(Error::EmptyMetadata)
            ),
            "метаинформация без публичной части принята: получатель не увидит имени"
        );
    }

    #[test]
    fn metadata_without_private_part_is_allowed() {
        assert!(
            Metadata::new(vec![1; 32], None)
                .unwrap()
                .private()
                .is_none(),
            "метаинформация без закрытой части всё же несёт закрытые сведения"
        );
    }

    #[test]
    fn fresh_metadata_starts_at_the_first_revision() {
        assert_eq!(
            metadata().revision(),
            1,
            "только что созданная метаинформация начата не с первой редакции"
        );
    }

    #[test]
    fn replacing_the_public_part_advances_the_revision() {
        assert_eq!(
            metadata().with_public(vec![3; 32]).unwrap().revision(),
            2,
            "замена публичной части не сдвинула редакцию"
        );
    }

    #[test]
    fn replacing_the_private_part_advances_the_revision() {
        assert_eq!(
            metadata().with_private(None).revision(),
            2,
            "замена закрытой части не сдвинула редакцию"
        );
    }

    #[test]
    fn replacing_the_public_part_keeps_the_private_one() {
        assert_eq!(
            metadata()
                .with_public(vec![3; 32])
                .unwrap()
                .private()
                .map(<[u8]>::to_vec),
            Some(vec![2; 32]),
            "замена публичной части затронула закрытую"
        );
    }

    #[test]
    fn replacing_the_private_part_keeps_the_public_one() {
        assert_eq!(
            metadata().with_private(Some(vec![4; 32])).public().to_vec(),
            vec![1; 32],
            "замена закрытой части затронула публичную"
        );
    }

    #[test]
    fn emptying_the_public_part_is_rejected() {
        assert!(
            matches!(
                metadata().with_public(Vec::new()),
                Err(Error::EmptyMetadata)
            ),
            "публичная часть опустошена заменой"
        );
    }
}
