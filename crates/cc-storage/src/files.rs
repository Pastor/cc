//! Хранилище файлов и их метаинформации.
//!
//! Здесь лежат метаданные, а шифротекст — в [`crate::Blobs`]: логический файл и
//! физическое содержимое разведены намеренно. Прежняя реализация смешивала их и
//! именовала содержимое хешем, отчего файлы разных владельцев затирали друг
//! друга.

use crate::error::{Error, Result};
use cc_domain::{
    ByteSize, Claimant, ContentId, Envelope, File, FileId, Grant, Metadata, Right, Subject,
    Technical, UserId,
};
use std::collections::HashMap;
use time::{Duration, OffsetDateTime};
use tokio::sync::RwLock;

/// Наибольшее число записей в одном ответе коллекции.
pub const PAGE_MAX: usize = 100;

/// Число записей в ответе коллекции по умолчанию.
pub const PAGE_DEFAULT: usize = 20;

/// Запись о файле: сам файл, его метаинформация и ключи доступа.
#[derive(Clone, Debug)]
struct Record {
    file: File,
    technical: Technical,
    metadata: Metadata,
    envelopes: Vec<Envelope>,
    discarded: Option<OffsetDateTime>,
}

/// Страница коллекции.
///
/// Курсор — идентификатор последней отданной записи: смещение сдвигается при
/// вставке и выдаёт одни записи дважды, а другие пропускает.
#[derive(Clone, Debug)]
pub struct Page {
    files: Vec<Listed>,
    next: Option<FileId>,
}

impl Page {
    /// Записи страницы.
    #[must_use]
    pub fn files(&self) -> &[Listed] {
        &self.files
    }

    /// Курсор следующей страницы, если она есть.
    #[must_use]
    pub const fn next(&self) -> Option<FileId> {
        self.next
    }
}

/// Файл в объёме, видимом заявителю.
///
/// Ключи доступа других субъектов сюда не попадают: в прежней реализации
/// список потоков отдавал наружу обёрнутый ключ и объект владельца.
#[derive(Clone, Debug)]
pub struct Listed {
    file: File,
    technical: Technical,
    metadata: Metadata,
    envelope: Option<Envelope>,
}

impl Listed {
    /// Файл.
    #[must_use]
    pub const fn file(&self) -> &File {
        &self.file
    }

    /// Техническая метаинформация.
    #[must_use]
    pub const fn technical(&self) -> &Technical {
        &self.technical
    }

    /// Метаинформация в объёме, видимом заявителю.
    ///
    /// Закрытая часть остаётся закрытой не потому, что здесь стоит проверка, а
    /// потому что зашифрована ключом учётной записи владельца. Проверка ниже
    /// лишь избавляет от бессмысленной пересылки.
    #[must_use]
    pub const fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Ключ доступа заявителя, если он у файла есть.
    #[must_use]
    pub const fn envelope(&self) -> Option<&Envelope> {
        self.envelope.as_ref()
    }
}

/// Окончательно стёртая запись.
///
/// Всё, что нужно вызывающему после стирания метаданных: чей был файл, какое
/// содержимое удалять и сколько квоты освободить.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Purged {
    owner: UserId,
    content: ContentId,
    size: ByteSize,
}

impl Purged {
    /// Владелец стёртого файла.
    #[must_use]
    pub const fn owner(&self) -> UserId {
        self.owner
    }

    /// Содержимое, подлежащее стиранию.
    #[must_use]
    pub const fn content(&self) -> ContentId {
        self.content
    }

    /// Освобождаемый объём.
    #[must_use]
    pub const fn size(&self) -> ByteSize {
        self.size
    }
}

/// Файлы, хранимые в памяти процесса.
///
/// Реализация временная: данные не переживают перезапуск. Постоянное хранилище
/// вводит TASK-018.
#[derive(Debug)]
pub struct Files {
    records: RwLock<HashMap<FileId, Record>>,
    trash: Duration,
}

impl Files {
    /// Заводит пустое хранилище с заданным сроком хранения в корзине.
    #[must_use]
    pub fn new(trash: Duration) -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            trash,
        }
    }

    /// Заводит файл вместе с ключом доступа владельца.
    ///
    /// Содержимое приходит отдельным обращением: сервер уже знает его размер и
    /// хеш и сверит их при приёме (`TODO.md`, раздел 4.6).
    #[tracing::instrument(skip_all, fields(file = %file.id(), owner = %file.owner()))]
    pub async fn create(
        &self,
        file: File,
        technical: Technical,
        metadata: Metadata,
        owner: Envelope,
    ) {
        let record = Record {
            file,
            technical,
            metadata,
            envelopes: vec![owner],
            discarded: None,
        };
        let mut records = self.records.write().await;
        records.insert(file.id(), record);
        drop(records);
    }

    /// Отдаёт файл в объёме прав заявителя.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`], если файла нет, он в корзине либо заявителю не
    /// виден: отсутствие доступа и отсутствие файла неразличимы.
    pub async fn one(&self, claimant: &Claimant, id: FileId, grants: &[Grant]) -> Result<Listed> {
        let records = self.records.read().await;
        let found = records.get(&id).filter(|record| record.discarded.is_none());
        let listed = found.and_then(|record| listed(record, claimant, grants));
        drop(records);
        listed.ok_or(Error::Missing)
    }

    /// Отдаёт страницу коллекции файлов, видимых заявителю.
    ///
    /// Порядок устойчив: записи упорядочены по времени создания, а при
    /// совпадении — по идентификатору.
    pub async fn all(
        &self,
        claimant: &Claimant,
        grants: &[Grant],
        after: Option<FileId>,
        limit: usize,
    ) -> Page {
        let limit = limit.clamp(1, PAGE_MAX);
        let records = self.records.read().await;
        let mut visible: Vec<Listed> = records
            .values()
            .filter(|record| record.discarded.is_none())
            .filter_map(|record| listed(record, claimant, grants))
            .collect();
        drop(records);
        visible.sort_by(|left, right| {
            left.technical
                .stamps()
                .created_at()
                .cmp(&right.technical.stamps().created_at())
                .then_with(|| left.file.id().to_string().cmp(&right.file.id().to_string()))
        });
        let start = after.map_or(0, |cursor| {
            visible
                .iter()
                .position(|listed| listed.file.id() == cursor)
                .map_or(0, |at| at + 1)
        });
        let mut files: Vec<Listed> = visible.into_iter().skip(start).take(limit + 1).collect();
        let next = (files.len() > limit).then(|| {
            files.truncate(limit);
            files.last().map(|listed| listed.file.id())
        });
        Page {
            files,
            next: next.flatten(),
        }
    }

    /// Заменяет публичную метаинформацию.
    ///
    /// Шифротекста содержимого операция не касается: метаинформация живёт
    /// отдельно (`TODO.md`, раздел 4.6, пункт 8).
    ///
    /// # Errors
    ///
    /// - [`Error::Missing`] — файла нет, он в корзине либо записывать в него
    ///   заявителю не разрешено;
    /// - [`Error::Stale`] — предъявленная редакция разошлась с текущей: чужое
    ///   изменение затирать нельзя;
    /// - [`Error::Domain`] — публичная часть пуста.
    pub async fn publish(
        &self,
        claimant: &Claimant,
        id: FileId,
        grants: &[Grant],
        public: Vec<u8>,
        expected: u64,
    ) -> Result<u64> {
        self.rewrite(claimant, id, grants, expected, false, |metadata| {
            metadata.with_public(public).map_err(Error::Domain)
        })
        .await
    }

    /// Заменяет закрытую метаинформацию.
    ///
    /// Только владелец: закрытая часть зашифрована ключом его учётной записи, и
    /// никому другому её ни прочитать, ни осмысленно переписать.
    ///
    /// # Errors
    ///
    /// - [`Error::Missing`] — файла нет, он в корзине либо заявитель не
    ///   владелец;
    /// - [`Error::Stale`] — предъявленная редакция разошлась с текущей.
    pub async fn conceal(
        &self,
        claimant: &Claimant,
        id: FileId,
        private: Option<Vec<u8>>,
        expected: u64,
    ) -> Result<u64> {
        self.rewrite(claimant, id, &[], expected, true, move |metadata| {
            Ok(metadata.with_private(private))
        })
        .await
    }

    /// Заменяет метаинформацию под проверкой редакции.
    async fn rewrite(
        &self,
        claimant: &Claimant,
        id: FileId,
        grants: &[Grant],
        expected: u64,
        owner_only: bool,
        change: impl FnOnce(Metadata) -> Result<Metadata>,
    ) -> Result<u64> {
        let mut records = self.records.write().await;
        let outcome = match records.get_mut(&id) {
            Some(record) if record.discarded.is_none() => {
                rewritten(record, claimant, grants, expected, owner_only, change)
            }
            _ => Err(Error::Missing),
        };
        drop(records);
        outcome
    }

    /// Присоединяет загруженное содержимое, отмечая изменение.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`], если файла нет либо он в корзине.
    pub async fn attach(&self, id: FileId, moment: OffsetDateTime) -> Result<()> {
        let mut records = self.records.write().await;
        let outcome = match records.get_mut(&id) {
            Some(record) if record.discarded.is_none() => {
                record.file = record.file.with_content(record.technical.content().id());
                record.technical = record.technical.clone().touched(moment);
                Ok(())
            }
            _ => Err(Error::Missing),
        };
        drop(records);
        outcome
    }

    /// Помещает файл в корзину.
    ///
    /// Окончательно стирает его [`Files::purge`] по истечении срока: до тех пор
    /// содержимое остаётся на месте (`TODO.md`, раздел 4.12).
    ///
    /// # Errors
    ///
    /// [`Error::Missing`], если файла нет, он уже в корзине либо заявителю не
    /// разрешено его удалять.
    #[tracing::instrument(skip(self, claimant, grants), fields(file = %id), err)]
    pub async fn discard(
        &self,
        claimant: &Claimant,
        id: FileId,
        grants: &[Grant],
        moment: OffsetDateTime,
    ) -> Result<()> {
        let mut records = self.records.write().await;
        let outcome = match records.get_mut(&id) {
            Some(record) if record.discarded.is_none() => {
                cc_domain::permit(claimant, &record.file, grants, Right::Delete)
                    .map_err(|_| Error::Missing)?;
                record.discarded = Some(moment);
                Ok(())
            }
            _ => Err(Error::Missing),
        };
        drop(records);
        outcome
    }

    /// Стирает записи, пережившие срок корзины, и отдаёт их содержимое.
    ///
    /// Шифротекст удаляет вызывающий: хранилище метаданных о файловой системе
    /// не знает. Квота освобождается здесь же — в момент окончательного
    /// удаления, а не при помещении в корзину.
    pub async fn purge(&self, now: OffsetDateTime) -> Vec<Purged> {
        let horizon = now - self.trash;
        let mut records = self.records.write().await;
        let expired: Vec<FileId> = records
            .iter()
            .filter(|(_, record)| record.discarded.is_some_and(|at| at <= horizon))
            .map(|(id, _)| *id)
            .collect();
        let purged = expired
            .iter()
            .filter_map(|id| records.remove(id))
            .map(|record| Purged {
                owner: record.file.owner(),
                content: record.technical.content().id(),
                size: record.technical.content().size(),
            })
            .collect();
        drop(records);
        purged
    }
}

impl Files {
    /// Убирает корзину по расписанию, стирая содержимое вместе с записями.
    ///
    /// Шифротекст стирается здесь же: запись без содержимого оставила бы
    /// занятое место, о котором никто больше не знает.
    #[must_use]
    pub fn sweeper(
        files: std::sync::Arc<Self>,
        blobs: std::sync::Arc<crate::Blobs>,
        period: Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let period = period
            .try_into()
            .unwrap_or(core::time::Duration::from_secs(3600));
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(period);
            loop {
                tokio::select! {
                    _ = ticks.tick() => {
                        for purged in files.purge(OffsetDateTime::now_utc()).await {
                            if let Err(failure) = blobs.remove(purged.content()).await {
                                tracing::warn!(
                                    error = %failure,
                                    content = %purged.content(),
                                    "содержимое из корзины не стёрлось"
                                );
                            }
                        }
                    }
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        })
    }
}

/// Собирает представление записи для заявителя, если она ему видна.
fn listed(record: &Record, claimant: &Claimant, grants: &[Grant]) -> Option<Listed> {
    if !cc_domain::visible(claimant, &record.file, grants) {
        return None;
    }
    let envelope = record
        .envelopes
        .iter()
        .find(|envelope| envelope.subject() == claimant.subject())
        .cloned();
    let owns = claimant.subject() == Subject::User(record.file.owner());
    let metadata = if owns {
        record.metadata.clone()
    } else {
        record.metadata.clone().hidden()
    };
    Some(Listed {
        file: record.file,
        technical: record.technical.clone(),
        metadata,
        envelope,
    })
}

/// Заменяет метаинформацию записи, проверив права и редакцию.
fn rewritten(
    record: &mut Record,
    claimant: &Claimant,
    grants: &[Grant],
    expected: u64,
    owner_only: bool,
    change: impl FnOnce(Metadata) -> Result<Metadata>,
) -> Result<u64> {
    if owner_only && claimant.subject() != Subject::User(record.file.owner()) {
        return Err(Error::Missing);
    }
    cc_domain::permit(claimant, &record.file, grants, Right::Write).map_err(|_| Error::Missing)?;
    if record.metadata.revision() != expected {
        return Err(Error::Stale);
    }
    let changed = change(record.metadata.clone())?;
    let revision = changed.revision();
    record.metadata = changed;
    Ok(revision)
}

/// Владелец файла как субъект доступа.
#[must_use]
pub const fn owner(user: UserId) -> Subject {
    Subject::User(user)
}
