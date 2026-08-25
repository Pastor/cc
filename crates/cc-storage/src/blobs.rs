//! Хранилище шифротекста.
//!
//! Сервер принимает уже зашифрованный поток и не расшифровывает его никогда.
//! Путь выводится из идентификатора содержимого: хеш, присланный клиентом, в
//! построении пути не участвует вовсе — именно так в прежней реализации
//! появлялась подстановка пути.

use crate::error::{Error, Result};
use cc_crypto::CiphertextHash;
use cc_domain::{ByteSize, ContentHash, ContentId};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

/// Хранилище шифротекста на файловой системе.
#[derive(Debug)]
pub struct Blobs {
    root: PathBuf,
}

impl Blobs {
    /// Открывает хранилище в указанном корне.
    ///
    /// Корень задаётся конфигурацией. Прежняя реализация молча создавала каталог
    /// в текущем рабочем каталоге процесса, отчего расположение данных зависело
    /// от того, откуда запущен сервер.
    ///
    /// # Errors
    ///
    /// [`Error::Io`], если каталог не удалось создать или он недоступен.
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).await?;
        let root = fs::canonicalize(&root).await?;
        Ok(Self { root })
    }

    /// Записывает шифротекст, сверяя его с заявленными размером и хешем.
    ///
    /// Расхождение — отклонение и удаление записанного: незавершённая загрузка
    /// не должна занимать квоту.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] — отказ файловой системы;
    /// - [`Error::ContentMismatch`] — размер или хеш не совпали с заявленными;
    /// - [`Error::PathEscape`] — построенный путь выходит за пределы корня.
    pub async fn put(
        &self,
        id: ContentId,
        ciphertext: &[u8],
        expected: &ContentHash,
        size: ByteSize,
    ) -> Result<()> {
        let actual = CiphertextHash::of(ciphertext);
        let computed = ContentHash::of(actual.as_bytes());
        if computed != *expected || ciphertext.len() as u64 != size.get() {
            return Err(Error::ContentMismatch);
        }
        let path = self.path(id)?;
        let mut file = fs::File::create(&path).await?;
        match file.write_all(ciphertext).await {
            Ok(()) => file.sync_all().await?,
            Err(source) => {
                drop(file);
                let _ = fs::remove_file(&path).await;
                return Err(Error::Io(source));
            }
        }
        Ok(())
    }

    /// Читает шифротекст целиком.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`], если содержимого нет, и [`Error::Io`] при отказе
    /// файловой системы.
    pub async fn get(&self, id: ContentId) -> Result<Vec<u8>> {
        let path = self.path(id)?;
        fs::read(&path).await.map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                Error::Missing
            } else {
                Error::Io(source)
            }
        })
    }

    /// Читает отрезок шифротекста — для докачки по диапазону.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`], если содержимого нет, и [`Error::Io`] при отказе
    /// файловой системы. Отрезок за пределами файла возвращается усечённым.
    pub async fn range(&self, id: ContentId, offset: u64, length: usize) -> Result<Vec<u8>> {
        let path = self.path(id)?;
        let mut file = fs::File::open(&path).await.map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                Error::Missing
            } else {
                Error::Io(source)
            }
        })?;
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let mut buffer = vec![0_u8; length];
        let read = file.read(&mut buffer).await?;
        buffer.truncate(read);
        Ok(buffer)
    }

    /// Удаляет шифротекст окончательно.
    ///
    /// Повторное удаление успешно: операция идемпотентна.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] при отказе файловой системы.
    pub async fn remove(&self, id: ContentId) -> Result<()> {
        let path = self.path(id)?;
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(Error::Io(source)),
        }
    }

    /// Отвечает, есть ли содержимое в хранилище.
    ///
    /// # Errors
    ///
    /// [`Error::PathEscape`], если построенный путь выходит за пределы корня.
    pub async fn contains(&self, id: ContentId) -> Result<bool> {
        Ok(fs::try_exists(self.path(id)?).await.unwrap_or(false))
    }

    /// Строит путь к содержимому и проверяет, что он лежит внутри корня.
    ///
    /// Проверка избыточна, пока путь выводится из идентификатора: `Uuid`
    /// печатается шестнадцатеричными цифрами и дефисами. Она оставлена потому,
    /// что стоит дёшево, а её отсутствие в прежней реализации стоило дорого.
    fn path(&self, id: ContentId) -> Result<PathBuf> {
        let name = id.to_string();
        if name.contains(['/', '\\', '.']) {
            return Err(Error::PathEscape);
        }
        let path = self.root.join(name);
        if !path.starts_with(&self.root) {
            return Err(Error::PathEscape);
        }
        Ok(path)
    }

    /// Корень хранилища.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}
