//! Проверка доступа к файлу.
//!
//! Проверка живёт в предметной области, а не в обработчике маршрута: обработчик
//! не должен уметь её пропустить. Прежняя реализация проверяла владельца только
//! при удалении и при выдаче доступа, отчего любой аутентифицированный
//! пользователь мог записать содержимое в чужой файл.

use crate::error::{Error, Result};
use crate::file::{File, Grant, Subject};
use crate::rights::{Right, Rights};

/// Заявитель: тот, от чьего имени выполняется операция.
///
/// Права сессии и права на файл — разные вещи. Прежняя реализация их смешивала,
/// сверяя набор действий сессии там, где следовало проверять права на ресурс.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claimant {
    subject: Subject,
    session: Rights,
}

impl Claimant {
    /// Собирает заявителя из субъекта и прав его сессии.
    #[must_use]
    pub const fn new(subject: Subject, session: Rights) -> Self {
        Self { subject, session }
    }

    /// Субъект.
    #[must_use]
    pub const fn subject(&self) -> Subject {
        self.subject
    }

    /// Права сессии.
    #[must_use]
    pub const fn session(&self) -> Rights {
        self.session
    }
}

/// Права заявителя на конкретный файл.
///
/// Владелец имеет все права; получатель — те, что ему выданы. И те и другие
/// дополнительно ограничены правами сессии: сессия, открытая с урезанным
/// набором, не может больше, чем запрошено при входе.
#[must_use]
pub fn rights(claimant: &Claimant, file: &File, grants: &[Grant]) -> Rights {
    let granted = match claimant.subject() {
        Subject::User(user) if user == file.owner() => Rights::all(),
        subject => grants
            .iter()
            .filter(|grant| grant.file() == file.id() && grant.subject() == subject)
            .fold(Rights::none(), |sum, grant| {
                grant.rights().iter().fold(sum, Rights::with)
            }),
    };
    granted
        .iter()
        .filter(|right| claimant.session().allows(*right))
        .collect()
}

/// Проверяет, что заявителю разрешена операция над файлом.
///
/// # Errors
///
/// [`Error::AccessDenied`], если права нет. Отсутствие доступа и отсутствие
/// файла для заявителя неразличимы: иначе ответ подтверждает существование
/// чужого ресурса.
pub fn permit(claimant: &Claimant, file: &File, grants: &[Grant], right: Right) -> Result<()> {
    if rights(claimant, file, grants).allows(right) {
        return Ok(());
    }
    Err(Error::AccessDenied)
}

/// Отвечает, виден ли файл заявителю вообще.
///
/// Файл виден, если есть хотя бы одно право на него.
#[must_use]
pub fn visible(claimant: &Claimant, file: &File, grants: &[Grant]) -> bool {
    !rights(claimant, file, grants).is_empty()
}

/// Проверяет право владельца выдать доступ с указанными правами.
///
/// # Errors
///
/// - [`Error::AccessDenied`] — у заявителя нет права выдавать доступ;
/// - [`Error::RightsEscalation`] — выдаваемые права шире собственных.
pub fn permit_grant(
    claimant: &Claimant,
    file: &File,
    grants: &[Grant],
    requested: Rights,
) -> Result<Rights> {
    let own = rights(claimant, file, grants);
    if !own.allows(Right::Grant) {
        return Err(Error::AccessDenied);
    }
    requested.granted_by(own)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use super::{permit, permit_grant, rights, visible, Claimant};
    use crate::file::{File, Grant, Subject};
    use crate::id::{FileId, GrantId, UserId};
    use crate::rights::{Right, Rights};

    fn owner() -> UserId {
        UserId::generate()
    }

    fn file(owner: UserId) -> File {
        File::new(FileId::generate(), owner, None)
    }

    fn claimant(user: UserId) -> Claimant {
        Claimant::new(Subject::User(user), Rights::all())
    }

    #[test]
    fn owner_has_every_right() {
        let owner = owner();
        assert_eq!(
            rights(&claimant(owner), &file(owner), &[]),
            Rights::all(),
            "владелец получил не все права на свой файл"
        );
    }

    #[test]
    fn stranger_has_no_rights() {
        let subject = file(owner());
        assert_eq!(
            rights(&claimant(owner()), &subject, &[]),
            Rights::none(),
            "посторонний получил права на чужой файл"
        );
    }

    #[test]
    fn stranger_does_not_see_the_file() {
        let subject = file(owner());
        assert!(
            !visible(&claimant(owner()), &subject, &[]),
            "чужой файл виден постороннему: его существование раскрыто"
        );
    }

    #[test]
    fn stranger_cannot_write_content() {
        let subject = file(owner());
        assert!(
            permit(&claimant(owner()), &subject, &[], Right::Write).is_err(),
            "посторонний допущен к записи содержимого чужого файла"
        );
    }

    #[test]
    fn grantee_gets_granted_rights() {
        let subject = file(owner());
        let user = owner();
        let grant = Grant::new(
            GrantId::generate(),
            subject.id(),
            Subject::User(user),
            Rights::read_only(),
        );
        assert_eq!(
            rights(&claimant(user), &subject, &[grant]),
            Rights::read_only(),
            "получателю достался не тот набор прав, что был выдан"
        );
    }

    #[test]
    fn grant_for_another_file_does_not_apply() {
        let subject = file(owner());
        let user = owner();
        let grant = Grant::new(
            GrantId::generate(),
            FileId::generate(),
            Subject::User(user),
            Rights::all(),
        );
        assert!(
            !visible(&claimant(user), &subject, &[grant]),
            "выдача доступа к одному файлу открыла другой"
        );
    }

    #[test]
    fn session_rights_narrow_file_rights() {
        let owner = owner();
        let limited = Claimant::new(Subject::User(owner), Rights::read_only());
        assert_eq!(
            rights(&limited, &file(owner), &[]),
            Rights::read_only(),
            "урезанная сессия дала владельцу больше, чем запрошено при входе"
        );
    }

    #[test]
    fn grantee_without_grant_right_cannot_pass_it_on() {
        let subject = file(owner());
        let user = owner();
        let grant = Grant::new(
            GrantId::generate(),
            subject.id(),
            Subject::User(user),
            Rights::read_only(),
        );
        assert!(
            permit_grant(&claimant(user), &subject, &[grant], Rights::read_only()).is_err(),
            "получатель без права выдачи передал файл дальше"
        );
    }

    #[test]
    fn grantee_with_grant_right_passes_on_within_own_rights() {
        let subject = file(owner());
        let user = owner();
        let held = Rights::read_only().with(Right::Grant);
        let grant = Grant::new(GrantId::generate(), subject.id(), Subject::User(user), held);
        assert!(
            permit_grant(&claimant(user), &subject, &[grant], Rights::read_only()).is_ok(),
            "получатель с правом выдачи не смог передать файл дальше"
        );
    }

    #[test]
    fn granting_beyond_own_rights_is_rejected() {
        let subject = file(owner());
        let user = owner();
        let held = Rights::read_only().with(Right::Grant);
        let grant = Grant::new(GrantId::generate(), subject.id(), Subject::User(user), held);
        assert!(
            permit_grant(&claimant(user), &subject, &[grant], Rights::all()).is_err(),
            "получатель выдал права шире собственных"
        );
    }

    #[test]
    fn owner_may_grant_everything() {
        let owner = owner();
        assert!(
            permit_grant(&claimant(owner), &file(owner), &[], Rights::all()).is_ok(),
            "владелец не смог выдать полный набор прав"
        );
    }
}
