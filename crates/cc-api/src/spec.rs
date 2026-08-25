//! Спецификация `OpenAPI`.
//!
//! Документ строится из тех же объявлений, что и маршруты: описание, разошедшееся
//! с реализацией, здесь невозможно по построению. Рукописная спецификация такого
//! свойства не имеет, поэтому `CLAUDE.md` её и запрещает.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

/// Корень спецификации.
#[derive(Debug, OpenApi)]
#[openapi(
    info(
        title = "cstorage",
        description = "Криптографическое файловое хранилище. Сервер хранит только \
                       шифротекст и обёрнутые ключи: расшифровать содержимое он не \
                       может ни в покое, ни во время работы.",
        version = "1",
    ),
    tags(
        (name = "users", description = "Учётные записи"),
        (name = "sessions", description = "Сессии"),
        (name = "files", description = "Файлы"),
        (name = "service", description = "Служебные маршруты вне версионирования"),
    ),
    modifiers(&Bearer),
)]
pub struct Spec;

/// Объявляет способ аутентификации: токен в заголовке.
#[derive(Debug)]
struct Bearer;

impl Modify for Bearer {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let Some(components) = openapi.components.as_mut() else {
            return;
        };
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some("Сессионный токен в записи Base64"))
                    .build(),
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "в тесте отказ обязан ронять тест, а не обрабатываться"
    )]

    use crate::router::describe;
    use utoipa::openapi::path::{Operation, PathItem};

    /// Собирает спецификацию так же, как это делает приложение.
    fn document() -> utoipa::openapi::OpenApi {
        describe()
    }

    /// Перечисляет операции элемента пути вместе с их методами.
    fn operations(item: &PathItem) -> Vec<(&'static str, &Operation)> {
        [
            ("GET", item.get.as_ref()),
            ("PUT", item.put.as_ref()),
            ("POST", item.post.as_ref()),
            ("DELETE", item.delete.as_ref()),
            ("PATCH", item.patch.as_ref()),
        ]
        .into_iter()
        .filter_map(|(method, operation)| operation.map(|operation| (method, operation)))
        .collect()
    }

    /// Собирает пути и методы, не удовлетворяющие условию.
    fn offending(
        document: &utoipa::openapi::OpenApi,
        acceptable: impl Fn(&str, &Operation) -> bool,
    ) -> Vec<String> {
        document
            .paths
            .paths
            .iter()
            .flat_map(|(path, item)| {
                operations(item)
                    .into_iter()
                    .filter(|(_, operation)| !acceptable(path, operation))
                    .map(|(method, _)| format!("{method} {path}"))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn every_operation_is_described() {
        assert!(
            offending(&document(), |_, operation| {
                operation.description.is_some() || operation.summary.is_some()
            })
            .is_empty(),
            "в спецификации есть операции без описания"
        );
    }

    #[test]
    fn every_operation_lists_responses() {
        assert!(
            offending(&document(), |_, operation| {
                !operation.responses.responses.is_empty()
            })
            .is_empty(),
            "в спецификации есть операции без кодов ответов"
        );
    }

    #[test]
    fn versioned_operations_declare_the_version_header() {
        assert!(
            offending(&document(), |path, operation| {
                if !path.starts_with("/api/") {
                    return true;
                }
                operation.parameters.as_ref().is_some_and(|parameters| {
                    parameters
                        .iter()
                        .any(|parameter| parameter.name == "API-Version")
                })
            })
            .is_empty(),
            "версионируемые операции не объявляют заголовка версии"
        );
    }

    #[test]
    fn document_declares_the_authentication_scheme() {
        assert!(
            document()
                .components
                .is_some_and(|components| components.security_schemes.contains_key("bearer")),
            "спецификация не объявляет способа аутентификации"
        );
    }

    #[test]
    fn document_serialises_to_json() {
        assert!(
            serde_json::to_string(&document()).is_ok(),
            "спецификация не сериализуется"
        );
    }

    #[test]
    fn document_covers_every_versioned_route() {
        let document = document();
        let expected = [
            "/api/users",
            "/api/users/me",
            "/api/users/{login}/public-key",
            "/api/users/{login}/prelude",
            "/api/sessions",
            "/api/sessions/current",
            "/api/sessions/{id}",
        ];
        let missing: Vec<&str> = expected
            .into_iter()
            .filter(|path| !document.paths.paths.contains_key(*path))
            .collect();
        assert!(missing.is_empty(), "маршруты без описания: {missing:?}");
    }
}
