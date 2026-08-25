//! Обмен кода авторизации у VK ID по сети.
//!
//! Отделён от проверок и включается возможностью `oauth`: без настроенного
//! приложения провайдера обмен бесполезен, а зависимость тянет за собой
//! HTTP-клиент и TLS-стек.

use crate::authorizations::Pkce;
use crate::error::{Error, Result};
use crate::vk::{Exchange, Subject, AUTHORIZE, TOKEN};
use core::future::Future;
use core::pin::Pin;
use oauth2::basic::{
    BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
    BasicTokenType,
};
use oauth2::{
    AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, EndpointNotSet, EndpointSet,
    ExtraTokenFields, PkceCodeVerifier, RedirectUrl, StandardRevocableToken, StandardTokenResponse,
    TokenUrl,
};
use serde::{Deserialize, Serialize};

/// Поле ответа, ради которого обмен и затевается.
///
/// Токен доступа сервер не хранит и не использует: файлы он отдаёт по своей
/// сессии, а не по чужому токену.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Identified {
    user_id: serde_json::Value,
}

impl ExtraTokenFields for Identified {}

/// Ответ VK ID на обмен кода.
type Response = StandardTokenResponse<Identified, BasicTokenType>;

/// Клиент VK ID с настроенными адресами.
type Configured = Client<
    BasicErrorResponse,
    Response,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

/// Обмен кода авторизации по сети.
#[derive(Debug)]
pub struct Oauth {
    client: Configured,
    http: oauth2::reqwest::Client,
}

impl Oauth {
    /// Настраивает обмен по идентификатору приложения, секрету и адресу возврата.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если адрес возврата не разбирается как URL.
    pub fn new(client: &str, secret: &str, redirect: &str) -> Result<Self> {
        let authorize = AuthUrl::new(AUTHORIZE.to_owned()).map_err(|_| Error::Malformed)?;
        let token = TokenUrl::new(TOKEN.to_owned()).map_err(|_| Error::Malformed)?;
        let redirect = RedirectUrl::new(redirect.to_owned()).map_err(|_| Error::Malformed)?;
        // Переходы за клиентом не отслеживаются: следование за ними открывает
        // путь к запросам от имени сервера во внутреннюю сеть.
        let http = oauth2::reqwest::ClientBuilder::new()
            .redirect(oauth2::reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Error::Malformed)?;
        Ok(Self {
            client: Client::new(ClientId::new(client.to_owned()))
                .set_client_secret(ClientSecret::new(secret.to_owned()))
                .set_auth_uri(authorize)
                .set_token_uri(token)
                .set_redirect_uri(redirect),
            http,
        })
    }
}

impl Exchange for Oauth {
    fn exchange<'a>(
        &'a self,
        code: &'a str,
        pkce: &'a Pkce,
    ) -> Pin<Box<dyn Future<Output = Result<Subject>> + Send + 'a>> {
        Box::pin(async move {
            let answer = self
                .client
                .exchange_code(AuthorizationCode::new(code.to_owned()))
                .set_pkce_verifier(PkceCodeVerifier::new(pkce.expose().to_owned()))
                .request_async(&self.http)
                .await
                .map_err(|_| Error::Missing)?;
            let subject = match answer.extra_fields().user_id.clone() {
                serde_json::Value::String(text) => text,
                serde_json::Value::Number(number) => number.to_string(),
                _ => return Err(Error::Malformed),
            };
            Subject::new(subject)
        })
    }
}
