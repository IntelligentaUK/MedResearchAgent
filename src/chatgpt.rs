//! "Sign in with ChatGPT" using OpenAI's open-source/local flow, which lets this app send
//! model requests billed to the signed-in user's ChatGPT plan instead of an API key.
//! See https://developers.openai.com/siwc/token-sharing-open-source.
//!
//! The app's own loopback server receives the OAuth callback, so sign-in must be started from
//! a browser on the machine running the server. Credentials are kept in an owner-only file
//! next to `library.json` (never in the library, HTML or logs), which works on every OS.

use crate::models::ResearchError;
use crate::store::write_private_file;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::redirect::Policy;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

pub const ISSUER: &str = "https://auth.openai.com";
const DISCOVERY_URL: &str = "https://auth.openai.com/.well-known/openid-configuration";
const AUTHORIZE_URL: &str = "https://auth.openai.com/api/accounts/authorize";
const TOKEN_URL: &str = "https://auth.openai.com/api/accounts/oauth/token";
/// The API audience requested for plan-billed access tokens.
pub const RESOURCE: &str = "https://api.openai.com/v1";
const SCOPES: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
/// Scope that authorizes model requests billed to the user's ChatGPT plan.
pub const PLAN_SCOPE: &str = "chatgpt.tokens.use.direct";
/// Client ID used until OpenAI issues this installation its own during the first sign-in.
const DYNAMIC_CLIENT_ID: &str = "dynamic_agent_client";
const AGENT_NAME: &str = "Medical Research Agent";
pub const CALLBACK_PATH: &str = "/auth/callback";
pub const MANAGE_USAGE_URL: &str = "https://chatgpt.com/settings/usage";
/// Access tokens last an hour; refresh this long before they expire.
const REFRESH_MARGIN_SECONDS: i64 = 120;
const SIGN_IN_TTL_SECONDS: i64 = 600;
const ID_TOKEN_LEEWAY_SECONDS: u64 = 5;

const AUTH_FILE: &str = "chatgpt-auth.json";
const HOST_FILE: &str = "chatgpt-host.json";

/// Refresh errors after which the token set can never work again.
const TERMINAL_REFRESH_ERRORS: &[&str] = &[
    "invalid_grant",
    "invalid_refresh_token",
    "token_expired",
    "refresh_token_expired",
    "refresh_token_invalidated",
    "refresh_token_reused",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredCredentials {
    /// Issued `oaiapp_…` client ID. Kept after sign-out so the registration is reused.
    client_id: Option<String>,
    issuer: Option<String>,
    subject: Option<String>,
    email: Option<String>,
    id_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    scopes: Vec<String>,
    saved_at: Option<DateTime<Utc>>,
    #[serde(default)]
    welcome_shown: bool,
}

impl StoredCredentials {
    fn signed_in(&self) -> bool {
        self.access_token.is_some() && self.refresh_token.is_some()
    }

    fn plan_usage(&self) -> bool {
        self.signed_in() && self.scopes.iter().any(|s| s == PLAN_SCOPE)
    }

    fn clear_tokens(&mut self) {
        self.id_token = None;
        self.access_token = None;
        self.refresh_token = None;
        self.expires_at = None;
        self.scopes.clear();
        self.saved_at = Some(Utc::now());
    }
}

#[derive(Serialize, Deserialize)]
struct HostRecord {
    ext_agent_host_id: String,
}

struct PendingSignIn {
    state: String,
    nonce: String,
    code_verifier: String,
    redirect_uri: String,
    client_id: Option<String>,
    started_at: DateTime<Utc>,
}

struct Inner {
    credentials: StoredCredentials,
    pending: Option<PendingSignIn>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChatGptStatus {
    pub signed_in: bool,
    pub email: Option<String>,
    /// The user granted plan usage (`chatgpt.tokens.use.direct`).
    pub plan_usage: bool,
    /// Show the one-time "You're using your ChatGPT plan" notice.
    pub show_welcome: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub error: Option<String>,
}

pub struct ChatGptAuth {
    dir: PathBuf,
    // Also serializes refreshes: refresh tokens rotate, so two refreshes must never race.
    inner: Mutex<Inner>,
}

impl ChatGptAuth {
    /// Loads saved credentials from `dir` (the directory holding `library.json`).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let credentials = std::fs::read(dir.join(AUTH_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            dir,
            inner: Mutex::new(Inner {
                credentials,
                pending: None,
            }),
        }
    }

    pub async fn status(&self) -> ChatGptStatus {
        let inner = self.inner.lock().await;
        let c = &inner.credentials;
        ChatGptStatus {
            signed_in: c.signed_in(),
            email: c.email.clone(),
            plan_usage: c.plan_usage(),
            show_welcome: c.plan_usage() && !c.welcome_shown,
        }
    }

    pub async fn dismiss_welcome(&self) -> Result<(), ResearchError> {
        let mut inner = self.inner.lock().await;
        inner.credentials.welcome_shown = true;
        self.persist(&inner.credentials)
    }

    /// Starts sign-in and returns the OpenAI authorization URL to send the browser to.
    /// `port` is the loopback port this server listens on. `request_consent` asks again for
    /// plan usage after the user declined it, and must only follow an explicit user choice.
    pub async fn begin_sign_in(
        &self,
        port: u16,
        request_consent: bool,
    ) -> Result<Url, ResearchError> {
        let host_id = self.host_id()?;
        let mut inner = self.inner.lock().await;
        let state = random_token();
        let nonce = random_token();
        let code_verifier = random_token();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");
        let issued = inner.credentials.client_id.clone();

        let mut url = Url::parse(AUTHORIZE_URL).expect("valid URL");
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("client_id", issued.as_deref().unwrap_or(DYNAMIC_CLIENT_ID));
            if issued.is_none() {
                query.append_pair("agent_name_hint", AGENT_NAME);
            }
            query.append_pair("ext_agent_host_id", &host_id);
            if let Some(ref id_token) = inner.credentials.id_token {
                query.append_pair("id_token_hint", id_token);
                if let Some(ref email) = inner.credentials.email {
                    query.append_pair("login_hint", email);
                }
            }
            query
                .append_pair("response_type", "code")
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("scope", SCOPES)
                .append_pair("resource", RESOURCE)
                .append_pair("state", &state)
                .append_pair("nonce", &nonce)
                .append_pair("code_challenge_method", "S256")
                .append_pair("code_challenge", &challenge);
            if request_consent {
                query.append_pair("prompt", "consent");
            }
        }
        inner.pending = Some(PendingSignIn {
            state,
            nonce,
            code_verifier,
            redirect_uri,
            client_id: issued,
            started_at: Utc::now(),
        });
        Ok(url)
    }

    /// Handles the OAuth callback: checks it belongs to the pending sign-in, exchanges the
    /// code, verifies the ID token and saves the credentials.
    pub async fn complete_sign_in(
        &self,
        params: CallbackParams,
    ) -> Result<ChatGptStatus, ResearchError> {
        let mut inner = self.inner.lock().await;
        let Some(pending) = inner.pending.take() else {
            return Err(unavailable(
                "No ChatGPT sign-in is in progress. Start again with Continue with ChatGPT.",
            ));
        };
        let supplied_state = params.state.as_deref().unwrap_or("");
        if !bool::from(supplied_state.as_bytes().ct_eq(pending.state.as_bytes())) {
            // Not the response to our request; keep waiting for the real one.
            inner.pending = Some(pending);
            return Err(invalid(
                "The ChatGPT sign-in response did not match the request. Start again.",
            ));
        }
        if Utc::now() - pending.started_at > ChronoDuration::seconds(SIGN_IN_TTL_SECONDS) {
            return Err(unavailable("ChatGPT sign-in took too long. Start again."));
        }
        if let Some(error) = params.error {
            return Err(unavailable(if error == "access_denied" {
                "ChatGPT sign-in was cancelled.".to_string()
            } else {
                format!("ChatGPT sign-in failed: {error}")
            }));
        }
        let code = params
            .code
            .filter(|c| !c.is_empty())
            .ok_or_else(|| invalid("ChatGPT sign-in returned no authorization code."))?;
        let client_id = match (pending.client_id.as_deref(), params.client_id.as_deref()) {
            (Some(saved), Some(returned)) if saved != returned => {
                return Err(invalid(
                    "ChatGPT returned a different app registration than expected. Start again.",
                ))
            }
            (Some(saved), _) => saved.to_string(),
            (None, Some(returned)) if !returned.is_empty() => returned.to_string(),
            _ => {
                return Err(invalid(
                    "ChatGPT did not return an app registration. Start again.",
                ))
            }
        };
        // Save the issued client ID before the exchange so a retry reuses this registration.
        if inner.credentials.client_id.as_deref() != Some(client_id.as_str()) {
            inner.credentials.client_id = Some(client_id.clone());
            self.persist(&inner.credentials)?;
        }

        let tokens = token_request(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client_id),
            ("code", &code),
            ("code_verifier", &pending.code_verifier),
            ("redirect_uri", &pending.redirect_uri),
            ("resource", RESOURCE),
        ])
        .await
        .map_err(|e| match e {
            TokenError::Rejected { ref error, .. } if error == "invalid_grant" => unavailable(
                "The ChatGPT sign-in code expired or was already used. Start again.",
            ),
            other => other.into(),
        })?;
        let id_token = tokens
            .id_token
            .ok_or_else(|| invalid("ChatGPT sign-in returned no ID token."))?;
        let claims = verify_id_token(&id_token, &client_id, &pending.nonce).await?;
        let (Some(access_token), Some(refresh_token)) = (tokens.access_token, tokens.refresh_token)
        else {
            return Err(invalid(
                "ChatGPT sign-in did not return the access and refresh tokens.",
            ));
        };
        // RFC 6749 §5.1: `scope` may be omitted when the grant matches the request.
        let granted = tokens
            .scope
            .or(params.scope)
            .unwrap_or_else(|| SCOPES.to_string());

        let now = Utc::now();
        let c = &mut inner.credentials;
        c.issuer = Some(ISSUER.to_string());
        c.subject = Some(claims.sub);
        c.email = claims.email;
        c.id_token = Some(id_token);
        c.access_token = Some(access_token);
        c.refresh_token = Some(refresh_token);
        c.expires_at = Some(now + ChronoDuration::seconds(tokens.expires_in.unwrap_or(3600)));
        c.scopes = granted.split_whitespace().map(str::to_string).collect();
        c.saved_at = Some(now);
        self.persist(&inner.credentials)?;
        let c = &inner.credentials;
        Ok(ChatGptStatus {
            signed_in: c.signed_in(),
            email: c.email.clone(),
            plan_usage: c.plan_usage(),
            show_welcome: c.plan_usage() && !c.welcome_shown,
        })
    }

    /// A current access token for plan-billed requests, refreshed first when it is close to
    /// expiry.
    pub async fn access_token(&self) -> Result<String, ResearchError> {
        let mut inner = self.inner.lock().await;
        if !inner.credentials.signed_in() {
            return Err(unavailable(
                "Continue with ChatGPT in Sources & credentials before using your ChatGPT plan.",
            ));
        }
        if !inner.credentials.plan_usage() {
            return Err(unavailable(
                "ChatGPT plan usage is not enabled for this sign-in. Choose Use your ChatGPT plan in Sources & credentials, or pick another model provider.",
            ));
        }
        let fresh = inner
            .credentials
            .expires_at
            .is_some_and(|t| t - Utc::now() > ChronoDuration::seconds(REFRESH_MARGIN_SECONDS));
        if !fresh {
            self.refresh(&mut inner.credentials).await?;
        }
        inner
            .credentials
            .access_token
            .clone()
            .ok_or_else(|| unavailable("Continue with ChatGPT again in Sources & credentials."))
    }

    async fn refresh(&self, c: &mut StoredCredentials) -> Result<(), ResearchError> {
        let (Some(client_id), Some(refresh_token)) = (c.client_id.clone(), c.refresh_token.clone())
        else {
            return Err(unavailable(
                "Continue with ChatGPT again in Sources & credentials.",
            ));
        };
        // Omitting `scope` keeps the existing grant.
        match token_request(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", &refresh_token),
            ("resource", RESOURCE),
        ])
        .await
        {
            Ok(tokens) => {
                let Some(access_token) = tokens.access_token else {
                    return Err(invalid("ChatGPT token refresh returned no access token."));
                };
                let now = Utc::now();
                c.access_token = Some(access_token);
                if let Some(rotated) = tokens.refresh_token {
                    c.refresh_token = Some(rotated);
                }
                c.expires_at =
                    Some(now + ChronoDuration::seconds(tokens.expires_in.unwrap_or(3600)));
                if let Some(scope) = tokens.scope {
                    c.scopes = scope.split_whitespace().map(str::to_string).collect();
                }
                c.saved_at = Some(now);
                self.persist(c)
            }
            Err(TokenError::Rejected { ref error, .. })
                if TERMINAL_REFRESH_ERRORS.contains(&error.as_str()) =>
            {
                c.clear_tokens();
                self.persist(c)?;
                Err(unavailable(
                    "Your ChatGPT sign-in expired or the app was disconnected in ChatGPT. Continue with ChatGPT again in Sources & credentials.",
                ))
            }
            // Includes `invalid_client`, which signing in again would not fix, and transient
            // failures, after which the saved credentials stay usable.
            Err(other) => Err(other.into()),
        }
    }

    /// Revokes the refresh token, then deletes the tokens. The issued client ID and host ID
    /// are kept so the next sign-in reuses this registration. Returns whether OpenAI
    /// confirmed the revocation.
    pub async fn sign_out(&self) -> Result<bool, ResearchError> {
        let mut inner = self.inner.lock().await;
        inner.pending = None;
        let confirmed = match (
            inner.credentials.client_id.clone(),
            inner.credentials.refresh_token.clone(),
        ) {
            (Some(client_id), Some(token)) => revoke(&client_id, &token).await,
            _ => true,
        };
        inner.credentials.clear_tokens();
        self.persist(&inner.credentials)?;
        Ok(confirmed)
    }

    fn persist(&self, credentials: &StoredCredentials) -> Result<(), ResearchError> {
        let payload = serde_json::to_vec_pretty(credentials)
            .map_err(|e| invalid(format!("Could not encode ChatGPT credentials: {e}")))?;
        write_private_file(&self.dir.join(AUTH_FILE), &payload)
    }

    /// The stable per-installation `ext_agent_host_id`, created on first use.
    fn host_id(&self) -> Result<String, ResearchError> {
        let path = self.dir.join(HOST_FILE);
        if let Some(record) = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<HostRecord>(&bytes).ok())
        {
            return Ok(record.ext_agent_host_id);
        }
        let record = HostRecord {
            ext_agent_host_id: format!("urn:uuid:{}", Uuid::new_v4()),
        };
        let payload = serde_json::to_vec_pretty(&record)
            .map_err(|e| invalid(format!("Could not encode host ID: {e}")))?;
        write_private_file(&path, &payload)?;
        Ok(record.ext_agent_host_id)
    }
}

fn unavailable(msg: impl Into<String>) -> ResearchError {
    ResearchError::Unavailable(msg.into())
}

fn invalid(msg: impl Into<String>) -> ResearchError {
    ResearchError::InvalidResponse(msg.into())
}

/// 256 random bits, base64url-encoded (also a valid 43-character PKCE verifier).
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn http_client(timeout_seconds: u64) -> Result<reqwest::Client, ResearchError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_seconds))
        .redirect(Policy::none())
        .build()
        .map_err(|e| unavailable(format!("Transport error: {e}")))
}

async fn get_json<T: DeserializeOwned>(url: &str) -> Result<T, ResearchError> {
    let response = http_client(30)?
        .get(url)
        .send()
        .await
        .map_err(|e| unavailable(format!("Could not reach ChatGPT sign-in: {e}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(ResearchError::Http(
            status.as_u16(),
            format!("ChatGPT sign-in metadata request to {url} failed."),
        ));
    }
    response
        .json()
        .await
        .map_err(|e| invalid(format!("Unreadable ChatGPT sign-in metadata: {e}")))
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
    revocation_endpoint: Option<String>,
}

/// Fetches OpenID discovery, accepting only endpoints on the expected issuer's host.
async fn discovery() -> Result<Discovery, ResearchError> {
    let found: Discovery = get_json(DISCOVERY_URL).await?;
    let on_issuer = |raw: &str| {
        Url::parse(raw)
            .is_ok_and(|u| u.scheme() == "https" && u.host_str() == Some("auth.openai.com"))
    };
    if found.issuer != ISSUER
        || !on_issuer(&found.jwks_uri)
        || found.revocation_endpoint.as_deref().is_some_and(|r| !on_issuer(r))
    {
        return Err(invalid(
            "ChatGPT sign-in metadata named an unexpected issuer or endpoint.",
        ));
    }
    Ok(found)
}

#[derive(Deserialize)]
struct IdClaims {
    sub: String,
    #[allow(dead_code)] // Required: decoding fails when the token has no `iat`.
    iat: i64,
    email: Option<String>,
    nonce: Option<String>,
}

async fn verify_id_token(
    id_token: &str,
    client_id: &str,
    nonce: &str,
) -> Result<IdClaims, ResearchError> {
    let header = decode_header(id_token)
        .map_err(|e| invalid(format!("ChatGPT returned an unreadable ID token: {e}")))?;
    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
    ) {
        return Err(invalid(
            "ChatGPT ID token uses an unsupported signing algorithm.",
        ));
    }
    let discovery = discovery().await?;
    let jwks: JwkSet = get_json(&discovery.jwks_uri).await?;
    let jwk = match header.kid.as_deref() {
        Some(kid) => jwks.find(kid),
        None if jwks.keys.len() == 1 => jwks.keys.first(),
        None => None,
    }
    .ok_or_else(|| invalid("No published OpenAI key matches the ChatGPT ID token."))?;
    let key = DecodingKey::from_jwk(jwk)
        .map_err(|e| invalid(format!("Unusable OpenAI signing key: {e}")))?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[discovery.issuer.as_str()]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);
    validation.leeway = ID_TOKEN_LEEWAY_SECONDS;
    let claims = decode::<IdClaims>(id_token, &key, &validation)
        .map_err(|e| invalid(format!("ChatGPT ID token failed verification: {e}")))?
        .claims;
    if claims.nonce.as_deref() != Some(nonce) {
        return Err(invalid("ChatGPT ID token was not issued for this sign-in."));
    }
    if claims.sub.trim().is_empty() {
        return Err(invalid("ChatGPT ID token has no account identity."));
    }
    Ok(claims)
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: Option<i64>,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
    error_description: Option<String>,
}

enum TokenError {
    Rejected {
        status: u16,
        error: String,
        description: Option<String>,
    },
    Transport(ResearchError),
}

impl From<TokenError> for ResearchError {
    fn from(e: TokenError) -> Self {
        match e {
            TokenError::Rejected {
                status,
                error,
                description,
            } => ResearchError::Http(
                status,
                match description {
                    Some(d) => format!("ChatGPT sign-in error {error}: {d}"),
                    None => format!("ChatGPT sign-in error {error}"),
                },
            ),
            TokenError::Transport(e) => e,
        }
    }
}

/// POSTs a form to the token endpoint. Error bodies are never echoed, since they may relate
/// to secrets.
async fn token_request(form: &[(&str, &str)]) -> Result<TokenResponse, TokenError> {
    let response = http_client(30)
        .map_err(TokenError::Transport)?
        .post(TOKEN_URL)
        .form(form)
        .send()
        .await
        .map_err(|e| TokenError::Transport(unavailable(format!("Could not reach ChatGPT sign-in: {}", e.without_url()))))?;
    let status = response.status();
    let bytes = response.bytes().await.map_err(|e| {
        TokenError::Transport(unavailable(format!(
            "ChatGPT sign-in response was interrupted: {}",
            e.without_url()
        )))
    })?;
    if status.is_success() {
        return serde_json::from_slice(&bytes).map_err(|e| {
            TokenError::Transport(invalid(format!("Unreadable ChatGPT token response: {e}")))
        });
    }
    match serde_json::from_slice::<OAuthError>(&bytes) {
        Ok(err) => Err(TokenError::Rejected {
            status: status.as_u16(),
            error: err.error,
            description: err.error_description,
        }),
        Err(_) => Err(TokenError::Transport(ResearchError::Http(
            status.as_u16(),
            "ChatGPT token request failed.".to_string(),
        ))),
    }
}

/// Revokes a refresh token, retrying network failures and 5xx responses. An empty 200 is
/// success, including for a token that was already invalid.
async fn revoke(client_id: &str, refresh_token: &str) -> bool {
    let Ok(endpoint) = discovery()
        .await
        .and_then(|d| d.revocation_endpoint.ok_or_else(|| invalid("no revocation endpoint")))
    else {
        return false;
    };
    let Ok(client) = http_client(15) else {
        return false;
    };
    for attempt in 1..=3u64 {
        let sent = client
            .post(&endpoint)
            .form(&[
                ("token", refresh_token),
                ("token_type_hint", "refresh_token"),
                ("client_id", client_id),
            ])
            .send()
            .await;
        match sent {
            Ok(r) if r.status().is_success() => return true,
            Ok(r) if r.status().is_client_error() => return false,
            _ => tokio::time::sleep(Duration::from_millis(500 * attempt)).await,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sign_in_url_uses_pkce_dynamic_registration_and_loopback_callback() {
        let dir = std::env::temp_dir().join(format!("siwc-test-{}", Uuid::new_v4()));
        let auth = ChatGptAuth::new(&dir);
        let url = auth.begin_sign_in(8080, false).await.expect("url");
        let q: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(url.as_str().split('?').next(), Some(AUTHORIZE_URL));
        assert_eq!(q["client_id"], DYNAMIC_CLIENT_ID);
        assert_eq!(q["agent_name_hint"], AGENT_NAME);
        assert!(q["ext_agent_host_id"].starts_with("urn:uuid:"));
        assert_eq!(q["redirect_uri"], "http://127.0.0.1:8080/auth/callback");
        assert_eq!(q["scope"], SCOPES);
        assert_eq!(q["resource"], RESOURCE);
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["code_challenge"].len(), 43);
        assert!(!q.contains_key("prompt") && !q.contains_key("id_token_hint"));

        // The host ID is stable across sign-in attempts.
        let again = auth.begin_sign_in(8081, true).await.expect("url");
        let q2: std::collections::HashMap<String, String> =
            again.query_pairs().into_owned().collect();
        assert_eq!(q2["ext_agent_host_id"], q["ext_agent_host_id"]);
        assert_eq!(q2["prompt"], "consent");
        assert_ne!(q2["state"], q["state"]);

        // A callback for an older attempt is rejected and the newest attempt stays pending.
        let stale = auth
            .complete_sign_in(CallbackParams {
                code: Some("code".into()),
                state: Some(q["state"].clone()),
                ..CallbackParams::default()
            })
            .await;
        assert!(stale.is_err());
        let declined = auth
            .complete_sign_in(CallbackParams {
                state: Some(q2["state"].clone()),
                error: Some("access_denied".into()),
                ..CallbackParams::default()
            })
            .await;
        assert!(matches!(declined, Err(ResearchError::Unavailable(m)) if m.contains("cancelled")));
        assert!(!auth.status().await.signed_in);
        assert!(auth.access_token().await.is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
