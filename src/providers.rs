use crate::models::{InstitutionalAccess, ResearchError};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::redirect::Policy;
use serde::Deserialize;
use crate::store::write_private_file;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

const KEYCHAIN_SERVICE: &str = "DementiaResearch";
const SECRETS_FILE: &str = "secrets.json";

/// Where API keys and institutional tokens are kept. Chosen once at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretBackend {
    /// The macOS login Keychain, through the Apple-signed `/usr/bin/security`.
    MacKeychain,
    /// Windows Credential Manager (DPAPI-encrypted, per user).
    WindowsCredentialManager,
    /// The freedesktop Secret Service (GNOME Keyring, KWallet, KeePassXC).
    SecretService,
    /// An owner-only file, used only when the OS offers no secret store (e.g. headless Linux).
    PrivateFile(PathBuf),
    /// Tests only.
    Memory,
}

impl SecretBackend {
    pub fn describe(&self) -> String {
        match self {
            SecretBackend::MacKeychain => "the macOS Keychain".to_string(),
            SecretBackend::WindowsCredentialManager => "Windows Credential Manager".to_string(),
            SecretBackend::SecretService => "the system keyring (Secret Service)".to_string(),
            SecretBackend::PrivateFile(path) => {
                format!("an owner-only file ({})", path.display())
            }
            SecretBackend::Memory => "memory".to_string(),
        }
    }

    /// False when secrets fall back to a plain (owner-only) file.
    pub fn is_encrypted_store(&self) -> bool {
        !matches!(self, SecretBackend::PrivateFile(_))
    }
}

#[derive(Clone)]
pub struct KeychainStore {
    backend: SecretBackend,
    // Holds the secrets for `Memory`; for `PrivateFile` it only serializes rewrites.
    memory: Arc<Mutex<HashMap<String, String>>>,
}

impl KeychainStore {
    /// The OS secret store, or an owner-only `secrets.json` in `data_dir` when there is none.
    pub fn system(data_dir: &Path) -> Self {
        let backend = os_secret_backend()
            .unwrap_or_else(|| SecretBackend::PrivateFile(data_dir.join(SECRETS_FILE)));
        Self {
            backend,
            memory: Arc::default(),
        }
    }

    /// Secrets in an owner-only JSON file, as used when the OS has no secret store.
    pub fn private_file(path: impl Into<PathBuf>) -> Self {
        Self {
            backend: SecretBackend::PrivateFile(path.into()),
            memory: Arc::default(),
        }
    }

    pub fn in_memory() -> Self {
        Self {
            backend: SecretBackend::Memory,
            memory: Arc::default(),
        }
    }

    pub fn backend(&self) -> &SecretBackend {
        &self.backend
    }

    pub fn get(&self, account: &str) -> Option<String> {
        let value = match &self.backend {
            SecretBackend::Memory => self.memory.lock().ok()?.get(account).cloned(),
            SecretBackend::MacKeychain => mac_keychain_get(account),
            SecretBackend::WindowsCredentialManager | SecretBackend::SecretService => {
                os_store_get(account)
            }
            SecretBackend::PrivateFile(path) => read_secrets_file(path).remove(account),
        };
        value.filter(|v| !v.is_empty())
    }

    pub fn set(&self, account: &str, value: &str) -> Result<(), ResearchError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return self.delete(account);
        }
        if trimmed.chars().any(char::is_control) {
            return Err(ResearchError::InvalidResponse(
                "Credentials cannot contain line breaks or control characters.".to_string(),
            ));
        }
        match &self.backend {
            SecretBackend::Memory => {
                if let Ok(mut guard) = self.memory.lock() {
                    guard.insert(account.to_string(), trimmed.to_string());
                }
                Ok(())
            }
            SecretBackend::MacKeychain => mac_keychain_set(account, trimmed),
            SecretBackend::WindowsCredentialManager | SecretBackend::SecretService => {
                os_store_set(account, trimmed)
            }
            SecretBackend::PrivateFile(path) => {
                let _guard = self.memory.lock();
                let mut secrets = read_secrets_file(path);
                secrets.insert(account.to_string(), trimmed.to_string());
                write_secrets_file(path, &secrets)
            }
        }
    }

    pub fn delete(&self, account: &str) -> Result<(), ResearchError> {
        match &self.backend {
            SecretBackend::Memory => {
                if let Ok(mut guard) = self.memory.lock() {
                    guard.remove(account);
                }
                Ok(())
            }
            SecretBackend::MacKeychain => {
                // Fails harmlessly when the item does not exist.
                let _ = Command::new("/usr/bin/security")
                    .args(["delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                Ok(())
            }
            SecretBackend::WindowsCredentialManager | SecretBackend::SecretService => {
                os_store_delete(account)
            }
            SecretBackend::PrivateFile(path) => {
                let _guard = self.memory.lock();
                let mut secrets = read_secrets_file(path);
                if secrets.remove(account).is_some() {
                    write_secrets_file(path, &secrets)?;
                }
                Ok(())
            }
        }
    }

    pub fn institutional_access(&self) -> InstitutionalAccess {
        InstitutionalAccess::new(
            self.get("elsevier_api_key"),
            self.get("elsevier_institution_token"),
            self.get("wiley_tdm_token"),
            self.get("library_proxy_prefix"),
        )
    }

    pub fn save_institutional_access(&self, access: &InstitutionalAccess) -> Result<(), ResearchError> {
        self.set(
            "elsevier_api_key",
            access.elsevier_api_key.as_deref().unwrap_or(""),
        )?;
        self.set(
            "elsevier_institution_token",
            access.elsevier_institution_token.as_deref().unwrap_or(""),
        )?;
        self.set(
            "wiley_tdm_token",
            access.wiley_tdm_token.as_deref().unwrap_or(""),
        )?;
        self.set(
            "library_proxy_prefix",
            access.library_proxy_prefix.as_deref().unwrap_or(""),
        )?;
        Ok(())
    }
}

fn mac_keychain_get(account: &str) -> Option<String> {
    let output = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Writes through `security -i` so the secret travels on stdin, never on a command line
/// where other local processes could read it. `security -i` reports no errors, so the
/// write is verified by reading it back.
fn mac_keychain_set(account: &str, value: &str) -> Result<(), ResearchError> {
    let quote = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    let command = format!(
        "add-generic-password -U -s {} -a {} -w {}\n",
        quote(KEYCHAIN_SERVICE),
        quote(account),
        quote(value)
    );
    let failed = |e: std::io::Error| ResearchError::Unavailable(format!("Keychain error: {e}"));
    let mut child = Command::new("/usr/bin/security")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(failed)?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(command.as_bytes()).map_err(failed)?;
    }
    child.wait().map_err(failed)?;
    if mac_keychain_get(account).as_deref() != Some(value) {
        return Err(ResearchError::Unavailable(
            "The macOS Keychain did not save the credential. Check that the login keychain is unlocked.".to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn os_secret_backend() -> Option<SecretBackend> {
    Some(SecretBackend::MacKeychain)
}

#[cfg(target_os = "windows")]
fn os_secret_backend() -> Option<SecretBackend> {
    let store = windows_native_keyring_store::Store::new().ok()?;
    keyring_core::set_default_store(store);
    Some(SecretBackend::WindowsCredentialManager)
}

/// Connects to the Secret Service over D-Bus; fails where none runs (servers, containers).
#[cfg(all(unix, not(target_os = "macos")))]
fn os_secret_backend() -> Option<SecretBackend> {
    let store = zbus_secret_service_keyring_store::Store::new().ok()?;
    keyring_core::set_default_store(store);
    Some(SecretBackend::SecretService)
}

#[cfg(not(any(unix, windows)))]
fn os_secret_backend() -> Option<SecretBackend> {
    None
}

#[cfg(any(windows, all(unix, not(target_os = "macos"))))]
fn os_store_entry(account: &str) -> Result<keyring_core::Entry, ResearchError> {
    keyring_core::Entry::new(KEYCHAIN_SERVICE, account)
        .map_err(|e| ResearchError::Unavailable(format!("Credential store error: {e}")))
}

#[cfg(any(windows, all(unix, not(target_os = "macos"))))]
fn os_store_get(account: &str) -> Option<String> {
    os_store_entry(account).ok()?.get_password().ok()
}

#[cfg(any(windows, all(unix, not(target_os = "macos"))))]
fn os_store_set(account: &str, value: &str) -> Result<(), ResearchError> {
    os_store_entry(account)?
        .set_password(value)
        .map_err(|e| ResearchError::Unavailable(format!("Credential store did not save: {e}")))
}

#[cfg(any(windows, all(unix, not(target_os = "macos"))))]
fn os_store_delete(account: &str) -> Result<(), ResearchError> {
    match os_store_entry(account)?.delete_credential() {
        Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
        Err(e) => Err(ResearchError::Unavailable(format!(
            "Credential store did not delete: {e}"
        ))),
    }
}

// Only reachable through the Windows/Secret Service backends, which macOS never selects.
#[cfg(target_os = "macos")]
fn os_store_get(_account: &str) -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn os_store_set(_account: &str, _value: &str) -> Result<(), ResearchError> {
    Err(ResearchError::Unavailable("No OS credential store.".to_string()))
}

#[cfg(target_os = "macos")]
fn os_store_delete(_account: &str) -> Result<(), ResearchError> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn os_store_get(_account: &str) -> Option<String> {
    None
}

#[cfg(not(any(unix, windows)))]
fn os_store_set(_account: &str, _value: &str) -> Result<(), ResearchError> {
    Err(ResearchError::Unavailable("No OS credential store.".to_string()))
}

#[cfg(not(any(unix, windows)))]
fn os_store_delete(_account: &str) -> Result<(), ResearchError> {
    Ok(())
}

fn read_secrets_file(path: &Path) -> HashMap<String, String> {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_secrets_file(path: &Path, secrets: &HashMap<String, String>) -> Result<(), ResearchError> {
    let payload = serde_json::to_vec_pretty(secrets)
        .map_err(|e| ResearchError::InvalidResponse(format!("Could not encode credentials: {e}")))?;
    write_private_file(path, &payload)
}

pub fn redact_secret(text: &str, secret: &str) -> String {
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        return text.to_string();
    }
    text.replace(trimmed, "[redacted]")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelVendor {
    Anthropic,
    OpenAi,
    /// OpenAI models billed to the user's ChatGPT plan via "Sign in with ChatGPT".
    ChatGpt,
}

impl ModelVendor {
    /// Order used by "Automatic" and by the model picker.
    pub const ALL: [ModelVendor; 3] = [ModelVendor::ChatGpt, ModelVendor::Anthropic, ModelVendor::OpenAi];

    pub fn parse(raw: &str) -> Self {
        let raw = raw.trim();
        if raw.eq_ignore_ascii_case("openai") {
            ModelVendor::OpenAi
        } else if raw.eq_ignore_ascii_case("chatgpt") {
            ModelVendor::ChatGpt
        } else {
            ModelVendor::Anthropic
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ModelVendor::Anthropic => "anthropic",
            ModelVendor::OpenAi => "openai",
            ModelVendor::ChatGpt => "chatgpt",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ModelVendor::Anthropic => "Claude (Anthropic)",
            ModelVendor::OpenAi => "OpenAI",
            ModelVendor::ChatGpt => "ChatGPT plan",
        }
    }

    /// Used when no model was chosen and none can be listed. Only Claude has one: OpenAI
    /// and ChatGPT plan models depend on the account, so they are always listed live.
    pub fn default_model(&self) -> Option<&'static str> {
        match self {
            ModelVendor::Anthropic => Some("claude-opus-5-5"),
            ModelVendor::OpenAi | ModelVendor::ChatGpt => None,
        }
    }
}

/// A model offered by a provider: the API identifier and a name to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelOption {
    pub id: String,
    pub label: String,
}

pub struct ClaudeProvider {
    endpoint: Url,
    models_endpoint: Url,
}

impl Default for ClaudeProvider {
    fn default() -> Self {
        Self {
            endpoint: Url::parse("https://api.anthropic.com/v1/messages").expect("valid URL"),
            models_endpoint: Url::parse("https://api.anthropic.com/v1/models").expect("valid URL"),
        }
    }
}

impl ClaudeProvider {
    pub async fn generate(
        &self,
        api_key: &str,
        model: &str,
        system: &str,
        prompt: &str,
    ) -> Result<String, ResearchError> {
        let key = api_key.trim();
        if key.is_empty() {
            return Err(ResearchError::Unavailable(
                "Add a Claude API key in Credentials before running a model stage.".to_string(),
            ));
        }
        // No sampling parameters: Claude 4.7 and later reject `temperature`/`top_p`/`top_k`.
        // Current models think before answering, and thinking counts toward `max_tokens`,
        // so leave room for it as well as the JSON answer.
        let body = serde_json::json!({
            "model": model,
            "max_tokens": 16000,
            "system": system,
            "messages": [{"role": "user", "content": prompt}]
        });
        let headers = Self::headers(key)?;
        let data = post_no_redirect(&self.endpoint, headers, &body, key).await?;

        #[derive(Deserialize)]
        struct Response {
            content: Vec<Block>,
            stop_reason: Option<String>,
        }
        #[derive(Deserialize)]
        struct Block {
            r#type: String,
            text: Option<String>,
        }
        let parsed: Response = serde_json::from_slice(&data).map_err(|e| {
            ResearchError::InvalidResponse(format!("Claude returned an unreadable response: {e}"))
        })?;
        match parsed.stop_reason.as_deref() {
            Some("refusal") => {
                return Err(ResearchError::Unavailable(
                    "Claude declined this request (refusal). Try another model.".to_string(),
                ))
            }
            Some("max_tokens") => {
                return Err(ResearchError::InvalidResponse(
                    "Claude's response was cut off at the output limit.".to_string(),
                ))
            }
            _ => {}
        }
        // Thinking blocks are skipped; only the answer text is used.
        let text = parsed
            .content
            .into_iter()
            .filter(|b| b.r#type == "text")
            .filter_map(|b| b.text)
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string();
        if text.is_empty() {
            return Err(ResearchError::InvalidResponse(
                "Claude returned an empty response.".to_string(),
            ));
        }
        Ok(text)
    }

    /// Every model this key can use, newest first, following pagination.
    pub async fn models(&self, api_key: &str) -> Result<Vec<ModelOption>, ResearchError> {
        let key = api_key.trim();
        if key.is_empty() {
            return Err(ResearchError::Unavailable(
                "Add a Claude API key first.".to_string(),
            ));
        }
        #[derive(Deserialize)]
        struct ModelsPage {
            data: Vec<ModelRow>,
            #[serde(default)]
            has_more: bool,
            last_id: Option<String>,
        }
        #[derive(Deserialize)]
        struct ModelRow {
            id: String,
            display_name: Option<String>,
        }
        let mut options = Vec::new();
        let mut after: Option<String> = None;
        // Bounded: a handful of pages covers every model by a wide margin.
        for _ in 0..5 {
            let mut url = self.models_endpoint.clone();
            url.query_pairs_mut().append_pair("limit", "1000");
            if let Some(ref after_id) = after {
                url.query_pairs_mut().append_pair("after_id", after_id);
            }
            let mut headers = Self::headers(key)?;
            headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
            let data = get_no_redirect(&url, headers, key).await?;
            let page: ModelsPage = serde_json::from_slice(&data).map_err(|e| {
                ResearchError::InvalidResponse(format!("Invalid Claude models response: {e}"))
            })?;
            options.extend(page.data.into_iter().map(|m| ModelOption {
                label: m.display_name.unwrap_or_else(|| m.id.clone()),
                id: m.id,
            }));
            match (page.has_more, page.last_id) {
                (true, Some(last)) => after = Some(last),
                _ => break,
            }
        }
        Ok(options)
    }

    fn headers(key: &str) -> Result<HeaderMap, ResearchError> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        let key_header = HeaderValue::from_str(key).map_err(|_| {
            ResearchError::InvalidResponse("Claude API key contains invalid header characters.".to_string())
        })?;
        headers.insert("x-api-key", key_header);
        Ok(headers)
    }
}

pub struct OpenAiProvider {
    endpoint: Url,
    models_endpoint: Url,
}

impl Default for OpenAiProvider {
    fn default() -> Self {
        Self {
            endpoint: Url::parse("https://api.openai.com/v1/responses").expect("valid URL"),
            models_endpoint: Url::parse("https://api.openai.com/v1/models").expect("valid URL"),
        }
    }
}

impl OpenAiProvider {
    pub async fn generate(
        &self,
        api_key: &str,
        model: &str,
        system: &str,
        prompt: &str,
    ) -> Result<String, ResearchError> {
        let key = api_key.trim();
        if key.is_empty() {
            return Err(ResearchError::Unavailable(
                "Add an OpenAI API key in Credentials before running a model stage.".to_string(),
            ));
        }
        let body = serde_json::json!({
            "model": model,
            "instructions": system,
            "input": prompt,
            "store": false
        });
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let bearer = HeaderValue::from_str(&format!("Bearer {key}")).map_err(|_| {
            ResearchError::InvalidResponse("OpenAI API key contains invalid header characters.".to_string())
        })?;
        headers.insert(AUTHORIZATION, bearer);

        let data = post_no_redirect(&self.endpoint, headers, &body, key).await?;

        #[derive(Deserialize)]
        struct Response {
            output_text: Option<String>,
            output: Option<Vec<Item>>,
        }
        #[derive(Deserialize)]
        struct Item {
            content: Option<Vec<ContentPart>>,
        }
        #[derive(Deserialize)]
        struct ContentPart {
            text: Option<String>,
        }
        let parsed: Response = serde_json::from_slice(&data).map_err(|e| {
            ResearchError::InvalidResponse(format!("OpenAI returned an unreadable response: {e}"))
        })?;
        if let Some(direct) = parsed.output_text.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
            return Ok(direct);
        }
        let text = parsed
            .output
            .unwrap_or_default()
            .into_iter()
            .flat_map(|i| i.content.unwrap_or_default())
            .filter_map(|p| p.text)
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string();
        if text.is_empty() {
            return Err(ResearchError::InvalidResponse(
                "OpenAI returned an empty response.".to_string(),
            ));
        }
        Ok(text)
    }

    /// Text-generation models this key can use, newest first. The API also lists
    /// embedding, speech, image and moderation models, which are left out.
    pub async fn models(&self, api_key: &str) -> Result<Vec<ModelOption>, ResearchError> {
        let key = api_key.trim();
        if key.is_empty() {
            return Err(ResearchError::Unavailable(
                "Add an OpenAI API key first.".to_string(),
            ));
        }
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let bearer = HeaderValue::from_str(&format!("Bearer {key}")).map_err(|_| {
            ResearchError::InvalidResponse("OpenAI API key contains invalid header characters.".to_string())
        })?;
        headers.insert(AUTHORIZATION, bearer);

        let data = get_no_redirect(&self.models_endpoint, headers, key).await?;
        #[derive(Deserialize)]
        struct ModelsEnvelope {
            data: Vec<ModelRow>,
        }
        #[derive(Deserialize)]
        struct ModelRow {
            id: String,
            #[serde(default)]
            created: i64,
        }
        let env: ModelsEnvelope = serde_json::from_slice(&data).map_err(|e| {
            ResearchError::InvalidResponse(format!("Invalid OpenAI models response: {e}"))
        })?;
        let mut rows: Vec<ModelRow> = env
            .data
            .into_iter()
            .filter(|m| is_openai_text_model(&m.id))
            .collect();
        rows.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.id.cmp(&b.id)));
        Ok(rows
            .into_iter()
            .map(|m| ModelOption {
                label: m.id.clone(),
                id: m.id,
            })
            .collect())
    }
}

/// Whether an OpenAI model ID names a text-generation model usable with the Responses API.
pub fn is_openai_text_model(id: &str) -> bool {
    const NOT_TEXT: &[&str] = &[
        "embedding", "tts", "whisper", "dall-e", "audio", "realtime", "transcribe",
        "image", "moderation", "search", "instruct", "babbage", "davinci",
    ];
    let id = id.to_ascii_lowercase();
    let family = id.starts_with("gpt-")
        || id.starts_with("chatgpt-")
        || (id.starts_with('o') && id[1..].starts_with(|c: char| c.is_ascii_digit()));
    family && !NOT_TEXT.iter().any(|word| id.contains(word))
}

/// Model requests billed to the signed-in user's ChatGPT plan. This route requires
/// `store: false` and `stream: true`, and only a `response.completed` event means success.
pub struct ChatGptPlanProvider {
    endpoint: Url,
    models_endpoint: Url,
}

impl Default for ChatGptPlanProvider {
    fn default() -> Self {
        Self {
            endpoint: Url::parse("https://api.openai.com/v1/responses").expect("valid URL"),
            models_endpoint: Url::parse("https://api.openai.com/v1/models").expect("valid URL"),
        }
    }
}

impl ChatGptPlanProvider {
    pub async fn generate(
        &self,
        access_token: &str,
        model: &str,
        system: &str,
        prompt: &str,
    ) -> Result<String, ResearchError> {
        let body = serde_json::json!({
            "model": model,
            "instructions": system,
            "input": [{"role": "user", "content": prompt}],
            "store": false,
            "stream": true
        });
        let mut headers = Self::headers(access_token)?;
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
        let client = Self::client(300, access_token)?;
        let response = client
            .post(self.endpoint.clone())
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                ResearchError::Unavailable(redact_secret(&format!("Network error: {e}"), access_token))
            })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|e| {
            ResearchError::Unavailable(redact_secret(&format!("Stream error: {e}"), access_token))
        })?;
        let text = String::from_utf8_lossy(&bytes);
        if !status.is_success() {
            return Err(chatgpt_plan_http_error(status.as_u16(), &text));
        }
        parse_responses_stream(&text)
    }

    /// Models offered to this account, in the server's order.
    pub async fn models(&self, access_token: &str) -> Result<Vec<ModelOption>, ResearchError> {
        let mut headers = Self::headers(access_token)?;
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let response = Self::client(30, access_token)?
            .get(self.models_endpoint.clone())
            .headers(headers)
            .send()
            .await
            .map_err(|e| {
                ResearchError::Unavailable(redact_secret(&format!("Network error: {e}"), access_token))
            })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|e| {
            ResearchError::Unavailable(redact_secret(&format!("Stream error: {e}"), access_token))
        })?;
        if !status.is_success() {
            return Err(chatgpt_plan_http_error(
                status.as_u16(),
                &String::from_utf8_lossy(&bytes),
            ));
        }
        #[derive(Deserialize)]
        struct ModelsEnvelope {
            models: Vec<ModelRow>,
        }
        #[derive(Deserialize)]
        struct ModelRow {
            slug: String,
            display_name: Option<String>,
            visibility: Option<String>,
        }
        let env: ModelsEnvelope = serde_json::from_slice(&bytes).map_err(|e| {
            ResearchError::InvalidResponse(format!("Invalid ChatGPT plan models response: {e}"))
        })?;
        Ok(env
            .models
            .into_iter()
            .filter(|m| m.visibility.as_deref() == Some("list"))
            .map(|m| ModelOption {
                label: m.display_name.unwrap_or_else(|| m.slug.clone()),
                id: m.slug,
            })
            .collect())
    }

    fn headers(access_token: &str) -> Result<HeaderMap, ResearchError> {
        let mut headers = HeaderMap::new();
        let bearer = HeaderValue::from_str(&format!("Bearer {}", access_token.trim())).map_err(|_| {
            ResearchError::InvalidResponse("ChatGPT access token contains invalid header characters.".to_string())
        })?;
        headers.insert(AUTHORIZATION, bearer);
        Ok(headers)
    }

    fn client(timeout_seconds: u64, access_token: &str) -> Result<reqwest::Client, ResearchError> {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .redirect(Policy::none())
            .build()
            .map_err(|e| {
                ResearchError::Unavailable(redact_secret(&format!("Transport error: {e}"), access_token))
            })
    }
}

/// Reads a Responses API server-sent event stream and returns the output text. Only a
/// `response.completed` event counts as success; a stream that ends without one has failed.
pub fn parse_responses_stream(stream: &str) -> Result<String, ResearchError> {
    #[derive(Deserialize)]
    struct Event {
        r#type: String,
        delta: Option<String>,
        response: Option<EventResponse>,
        code: Option<String>,
        message: Option<String>,
        param: Option<String>,
    }
    #[derive(Deserialize)]
    struct EventResponse {
        error: Option<ApiError>,
        incomplete_details: Option<IncompleteDetails>,
    }
    #[derive(Deserialize)]
    struct IncompleteDetails {
        reason: Option<String>,
    }

    let mut text = String::new();
    let mut data = String::new();
    // A blank line ends an event; the trailing "" flushes a final event with no blank line.
    for line in stream.lines().chain(std::iter::once("")) {
        if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
            continue;
        }
        if !line.is_empty() || data.is_empty() {
            continue;
        }
        let payload = std::mem::take(&mut data);
        if payload == "[DONE]" {
            continue;
        }
        let Ok(event) = serde_json::from_str::<Event>(&payload) else {
            continue;
        };
        match event.r#type.as_str() {
            "response.output_text.delta" => text.push_str(event.delta.as_deref().unwrap_or("")),
            "response.completed" => {
                let text = text.trim().to_string();
                if text.is_empty() {
                    return Err(ResearchError::InvalidResponse(
                        "The ChatGPT plan returned an empty response.".to_string(),
                    ));
                }
                return Ok(text);
            }
            "response.failed" => {
                let error = event.response.and_then(|r| r.error).unwrap_or_default();
                return Err(chatgpt_plan_error(None, &error));
            }
            "response.incomplete" => {
                let reason = event
                    .response
                    .and_then(|r| r.incomplete_details)
                    .and_then(|d| d.reason)
                    .unwrap_or_else(|| "unknown".to_string());
                return Err(ResearchError::InvalidResponse(format!(
                    "The ChatGPT plan response was incomplete ({reason})."
                )));
            }
            "error" => {
                let error = ApiError {
                    code: event.code,
                    message: event.message,
                    param: event.param,
                };
                return Err(chatgpt_plan_error(None, &error));
            }
            _ => {}
        }
    }
    Err(ResearchError::Unavailable(
        "The ChatGPT plan response ended before it completed.".to_string(),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct ApiError {
    code: Option<String>,
    message: Option<String>,
    param: Option<String>,
}

/// Maps an HTTP error from the ChatGPT plan route. Bodies are either the standard
/// `{"error": {...}}` object or `{"detail": "..."}` diagnostic text.
fn chatgpt_plan_http_error(status: u16, body: &str) -> ResearchError {
    #[derive(Deserialize)]
    struct Envelope {
        error: Option<ApiError>,
        detail: Option<String>,
    }
    let parsed = serde_json::from_str::<Envelope>(body).ok();
    let error = match parsed {
        Some(Envelope { error: Some(e), .. }) => e,
        Some(Envelope { detail, .. }) => ApiError {
            message: detail,
            ..ApiError::default()
        },
        None => ApiError::default(),
    };
    chatgpt_plan_error(Some(status), &error)
}

/// Plan-billing errors stop the run; the app never silently switches to another billing path.
fn chatgpt_plan_error(status: Option<u16>, error: &ApiError) -> ResearchError {
    let manage = crate::chatgpt::MANAGE_USAGE_URL;
    let code = error.code.as_deref().unwrap_or("");
    let detail = error.message.as_deref().unwrap_or("").chars().take(300).collect::<String>();
    let message = match (code, status) {
        ("subscription_sharing_usage_limit_exceeded", _) => format!(
            "Usage limit reached for your ChatGPT plan in this app. Manage usage at {manage}."
        ),
        ("subscription_sharing_user_not_eligible", _) => {
            "ChatGPT plan usage is not available for this account, workspace or policy. Choose another model provider.".to_string()
        }
        ("subscription_sharing_usage_unavailable", _)
        | ("subscription_sharing_user_unavailable", _)
        | (_, Some(503)) => {
            "ChatGPT plan usage is temporarily unavailable. Try again later.".to_string()
        }
        ("subscription_sharing_unsupported_capability", _) => format!(
            "The ChatGPT plan does not support part of this request ({}).",
            error.param.as_deref().unwrap_or("unspecified")
        ),
        (_, Some(401)) => format!(
            "The ChatGPT plan rejected this sign-in. Check the account in Sources & credentials. {detail}"
        ),
        (_, Some(403)) => format!("The ChatGPT plan refused this request. {detail}"),
        _ => format!("ChatGPT plan request failed ({code}). {detail}"),
    };
    let message = message.trim().to_string();
    match status {
        Some(s) => ResearchError::Http(s, message),
        None => ResearchError::Unavailable(message),
    }
}

async fn post_no_redirect(
    url: &Url,
    headers: HeaderMap,
    body: &serde_json::Value,
    secret_to_redact: &str,
) -> Result<Vec<u8>, ResearchError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .redirect(Policy::none())
        .build()
        .map_err(|e| {
            ResearchError::Unavailable(redact_secret(&format!("Transport error: {e}"), secret_to_redact))
        })?;

    let response = client
        .post(url.clone())
        .headers(headers)
        .json(body)
        .send()
        .await
        .map_err(|e| {
            ResearchError::Unavailable(redact_secret(&format!("Network error: {e}"), secret_to_redact))
        })?;

    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| {
            ResearchError::Unavailable(redact_secret(&format!("Stream error: {e}"), secret_to_redact))
        })?;

    if !status.is_success() {
        let preview: String = String::from_utf8_lossy(&bytes).chars().take(300).collect();
        return Err(ResearchError::Http(
            status.as_u16(),
            redact_secret(&preview, secret_to_redact),
        ));
    }
    Ok(bytes.to_vec())
}

async fn get_no_redirect(
    url: &Url,
    headers: HeaderMap,
    secret_to_redact: &str,
) -> Result<Vec<u8>, ResearchError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(Policy::none())
        .build()
        .map_err(|e| {
            ResearchError::Unavailable(redact_secret(&format!("Transport error: {e}"), secret_to_redact))
        })?;

    let response = client
        .get(url.clone())
        .headers(headers)
        .send()
        .await
        .map_err(|e| {
            ResearchError::Unavailable(redact_secret(&format!("Network error: {e}"), secret_to_redact))
        })?;

    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| {
            ResearchError::Unavailable(redact_secret(&format!("Stream error: {e}"), secret_to_redact))
        })?;

    if !status.is_success() {
        let preview: String = String::from_utf8_lossy(&bytes).chars().take(300).collect();
        return Err(ResearchError::Http(
            status.as_u16(),
            redact_secret(&preview, secret_to_redact),
        ));
    }
    Ok(bytes.to_vec())
}
