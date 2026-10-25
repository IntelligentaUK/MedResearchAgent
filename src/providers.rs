use crate::models::{InstitutionalAccess, ResearchError};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::redirect::Policy;
use serde::Deserialize;
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

const KEYCHAIN_SERVICE: &str = "DementiaResearch";

#[derive(Clone, Default)]
pub struct KeychainStore {
    in_memory: Option<Arc<Mutex<HashMap<String, String>>>>,
}

impl KeychainStore {
    pub fn system() -> Self {
        Self { in_memory: None }
    }

    pub fn in_memory() -> Self {
        Self {
            in_memory: Some(Arc::new(Mutex::new(HashMap::new()))),
        }
    }

    pub fn get(&self, account: &str) -> Option<String> {
        if let Some(ref mem) = self.in_memory {
            return mem.lock().ok()?.get(account).cloned();
        }
        if cfg!(target_os = "macos") {
            let output = Command::new("/usr/bin/security")
                .args([
                    "find-generic-password",
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-a",
                    account,
                    "-w",
                ])
                .output()
                .ok()?;
            if output.status.success() {
                let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
        None
    }

    pub fn set(&self, account: &str, value: &str) -> Result<(), ResearchError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return self.delete(account);
        }
        if let Some(ref mem) = self.in_memory {
            if let Ok(mut guard) = mem.lock() {
                guard.insert(account.to_string(), trimmed.to_string());
            }
            return Ok(());
        }
        if cfg!(target_os = "macos") {
            let status = Command::new("/usr/bin/security")
                .args([
                    "add-generic-password",
                    "-U",
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-a",
                    account,
                    "-w",
                    trimmed,
                ])
                .status()
                .map_err(|e| ResearchError::Unavailable(format!("Keychain error: {e}")))?;
            if !status.success() {
                return Err(ResearchError::Unavailable(
                    "macOS Keychain rejected saving the credential.".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn delete(&self, account: &str) -> Result<(), ResearchError> {
        if let Some(ref mem) = self.in_memory {
            if let Ok(mut guard) = mem.lock() {
                guard.remove(account);
            }
            return Ok(());
        }
        if cfg!(target_os = "macos") {
            let _ = Command::new("/usr/bin/security")
                .args([
                    "delete-generic-password",
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-a",
                    account,
                ])
                .status();
        }
        Ok(())
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

pub fn redact_secret(text: &str, secret: &str) -> String {
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        return text.to_string();
    }
    text.replace(trimmed, "[redacted]")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelVendor {
    Anthropic,
    OpenAi,
    /// OpenAI models billed to the user's ChatGPT plan via "Sign in with ChatGPT".
    ChatGpt,
}

impl ModelVendor {
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

    /// `None` for the ChatGPT plan, whose models depend on the account and are listed live.
    pub fn default_model(&self) -> Option<&'static str> {
        match self {
            ModelVendor::Anthropic => Some("claude-sonnet-4-6"),
            ModelVendor::OpenAi => Some("gpt-5.4"),
            ModelVendor::ChatGpt => None,
        }
    }
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
        let body = serde_json::json!({
            "model": model,
            "max_tokens": 4096,
            "temperature": 0.2,
            "system": system,
            "messages": [{"role": "user", "content": prompt}]
        });
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            "anthropic-version",
            HeaderValue::from_static("2023-06-01"),
        );
        let key_header = HeaderValue::from_str(key).map_err(|_| {
            ResearchError::InvalidResponse("Claude API key contains invalid header characters.".to_string())
        })?;
        headers.insert("x-api-key", key_header);

        let data = post_no_redirect(&self.endpoint, headers, &body, key).await?;

        #[derive(Deserialize)]
        struct Response {
            content: Vec<Block>,
        }
        #[derive(Deserialize)]
        struct Block {
            r#type: String,
            text: Option<String>,
        }
        let parsed: Response = serde_json::from_slice(&data).map_err(|e| {
            ResearchError::InvalidResponse(format!("Claude returned an unreadable response: {e}"))
        })?;
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

    pub async fn models(&self, api_key: &str) -> Result<Vec<String>, ResearchError> {
        let key = api_key.trim();
        if key.is_empty() {
            return Err(ResearchError::Unavailable(
                "Add a Claude API key first.".to_string(),
            ));
        }
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            "anthropic-version",
            HeaderValue::from_static("2023-06-01"),
        );
        let key_header = HeaderValue::from_str(key).map_err(|_| {
            ResearchError::InvalidResponse("Claude API key contains invalid header characters.".to_string())
        })?;
        headers.insert("x-api-key", key_header);

        let data = get_no_redirect(&self.models_endpoint, headers, key).await?;
        #[derive(Deserialize)]
        struct ModelsEnvelope {
            data: Vec<ModelRow>,
        }
        #[derive(Deserialize)]
        struct ModelRow {
            id: String,
        }
        let env: ModelsEnvelope = serde_json::from_slice(&data).map_err(|e| {
            ResearchError::InvalidResponse(format!("Invalid Claude models response: {e}"))
        })?;
        Ok(env.data.into_iter().map(|m| m.id).collect())
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

    pub async fn models(&self, api_key: &str) -> Result<Vec<String>, ResearchError> {
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
        }
        let env: ModelsEnvelope = serde_json::from_slice(&data).map_err(|e| {
            ResearchError::InvalidResponse(format!("Invalid OpenAI models response: {e}"))
        })?;
        Ok(env.data.into_iter().map(|m| m.id).collect())
    }
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

    /// Model slugs offered to this account, in the server's order.
    pub async fn models(&self, access_token: &str) -> Result<Vec<String>, ResearchError> {
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
            visibility: Option<String>,
        }
        let env: ModelsEnvelope = serde_json::from_slice(&bytes).map_err(|e| {
            ResearchError::InvalidResponse(format!("Invalid ChatGPT plan models response: {e}"))
        })?;
        Ok(env
            .models
            .into_iter()
            .filter(|m| m.visibility.as_deref() == Some("list"))
            .map(|m| m.slug)
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
