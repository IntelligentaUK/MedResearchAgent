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
}

impl ModelVendor {
    pub fn parse(raw: &str) -> Self {
        if raw.trim().eq_ignore_ascii_case("openai") {
            ModelVendor::OpenAi
        } else {
            ModelVendor::Anthropic
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ModelVendor::Anthropic => "anthropic",
            ModelVendor::OpenAi => "openai",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ModelVendor::Anthropic => "Claude (Anthropic)",
            ModelVendor::OpenAi => "OpenAI",
        }
    }

    pub fn default_model(&self) -> &'static str {
        match self {
            ModelVendor::Anthropic => "claude-sonnet-4-6",
            ModelVendor::OpenAi => "gpt-5.4",
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
