//! Which models each provider offers, which one runs, and the remembered choice.
//!
//! Model lists come live from each provider's API (cached), so the picker always shows the
//! models the user's key or ChatGPT plan can actually use. The last explicit choice is kept
//! in `preferences.json` next to `library.json`; "Automatic" runs it while its provider is
//! still set up, and otherwise the first set-up provider in [`ModelVendor::ALL`] order.

use crate::chatgpt::ChatGptAuth;
use crate::models::ResearchError;
use crate::providers::{
    ChatGptPlanProvider, ClaudeProvider, KeychainStore, ModelOption, ModelVendor, OpenAiProvider,
};
use crate::store::write_private_file;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const PREFERENCES_FILE: &str = "preferences.json";
const LIST_TTL: Duration = Duration::from_secs(60 * 60);
/// Failed lookups are retried sooner, but not on every page load.
const ERROR_TTL: Duration = Duration::from_secs(5 * 60);
const LIST_TIMEOUT: Duration = Duration::from_secs(10);

/// A provider and one of its models, written `vendor:model` in forms and preferences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelChoice {
    pub vendor: ModelVendor,
    pub model: String,
}

impl ModelChoice {
    pub fn encode(&self) -> String {
        format!("{}:{}", self.vendor.as_str(), self.model)
    }

    /// Parses `vendor:model`. Model IDs may themselves contain `:` (OpenAI fine-tunes).
    pub fn decode(raw: &str) -> Option<Self> {
        let (vendor, model) = raw.trim().split_once(':')?;
        let vendor = match vendor {
            "anthropic" => ModelVendor::Anthropic,
            "openai" => ModelVendor::OpenAi,
            "chatgpt" => ModelVendor::ChatGpt,
            _ => return None,
        };
        let model = model.trim();
        let valid = !model.is_empty()
            && model.len() <= 200
            && model
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._:/".contains(c));
        valid.then(|| Self {
            vendor,
            model: model.to_string(),
        })
    }

    pub fn describe(&self) -> String {
        format!("{} · {}", self.vendor.display_name(), self.model)
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Preferences {
    model: Option<String>,
}

#[derive(Clone)]
struct CachedList {
    result: Result<Vec<ModelOption>, String>,
    fetched_at: Instant,
}

/// The credentials needed to list and run models, borrowed from the app state.
pub struct ProviderAccess<'a> {
    pub keychain: &'a KeychainStore,
    pub chatgpt: &'a ChatGptAuth,
}

impl ProviderAccess<'_> {
    /// Whether the provider is set up (no network call).
    pub async fn ready(&self, vendor: ModelVendor) -> bool {
        match vendor.api_key_account() {
            Some(account) => self.keychain.get(account).is_some(),
            None => self.chatgpt.status().await.plan_usage,
        }
    }

    async fn list(&self, vendor: ModelVendor) -> Result<Vec<ModelOption>, ResearchError> {
        match vendor {
            ModelVendor::ChatGpt => {
                let token = self.chatgpt.access_token().await?;
                ChatGptPlanProvider::default().models(&token).await
            }
            ModelVendor::Anthropic => {
                let key = self.keychain.get("anthropic_api_key").unwrap_or_default();
                ClaudeProvider::default().models(&key).await
            }
            ModelVendor::OpenAi => {
                let key = self.keychain.get("openai_api_key").unwrap_or_default();
                OpenAiProvider::default().models(&key).await
            }
        }
    }
}

pub struct ModelCatalog {
    preferences_path: PathBuf,
    preferred: RwLock<Option<ModelChoice>>,
    cache: RwLock<HashMap<ModelVendor, CachedList>>,
    /// Messages for the next page view, e.g. that a rejected key was removed.
    notices: Mutex<Vec<String>>,
}

impl ModelCatalog {
    /// Loads the remembered choice from `data_dir`.
    pub fn new(data_dir: &Path) -> Self {
        let preferences_path = data_dir.join(PREFERENCES_FILE);
        let preferred = std::fs::read(&preferences_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Preferences>(&bytes).ok())
            .and_then(|p| p.model)
            .and_then(|raw| ModelChoice::decode(&raw));
        Self {
            preferences_path,
            preferred: RwLock::new(preferred),
            cache: RwLock::default(),
            notices: Mutex::default(),
        }
    }

    /// Messages to show on the next page view, oldest first.
    pub fn take_notices(&self) -> Vec<String> {
        self.notices
            .lock()
            .map(|mut notices| std::mem::take(&mut *notices))
            .unwrap_or_default()
    }

    /// Deletes a provider's saved API key after the provider rejected it (HTTP 401), but
    /// only while the saved key is still the one that was rejected, so a key saved in the
    /// meantime is kept. Returns the message to show.
    pub async fn forget_rejected_key(
        &self,
        keychain: &KeychainStore,
        vendor: ModelVendor,
        rejected_key: &str,
    ) -> String {
        let name = vendor.display_name();
        let Some(account) = vendor.api_key_account() else {
            return format!("{name} rejected the credentials.");
        };
        if keychain.get(account).as_deref() != Some(rejected_key.trim()) {
            return format!("{name} rejected an API key that has since been replaced.");
        }
        let message = match keychain.delete(account) {
            Ok(()) => format!(
                "{name} rejected the saved API key as invalid, so it was removed. Add a valid key in Sources & credentials."
            ),
            Err(e) => format!("{name} rejected the saved API key as invalid, but it could not be removed: {e}"),
        };
        self.invalidate(&[vendor]).await;
        if let Ok(mut notices) = self.notices.lock() {
            notices.push(message.clone());
        }
        message
    }

    pub async fn preferred(&self) -> Option<ModelChoice> {
        self.preferred.read().await.clone()
    }

    /// Remembers an explicit choice, or forgets it (`None`, for "Automatic").
    pub async fn remember(&self, choice: Option<&ModelChoice>) -> Result<(), ResearchError> {
        let mut preferred = self.preferred.write().await;
        if preferred.as_ref() == choice {
            return Ok(());
        }
        let payload = serde_json::to_vec_pretty(&Preferences {
            model: choice.map(ModelChoice::encode),
        })
        .map_err(|e| ResearchError::InvalidResponse(format!("Could not encode preferences: {e}")))?;
        write_private_file(&self.preferences_path, &payload)?;
        *preferred = choice.cloned();
        Ok(())
    }

    /// Drops cached lists, e.g. after keys change or a ChatGPT sign-in or sign-out.
    pub async fn invalidate(&self, vendors: &[ModelVendor]) {
        let mut cache = self.cache.write().await;
        for vendor in vendors {
            cache.remove(vendor);
        }
    }

    /// The provider's models, or `None` when it is not set up.
    pub async fn models(
        &self,
        access: &ProviderAccess<'_>,
        vendor: ModelVendor,
    ) -> Option<Result<Vec<ModelOption>, String>> {
        if !access.ready(vendor).await {
            return None;
        }
        if let Some(cached) = self.cache.read().await.get(&vendor) {
            let ttl = if cached.result.is_ok() { LIST_TTL } else { ERROR_TTL };
            if cached.fetched_at.elapsed() < ttl {
                return Some(cached.result.clone());
            }
        }
        let key_used = vendor
            .api_key_account()
            .and_then(|account| access.keychain.get(account));
        let result = match tokio::time::timeout(LIST_TIMEOUT, access.list(vendor)).await {
            Ok(Ok(list)) if list.is_empty() => Err("no models are available".to_string()),
            Ok(Ok(list)) => Ok(list),
            Ok(Err(ResearchError::InvalidCredential(_))) if key_used.is_some() => {
                let key = key_used.unwrap_or_default();
                return Some(Err(self.forget_rejected_key(access.keychain, vendor, &key).await));
            }
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("the provider did not respond in time".to_string()),
        };
        self.cache.write().await.insert(
            vendor,
            CachedList {
                result: result.clone(),
                fetched_at: Instant::now(),
            },
        );
        Some(result)
    }

    /// The model to use when only the provider was chosen: its recommended default if the
    /// account offers it (or the list is unavailable), else the first model listed.
    pub async fn default_model(
        &self,
        access: &ProviderAccess<'_>,
        vendor: ModelVendor,
    ) -> Result<String, ResearchError> {
        let listed = self.models(access, vendor).await;
        if let Some(Ok(ref list)) = listed {
            if let Some(default) = vendor
                .default_model()
                .filter(|d| list.iter().any(|m| m.id == *d))
            {
                return Ok(default.to_string());
            }
            if let Some(first) = list.first() {
                return Ok(first.id.clone());
            }
        }
        match (vendor.default_model(), listed) {
            (Some(default), Some(_)) => Ok(default.to_string()),
            (_, None) => Err(ResearchError::Unavailable(format!(
                "{} is not set up. Add it in Sources & credentials.",
                vendor.display_name()
            ))),
            (None, Some(Err(e))) => Err(ResearchError::Unavailable(format!(
                "Could not list {} models: {e}",
                vendor.display_name()
            ))),
            (None, Some(Ok(_))) => Err(ResearchError::Unavailable(format!(
                "{} offers no models.",
                vendor.display_name()
            ))),
        }
    }

    /// What "Automatic" runs: the remembered choice while its provider is still set up,
    /// otherwise the first set-up provider and its default model.
    pub async fn resolve_auto(
        &self,
        access: &ProviderAccess<'_>,
    ) -> Result<ModelChoice, ResearchError> {
        if let Some(choice) = self.preferred().await {
            if access.ready(choice.vendor).await {
                return Ok(choice);
            }
        }
        self.resolve_default(access).await
    }

    /// The first set-up provider and its default model, ignoring the remembered choice.
    pub async fn resolve_default(
        &self,
        access: &ProviderAccess<'_>,
    ) -> Result<ModelChoice, ResearchError> {
        for vendor in ModelVendor::ALL {
            if access.ready(vendor).await {
                return Ok(ModelChoice {
                    vendor,
                    model: self.default_model(access, vendor).await?,
                });
            }
        }
        Err(ResearchError::Unavailable(
            "Continue with ChatGPT, or add a Claude or OpenAI API key, in Sources & credentials first.".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choices_round_trip_and_reject_unsafe_values() {
        let choice = ModelChoice::decode("openai:ft:gpt-4o:org::abc123").expect("fine-tune id");
        assert_eq!(choice.vendor, ModelVendor::OpenAi);
        assert_eq!(choice.model, "ft:gpt-4o:org::abc123");
        assert_eq!(
            ModelChoice::decode(&choice.encode()).as_ref(),
            Some(&choice)
        );
        assert!(ModelChoice::decode("anthropic:claude-opus-5-5").is_some());
        assert!(ModelChoice::decode("auto").is_none());
        assert!(ModelChoice::decode("anthropic:").is_none());
        assert!(ModelChoice::decode("other:model").is_none());
        assert!(ModelChoice::decode("chatgpt:<script>").is_none());
    }

    #[tokio::test]
    async fn remembered_choice_persists_and_is_used_while_its_provider_is_set_up() {
        let dir = std::env::temp_dir().join(format!("catalog-test-{}", uuid::Uuid::new_v4()));
        let keychain = KeychainStore::in_memory();
        let chatgpt = ChatGptAuth::new(&dir);
        let access = ProviderAccess {
            keychain: &keychain,
            chatgpt: &chatgpt,
        };
        let catalog = ModelCatalog::new(&dir);
        assert!(catalog.resolve_auto(&access).await.is_err());

        let choice = ModelChoice::decode("openai:gpt-test").expect("choice");
        catalog.remember(Some(&choice)).await.expect("remember");
        assert_eq!(ModelCatalog::new(&dir).preferred().await, Some(choice.clone()));

        // Not used while OpenAI has no key.
        assert!(catalog.resolve_auto(&access).await.is_err());
        keychain.set("openai_api_key", "sk-test").expect("key");
        assert_eq!(catalog.resolve_auto(&access).await.expect("auto"), choice);

        catalog.remember(None).await.expect("forget");
        assert_eq!(ModelCatalog::new(&dir).preferred().await, None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
