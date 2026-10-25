use crate::agents::{
    AutonomousDiscoveryAgent, GenerateFn, HypothesisConnectionAgent, HypothesisValidationAgent,
    ProgressFn, RetrieveFn, SearchFn,
};
use crate::chatgpt::{CallbackParams, ChatGptAuth, ChatGptStatus, CALLBACK_PATH, MANAGE_USAGE_URL};
use crate::catalog::{JournalTier, ResearchSourceCatalog, WIDER_CORPUS_PAGE_SIZE};
use crate::datasets::CancerDatasetClient;
use crate::jobs::{JobRunner, JobSnapshot, JobStatus, JobUpdate, Progress};
use crate::literature::{FreeFullTextClient, FreeLiteratureSearchClient};
use crate::model_catalog::{ModelCatalog, ModelChoice, ProviderAccess};
use crate::models::{
    InstitutionalAccess, LibrarySnapshot, Paper, ResearchDomain, ResearchError,
};
use crate::providers::{
    check_credential_format, ChatGptPlanProvider, ClaudeProvider, KeychainStore, ModelOption,
    ModelVendor, OpenAiProvider, SecretBackend,
};
use crate::report::ResearchReportBuilder;
use crate::store::LibraryStore;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Form, Path, Query, State};
use axum::http::{ header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::Utc;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct AppState {
    pub store: LibraryStore,
    pub keychain: KeychainStore,
    pub chatgpt: ChatGptAuth,
    pub models: ModelCatalog,
    pub jobs: Arc<JobRunner>,
    pub library: RwLock<LibrarySnapshot>,
    pub csrf_token: String,
    /// The value of the session cookie that marks the owner's browser (see `SESSION_COOKIE`).
    pub session_token: String,
    /// The token in the start link printed at startup; opening it sets the session cookie.
    pub bootstrap_token: String,
    pub flash: RwLock<Option<String>>,
}

/// The cookie that identifies the browser the owner opened the start link in. Every page,
/// export and action needs it; without it the server answers 401. It is host-scoped by the
/// browser, so a page on another origin (even one whose DNS name resolves to this loopback
/// address) never carries it.
pub const SESSION_COOKIE: &str = "dementia_research_session";

/// 256 random bits from the OS, as hex.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl AppState {
    pub fn new(store: LibraryStore, keychain: KeychainStore) -> Result<Arc<Self>, ResearchError> {
        let library = store.load()?;
        let csrf_token = random_token();
        // ChatGPT credentials and preferences live next to library.json, outside it.
        let data_dir = store
            .path()
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        Ok(Arc::new(Self {
            store,
            keychain,
            chatgpt: ChatGptAuth::new(&data_dir),
            models: ModelCatalog::new(&data_dir),
            jobs: Arc::default(),
            library: RwLock::new(library),
            csrf_token,
            session_token: random_token(),
            bootstrap_token: random_token(),
            flash: RwLock::new(None),
        }))
    }

    /// The link that opens the workspace in the owner's browser and starts its session.
    pub fn start_link(&self, addr: &std::net::SocketAddr) -> String {
        format!("http://{addr}/?token={}", self.bootstrap_token)
    }

    /// The path prefix every private route is served under: `/s/<session token>`. A page
    /// on another port of this host never learns it (`Referrer-Policy: same-origin`), so a
    /// cookie leaked to such a page cannot be replayed on its own.
    pub fn session_prefix(&self) -> String {
        format!("/s/{}", self.session_token)
    }

    /// A private route's address. `rest` is relative to the workspace: `""`,
    /// `"?section=loop"` or `"export/library.json"`.
    pub fn private_path(&self, rest: &str) -> String {
        format!("{}/{rest}", self.session_prefix())
    }

    fn provider_access(&self) -> ProviderAccess<'_> {
        ProviderAccess {
            keychain: &self.keychain,
            chatgpt: &self.chatgpt,
        }
    }

    async fn set_flash(&self, msg: impl Into<String>) {
        let mut guard = self.flash.write().await;
        *guard = Some(msg.into());
    }

    async fn take_flash(&self) -> Option<String> {
        let mut guard = self.flash.write().await;
        guard.take()
    }
}

/// Where the workspace lives; the segment must equal the session token.
const SESSION_MOUNT: &str = "/s/{session}";

pub fn build_router(state: Arc<AppState>) -> Router {
    // Private routes are registered one by one under the session prefix (rather than
    // nested) so that the workspace root matches with its trailing slash, which the
    // page's `<base>` and every relative link rely on.
    let at = |rest: &str| format!("{SESSION_MOUNT}/{rest}");
    Router::new()
        .route("/", get(root_handler))
        .route("/static/app.css", get(stylesheet_handler))
        .route("/static/app.js", get(script_handler))
        .route(CALLBACK_PATH, get(chatgpt_callback_handler))
        .route(&at(""), get(index_handler))
        .route(&at("events"), get(events_handler))
        .route(&at("domain"), post(switch_domain_handler))
        .route(&at("objectives"), post(objectives_handler))
        .route(&at("queue/manual"), post(enqueue_manual_handler))
        .route(&at("literature/search"), post(literature_search_handler))
        .route(&at("papers/retrieve"), post(retrieve_paper_handler))
        .route(&at("datasets/discover"), post(discover_datasets_handler))
        .route(&at("loop/discover"), post(run_discovery_handler))
        .route(&at("loop/validate"), post(run_validation_handler))
        .route(&at("loop/connect"), post(run_connection_handler))
        .route(&at("credentials"), post(save_credentials_handler))
        .route(&at("chatgpt/sign-in"), post(chatgpt_sign_in_handler))
        .route(&at("chatgpt/sign-out"), post(chatgpt_sign_out_handler))
        .route(&at("chatgpt/welcome"), post(chatgpt_welcome_handler))
        .route(&at("export/library.md"), get(export_library_md_handler))
        .route(&at("export/library.txt"), get(export_library_txt_handler))
        .route(&at("export/library.json"), get(export_library_json_handler))
        .route(&at("export/paper/{id}"), get(export_paper_md_handler))
        .route(&at("export/validation/{id}"), get(export_validation_md_handler))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            request_guard_middleware,
        ))
        .with_state(state)
}

/// Checks every request before it reaches a handler, then adds the security headers to
/// every response:
/// 1. the `Host` must be this server's loopback address (no DNS-rebound names);
/// 2. apart from the start page, stylesheet, script and OAuth callback, the request must be
///    under the session path and carry the session cookie, both of which only the start
///    link establishes;
/// 3. a `POST` must come from this origin.
async fn request_guard_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let mut res = guard_request(&state, req, next).await;
    apply_security_headers(&mut res);
    res
}

async fn guard_request(state: &AppState, req: Request<Body>, next: Next) -> Response {
    if loopback_authority(req.headers()).is_none() {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            "This server only answers requests addressed to its loopback address.",
        )
            .into_response();
    }
    let path = req.uri().path();
    // The start page checks the start-link token itself; the stylesheet and script hold
    // nothing private; the OAuth callback is bound to the pending sign-in by its `state`
    // value and may arrive without the cookie when the sign-in was started from
    // `localhost` rather than `127.0.0.1`.
    if path == "/" || path.starts_with("/static/") || path == CALLBACK_PATH {
        return next.run(req).await;
    }
    // Everything else is the workspace: the session path and the session cookie are both
    // required, so neither a leaked cookie nor a leaked address is enough on its own.
    let path_ok = session_segment(path).is_some_and(|s| verify_csrf(&state.session_token, s));
    if !path_ok || !has_session_cookie(req.headers(), &state.session_token) {
        return unauthorized_response(req.method());
    }
    if req.method() == Method::POST && !same_origin_allowed(req.headers()) {
        return (
            StatusCode::FORBIDDEN,
            "Cross-origin state-changing requests are forbidden.",
        )
            .into_response();
    }
    next.run(req).await
}

/// The session token segment of a workspace path (`/s/<token>/...`).
fn session_segment(path: &str) -> Option<&str> {
    path.strip_prefix("/s/")
        .map(|rest| rest.split('/').next().unwrap_or(""))
}

#[derive(Deserialize, Default)]
struct StartQuery {
    token: Option<String>,
}

/// The start page: with the start link's token it begins the owner's session; anything
/// else is told where the start link is.
async fn root_handler(State(state): State<Arc<AppState>>, Query(query): Query<StartQuery>) -> Response {
    match query.token {
        Some(token) if verify_csrf(&state.bootstrap_token, &token) => start_session_response(&state),
        _ => unauthorized_response(&Method::GET),
    }
}

/// Sets the session cookie and sends the browser to the workspace, under the session path,
/// without the start-link token in its address bar or history.
fn start_session_response(state: &AppState) -> Response {
    let mut res = Redirect::to(&state.private_path("")).into_response();
    let cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Lax",
        state.session_token
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        res.headers_mut().insert(header::SET_COOKIE, value);
    }
    res
}

fn unauthorized_response(method: &Method) -> Response {
    if method == Method::GET {
        let page = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Medical Research Agent</title>
<link rel="stylesheet" href="/static/app.css"></head>
<body><main class="content">
<h1>Open the app from its start link</h1>
<p>The workspace is only shown to the browser that opened the start link printed in the
terminal when the app started, at the address that link leads to. Copy that link (it ends in <code>?token=…</code>) into
this browser, or restart the app to print a new one.</p>
</main></body></html>"#;
        (StatusCode::UNAUTHORIZED, Html(page)).into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "This request needs the session cookie set by the app's start link.",
        )
            .into_response()
    }
}

/// Whether a `Cookie` header carries the session cookie with the expected value.
pub fn has_session_cookie(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .any(|(name, value)| name.trim() == SESSION_COOKIE && verify_csrf(expected, value.trim()))
}

fn apply_security_headers(res: &mut Response) {
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://auth.openai.com",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    // `same-origin` rather than `no-referrer`: under `no-referrer` browsers send `Origin: null`
    // on form submissions, which `same_origin_allowed` (correctly) rejects. External links
    // still receive no referrer.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    headers.insert(
        "Cross-Origin-Opener-Policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "Cross-Origin-Resource-Policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
}

/// Whether a `POST` comes from a page this server served: `Sec-Fetch-Site` must be
/// `same-origin` (or `none`, a direct navigation), and `Origin`, when sent, must be a
/// plain-HTTP loopback origin (`127.0.0.1`, `localhost` or `[::1]`, any port).
pub fn same_origin_allowed(headers: &HeaderMap) -> bool {
    if let Some(sec_site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if !matches!(sec_site, "same-origin" | "none") {
            return false;
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let allowed = url::Url::parse(origin)
            .ok()
            .is_some_and(|u| u.scheme() == "http" && is_loopback_host(&u));
        if !allowed {
            return false;
        }
    }
    true
}

fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// The port of a request's `Host` header when that header names a loopback address;
/// `None` for any other authority (including a DNS name an attacker pointed at loopback).
pub fn loopback_authority(headers: &HeaderMap) -> Option<u16> {
    let mut hosts = headers.get_all(header::HOST).iter();
    let host = hosts.next()?.to_str().ok()?;
    if hosts.next().is_some() {
        // Two `Host` headers: an ambiguous request is not a loopback one.
        return None;
    }
    let url = url::Url::parse(&format!("http://{host}")).ok()?;
    is_loopback_host(&url).then(|| url.port().unwrap_or(80))
}

pub fn verify_csrf(expected: &str, supplied: &str) -> bool {
    let a = expected.as_bytes();
    let b = supplied.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

fn safe_https_href(url: &url::Url) -> String {
    if url.scheme() == "https" {
        html_escape(url.as_str())
    } else {
        "#".to_string()
    }
}

#[derive(Deserialize, Default)]
pub struct WorkspaceQuery {
    pub section: Option<String>,
}

/// The workspace. A `GET` never changes anything: the research field is switched only by
/// the CSRF-protected `POST /domain`.
async fn index_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WorkspaceQuery>,
) -> Html<String> {
    let section = query.section.as_deref().unwrap_or("loop");
    // Built before taking the library lock: listing models can wait on the network.
    let model_picker = if is_loop_section(section) {
        render_model_picker(&state).await
    } else {
        String::new()
    };
    let mut messages = state.models.take_notices();
    messages.extend(state.take_flash().await);
    let flash = (!messages.is_empty()).then(|| messages.join(" "));
    let access = state.keychain.institutional_access();
    let has_claude_key = state.keychain.get("anthropic_api_key").is_some();
    let has_openai_key = state.keychain.get("openai_api_key").is_some();
    let chatgpt = state.chatgpt.status().await;
    let jobs = state.jobs.all_latest();
    let lib = state.library.read().await;

    Html(render_workspace(
        &lib,
        &state.private_path(""),
        section,
        &state.csrf_token,
        flash.as_deref(),
        &access,
        has_claude_key,
        has_openai_key,
        &chatgpt,
        state.keychain.backend(),
        &model_picker,
        &jobs,
    ))
}

/// The research loop is the default page for any section name not listed here.
fn is_loop_section(section: &str) -> bool {
    !matches!(
        section,
        "library" | "queue" | "validations" | "datasets" | "cycles" | "sources" | "connections"
    )
}

/// The model picker: "Automatic" plus each set-up provider's live model list.
async fn render_model_picker(state: &Arc<AppState>) -> String {
    let access = state.provider_access();
    let (chatgpt_models, claude_models, openai_models) = tokio::join!(
        state.models.models(&access, ModelVendor::ChatGpt),
        state.models.models(&access, ModelVendor::Anthropic),
        state.models.models(&access, ModelVendor::OpenAi),
    );
    let preferred = state.models.preferred().await;
    let current = state.models.resolve_auto(&access).await;
    let automatic = state.models.resolve_default(&access).await;

    let mut groups = String::new();
    let mut notes = Vec::new();
    let mut not_set_up = Vec::new();
    let mut preferred_listed = false;
    for (vendor, listed) in [
        (ModelVendor::ChatGpt, chatgpt_models),
        (ModelVendor::Anthropic, claude_models),
        (ModelVendor::OpenAi, openai_models),
    ] {
        let options: Vec<ModelOption> = match listed {
            None => {
                not_set_up.push(vendor.display_name());
                continue;
            }
            Some(Ok(list)) => list,
            Some(Err(e)) => {
                notes.push(format!("Could not list {} models: {e}", vendor.display_name()));
                match vendor.default_model() {
                    Some(d) => vec![ModelOption {
                        id: d.to_string(),
                        label: format!("{d} (default)"),
                    }],
                    None => continue,
                }
            }
        };
        let mut option_html = String::new();
        for option in options {
            let choice = ModelChoice {
                vendor,
                model: option.id,
            };
            let selected = preferred.as_ref() == Some(&choice);
            preferred_listed |= selected;
            option_html.push_str(&format!(
                r#"<option value="{}"{}>{}</option>"#,
                html_escape(&choice.encode()),
                if selected { " selected" } else { "" },
                html_escape(&option.label)
            ));
        }
        let group = match vendor {
            ModelVendor::ChatGpt => "ChatGPT plan (Sign in with ChatGPT)",
            ModelVendor::Anthropic => "Claude (Anthropic API key)",
            ModelVendor::OpenAi => "OpenAI (API key)",
        };
        groups.push_str(&format!(
            r#"<optgroup label="{}">{option_html}</optgroup>"#,
            html_escape(group)
        ));
    }
    if !not_set_up.is_empty() {
        notes.push(format!(
            "Not set up: {}. Add them in Sources & credentials.",
            not_set_up.join(", ")
        ));
    }

    let automatic_label = match &automatic {
        Ok(choice) => format!("Automatic ({})", choice.describe()),
        Err(_) => "Automatic".to_string(),
    };
    let current_line = match &current {
        Ok(choice) => format!(
            "Validation and connection review use {}.",
            html_escape(&choice.describe())
        ),
        Err(e) => html_escape(&e.to_string()),
    };
    let plan_status = if matches!(&current, Ok(c) if c.vendor == ModelVendor::ChatGpt) {
        format!(
            r#" · Using ChatGPT plan · <a href="{MANAGE_USAGE_URL}" rel="noopener noreferrer" target="_blank">Manage usage</a>"#
        )
    } else {
        String::new()
    };
    let notes_html: String = notes
        .iter()
        .map(|n| format!(r#"<p class="caption">{}</p>"#, html_escape(n)))
        .collect();
    format!(
        r#"<label>Model
              <select name="vendor">
                <option value="automatic"{}>{}</option>
                {groups}
              </select>
            </label>
            <p class="caption">{current_line}{plan_status}</p>
            {notes_html}"#,
        if preferred_listed { "" } else { " selected" },
        html_escape(&automatic_label)
    )
}

#[derive(Deserialize)]
struct DomainForm {
    csrf_token: String,
    domain: String,
    section: Option<String>,
}

async fn switch_domain_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<DomainForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let domain = if form.domain.eq_ignore_ascii_case("cancer") {
        ResearchDomain::Cancer
    } else {
        ResearchDomain::Dementia
    };
    {
        let mut lib = state.library.write().await;
        lib.pipeline.select_domain(domain);
        let _ = state.store.save(&lib);
    }
    let sec = form.section.as_deref().unwrap_or("loop");
    Redirect::to(&state.private_path(&format!("?section={}", urlencoding::encode(sec)))).into_response()
}

#[derive(Deserialize)]
struct ObjectiveForm {
    csrf_token: String,
    action: String,
    text: String,
}

async fn objectives_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ObjectiveForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let mut lib = state.library.write().await;
    let domain = lib.pipeline.settings.domain();
    if form.action == "remove" {
        lib.pipeline.remove_objective(&form.text, domain);
        state.set_flash("Removed research objective.").await;
    } else {
        lib.pipeline.enqueue_objective(&form.text, domain);
        state.set_flash("Added research objective to queue.").await;
    }
    let _ = state.store.save(&lib);
    Redirect::to(&state.private_path("?section=loop")).into_response()
}

#[derive(Deserialize)]
struct ManualHypothesisForm {
    csrf_token: String,
    title: String,
    statement: String,
}

async fn enqueue_manual_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ManualHypothesisForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let mut lib = state.library.write().await;
    let domain = lib.pipeline.settings.domain();
    match LibraryStore::enqueue_manual_hypothesis(&mut lib, &form.title, &form.statement, domain) {
        Ok(id) => {
            let _ = state.store.save(&lib);
            state
                .set_flash(format!("Queued hypothesis {id} for independent validation."))
                .await;
        }
        Err(e) => {
            state.set_flash(format!("Could not queue hypothesis: {e}")).await;
        }
    }
    Redirect::to(&state.private_path("?section=queue")).into_response()
}

#[derive(Deserialize)]
struct LiteratureSearchForm {
    csrf_token: String,
    query: String,
}

async fn literature_search_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LiteratureSearchForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let domain = state.library.read().await.pipeline.settings.domain();
    let access = state.keychain.institutional_access();
    let client = FreeLiteratureSearchClient::default();
    match client.search(&form.query, domain, &access).await {
        Ok(res) => {
            let count = res.papers.len();
            let mut lib = state.library.write().await;
            for p in res.papers {
                lib.upsert_paper(p, domain);
            }
            // Metadata may have changed under existing citations.
            LibraryStore::reverify_all_citations(&mut lib);
            lib.pipeline.record(format!(
                "Literature search '{}' returned {count} deduplicated eligible records.",
                form.query.trim()
            ));
            let _ = state.store.save(&lib);
            state
                .set_flash(format!(
                    "Saved {count} eligible open-access or author-manuscript records to the {} evidence library.",
                    domain.display_name()
                ))
                .await;
        }
        Err(e) => {
            state.set_flash(format!("Literature search failed: {e}")).await;
        }
    }
    Redirect::to(&state.private_path("?section=library")).into_response()
}

#[derive(Deserialize)]
struct RetrievePaperForm {
    csrf_token: String,
    paper_id: String,
}

async fn retrieve_paper_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<RetrievePaperForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let (paper_opt, domain) = {
        let lib = state.library.read().await;
        (
            lib.papers.iter().find(|p| p.id == form.paper_id).cloned(),
            lib.pipeline.settings.domain(),
        )
    };
    let Some(mut paper) = paper_opt else {
        state.set_flash("Paper ID not found in library.").await;
        return Redirect::to(&state.private_path("?section=library")).into_response();
    };
    let access = state.keychain.institutional_access();
    let ft_client = FreeFullTextClient::default();
    match ft_client.full_text(&paper, &access).await {
        Ok(article) => {
            let count = article.passages.len();
            let fmt = article.format.clone();
            paper.full_text = Some(article);
            let mut lib = state.library.write().await;
            lib.upsert_paper(paper, domain);
            LibraryStore::reverify_all_citations(&mut lib);
            let _ = state.store.save(&lib);
            state
                .set_flash(format!(
                    "Retrieved {count} structured article-body passages ({fmt}) for {}.",
                    form.paper_id
                ))
                .await;
        }
        Err(e) => {
            state
                .set_flash(format!("Full-text retrieval failed for {}: {e}", form.paper_id))
                .await;
        }
    }
    Redirect::to(&state.private_path("?section=library")).into_response()
}

#[derive(Deserialize)]
struct DatasetDiscoverForm {
    csrf_token: String,
    query: String,
}

async fn discover_datasets_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<DatasetDiscoverForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let client = CancerDatasetClient::default();
    match client
        .discover(&form.query, ResearchDomain::Cancer, 8)
        .await
    {
        Ok(res) => {
            let count = res.records.len();
            let mut lib = state.library.write().await;
            LibraryStore::merge_datasets(&mut lib, res.records);
            lib.pipeline.record(format!(
                "Discovered {count} public cancer dataset catalog records for '{}'.",
                form.query.trim()
            ));
            let _ = state.store.save(&lib);
            state
                .set_flash(format!(
                    "Discovered {count} public NCI GDC & cBioPortal dataset metadata records."
                ))
                .await;
        }
        Err(e) => {
            state
                .set_flash(format!("Dataset catalog lookup failed: {e}"))
                .await;
        }
    }
    Redirect::to(&state.private_path("?section=datasets")).into_response()
}

#[derive(Deserialize)]
struct RunAgentForm {
    csrf_token: String,
    vendor: String,
    model: Option<String>,
    objective: Option<String>,
    hypothesis_id: Option<String>,
}

struct ModelSelection {
    vendor: ModelVendor,
    model: String,
    generate: GenerateFn<'static>,
}

/// Resolves the picker's value into a provider, model and generator for an agent run:
/// `vendor:model` (remembered for "Automatic"), `automatic` (forget the remembered choice),
/// `auto` (the remembered choice, else the first set-up provider), or a bare vendor.
async fn select_model(
    state: &Arc<AppState>,
    raw: &str,
    model: Option<&str>,
) -> Result<ModelSelection, ResearchError> {
    let access = state.provider_access();
    let raw = raw.trim();
    let choice = if raw.is_empty() || raw == "auto" {
        state.models.resolve_auto(&access).await?
    } else if raw == "automatic" {
        state.models.remember(None).await?;
        state.models.resolve_auto(&access).await?
    } else if let Some(choice) = ModelChoice::decode(raw) {
        state.models.remember(Some(&choice)).await?;
        choice
    } else {
        let vendor = ModelVendor::parse(raw);
        let model = match model.map(str::trim).filter(|m| !m.is_empty()) {
            Some(m) => m.to_string(),
            None => state.models.default_model(&access, vendor).await?,
        };
        ModelChoice { vendor, model }
    };
    if !access.ready(choice.vendor).await {
        return Err(ResearchError::Unavailable(format!(
            "{} is not set up. Add it in Sources & credentials, or choose another model.",
            choice.vendor.display_name()
        )));
    }

    let ModelChoice { vendor, model } = choice;
    let m = model.clone();
    let provider_call: GenerateFn<'static> = match vendor {
        ModelVendor::ChatGpt => {
            let app = Arc::clone(state);
            Box::new(move |sys, prompt| {
                let app = Arc::clone(&app);
                let m = m.clone();
                Box::pin(async move {
                    // Fetched per request so long runs pick up refreshed tokens.
                    let token = app.chatgpt.access_token().await?;
                    ChatGptPlanProvider::default()
                        .generate(&token, &m, &sys, &prompt)
                        .await
                })
            })
        }
        ModelVendor::Anthropic | ModelVendor::OpenAi => {
            let key = vendor
                .api_key_account()
                .and_then(|account| state.keychain.get(account))
                .unwrap_or_default();
            let app = Arc::clone(state);
            Box::new(move |sys, prompt| {
                let k = key.clone();
                let m = m.clone();
                let app = Arc::clone(&app);
                Box::pin(async move {
                    let result = match vendor {
                        ModelVendor::OpenAi => {
                            OpenAiProvider::default().generate(&k, &m, &sys, &prompt).await
                        }
                        _ => ClaudeProvider::default().generate(&k, &m, &sys, &prompt).await,
                    };
                    match result {
                        Err(ResearchError::InvalidCredential(_)) => Err(ResearchError::Unavailable(
                            app.models
                                .forget_rejected_key(&app.keychain, vendor, &k)
                                .await,
                        )),
                        other => other,
                    }
                })
            })
        }
    };
    Ok(ModelSelection {
        vendor,
        model,
        generate: budgeted_generate(Arc::clone(state), provider_call),
    })
}

/// Wraps a provider call so that every attempted model request, including structured-output
/// repairs, is counted against the daily budget before it is sent. The count is saved with
/// the library, so it survives a restart.
pub fn budgeted_generate(app: Arc<AppState>, inner: GenerateFn<'static>) -> GenerateFn<'static> {
    let inner = Arc::new(inner);
    Box::new(move |system, prompt| {
        let app = Arc::clone(&app);
        let inner = Arc::clone(&inner);
        Box::pin(async move {
            {
                let mut lib = app.library.write().await;
                lib.pipeline.reserve_model_request(Utc::now())?;
                let _ = app.store.save(&lib);
            }
            // The provider is asked only once the request has been admitted.
            inner(system, prompt).await
        })
    })
}

/// Why a stage cannot start when the day's model budget is already used up.
fn budget_message(lib: &LibrarySnapshot, stage: &str) -> Option<String> {
    (!lib.pipeline.model_budget_available(Utc::now()))
        .then(|| format!("Cannot start {stage}: {}", ResearchError::BudgetExhausted))
}

#[derive(Deserialize)]
struct ChatGptActionForm {
    csrf_token: String,
    section: Option<String>,
    enable_plan: Option<String>,
}

/// "Continue with ChatGPT": sends the browser to OpenAI, which redirects back to
/// `CALLBACK_PATH` on this server's loopback port.
async fn chatgpt_sign_in_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ChatGptActionForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let Some(port) = loopback_authority(&headers) else {
        state
            .set_flash("Sign in with ChatGPT from a browser on the computer running this app (http://127.0.0.1).")
            .await;
        return Redirect::to(&state.private_path("?section=sources")).into_response();
    };
    match state
        .chatgpt
        .begin_sign_in(port, form.enable_plan.is_some())
        .await
    {
        Ok(url) => Redirect::to(url.as_str()).into_response(),
        Err(e) => {
            state.set_flash(format!("Could not start ChatGPT sign-in: {e}")).await;
            Redirect::to(&state.private_path("?section=sources")).into_response()
        }
    }
}

async fn chatgpt_callback_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CallbackParams>,
) -> Response {
    let completed = state.chatgpt.complete_sign_in(params).await;
    state.models.invalidate(&[ModelVendor::ChatGpt]).await;
    let message = match completed {
        Ok(status) => {
            let who = status.email.as_deref().unwrap_or("your ChatGPT account");
            if status.plan_usage {
                format!("Signed in with ChatGPT as {who}. Using ChatGPT plan.")
            } else {
                format!(
                    "Signed in with ChatGPT as {who}, but ChatGPT plan usage was not granted. Choose Use your ChatGPT plan to enable it, or use an API key."
                )
            }
        }
        Err(e) => format!("ChatGPT sign-in did not complete: {e}"),
    };
    state.set_flash(message).await;
    Redirect::to(&state.private_path("?section=sources")).into_response()
}

async fn chatgpt_sign_out_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ChatGptActionForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let signed_out = state.chatgpt.sign_out().await;
    state.models.invalidate(&[ModelVendor::ChatGpt]).await;
    let message = match signed_out {
        Ok(true) => "Signed out of ChatGPT.".to_string(),
        Ok(false) => "Signed out of ChatGPT on this computer, but OpenAI did not confirm the session was revoked. You can disconnect the app in ChatGPT settings.".to_string(),
        Err(e) => format!("ChatGPT sign-out failed: {e}"),
    };
    state.set_flash(message).await;
    Redirect::to(&state.private_path("?section=sources")).into_response()
}

async fn chatgpt_welcome_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ChatGptActionForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    if let Err(e) = state.chatgpt.dismiss_welcome().await {
        state.set_flash(format!("Could not save that setting: {e}")).await;
    }
    let section = form
        .section
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase()))
        .unwrap_or_else(|| "loop".to_string());
    Redirect::to(&state.private_path(&format!("?section={section}"))).into_response()
}

/// Where to send the browser back to: the workspace section it came from (same-origin
/// `Referer`), else `fallback`.
fn back_to(state: &AppState, headers: &HeaderMap, fallback: &str) -> String {
    let workspace = state.private_path("");
    let section = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| url::Url::parse(raw).ok())
        .filter(|u| u.path() == workspace)
        .and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "section")
                .map(|(_, v)| v.into_owned())
        })
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase()));
    state.private_path(&format!("?section={}", section.as_deref().unwrap_or(fallback)))
}

/// Literature search and full-text retrieval for an agent, reporting each step.
fn literature_tools(
    domain: ResearchDomain,
    access: &InstitutionalAccess,
    progress: &Progress,
) -> (SearchFn<'static>, RetrieveFn<'static>) {
    let (search_access, retrieve_access) = (access.clone(), access.clone());
    let (search_progress, retrieve_progress) = (progress.clone(), progress.clone());
    let search: SearchFn<'static> = Box::new(move |query| {
        let acc = search_access.clone();
        let progress = search_progress.clone();
        Box::pin(async move {
            progress.report(format!("Searching the literature: {query}"));
            let result = FreeLiteratureSearchClient::default()
                .search(&query, domain, &acc)
                .await;
            match &result {
                Ok(found) => progress.report(format!("Found {} records", found.papers.len())),
                Err(e) => progress.report(format!("Search failed: {e}")),
            }
            result
        })
    });
    let retrieve: RetrieveFn<'static> = Box::new(move |paper| {
        let acc = retrieve_access.clone();
        let progress = retrieve_progress.clone();
        Box::pin(async move {
            let title: String = paper.title.chars().take(120).collect();
            progress.report(format!("Reading full text: {title}"));
            let result = FreeFullTextClient::default().full_text(&paper, &acc).await;
            if let Err(e) = &result {
                progress.report(format!("Full text unavailable: {e}"));
            }
            result
        })
    });
    (search, retrieve)
}

fn progress_fn(progress: &Progress) -> ProgressFn<'static> {
    let progress = progress.clone();
    Box::new(move |message| progress.report(message))
}

/// Flashes why a stage could not start, or nothing when it did, and returns to the page.
async fn after_start(
    state: &AppState,
    started: Result<u64, String>,
    headers: &HeaderMap,
    fallback: &str,
) -> Response {
    if let Err(e) = started {
        state.set_flash(e).await;
    }
    Redirect::to(&back_to(state, headers, fallback)).into_response()
}

async fn run_discovery_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<RunAgentForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let selection = match select_model(&state, &form.vendor, form.model.as_deref()).await {
        Ok(selection) => selection,
        Err(e) => {
            state.set_flash(format!("Cannot start discovery: {e}")).await;
            return Redirect::to(&back_to(&state, &headers, "loop")).into_response();
        }
    };
    let requested_objective = form.objective.clone().filter(|s| !s.trim().is_empty());
    let domain = state.library.read().await.pipeline.settings.domain();
    let app = Arc::clone(&state);
    let title = format!("Discovery cycle · {}", selection.model);
    let started = state.jobs.start(domain, title, "cycles", move |progress| async move {
        let ModelSelection {
            vendor,
            model,
            generate,
        } = selection;
        let (prev_statements, objective) = {
            let lib = app.library.read().await;
            if let Some(message) = budget_message(&lib, "discovery") {
                return Err(message);
            }
            let prev: Vec<String> = lib
                .pipeline
                .queue
                .iter()
                .filter(|q| q.domain() == domain)
                .map(|q| q.draft.statement.clone())
                .collect();
            let obj = requested_objective
                .or_else(|| lib.pipeline.objectives(domain).into_iter().next());
            (prev, obj)
        };
        progress.report(format!("Using {} · {model}", vendor.display_name()));
        let access = app.keychain.institutional_access();
        let (search, retrieve) = literature_tools(domain, &access, &progress);
        let agent = AutonomousDiscoveryAgent {
            generate,
            search,
            retrieve,
            progress: progress_fn(&progress),
            access,
        };
        let cycle = agent
            .discover(
                objective.as_deref(),
                &prev_statements,
                vendor.display_name(),
                &model,
                domain,
                "",
            )
            .await
            .map_err(|e| format!("Discovery cycle failed: {e}"))?;
        let count = cycle.hypotheses.len();
        let mut lib = app.library.write().await;
        LibraryStore::complete_discovery(&mut lib, cycle, Vec::new());
        app.store
            .save(&lib)
            .map_err(|e| format!("Discovery finished but could not be saved: {e}"))?;
        Ok(format!(
            "Discovery cycle completed: {count} grounded hypotheses added to the validation queue."
        ))
    });
    after_start(&state, started, &headers, "loop").await
}

async fn run_validation_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<RunAgentForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let target_item = {
        let lib = state.library.read().await;
        let d = lib.pipeline.settings.domain();
        if let Some(ref raw_id) = form.hypothesis_id {
            Uuid::parse_str(raw_id)
                .ok()
                .and_then(|id| lib.pipeline.queue.iter().find(|q| q.id == id).cloned())
        } else {
            lib.pipeline
                .queue
                .iter()
                .find(|q| q.domain() == d && q.validation_id.is_none())
                .cloned()
        }
    };
    let Some(target_item) = target_item else {
        state
            .set_flash("No queued hypothesis found to validate.")
            .await;
        return Redirect::to(&back_to(&state, &headers, "queue")).into_response();
    };
    let selection = match select_model(&state, &form.vendor, form.model.as_deref()).await {
        Ok(selection) => selection,
        Err(e) => {
            state.set_flash(format!("Cannot start validation: {e}")).await;
            return Redirect::to(&back_to(&state, &headers, "queue")).into_response();
        }
    };
    let app = Arc::clone(&state);
    let title = format!(
        "Validation · {}",
        target_item.draft.title.chars().take(80).collect::<String>()
    );
    let domain = target_item.domain();
    let started = state.jobs.start(domain, title, "validations", move |progress| async move {
        let ModelSelection {
            vendor,
            model,
            generate,
        } = selection;
        let supplied_papers = {
            let lib = app.library.read().await;
            if let Some(message) = budget_message(&lib, "validation") {
                return Err(message);
            }
            lib.research_papers(domain)
        };
        progress.report(format!("Using {} · {model}", vendor.display_name()));
        let access = app.keychain.institutional_access();
        let (search, retrieve) = literature_tools(domain, &access, &progress);
        let agent = HypothesisValidationAgent {
            generate,
            search,
            retrieve,
            progress: progress_fn(&progress),
            access,
        };
        let validation = agent
            .validate(
                &target_item,
                &supplied_papers,
                vendor.display_name(),
                &model,
                domain,
                "",
            )
            .await
            .map_err(|e| format!("Validation failed: {e}"))?;
        let label = validation.verdict.label();
        let mut lib = app.library.write().await;
        LibraryStore::complete_validation(&mut lib, validation, Vec::new());
        app.store
            .save(&lib)
            .map_err(|e| format!("Validation finished but could not be saved: {e}"))?;
        Ok(format!("Validation completed: {label}."))
    });
    after_start(&state, started, &headers, "queue").await
}

async fn run_connection_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<RunAgentForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let selection = match select_model(&state, &form.vendor, form.model.as_deref()).await {
        Ok(selection) => selection,
        Err(e) => {
            state
                .set_flash(format!("Cannot start connection review: {e}"))
                .await;
            return Redirect::to(&back_to(&state, &headers, "connections")).into_response();
        }
    };
    let domain = state.library.read().await.pipeline.settings.domain();
    let app = Arc::clone(&state);
    let title = format!("Connection review · {}", selection.model);
    let started = state.jobs.start(domain, title, "connections", move |progress| async move {
        let ModelSelection {
            vendor,
            model,
            generate,
        } = selection;
        let (items, validations, papers, offset) = {
            let lib = app.library.read().await;
            if let Some(message) = budget_message(&lib, "connection review") {
                return Err(message);
            }
            (
                lib.pipeline.queue.clone(),
                lib.pipeline.validations.clone(),
                lib.research_papers(domain),
                lib.pipeline.connections.len(),
            )
        };
        progress.report(format!("Using {} · {model}", vendor.display_name()));
        let access = app.keychain.institutional_access();
        let (search, retrieve) = literature_tools(domain, &access, &progress);
        let agent = HypothesisConnectionAgent {
            generate,
            search,
            retrieve,
            progress: progress_fn(&progress),
            access,
        };
        let review = agent
            .connect(
                &items,
                &validations,
                &papers,
                vendor.display_name(),
                &model,
                offset,
                domain,
                "",
            )
            .await
            .map_err(|e| format!("Connection review failed: {e}"))?;
        let count = review.proposals.len();
        let mut lib = app.library.write().await;
        LibraryStore::complete_connection(&mut lib, review, Vec::new());
        app.store
            .save(&lib)
            .map_err(|e| format!("Connection review finished but could not be saved: {e}"))?;
        Ok(format!(
            "Connection review completed: {count} proposals queued."
        ))
    });
    after_start(&state, started, &headers, "connections").await
}

/// Server-sent events for the activity panel: the latest job's state on connect, then
/// every change. The connection stays open while the page does.
async fn events_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    // Subscribe before reading the snapshot so no update falls between the two.
    let updates = BroadcastStream::new(state.jobs.subscribe()).filter_map(|update| {
        let update = update.ok()?;
        let kind = match &update {
            JobUpdate::Started { .. } => "started",
            JobUpdate::Progress { .. } => "progress",
            JobUpdate::Finished { .. } => "finished",
        };
        Event::default().event(kind).json_data(&update).ok().map(Ok)
    });
    let snapshot = Event::default()
        .event("snapshot")
        .json_data(state.jobs.all_latest())
        .unwrap_or_else(|_| Event::default().event("snapshot").data("null"));
    Sse::new(tokio_stream::once(Ok(snapshot)).chain(updates)).keep_alive(KeepAlive::default())
}

async fn script_handler() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        WORKSPACE_JS,
    )
        .into_response()
}

#[derive(Deserialize)]
struct CredentialsForm {
    csrf_token: String,
    anthropic_api_key: Option<String>,
    openai_api_key: Option<String>,
    elsevier_api_key: Option<String>,
    elsevier_institution_token: Option<String>,
    wiley_tdm_token: Option<String>,
    library_proxy_prefix: Option<String>,
}

async fn save_credentials_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<CredentialsForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    // Blank fields keep the saved value; filled-in fields are saved only if they look like
    // the credential that field expects.
    let mut rejected = Vec::new();
    let mut accepted = 0;
    let mut accept = |label: &str, account: &str, value: Option<String>| -> Option<String> {
        let value = value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())?;
        match check_credential_format(account, &value) {
            Ok(()) => {
                accepted += 1;
                Some(value)
            }
            Err(why) => {
                rejected.push(format!("{label} not saved: {why}"));
                None
            }
        }
    };
    let anthropic = accept("Claude API key", "anthropic_api_key", form.anthropic_api_key);
    let openai = accept("OpenAI API key", "openai_api_key", form.openai_api_key);
    let elsevier = accept("Elsevier API key", "elsevier_api_key", form.elsevier_api_key);
    let insttoken = accept(
        "Elsevier institution token",
        "elsevier_institution_token",
        form.elsevier_institution_token,
    );
    let wiley = accept("Wiley TDM token", "wiley_tdm_token", form.wiley_tdm_token);
    let proxy = accept(
        "Library proxy prefix",
        "library_proxy_prefix",
        form.library_proxy_prefix,
    );

    let mut failures = Vec::new();
    if let Some(k) = anthropic {
        if state.keychain.set("anthropic_api_key", &k).is_err() {
            failures.push("Claude API key");
        }
    }
    if let Some(k) = openai {
        if state.keychain.set("openai_api_key", &k).is_err() {
            failures.push("OpenAI API key");
        }
    }
    let current = state.keychain.institutional_access();
    let updated = InstitutionalAccess::new(
        elsevier.or(current.elsevier_api_key),
        insttoken.or(current.elsevier_institution_token),
        wiley.or(current.wiley_tdm_token),
        proxy.or(current.library_proxy_prefix),
    );
    if state.keychain.save_institutional_access(&updated).is_err() {
        failures.push("institutional access settings");
    }
    state
        .models
        .invalidate(&[ModelVendor::Anthropic, ModelVendor::OpenAi])
        .await;
    let store = state.keychain.backend().describe();
    let mut messages = rejected;
    if !failures.is_empty() {
        messages.push(format!(
            "{} did not save: {}. Check that it is unlocked and available.",
            capitalize(&store),
            failures.join(", ")
        ));
    } else if accepted > 0 {
        messages.push(format!("Credentials saved to {store}."));
    } else if messages.is_empty() {
        messages.push("Nothing to save: every field was left blank.".to_string());
    }
    state.set_flash(messages.join(" ")).await;
    Redirect::to(&state.private_path("?section=sources")).into_response()
}

async fn export_library_md_handler(State(state): State<Arc<AppState>>) -> Response {
    let lib = state.library.read().await;
    let md = ResearchReportBuilder::pipeline(&lib).markdown();
    (
        [
            (header::CONTENT_TYPE, "text/markdown; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                r#"attachment; filename="research-library.md""#,
            ),
        ],
        md,
    )
        .into_response()
}

async fn export_library_txt_handler(State(state): State<Arc<AppState>>) -> Response {
    let lib = state.library.read().await;
    let txt = ResearchReportBuilder::pipeline(&lib).plain_text();
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                r#"attachment; filename="research-library.txt""#,
            ),
        ],
        txt,
    )
        .into_response()
}

async fn export_library_json_handler(State(state): State<Arc<AppState>>) -> Response {
    let mut lib = state.library.read().await.clone();
    // Swift legacy runs are kept only for round-tripping library.json; they are opaque here,
    // so their papers cannot be checked for restricted bodies and are left out of exports.
    lib.runs.clear();
    // Restricted TDM / author-manuscript bodies are removed from every copy of every paper:
    // validations, cycles and connection reviews keep their own copies, not only `papers`.
    lib.redact_restricted_bodies();
    let json = serde_json::to_string_pretty(&lib).unwrap_or_else(|_| "{}".to_string());
    (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                r#"attachment; filename="research-library.json""#,
            ),
        ],
        json,
    )
        .into_response()
}

async fn export_paper_md_handler(
    State(state): State<Arc<AppState>>,
    Path((_session, id)): Path<(String, String)>,
) -> Response {
    let lib = state.library.read().await;
    let Some(paper) = lib.papers.iter().find(|p| p.id == id) else {
        return (StatusCode::NOT_FOUND, "Paper not found").into_response();
    };
    let md = ResearchReportBuilder::paper(paper).markdown();
    (
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        md,
    )
        .into_response()
}

async fn export_validation_md_handler(
    State(state): State<Arc<AppState>>,
    Path((_session, id)): Path<(String, String)>,
) -> Response {
    let lib = state.library.read().await;
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (StatusCode::BAD_REQUEST, "Invalid validation ID").into_response();
    };
    let Some(val) = lib.pipeline.validations.iter().find(|v| v.id == uuid) else {
        return (StatusCode::NOT_FOUND, "Validation not found").into_response();
    };
    let md = ResearchReportBuilder::validation(val).markdown();
    (
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        md,
    )
        .into_response()
}

async fn stylesheet_handler() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        WORKSPACE_CSS,
    )
        .into_response()
}

fn render_workspace(
    lib: &LibrarySnapshot,
    base: &str,
    section: &str,
    csrf_token: &str,
    flash: Option<&str>,
    access: &InstitutionalAccess,
    has_claude_key: bool,
    has_openai_key: bool,
    chatgpt: &ChatGptStatus,
    secret_store: &SecretBackend,
    model_picker: &str,
    jobs: &[JobSnapshot],
) -> String {
    let domain = lib.pipeline.settings.domain();
    let domain_papers = lib.research_papers(domain);
    let domain_queue: Vec<_> = lib
        .pipeline
        .queue
        .iter()
        .filter(|q| q.domain() == domain)
        .collect();
    let domain_validations: Vec<_> = lib
        .pipeline
        .validations
        .iter()
        .filter(|v| v.domain() == domain)
        .collect();
    let domain_cycles: Vec<_> = lib
        .pipeline
        .cycles
        .iter()
        .filter(|c| c.domain() == domain)
        .collect();
    let domain_connections: Vec<_> = lib
        .pipeline
        .connections
        .iter()
        .filter(|c| c.domain() == domain)
        .collect();
    let datasets = lib.dataset_records.as_deref().unwrap_or(&[]);

    let nav_items = [
        ("loop", "Research loop", lib.pipeline.objectives(domain).len()),
        ("library", "Evidence library", domain_papers.len()),
        ("queue", "Hypothesis queue", domain_queue.len()),
        ("validations", "Validation results", domain_validations.len()),
        ("datasets", "Public datasets", datasets.len()),
        ("cycles", "Discovery cycles", domain_cycles.len()),
        (
            "sources",
            "Sources & credentials",
            ResearchSourceCatalog::all_journals(domain).len(),
        ),
        ("connections", "Connections", domain_connections.len()),
    ];

    let mut nav_html = String::new();
    for (id, label, count) in nav_items {
        let active = if section == id { " class=\"active\"" } else { "" };
        nav_html.push_str(&format!(
            r#"<li><a href="?section={id}"{active}><span>{}</span><span class="badge">{count}</span></a></li>"#,
            html_escape(label)
        ));
    }

    let flash_html = match flash {
        Some(msg) => format!(r#"<div class="alert">{}</div>"#, html_escape(msg)),
        None => String::new(),
    };

    let main_content = match section {
        "library" => render_library_section(&domain_papers, csrf_token, access),
        "queue" => render_queue_section(&domain_queue, csrf_token),
        "validations" => render_validations_section(&domain_validations),
        "datasets" => render_datasets_section(datasets, csrf_token),
        "cycles" => render_cycles_section(&domain_cycles, csrf_token),
        "sources" => render_sources_section(
            domain,
            csrf_token,
            access,
            has_claude_key,
            has_openai_key,
            chatgpt,
            secret_store,
        ),
        "connections" => render_connections_section(&domain_connections, csrf_token),
        _ => render_loop_section(lib, domain, csrf_token, model_picker),
    };

    // Shown once, after the first sign-in that enables ChatGPT plan usage.
    let welcome_html = if chatgpt.show_welcome {
        format!(
            r#"<div class="alert">
        <strong>You're using your ChatGPT plan</strong>
        <p>Model stages in this app now count toward your ChatGPT plan's usage. <a href="{MANAGE_USAGE_URL}" rel="noopener noreferrer" target="_blank">Manage usage</a></p>
        <form method="post" action="chatgpt/welcome">
          <input type="hidden" name="csrf_token" value="{}">
          <input type="hidden" name="section" value="{}">
          <button type="submit" class="btn-secondary btn-small">Got it</button>
        </form>
      </div>"#,
            html_escape(csrf_token),
            html_escape(section)
        )
    } else {
        String::new()
    };

    let job = jobs.iter().find(|j| j.domain == domain);
    let others_running: Vec<&JobSnapshot> = jobs
        .iter()
        .filter(|j| j.domain != domain && j.status == JobStatus::Running)
        .collect();
    let job_panel = render_job_panel(job, &others_running);
    let job_running = job.is_some_and(|j| j.status == JobStatus::Running);

    let csrf_escaped = html_escape(csrf_token);
    let dementia_selected = if domain == ResearchDomain::Dementia {
        " selected"
    } else {
        ""
    };
    let cancer_selected = if domain == ResearchDomain::Cancer {
        " selected"
    } else {
        ""
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <base href="{}">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{} Medical Research Agent — Hardened Rust/Axum SSR</title>
  <link rel="stylesheet" href="/static/app.css">
  <script src="/static/app.js" defer></script>
</head>
<body data-job-running="{job_running}" data-domain="{}">
  <div class="layout">
    <aside class="sidebar">
      <div class="brand">
        <h1>Medical Research</h1>
        <p class="subtitle">Rust + Axum SSR · <code>#![forbid(unsafe_code)]</code> · <code>rustls</code></p>
      </div>
      <form method="post" action="domain" class="domain-switcher">
        <input type="hidden" name="csrf_token" value="{csrf_escaped}">
        <input type="hidden" name="section" value="{}">
        <label for="domain-select">Research field</label>
        <div class="row">
          <select id="domain-select" name="domain">
            <option value="dementia"{dementia_selected}>Dementia</option>
            <option value="cancer"{cancer_selected}>Cancer</option>
          </select>
          <button type="submit" class="btn-secondary">Switch</button>
        </div>
      </form>
      <nav>
        <ul>{nav_html}</ul>
      </nav>
      <div class="exports">
        <p class="caption">Export library (redacts TDM/AUTH_MAN bodies)</p>
        <div class="row">
          <a href="export/library.md" class="btn-link">Markdown</a>
          <a href="export/library.txt" class="btn-link">Text</a>
          <a href="export/library.json" class="btn-link">JSON</a>
        </div>
      </div>
    </aside>
    <main class="content">
      {job_panel}
      {welcome_html}
      {flash_html}
      {main_content}
    </main>
  </div>
</body>
</html>"#,
        html_escape(base),
        html_escape(domain.display_name()),
        domain.as_str(),
        html_escape(section)
    )
}

/// The activity panel for the latest research stage. `static/app.js` keeps it live; this
/// server-rendered copy is what a page shows on load (and without JavaScript).
fn render_job_panel(job: Option<&JobSnapshot>, others_running: &[&JobSnapshot]) -> String {
    let others: String = others_running
        .iter()
        .map(|other| {
            format!(
                r#"<p class="caption">{} research is running: {}</p>"#,
                html_escape(&other.field),
                html_escape(&other.title)
            )
        })
        .collect();
    let others_html = format!(r#"<div id="job-others">{others}</div>"#);
    let Some(job) = job else {
        return format!(
            r#"{others_html}<section id="job-panel" class="card job-panel" hidden></section>"#
        );
    };
    let (status, pill, label) = match job.status {
        JobStatus::Running => ("running", "pill-warn", "Running"),
        JobStatus::Succeeded => ("succeeded", "pill-ok", "Completed"),
        JobStatus::Failed => ("failed", "pill-error", "Failed"),
    };
    let lines: String = job
        .log
        .iter()
        .map(|line| {
            format!(
                r#"<li><time datetime="{}">{}</time> {}</li>"#,
                html_escape(&line.at.to_rfc3339()),
                line.at.format("%H:%M:%S UTC"),
                html_escape(&line.message)
            )
        })
        .collect();
    let outcome = job
        .outcome
        .as_deref()
        .map(|o| {
            let class = if job.status == JobStatus::Failed { "job-outcome job-failed" } else { "job-outcome" };
            format!(r#"<p class="{class}">{}</p>"#, html_escape(o))
        })
        .unwrap_or_default();
    let results = if job.status == JobStatus::Running {
        String::new()
    } else {
        format!(
            r#"<a class="btn-link" href="?section={}">View results</a>"#,
            html_escape(&job.section)
        )
    };
    format!(
        r#"{others_html}<section id="job-panel" class="card job-panel" data-job-id="{}" data-status="{status}">
        <div class="row-between"><h3>{}</h3><span class="pill {pill}">{label}</span></div>
        {outcome}
        <ol class="job-log">{lines}</ol>
        {results}
      </section>"#,
        job.id,
        html_escape(&job.title)
    )
}

fn render_loop_section(
    lib: &LibrarySnapshot,
    domain: ResearchDomain,
    csrf_token: &str,
    model_picker: &str,
) -> String {
    let csrf = html_escape(csrf_token);
    let objectives = lib.pipeline.objectives(domain);
    let mut obj_items = String::new();
    if objectives.is_empty() {
        obj_items.push_str(&format!(
            r#"<li class="muted">No manual objectives queued. Default autonomous question: <em>{}</em></li>"#,
            html_escape(domain.default_objective())
        ));
    } else {
        for obj in &objectives {
            let escaped = html_escape(obj);
            obj_items.push_str(&format!(
                r#"<li class="list-row">
                  <span>{escaped}</span>
                  <form method="post" action="objectives" class="inline-form">
                    <input type="hidden" name="csrf_token" value="{csrf}">
                    <input type="hidden" name="action" value="remove">
                    <input type="hidden" name="text" value="{escaped}">
                    <button type="submit" class="btn-secondary btn-small">Remove</button>
                  </form>
                </li>"#
            ));
        }
    }

    let mut events_html = String::new();
    for ev in lib.pipeline.events.iter().take(20) {
        events_html.push_str(&format!(
            r#"<li><span class="mono muted">{}</span> — {}</li>"#,
            html_escape(&ev.date.to_rfc3339()),
            html_escape(&ev.message)
        ));
    }
    if events_html.is_empty() {
        events_html.push_str(r#"<li class="muted">No pipeline events recorded yet.</li>"#);
    }

    format!(
        r#"<header class="page-header">
        <h2>{} Research Loop</h2>
        <p>Autonomous multi-journal literature discovery, four-lens independent validation, and cross-hypothesis synthesis.</p>
      </header>
      <div class="grid-two">
        <section class="card">
          <h3>Run Bounded Research Stage</h3>
          <form method="post" action="loop/discover" class="stack">
            <input type="hidden" name="csrf_token" value="{csrf}">
            {model_picker}
            <label>Optional focus objective
              <input type="text" name="objective" placeholder="{}">
            </label>
            <button type="submit" class="btn-primary">Run Discovery Cycle</button>
          </form>
          <hr>
          <div class="row">
            <form method="post" action="loop/validate">
              <input type="hidden" name="csrf_token" value="{csrf}">
              <input type="hidden" name="vendor" value="auto">
              <button type="submit" class="btn-secondary">Validate Next Queued Hypothesis</button>
            </form>
            <form method="post" action="loop/connect">
              <input type="hidden" name="csrf_token" value="{csrf}">
              <input type="hidden" name="vendor" value="auto">
              <button type="submit" class="btn-secondary">Run Connection Review</button>
            </form>
          </div>
        </section>
        <section class="card">
          <h3>Queued Research Objectives ({})</h3>
          <form method="post" action="objectives" class="row">
            <input type="hidden" name="csrf_token" value="{csrf}">
            <input type="hidden" name="action" value="add">
            <input type="text" name="text" placeholder="Add a research question..." required>
            <button type="submit" class="btn-primary">Enqueue</button>
          </form>
          <ul class="clean-list">{obj_items}</ul>
        </section>
      </div>
      <section class="card">
        <h3>Audit Log &amp; Pipeline Activity</h3>
        <p class="caption">Model requests today: {} / {}</p>
        <ul class="clean-list">{events_html}</ul>
      </section>"#,
        html_escape(domain.display_name()),
        html_escape(domain.default_objective()),
        html_escape(domain.display_name()),
        lib.pipeline.model_requests_today,
        lib.pipeline.settings.daily_model_budget
    )
}

fn render_library_section(
    papers: &[Paper],
    csrf_token: &str,
    access: &InstitutionalAccess,
) -> String {
    let csrf = html_escape(csrf_token);
    let mut rows = String::new();
    for p in papers {
        let restricted_badge = if p.is_body_redistribution_restricted() {
            r#"<span class="pill pill-warn">Body not exported (no open licence)</span>"#
        } else if p.full_text.is_some() {
            r#"<span class="pill pill-ok">Open-access full text</span>"#
        } else {
            r#"<span class="pill">Metadata / Abstract only</span>"#
        };
        let proxy_link = access
            .proxied_url(p)
            .map(|u| {
                format!(
                    r#" · <a href="{}" rel="noopener noreferrer" target="_blank">Institutional proxy</a>"#,
                    safe_https_href(&u)
                )
            })
            .unwrap_or_default();

        rows.push_str(&format!(
            r#"<article class="card">
              <div class="row-between">
                <h4>{}</h4>
                {restricted_badge}
              </div>
              <p class="caption">{} · ID: <code>{}</code></p>
              <p>{}</p>
              <div class="row">
                <a href="{}" rel="noopener noreferrer" target="_blank" class="btn-link">Reader page</a>
                <a href="export/paper/{}" class="btn-link">Export Markdown</a>
                {proxy_link}
                <form method="post" action="papers/retrieve" class="inline-form">
                  <input type="hidden" name="csrf_token" value="{csrf}">
                  <input type="hidden" name="paper_id" value="{}">
                  <button type="submit" class="btn-secondary btn-small">Retrieve Full Text</button>
                </form>
              </div>
            </article>"#,
            html_escape(&p.title),
            html_escape(&p.citation()),
            html_escape(&p.id),
            html_escape(if p.abstract_text.is_empty() {
                "No abstract stored."
            } else {
                &p.abstract_text
            }),
            safe_https_href(&p.reader_page_url()),
            html_escape(&urlencoding::encode(&p.id)),
            html_escape(&p.id)
        ));
    }
    if rows.is_empty() {
        rows.push_str(r#"<p class="muted">No papers saved in this field yet. Run a literature search above.</p>"#);
    }

    format!(
        r#"<header class="page-header">
        <h2>Evidence Library</h2>
        <p>Every search automatically excludes conference abstracts (<code>NOT PUB_TYPE:"Abstract"</code>) and deduplicates before applying the cap.</p>
      </header>
      <section class="card">
        <form method="post" action="literature/search" class="row">
          <input type="hidden" name="csrf_token" value="{csrf}">
          <input type="text" name="query" placeholder="Search Europe PMC &amp; configured field/mechanism journals (e.g., cGAS-STING microglia)..." required>
          <button type="submit" class="btn-primary">Search Literature</button>
        </form>
      </section>
      <div class="stack">{rows}</div>"#
    )
}

fn render_queue_section(
    queue: &[&crate::models::QueuedHypothesis],
    csrf_token: &str,
) -> String {
    let csrf = html_escape(csrf_token);
    let mut cards = String::new();
    for item in queue {
        let mut cits = String::new();
        for c in &item.draft.citations {
            cits.push_str(&format!(
                r#"<li><blockquote>“{}”</blockquote><span class="caption">{} / {} — {}</span></li>"#,
                html_escape(&c.quote),
                html_escape(&c.paper_id),
                html_escape(&c.passage_id),
                html_escape(&c.verification_description())
            ));
        }
        cards.push_str(&format!(
            r#"<article class="card">
              <div class="row-between">
                <h4>{}</h4>
                <span class="pill">{}</span>
              </div>
              <p><strong>Statement:</strong> {}</p>
              <p class="caption">ID: <code>{}</code> · Origin: {} · Generation: {}</p>
              <ul class="clean-list">{cits}</ul>
              <form method="post" action="loop/validate" class="row">
                <input type="hidden" name="csrf_token" value="{csrf}">
                <input type="hidden" name="vendor" value="auto">
                <input type="hidden" name="hypothesis_id" value="{}">
                <button type="submit" class="btn-secondary btn-small">Validate This Hypothesis</button>
              </form>
            </article>"#,
            html_escape(&item.draft.title),
            html_escape(&format!("{:?}", item.status)),
            html_escape(&item.draft.statement),
            html_escape(&item.id.to_string()),
            html_escape(item.origin.as_str()),
            item.generation,
            html_escape(&item.id.to_string())
        ));
    }
    if cards.is_empty() {
        cards.push_str(r#"<p class="muted">No hypotheses in this field's queue yet.</p>"#);
    }

    format!(
        r#"<header class="page-header">
        <h2>Hypothesis Queue</h2>
        <p>Testable research proposals awaiting or completed independent four-lens validation.</p>
      </header>
      <section class="card">
        <h3>Queue Manual Hypothesis for Independent Validation</h3>
        <form method="post" action="queue/manual" class="stack">
          <input type="hidden" name="csrf_token" value="{csrf}">
          <label>Working title
            <input type="text" name="title" placeholder="Short descriptive title">
          </label>
          <label>Testable hypothesis statement
            <textarea name="statement" rows="3" placeholder="Specify population/model, mechanism/exposure, comparator, and predicted outcome..." required></textarea>
          </label>
          <button type="submit" class="btn-primary">Enqueue Hypothesis</button>
        </form>
      </section>
      <div class="stack">{cards}</div>"#
    )
}

fn render_validations_section(
    validations: &[&crate::models::HypothesisValidation],
) -> String {
    let mut cards = String::new();
    for v in validations {
        let mut claims_html = String::new();
        for c in &v.claims {
            claims_html.push_str(&format!(
                r#"<li><strong>{}: {}</strong> — {}<br><span class="caption">{}</span></li>"#,
                html_escape(&c.id),
                html_escape(c.verdict.label()),
                html_escape(&c.statement),
                html_escape(&c.rationale)
            ));
        }
        cards.push_str(&format!(
            r#"<article class="card">
              <div class="row-between">
                <h4>{}</h4>
                <span class="pill pill-ok">{}</span>
              </div>
              <p class="caption">Assessment ID: <code>{}</code> · Model: {} ({})</p>
              <p><strong>Summary:</strong> {}</p>
              <p><strong>Can conclude:</strong> {}</p>
              <p><strong>Cannot conclude:</strong> {}</p>
              <h5>Necessary Claims</h5>
              <ul class="clean-list">{claims_html}</ul>
              <div class="row">
                <a href="export/validation/{}" class="btn-link">Export Assessment Markdown</a>
              </div>
            </article>"#,
            html_escape(&v.original_statement),
            html_escape(v.verdict.label()),
            html_escape(&v.id.to_string()),
            html_escape(&v.model),
            html_escape(&v.provider),
            html_escape(&v.summary),
            html_escape(&v.can_conclude),
            html_escape(&v.cannot_conclude),
            html_escape(&v.id.to_string())
        ));
    }
    if cards.is_empty() {
        cards.push_str(r#"<p class="muted">No validation assessments recorded in this field yet.</p>"#);
    }

    format!(
        r#"<header class="page-header">
        <h2>Validation Results</h2>
        <p>Independent criteria are defined from the exact statement before the proposer's rationale or bibliography is exposed.</p>
      </header>
      <div class="stack">{cards}</div>"#
    )
}

fn render_datasets_section(
    datasets: &[crate::models::ResearchDatasetRecord],
    csrf_token: &str,
) -> String {
    let csrf = html_escape(csrf_token);
    let mut cards = String::new();
    for d in datasets {
        cards.push_str(&format!(
            r#"<article class="card">
              <div class="row-between">
                <h4>{}</h4>
                <span class="pill">{}</span>
              </div>
              <p>{}</p>
              <p class="caption">Access: {} · Samples: {}</p>
              <p class="caption"><em>{}</em></p>
              <a href="{}" rel="noopener noreferrer" target="_blank" class="btn-link">Open Portal</a>
            </article>"#,
            html_escape(&d.title),
            html_escape(&d.provider),
            html_escape(&d.summary),
            html_escape(&d.access),
            d.sample_count
                .map(|c| c.to_string())
                .unwrap_or_else(|| "Unreported".to_string()),
            html_escape(&d.evidence_use),
            safe_https_href(&d.source_url)
        ));
    }
    if cards.is_empty() {
        cards.push_str(r#"<p class="muted">No public dataset metadata cached yet.</p>"#);
    }

    format!(
        r#"<header class="page-header">
        <h2>Public Cancer Datasets (NCI GDC &amp; cBioPortal)</h2>
        <p>Dataset metadata is strictly separated from supporting article evidence and used only for feasibility and next-test planning.</p>
      </header>
      <section class="card">
        <form method="post" action="datasets/discover" class="row">
          <input type="hidden" name="csrf_token" value="{csrf}">
          <input type="text" name="query" placeholder="Search public cohorts (e.g., glioblastoma EGFR RNA-seq)..." required>
          <button type="submit" class="btn-primary">Discover Public Cohorts</button>
        </form>
      </section>
      <div class="stack">{cards}</div>"#
    )
}

fn render_cycles_section(
    cycles: &[&crate::models::DiscoveryCycle],
    csrf_token: &str,
) -> String {
    let csrf = html_escape(csrf_token);
    let mut cards = String::new();
    for c in cycles {
        cards.push_str(&format!(
            r#"<article class="card">
              <h4>Objective: {}</h4>
              <p class="caption">Cycle ID: <code>{}</code> · {} · {} directions mapped · {} hypotheses drafted</p>
              <p class="caption">Model: <code>{}</code> ({})</p>
            </article>"#,
            html_escape(&c.objective),
            html_escape(&c.id.to_string()),
            html_escape(&c.created_at.to_rfc3339()),
            c.landscape.len(),
            c.hypotheses.len(),
            html_escape(&c.model),
            html_escape(&c.provider)
        ));
    }
    if cards.is_empty() {
        cards.push_str(r#"<p class="muted">No discovery cycles recorded in this field yet.</p>"#);
    }

    format!(
        r#"<header class="page-header">
        <h2>Discovery Cycles</h2>
        <p>Each cycle surveys configured field &amp; mechanism journals plus Europe PMC, deduplicates before capping, and verifies exact 20+ character quotes.</p>
      </header>
      <section class="card">
        <form method="post" action="loop/discover" class="row">
          <input type="hidden" name="csrf_token" value="{csrf}">
          <input type="hidden" name="vendor" value="auto">
          <input type="text" name="objective" placeholder="Optional discovery objective...">
          <button type="submit" class="btn-primary">Start Discovery Cycle</button>
        </form>
      </section>
      <div class="stack">{cards}</div>"#
    )
}

fn render_sources_section(
    domain: ResearchDomain,
    csrf_token: &str,
    access: &InstitutionalAccess,
    has_claude_key: bool,
    has_openai_key: bool,
    chatgpt: &ChatGptStatus,
    secret_store: &SecretBackend,
) -> String {
    let csrf = html_escape(csrf_token);
    let store_name = html_escape(&secret_store.describe());
    let store_note = if secret_store.is_encrypted_store() {
        String::new()
    } else {
        r#"<p class="caption">No system keyring was found on this computer, so these are kept in an owner-only file instead. Install and unlock a keyring (such as GNOME Keyring or KWallet) and restart the app to use it.</p>"#.to_string()
    };
    let chatgpt_card = render_chatgpt_card(&csrf, chatgpt);
    let journals = ResearchSourceCatalog::all_journals(domain);
    let max_records = ResearchSourceCatalog::maximum_records(domain);

    let mut journal_rows = String::new();
    for j in &journals {
        let tier_badge = match j.tier {
            JournalTier::Field => r#"<span class="pill pill-ok">Field journal (3/search)</span>"#,
            JournalTier::Mechanism => {
                r#"<span class="pill pill-warn">Mechanism &amp; contributing factors (2/search)</span>"#
            }
        };
        journal_rows.push_str(&format!(
            r#"<article class="card">
              <div class="row-between">
                <h4>{}</h4>
                {tier_badge}
              </div>
              <p class="caption">ISSNs: <code>{}</code></p>
              <p>{}</p>
              <p class="caption">Europe PMC filter: <code>{}</code></p>
              <a href="{}" rel="noopener noreferrer" target="_blank" class="btn-link">Journal Page</a>
            </article>"#,
            html_escape(j.name),
            html_escape(&j.issns.join(", ")),
            html_escape(j.access_notes),
            html_escape(&j.europe_pmc_filter()),
            url::Url::parse(j.homepage)
                .map(|u| safe_https_href(&u))
                .unwrap_or_else(|_| "#".to_string())
        ));
    }

    let claude_status = if has_claude_key {
        "Saved"
    } else {
        "Not configured"
    };
    let openai_status = if has_openai_key {
        "Saved"
    } else {
        "Not configured"
    };
    let elsevier_status = if access.elsevier_api_key.is_some() {
        "Saved"
    } else {
        "Not configured"
    };
    let wiley_status = if access.wiley_tdm_token.is_some() {
        "Saved"
    } else {
        "Not configured"
    };

    format!(
        r#"<header class="page-header">
        <h2>Configured Sources &amp; Credentials ({})</h2>
        <p>Per-search cap: <strong>{max_records}</strong> records ({} field journals × 3 + {} mechanism journals × 2 + wider Europe PMC corpus × {WIDER_CORPUS_PAGE_SIZE}).</p>
      </header>
      {chatgpt_card}
      <section class="card">
        <h3>API Keys &amp; Institutional Credentials</h3>
        <p class="caption">Stored in {store_name}. Never written to <code>library.json</code> or shown on this page.</p>
        {store_note}
        <form method="post" action="credentials" class="stack">
          <input type="hidden" name="csrf_token" value="{csrf}">
          <div class="grid-two">
            <label>Claude API Key ({claude_status})
              <input type="password" name="anthropic_api_key" autocomplete="off" placeholder="sk-ant-...">
            </label>
            <label>OpenAI API Key ({openai_status})
              <input type="password" name="openai_api_key" autocomplete="off" placeholder="sk-...">
            </label>
            <label>Elsevier TDM API Key ({elsevier_status})
              <input type="password" name="elsevier_api_key" autocomplete="off" placeholder="Elsevier X-ELS-APIKey">
            </label>
            <label>Elsevier Institution Token
              <input type="password" name="elsevier_institution_token" autocomplete="off" placeholder="Optional X-ELS-Insttoken">
            </label>
            <label>Wiley TDM Client Token ({wiley_status})
              <input type="password" name="wiley_tdm_token" autocomplete="off" placeholder="Wiley-TDM-Client-Token">
            </label>
            <label>Institutional Library Proxy Prefix (HTTPS only)
              <input type="url" name="library_proxy_prefix" placeholder="https://ezproxy.example.edu/login?url=">
            </label>
          </div>
          <button type="submit" class="btn-primary">Save Credentials</button>
        </form>
      </section>
      <div class="stack">{journal_rows}</div>"#,
        html_escape(domain.display_name()),
        ResearchSourceCatalog::journals(domain).len(),
        ResearchSourceCatalog::mechanism_journals(domain).len()
    )
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn render_chatgpt_card(csrf: &str, chatgpt: &ChatGptStatus) -> String {
    let sign_out = format!(
        r#"<form method="post" action="chatgpt/sign-out">
            <input type="hidden" name="csrf_token" value="{csrf}">
            <button type="submit" class="btn-secondary">Sign out</button>
          </form>"#
    );
    let manage = format!(
        r#"<a href="{MANAGE_USAGE_URL}" rel="noopener noreferrer" target="_blank">Manage usage</a>"#
    );
    let who = html_escape(chatgpt.email.as_deref().unwrap_or("your ChatGPT account"));
    let body = if !chatgpt.signed_in {
        format!(
            r#"<p>Run model stages on your ChatGPT plan instead of an API key. Requests count toward your plan's usage, and you can set limits for this app in ChatGPT settings. Sign-in must be done in a browser on the computer running this app.</p>
        <form method="post" action="chatgpt/sign-in">
          <input type="hidden" name="csrf_token" value="{csrf}">
          <button type="submit" class="btn-primary">Continue with ChatGPT</button>
        </form>"#
        )
    } else if chatgpt.plan_usage {
        format!(
            r#"<p>Signed in as <strong>{who}</strong>.</p>
        <p class="caption">Using ChatGPT plan · {manage}</p>
        {sign_out}"#
        )
    } else {
        format!(
            r#"<p>Signed in as <strong>{who}</strong>. ChatGPT plan usage is off, so model stages need an API key.</p>
        <div class="row">
          <form method="post" action="chatgpt/sign-in">
            <input type="hidden" name="csrf_token" value="{csrf}">
            <input type="hidden" name="enable_plan" value="1">
            <button type="submit" class="btn-primary">Use your ChatGPT plan</button>
          </form>
          {sign_out}
        </div>"#
        )
    };
    format!(
        r#"<section class="card">
        <h3>Use your ChatGPT plan</h3>
        {body}
      </section>"#
    )
}

fn render_connections_section(
    connections: &[&crate::models::ConnectionReview],
    csrf_token: &str,
) -> String {
    let csrf = html_escape(csrf_token);
    let mut cards = String::new();
    for rev in connections {
        cards.push_str(&format!(
            r#"<article class="card">
              <h4>Connection Review <code>{}</code></h4>
              <p class="caption">Created: {} · Proposals queued: {} · Model: <code>{}</code> ({})</p>
            </article>"#,
            html_escape(&rev.id.to_string()),
            html_escape(&rev.created_at.to_rfc3339()),
            rev.proposals.len(),
            html_escape(&rev.model),
            html_escape(&rev.provider)
        ));
    }
    if cards.is_empty() {
        cards.push_str(r#"<p class="muted">No connection reviews recorded in this field yet.</p>"#);
    }

    format!(
        r#"<header class="page-header">
        <h2>Cross-Hypothesis Connections &amp; Reconsiderations</h2>
        <p>Compares assessed hypotheses to propose testable bridges or reconsider negative/inconclusive ideas when genuinely new cited article bodies appear.</p>
      </header>
      <section class="card">
        <form method="post" action="loop/connect" class="row">
          <input type="hidden" name="csrf_token" value="{csrf}">
          <input type="hidden" name="vendor" value="auto">
          <button type="submit" class="btn-primary">Run Connection Review</button>
        </form>
      </section>
      <div class="stack">{cards}</div>"#
    )
}

const WORKSPACE_CSS: &str = r#":root {
  --bg: #0f141c;
  --panel: #171f2c;
  --border: #263246;
  --text: #e6edf7;
  --muted: #93a3b8;
  --accent: #3b82f6;
  --accent-hover: #2563eb;
  --ok: #10b981;
  --warn: #f59e0b;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.55;
}
.layout {
  display: grid;
  grid-template-columns: 280px minmax(0, 1fr);
  min-height: 100vh;
}
.sidebar {
  background: var(--panel);
  border-right: 1px solid var(--border);
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}
.brand h1 { margin: 0; font-size: 1.2rem; }
.subtitle { margin: 0.25rem 0 0; font-size: 0.78rem; color: var(--muted); }
.sidebar nav ul { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 0.35rem; }
.sidebar nav a {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.55rem 0.75rem;
  border-radius: 6px;
  color: var(--text);
  text-decoration: none;
  font-size: 0.92rem;
}
.sidebar nav a.active, .sidebar nav a:hover { background: rgba(59, 130, 246, 0.16); color: #fff; }
.badge {
  background: var(--border);
  padding: 0.1rem 0.45rem;
  border-radius: 999px;
  font-size: 0.75rem;
}
.content { padding: 2rem; max-width: 1180px; }
.page-header { margin-bottom: 1.5rem; }
.page-header h2 { margin: 0 0 0.35rem; }
.page-header p { margin: 0; color: var(--muted); }
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.25rem;
  margin-bottom: 1rem;
}
.grid-two { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.stack { display: flex; flex-direction: column; gap: 0.85rem; }
.row { display: flex; gap: 0.65rem; align-items: center; flex-wrap: wrap; }
.row-between { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; }
input[type="text"], input[type="password"], input[type="url"], select, textarea {
  width: 100%;
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 0.55rem 0.75rem;
  border-radius: 6px;
  font-size: 0.92rem;
}
.row > input[type="text"] { flex: 1; }
.btn-primary, .btn-secondary {
  border: none;
  border-radius: 6px;
  padding: 0.55rem 1rem;
  font-weight: 600;
  cursor: pointer;
  font-size: 0.9rem;
}
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent-hover); }
.btn-secondary { background: var(--border); color: var(--text); }
.btn-small { padding: 0.3rem 0.65rem; font-size: 0.8rem; }
.btn-link { color: var(--accent); text-decoration: none; font-size: 0.88rem; font-weight: 500; }
.btn-link:hover { text-decoration: underline; }
.pill {
  padding: 0.2rem 0.6rem;
  border-radius: 999px;
  font-size: 0.75rem;
  background: var(--border);
  white-space: nowrap;
}
.pill-ok { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; }
.pill-warn { background: rgba(245, 158, 11, 0.2); color: #fcd34d; }
.alert {
  background: rgba(59, 130, 246, 0.18);
  border: 1px solid var(--accent);
  padding: 0.85rem 1rem;
  border-radius: 8px;
  margin-bottom: 1.25rem;
}
.caption, .muted { color: var(--muted); font-size: 0.85rem; }
.clean-list { list-style: none; padding: 0; margin: 0.5rem 0 0; display: flex; flex-direction: column; gap: 0.5rem; }
.list-row { display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; }
.inline-form { display: inline; }
blockquote {
  margin: 0.35rem 0;
  padding-left: 0.75rem;
  border-left: 3px solid var(--accent);
  color: var(--text);
}
.pill-error { background: rgba(239, 68, 68, 0.2); color: #fca5a5; }
.content a:not(.btn-link) { color: #93c5fd; }
.job-panel { border-color: var(--accent); }
.job-panel h3 { margin: 0; }
.job-outcome { margin: 0.5rem 0 0; }
.job-failed { color: #fca5a5; }
.job-log {
  list-style: none;
  margin: 0.75rem 0 0.5rem;
  padding: 0;
  max-height: 16rem;
  overflow-y: auto;
  font-size: 0.85rem;
}
.job-log li { padding: 0.2rem 0; border-bottom: 1px solid var(--border); overflow-wrap: anywhere; }
.job-log time { color: var(--muted); font-variant-numeric: tabular-nums; margin-right: 0.5rem; }
/* One stage runs at a time; the server also refuses a second one. */
body[data-job-running="true"] form[action^="/loop/"] button { opacity: 0.5; pointer-events: none; }
"#;

/// Keeps the activity panel live over server-sent events and, when a stage finishes,
/// reloads the page content in place. Builds every element with `textContent`; no
/// server or model text is ever parsed as HTML except the app's own escaped pages.
const WORKSPACE_JS: &str = r##""use strict";
(() => {
  if (!("EventSource" in window)) return;
  const LABELS = { running: "Running", succeeded: "Completed", failed: "Failed" };
  const PILLS = { running: "pill-warn", succeeded: "pill-ok", failed: "pill-error" };
  // Latest job per research field ("dementia", "cancer").
  let jobs = {};
  const currentDomain = () => document.body.dataset.domain;
  const currentJob = () => jobs[currentDomain()] || null;

  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const logLine = (line) => {
    const item = el("li");
    const time = el("time", null, new Date(line.at).toLocaleTimeString());
    time.dateTime = line.at;
    item.append(time, " ", line.message);
    return item;
  };

  function renderOthers() {
    const others = document.getElementById("job-others");
    if (!others) return;
    const notes = Object.values(jobs)
      .filter((job) => job.domain !== currentDomain() && job.status === "running")
      .map((job) => el("p", "caption", job.field + " research is running: " + job.title));
    others.replaceChildren(...notes);
  }

  function render() {
    const job = currentJob();
    document.body.dataset.jobRunning = String(job !== null && job.status === "running");
    renderOthers();
    const panel = document.getElementById("job-panel");
    if (!panel) return;
    if (!job) {
      panel.hidden = true;
      panel.replaceChildren();
      return;
    }
    panel.hidden = false;
    panel.dataset.jobId = String(job.id);
    panel.dataset.status = job.status;
    const head = el("div", "row-between");
    head.append(el("h3", null, job.title), el("span", "pill " + PILLS[job.status], LABELS[job.status]));
    const parts = [head];
    if (job.outcome) {
      parts.push(el("p", job.status === "failed" ? "job-outcome job-failed" : "job-outcome", job.outcome));
    }
    const log = el("ol", "job-log");
    job.log.forEach((line) => log.append(logLine(line)));
    parts.push(log);
    if (job.status !== "running") {
      const link = el("a", "btn-link", "View results");
      link.href = "?section=" + encodeURIComponent(job.section);
      parts.push(link);
    }
    panel.replaceChildren(...parts);
    log.scrollTop = log.scrollHeight;
  }

  function appendLine(update) {
    const job = jobs[update.domain];
    if (!job || job.id !== update.id) return;
    job.log.push(update.line);
    if (update.domain !== currentDomain()) return;
    const log = document.querySelector("#job-panel .job-log");
    if (!log) return render();
    const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
    log.append(logLine(update.line));
    if (atBottom) log.scrollTop = log.scrollHeight;
  }

  // Swap in the updated page content (new results, counts) without a full reload, unless
  // the user is typing in a field.
  async function refreshContent() {
    const active = document.activeElement;
    if (active && active.matches("input, textarea, select") && active.closest("main")) return;
    try {
      const response = await fetch(location.href, { headers: { Accept: "text/html" }, cache: "no-store" });
      if (!response.ok) return;
      const page = new DOMParser().parseFromString(await response.text(), "text/html");
      // The field may have been switched in another tab; reload fully if so.
      if (page.body.dataset.domain !== currentDomain()) {
        location.reload();
        return;
      }
      for (const selector of ["main.content", "aside.sidebar nav"]) {
        const fresh = page.querySelector(selector);
        const current = document.querySelector(selector);
        if (fresh && current) current.replaceWith(document.adoptNode(fresh));
      }
      render();
    } catch (_) {
      // Keep the current page; the "View results" link still works.
    }
  }

  const source = new EventSource("events");
  const read = (event) => JSON.parse(event.data);
  source.addEventListener("snapshot", (event) => {
    const before = currentJob();
    jobs = {};
    for (const job of read(event) || []) jobs[job.domain] = job;
    render();
    // Reconnected after this field's stage finished while the connection was down.
    const after = currentJob();
    if (before && before.status === "running" && after && after.id === before.id && after.status !== "running") {
      refreshContent();
    }
  });
  source.addEventListener("started", (event) => {
    const job = read(event).job;
    jobs[job.domain] = job;
    render();
  });
  source.addEventListener("progress", (event) => appendLine(read(event)));
  source.addEventListener("finished", (event) => {
    const job = read(event).job;
    jobs[job.domain] = job;
    render();
    if (job.domain === currentDomain()) refreshContent();
  });
})();
"##;
