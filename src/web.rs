use crate::agents::{
    AutonomousDiscoveryAgent, HypothesisConnectionAgent, HypothesisValidationAgent,
};
use crate::catalog::{JournalTier, ResearchSourceCatalog, WIDER_CORPUS_PAGE_SIZE};
use crate::datasets::CancerDatasetClient;
use crate::literature::{FreeFullTextClient, FreeLiteratureSearchClient};
use crate::models::{
    InstitutionalAccess, LibrarySnapshot, Paper, ResearchDomain, ResearchError,
};
use crate::providers::{ClaudeProvider, KeychainStore, ModelVendor, OpenAiProvider};
use crate::report::ResearchReportBuilder;
use crate::store::LibraryStore;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Form, Path, Query, State};
use axum::http::{ header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::Utc;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct AppState {
    pub store: LibraryStore,
    pub keychain: KeychainStore,
    pub library: RwLock<LibrarySnapshot>,
    pub csrf_token: String,
    pub flash: RwLock<Option<String>>,
}

impl AppState {
    pub fn new(store: LibraryStore, keychain: KeychainStore) -> Result<Arc<Self>, ResearchError> {
        let library = store.load()?;
        let mut hasher = Sha256::new();
        hasher.update(Uuid::new_v4().as_bytes());
        hasher.update(Uuid::new_v4().as_bytes());
        let csrf_token = format!("{:x}", hasher.finalize());
        Ok(Arc::new(Self {
            store,
            keychain,
            library: RwLock::new(library),
            csrf_token,
            flash: RwLock::new(None),
        }))
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

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/static/app.css", get(stylesheet_handler))
        .route("/domain", post(switch_domain_handler))
        .route("/objectives", post(objectives_handler))
        .route("/queue/manual", post(enqueue_manual_handler))
        .route("/literature/search", post(literature_search_handler))
        .route("/papers/retrieve", post(retrieve_paper_handler))
        .route("/datasets/discover", post(discover_datasets_handler))
        .route("/loop/discover", post(run_discovery_handler))
        .route("/loop/validate", post(run_validation_handler))
        .route("/loop/connect", post(run_connection_handler))
        .route("/credentials", post(save_credentials_handler))
        .route("/export/library.md", get(export_library_md_handler))
        .route("/export/library.txt", get(export_library_txt_handler))
        .route("/export/library.json", get(export_library_json_handler))
        .route("/export/paper/{id}", get(export_paper_md_handler))
        .route("/export/validation/{id}", get(export_validation_md_handler))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}

async fn security_headers_middleware(req: Request<Body>, next: Next) -> Response {
    if req.method() == Method::POST && !same_origin_allowed(req.headers()) {
        return (
            StatusCode::FORBIDDEN,
            "Cross-origin state-changing requests are forbidden.",
        )
            .into_response();
    }

    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
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
    res
}

pub fn same_origin_allowed(headers: &HeaderMap) -> bool {
    if let Some(sec_site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if !matches!(sec_site, "same-origin" | "none") {
            return false;
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let lower = origin.to_ascii_lowercase();
        if !lower.starts_with("http://127.0.0.1:")
            && !lower.starts_with("http://localhost:")
            && lower != "http://127.0.0.1"
            && lower != "http://localhost"
        {
            return false;
        }
    }
    true
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
    pub domain: Option<String>,
}

async fn index_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WorkspaceQuery>,
) -> Html<String> {
    if let Some(ref dom_str) = query.domain {
        let requested_domain = if dom_str.eq_ignore_ascii_case("cancer") {
            ResearchDomain::Cancer
        } else {
            ResearchDomain::Dementia
        };
        let mut lib = state.library.write().await;
        if lib.pipeline.settings.domain() != requested_domain {
            lib.pipeline.select_domain(requested_domain);
            let _ = state.store.save(&lib);
        }
    }

    let section = query.section.as_deref().unwrap_or("loop");
    let flash = state.take_flash().await;
    let lib = state.library.read().await;
    let access = state.keychain.institutional_access();
    let has_claude_key = state.keychain.get("anthropic_api_key").is_some();
    let has_openai_key = state.keychain.get("openai_api_key").is_some();

    Html(render_workspace(
        &lib,
        section,
        &state.csrf_token,
        flash.as_deref(),
        &access,
        has_claude_key,
        has_openai_key,
    ))
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
    Redirect::to(&format!("/?section={}", urlencoding::encode(sec))).into_response()
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
    Redirect::to("/?section=loop").into_response()
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
    Redirect::to("/?section=queue").into_response()
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
    Redirect::to("/?section=library").into_response()
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
        return Redirect::to("/?section=library").into_response();
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
    Redirect::to("/?section=library").into_response()
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
    Redirect::to("/?section=datasets").into_response()
}

#[derive(Deserialize)]
struct RunAgentForm {
    csrf_token: String,
    vendor: String,
    model: Option<String>,
    objective: Option<String>,
    hypothesis_id: Option<String>,
}

async fn run_discovery_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<RunAgentForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let vendor = ModelVendor::parse(&form.vendor);
    let model = form
        .model
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| vendor.default_model())
        .to_string();
    let api_key = match vendor {
        ModelVendor::Anthropic => state.keychain.get("anthropic_api_key"),
        ModelVendor::OpenAi => state.keychain.get("openai_api_key"),
    }
    .unwrap_or_default();

    let (domain, prev_statements, objective) = {
        let mut lib = state.library.write().await;
        if let Err(e) = lib.pipeline.reserve_model_request(Utc::now()) {
            state.set_flash(format!("Cannot start discovery: {e}")).await;
            return Redirect::to("/?section=cycles").into_response();
        }
        let d = lib.pipeline.settings.domain();
        let prev: Vec<String> = lib
            .pipeline
            .queue
            .iter()
            .filter(|q| q.domain() == d)
            .map(|q| q.draft.statement.clone())
            .collect();
        let obj = form
            .objective
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| lib.pipeline.objectives(d).into_iter().next());
        (d, prev, obj)
    };

    let access = state.keychain.institutional_access();
    let access_search = access.clone();
    let access_retrieve = access.clone();
    let key_clone = api_key.clone();
    let model_clone = model.clone();

    let agent = AutonomousDiscoveryAgent {
        generate: Box::new(move |sys, prompt| {
            let k = key_clone.clone();
            let m = model_clone.clone();
            Box::pin(async move {
                match vendor {
                    ModelVendor::Anthropic => {
                        ClaudeProvider::default().generate(&k, &m, &sys, &prompt).await
                    }
                    ModelVendor::OpenAi => {
                        OpenAiProvider::default().generate(&k, &m, &sys, &prompt).await
                    }
                }
            })
        }),
        search: Box::new(move |q| {
            let acc = access_search.clone();
            Box::pin(async move {
                FreeLiteratureSearchClient::default()
                    .search(&q, domain, &acc)
                    .await
            })
        }),
        retrieve: Box::new(move |paper| {
            let acc = access_retrieve.clone();
            Box::pin(async move { FreeFullTextClient::default().full_text(&paper, &acc).await })
        }),
        access,
    };

    match agent
        .discover(
            objective.as_deref(),
            &prev_statements,
            vendor.display_name(),
            &model,
            domain,
            "",
        )
        .await
    {
        Ok(cycle) => {
            let count = cycle.hypotheses.len();
            let mut lib = state.library.write().await;
            LibraryStore::complete_discovery(&mut lib, cycle, Vec::new());
            let _ = state.store.save(&lib);
            state
                .set_flash(format!(
                    "Discovery cycle completed: {count} grounded hypotheses added to the validation queue."
                ))
                .await;
        }
        Err(e) => {
            state.set_flash(format!("Discovery cycle failed: {e}")).await;
        }
    }
    Redirect::to("/?section=cycles").into_response()
}

async fn run_validation_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<RunAgentForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let vendor = ModelVendor::parse(&form.vendor);
    let model = form
        .model
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| vendor.default_model())
        .to_string();
    let api_key = match vendor {
        ModelVendor::Anthropic => state.keychain.get("anthropic_api_key"),
        ModelVendor::OpenAi => state.keychain.get("openai_api_key"),
    }
    .unwrap_or_default();

    let (target_item, supplied_papers, domain) = {
        let mut lib = state.library.write().await;
        let d = lib.pipeline.settings.domain();
        let item_opt = if let Some(ref raw_id) = form.hypothesis_id {
            Uuid::parse_str(raw_id)
                .ok()
                .and_then(|id| lib.pipeline.queue.iter().find(|q| q.id == id).cloned())
        } else {
            lib.pipeline
                .queue
                .iter()
                .find(|q| q.domain() == d && q.validation_id.is_none())
                .cloned()
        };
        let Some(item) = item_opt else {
            state
                .set_flash("No queued hypothesis found to validate.")
                .await;
            return Redirect::to("/?section=queue").into_response();
        };
        if let Err(e) = lib.pipeline.reserve_model_request(Utc::now()) {
            state.set_flash(format!("Cannot start validation: {e}")).await;
            return Redirect::to("/?section=queue").into_response();
        }
        let papers = lib.research_papers(item.domain());
        let item_domain = item.domain();
        (item, papers, item_domain)
    };

    let access = state.keychain.institutional_access();
    let access_search = access.clone();
    let access_retrieve = access.clone();
    let key_clone = api_key.clone();
    let model_clone = model.clone();

    let agent = HypothesisValidationAgent {
        generate: Box::new(move |sys, prompt| {
            let k = key_clone.clone();
            let m = model_clone.clone();
            Box::pin(async move {
                match vendor {
                    ModelVendor::Anthropic => {
                        ClaudeProvider::default().generate(&k, &m, &sys, &prompt).await
                    }
                    ModelVendor::OpenAi => {
                        OpenAiProvider::default().generate(&k, &m, &sys, &prompt).await
                    }
                }
            })
        }),
        search: Box::new(move |q| {
            let acc = access_search.clone();
            Box::pin(async move {
                FreeLiteratureSearchClient::default()
                    .search(&q, domain, &acc)
                    .await
            })
        }),
        retrieve: Box::new(move |paper| {
            let acc = access_retrieve.clone();
            Box::pin(async move { FreeFullTextClient::default().full_text(&paper, &acc).await })
        }),
        access,
    };

    match agent
        .validate(
            &target_item,
            &supplied_papers,
            vendor.display_name(),
            &model,
            domain,
            "",
        )
        .await
    {
        Ok(validation) => {
            let label = validation.verdict.label();
            let mut lib = state.library.write().await;
            LibraryStore::complete_validation(&mut lib, validation, Vec::new());
            let _ = state.store.save(&lib);
            state
                .set_flash(format!("Validation completed: {label}."))
                .await;
        }
        Err(e) => {
            state.set_flash(format!("Validation failed: {e}")).await;
        }
    }
    Redirect::to("/?section=validations").into_response()
}

async fn run_connection_handler(
    State(state): State<Arc<AppState>>,
    Form(form): Form<RunAgentForm>,
) -> Response {
    if !verify_csrf(&state.csrf_token, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
    }
    let vendor = ModelVendor::parse(&form.vendor);
    let model = form
        .model
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| vendor.default_model())
        .to_string();
    let api_key = match vendor {
        ModelVendor::Anthropic => state.keychain.get("anthropic_api_key"),
        ModelVendor::OpenAi => state.keychain.get("openai_api_key"),
    }
    .unwrap_or_default();

    let (items, validations, papers, offset, domain) = {
        let mut lib = state.library.write().await;
        if let Err(e) = lib.pipeline.reserve_model_request(Utc::now()) {
            state
                .set_flash(format!("Cannot start connection review: {e}"))
                .await;
            return Redirect::to("/?section=connections").into_response();
        }
        let d = lib.pipeline.settings.domain();
        (
            lib.pipeline.queue.clone(),
            lib.pipeline.validations.clone(),
            lib.research_papers(d),
            lib.pipeline.connections.len(),
            d,
        )
    };

    let access = state.keychain.institutional_access();
    let access_search = access.clone();
    let access_retrieve = access.clone();
    let key_clone = api_key.clone();
    let model_clone = model.clone();

    let agent = HypothesisConnectionAgent {
        generate: Box::new(move |sys, prompt| {
            let k = key_clone.clone();
            let m = model_clone.clone();
            Box::pin(async move {
                match vendor {
                    ModelVendor::Anthropic => {
                        ClaudeProvider::default().generate(&k, &m, &sys, &prompt).await
                    }
                    ModelVendor::OpenAi => {
                        OpenAiProvider::default().generate(&k, &m, &sys, &prompt).await
                    }
                }
            })
        }),
        search: Box::new(move |q| {
            let acc = access_search.clone();
            Box::pin(async move {
                FreeLiteratureSearchClient::default()
                    .search(&q, domain, &acc)
                    .await
            })
        }),
        retrieve: Box::new(move |paper| {
            let acc = access_retrieve.clone();
            Box::pin(async move { FreeFullTextClient::default().full_text(&paper, &acc).await })
        }),
        access,
    };

    match agent
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
    {
        Ok(review) => {
            let count = review.proposals.len();
            let mut lib = state.library.write().await;
            LibraryStore::complete_connection(&mut lib, review, Vec::new());
            let _ = state.store.save(&lib);
            state
                .set_flash(format!(
                    "Connection review completed: {count} proposals queued."
                ))
                .await;
        }
        Err(e) => {
            state
                .set_flash(format!("Connection review failed: {e}"))
                .await;
        }
    }
    Redirect::to("/?section=connections").into_response()
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
    if let Some(ref k) = form.anthropic_api_key {
        if !k.trim().is_empty() {
            let _ = state.keychain.set("anthropic_api_key", k);
        }
    }
    if let Some(ref k) = form.openai_api_key {
        if !k.trim().is_empty() {
            let _ = state.keychain.set("openai_api_key", k);
        }
    }
    let current = state.keychain.institutional_access();
    let updated = InstitutionalAccess::new(
        form.elsevier_api_key
            .filter(|s| !s.trim().is_empty())
            .or(current.elsevier_api_key),
        form.elsevier_institution_token
            .filter(|s| !s.trim().is_empty())
            .or(current.elsevier_institution_token),
        form.wiley_tdm_token
            .filter(|s| !s.trim().is_empty())
            .or(current.wiley_tdm_token),
        form.library_proxy_prefix
            .filter(|s| !s.trim().is_empty())
            .or(current.library_proxy_prefix),
    );
    let _ = state.keychain.save_institutional_access(&updated);
    state
        .set_flash("Credentials updated in macOS Keychain.")
        .await;
    Redirect::to("/?section=sources").into_response()
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
    // Redact restricted TDM / author-manuscript bodies from exported JSON bundles as well.
    for paper in &mut lib.papers {
        if paper.is_body_redistribution_restricted() {
            if let Some(ref mut ft) = paper.full_text {
                ft.passages.clear();
            }
        }
    }
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
    Path(id): Path<String>,
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
    Path(id): Path<String>,
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
    section: &str,
    csrf_token: &str,
    flash: Option<&str>,
    access: &InstitutionalAccess,
    has_claude_key: bool,
    has_openai_key: bool,
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
            r#"<li><a href="/?section={id}"{active}><span>{}</span><span class="badge">{count}</span></a></li>"#,
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
        "sources" => render_sources_section(domain, csrf_token, access, has_claude_key, has_openai_key),
        "connections" => render_connections_section(&domain_connections, csrf_token),
        _ => render_loop_section(lib, domain, csrf_token),
    };

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
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{} Medical Research Agent — Hardened Rust/Axum SSR</title>
  <link rel="stylesheet" href="/static/app.css">
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <div class="brand">
        <h1>Medical Research</h1>
        <p class="subtitle">Rust + Axum SSR · <code>#![forbid(unsafe_code)]</code> · <code>rustls</code></p>
      </div>
      <form method="post" action="/domain" class="domain-switcher">
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
          <a href="/export/library.md" class="btn-link">Markdown</a>
          <a href="/export/library.txt" class="btn-link">Text</a>
          <a href="/export/library.json" class="btn-link">JSON</a>
        </div>
      </div>
    </aside>
    <main class="content">
      {flash_html}
      {main_content}
    </main>
  </div>
</body>
</html>"#,
        html_escape(domain.display_name()),
        html_escape(section)
    )
}

fn render_loop_section(
    lib: &LibrarySnapshot,
    domain: ResearchDomain,
    csrf_token: &str,
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
                  <form method="post" action="/objectives" class="inline-form">
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
          <form method="post" action="/loop/discover" class="stack">
            <input type="hidden" name="csrf_token" value="{csrf}">
            <label>Model provider
              <select name="vendor">
                <option value="anthropic">Claude (Anthropic)</option>
                <option value="openai">OpenAI (store: false)</option>
              </select>
            </label>
            <label>Optional focus objective
              <input type="text" name="objective" placeholder="{}">
            </label>
            <button type="submit" class="btn-primary">Run Discovery Cycle</button>
          </form>
          <hr>
          <div class="row">
            <form method="post" action="/loop/validate">
              <input type="hidden" name="csrf_token" value="{csrf}">
              <input type="hidden" name="vendor" value="anthropic">
              <button type="submit" class="btn-secondary">Validate Next Queued Hypothesis</button>
            </form>
            <form method="post" action="/loop/connect">
              <input type="hidden" name="csrf_token" value="{csrf}">
              <input type="hidden" name="vendor" value="anthropic">
              <button type="submit" class="btn-secondary">Run Connection Review</button>
            </form>
          </div>
        </section>
        <section class="card">
          <h3>Queued Research Objectives ({})</h3>
          <form method="post" action="/objectives" class="row">
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
            r#"<span class="pill pill-warn">TDM / Author MS (Body not exported)</span>"#
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
                <a href="/export/paper/{}" class="btn-link">Export Markdown</a>
                {proxy_link}
                <form method="post" action="/papers/retrieve" class="inline-form">
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
        <form method="post" action="/literature/search" class="row">
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
              <form method="post" action="/loop/validate" class="row">
                <input type="hidden" name="csrf_token" value="{csrf}">
                <input type="hidden" name="vendor" value="anthropic">
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
        <form method="post" action="/queue/manual" class="stack">
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
                <a href="/export/validation/{}" class="btn-link">Export Assessment Markdown</a>
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
        <form method="post" action="/datasets/discover" class="row">
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
            </article>"#,
            html_escape(&c.objective),
            html_escape(&c.id.to_string()),
            html_escape(&c.created_at.to_rfc3339()),
            c.landscape.len(),
            c.hypotheses.len()
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
        <form method="post" action="/loop/discover" class="row">
          <input type="hidden" name="csrf_token" value="{csrf}">
          <input type="hidden" name="vendor" value="anthropic">
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
) -> String {
    let csrf = html_escape(csrf_token);
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
        "Configured in Keychain"
    } else {
        "Not configured"
    };
    let openai_status = if has_openai_key {
        "Configured in Keychain"
    } else {
        "Not configured"
    };
    let elsevier_status = if access.elsevier_api_key.is_some() {
        "Configured in Keychain"
    } else {
        "Not configured"
    };
    let wiley_status = if access.wiley_tdm_token.is_some() {
        "Configured in Keychain"
    } else {
        "Not configured"
    };

    format!(
        r#"<header class="page-header">
        <h2>Configured Sources &amp; Keychain Credentials ({})</h2>
        <p>Per-search cap: <strong>{max_records}</strong> records ({} field journals × 3 + {} mechanism journals × 2 + wider Europe PMC corpus × {WIDER_CORPUS_PAGE_SIZE}).</p>
      </header>
      <section class="card">
        <h3>macOS Keychain Credentials (Never stored in <code>library.json</code> or echoed to HTML)</h3>
        <form method="post" action="/credentials" class="stack">
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
          <button type="submit" class="btn-primary">Save to Keychain</button>
        </form>
      </section>
      <div class="stack">{journal_rows}</div>"#,
        html_escape(domain.display_name()),
        ResearchSourceCatalog::journals(domain).len(),
        ResearchSourceCatalog::mechanism_journals(domain).len()
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
              <p class="caption">Created: {} · Proposals queued: {}</p>
            </article>"#,
            html_escape(&rev.id.to_string()),
            html_escape(&rev.created_at.to_rfc3339()),
            rev.proposals.len()
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
        <form method="post" action="/loop/connect" class="row">
          <input type="hidden" name="csrf_token" value="{csrf}">
          <input type="hidden" name="vendor" value="anthropic">
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
  grid-template-columns: 280px 1fr;
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
"#;
