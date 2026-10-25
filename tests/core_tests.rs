use chrono::Utc;
use dementia_research_web::catalog::{JournalTier, ResearchSourceCatalog};
use dementia_research_web::citation::{EvidenceValidator, QuoteMatcher};
use dementia_research_web::datasets::CancerDatasetUrlPolicy;
use dementia_research_web::dedup::PaperDeduplicator;
use dementia_research_web::literature::{EuropePmcClient, PublicLiteratureUrlPolicy};
use dementia_research_web::models::{
    ArticleText, CitationVerificationStatus, EvidenceCitation, InstitutionalAccess, Paper, Passage,
    ResearchDomain,
};
use dementia_research_web::parsers::{ArticleTextParser, AUTHOR_MANUSCRIPT_LICENSE};
use dementia_research_web::report::ResearchReportBuilder;
use dementia_research_web::web::{
    html_escape, same_origin_allowed, verify_csrf, AppState, SESSION_COOKIE,
};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request};
use std::sync::Arc;
use url::Url;

/// A fresh app state on an empty temporary data directory.
fn fresh_state() -> (Arc<AppState>, std::path::PathBuf) {
    use dementia_research_web::providers::KeychainStore;
    use dementia_research_web::store::LibraryStore;
    let dir = std::env::temp_dir().join(format!("dra-test-{}", uuid::Uuid::new_v4()));
    let state = AppState::new(
        LibraryStore::new(dir.join("library.json")),
        KeychainStore::in_memory(),
    )
    .expect("state");
    (state, dir)
}

/// A request as the owner's browser sends it: addressed to the loopback host and carrying
/// the session cookie the start link set.
fn owner_request(state: &AppState, method: Method, uri: &str) -> axum::http::request::Builder {
    owner_request_at(state, method, uri, "127.0.0.1:8080")
}

fn owner_request_at(
    state: &AppState,
    method: Method,
    uri: &str,
    host: &str,
) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, host)
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", state.session_token),
        )
}

/// A paper whose stored body may not be redistributed, holding `sentinel` as its only passage.
fn restricted_paper(id: &str, sentinel: &str) -> Paper {
    let source_url = Url::parse("https://www.ncbi.nlm.nih.gov/research/bionlp/RESTful/pmcoa.cgi/BioC_json/PMC6500498/unicode").unwrap();
    Paper {
        id: id.to_string(),
        title: "L1 drives IFN in senescent cells".to_string(),
        pmcid: Some("PMC6500498".to_string()),
        is_open_access: false,
        is_author_manuscript: true,
        full_text: Some(ArticleText {
            passages: vec![Passage {
                id: "body-1".to_string(),
                section: "Results".to_string(),
                text: sentinel.to_string(),
            }],
            format: "PMC BioC JSON".to_string(),
            source_url,
            retrieved_at: Utc::now(),
            checksum: "abc123".to_string(),
            license: Some(AUTHOR_MANUSCRIPT_LICENSE.to_string()),
            version: None,
            license_url: None,
        }),
        ..Paper::default()
    }
}

#[test]
fn catalog_tiers_and_caps_match_specification() {
    let dementia_field = ResearchSourceCatalog::journals(ResearchDomain::Dementia);
    let dementia_mech = ResearchSourceCatalog::mechanism_journals(ResearchDomain::Dementia);
    assert_eq!(dementia_field.len(), 8);
    assert_eq!(dementia_mech.len(), 7);
    assert!(dementia_field.iter().all(|j| j.tier == JournalTier::Field && j.page_size() == 3));
    assert!(dementia_mech.iter().all(|j| j.tier == JournalTier::Mechanism && j.page_size() == 2));
    assert_eq!(
        ResearchSourceCatalog::maximum_records(ResearchDomain::Dementia),
        50
    );

    let cancer_field = ResearchSourceCatalog::journals(ResearchDomain::Cancer);
    let cancer_mech = ResearchSourceCatalog::mechanism_journals(ResearchDomain::Cancer);
    assert_eq!(cancer_field.len(), 8);
    assert_eq!(cancer_mech.len(), 0);
    assert_eq!(
        ResearchSourceCatalog::maximum_records(ResearchDomain::Cancer),
        36
    );
}

#[test]
fn europe_pmc_query_excludes_abstracts_and_scopes_access() {
    let open_only = InstitutionalAccess::default();
    let q = EuropePmcClient::compose_query("microglia", true, true, &open_only).unwrap();
    assert_eq!(
        q,
        r#"((microglia) NOT PUB_TYPE:"Abstract") AND (OPEN_ACCESS:Y OR AUTH_MAN:Y)"#
    );

    let with_elsevier = InstitutionalAccess::new(
        Some("els-key".to_string()),
        None,
        None,
        None,
    );
    let q_tdm = EuropePmcClient::compose_query("microglia", true, true, &with_elsevier).unwrap();
    assert_eq!(
        q_tdm,
        r#"((microglia) NOT PUB_TYPE:"Abstract") AND (OPEN_ACCESS:Y OR AUTH_MAN:Y OR DOI:10.1016*)"#
    );
}

#[test]
fn deduplicator_bridges_shared_identifiers_and_preserves_distinct_versions() {
    let p1 = Paper {
        id: "MED:1".to_string(),
        title: "cGAS-STING in aged microglia".to_string(),
        doi: Some("10.1038/s41586-023-06373-1".to_string()),
        ..Paper::default()
    };
    let p2 = Paper {
        id: "PMC:2".to_string(),
        title: "cGAS-STING in aged microglia".to_string(),
        doi: Some("https://doi.org/10.1038/S41586-023-06373-1".to_string()),
        pmcid: Some("PMC10409717".to_string()),
        is_open_access: true,
        ..Paper::default()
    };
    let merged = PaperDeduplicator::deduplicate(&[p1, p2]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].pmcid.as_deref(), Some("PMC10409717"));
    assert!(merged[0].is_open_access);
}

#[test]
fn quote_matcher_enforces_20_chars_word_boundaries_and_negation() {
    let passage = "In aged mice, pharmacological STING inhibition did not improve tau pathology in the cortex, whereas microglial cGAS activation drove persistent type I interferon signaling.";

    // Valid quote >= 20 chars with intact context
    let valid_quote = "microglial cGAS activation drove persistent type I interferon signaling";
    let matched = QuoteMatcher::locate(valid_quote, passage);
    assert!(matched.is_some());

    // Rejects quote that drops preceding negation ("did not ")
    let dropped_negation = "improve tau pathology in the cortex, whereas microglial cGAS";
    assert!(QuoteMatcher::locate(dropped_negation, passage).is_none());

    // Rejects mid-word boundary clip
    let clipped = "croglial cGAS activation drove persistent type I interferon";
    assert!(QuoteMatcher::locate(clipped, passage).is_none());
}

#[test]
fn parsers_reject_xxe_entities_and_bioc_html_error_pages() {
    let xxe_xml = br#"<?xml version="1.0"?><!DOCTYPE article [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><article><body><p>&xxe;</p></body></article>"#;
    let url = Url::parse("https://www.ebi.ac.uk/europepmc/webservices/rest/PMC1/fullTextXML").unwrap();
    let res = ArticleTextParser::jats(xxe_xml, url.clone(), None);
    assert!(res.is_err());

    let bioc_missing = br#"<html><body>No result can be found.</body></html>"#;
    let bioc_url = Url::parse("https://www.ncbi.nlm.nih.gov/research/bionlp/RESTful/pmcoa.cgi/BioC_json/PMC1/unicode").unwrap();
    let bioc_res = ArticleTextParser::bioc(bioc_missing, bioc_url, Some(AUTHOR_MANUSCRIPT_LICENSE), Some("PMC1"));
    assert!(bioc_res.is_err());
}

#[test]
fn report_builder_omits_restricted_author_manuscript_and_tdm_passages() {
    let paper = restricted_paper(
        "MED:30728521",
        "Sensitive author manuscript body text that must not be redistributed in full.",
    );

    assert!(paper.is_body_redistribution_restricted());
    let report = ResearchReportBuilder::paper(&paper);
    let md = report.markdown();
    assert!(!md.contains("Sensitive author manuscript body text"));
    assert!(md.contains("omitted from exported reports because the source carries no open redistribution licence"));
}

#[test]
fn url_policies_enforce_https_allowlist_and_reject_credentials_or_tokens() {
    let valid_epmc = Url::parse("https://www.ebi.ac.uk/europepmc/webservices/rest/search?query=test").unwrap();
    assert!(PublicLiteratureUrlPolicy::allows(&valid_epmc, false));

    let http_epmc = Url::parse("http://www.ebi.ac.uk/europepmc/webservices/rest/search").unwrap();
    assert!(!PublicLiteratureUrlPolicy::allows(&http_epmc, false));

    let leaked_token = Url::parse("https://www.ebi.ac.uk/europepmc/webservices/rest/search?api_key=secret").unwrap();
    assert!(!PublicLiteratureUrlPolicy::allows(&leaked_token, false));

    let valid_gdc = Url::parse("https://api.gdc.cancer.gov/projects?size=10").unwrap();
    assert!(CancerDatasetUrlPolicy::allows(&valid_gdc));

    let disallowed_gdc_path = Url::parse("https://api.gdc.cancer.gov/cases").unwrap();
    assert!(!CancerDatasetUrlPolicy::allows(&disallowed_gdc_path));
}

#[test]
fn web_security_primitives_escape_xss_and_verify_csrf_and_origin() {
    let raw = r#"<script>alert("xss" & 'csr')</script>"#;
    assert_eq!(
        html_escape(raw),
        "&lt;script&gt;alert(&quot;xss&quot; &amp; &#x27;csr&#x27;)&lt;/script&gt;"
    );

    assert!(verify_csrf("token-123456", "token-123456"));
    assert!(!verify_csrf("token-123456", "token-123457"));
    assert!(!verify_csrf("token-123456", "short"));

    let mut ok_headers = HeaderMap::new();
    ok_headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    ok_headers.insert(header::ORIGIN, HeaderValue::from_static("http://127.0.0.1:8080"));
    assert!(same_origin_allowed(&ok_headers));

    let mut cross_site = HeaderMap::new();
    cross_site.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
    assert!(!same_origin_allowed(&cross_site));

    let mut evil_origin = HeaderMap::new();
    evil_origin.insert(header::ORIGIN, HeaderValue::from_static("https://evil.example.com"));
    assert!(!same_origin_allowed(&evil_origin));
}

#[test]
fn citation_verifier_records_verified_status_and_sha256_provenance() {
    let source_url = Url::parse("https://www.ebi.ac.uk/europepmc/webservices/rest/PMC1/fullTextXML").unwrap();
    let paper = Paper {
        id: "PMC1".to_string(),
        title: "Test paper".to_string(),
        is_open_access: true,
        full_text: Some(ArticleText {
            passages: vec![Passage {
                id: "body-1".to_string(),
                section: "Results".to_string(),
                text: "Loss of progranulin causes bis(monoacylglycero)phosphate deficiency and ganglioside accumulation in lysosomes.".to_string(),
            }],
            format: "Europe PMC JATS XML".to_string(),
            source_url,
            retrieved_at: Utc::now(),
            checksum: "deadbeefcafe".to_string(),
            license: Some("cc-by".to_string()),
            version: None,
            license_url: None,
        }),
        ..Paper::default()
    };

    let sources = EvidenceValidator::verification_documents(&[paper], true);
    let cit = EvidenceCitation::new(
        "PMC1",
        "body-1",
        "bis(monoacylglycero)phosphate deficiency and ganglioside accumulation in lysosomes",
        "Supports lysosomal lipid defect",
    );
    let checked = EvidenceValidator::verify(&cit, &sources, Utc::now());
    assert_eq!(
        checked.verification_status,
        Some(CitationVerificationStatus::Verified)
    );
    assert_eq!(checked.source_checksum.as_deref(), Some("deadbeefcafe"));
}

#[test]
fn swift_dates_round_trip_exactly_and_accept_rfc3339() {
    use dementia_research_web::swift_date::{from_seconds, to_seconds};

    let reference = from_seconds(0.0).expect("reference date");
    assert_eq!(reference.to_rfc3339(), "2001-01-01T00:00:00+00:00");
    let before = from_seconds(-0.25).expect("pre-2001 date");
    assert_eq!(before.to_rfc3339(), "2000-12-31T23:59:59.750+00:00");
    // A value written by the Swift app must come back bit-for-bit identical.
    for seconds in [814019254.801979, 814022562.203605, 814019276.298247] {
        assert_eq!(to_seconds(&from_seconds(seconds).expect("date")), seconds);
    }
    assert!(from_seconds(f64::NAN).is_none());
}

#[test]
fn library_snapshot_uses_swift_library_json_format() {
    use dementia_research_web::models::LibrarySnapshot;

    // Swift dates are `Double`s (~0.1 µs resolution today), so use one the Swift app wrote
    // rather than `Utc::now()`, whose nanoseconds would not survive the round trip.
    let swift_date = dementia_research_web::swift_date::from_seconds(814019254.801979)
        .expect("date");
    let mut snapshot = LibrarySnapshot::default();
    snapshot.pipeline.model_usage_date = swift_date;
    snapshot.papers.push(Paper {
        id: "PMC1".to_string(),
        abstract_text: "Swift stores this under the abstract key.".to_string(),
        retrieved_at: swift_date,
        ..Paper::default()
    });
    snapshot.runs.push(serde_json::json!({ "createdAt": 814019437.491332, "hypotheses": [] }));

    let mut json = serde_json::to_value(&snapshot).expect("encode");
    let paper = &json["papers"][0];
    assert_eq!(paper["abstract"], "Swift stores this under the abstract key.");
    assert!(paper.get("abstractText").is_none());
    assert!(paper["retrievedAt"].is_f64(), "dates are Swift reference-date seconds");
    assert_eq!(json["runs"][0]["createdAt"], 814019437.491332);
    assert!(json["pipeline"]["modelUsageDate"].is_f64());

    let decoded: LibrarySnapshot = serde_json::from_value(json.clone()).expect("decode");
    assert_eq!(decoded, snapshot);

    // Files written by earlier builds of this port (abstractText, RFC 3339 dates) still load.
    let paper = json["papers"][0].as_object_mut().expect("paper object");
    let abstract_text = paper.remove("abstract").expect("abstract");
    paper.insert("abstractText".to_string(), abstract_text);
    paper.insert("retrievedAt".to_string(), "2026-10-18T12:27:34Z".into());
    let legacy: LibrarySnapshot = serde_json::from_value(json).expect("decode legacy");
    assert_eq!(legacy.papers[0].abstract_text, "Swift stores this under the abstract key.");
    assert_eq!(legacy.papers[0].retrieved_at.to_rfc3339(), "2026-10-18T12:27:34+00:00");
}

#[tokio::test]
async fn pages_send_origin_on_same_origin_form_posts() {
    use axum::body::Body;
    use axum::http::StatusCode;
    use dementia_research_web::web::build_router;
    use tower::ServiceExt;

    let (state, dir) = fresh_state();
    let app = build_router(state.clone());

    // `no-referrer` makes browsers send `Origin: null` on form posts, which the origin check
    // rejects; every button in the app then failed with 403.
    let page = app
        .clone()
        .oneshot(owner_request(&state, Method::GET, "/").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()[header::REFERRER_POLICY], "same-origin");

    let null_origin = owner_request(&state, Method::POST, "/domain")
        .header(header::ORIGIN, "null")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("domain=cancer"))
        .expect("request");
    let rejected = app.oneshot(null_origin).await.expect("response");
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn chatgpt_plan_stream_succeeds_only_on_completed_event() {
    use dementia_research_web::models::ResearchError;
    use dementia_research_web::providers::parse_responses_stream;

    let ok = "event: response.created\ndata: {\"type\":\"response.created\"}\n\n\
              data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello\"}\n\n\
              data: {\"type\":\"response.output_text.delta\",\"delta\":\", plan\"}\n\n\
              data: {\"type\":\"response.completed\",\"response\":{}}\n\n";
    assert_eq!(parse_responses_stream(ok).expect("text"), "Hello, plan");

    // Text without a completion event is a failed request.
    let cut = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n";
    assert!(matches!(parse_responses_stream(cut), Err(ResearchError::Unavailable(_))));

    let limit = "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"subscription_sharing_usage_limit_exceeded\",\"message\":\"limit\"}}}\n\n";
    let err = parse_responses_stream(limit).expect_err("usage limit").to_string();
    assert!(err.contains("Usage limit reached") && err.contains("chatgpt.com/settings/usage"));

    let incomplete = "data: {\"type\":\"response.incomplete\",\"response\":{\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}}";
    let err = parse_responses_stream(incomplete).expect_err("incomplete").to_string();
    assert!(err.contains("incomplete (max_output_tokens)"));
}

#[tokio::test]
async fn continue_with_chatgpt_redirects_to_openai_with_loopback_callback() {
    use axum::body::Body;
    use axum::http::StatusCode;
    use dementia_research_web::web::build_router;
    use tower::ServiceExt;

    let (state, dir) = fresh_state();
    let csrf = state.csrf_token.clone();
    let session = state.session_token.clone();
    let app = build_router(state);

    let sign_in = move |host: &'static str, token: String| {
        Request::builder()
            .method(Method::POST)
            .uri("/chatgpt/sign-in")
            .header(header::HOST, host)
            .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
            .header(header::ORIGIN, format!("http://{host}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf_token={token}")))
            .expect("request")
    };

    let response = app.clone().oneshot(sign_in("localhost:18080", csrf.clone())).await.expect("response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = Url::parse(response.headers()[header::LOCATION].to_str().expect("location")).expect("url");
    assert_eq!(location.host_str(), Some("auth.openai.com"));
    let redirect_uri = location
        .query_pairs()
        .find(|(k, _)| k == "redirect_uri")
        .map(|(_, v)| v.into_owned());
    // Always 127.0.0.1 (never localhost), on the port the app was reached on.
    assert_eq!(redirect_uri.as_deref(), Some("http://127.0.0.1:18080/auth/callback"));
    assert!(dir.join("chatgpt-host.json").exists());

    let forged = app.clone().oneshot(sign_in("localhost:18080", "wrong".into())).await.expect("response");
    assert_eq!(forged.status(), StatusCode::FORBIDDEN);

    // A callback that does not match the pending sign-in is refused without saving anything.
    // The callback needs no session cookie (it is bound to the sign-in by `state`), but it
    // must still be addressed to the loopback host.
    let callback = Request::get("/auth/callback?code=abc&state=forged&client_id=oaiapp_x")
        .header(header::HOST, "127.0.0.1:18080")
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(callback).await.expect("response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(!dir.join("chatgpt-auth.json").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn data_directory_follows_each_platforms_convention() {
    use dementia_research_web::store::data_dir_for;
    use std::ffi::OsString;
    use std::path::PathBuf;

    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| OsString::from(*v))
        }
    };
    let windows = data_dir_for(env(&[("APPDATA", "/C/Users/ada/AppData/Roaming"), ("HOME", "/C/Users/ada")]), true, false);
    assert_eq!(windows, PathBuf::from("/C/Users/ada/AppData/Roaming/DementiaResearch"));
    // Windows without APPDATA falls back to the profile, never to the working directory.
    let profile = data_dir_for(env(&[("USERPROFILE", "/C/Users/ada")]), true, false);
    assert_eq!(profile, PathBuf::from("/C/Users/ada/AppData/Roaming/DementiaResearch"));

    let mac = data_dir_for(env(&[("HOME", "/Users/ada"), ("XDG_DATA_HOME", "/x")]), false, true);
    assert_eq!(mac, PathBuf::from("/Users/ada/Library/Application Support/DementiaResearch"));

    let xdg = data_dir_for(env(&[("HOME", "/home/ada"), ("XDG_DATA_HOME", "/data/ada")]), false, false);
    assert_eq!(xdg, PathBuf::from("/data/ada/dementia-research"));
    let linux = data_dir_for(env(&[("HOME", "/home/ada"), ("XDG_DATA_HOME", "relative")]), false, false);
    assert_eq!(linux, PathBuf::from("/home/ada/.local/share/dementia-research"));

    let overridden = data_dir_for(env(&[("DEMENTIA_RESEARCH_DATA_DIR", "/srv/dra"), ("APPDATA", "/a")]), true, false);
    assert_eq!(overridden, PathBuf::from("/srv/dra"));
}

#[test]
fn private_file_secret_store_round_trips_with_owner_only_permissions() {
    use dementia_research_web::providers::KeychainStore;

    let dir = std::env::temp_dir().join(format!("dra-secrets-{}", uuid::Uuid::new_v4()));
    let path = dir.join("secrets.json");
    let store = KeychainStore::private_file(&path);
    assert!(!store.backend().is_encrypted_store());

    store.set("anthropic_api_key", "  sk-ant-test-value  ").expect("save");
    store.set("openai_api_key", "sk-test-other").expect("save");
    assert_eq!(store.get("anthropic_api_key").as_deref(), Some("sk-ant-test-value"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // A fresh store reading the same file sees the saved values.
    let reopened = KeychainStore::private_file(&path);
    assert_eq!(reopened.get("openai_api_key").as_deref(), Some("sk-test-other"));

    assert!(store.set("anthropic_api_key", "line\nbreak").is_err());
    store.set("anthropic_api_key", "").expect("blank deletes");
    assert_eq!(reopened.get("anthropic_api_key"), None);
    assert_eq!(reopened.get("openai_api_key").as_deref(), Some("sk-test-other"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn openai_model_list_keeps_only_text_generation_models() {
    use dementia_research_web::providers::is_openai_text_model;

    for id in ["gpt-5.4", "gpt-4o-mini", "o3", "o4-mini", "chatgpt-4o-latest"] {
        assert!(is_openai_text_model(id), "{id} should be offered");
    }
    for id in [
        "text-embedding-3-large", "tts-1", "whisper-1", "dall-e-3", "gpt-4o-realtime-preview",
        "gpt-4o-mini-transcribe", "gpt-image-1", "omni-moderation-latest", "gpt-3.5-turbo-instruct",
        "babbage-002", "gpt-4o-search-preview",
    ] {
        assert!(!is_openai_text_model(id), "{id} should be hidden");
    }
}

#[tokio::test]
async fn loop_page_offers_automatic_model_and_explains_missing_providers() {
    use axum::body::Body;
    use dementia_research_web::web::build_router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let (state, dir) = fresh_state();
    let app = build_router(state.clone());
    let response = app
        .oneshot(
            owner_request(&state, Method::GET, "/?section=loop")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let html = String::from_utf8(
        response.into_body().collect().await.expect("body").to_bytes().to_vec(),
    )
    .expect("utf8");
    assert!(html.contains(r#"<option value="automatic" selected>Automatic</option>"#));
    assert!(html.contains("Not set up: ChatGPT plan, Claude (Anthropic), OpenAI."));
    assert!(!html.contains("<optgroup"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn credential_formats_are_checked_before_saving() {
    use dementia_research_web::providers::check_credential_format as check;

    let claude = format!("sk-ant-api03-{}", "A".repeat(40));
    assert!(check("anthropic_api_key", &claude).is_ok());
    for bad in ["sk-ant-oat01-abcdefghijklmnopqrstuvwxyz0123456789", "sk-ant-admin01-abcdefghijklmnopqrstuvwxyz0123456789", "sk-proj-abc", "hello", "sk-ant-api03-short"] {
        assert!(check("anthropic_api_key", bad).is_err(), "{bad} accepted");
    }
    let err = check("anthropic_api_key", "sk-ant-oat01-abcdefghijklmnopqrstuvwxyz0123456789").unwrap_err();
    assert!(err.contains("sign-in token") && !err.contains("abcdefgh"), "message must not echo the value");

    let openai = format!("sk-proj-{}", "b".repeat(48));
    assert!(check("openai_api_key", &openai).is_ok());
    assert!(check("openai_api_key", &format!("sk-admin-{}", "c".repeat(40))).is_err());
    assert!(check("openai_api_key", &claude.replace("sk-", "pk-")).is_err());

    assert!(check("elsevier_api_key", "0123456789abcdef0123456789abcdef").is_ok());
    assert!(check("elsevier_api_key", "not a key!").is_err());
    assert!(check("wiley_tdm_token", "123e4567-e89b-12d3-a456-426614174000").is_ok());
    assert!(check("wiley_tdm_token", "not-a-token").is_err());
    assert!(check("library_proxy_prefix", "https://ezproxy.example.edu/login?url=").is_ok());
    assert!(check("library_proxy_prefix", "http://ezproxy.example.edu/login?url=").is_err());
    assert!(check("library_proxy_prefix", "https://user:pw@ezproxy.example.edu/").is_err());
}

#[tokio::test]
async fn rejected_keys_are_removed_unless_already_replaced() {
    use dementia_research_web::model_catalog::ModelCatalog;
    use dementia_research_web::providers::{KeychainStore, ModelVendor};

    let dir = std::env::temp_dir().join(format!("dra-test-{}", uuid::Uuid::new_v4()));
    let keychain = KeychainStore::in_memory();
    let catalog = ModelCatalog::new(&dir);

    keychain.set("anthropic_api_key", "sk-ant-api03-old").expect("save");
    let message = catalog
        .forget_rejected_key(&keychain, ModelVendor::Anthropic, "sk-ant-api03-old")
        .await;
    assert!(message.contains("was removed"));
    assert_eq!(keychain.get("anthropic_api_key"), None);
    assert_eq!(catalog.take_notices(), vec![message]);
    assert!(catalog.take_notices().is_empty());

    // A key saved after the rejected request was sent is kept.
    keychain.set("openai_api_key", "sk-proj-new").expect("save");
    catalog
        .forget_rejected_key(&keychain, ModelVendor::OpenAi, "sk-proj-old")
        .await;
    assert_eq!(keychain.get("openai_api_key").as_deref(), Some("sk-proj-new"));
    assert!(catalog.take_notices().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn credentials_form_saves_valid_keys_and_explains_rejected_ones() {
    use axum::body::Body;
    use axum::http::StatusCode;
    use dementia_research_web::providers::KeychainStore;
    use dementia_research_web::store::LibraryStore;
    use dementia_research_web::web::build_router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let dir = std::env::temp_dir().join(format!("dra-test-{}", uuid::Uuid::new_v4()));
    let keychain = KeychainStore::in_memory();
    let state = AppState::new(LibraryStore::new(dir.join("library.json")), keychain.clone())
        .expect("state");
    let csrf = state.csrf_token.clone();
    let app = build_router(state.clone());

    let openai = format!("sk-proj-{}", "b".repeat(48));
    let body = format!(
        "csrf_token={csrf}&anthropic_api_key=sk-ant-oat01-notanapikeyatallnotanapikeyatall&openai_api_key={openai}"
    );
    let response = app
        .clone()
        .oneshot(
            owner_request(&state, Method::POST, "/credentials")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(keychain.get("anthropic_api_key"), None);
    assert_eq!(keychain.get("openai_api_key").as_deref(), Some(openai.as_str()));

    let page = app
        .oneshot(
            owner_request(&state, Method::GET, "/?section=sources")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let html = String::from_utf8(page.into_body().collect().await.expect("body").to_bytes().to_vec())
        .expect("utf8");
    assert!(html.contains("Claude API key not saved: That is a Claude sign-in token"));
    assert!(html.contains("Credentials saved to memory."));
    assert!(!html.contains("notanapikey"), "the rejected value must not be echoed");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn only_a_401_naming_the_key_as_invalid_counts_as_an_invalid_key() {
    use dementia_research_web::providers::{is_invalid_key_response as invalid, ModelVendor::{Anthropic, ChatGpt, OpenAi}};

    let anthropic_auth = br#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"},"request_id":"req_1"}"#;
    let anthropic_missing = br#"{"type":"error","error":{"type":"authentication_error","message":"x-api-key header is required"}}"#;
    let anthropic_credit = br#"{"type":"error","error":{"type":"invalid_request_error","message":"Your credit balance is too low to access the Anthropic API."}}"#;
    let anthropic_permission = br#"{"type":"error","error":{"type":"permission_error","message":"Your API key does not have permission to use the specified resource."}}"#;
    let anthropic_rate = br#"{"type":"error","error":{"type":"rate_limit_error","message":"Number of request tokens has exceeded your per-minute rate limit"}}"#;
    let anthropic_overloaded = br#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#;
    assert!(invalid(Anthropic, 401, anthropic_auth));
    assert!(invalid(Anthropic, 401, anthropic_missing));
    assert!(!invalid(Anthropic, 400, anthropic_credit));
    assert!(!invalid(Anthropic, 403, anthropic_permission));
    assert!(!invalid(Anthropic, 429, anthropic_rate));
    assert!(!invalid(Anthropic, 529, anthropic_overloaded));
    // A 401 that does not name the key as invalid is not enough.
    assert!(!invalid(Anthropic, 401, anthropic_permission));
    assert!(!invalid(Anthropic, 401, b"<html>Unauthorized</html>"));
    assert!(!invalid(Anthropic, 401, b""));

    let openai_invalid = br#"{"error":{"message":"Incorrect API key provided: sk-****abcd.","type":"invalid_request_error","param":null,"code":"invalid_api_key"}}"#;
    let openai_quota = br#"{"error":{"message":"You exceeded your current quota.","type":"insufficient_quota","param":null,"code":"insufficient_quota"}}"#;
    let openai_org = br#"{"error":{"message":"You must be a member of an organization to use the API.","type":"invalid_request_error","param":null,"code":"no_organization"}}"#;
    let openai_ip = br#"{"error":{"message":"You are not allowed to access this resource from this IP address.","type":"invalid_request_error","param":null,"code":null}}"#;
    assert!(invalid(OpenAi, 401, openai_invalid));
    assert!(!invalid(OpenAi, 429, openai_quota));
    assert!(!invalid(OpenAi, 401, openai_org));
    assert!(!invalid(OpenAi, 401, openai_ip));
    // Each provider's rule applies only to its own responses.
    assert!(!invalid(OpenAi, 401, anthropic_auth));
    assert!(!invalid(Anthropic, 401, openai_invalid));
    assert!(!invalid(ChatGpt, 401, openai_invalid));
}

#[tokio::test]
async fn local_clients_are_refused_until_the_start_link_is_opened() {
    use axum::body::Body;
    use axum::http::StatusCode;
    use dementia_research_web::web::build_router;
    use tower::ServiceExt;

    let (state, dir) = fresh_state();
    let csrf = state.csrf_token.clone();
    let app = build_router(state.clone());
    let anonymous = |method: Method, uri: &str| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "127.0.0.1:8080")
    };

    // Another local process can connect to the loopback port, but gets nothing without
    // the session cookie: no page, no export, no event stream, no action.
    for uri in ["/", "/?section=library", "/export/library.json", "/export/library.md", "/events"] {
        let response = app
            .clone()
            .oneshot(anonymous(Method::GET, uri).body(Body::empty()).expect("request"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }
    let post = anonymous(Method::POST, "/domain")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("csrf_token={csrf}&domain=cancer")))
        .expect("request");
    let response = app.clone().oneshot(post).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        state.library.read().await.pipeline.settings.domain(),
        ResearchDomain::Dementia
    );

    // The stylesheet and script hold nothing private.
    let css = app
        .clone()
        .oneshot(anonymous(Method::GET, "/static/app.css").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(css.status(), StatusCode::OK);

    // A wrong token does not start a session; the right one sets the cookie and drops the
    // token from the address.
    let wrong = app
        .clone()
        .oneshot(anonymous(Method::GET, "/?token=nope").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert!(wrong.headers().get(header::SET_COOKIE).is_none());

    let start = format!("/?token={}", state.bootstrap_token);
    let started = app
        .clone()
        .oneshot(anonymous(Method::GET, &start).body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(started.status(), StatusCode::SEE_OTHER);
    assert_eq!(started.headers()[header::LOCATION], "/");
    let cookie = started.headers()[header::SET_COOKIE].to_str().expect("cookie");
    assert!(cookie.starts_with(&format!("{SESSION_COOKIE}={}", state.session_token)));
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"));
    assert_eq!(state.start_link(&"127.0.0.1:8080".parse().unwrap()), format!("http://127.0.0.1:8080{start}"));

    // With the cookie, every loopback spelling works.
    for host in ["127.0.0.1:8080", "localhost:8080", "[::1]:8080"] {
        let response = app
            .clone()
            .oneshot(
                owner_request_at(&state, Method::GET, "/", host)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK, "{host}");
    }

    // A DNS name an attacker points at 127.0.0.1 is refused before any handler runs, cookie or not.
    let rebound = app
        .clone()
        .oneshot(
            owner_request_at(&state, Method::GET, "/export/library.json", "research.attacker.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(rebound.status(), StatusCode::MISDIRECTED_REQUEST);
    // So is a request with two Host headers, whichever comes first.
    let ambiguous = app
        .oneshot(
            owner_request(&state, Method::GET, "/")
                .header(header::HOST, "research.attacker.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(ambiguous.status(), StatusCode::MISDIRECTED_REQUEST);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn only_the_csrf_protected_post_switches_the_research_field() {
    use axum::body::Body;
    use axum::http::StatusCode;
    use dementia_research_web::web::build_router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let (state, dir) = fresh_state();
    let csrf = state.csrf_token.clone();
    let app = build_router(state.clone());

    // A navigation (which any site can induce) changes nothing.
    let page = app
        .clone()
        .oneshot(
            owner_request(&state, Method::GET, "/?domain=cancer&section=loop")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(page.status(), StatusCode::OK);
    let html = String::from_utf8(page.into_body().collect().await.expect("body").to_bytes().to_vec())
        .expect("utf8");
    assert!(html.contains(r#"data-domain="dementia""#));
    assert_eq!(
        state.library.read().await.pipeline.settings.domain(),
        ResearchDomain::Dementia
    );
    assert!(!dir.join("library.json").exists(), "a GET must not save the library");

    let switched = app
        .oneshot(
            owner_request(&state, Method::POST, "/domain")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("csrf_token={csrf}&domain=cancer")))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(switched.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        state.library.read().await.pipeline.settings.domain(),
        ResearchDomain::Cancer
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn every_model_call_counts_against_the_daily_budget() {
    use dementia_research_web::agents::GenerateFn;
    use dementia_research_web::models::ResearchError;
    use dementia_research_web::store::LibraryStore;
    use dementia_research_web::web::budgeted_generate;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (state, dir) = fresh_state();
    state.library.write().await.pipeline.settings.daily_model_budget = 2;
    let sent = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&sent);
    let provider: GenerateFn<'static> = Box::new(move |_system, _prompt| {
        counter.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok("{}".to_string()) })
    });
    let generate = budgeted_generate(Arc::clone(&state), provider);

    assert!(generate("s".into(), "p".into()).await.is_ok());
    assert!(generate("s".into(), "repair".into()).await.is_ok());
    let third = generate("s".into(), "p".into()).await;
    assert!(matches!(third, Err(ResearchError::BudgetExhausted)), "{third:?}");
    // The refused request never reached the provider.
    assert_eq!(sent.load(Ordering::SeqCst), 2);
    assert_eq!(state.library.read().await.pipeline.model_requests_today, 2);
    assert!(!state.library.read().await.pipeline.model_budget_available(Utc::now()));
    // The count is saved, so a restart cannot reset it.
    let saved = LibraryStore::new(dir.join("library.json")).load().expect("load");
    assert_eq!(saved.pipeline.model_requests_today, 2);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn json_export_redacts_restricted_bodies_in_every_record() {
    use axum::body::Body;
    use dementia_research_web::models::{
        ConnectionReview, DiscoveryCycle, HypothesisValidation, LibrarySnapshot,
        ValidationVerdict,
    };
    use dementia_research_web::web::build_router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let sentinel = "RESTRICTED-BODY-SENTINEL-7f3a";
    let paper = restricted_paper("MED:1", sentinel);
    let mut lib = LibrarySnapshot::default();
    lib.papers.push(paper.clone());
    lib.pipeline.cycles.push(DiscoveryCycle {
        dataset_records: None,
        research_domain: None,
        id: uuid::Uuid::new_v4(),
        created_at: Utc::now(),
        objective: "objective".to_string(),
        landscape: Vec::new(),
        hypotheses: Vec::new(),
        papers: vec![paper.clone()],
        audit: Vec::new(),
        provider: "p".to_string(),
        model: "m".to_string(),
    });
    lib.pipeline.connections.push(ConnectionReview {
        dataset_records: None,
        research_domain: None,
        id: uuid::Uuid::new_v4(),
        created_at: Utc::now(),
        proposals: Vec::new(),
        papers: vec![paper.clone()],
        audit: Vec::new(),
        provider: "p".to_string(),
        model: "m".to_string(),
    });
    lib.pipeline.validations.push(HypothesisValidation {
        dataset_records: None,
        research_domain: None,
        id: uuid::Uuid::new_v4(),
        hypothesis_id: uuid::Uuid::new_v4(),
        original_statement: "statement".to_string(),
        created_at: Utc::now(),
        verdict: ValidationVerdict::Unresolved,
        confidence: "low".to_string(),
        summary: String::new(),
        criteria: Vec::new(),
        claims: Vec::new(),
        evidence: Vec::new(),
        can_conclude: String::new(),
        cannot_conclude: String::new(),
        would_change_assessment: String::new(),
        next_test: String::new(),
        limitations: Vec::new(),
        papers: vec![paper.clone()],
        audit: Vec::new(),
        provider: "p".to_string(),
        model: "m".to_string(),
        proposed_revision: None,
        supplied_citation_checks: None,
    });
    assert_eq!(
        serde_json::to_string(&lib).unwrap().matches(sentinel).count(),
        4,
        "the fixture holds the body in all four places"
    );

    let (state, dir) = fresh_state();
    *state.library.write().await = lib;
    let app = build_router(state.clone());
    let response = app
        .oneshot(
            owner_request(&state, Method::GET, "/export/library.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let json = String::from_utf8(response.into_body().collect().await.expect("body").to_bytes().to_vec())
        .expect("utf8");
    assert!(!json.contains(sentinel), "a restricted body leaked into the export");
    // Metadata and provenance stay.
    assert_eq!(json.matches("L1 drives IFN in senescent cells").count(), 4);
    assert!(json.contains("abc123"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn tdm_redirects_send_publisher_credentials_only_to_the_publisher() {
    use dementia_research_web::literature::{tdm_destination_allowed, tdm_hop_headers};

    for allowed in ["https://api.elsevier.com/content/x", "https://cdn.elsevier.com/x?y=1"] {
        assert!(tdm_destination_allowed(&Url::parse(allowed).unwrap()), "{allowed}");
    }
    for blocked in [
        "http://api.elsevier.com/content/x",
        "https://api.elsevier.com:8443/content/x",
        "https://10.0.0.5/metadata",
        "https://[::1]/metadata",
        "https://169.254.169.254/latest",
        "https://user@api.elsevier.com/x",
        "https://api.elsevier.com./x",
    ] {
        assert!(!tdm_destination_allowed(&Url::parse(blocked).unwrap()), "{blocked}");
    }

    let mut headers = HeaderMap::new();
    headers.insert("X-ELS-APIKey", HeaderValue::from_static("els-key"));
    headers.insert("X-ELS-Insttoken", HeaderValue::from_static("inst-token"));
    headers.insert("Wiley-TDM-Client-Token", HeaderValue::from_static("wiley"));
    headers.insert(header::ACCEPT, HeaderValue::from_static("text/xml"));

    let publisher = tdm_hop_headers("api.elsevier.com", &Url::parse("https://API.Elsevier.com/content/x").unwrap(), &headers);
    assert!(publisher.contains_key("X-ELS-APIKey") && publisher.contains_key("X-ELS-Insttoken"));

    // Any hop to another host, first or later, carries no credential.
    let cdn = tdm_hop_headers("api.elsevier.com", &Url::parse("https://cdn.elsevier.com/x").unwrap(), &headers);
    assert!(!cdn.contains_key("X-ELS-APIKey"));
    assert!(!cdn.contains_key("X-ELS-Insttoken"));
    assert!(!cdn.contains_key("Wiley-TDM-Client-Token"));
    assert_eq!(cdn[header::ACCEPT], "text/xml");
}

#[test]
fn bodies_stay_local_unless_their_licence_is_known_to_allow_redistribution() {
    use dementia_research_web::models::license_permits_redistribution;

    let with = |license: Option<&str>, url: Option<&str>, format: &str, record_license: Option<&str>| Paper {
        id: "MED:2".to_string(),
        title: "Paper".to_string(),
        is_open_access: true,
        license: record_license.map(str::to_string),
        full_text: Some(ArticleText {
            passages: vec![Passage {
                id: "p1".to_string(),
                section: "Results".to_string(),
                text: "Body".to_string(),
            }],
            format: format.to_string(),
            source_url: Url::parse("https://europepmc.org/x").unwrap(),
            retrieved_at: Utc::now(),
            checksum: "c".to_string(),
            license: license.map(str::to_string),
            version: None,
            license_url: url.map(|u| Url::parse(u).unwrap()),
        }),
        ..Paper::default()
    };

    // Known open licences, by wording or by URL.
    assert!(!with(Some("This is an open access article distributed under the terms of the Creative Commons Attribution License"), None, "JATS XML", None).is_body_redistribution_restricted());
    assert!(!with(None, Some("https://creativecommons.org/licenses/by-nc-nd/4.0/"), "JATS XML", None).is_body_redistribution_restricted());
    assert!(!with(None, None, "JATS XML", Some("cc by")).is_body_redistribution_restricted());
    assert!(!with(Some("CC0 1.0 Universal"), None, "BioC JSON", None).is_body_redistribution_restricted());

    // Unknown, missing or restrictive terms keep the body local.
    assert!(with(None, None, "JATS XML", None).is_body_redistribution_restricted());
    assert!(with(Some("Licence: see publisher"), None, "JATS XML", None).is_body_redistribution_restricted());
    assert!(with(Some("© 2024 The Authors. All rights reserved."), None, "JATS XML", None).is_body_redistribution_restricted());
    // The more restrictive statement wins when the record and the document disagree.
    assert!(with(Some("All rights reserved"), Some("https://creativecommons.org/licenses/by/4.0/"), "JATS XML", Some("cc by")).is_body_redistribution_restricted());
    // Institutional copies are never redistributable, whatever the licence text.
    assert!(with(Some("cc by"), None, "Elsevier TDM XML", None).is_body_redistribution_restricted());
    // No body, nothing to keep local.
    assert!(!Paper { id: "MED:3".to_string(), is_open_access: true, ..Paper::default() }.is_body_redistribution_restricted());

    assert!(license_permits_redistribution(["cc-by-sa"], None));
    assert!(!license_permits_redistribution(["cc by", "not for redistribution"], None));
    assert!(!license_permits_redistribution(std::iter::empty(), None));
}

#[test]
fn quote_matcher_rejects_quotes_longer_than_the_maximum() {
    let passage = "word ".repeat(200);
    let short = "word ".repeat(10).trim().to_string();
    assert!(QuoteMatcher::locate(&short, &passage).is_some());
    let long = "word ".repeat(90).trim().to_string();
    assert!(long.len() > QuoteMatcher::MAXIMUM_LENGTH);
    assert!(QuoteMatcher::locate(&long, &passage).is_none());
}

#[test]
fn report_stops_reproducing_restricted_quotations_past_the_allowance() {
    use dementia_research_web::models::{HypothesisDraft, HypothesisOrigin, QueuedHypothesis};
    use dementia_research_web::report::RESTRICTED_QUOTE_ALLOWANCE;

    let body = "sentence ".repeat(120);
    let paper = restricted_paper("MED:4", body.trim());
    let quote = "sentence ".repeat(44).trim().to_string();
    assert!(quote.len() <= QuoteMatcher::MAXIMUM_LENGTH && 3 * quote.len() > RESTRICTED_QUOTE_ALLOWANCE);
    let mut draft = HypothesisDraft::minimal("Title", "Statement under test");
    draft.citations = (0..3)
        .map(|i| EvidenceCitation::new("MED:4", "body-1", &quote, &format!("interpretation {i}")))
        .collect();
    let item = QueuedHypothesis::new(draft, HypothesisOrigin::Manual, ResearchDomain::Dementia);
    let md = ResearchReportBuilder::hypothesis(&item, std::slice::from_ref(&paper)).markdown();
    assert_eq!(md.matches(&quote).count(), 2, "{md}");
    assert_eq!(md.matches("Quotation from MED:4 not reproduced").count(), 1);
    assert_eq!(md.matches("interpretation").count(), 3, "every citation is still listed");
    assert!(!md.contains(body.trim()));
}

#[test]
fn xml_parsers_refuse_documents_nested_too_deeply() {
    use dementia_research_web::parsers::{ElsevierArticleParser, MAX_XML_DEPTH};

    let nested = |depth: usize| {
        format!(
            "<article><front><article-meta><article-title>Deep nesting test article title</article-title></article-meta></front><body>{}<p>Deep paragraph text long enough to count.</p>{}</body></article>",
            "<sec>".repeat(depth),
            "</sec>".repeat(depth)
        )
    };
    let url = Url::parse("https://www.ebi.ac.uk/europepmc/webservices/rest/PMC1/fullTextXML").unwrap();
    assert!(ArticleTextParser::jats(nested(40).as_bytes(), url.clone(), Some("cc by")).is_ok());

    // Within the node limit, but deep enough to overflow the parser's recursion (one frame
    // per level), so it must be refused before parsing.
    let deep = nested(MAX_XML_DEPTH + 20_000);
    let err = ArticleTextParser::jats(deep.as_bytes(), url.clone(), None).unwrap_err().to_string();
    assert!(err.contains("nested too deeply"), "{err}");
    let paper = Paper { title: "Deep nesting test article title".to_string(), ..Paper::default() };
    assert!(ArticleTextParser::validate_xml_identity(deep.as_bytes(), &paper).is_err());

    let elsevier = format!(
        "<full-text-retrieval-response><coredata><doi>10.1016/j.test.2024.001</doi></coredata><originalText>{}<para>Elsevier body text.</para>{}</originalText></full-text-retrieval-response>",
        "<section>".repeat(MAX_XML_DEPTH + 20_000),
        "</section>".repeat(MAX_XML_DEPTH + 20_000)
    );
    let elsevier_url = Url::parse("https://api.elsevier.com/content/article/doi/10.1016/j.test.2024.001").unwrap();
    assert!(ElsevierArticleParser::parse(elsevier.as_bytes(), elsevier_url, "10.1016/j.test.2024.001", "tdm").is_err());
}

#[test]
fn full_text_is_attached_only_when_the_document_identifies_the_requested_paper() {
    use dementia_research_web::parsers::ElsevierArticleParser;

    let bioc_url = Url::parse("https://www.ncbi.nlm.nih.gov/research/bionlp/RESTful/pmcoa.cgi/BioC_json/PMC6500498/unicode").unwrap();
    let bioc = |id_field: &str| {
        format!(
            r#"{{"documents":[{{{id_field}"passages":[{{"infons":{{"section_type":"RESULTS","type":"paragraph"}},"text":"Body text long enough to count as a passage here."}}]}}]}}"#
        )
    };
    assert!(ArticleTextParser::bioc(bioc(r#""id":"6500498","#).as_bytes(), bioc_url.clone(), None, Some("PMC6500498")).is_ok());
    assert!(ArticleTextParser::bioc(bioc(r#""id":"PMC6500498","#).as_bytes(), bioc_url.clone(), None, Some("pmc6500498")).is_ok());
    let other = ArticleTextParser::bioc(bioc(r#""id":"111","#).as_bytes(), bioc_url.clone(), None, Some("PMC6500498")).unwrap_err().to_string();
    assert!(other.contains("describes PMC111"), "{other}");
    let anonymous = ArticleTextParser::bioc(bioc("").as_bytes(), bioc_url.clone(), None, Some("PMC6500498")).unwrap_err().to_string();
    assert!(anonymous.contains("no PMC identifier"), "{anonymous}");

    let elsevier = |doi_element: &str| {
        format!(
            r#"<full-text-retrieval-response xmlns:prism="http://prismstandard.org/namespaces/basic/2.0/"><coredata>{doi_element}</coredata><originalText><section-title>Results</section-title><para>Elsevier body paragraph text that is long enough.</para></originalText></full-text-retrieval-response>"#
        )
    };
    let elsevier_url = Url::parse("https://api.elsevier.com/content/article/doi/10.1016/j.test.2024.001").unwrap();
    let wanted = "10.1016/j.test.2024.001";
    assert!(ElsevierArticleParser::parse(elsevier("<prism:doi>10.1016/j.test.2024.001</prism:doi>").as_bytes(), elsevier_url.clone(), wanted, "tdm").is_ok());
    assert!(ElsevierArticleParser::parse(elsevier("<prism:doi>10.1016/j.other.2024.009</prism:doi>").as_bytes(), elsevier_url.clone(), wanted, "tdm").is_err());
    let no_doi = ElsevierArticleParser::parse(elsevier("").as_bytes(), elsevier_url, wanted, "tdm").unwrap_err().to_string();
    assert!(no_doi.contains("no readable DOI"), "{no_doi}");

    // A matching title does not excuse a conflicting identifier.
    let jats = r#"<article><front><article-meta><article-title>A sufficiently long article title for matching</article-title><article-id pub-id-type="doi">10.1000/other</article-id></article-meta></front><body><p>Body.</p></body></article>"#;
    let same_title_other_doi = Paper {
        title: "A sufficiently long article title for matching".to_string(),
        doi: Some("10.1000/mine".to_string()),
        ..Paper::default()
    };
    assert!(ArticleTextParser::validate_xml_identity(jats.as_bytes(), &same_title_other_doi).is_err());
    let same_title_no_doi = Paper { doi: None, ..same_title_other_doi.clone() };
    assert!(ArticleTextParser::validate_xml_identity(jats.as_bytes(), &same_title_no_doi).is_ok());
    let same_doi = Paper { title: "Different".to_string(), doi: Some("https://doi.org/10.1000/OTHER".to_string()), ..Paper::default() };
    assert!(ArticleTextParser::validate_xml_identity(jats.as_bytes(), &same_doi).is_ok());
}

#[test]
fn xml_text_is_collected_once_per_text_node() {
    use dementia_research_web::parsers::{xml_nesting_depth, ElsevierArticleParser};

    let xml = r#"<article><front><article-meta><article-title>A title long enough for identity matching</article-title></article-meta></front><body><sec><title>Results</title><p>Hello <italic>world</italic>, again.<xref ref-type="bibr">1</xref></p></sec></body></article>"#;
    let url = Url::parse("https://www.ebi.ac.uk/europepmc/webservices/rest/PMC1/fullTextXML").unwrap();
    let article = ArticleTextParser::jats(xml.as_bytes(), url, Some("cc by")).expect("parsed");
    assert_eq!(article.passages.len(), 1);
    assert_eq!(article.passages[0].section, "Results");
    assert_eq!(article.passages[0].text, "Hello world, again.1");

    // Titles compare exactly, so a paper can be tied to its XML by title alone.
    let paper = Paper {
        title: "A title long enough for identity matching".to_string(),
        ..Paper::default()
    };
    ArticleTextParser::validate_xml_identity(xml.as_bytes(), &paper).expect("title matches");

    // And an Elsevier DOI is read once, so a matching response is accepted.
    let elsevier = r#"<full-text-retrieval-response xmlns:prism="http://prismstandard.org/namespaces/basic/2.0/"><coredata><prism:doi>10.1016/j.test.2024.001</prism:doi></coredata><originalText><section-title>Results</section-title><para>Elsevier <b>body</b> paragraph.</para></originalText></full-text-retrieval-response>"#;
    let elsevier_url = Url::parse("https://api.elsevier.com/content/article/doi/10.1016/j.test.2024.001").unwrap();
    let parsed = ElsevierArticleParser::parse(elsevier.as_bytes(), elsevier_url, "10.1016/j.test.2024.001", "tdm").expect("parsed");
    assert_eq!(parsed.passages[0].text, "Elsevier body paragraph.");
    assert_eq!(parsed.passages[0].section, "Results");

    // The markup scan that guards the parser counts nesting, not angle brackets in other places.
    assert_eq!(xml_nesting_depth(r#"<a><!-- <x><y> --><b attr="<c><d>"><![CDATA[<e><f><g>]]><?pi <h>?><i/></b></a>"#), 2);
    assert_eq!(xml_nesting_depth("<a><b><c></c></b><d/></a>"), 3);
}
