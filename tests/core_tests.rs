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
use dementia_research_web::web::{html_escape, same_origin_allowed, verify_csrf};
use axum::http::{header, HeaderMap, HeaderValue};
use url::Url;

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
    let bioc_res = ArticleTextParser::bioc(bioc_missing, bioc_url, Some(AUTHOR_MANUSCRIPT_LICENSE));
    assert!(bioc_res.is_err());
}

#[test]
fn report_builder_omits_restricted_author_manuscript_and_tdm_passages() {
    let source_url = Url::parse("https://www.ncbi.nlm.nih.gov/research/bionlp/RESTful/pmcoa.cgi/BioC_json/PMC6500498/unicode").unwrap();
    let paper = Paper {
        id: "MED:30728521".to_string(),
        title: "L1 drives IFN in senescent cells".to_string(),
        pmcid: Some("PMC6500498".to_string()),
        is_open_access: false,
        is_author_manuscript: true,
        full_text: Some(ArticleText {
            passages: vec![Passage {
                id: "body-1".to_string(),
                section: "Results".to_string(),
                text: "Sensitive author manuscript body text that must not be redistributed in full.".to_string(),
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
    };

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
    use axum::http::{Method, Request, StatusCode};
    use dementia_research_web::providers::KeychainStore;
    use dementia_research_web::store::LibraryStore;
    use dementia_research_web::web::{build_router, AppState};
    use tower::ServiceExt;

    let dir = std::env::temp_dir().join(format!("dra-test-{}", uuid::Uuid::new_v4()));
    let state = AppState::new(
        LibraryStore::new(dir.join("library.json")),
        KeychainStore::in_memory(),
    )
    .expect("state");
    let app = build_router(state);

    // `no-referrer` makes browsers send `Origin: null` on form posts, which the origin check
    // rejects; every button in the app then failed with 403.
    let page = app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(page.headers()[header::REFERRER_POLICY], "same-origin");

    let null_origin = Request::builder()
        .method(Method::POST)
        .uri("/domain")
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
    use axum::http::{Method, Request, StatusCode};
    use dementia_research_web::providers::KeychainStore;
    use dementia_research_web::store::LibraryStore;
    use dementia_research_web::web::{build_router, AppState};
    use tower::ServiceExt;

    let dir = std::env::temp_dir().join(format!("dra-test-{}", uuid::Uuid::new_v4()));
    let state = AppState::new(
        LibraryStore::new(dir.join("library.json")),
        KeychainStore::in_memory(),
    )
    .expect("state");
    let csrf = state.csrf_token.clone();
    let app = build_router(state);

    let sign_in = |host: &'static str, token: String| {
        Request::builder()
            .method(Method::POST)
            .uri("/chatgpt/sign-in")
            .header(header::HOST, host)
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
    let callback = Request::get("/auth/callback?code=abc&state=forged&client_id=oaiapp_x")
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
    use axum::http::Request;
    use dementia_research_web::providers::KeychainStore;
    use dementia_research_web::store::LibraryStore;
    use dementia_research_web::web::{build_router, AppState};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let dir = std::env::temp_dir().join(format!("dra-test-{}", uuid::Uuid::new_v4()));
    let state = AppState::new(
        LibraryStore::new(dir.join("library.json")),
        KeychainStore::in_memory(),
    )
    .expect("state");
    let app = build_router(state);
    let response = app
        .oneshot(Request::get("/?section=loop").body(Body::empty()).expect("request"))
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
    use axum::http::{Method, Request, StatusCode};
    use dementia_research_web::providers::KeychainStore;
    use dementia_research_web::store::LibraryStore;
    use dementia_research_web::web::{build_router, AppState};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let dir = std::env::temp_dir().join(format!("dra-test-{}", uuid::Uuid::new_v4()));
    let keychain = KeychainStore::in_memory();
    let state = AppState::new(LibraryStore::new(dir.join("library.json")), keychain.clone())
        .expect("state");
    let csrf = state.csrf_token.clone();
    let app = build_router(state);

    let openai = format!("sk-proj-{}", "b".repeat(48));
    let body = format!(
        "csrf_token={csrf}&anthropic_api_key=sk-ant-oat01-notanapikeyatallnotanapikeyatall&openai_api_key={openai}"
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/credentials")
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
        .oneshot(Request::get("/?section=sources").body(Body::empty()).expect("request"))
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
