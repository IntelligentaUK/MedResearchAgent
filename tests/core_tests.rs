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
