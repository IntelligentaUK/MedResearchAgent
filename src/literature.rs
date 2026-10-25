use crate::catalog::{ResearchSourceCatalog, WIDER_CORPUS_PAGE_SIZE};
use crate::dedup::PaperDeduplicator;
use crate::models::{
    normalize_doi, ArticleText, FullTextLocation, InstitutionalAccess, Paper, ResearchDomain,
    ResearchError, TdmPublisher,
};
use crate::parsers::{
    ArticleTextParser, ElsevierArticleParser, MarkupText, AUTHOR_MANUSCRIPT_LICENSE,
};
use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, COOKIE, USER_AGENT};
use reqwest::redirect::Policy;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::Duration;
use url::Url;

static PMCID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^PMC[0-9]+$").expect("valid regex"));

#[derive(Debug, Clone)]
pub struct SearchPage {
    pub papers: Vec<Paper>,
    pub next_cursor: Option<String>,
    pub total: usize,
    pub query: String,
    pub request_url: Url,
    pub retrieved_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct LiteratureSearchResult {
    pub papers: Vec<Paper>,
    pub notes: Vec<String>,
}

/// Explicit first-party publishers/repositories; no general-purpose web fetch.
pub struct PublicLiteratureUrlPolicy;

impl PublicLiteratureUrlPolicy {
    const EXACT_HOSTS: &'static [&'static str] = &[
        "www.ebi.ac.uk",
        "ebi.ac.uk",
        "zenodo.org",
        "www.zenodo.org",
    ];
    const DOMAINS: &'static [&'static str] = &[
        "ncbi.nlm.nih.gov",
        "europepmc.org",
        "biomedcentral.com",
        "link.springer.com",
        "link.springernature.com",
        "static-content.springer-cdn.com",
        "onlinelibrary.wiley.com",
        "frontiersin.org",
        "scielo.br",
        "scielo.org",
        "hal.science",
        "archives-ouvertes.fr",
    ];
    const FORBIDDEN_QUERY_KEYS: &'static [&'static str] = &[
        "api_key",
        "apikey",
        "token",
        "access_token",
        "auth",
        "authorization",
        "key",
        "signature",
        "x-amz-signature",
    ];

    pub fn allows(url: &Url, metadata: bool) -> bool {
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return false;
        }
        if !matches!(url.port(), None | Some(443)) {
            return false;
        }
        let Some(host) = url.host_str().map(|h| h.to_ascii_lowercase()) else {
            return false;
        };
        if host.ends_with('.') {
            return false;
        }
        for (k, _) in url.query_pairs() {
            if Self::FORBIDDEN_QUERY_KEYS.contains(&k.to_ascii_lowercase().as_str()) {
                return false;
            }
        }
        if metadata {
            return host == "api.openalex.org" && url.path().starts_with("/works/");
        }
        Self::EXACT_HOSTS.contains(&host.as_str())
            || Self::DOMAINS
                .iter()
                .any(|d| host == *d || host.ends_with(&format!(".{d}")))
    }
}

pub struct EuropePmcClient {
    base_url: Url,
    bioc_base_url: Url,
}

impl Default for EuropePmcClient {
    fn default() -> Self {
        Self::new(
            Url::parse("https://www.ebi.ac.uk/europepmc/webservices/rest/")
                .expect("valid static URL"),
            Url::parse("https://www.ncbi.nlm.nih.gov/research/bionlp/RESTful/pmcoa.cgi/BioC_json/")
                .expect("valid static URL"),
        )
    }
}

impl EuropePmcClient {
    pub const ABSTRACT_EXCLUSION: &'static str = r#"NOT PUB_TYPE:"Abstract""#;
    pub const ACCESS_RESTRICTION: &'static str = "(OPEN_ACCESS:Y OR AUTH_MAN:Y)";

    pub fn new(base_url: Url, bioc_base_url: Url) -> Self {
        Self {
            base_url,
            bioc_base_url,
        }
    }

    pub fn access_restriction(access: &InstitutionalAccess) -> String {
        match access.search_clause() {
            Some(clause) => format!("(OPEN_ACCESS:Y OR AUTH_MAN:Y OR {clause})"),
            None => Self::ACCESS_RESTRICTION.to_string(),
        }
    }

    pub fn compose_query(
        query: &str,
        open_access_only: bool,
        exclude_abstracts: bool,
        access: &InstitutionalAccess,
    ) -> Result<String, ResearchError> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(ResearchError::Unavailable(
                "Enter a literature search query.".to_string(),
            ));
        }
        let scoped = if exclude_abstracts {
            format!("({trimmed}) {}", Self::ABSTRACT_EXCLUSION)
        } else {
            trimmed.to_string()
        };
        Ok(if open_access_only {
            format!("({scoped}) AND {}", Self::access_restriction(access))
        } else {
            scoped
        })
    }

    pub async fn search(
        &self,
        query: &str,
        open_access_only: bool,
        exclude_abstracts: bool,
        cursor: &str,
        page_size: usize,
        access: &InstitutionalAccess,
    ) -> Result<SearchPage, ResearchError> {
        let effective_query =
            Self::compose_query(query, open_access_only, exclude_abstracts, access)?;
        let mut url = self
            .base_url
            .join("search")
            .map_err(|_| ResearchError::InvalidResponse("Invalid search URL.".to_string()))?;
        let clamped_size = page_size.clamp(1, 100).to_string();
        url.query_pairs_mut()
            .append_pair("query", &effective_query)
            .append_pair("format", "json")
            .append_pair("resultType", "core")
            .append_pair("pageSize", &clamped_size)
            .append_pair("cursorMark", cursor);

        let (data, _) = download_public(&url, "application/json", false, 20 * 1024 * 1024).await?;
        Self::parse_search_response(&data, effective_query, url, cursor)
    }

    pub fn parse_search_response(
        data: &[u8],
        effective_query: String,
        request_url: Url,
        cursor: &str,
    ) -> Result<SearchPage, ResearchError> {
        let response: EuropePmcSearchResponse = serde_json::from_slice(data).map_err(|e| {
            ResearchError::InvalidResponse(format!(
                "Europe PMC did not return a valid search result: {e}"
            ))
        })?;
        let now = Utc::now();
        let raw_papers: Vec<Paper> = response
            .result_list
            .map(|r| {
                r.result
                    .into_iter()
                    .map(|rec| rec.into_paper(now))
                    .filter(|p| !p.is_conference_abstract())
                    .collect()
            })
            .unwrap_or_default();
        let papers = PaperDeduplicator::deduplicate(&raw_papers);
        let next_cursor = response.next_cursor_mark.filter(|next| {
            !next.is_empty() && next.as_str() != cursor && !papers.is_empty()
        });
        Ok(SearchPage {
            papers,
            next_cursor,
            total: response.hit_count.unwrap_or(0),
            query: effective_query,
            request_url,
            retrieved_at: now,
        })
    }

    pub async fn full_text(&self, paper: &Paper) -> Result<ArticleText, ResearchError> {
        let identifier = paper.pmcid.as_deref().unwrap_or("").trim().to_uppercase();
        if !PMCID_RE.is_match(&identifier) {
            return Err(ResearchError::Unavailable(
                "No valid PMCID is available for structured full text.".to_string(),
            ));
        }
        if !paper.is_open_access && !paper.is_author_manuscript {
            return Err(ResearchError::Unavailable(
                "This record is not marked open access or as a PMC author manuscript; public full-text retrieval was not attempted."
                    .to_string(),
            ));
        }
        let bioc_url = self
            .bioc_base_url
            .join(&format!("{identifier}/unicode"))
            .map_err(|_| ResearchError::InvalidResponse("Invalid BioC URL.".to_string()))?;

        if !paper.is_open_access {
            let (data, _) =
                download_public(&bioc_url, "application/json", false, 20 * 1024 * 1024).await?;
            return ArticleTextParser::bioc(&data, bioc_url, Some(AUTHOR_MANUSCRIPT_LICENSE));
        }

        let jats_url = self
            .base_url
            .join(&format!("{identifier}/fullTextXML"))
            .map_err(|_| ResearchError::InvalidResponse("Invalid JATS URL.".to_string()))?;

        match download_public(&jats_url, "application/xml", false, 20 * 1024 * 1024).await {
            Ok((data, _)) => {
                match ArticleTextParser::jats(&data, jats_url, paper.license.as_deref()) {
                    Ok(article) => return Ok(article),
                    Err(first_err) => {
                        let (bioc_data, _) = download_public(
                            &bioc_url,
                            "application/json",
                            false,
                            20 * 1024 * 1024,
                        )
                        .await
                        .map_err(|second_err| {
                            ResearchError::Unavailable(format!(
                                "Structured full text was unavailable. Europe PMC: {first_err} BioC: {second_err}"
                            ))
                        })?;
                        return ArticleTextParser::bioc(
                            &bioc_data,
                            bioc_url,
                            paper.license.as_deref(),
                        );
                    }
                }
            }
            Err(first_err) => {
                let (bioc_data, _) =
                    download_public(&bioc_url, "application/json", false, 20 * 1024 * 1024)
                        .await
                        .map_err(|second_err| {
                            ResearchError::Unavailable(format!(
                                "Structured full text was unavailable. Europe PMC: {first_err} BioC: {second_err}"
                            ))
                        })?;
                ArticleTextParser::bioc(&bioc_data, bioc_url, paper.license.as_deref())
            }
        }
    }
}

pub struct OpenAccessResolver;

impl OpenAccessResolver {
    pub async fn locations(paper: &Paper) -> Result<Vec<FullTextLocation>, ResearchError> {
        let Some(doi) = normalize_doi(paper.doi.as_deref()) else {
            return Ok(Vec::new());
        };
        let url = Url::parse(&format!("https://api.openalex.org/works/https://doi.org/{doi}"))
            .map_err(|_| ResearchError::InvalidResponse("Invalid OpenAlex URL.".to_string()))?;
        let (data, _) = download_public(&url, "application/json", true, 2 * 1024 * 1024).await?;
        Self::parse_work(&data, &doi, paper.is_preprint)
    }

    pub fn parse_work(
        data: &[u8],
        expected_doi: &str,
        is_preprint: bool,
    ) -> Result<Vec<FullTextLocation>, ResearchError> {
        #[derive(Deserialize)]
        struct Work {
            doi: Option<String>,
            is_retracted: Option<bool>,
            best_oa_location: Option<OaLocation>,
            primary_location: Option<OaLocation>,
            locations: Option<Vec<OaLocation>>,
        }
        #[derive(Deserialize)]
        struct OaLocation {
            is_oa: Option<bool>,
            pdf_url: Option<String>,
            license: Option<String>,
            version: Option<String>,
        }
        let work: Work = serde_json::from_slice(data).map_err(|_| {
            ResearchError::InvalidResponse("OpenAlex did not return valid DOI metadata.".to_string())
        })?;
        if normalize_doi(work.doi.as_deref()).as_deref() != Some(expected_doi) {
            return Err(ResearchError::InvalidResponse(
                "The open-access metadata does not match the requested DOI.".to_string(),
            ));
        }
        if work.is_retracted == Some(true) {
            return Err(ResearchError::Unavailable(
                "OpenAlex flags this work as retracted; it cannot supply supporting evidence."
                    .to_string(),
            ));
        }
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        let candidates = work
            .best_oa_location
            .into_iter()
            .chain(work.primary_location)
            .chain(work.locations.unwrap_or_default());
        for loc in candidates {
            if loc.is_oa != Some(true) {
                continue;
            }
            if !is_preprint && loc.version.as_deref() == Some("submittedVersion") {
                continue;
            }
            let Some(raw_url) = loc.pdf_url else {
                continue;
            };
            let Ok(parsed_url) = Url::parse(&raw_url) else {
                continue;
            };
            if !PublicLiteratureUrlPolicy::allows(&parsed_url, false)
                || !seen.insert(parsed_url.clone())
            {
                continue;
            }
            out.push(FullTextLocation {
                url: parsed_url,
                format: "PDF".to_string(),
                license: loc.license,
                version: loc.version,
            });
            if out.len() >= 3 {
                break;
            }
        }
        Ok(out)
    }
}

pub struct InstitutionalFullTextClient {
    elsevier_host: String,
    wiley_host: String,
}

impl Default for InstitutionalFullTextClient {
    fn default() -> Self {
        Self {
            elsevier_host: "api.elsevier.com".to_string(),
            wiley_host: "api.wiley.com".to_string(),
        }
    }
}

impl InstitutionalFullTextClient {
    pub async fn full_text(
        &self,
        paper: &Paper,
        access: &InstitutionalAccess,
    ) -> Result<ArticleText, ResearchError> {
        let Some(doi) = normalize_doi(paper.doi.as_deref()) else {
            return Err(ResearchError::Unavailable(
                "No configured institutional text-mining route covers this paper's DOI."
                    .to_string(),
            ));
        };
        let Some(publisher) = access.publisher_for(Some(&doi)) else {
            return Err(ResearchError::Unavailable(
                "No configured institutional text-mining route covers this paper's DOI."
                    .to_string(),
            ));
        };
        if paper.is_retracted() {
            return Err(ResearchError::Unavailable(
                "Retracted records are not retrieved.".to_string(),
            ));
        }
        let license = InstitutionalAccess::license_for(publisher);
        match publisher {
            TdmPublisher::Elsevier => {
                let url = Url::parse(&format!(
                    "https://{}/content/article/doi/{doi}?view=FULL",
                    self.elsevier_host
                ))
                .map_err(|_| {
                    ResearchError::InvalidResponse("Invalid Elsevier TDM URL.".to_string())
                })?;
                let mut headers = HeaderMap::new();
                headers.insert(ACCEPT, HeaderValue::from_static("text/xml"));
                if let Some(ref key) = access.elsevier_api_key {
                    if let Ok(val) = HeaderValue::from_str(key) {
                        headers.insert("X-ELS-APIKey", val);
                    }
                }
                if let Some(ref token) = access.elsevier_institution_token {
                    if let Ok(val) = HeaderValue::from_str(token) {
                        headers.insert("X-ELS-Insttoken", val);
                    }
                }
                let (data, final_url) = download_tdm(&url, headers, publisher).await?;
                ElsevierArticleParser::parse(&data, final_url, &doi, &license)
            }
            TdmPublisher::Wiley => {
                let encoded = urlencoding::encode(&doi);
                let url = Url::parse(&format!(
                    "https://{}/onlinelibrary/tdm/v1/articles/{encoded}",
                    self.wiley_host
                ))
                .map_err(|_| {
                    ResearchError::InvalidResponse("Invalid Wiley TDM URL.".to_string())
                })?;
                let mut headers = HeaderMap::new();
                headers.insert(ACCEPT, HeaderValue::from_static("application/pdf"));
                if let Some(ref token) = access.wiley_tdm_token {
                    if let Ok(val) = HeaderValue::from_str(token) {
                        headers.insert("Wiley-TDM-Client-Token", val);
                    }
                }
                let (_data, _final_url) = download_tdm(&url, headers, publisher).await?;
                Err(ResearchError::Unavailable(
                    "Wiley TDM PDF requires local PDF text extraction.".to_string(),
                ))
            }
        }
    }
}

pub struct FreeFullTextClient {
    pub europe_pmc: EuropePmcClient,
    pub institutional: InstitutionalFullTextClient,
}

impl Default for FreeFullTextClient {
    fn default() -> Self {
        Self {
            europe_pmc: EuropePmcClient::default(),
            institutional: InstitutionalFullTextClient::default(),
        }
    }
}

impl FreeFullTextClient {
    pub async fn full_text(
        &self,
        paper: &Paper,
        access: &InstitutionalAccess,
    ) -> Result<ArticleText, ResearchError> {
        if !paper.has_retrieval_route(access) || paper.is_retracted() {
            return Err(ResearchError::Unavailable(
                "Only eligible open-access papers, PMC author manuscripts or articles covered by configured institutional text-mining access can supply supporting evidence."
                    .to_string(),
            ));
        }
        // A paywalled article covered by the institution's TDM credentials has exactly that route.
        if !paper.has_free_full_text_route() {
            return self.institutional.full_text(paper, access).await;
        }
        // An author manuscript has one permitted free route: PMC BioC. No public PDF copy is resolved or fetched,
        // though configured institutional TDM credentials can still supply the publisher text if PMC BioC is unavailable.
        if !paper.is_open_access {
            match self.europe_pmc.full_text(paper).await {
                Ok(article) => return Ok(article),
                Err(err) => {
                    if access.publisher_for(paper.doi.as_deref()).is_some() {
                        return self.institutional.full_text(paper, access).await;
                    }
                    return Err(err);
                }
            }
        }

        let mut failures = Vec::new();
        if paper.pmcid.is_some() {
            match self.europe_pmc.full_text(paper).await {
                Ok(article) => return Ok(article),
                Err(e) => failures.push(e.to_string()),
            }
        }

        let mut seen = HashSet::new();
        let mut candidates: Vec<FullTextLocation> = paper
            .full_text_locations
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|loc| {
                PublicLiteratureUrlPolicy::allows(&loc.url, false) && seen.insert(loc.url.clone())
            })
            .collect();

        let mut attempts = 0usize;
        for resolve_metadata in [false, true] {
            if resolve_metadata {
                if attempts >= 3 {
                    break;
                }
                match OpenAccessResolver::locations(paper).await {
                    Ok(resolved) => {
                        candidates = resolved
                            .into_iter()
                            .filter(|loc| seen.insert(loc.url.clone()))
                            .collect();
                    }
                    Err(e) => {
                        failures.push(e.to_string());
                        break;
                    }
                }
            }
            for loc in candidates.iter().take(3usize.saturating_sub(attempts)) {
                if !paper.is_preprint && loc.version.as_deref() == Some("submittedVersion") {
                    continue;
                }
                let fmt = loc.format.to_lowercase();
                if !fmt.contains("xml") {
                    continue;
                }
                attempts += 1;
                match download_public(&loc.url, "application/xml", false, 20 * 1024 * 1024).await {
                    Ok((data, final_url)) => {
                        let license = loc.license.as_deref().or(paper.license.as_deref());
                        match ArticleTextParser::jats(&data, final_url, license) {
                            Ok(mut article) => {
                                if let Err(e) = ArticleTextParser::validate_xml_identity(&data, paper)
                                {
                                    failures.push(e.to_string());
                                    continue;
                                }
                                if article.version.is_none() {
                                    article.version = loc.version.clone();
                                }
                                return Ok(article);
                            }
                            Err(e) => failures.push(e.to_string()),
                        }
                    }
                    Err(e) => failures.push(e.to_string()),
                }
            }
        }

        if access.publisher_for(paper.doi.as_deref()).is_some() {
            match self.institutional.full_text(paper, access).await {
                Ok(article) => return Ok(article),
                Err(e) => failures.push(e.to_string()),
            }
        }

        let reason = failures
            .last()
            .map(|r| format!(" {r}"))
            .unwrap_or_else(|| " No supported free full-text location was found.".to_string());
        Err(ResearchError::Unavailable(format!(
            "Full text could not be retrieved; this paper is unavailable for supporting evidence.{reason}"
        )))
    }
}

pub struct FreeLiteratureSearchClient {
    pub client: EuropePmcClient,
}

impl Default for FreeLiteratureSearchClient {
    fn default() -> Self {
        Self {
            client: EuropePmcClient::default(),
        }
    }
}

impl FreeLiteratureSearchClient {
    pub fn maximum_records(domain: ResearchDomain) -> usize {
        ResearchSourceCatalog::maximum_records(domain)
    }

    pub async fn search(
        &self,
        query: &str,
        domain: ResearchDomain,
        access: &InstitutionalAccess,
    ) -> Result<LiteratureSearchResult, ResearchError> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(ResearchError::Unavailable(
                "Enter a literature search query.".to_string(),
            ));
        }

        let journals = ResearchSourceCatalog::all_journals(domain);
        let mut groups: Vec<Vec<Paper>> = Vec::new();
        let mut notes: Vec<String> = vec![format!(
            "{} research literature search across {} configured journals plus the wider Europe PMC corpus (NOT PUB_TYPE:\"Abstract\", {}).",
            domain.display_name(),
            journals.len(),
            EuropePmcClient::access_restriction(access)
        )];
        let mut successes = 0usize;
        let mut errors = Vec::new();

        for journal in &journals {
            let scoped_query = format!("({trimmed}) AND {}", journal.europe_pmc_filter());
            match self
                .client
                .search(
                    &scoped_query,
                    true,
                    true,
                    "*",
                    journal.page_size(),
                    access,
                )
                .await
            {
                Ok(page) => {
                    successes += 1;
                    let accepted: Vec<Paper> = page
                        .papers
                        .into_iter()
                        .filter(|p| p.has_retrieval_route(access) && !p.is_conference_abstract())
                        .take(journal.page_size())
                        .map(|mut p| {
                            let mut ids = p.catalog_source_ids.unwrap_or_default();
                            if !ids.contains(&journal.id.to_string()) {
                                ids.push(journal.id.to_string());
                            }
                            p.catalog_source_ids = Some(ids);
                            p
                        })
                        .collect();
                    notes.push(format!(
                        "{}: {} indexed open-access or author-manuscript hits, {} retained ({}).",
                        journal.name,
                        page.total,
                        accepted.len(),
                        page.request_url
                    ));
                    groups.push(accepted);
                }
                Err(e) => {
                    let msg = format!("{}: search unavailable ({e}).", journal.name);
                    notes.push(msg.clone());
                    errors.push(msg);
                }
            }
        }

        match self
            .client
            .search(trimmed, true, true, "*", WIDER_CORPUS_PAGE_SIZE, access)
            .await
        {
            Ok(page) => {
                successes += 1;
                let accepted: Vec<Paper> = page
                    .papers
                    .into_iter()
                    .filter(|p| p.has_retrieval_route(access) && !p.is_conference_abstract())
                    .take(WIDER_CORPUS_PAGE_SIZE)
                    .map(|mut p| {
                        let matched_ids: Vec<String> = journals
                            .iter()
                            .filter(|j| {
                                p.journal_issns.as_ref().is_some_and(|issns| {
                                    issns.iter().any(|i| j.issns.contains(&i.as_str()))
                                })
                            })
                            .map(|j| j.id.to_string())
                            .collect();
                        p.catalog_source_ids = Some(matched_ids);
                        p
                    })
                    .collect();
                notes.push(format!(
                    "Wider Europe PMC corpus: {} indexed open-access or author-manuscript hits, {} retained ({}).",
                    page.total,
                    accepted.len(),
                    page.request_url
                ));
                groups.push(accepted);
            }
            Err(e) => {
                let msg = format!("Wider Europe PMC corpus: search unavailable ({e}).");
                notes.push(msg.clone());
                errors.push(msg);
            }
        }

        if successes == 0 {
            return Err(ResearchError::Unavailable(format!(
                "All literature search targets failed. {}",
                errors.join(" ")
            )));
        }

        let mut interleaved = Vec::new();
        let max_len = groups.iter().map(Vec::len).max().unwrap_or(0);
        for offset in 0..max_len {
            for group in &groups {
                if let Some(paper) = group.get(offset) {
                    interleaved.push(paper.clone());
                }
            }
        }

        let deduped = PaperDeduplicator::deduplicate(&interleaved);
        let max_records = Self::maximum_records(domain);
        Ok(LiteratureSearchResult {
            papers: deduped.into_iter().take(max_records).collect(),
            notes,
        })
    }
}

pub async fn download_public(
    url: &Url,
    accept: &str,
    metadata: bool,
    limit: usize,
) -> Result<(Vec<u8>, Url), ResearchError> {
    if !PublicLiteratureUrlPolicy::allows(url, metadata) {
        return Err(ResearchError::Unavailable(
            "This full-text link is not a supported public publisher or repository URL."
                .to_string(),
        ));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(Policy::custom(move |attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.error("Too many redirects");
            }
            if !PublicLiteratureUrlPolicy::allows(attempt.url(), metadata) {
                return attempt.stop();
            }
            attempt.follow()
        }))
        .build()
        .map_err(|e| ResearchError::Unavailable(format!("Transport error: {e}")))?;

    let mut response = client
        .get(url.clone())
        .header(ACCEPT, accept)
        .header(
            USER_AGENT,
            "DementiaResearch/0.4 (public literature research; rustls)",
        )
        .send()
        .await
        .map_err(|e| ResearchError::Unavailable(format!("Network error: {e}")))?;

    let final_url = response.url().clone();
    if !PublicLiteratureUrlPolicy::allows(&final_url, metadata) {
        return Err(ResearchError::InvalidResponse(
            "The full-text response came from an unsupported location.".to_string(),
        ));
    }
    let status = response.status();
    if !status.is_success() {
        return Err(ResearchError::Http(
            status.as_u16(),
            format!(
                "Public access was unavailable from {}.",
                url.host_str().unwrap_or("the literature service")
            ),
        ));
    }
    if let Some(len) = response.content_length() {
        if len > limit as u64 {
            return Err(ResearchError::InvalidResponse(
                "This literature response exceeds its download size limit.".to_string(),
            ));
        }
    }
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| ResearchError::Unavailable(format!("Stream error: {e}")))?
    {
        if data.len() + chunk.len() > limit {
            return Err(ResearchError::InvalidResponse(
                "This literature response exceeds its download size limit.".to_string(),
            ));
        }
        data.extend_from_slice(&chunk);
    }
    Ok((data, final_url))
}

async fn download_tdm(
    url: &Url,
    headers: HeaderMap,
    publisher: TdmPublisher,
) -> Result<(Vec<u8>, Url), ResearchError> {
    let origin_host = url.host_str().unwrap_or("").to_ascii_lowercase();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .redirect(Policy::custom(move |attempt| {
            if attempt.url().scheme() != "https" {
                return attempt.stop();
            }
            if attempt.previous().len() >= 5 {
                return attempt.error("Too many redirects");
            }
            attempt.follow()
        }))
        .build()
        .map_err(|e| ResearchError::Unavailable(format!("TDM transport error: {e}")))?;

    // Check first hop manually if redirected off-host so TDM headers are never sent to a CDN host
    let no_redirect_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(Policy::none())
        .build()
        .map_err(|e| ResearchError::Unavailable(format!("TDM transport error: {e}")))?;

    let initial = no_redirect_client
        .get(url.clone())
        .headers(headers.clone())
        .header(
            USER_AGENT,
            "DementiaResearch/0.4 (institutional text and data mining; rustls)",
        )
        .send()
        .await
        .map_err(|e| ResearchError::Unavailable(format!("TDM request error: {e}")))?;

    let mut response = if initial.status().is_redirection() {
        let Some(loc) = initial
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| url.join(s).ok())
        else {
            return Err(ResearchError::InvalidResponse(
                "Invalid TDM redirect location.".to_string(),
            ));
        };
        if loc.scheme() != "https" {
            return Err(ResearchError::InvalidResponse(
                "Insecure TDM redirect blocked.".to_string(),
            ));
        }
        let mut next_headers = headers;
        if loc.host_str().map(|h| h.to_ascii_lowercase()).as_deref() != Some(origin_host.as_str()) {
            next_headers.remove("X-ELS-APIKey");
            next_headers.remove("X-ELS-Insttoken");
            next_headers.remove("Wiley-TDM-Client-Token");
            next_headers.remove(AUTHORIZATION);
            next_headers.remove(COOKIE);
        }
        client
            .get(loc)
            .headers(next_headers)
            .header(
                USER_AGENT,
                "DementiaResearch/0.4 (institutional text and data mining; rustls)",
            )
            .send()
            .await
            .map_err(|e| ResearchError::Unavailable(format!("TDM redirect error: {e}")))?
    } else {
        initial
    };

    let status = response.status();
    if !status.is_success() {
        let hint = if status.as_u16() == 401 || status.as_u16() == 403 {
            format!(
                "The {} TDM credentials were not accepted or do not entitle this article; check the key, the institution token and whether requests must come from the institution's network.",
                publisher.display_name()
            )
        } else {
            format!("The {} TDM API was unavailable.", publisher.display_name())
        };
        return Err(ResearchError::Http(status.as_u16(), hint));
    }

    let final_url = response.url().clone();
    let limit = 20 * 1024 * 1024;
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| ResearchError::Unavailable(format!("TDM stream error: {e}")))?
    {
        if data.len() + chunk.len() > limit {
            return Err(ResearchError::InvalidResponse(
                "This TDM response exceeds its download size limit.".to_string(),
            ));
        }
        data.extend_from_slice(&chunk);
    }
    Ok((data, final_url))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EuropePmcSearchResponse {
    hit_count: Option<usize>,
    next_cursor_mark: Option<String>,
    result_list: Option<EuropePmcResultList>,
}

#[derive(Deserialize)]
struct EuropePmcResultList {
    result: Vec<EuropePmcRecord>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EuropePmcRecord {
    id: String,
    source: String,
    title: Option<String>,
    author_string: Option<String>,
    pub_year: Option<String>,
    doi: Option<String>,
    pmid: Option<String>,
    pmcid: Option<String>,
    abstract_text: Option<String>,
    is_open_access: Option<String>,
    auth_man: Option<String>,
    license: Option<String>,
    journal_info: Option<EuropePmcJournalInfo>,
    pub_type_list: Option<EuropePmcPubTypes>,
    version_number: Option< serde_json::Value >,
    full_text_url_list: Option<EuropePmcFullTextUrls>,
}

#[derive(Deserialize)]
struct EuropePmcJournalInfo {
    journal: Option<EuropePmcJournal>,
}

#[derive(Deserialize)]
struct EuropePmcJournal {
    title: Option<String>,
    issn: Option<String>,
    essn: Option<String>,
}

#[derive(Deserialize)]
struct EuropePmcPubTypes {
    #[serde(rename = "pubType")]
    pub_type: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct EuropePmcFullTextUrls {
    #[serde(rename = "fullTextUrl")]
    full_text_url: Option<Vec<EuropePmcLocation>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EuropePmcLocation {
    availability: Option<String>,
    availability_code: Option<String>,
    document_style: Option<String>,
    url: Option<String>,
}

impl EuropePmcLocation {
    fn public_copy(&self, license: Option<&str>, version: Option<&str>) -> Option<FullTextLocation> {
        let code = self.availability_code.as_deref().unwrap_or("").to_uppercase();
        let avail = self.availability.as_deref().unwrap_or("").to_lowercase();
        let public_access =
            code == "OA" || code == "F" || avail == "open access" || avail == "free";
        let style = self.document_style.as_deref().unwrap_or("").to_lowercase();
        if !public_access || (style != "pdf" && style != "xml") {
            return None;
        }
        let parsed = Url::parse(self.url.as_deref()?).ok()?;
        if parsed.scheme() != "https" {
            return None;
        }
        Some(FullTextLocation {
            url: parsed,
            format: style.to_uppercase(),
            license: license.map(ToString::to_string),
            version: version.map(ToString::to_string),
        })
    }
}

impl EuropePmcRecord {
    fn into_paper(self, retrieved_at: DateTime<Utc>) -> Paper {
        let pub_types = self
            .pub_type_list
            .and_then(|p| p.pub_type)
            .unwrap_or_default();
        let is_preprint = self.source == "PPR"
            || pub_types
                .iter()
                .any(|t| t.to_lowercase().contains("preprint"));
        let version = self.version_number.and_then(|v| match v {
            serde_json::Value::String(s) => Some(s),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        });
        let pmid = self
            .pmid
            .or_else(|| (self.source == "MED").then(|| self.id.clone()));
        let pmcid = self
            .pmcid
            .or_else(|| (self.source == "PMC").then(|| self.id.clone()));
        let native_id = match version.as_deref() {
            Some(v) => format!("{}:{}:v{v}", self.source, self.id),
            None => format!("{}:{}", self.source, self.id),
        };
        let source_url = Url::parse(&format!(
            "https://europepmc.org/article/{}/{}",
            self.source, self.id
        ))
        .unwrap_or_else(|_| Url::parse("https://europepmc.org").expect("static URL"));
        let is_oa = self.is_open_access.as_deref() == Some("Y");
        let is_auth_man = self.auth_man.as_deref() == Some("Y");
        let locations = if is_oa {
            self.full_text_url_list
                .and_then(|l| l.full_text_url)
                .map(|list| {
                    list.iter()
                        .filter_map(|loc| {
                            loc.public_copy(self.license.as_deref(), version.as_deref())
                        })
                        .collect::<Vec<_>>()
                })
        } else {
            None
        };
        let journal_title = self
            .journal_info
            .as_ref()
            .and_then(|j| j.journal.as_ref())
            .and_then(|j| j.title.clone())
            .unwrap_or_default();
        let issns: Vec<String> = [
            self.journal_info
                .as_ref()
                .and_then(|j| j.journal.as_ref())
                .and_then(|j| j.issn.clone()),
            self.journal_info
                .as_ref()
                .and_then(|j| j.journal.as_ref())
                .and_then(|j| j.essn.clone()),
        ]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .collect();

        Paper {
            id: native_id,
            title: MarkupText::plain(
                self.title
                    .as_deref()
                    .unwrap_or(&format!("Untitled article ({})", self.id)),
            ),
            authors: self.author_string.unwrap_or_default(),
            journal: journal_title,
            year: self.pub_year.and_then(|y| y.parse::<i32>().ok()),
            doi: self.doi,
            pmid,
            pmcid,
            abstract_text: MarkupText::plain(self.abstract_text.as_deref().unwrap_or("")),
            is_open_access: is_oa,
            is_author_manuscript: is_auth_man,
            is_preprint,
            license: self.license,
            source: format!("Europe PMC ({})", self.source),
            source_url,
            retrieved_at,
            full_text: None,
            version,
            publication_types: pub_types,
            full_text_locations: locations,
            journal_issns: (!issns.is_empty()).then_some(issns),
            catalog_source_ids: None,
            license_url: None,
        }
    }
}
