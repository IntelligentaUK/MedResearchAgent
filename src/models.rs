use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResearchError {
    #[error("{0}")]
    InvalidResponse(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("Request failed ({0}): {1}")]
    Http(u16, String),
    #[error("Daily model request allowance reached.")]
    BudgetExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ResearchDomain {
    #[default]
    Dementia,
    Cancer,
}

impl ResearchDomain {
    pub const ALL: [ResearchDomain; 2] = [ResearchDomain::Dementia, ResearchDomain::Cancer];

    pub fn as_str(&self) -> &'static str {
        match self {
            ResearchDomain::Dementia => "dementia",
            ResearchDomain::Cancer => "cancer",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ResearchDomain::Dementia => "Dementia",
            ResearchDomain::Cancer => "Cancer",
        }
    }

    pub fn query(&self) -> &'static str {
        match self {
            ResearchDomain::Dementia => {
                r#"TITLE_ABS:dementia OR TITLE_ABS:alzheimer* OR TITLE_ABS:"Lewy body" OR TITLE_ABS:frontotemporal OR TITLE_ABS:"vascular cognitive impairment""#
            }
            ResearchDomain::Cancer => {
                r#"TITLE_ABS:cancer OR TITLE_ABS:neoplasm* OR TITLE_ABS:tumor* OR TITLE_ABS:tumour* OR TITLE_ABS:carcinoma* OR TITLE_ABS:leukemia OR TITLE_ABS:leukaemia OR TITLE_ABS:lymphoma OR TITLE_ABS:myeloma OR TITLE_ABS:sarcoma OR TITLE_ABS:melanoma"#
            }
        }
    }

    pub fn default_objective(&self) -> &'static str {
        match self {
            ResearchDomain::Dementia => {
                "Which connections between dementia mechanisms suggest a testable new research direction?"
            }
            ResearchDomain::Cancer => {
                "Which unresolved cancer mechanisms, treatment resistance patterns or biomarkers suggest a testable new research direction?"
            }
        }
    }

    pub fn instructions(&self, original: &str) -> String {
        if *self == ResearchDomain::Dementia {
            return original.to_string();
        }
        let adapted = original
            .replace("Dementia", "Cancer")
            .replace("dementia", "cancer")
            .replace(
                "cognition, functioning or quality-of-life improvements",
                "improvements in survival, toxicity or quality of life",
            )
            .replace(
                "cognition, function, and quality of life",
                "survival, toxicity, and quality of life",
            )
            .replace("mixed pathologies", "tumour histologies and molecular subtypes");
        format!(
            "{adapted}\n\n\
ONCOLOGY RESEARCH SCOPE:\n\
Investigate cancer across prevention, mechanisms, early detection, progression, metastasis, treatment resistance and survivorship. State tumour site, histology, stage, molecular subtype, biomarker assay, treatment and line of therapy wherever relevant. Do not pool unrelated cancers or populations without a justified mechanism and explicit limits. Distinguish cell-line, organoid, animal, observational human and randomized clinical evidence. A preclinical effect does not establish patient benefit. Distinguish response, progression-free survival, overall survival, toxicity and quality of life; do not silently substitute endpoints. Check confounding, multiple testing, selection, batch effects, tumour purity and independent replication when relevant. TCGA, GDC and cBioPortal can expose the same underlying cohort; different portals and publications are not independent samples.\n\
Dataset catalog records describe available resources and possible next studies. They are untrusted data, not observed effect estimates, experimental validation or proof that a dataset was analysed. Do not invent patient-level results or statistical calculations. Propose an appropriate analysis and explicitly state which data or definitions would be needed. Only public, unauthenticated resources are connected; do not assume access to controlled data. Retain dataset identifiers, access terms and provenance. Research proposals are not patient-specific treatment recommendations."
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Passage {
    pub id: String,
    pub section: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArticleText {
    pub passages: Vec<Passage>,
    pub format: String,
    #[serde(rename = "sourceURL")]
    pub source_url: Url,
    #[serde(with = "crate::swift_date")]
    pub retrieved_at: DateTime<Utc>,
    pub checksum: String,
    pub license: Option<String>,
    pub version: Option<String>,
    #[serde(rename = "licenseURL")]
    pub license_url: Option<Url>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FullTextLocation {
    pub url: Url,
    pub format: String,
    pub license: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Paper {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub authors: String,
    #[serde(default)]
    pub journal: String,
    pub year: Option<i32>,
    pub doi: Option<String>,
    pub pmid: Option<String>,
    pub pmcid: Option<String>,
    // Swift's `Paper` stores this as `abstract`; earlier builds of this port wrote `abstractText`.
    #[serde(rename = "abstract", alias = "abstractText", default)]
    pub abstract_text: String,
    #[serde(default)]
    pub is_open_access: bool,
    #[serde(default)]
    pub is_author_manuscript: bool,
    #[serde(default)]
    pub is_preprint: bool,
    pub license: Option<String>,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(rename = "sourceURL", default = "default_source_url")]
    pub source_url: Url,
    #[serde(default = "Utc::now")]
    #[serde(with = "crate::swift_date")]
    pub retrieved_at: DateTime<Utc>,
    pub full_text: Option<ArticleText>,
    pub version: Option<String>,
    #[serde(default)]
    pub publication_types: Vec<String>,
    pub full_text_locations: Option<Vec<FullTextLocation>>,
    #[serde(rename = "journalISSNs")]
    pub journal_issns: Option<Vec<String>>,
    #[serde(rename = "catalogSourceIDs")]
    pub catalog_source_ids: Option<Vec<String>>,
    #[serde(rename = "licenseURL")]
    pub license_url: Option<Url>,
}

fn default_source() -> String {
    "Europe PMC".to_string()
}

fn default_source_url() -> Url {
    Url::parse("https://europepmc.org").expect("static URL is valid")
}

impl Default for Paper {
    fn default() -> Self {
        Self {
            id: String::new(),
            title: String::new(),
            authors: String::new(),
            journal: String::new(),
            year: None,
            doi: None,
            pmid: None,
            pmcid: None,
            abstract_text: String::new(),
            is_open_access: false,
            is_author_manuscript: false,
            is_preprint: false,
            license: None,
            source: default_source(),
            source_url: default_source_url(),
            retrieved_at: Utc::now(),
            full_text: None,
            version: None,
            publication_types: Vec::new(),
            full_text_locations: None,
            journal_issns: None,
            catalog_source_ids: None,
            license_url: None,
        }
    }
}

impl Paper {
    pub fn evidence_label(&self) -> &'static str {
        if self.full_text.is_none() {
            "Abstract only"
        } else {
            "Full text"
        }
    }

    /// True when a supported free, machine-readable route to the article body may exist:
    /// an open-access record, or a PMC author manuscript with a PMCID for the BioC service.
    pub fn has_free_full_text_route(&self) -> bool {
        self.is_open_access
            || (self.is_author_manuscript
                && self.pmcid.as_deref().is_some_and(|p| !p.trim().is_empty()))
    }

    pub fn has_retrieval_route(&self, access: &InstitutionalAccess) -> bool {
        self.has_free_full_text_route() || access.publisher_for(self.doi.as_deref()).is_some()
    }

    /// True when the stored article body was retrieved under text-mining terms (an un-licensed PMC author
    /// manuscript or an institutional TDM copy) that permit short verified quotations but not body redistribution.
    pub fn is_body_redistribution_restricted(&self) -> bool {
        (self.is_author_manuscript && !self.is_open_access)
            || self
                .full_text
                .as_ref()
                .is_some_and(|t| t.format.contains("TDM"))
            || self
                .full_text
                .as_ref()
                .and_then(|t| t.license.as_deref())
                .is_some_and(|l| {
                    let lower = l.to_lowercase();
                    lower.contains("no open redistribution")
                        || lower.contains("not for redistribution")
                })
    }

    pub fn is_conference_abstract(&self) -> bool {
        self.publication_types
            .iter()
            .any(|t| t.trim().eq_ignore_ascii_case("abstract"))
    }

    pub fn is_retracted(&self) -> bool {
        self.publication_types.iter().any(|t| {
            let lower = t.to_lowercase();
            lower.contains("retracted publication") || lower.contains("retraction of publication")
        })
    }

    pub fn citation(&self) -> String {
        let year_str = self.year.map(|y| y.to_string());
        [
            Some(self.authors.as_str()),
            Some(self.title.as_str()),
            Some(self.journal.as_str()),
            year_str.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(". ")
    }

    pub fn evidence_passages(&self) -> Vec<Passage> {
        if let Some(ref ft) = self.full_text {
            if !ft.passages.is_empty() {
                return ft.passages.clone();
            }
        }
        if self.abstract_text.is_empty() {
            Vec::new()
        } else {
            vec![Passage {
                id: "abstract".to_string(),
                section: "Abstract only".to_string(),
                text: self.abstract_text.clone(),
            }]
        }
    }

    pub fn reader_page_url(&self) -> Url {
        if let Some(ref pmcid) = self.pmcid {
            let clean = pmcid.trim().to_uppercase();
            if clean.starts_with("PMC") && clean[3..].chars().all(|c| c.is_ascii_digit()) {
                if let Ok(u) = Url::parse(&format!("https://europepmc.org/articles/{clean}")) {
                    return u;
                }
            }
        }
        if let Some(doi) = normalize_doi(self.doi.as_deref()) {
            if let Ok(u) = Url::parse(&format!("https://doi.org/{doi}")) {
                return u;
            }
        }
        self.source_url.clone()
    }
}

static DOI_PREFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(https?://(dx\.)?doi\.org/|doi:\s*)").expect("valid regex"));
static DOI_VALID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^10\.[0-9]{4,9}/[^\s\x00-\x1F\x7F]+$").expect("valid regex"));

pub fn normalize_doi(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim().to_lowercase();
    let stripped = DOI_PREFIX_RE.replace(&raw, "").to_string();
    if DOI_VALID_RE.is_match(&stripped) {
        Some(stripped)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TdmPublisher {
    Elsevier,
    Wiley,
}

impl TdmPublisher {
    pub fn display_name(&self) -> &'static str {
        match self {
            TdmPublisher::Elsevier => "Elsevier",
            TdmPublisher::Wiley => "Wiley",
        }
    }

    pub fn doi_prefixes(&self) -> &'static [&'static str] {
        match self {
            TdmPublisher::Elsevier => &["10.1016"],
            TdmPublisher::Wiley => &["10.1002", "10.1111"],
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstitutionalAccess {
    pub elsevier_api_key: Option<String>,
    pub elsevier_institution_token: Option<String>,
    pub wiley_tdm_token: Option<String>,
    pub library_proxy_prefix: Option<String>,
}

impl InstitutionalAccess {
    pub fn new(
        elsevier_api_key: Option<String>,
        elsevier_institution_token: Option<String>,
        wiley_tdm_token: Option<String>,
        library_proxy_prefix: Option<String>,
    ) -> Self {
        Self {
            elsevier_api_key: clean_opt(elsevier_api_key),
            elsevier_institution_token: clean_opt(elsevier_institution_token),
            wiley_tdm_token: clean_opt(wiley_tdm_token),
            library_proxy_prefix: clean_opt(library_proxy_prefix),
        }
    }

    pub fn text_mining_publishers(&self) -> Vec<TdmPublisher> {
        let mut out = Vec::new();
        if self.elsevier_api_key.is_some() {
            out.push(TdmPublisher::Elsevier);
        }
        if self.wiley_tdm_token.is_some() {
            out.push(TdmPublisher::Wiley);
        }
        out
    }

    pub fn has_text_mining(&self) -> bool {
        !self.text_mining_publishers().is_empty()
    }

    pub fn publisher_for(&self, doi: Option<&str>) -> Option<TdmPublisher> {
        let doi = normalize_doi(doi)?;
        self.text_mining_publishers().into_iter().find(|pub_| {
            pub_.doi_prefixes()
                .iter()
                .any(|prefix| doi.starts_with(&format!("{prefix}/")))
        })
    }

    pub fn search_clause(&self) -> Option<String> {
        let prefixes: Vec<String> = self
            .text_mining_publishers()
            .into_iter()
            .flat_map(|p| p.doi_prefixes().iter().map(|pfx| format!("DOI:{pfx}*")))
            .collect();
        if prefixes.is_empty() {
            None
        } else {
            Some(prefixes.join(" OR "))
        }
    }

    pub fn proxied_url(&self, paper: &Paper) -> Option<Url> {
        let prefix = self.library_proxy_prefix.as_deref()?;
        let parsed_prefix = Url::parse(prefix).ok()?;
        if parsed_prefix.scheme() != "https" {
            return None;
        }
        let target = if let Some(doi) = normalize_doi(paper.doi.as_deref()) {
            Url::parse(&format!("https://doi.org/{doi}")).ok()?
        } else {
            paper.source_url.clone()
        };
        let encoded = urlencoding::encode(target.as_str());
        let joined = if prefix.ends_with('=') {
            format!("{prefix}{encoded}")
        } else if prefix.contains('?') {
            format!("{prefix}&url={encoded}")
        } else {
            format!("{prefix}?url={encoded}")
        };
        Url::parse(&joined).ok()
    }

    pub fn license_for(publisher: TdmPublisher) -> String {
        format!(
            "Institutional text-and-data-mining licence ({}): text mining only under the subscribing institution's agreement; no open licence, body not for redistribution",
            publisher.display_name()
        )
    }
}

fn clean_opt(val: Option<String>) -> Option<String> {
    let trimmed = val?.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CitationVerificationStatus {
    Verified,
    NotLocated,
    SourceUnread,
}

impl CitationVerificationStatus {
    pub fn label(&self) -> &'static str {
        match self {
            CitationVerificationStatus::Verified => "Quote verified in stored source text",
            CitationVerificationStatus::NotLocated => "Quote not located in source text",
            CitationVerificationStatus::SourceUnread => "Source text not read; quote unverified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassageTextRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceCitation {
    #[serde(rename = "paperID")]
    pub paper_id: String,
    #[serde(rename = "passageID")]
    pub passage_id: String,
    pub quote: String,
    pub interpretation: String,
    pub verification_status: Option<CitationVerificationStatus>,
    #[serde(with = "crate::swift_date::option", default)]
    pub verified_at: Option<DateTime<Utc>>,
    pub matched_range: Option<PassageTextRange>,
    pub source_checksum: Option<String>,
    pub matched_text: Option<String>,
}

impl EvidenceCitation {
    pub fn new(paper_id: &str, passage_id: &str, quote: &str, interpretation: &str) -> Self {
        Self {
            paper_id: paper_id.to_string(),
            passage_id: passage_id.to_string(),
            quote: quote.to_string(),
            interpretation: interpretation.to_string(),
            verification_status: None,
            verified_at: None,
            matched_range: None,
            source_checksum: None,
            matched_text: None,
        }
    }

    pub fn is_verified(&self) -> bool {
        self.verification_status == Some(CitationVerificationStatus::Verified)
    }

    pub fn verification_label(&self) -> &'static str {
        self.verification_status
            .map(|s| s.label())
            .unwrap_or("Not yet checked against source text")
    }

    pub fn verification_description(&self) -> String {
        let mut details = Vec::new();
        if let Some(ref checksum) = self.source_checksum {
            details.push(format!("SHA-256 {checksum}"));
        } else if self.verification_status == Some(CitationVerificationStatus::Verified) {
            details.push("abstract text, no article-body checksum".to_string());
        }
        if let Some(range) = self.matched_range {
            details.push(format!(
                "characters {}–{} of passage {}",
                range.start, range.end, self.passage_id
            ));
        }
        if let Some(verified_at) = self.verified_at {
            details.push(format!("verified {}", verified_at.to_rfc3339()));
        }
        if details.is_empty() {
            self.verification_label().to_string()
        } else {
            format!("{} ({})", self.verification_label(), details.join("; "))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HypothesisDraft {
    pub title: String,
    pub statement: String,
    #[serde(default = "default_unspecified")]
    pub r#type: String,
    #[serde(default = "default_to_be_assessed")]
    pub scope: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub necessary_claims: Vec<String>,
    #[serde(default)]
    pub predictions: Vec<String>,
    #[serde(default)]
    pub falsification_criteria: Vec<String>,
    #[serde(default)]
    pub alternatives: Vec<String>,
    #[serde(default)]
    pub next_test: String,
    #[serde(default = "default_not_assessed")]
    pub novelty: String,
    #[serde(default = "default_not_assessed")]
    pub support: String,
    #[serde(default = "default_not_assessed")]
    pub importance: String,
    #[serde(default = "default_not_assessed")]
    pub originality: String,
    #[serde(default = "default_not_assessed")]
    pub feasibility: String,
    #[serde(default)]
    pub citations: Vec<EvidenceCitation>,
}

fn default_unspecified() -> String {
    "Unspecified".to_string()
}
fn default_to_be_assessed() -> String {
    "To be assessed".to_string()
}
fn default_not_assessed() -> String {
    "Not assessed".to_string()
}

impl HypothesisDraft {
    pub fn minimal(title: &str, statement: &str) -> Self {
        Self {
            title: title.to_string(),
            statement: statement.to_string(),
            r#type: default_unspecified(),
            scope: default_to_be_assessed(),
            rationale: String::new(),
            necessary_claims: Vec::new(),
            predictions: Vec::new(),
            falsification_criteria: Vec::new(),
            alternatives: Vec::new(),
            next_test: String::new(),
            novelty: default_not_assessed(),
            support: default_not_assessed(),
            importance: default_not_assessed(),
            originality: default_not_assessed(),
            feasibility: default_not_assessed(),
            citations: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HypothesisOrigin {
    Manual,
    Generated,
    Correlation,
    Reconsideration,
    Legacy,
}

impl HypothesisOrigin {
    pub fn as_str(&self) -> &'static str {
        match self {
            HypothesisOrigin::Manual => "manual",
            HypothesisOrigin::Generated => "generated",
            HypothesisOrigin::Correlation => "correlation",
            HypothesisOrigin::Reconsideration => "reconsideration",
            HypothesisOrigin::Legacy => "legacy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HypothesisQueueStatus {
    Pending,
    Processing,
    RetryScheduled,
    Assessed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueuedHypothesis {
    pub research_domain: Option<ResearchDomain>,
    pub id: Uuid,
    pub draft: HypothesisDraft,
    pub origin: HypothesisOrigin,
    #[serde(rename = "parentIDs", default)]
    pub parent_ids: Vec<Uuid>,
    #[serde(default)]
    pub generation: usize,
    #[serde(rename = "sourcePaperIDs", default)]
    pub source_paper_ids: Vec<String>,
    #[serde(with = "crate::swift_date")]
    pub created_at: DateTime<Utc>,
    pub status: HypothesisQueueStatus,
    pub attempts: usize,
    #[serde(with = "crate::swift_date::option", default)]
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    #[serde(rename = "validationID")]
    pub validation_id: Option<Uuid>,
}

impl QueuedHypothesis {
    pub fn new(
        draft: HypothesisDraft,
        origin: HypothesisOrigin,
        domain: ResearchDomain,
    ) -> Self {
        Self {
            research_domain: Some(domain),
            id: Uuid::new_v4(),
            draft,
            origin,
            parent_ids: Vec::new(),
            generation: 0,
            source_paper_ids: Vec::new(),
            created_at: Utc::now(),
            status: HypothesisQueueStatus::Pending,
            attempts: 0,
            next_attempt_at: None,
            last_error: None,
            validation_id: None,
        }
    }

    pub fn domain(&self) -> ResearchDomain {
        self.research_domain.unwrap_or(ResearchDomain::Dementia)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ValidationVerdict {
    StronglySupported,
    ProvisionallySupported,
    Unresolved,
    Weakened,
    Contradicted,
    NotAssessable,
}

impl ValidationVerdict {
    pub fn is_supported(&self) -> bool {
        matches!(
            self,
            ValidationVerdict::StronglySupported | ValidationVerdict::ProvisionallySupported
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            ValidationVerdict::StronglySupported => "Strongly supported within scope",
            ValidationVerdict::ProvisionallySupported => "Provisionally supported",
            ValidationVerdict::Unresolved => "Unresolved",
            ValidationVerdict::Weakened => "Weakened",
            ValidationVerdict::Contradicted => "Contradicted within scope",
            ValidationVerdict::NotAssessable => "Not assessable from accessible evidence",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimAssessment {
    pub id: String,
    pub statement: String,
    pub verdict: ValidationVerdict,
    pub rationale: String,
    #[serde(default)]
    pub citations: Vec<EvidenceCitation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudyEvidence {
    #[serde(rename = "paperID")]
    pub paper_id: String,
    #[serde(rename = "claimIDs", default)]
    pub claim_ids: Vec<String>,
    pub stance: String,
    pub design: String,
    pub population: String,
    pub sample_size: String,
    pub exposure_comparator_outcome: String,
    pub follow_up: String,
    pub effect: String,
    pub uncertainty: String,
    pub analysis_status: String,
    pub cohort_overlap: String,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchDatasetRecord {
    pub id: String,
    pub provider: String,
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub cancer_types: Vec<String>,
    #[serde(default)]
    pub data_types: Vec<String>,
    pub sample_count: Option<usize>,
    pub access: String,
    pub terms: String,
    #[serde(rename = "sourceURL")]
    pub source_url: Url,
    #[serde(rename = "apiURL")]
    pub api_url: Url,
    #[serde(rename = "downloadURL")]
    pub download_url: Option<Url>,
    #[serde(with = "crate::swift_date")]
    pub retrieved_at: DateTime<Utc>,
    #[serde(default = "default_dataset_evidence_use")]
    pub evidence_use: String,
}

pub fn default_dataset_evidence_use() -> String {
    "Dataset metadata only. No sample-level data, statistical analysis, association or experimental validation was obtained. Use for planning a future test, never as supporting article evidence.".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HypothesisValidation {
    pub dataset_records: Option<Vec<ResearchDatasetRecord>>,
    pub research_domain: Option<ResearchDomain>,
    pub id: Uuid,
    #[serde(rename = "hypothesisID")]
    pub hypothesis_id: Uuid,
    pub original_statement: String,
    #[serde(with = "crate::swift_date")]
    pub created_at: DateTime<Utc>,
    pub verdict: ValidationVerdict,
    pub confidence: String,
    pub summary: String,
    #[serde(default)]
    pub criteria: Vec<String>,
    #[serde(default)]
    pub claims: Vec<ClaimAssessment>,
    #[serde(default)]
    pub evidence: Vec<StudyEvidence>,
    #[serde(default)]
    pub can_conclude: String,
    #[serde(default)]
    pub cannot_conclude: String,
    #[serde(default)]
    pub would_change_assessment: String,
    #[serde(default)]
    pub next_test: String,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(default)]
    pub papers: Vec<Paper>,
    #[serde(default)]
    pub audit: Vec<String>,
    pub provider: String,
    pub model: String,
    pub proposed_revision: Option<HypothesisDraft>,
    pub supplied_citation_checks: Option<Vec<EvidenceCitation>>,
}

impl HypothesisValidation {
    pub fn domain(&self) -> ResearchDomain {
        self.research_domain.unwrap_or(ResearchDomain::Dementia)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchDirection {
    pub title: String,
    pub question: String,
    pub known: String,
    pub gap: String,
    pub importance: String,
    pub selection_reason: String,
    pub selected: bool,
    #[serde(rename = "paperIDs", default)]
    pub paper_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryCycle {
    pub dataset_records: Option<Vec<ResearchDatasetRecord>>,
    pub research_domain: Option<ResearchDomain>,
    pub id: Uuid,
    #[serde(with = "crate::swift_date")]
    pub created_at: DateTime<Utc>,
    pub objective: String,
    pub landscape: Vec<ResearchDirection>,
    pub hypotheses: Vec<HypothesisDraft>,
    pub papers: Vec<Paper>,
    pub audit: Vec<String>,
    pub provider: String,
    pub model: String,
}

impl DiscoveryCycle {
    pub fn domain(&self) -> ResearchDomain {
        self.research_domain.unwrap_or(ResearchDomain::Dementia)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedHypothesis {
    pub draft: HypothesisDraft,
    #[serde(rename = "parentIDs")]
    pub parent_ids: Vec<Uuid>,
    pub reason: String,
    #[serde(rename = "newEvidencePaperIDs", default)]
    pub new_evidence_paper_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionReview {
    pub dataset_records: Option<Vec<ResearchDatasetRecord>>,
    pub research_domain: Option<ResearchDomain>,
    pub id: Uuid,
    #[serde(with = "crate::swift_date")]
    pub created_at: DateTime<Utc>,
    pub proposals: Vec<LinkedHypothesis>,
    pub papers: Vec<Paper>,
    pub audit: Vec<String>,
    pub provider: String,
    pub model: String,
}

impl ConnectionReview {
    pub fn domain(&self) -> ResearchDomain {
        self.research_domain.unwrap_or(ResearchDomain::Dementia)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchObjective {
    pub id: Uuid,
    pub text: String,
    pub domain: ResearchDomain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchLoopSettings {
    pub selected_research_domain: Option<ResearchDomain>,
    #[serde(default)]
    pub processing_enabled: bool,
    #[serde(default)]
    pub autonomous_enabled: bool,
    #[serde(default = "default_cycle_interval")]
    pub cycle_interval_minutes: usize,
    #[serde(default = "default_daily_budget")]
    pub daily_model_budget: usize,
    #[serde(default = "default_max_pending")]
    pub maximum_pending_ideas: usize,
}

fn default_cycle_interval() -> usize {
    15
}
fn default_daily_budget() -> usize {
    120
}
fn default_max_pending() -> usize {
    40
}

impl Default for ResearchLoopSettings {
    fn default() -> Self {
        Self {
            selected_research_domain: Some(ResearchDomain::Dementia),
            processing_enabled: false,
            autonomous_enabled: false,
            cycle_interval_minutes: 15,
            daily_model_budget: 120,
            maximum_pending_ideas: 40,
        }
    }
}

impl ResearchLoopSettings {
    pub fn domain(&self) -> ResearchDomain {
        self.selected_research_domain
            .unwrap_or(ResearchDomain::Dementia)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchEvent {
    pub id: Uuid,
    #[serde(with = "crate::swift_date")]
    pub date: DateTime<Utc>,
    pub message: String,
}

impl ResearchEvent {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            date: Utc::now(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchDomainLoopState {
    #[serde(default)]
    pub processing_enabled: bool,
    #[serde(default)]
    pub autonomous_enabled: bool,
    #[serde(with = "crate::swift_date::option", default)]
    pub next_discovery_at: Option<DateTime<Utc>>,
    #[serde(with = "crate::swift_date::option", default)]
    pub next_connection_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub discovery_failures: usize,
    #[serde(default)]
    pub connection_failures: usize,
    pub last_connection_signature: Option<String>,
    pub last_completed_stage: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchPipeline {
    #[serde(default)]
    pub settings: ResearchLoopSettings,
    #[serde(default)]
    pub queue: Vec<QueuedHypothesis>,
    #[serde(default)]
    pub validations: Vec<HypothesisValidation>,
    #[serde(default)]
    pub cycles: Vec<DiscoveryCycle>,
    #[serde(default)]
    pub connections: Vec<ConnectionReview>,
    #[serde(default)]
    pub events: Vec<ResearchEvent>,
    #[serde(with = "crate::swift_date::option", default)]
    pub next_discovery_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub discovery_failures: usize,
    #[serde(default)]
    pub connection_failures: usize,
    #[serde(with = "crate::swift_date::option", default)]
    pub next_connection_at: Option<DateTime<Utc>>,
    pub last_connection_signature: Option<String>,
    pub last_completed_stage: Option<String>,
    pub domain_loop_states: Option<HashMap<String, ResearchDomainLoopState>>,
    #[serde(default = "Utc::now")]
    #[serde(with = "crate::swift_date")]
    pub model_usage_date: DateTime<Utc>,
    #[serde(default)]
    pub model_requests_today: usize,
    #[serde(default)]
    pub manual_objectives: Vec<String>,
    pub research_objectives: Option<Vec<ResearchObjective>>,
}

impl ResearchPipeline {
    pub fn loop_state(&self, domain: ResearchDomain) -> ResearchDomainLoopState {
        if let Some(ref map) = self.domain_loop_states {
            if let Some(state) = map.get(domain.as_str()) {
                return state.clone();
            }
        }
        if self.domain_loop_states.is_none() && domain == self.settings.domain() {
            return ResearchDomainLoopState {
                processing_enabled: self.settings.processing_enabled,
                autonomous_enabled: self.settings.autonomous_enabled,
                next_discovery_at: self.next_discovery_at,
                next_connection_at: self.next_connection_at,
                discovery_failures: self.discovery_failures,
                connection_failures: self.connection_failures,
                last_connection_signature: self.last_connection_signature.clone(),
                last_completed_stage: self.last_completed_stage.clone(),
            };
        }
        ResearchDomainLoopState::default()
    }

    pub fn update_loop_state(
        &mut self,
        domain: ResearchDomain,
        f: impl FnOnce(&mut ResearchDomainLoopState),
    ) {
        let mut states = HashMap::new();
        for d in ResearchDomain::ALL {
            states.insert(d.as_str().to_string(), self.loop_state(d));
        }
        let entry = states.entry(domain.as_str().to_string()).or_default();
        f(entry);
        self.domain_loop_states = Some(states);
        if let Some(active) = self
            .domain_loop_states
            .as_ref()
            .and_then(|m| m.get(self.settings.domain().as_str()))
        {
            self.settings.processing_enabled = active.processing_enabled;
            self.settings.autonomous_enabled = active.autonomous_enabled;
            self.next_discovery_at = active.next_discovery_at;
            self.next_connection_at = active.next_connection_at;
            self.discovery_failures = active.discovery_failures;
            self.connection_failures = active.connection_failures;
            self.last_connection_signature = active.last_connection_signature.clone();
            self.last_completed_stage = active.last_completed_stage.clone();
        }
    }

    pub fn select_domain(&mut self, domain: ResearchDomain) {
        if self.settings.domain() == domain {
            return;
        }
        self.update_loop_state(domain, |_| {});
        self.settings.selected_research_domain = Some(domain);
        self.update_loop_state(domain, |_| {});
        self.record(format!(
            "Viewing {} research. Running research in other fields continues.",
            domain.display_name()
        ));
    }

    pub fn objectives(&self, domain: ResearchDomain) -> Vec<String> {
        let mut out = Vec::new();
        if domain == ResearchDomain::Dementia {
            out.extend(self.manual_objectives.clone());
        }
        if let Some(ref objs) = self.research_objectives {
            out.extend(
                objs.iter()
                    .filter(|o| o.domain == domain)
                    .map(|o| o.text.clone()),
            );
        }
        out
    }

    pub fn enqueue_objective(&mut self, text: &str, domain: ResearchDomain) {
        let trimmed = text.trim();
        if trimmed.is_empty() || self.objectives(domain).iter().any(|existing| existing == trimmed) {
            return;
        }
        self.research_objectives
            .get_or_insert_with(Vec::new)
            .push(ResearchObjective {
                id: Uuid::new_v4(),
                text: trimmed.to_string(),
                domain,
            });
    }

    pub fn remove_objective(&mut self, text: &str, domain: ResearchDomain) {
        if let Some(ref mut objs) = self.research_objectives {
            objs.retain(|o| !(o.text == text && o.domain == domain));
        }
        if domain == ResearchDomain::Dementia {
            self.manual_objectives.retain(|o| o != text);
        }
    }

    pub fn record(&mut self, message: impl Into<String>) {
        self.events.insert(0, ResearchEvent::new(message));
        if self.events.len() > 500 {
            self.events.truncate(500);
        }
    }

    pub fn reserve_model_request(&mut self, now: DateTime<Utc>) -> Result<(), ResearchError> {
        if self.model_usage_date.date_naive() != now.date_naive() {
            self.model_usage_date = now;
            self.model_requests_today = 0;
        }
        if self.model_requests_today >= self.settings.daily_model_budget {
            return Err(ResearchError::BudgetExhausted);
        }
        self.model_requests_today += 1;
        Ok(())
    }

    pub fn statement_key(text: &str) -> String {
        let symbols: HashSet<char> = "<>≤≥=+−-%./^≠±".chars().collect();
        let mut tokens = String::new();
        let chars: Vec<char> = text.to_lowercase().chars().collect();
        for (i, &ch) in chars.iter().enumerate() {
            if ch == '.' {
                let left_digit = i > 0 && chars[i - 1].is_ascii_digit();
                let right_digit = i + 1 < chars.len() && chars[i + 1].is_ascii_digit();
                if left_digit && right_digit {
                    tokens.push('.');
                } else {
                    tokens.push(' ');
                }
            } else if symbols.contains(&ch) {
                tokens.push(' ');
                tokens.push(ch);
                tokens.push(' ');
            } else if ch.is_alphanumeric() {
                tokens.push(ch);
            } else {
                tokens.push(' ');
            }
        }
        tokens.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    pub fn enqueue(&mut self, item: QueuedHypothesis) -> bool {
        let key = Self::statement_key(&item.draft.statement);
        if key.is_empty() {
            return false;
        }
        let domain = item.domain();
        if self
            .queue
            .iter()
            .any(|q| q.domain() == domain && Self::statement_key(&q.draft.statement) == key)
        {
            return false;
        }
        let title = item.draft.title.clone();
        let origin = item.origin.as_str();
        self.queue.push(item);
        self.record(format!("Queued {title} ({origin})."));
        true
    }

    pub fn connection_signature(&self, papers: &[Paper], domain: Option<ResearchDomain>) -> String {
        let mut records: Vec<String> = self
            .validations
            .iter()
            .filter(|v| domain.is_none_or(|d| v.domain() == d))
            .map(|v| v.id.to_string())
            .collect();
        records.sort();
        let mut paper_hashes: Vec<String> = papers
            .iter()
            .filter_map(|p| p.full_text.as_ref().map(|ft| format!("{}:{}", p.id, ft.checksum)))
            .collect();
        paper_hashes.sort();
        records.extend(paper_hashes);
        let digest = Sha256::digest(records.join("\n").as_bytes());
        format!("{digest:x}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LibrarySnapshot {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub papers: Vec<Paper>,
    /// Research runs saved by the Swift app's legacy notebook. This port does not use them,
    /// but keeps them verbatim (and always writes the key, which Swift requires) so that
    /// saving from either app never drops the other's data.
    #[serde(default)]
    pub runs: Vec<serde_json::Value>,
    #[serde(default)]
    pub dataset_records: Option<Vec<ResearchDatasetRecord>>,
    #[serde(default)]
    pub pipeline: ResearchPipeline,
    #[serde(default)]
    pub paper_domains: Option<HashMap<String, Vec<ResearchDomain>>>,
}

fn default_schema_version() -> u32 {
    4
}

impl Default for LibrarySnapshot {
    fn default() -> Self {
        Self {
            schema_version: 4,
            papers: Vec::new(),
            runs: Vec::new(),
            dataset_records: Some(Vec::new()),
            pipeline: ResearchPipeline::default(),
            paper_domains: Some(HashMap::new()),
        }
    }
}

impl LibrarySnapshot {
    pub fn upsert_paper(&mut self, paper: Paper, domain: ResearchDomain) {
        let id = paper.id.clone();
        if let Some(existing) = self.papers.iter_mut().find(|p| p.id == id) {
            *existing = paper;
        } else {
            self.papers.push(paper);
        }
        let domains = self
            .paper_domains
            .get_or_insert_with(HashMap::new)
            .entry(id)
            .or_default();
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }

    pub fn research_papers(&self, domain: ResearchDomain) -> Vec<Paper> {
        self.papers
            .iter()
            .filter(|p| {
                if let Some(ref map) = self.paper_domains {
                    if let Some(domains) = map.get(&p.id) {
                        return domains.contains(&domain);
                    }
                }
                domain == ResearchDomain::Dementia
            })
            .cloned()
            .collect()
    }
}
