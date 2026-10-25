use crate::models::{
    default_dataset_evidence_use, ResearchDatasetRecord, ResearchDomain, ResearchError,
};
use chrono::{DateTime, Utc};
use reqwest::header::{ACCEPT, USER_AGENT};
use reqwest::redirect::Policy;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use url::Url;

pub struct CancerDatasetDiscoveryResult {
    pub records: Vec<ResearchDatasetRecord>,
    pub notes: Vec<String>,
}

pub struct CancerDatasetUrlPolicy;

impl CancerDatasetUrlPolicy {
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

    pub fn allows(url: &Url) -> bool {
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
        match host.as_str() {
            "api.gdc.cancer.gov" => matches!(url.path(), "/projects" | "/files"),
            "www.cbioportal.org" => url.path() == "/api/studies",
            _ => false,
        }
    }
}

/// Values a record may list for one field (cancer types, projects, data types). Catalog
/// responses are untrusted; this keeps the per-record work and output small.
const MAX_LISTED_VALUES: usize = 64;

/// The distinct values, in first-seen order, up to `MAX_LISTED_VALUES`. Membership is a set
/// lookup, so the work is linear in the input.
fn unique_in_order(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        if out.len() >= MAX_LISTED_VALUES {
            break;
        }
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

pub struct CancerDatasetClient {
    gdc_base_url: Url,
    cbio_base_url: Url,
}

impl Default for CancerDatasetClient {
    fn default() -> Self {
        Self {
            gdc_base_url: Url::parse("https://api.gdc.cancer.gov/").expect("valid static URL"),
            cbio_base_url: Url::parse("https://www.cbioportal.org/api/").expect("valid static URL"),
        }
    }
}

impl CancerDatasetClient {
    const STOP_WORDS: &'static [&'static str] = &[
        "cancer",
        "cancers",
        "tumor",
        "tumour",
        "tumors",
        "tumours",
        "oncology",
        "malignant",
        "neoplasm",
        "neoplasms",
        "disease",
        "patients",
        "patient",
        "study",
        "studies",
        "research",
        "direction",
        "directions",
        "hypothesis",
        "hypotheses",
        "evidence",
        "mechanism",
        "mechanisms",
        "treatment",
        "therapy",
        "clinical",
        "human",
        "using",
        "between",
        "which",
        "could",
        "would",
        "should",
        "suggest",
        "testable",
        "unresolved",
        "patterns",
    ];

    pub async fn discover(
        &self,
        query: &str,
        domain: ResearchDomain,
        maximum_records: usize,
    ) -> Result<CancerDatasetDiscoveryResult, ResearchError> {
        if domain != ResearchDomain::Cancer {
            return Ok(CancerDatasetDiscoveryResult {
                records: Vec::new(),
                notes: Vec::new(),
            });
        }
        let terms = Self::keywords(query);
        let mut records = Vec::new();
        let mut notes = Vec::new();
        let mut errors = Vec::new();
        let per_source = (maximum_records / 2).max(2);

        match self.search_gdc_projects(&terms, per_source).await {
            Ok((found, note)) => {
                records.extend(found);
                notes.push(note);
            }
            Err(e) => {
                let msg = format!("NCI GDC project catalog unavailable ({e}).");
                notes.push(msg.clone());
                errors.push(msg);
            }
        }

        match self.search_gdc_open_files(&terms, 2.min(maximum_records)).await {
            Ok((found, note)) => {
                records.extend(found);
                notes.push(note);
            }
            Err(e) => {
                let msg = format!("NCI GDC open-file catalog unavailable ({e}).");
                notes.push(msg.clone());
                errors.push(msg);
            }
        }

        match self.search_cbio_studies(&terms, per_source).await {
            Ok((found, note)) => {
                records.extend(found);
                notes.push(note);
            }
            Err(e) => {
                let msg = format!("cBioPortal study catalog unavailable ({e}).");
                notes.push(msg.clone());
                errors.push(msg);
            }
        }

        if records.is_empty() && !errors.is_empty() {
            return Err(ResearchError::Unavailable(errors.join(" ")));
        }

        let mut seen = HashSet::new();
        let deduped: Vec<ResearchDatasetRecord> = records
            .into_iter()
            .filter(|r| seen.insert(r.id.clone()))
            .take(maximum_records)
            .collect();

        Ok(CancerDatasetDiscoveryResult {
            records: deduped,
            notes,
        })
    }

    pub fn keywords(text: &str) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for token in text
            .to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 4 && !Self::STOP_WORDS.contains(t))
        {
            if seen.insert(token.to_string()) {
                out.push(token.to_string());
                if out.len() >= 10 {
                    break;
                }
            }
        }
        out
    }

    async fn search_gdc_projects(
        &self,
        terms: &[String],
        limit: usize,
    ) -> Result<(Vec<ResearchDatasetRecord>, String), ResearchError> {
        let mut url = self
            .gdc_base_url
            .join("projects")
            .map_err(|_| ResearchError::InvalidResponse("Invalid GDC URL.".to_string()))?;
        url.query_pairs_mut()
            .append_pair(
                "fields",
                "project_id,name,primary_site,disease_type,program.name,summary.case_count,summary.file_count,summary.data_categories.data_category,summary.data_categories.case_count",
            )
            .append_pair("size", "100")
            .append_pair("sort", "summary.case_count:desc");
        let (data, final_url) = Self::download(&url).await?;
        let now = Utc::now();
        let (records, total) = Self::parse_gdc_projects(&data, terms, limit, &final_url, now)?;
        let note = format!(
            "NCI GDC projects: {total} open project metadata records checked, {} retained ({final_url}).",
            records.len()
        );
        Ok((records, note))
    }

    pub fn parse_gdc_projects(
        data: &[u8],
        terms: &[String],
        limit: usize,
        api_url: &Url,
        now: DateTime<Utc>,
    ) -> Result<(Vec<ResearchDatasetRecord>, usize), ResearchError> {
        #[derive(Deserialize)]
        struct Envelope {
            data: HitsContainer,
        }
        #[derive(Deserialize)]
        struct HitsContainer {
            hits: Vec<GdcProject>,
        }
        #[derive(Deserialize)]
        struct GdcProject {
            id: Option<String>,
            project_id: Option<String>,
            name: Option<String>,
            primary_site: Option<Vec<String>>,
            disease_type: Option<Vec<String>>,
            program: Option<GdcProgram>,
            summary: Option<GdcSummary>,
        }
        #[derive(Deserialize)]
        struct GdcProgram {
            name: Option<String>,
        }
        #[derive(Deserialize)]
        struct GdcSummary {
            case_count: Option<usize>,
            file_count: Option<usize>,
            data_categories: Option<Vec<GdcDataCategory>>,
        }
        #[derive(Deserialize)]
        struct GdcDataCategory {
            data_category: Option<String>,
        }

        let env: Envelope = serde_json::from_slice(data).map_err(|e| {
            ResearchError::InvalidResponse(format!(
                "NCI GDC did not return valid project metadata: {e}"
            ))
        })?;
        let total = env.data.hits.len();
        let mut ranked: Vec<(i64, usize, ResearchDatasetRecord)> = env
            .data
            .hits
            .into_iter()
            .filter_map(|p| {
                let pid = p.project_id.or(p.id)?.trim().to_string();
                let name = p.name.as_deref().unwrap_or("").trim().to_string();
                if pid.is_empty() || name.is_empty() {
                    return None;
                }
                let sites: Vec<String> = p
                    .primary_site
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|s| !s.trim().is_empty())
                    .collect();
                let diseases: Vec<String> = p
                    .disease_type
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|s| !s.trim().is_empty())
                    .collect();
                let categories: Vec<String> = p
                    .summary
                    .as_ref()
                    .and_then(|s| s.data_categories.as_ref())
                    .map(|cats| {
                        cats.iter()
                            .filter_map(|c| c.data_category.clone())
                            .filter(|s| !s.trim().is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                let mut haystack_parts = vec![pid.clone(), name.clone()];
                if let Some(prog) = p.program.as_ref().and_then(|pr| pr.name.clone()) {
                    haystack_parts.push(prog);
                }
                haystack_parts.extend(sites.clone());
                haystack_parts.extend(diseases.clone());
                haystack_parts.extend(categories.clone());
                let score = Self::score(&haystack_parts.join(" "), terms);
                let cases = p.summary.as_ref().and_then(|s| s.case_count).unwrap_or(0);
                let files = p.summary.as_ref().and_then(|s| s.file_count);
                let encoded = urlencoding::encode(&pid);
                let portal =
                    Url::parse(&format!("https://portal.gdc.cancer.gov/projects/{encoded}")).ok()?;
                let cancer_types =
                    unique_in_order(diseases.iter().chain(sites.iter()).cloned());
                let mut summary_parts = vec![name.clone()];
                if !diseases.is_empty() {
                    summary_parts.push(format!("Disease types: {}", diseases.join(", ")));
                }
                if !sites.is_empty() {
                    summary_parts.push(format!("Primary sites: {}", sites.join(", ")));
                }
                if cases > 0 {
                    summary_parts.push(format!("Cases: {cases}"));
                }
                if let Some(f) = files {
                    summary_parts.push(format!("Files: {f}"));
                }
                if !categories.is_empty() {
                    summary_parts.push(format!(
                        "Data categories: {}",
                        categories.iter().take(6).cloned().collect::<Vec<_>>().join(", ")
                    ));
                }
                let record = ResearchDatasetRecord {
                    id: format!("gdc:{pid}"),
                    provider: "NCI Genomic Data Commons".to_string(),
                    title: format!("{pid}: {name}"),
                    summary: format!("{}.", summary_parts.join(". ")),
                    cancer_types,
                    data_types: categories,
                    sample_count: p.summary.and_then(|s| s.case_count),
                    access: "Open project metadata; project contains open-access and controlled-access files depending on data category".to_string(),
                    terms: "Public NCI GDC metadata via unauthenticated HTTPS API; follow NIH Genomic Data Sharing Policy, GDC Data Use Policy and controlled-access rules where applicable".to_string(),
                    source_url: portal,
                    api_url: api_url.clone(),
                    download_url: None,
                    retrieved_at: now,
                    evidence_use: default_dataset_evidence_use(),
                };
                Some((score, cases, record))
            })
            .collect();

        ranked.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.2.id.cmp(&b.2.id))
        });

        let matched: Vec<ResearchDatasetRecord> = ranked
            .iter()
            .filter(|(s, _, _)| *s > 0)
            .map(|(_, _, r)| r.clone())
            .collect();
        let chosen = if matched.is_empty() {
            ranked.into_iter().take(limit).map(|(_, _, r)| r).collect()
        } else {
            matched.into_iter().take(limit).collect()
        };
        Ok((chosen, total))
    }

    async fn search_gdc_open_files(
        &self,
        terms: &[String],
        limit: usize,
    ) -> Result<(Vec<ResearchDatasetRecord>, String), ResearchError> {
        let filter = serde_json::json!({
            "op": "and",
            "content": [
                {"op": "in", "content": {"field": "access", "value": ["open"]}},
                {"op": "in", "content": {"field": "state", "value": ["released"]}}
            ]
        });
        let filter_str = serde_json::to_string(&filter)
            .map_err(|_| ResearchError::InvalidResponse("Invalid GDC filter.".to_string()))?;
        let mut url = self
            .gdc_base_url
            .join("files")
            .map_err(|_| ResearchError::InvalidResponse("Invalid GDC files URL.".to_string()))?;
        url.query_pairs_mut()
            .append_pair("filters", &filter_str)
            .append_pair(
                "fields",
                "file_id,file_name,data_category,data_type,data_format,experimental_strategy,access,state,file_size,cases.project.project_id,cases.project.name,cases.project.primary_site,cases.project.disease_type",
            )
            .append_pair("size", "40")
            .append_pair("sort", "file_name:asc");
        let (data, final_url) = Self::download(&url).await?;
        let now = Utc::now();
        let (records, total) = Self::parse_gdc_files(&data, terms, limit, &final_url, now)?;
        let note = format!(
            "NCI GDC open files: {total} open released file metadata records checked, {} retained ({final_url}).",
            records.len()
        );
        Ok((records, note))
    }

    pub fn parse_gdc_files(
        data: &[u8],
        terms: &[String],
        limit: usize,
        api_url: &Url,
        now: DateTime<Utc>,
    ) -> Result<(Vec<ResearchDatasetRecord>, usize), ResearchError> {
        #[derive(Deserialize)]
        struct Envelope {
            data: HitsContainer,
        }
        #[derive(Deserialize)]
        struct HitsContainer {
            hits: Vec<GdcFile>,
        }
        #[derive(Deserialize)]
        struct GdcFile {
            id: Option<String>,
            file_id: Option<String>,
            file_name: Option<String>,
            data_category: Option<String>,
            data_type: Option<String>,
            data_format: Option<String>,
            experimental_strategy: Option<String>,
            access: Option<String>,
            state: Option<String>,
            file_size: Option<usize>,
            cases: Option<Vec<GdcCase>>,
        }
        #[derive(Deserialize)]
        struct GdcCase {
            project: Option<GdcCaseProject>,
        }
        #[derive(Deserialize)]
        struct GdcCaseProject {
            project_id: Option<String>,
            name: Option<String>,
            primary_site: Option<Vec<String>>,
            disease_type: Option<Vec<String>>,
        }

        let env: Envelope = serde_json::from_slice(data).map_err(|e| {
            ResearchError::InvalidResponse(format!(
                "NCI GDC did not return valid open-file metadata: {e}"
            ))
        })?;
        let total = env.data.hits.len();
        let mut ranked: Vec<(i64, usize, ResearchDatasetRecord)> = env
            .data
            .hits
            .into_iter()
            .filter_map(|f| {
                if !f.access.as_deref().unwrap_or("").eq_ignore_ascii_case("open")
                    || !f
                        .state
                        .as_deref()
                        .unwrap_or("")
                        .eq_ignore_ascii_case("released")
                {
                    return None;
                }
                let fid = f.file_id.or(f.id)?.trim().to_string();
                let name = f.file_name.as_deref().unwrap_or("").trim().to_string();
                if fid.is_empty() || name.is_empty() {
                    return None;
                }
                let cases = f.cases.unwrap_or_default();
                let projects: Vec<String> = cases
                    .iter()
                    .filter_map(|c| c.project.as_ref()?.project_id.clone())
                    .collect();
                let project_names: Vec<String> = cases
                    .iter()
                    .filter_map(|c| c.project.as_ref()?.name.clone())
                    .collect();
                let cancer_types = unique_in_order(cases.iter().flat_map(|c| {
                    let project = c.project.as_ref();
                    project
                        .and_then(|p| p.disease_type.clone())
                        .unwrap_or_default()
                        .into_iter()
                        .chain(
                            project
                                .and_then(|p| p.primary_site.clone())
                                .unwrap_or_default(),
                        )
                }));
                let data_types: Vec<String> = [
                    f.data_category,
                    f.data_type,
                    f.experimental_strategy,
                    f.data_format,
                ]
                .into_iter()
                .flatten()
                .filter(|s| !s.trim().is_empty())
                .collect();
                let mut haystack_parts = vec![fid.clone(), name.clone()];
                haystack_parts.extend(projects.clone());
                haystack_parts.extend(project_names.clone());
                haystack_parts.extend(cancer_types.clone());
                haystack_parts.extend(data_types.clone());
                let score = Self::score(&haystack_parts.join(" "), terms);
                let encoded = urlencoding::encode(&fid);
                let portal =
                    Url::parse(&format!("https://portal.gdc.cancer.gov/files/{encoded}")).ok()?;
                let download =
                    Url::parse(&format!("https://api.gdc.cancer.gov/data/{encoded}")).ok();
                let mut summary_parts = vec![format!("Open GDC file {name}")];
                if !projects.is_empty() {
                    summary_parts.push(format!("Projects: {}", projects.join(", ")));
                }
                if !cancer_types.is_empty() {
                    summary_parts.push(format!("Cancer types: {}", cancer_types.join(", ")));
                }
                if !data_types.is_empty() {
                    summary_parts.push(format!("Data: {}", data_types.join(", ")));
                }
                if let Some(sz) = f.file_size {
                    summary_parts.push(format!("File size: {sz} bytes"));
                }
                let record = ResearchDatasetRecord {
                    id: format!("gdc-file:{fid}"),
                    provider: "NCI Genomic Data Commons".to_string(),
                    title: format!("GDC open file: {name}"),
                    summary: format!("{}.", summary_parts.join(". ")),
                    cancer_types,
                    data_types,
                    sample_count: if cases.is_empty() {
                        None
                    } else {
                        Some(cases.len())
                    },
                    access: "Open-access released GDC file metadata".to_string(),
                    terms: "Open-access GDC file metadata via unauthenticated HTTPS API; follow NIH Genomic Data Sharing Policy and GDC Data Use Policy".to_string(),
                    source_url: portal,
                    api_url: api_url.clone(),
                    download_url: download,
                    retrieved_at: now,
                    evidence_use: default_dataset_evidence_use(),
                };
                Some((score, cases.len(), record))
            })
            .collect();

        ranked.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.2.id.cmp(&b.2.id))
        });

        let matched: Vec<ResearchDatasetRecord> = ranked
            .iter()
            .filter(|(s, _, _)| *s > 0)
            .map(|(_, _, r)| r.clone())
            .collect();
        let chosen = if matched.is_empty() {
            ranked.into_iter().take(limit).map(|(_, _, r)| r).collect()
        } else {
            matched.into_iter().take(limit).collect()
        };
        Ok((chosen, total))
    }

    async fn search_cbio_studies(
        &self,
        terms: &[String],
        limit: usize,
    ) -> Result<(Vec<ResearchDatasetRecord>, String), ResearchError> {
        let mut url = self
            .cbio_base_url
            .join("studies")
            .map_err(|_| ResearchError::InvalidResponse("Invalid cBioPortal URL.".to_string()))?;
        url.query_pairs_mut()
            .append_pair("projection", "SUMMARY")
            .append_pair("pageSize", "200")
            .append_pair("pageNumber", "0");
        let (data, final_url) = Self::download(&url).await?;
        let now = Utc::now();
        let (records, total) = Self::parse_cbio_studies(&data, terms, limit, &final_url, now)?;
        let note = format!(
            "cBioPortal studies: {total} public study metadata records checked, {} retained ({final_url}).",
            records.len()
        );
        Ok((records, note))
    }

    pub fn parse_cbio_studies(
        data: &[u8],
        terms: &[String],
        limit: usize,
        api_url: &Url,
        now: DateTime<Utc>,
    ) -> Result<(Vec<ResearchDatasetRecord>, usize), ResearchError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct CbioStudy {
            study_id: Option<String>,
            name: Option<String>,
            description: Option<String>,
            public_study: Option<bool>,
            cancer_type_id: Option<String>,
            citation: Option<String>,
            pmid: Option<String>,
            all_sample_count: Option<usize>,
            sequenced_sample_count: Option<usize>,
            cna_sample_count: Option<usize>,
            mrna_rna_seq_sample_count: Option<usize>,
            methylation_hm27_sample_count: Option<usize>,
        }

        let studies: Vec<CbioStudy> = serde_json::from_slice(data).map_err(|e| {
            ResearchError::InvalidResponse(format!(
                "cBioPortal did not return valid study metadata: {e}"
            ))
        })?;
        let total = studies.len();
        let mut ranked: Vec<(i64, usize, ResearchDatasetRecord)> = studies
            .into_iter()
            .filter_map(|s| {
                if s.public_study == Some(false) {
                    return None;
                }
                let sid = s.study_id?.trim().to_string();
                let name = s.name.as_deref().unwrap_or("").trim().to_string();
                if sid.is_empty() || name.is_empty() {
                    return None;
                }
                let samples = s.all_sample_count.unwrap_or(0);
                if samples == 0 {
                    return None;
                }
                let desc = s.description.as_deref().unwrap_or("").trim().to_string();
                let desc_lower = desc.to_lowercase();
                if ["embargo", "restricted", "controlled-access", "dbgap", "private"]
                    .iter()
                    .any(|w| desc_lower.contains(w))
                {
                    return None;
                }
                let cancer_type = s
                    .cancer_type_id
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let mut data_types = vec!["Clinical and sample-level study summary".to_string()];
                if s.sequenced_sample_count.unwrap_or(0) > 0 {
                    data_types.push("Somatic mutation profiling".to_string());
                }
                if s.cna_sample_count.unwrap_or(0) > 0 {
                    data_types.push("Copy-number alteration".to_string());
                }
                if s.mrna_rna_seq_sample_count.unwrap_or(0) > 0 {
                    data_types.push("RNA-seq expression".to_string());
                }
                if s.methylation_hm27_sample_count.unwrap_or(0) > 0 {
                    data_types.push("DNA methylation".to_string());
                }
                let mut haystack_parts = vec![
                    sid.clone(),
                    name.clone(),
                    desc.clone(),
                    cancer_type.clone(),
                    s.citation.clone().unwrap_or_default(),
                ];
                haystack_parts.extend(data_types.clone());
                let score = Self::score(&haystack_parts.join(" "), terms);
                let encoded = urlencoding::encode(&sid);
                let portal =
                    Url::parse(&format!("https://www.cbioportal.org/study/summary?id={encoded}"))
                        .ok()?;
                let mut summary_parts = vec![name.clone()];
                if !desc.is_empty() {
                    summary_parts.push(desc);
                }
                summary_parts.push(format!("Samples: {samples}"));
                if let Some(cit) = s.citation.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
                    summary_parts.push(format!("Citation: {cit}"));
                }
                if let Some(pmid) = s.pmid.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
                    summary_parts.push(format!("PMID: {pmid}"));
                }
                let record = ResearchDatasetRecord {
                    id: format!("cbioportal:{sid}"),
                    provider: "cBioPortal for Cancer Genomics".to_string(),
                    title: format!("{sid}: {name}"),
                    summary: format!("{}.", summary_parts.join(". ")),
                    cancer_types: if cancer_type.is_empty() {
                        Vec::new()
                    } else {
                        vec![cancer_type]
                    },
                    data_types,
                    sample_count: s.all_sample_count,
                    access: "Public cBioPortal study metadata".to_string(),
                    terms: "Public cBioPortal study metadata via unauthenticated HTTPS API; cite the original study and follow cBioPortal terms of use".to_string(),
                    source_url: portal,
                    api_url: api_url.clone(),
                    download_url: None,
                    retrieved_at: now,
                    evidence_use: default_dataset_evidence_use(),
                };
                Some((score, samples, record))
            })
            .collect();

        ranked.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.2.id.cmp(&b.2.id))
        });

        let matched: Vec<ResearchDatasetRecord> = ranked
            .iter()
            .filter(|(s, _, _)| *s > 0)
            .map(|(_, _, r)| r.clone())
            .collect();
        let chosen = if matched.is_empty() {
            ranked.into_iter().take(limit).map(|(_, _, r)| r).collect()
        } else {
            matched.into_iter().take(limit).collect()
        };
        Ok((chosen, total))
    }

    fn score(haystack: &str, terms: &[String]) -> i64 {
        if terms.is_empty() {
            return 1;
        }
        let lower = haystack.to_lowercase();
        let mut total = 0i64;
        for term in terms {
            if lower.contains(term) {
                total += (term.len() as i64).max(3);
            }
        }
        total
    }

    async fn download(url: &Url) -> Result<(Vec<u8>, Url), ResearchError> {
        if !CancerDatasetUrlPolicy::allows(url) {
            return Err(ResearchError::Unavailable(
                "This cancer dataset endpoint is not on the public dataset allowlist.".to_string(),
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(Policy::custom(|attempt| {
                if attempt.previous().len() >= 3 {
                    return attempt.error("Too many redirects");
                }
                if !CancerDatasetUrlPolicy::allows(attempt.url()) {
                    return attempt.stop();
                }
                attempt.follow()
            }))
            .build()
            .map_err(|e| ResearchError::Unavailable(format!("Transport error: {e}")))?;

        let mut response = client
            .get(url.clone())
            .header(ACCEPT, "application/json")
            .header(
                USER_AGENT,
                "DementiaResearch/0.4 (public cancer dataset catalog; rustls)",
            )
            .send()
            .await
            .map_err(|e| ResearchError::Unavailable(format!("Network error: {e}")))?;

        let final_url = response.url().clone();
        if !CancerDatasetUrlPolicy::allows(&final_url) {
            return Err(ResearchError::InvalidResponse(
                "The cancer dataset response came from an unsupported location.".to_string(),
            ));
        }
        let status = response.status();
        if !status.is_success() {
            return Err(ResearchError::Http(
                status.as_u16(),
                format!(
                    "Public dataset catalog access failed from {}.",
                    final_url.host_str().unwrap_or("dataset service")
                ),
            ));
        }
        let limit = 2 * 1024 * 1024;
        if let Some(len) = response.content_length() {
            if len as usize > limit {
                return Err(ResearchError::InvalidResponse(
                    "The dataset catalog response exceeded the local safety size limit."
                        .to_string(),
                ));
            }
        }
        let mut out = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| ResearchError::Unavailable(format!("Stream error: {e}")))?
        {
            if out.len() + chunk.len() > limit {
                return Err(ResearchError::InvalidResponse(
                    "The dataset catalog response exceeded the local safety size limit."
                        .to_string(),
                ));
            }
            out.extend_from_slice(&chunk);
        }
        Ok((out, final_url))
    }
}
