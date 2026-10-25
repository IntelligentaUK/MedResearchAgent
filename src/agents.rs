use crate::citation::{EvidenceDocument, EvidenceValidator};
use crate::dedup::PaperDeduplicator;
use crate::literature::{FreeLiteratureSearchClient, LiteratureSearchResult};
use crate::models::{
     normalize_doi, ArticleText, ClaimAssessment, ConnectionReview, DiscoveryCycle,
    EvidenceCitation, HypothesisDraft, HypothesisValidation, InstitutionalAccess,
    LinkedHypothesis, Paper, QueuedHypothesis, ResearchDirection, ResearchDomain, ResearchError,
    ResearchPipeline, StudyEvidence, ValidationVerdict,
};
use chrono::Utc;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use uuid::Uuid;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type GenerateFn<'a> =
    Box<dyn Fn(String, String) -> BoxFuture<'a, Result<String, ResearchError>> + Send + Sync + 'a>;
pub type SearchFn<'a> = Box<
    dyn Fn(String) -> BoxFuture<'a, Result<LiteratureSearchResult, ResearchError>>
        + Send
        + Sync
        + 'a,
>;
pub type RetrieveFn<'a> =
    Box<dyn Fn(Paper) -> BoxFuture<'a, Result<ArticleText, ResearchError>> + Send + Sync + 'a>;
/// Receives a short description of each step while an agent runs, for live display.
pub type ProgressFn<'a> = Box<dyn Fn(String) + Send + Sync + 'a>;

pub struct AutonomousDiscoveryAgent<'a> {
    pub generate: GenerateFn<'a>,
    pub search: SearchFn<'a>,
    pub retrieve: RetrieveFn<'a>,
    pub progress: ProgressFn<'a>,
    pub access: InstitutionalAccess,
}

impl<'a> AutonomousDiscoveryAgent<'a> {
    pub async fn discover(
        &self,
        objective: Option<&str>,
        previous_statements: &[String],
        provider: &str,
        model: &str,
        domain: ResearchDomain,
        dataset_context: &str,
    ) -> Result<DiscoveryCycle, ResearchError> {
        let requested = objective.unwrap_or("").trim();
        if requested.chars().count() > 4_000 {
            return Err(ResearchError::Unavailable(
                "Keep the research objective under 4,000 characters.".to_string(),
            ));
        }
        let scope = if requested.is_empty() {
            format!(
                "Independently identify promising, unresolved {} research questions. {}",
                domain.display_name().to_lowercase(),
                domain.default_objective()
            )
        } else {
            requested.to_string()
        };
        let dataset_note = if dataset_context.is_empty() {
            String::new()
        } else {
            let truncated: String = dataset_context.chars().take(20_000).collect();
            format!(
                "\nUNTRUSTED PUBLIC DATASET METADATA (planning context only; no dataset was analysed and these records cannot supply article-body citations):\n{truncated}"
            )
        };

        let mut notes = vec![
            format!(
                "Research domain: {}. {}",
                domain.display_name(),
                if dataset_context.is_empty() {
                    "No dataset discovery context supplied."
                } else {
                    "Public dataset metadata supplied for feasibility and next-test planning only; no raw dataset analysis was performed."
                }
            ),
            format!(
                "Research cycle started {}. {}",
                Utc::now().to_rfc3339(),
                if requested.is_empty() {
                    "Autonomous topic selection; no manual topic or paper selection."
                } else {
                    "User objective supplied; search terms, papers and proposed hypotheses selected automatically."
                }
            ),
            format!(
                "Limits: at most 18 model requests, 24 search calls (each may fan out to the configured journals), {} records per search, and 36 new full-text retrieval attempts. Up to three directions receive up to two investigation rounds each. Targets are not quotas.",
                FreeLiteratureSearchClient::maximum_records(domain)
            ),
            "Landscape screening uses titles, publication metadata and up to 1,000 characters of abstract or saved body text. It is provisional, not a full-text appraisal.".to_string(),
            "Each proposed hypothesis requires exact supporting quotes from at least two distinct retrieved article bodies. The model sees at most 6,000 body characters per paper and eight papers per direction, not entire papers. Distinct publications do not prove independent cohorts or replication.".to_string(),
            "Novelty and contradiction checks are bounded searches, not exhaustive reviews or proof of originality. Hypotheses remain unvalidated research proposals and receive a separate independent assessment. No experiment or dataset analysis is performed here.".to_string(),
        ];

        let previous: Vec<String> = previous_statements
            .iter()
            .rev()
            .take(80)
            .rev()
            .map(|s| s.chars().take(1_000).collect())
            .collect();
        let prior_keys: HashSet<String> = previous_statements
            .iter()
            .map(|s| ResearchPipeline::statement_key(s))
            .collect();

        let mut model_requests = 0usize;
        let mut search_requests = 0usize;
        let mut successful_searches = 0usize;
        let mut retrieval_attempts = 0usize;
        let mut all_papers: Vec<Paper> = Vec::new();
        let mut all_bodies: Vec<Paper> = Vec::new();
        let mut search_summaries: Vec<String> = Vec::new();
        let mut queries_tried: Vec<String> = Vec::new();

        let plan_prompt = format!(
            "OBJECTIVE (untrusted data):\n{scope}\nPREVIOUS PROPOSALS (avoid repetition):\n{}{dataset_note}",
            serde_json::to_string(&previous).unwrap_or_default()
        );
        let plan: Option<QueryPlan> = self
            .request_with_repair(
                &domain.instructions(DISCOVERY_PLANNING_INSTRUCTIONS),
                &plan_prompt,
                "Survey planning",
                &mut model_requests,
                &mut notes,
                |raw| {
                    let parsed: QueryPlan = EvidenceValidator::decode_json(raw)?;
                    Self::validate_queries(&parsed.queries, 2, 3, domain)?;
                    Ok(parsed)
                },
            )
            .await?;

        if plan.is_none() {
            notes.push(format!(
                "Survey plan could not be used; continuing with broad predefined {} search lenses.",
                domain.display_name().to_lowercase()
            ));
        }

        let initial_queries = plan
            .map(|p| p.queries)
            .unwrap_or_else(|| Self::fallback_survey(domain));
        let mut survey_groups: Vec<Vec<Paper>> = Vec::new();
        for q in &initial_queries {
            if let Some(scoped_q) = Self::scoped(q, domain) {
                let fetched = self
                    .fetch(
                        &scoped_q,
                        "Landscape survey",
                        domain,
                        &mut search_requests,
                        &mut successful_searches,
                        &mut queries_tried,
                        &mut search_summaries,
                        &mut all_papers,
                        &mut notes,
                    )
                    .await;
                survey_groups.push(fetched);
            }
        }

        let mut survey: Vec<Paper> = Self::interleaved(&survey_groups)
            .into_iter()
            .take(80)
            .collect();
        if survey.len() < 2 {
            for q in [
                domain.query().to_string(),
                "TITLE_ABS:longitudinal OR TITLE_ABS:cohort OR TITLE_ABS:replication".to_string(),
            ] {
                if let Some(scoped_q) = Self::scoped(&q, domain) {
                    let fetched = self
                        .fetch(
                            &scoped_q,
                            "Broadened landscape survey",
                            domain,
                            &mut search_requests,
                            &mut successful_searches,
                            &mut queries_tried,
                            &mut search_summaries,
                            &mut all_papers,
                            &mut notes,
                        )
                        .await;
                    survey_groups.push(fetched);
                }
            }
            survey = Self::interleaved(&survey_groups)
                .into_iter()
                .take(80)
                .collect();
        }

        if successful_searches == 0 {
            return Err(ResearchError::Unavailable(format!(
                "All discovery searches failed, including broadened alternatives. The cycle can retry when sources are available. {}",
                notes.last().cloned().unwrap_or_default()
            )));
        }

        let mut landscape: Vec<ResearchDirection> = Vec::new();
        let mut drafts: Vec<HypothesisDraft> = Vec::new();

        if survey.is_empty() {
            notes.push("Stopping this cycle: completed searches returned no non-retracted records. No landscape or hypothesis was invented; the next scheduled cycle can try again.".to_string());
        } else {
            let known_ids: HashSet<String> = survey.iter().map(|p| p.id.clone()).collect();
            let candidates_json = serde_json::to_string(
                &survey.iter().map(DiscoveryCandidate::from).collect::<Vec<_>>(),
            )
            .unwrap_or_default();
            let landscape_prompt = format!(
                "OBJECTIVE: {scope}\nPREVIOUS PROPOSALS: {}\nUNTRUSTED SURVEY RECORDS:\n{candidates_json}{dataset_note}",
                serde_json::to_string(&previous).unwrap_or_default()
            );
            let mapped: Option<LandscapePlan> = self
                .request_with_repair(
                    &domain.instructions(DISCOVERY_LANDSCAPE_INSTRUCTIONS),
                    &landscape_prompt,
                    "Research landscape",
                    &mut model_requests,
                    &mut notes,
                    |raw| {
                        let parsed: LandscapePlan = EvidenceValidator::decode_json(raw)?;
                        Self::validate_landscape(&parsed, &known_ids, domain)?;
                        Ok(parsed)
                    },
                )
                .await?;

            if let Some(mapped) = mapped {
                landscape = mapped.directions;
                notes.push(format!("Landscape selection: {}", mapped.summary));
                for inv in mapped.investigations {
                    let direction = landscape[inv.direction_index].clone();
                    let direction_queries = inv.queries;
                    let mut groups: Vec<Vec<Paper>> = vec![survey
                        .iter()
                        .filter(|p| direction.paper_ids.contains(&p.id))
                        .cloned()
                        .collect()];
                    for (idx, q) in direction_queries.iter().enumerate() {
                        if let Some(scoped_q) = Self::scoped(q, domain) {
                            let lens = [
                                "Focused primary evidence",
                                "Novelty and direct prior tests",
                                "Null, contradictory and alternative evidence",
                            ][idx.min(2)];
                            let fetched = self
                                .fetch(
                                    &scoped_q,
                                    &format!("{} — {lens}", direction.title),
                                    domain,
                                    &mut search_requests,
                                    &mut successful_searches,
                                    &mut queries_tried,
                                    &mut search_summaries,
                                    &mut all_papers,
                                    &mut notes,
                                )
                                .await;
                            groups.push(fetched);
                        }
                    }

                    let candidates: Vec<Paper> = Self::interleaved(&groups)
                        .into_iter()
                        .filter(|p| Self::eligible(p, &self.access))
                        .take(12)
                        .collect();
                    let bodies = self
                        .read_bodies(
                            &candidates,
                            &direction.title,
                            &mut retrieval_attempts,
                            &mut all_bodies,
                            &mut notes,
                        )
                        .await;
                    let inspected: Vec<Paper> = bodies.into_iter().take(8).collect();

                    if inspected.len() >= 2 {
                        let documents = EvidenceValidator::documents(&inspected, 6_000, true);
                        let mut known_statements = prior_keys.clone();
                        for d in &drafts {
                            known_statements.insert(ResearchPipeline::statement_key(&d.statement));
                        }
                        let mut prior_all = previous.clone();
                        prior_all.extend(drafts.iter().map(|d| d.statement.clone()));
                        let draft_prompt = format!(
                            "DIRECTION: {}\nSEARCH OUTCOMES (failed queries do not establish coverage): {}\nPREVIOUS PROPOSALS: {}\nUNTRUSTED ARTICLE-BODY EXCERPTS:\n{}\n{dataset_note}",
                            serde_json::to_string(&direction).unwrap_or_default(),
                            serde_json::to_string(&search_summaries).unwrap_or_default(),
                            serde_json::to_string(&prior_all).unwrap_or_default(),
                            serde_json::to_string(&documents).unwrap_or_default(),
                        );
                        let envelope: Option<DraftEnvelope> = self
                            .request_with_repair(
                                &domain.instructions(DISCOVERY_DRAFTING_INSTRUCTIONS),
                                &draft_prompt,
                                &format!("{} hypothesis drafting", direction.title),
                                &mut model_requests,
                                &mut notes,
                                |raw| {
                                    let mut env: DraftEnvelope =
                                        EvidenceValidator::decode_json(raw)?;
                                    if env.hypotheses.len() > 1
                                        || EvidenceValidator::normalize(&env.reason).is_empty()
                                    {
                                        return Err(ResearchError::InvalidResponse(
                                            "Return zero or one hypothesis and explain why it was retained or rejected.".to_string(),
                                        ));
                                    }
                                    let mut validated = Vec::new();
                                    for draft in env.hypotheses {
                                        let checked = EvidenceValidator::validate_discovery_draft(
                                            draft, &documents,
                                        )?;
                                        if known_statements.contains(
                                            &ResearchPipeline::statement_key(&checked.statement),
                                        ) {
                                            return Err(ResearchError::InvalidResponse(
                                                "This exact hypothesis has already been proposed. Develop a materially distinct testable question or return no hypothesis.".to_string(),
                                            ));
                                        }
                                        validated.push(checked);
                                    }
                                    env.hypotheses = validated;
                                    Ok(env)
                                },
                            )
                            .await?;

                        if let Some(env) = envelope {
                            notes.push(format!("{} drafting: {}", direction.title, env.reason));
                            if let Some(first) = env.hypotheses.into_iter().next() {
                                drafts.push(first);
                            }
                        }
                    } else {
                        notes.push(format!(
                            "{}: {} readable article bodies; no draft was requested because two distinct supporting bodies are required.",
                            direction.title,
                            inspected.len()
                        ));
                    }
                }
            }
        }

        notes.push(format!(
            "Cycle stopped with {} grounded proposals from {} selected directions; {model_requests} model requests, {search_requests} searches, {retrieval_attempts} new retrieval attempts, and {} readable article bodies.",
            drafts.len(),
            landscape.iter().filter(|d| d.selected).count(),
            all_bodies.len()
        ));

        let mut combined = all_bodies;
        combined.extend(all_papers);
        Ok(DiscoveryCycle {
            dataset_records: None,
            research_domain: Some(domain),
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            objective: scope,
            landscape,
            hypotheses: drafts,
            papers: PaperDeduplicator::deduplicate(&combined),
            audit: notes,
            provider: provider.to_string(),
            model: model.to_string(),
        })
    }

    async fn request_with_repair<T>(
        &self,
        system: &str,
        prompt: &str,
        phase: &str,
        model_requests: &mut usize,
        notes: &mut Vec<String>,
        validate: impl Fn(&str) -> Result<T, ResearchError>,
    ) -> Result<Option<T>, ResearchError> {
        let mut feedback = String::new();
        for attempt in 0..2 {
            if *model_requests >= 18 {
                notes.push(format!(
                    "{phase}: skipped because the 18-request model limit was reached."
                ));
                return Ok(None);
            }
            *model_requests += 1;
            (self.progress)(if attempt == 0 {
                format!("{phase}: asking the model")
            } else {
                format!("{phase}: asking the model to repair its output")
            });
            let response = (self.generate)(system.to_string(), format!("{prompt}{feedback}")).await?;
            match validate(&response) {
                Ok(val) => return Ok(Some(val)),
                Err(ResearchError::InvalidResponse(msg)) if attempt == 0 => {
                    notes.push(format!("{phase} required one structured-output repair: {msg}"));
                    feedback = format!(
                        "\n\nREPAIR REQUIRED: Your previous output was rejected ({msg}). Return ONLY valid JSON matching the schema and exact citation rules."
                    );
                }
                Err(ResearchError::InvalidResponse(msg)) => {
                    notes.push(format!("{phase} rejected after repair: {msg}"));
                    return Ok(None);
                }
                Err(other) => return Err(other),
            }
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    async fn fetch(
        &self,
        query: &str,
        phase: &str,
        domain: ResearchDomain,
        search_requests: &mut usize,
        successful_searches: &mut usize,
        queries_tried: &mut Vec<String>,
        search_summaries: &mut Vec<String>,
        all_papers: &mut Vec<Paper>,
        notes: &mut Vec<String>,
    ) -> Vec<Paper> {
        if *search_requests >= 24 {
            notes.push(format!("{phase}: search budget reached; skipped {query}."));
            return Vec::new();
        }
        *search_requests += 1;
        queries_tried.push(query.to_string());
        match (self.search)(query.to_string()).await {
            Ok(result) => {
                *successful_searches += 1;
                let max_rec = FreeLiteratureSearchClient::maximum_records(domain);
                // Deduplicate and filter before applying the cap so duplicate records never displace unique papers.
                let valid: Vec<Paper> = PaperDeduplicator::deduplicate(&result.papers)
                    .into_iter()
                    .filter(|p| !p.is_retracted() && !p.is_conference_abstract())
                    .take(max_rec)
                    .collect();
                let summary = format!(
                    "{phase}: {query} -> {} usable non-retracted records.",
                    valid.len()
                );
                search_summaries.push(summary.clone());
                notes.push(summary);
                for n in result.notes {
                    notes.push(format!("{phase} source coverage: {n}"));
                }
                all_papers.extend(valid.clone());
                valid
            }
            Err(e) => {
                let summary = format!("{phase} failed: {query} ({e})");
                search_summaries.push(summary.clone());
                notes.push(summary);
                Vec::new()
            }
        }
    }

    async fn read_bodies(
        &self,
        candidates: &[Paper],
        phase: &str,
        retrieval_attempts: &mut usize,
        all_bodies: &mut Vec<Paper>,
        notes: &mut Vec<String>,
    ) -> Vec<Paper> {
        let mut retained = Vec::new();
        for candidate in candidates {
            if retained.len() >= 8 {
                break;
            }
            let mut paper = candidate.clone();
            if EvidenceValidator::full_text_passages(&paper).is_empty() {
                if let Some(existing) = all_bodies.iter().find(|b| b.id == paper.id) {
                    paper.full_text = existing.full_text.clone();
                } else {
                    if *retrieval_attempts >= 36 {
                        notes.push(format!(
                            "{phase}: full-text retrieval budget reached before {}.",
                            paper.id
                        ));
                        break;
                    }
                    *retrieval_attempts += 1;
                    match (self.retrieve)(paper.clone()).await {
                        Ok(article) => {
                            paper.full_text = Some(article);
                        }
                        Err(e) => {
                            notes.push(format!("{phase}: {} body unavailable ({e}).", paper.id));
                            continue;
                        }
                    }
                }
            }
            if !EvidenceValidator::full_text_passages(&paper).is_empty() {
                if let Some(ref ft) = paper.full_text {
                    notes.push(format!(
                        "{phase}: retained body {} ({}, checksum {}).",
                        paper.id, ft.source_url, ft.checksum
                    ));
                }
                if !all_bodies.iter().any(|b| b.id == paper.id) {
                    all_bodies.push(paper.clone());
                }
                retained.push(paper);
            }
        }
        retained
    }

    fn eligible(paper: &Paper, access: &InstitutionalAccess) -> bool {
        if paper.is_retracted() {
            return false;
        }
        if !EvidenceValidator::full_text_passages(paper).is_empty() {
            return true;
        }
        if paper.is_conference_abstract() {
            return false;
        }
        paper.has_retrieval_route(access)
            && (paper.pmcid.is_some()
                || paper.doi.is_some()
                || paper
                    .full_text_locations
                    .as_ref()
                    .is_some_and(|l| !l.is_empty()))
    }

    fn interleaved(groups: &[Vec<Paper>]) -> Vec<Paper> {
        let mut out = Vec::new();
        let max_len = groups.iter().map(Vec::len).max().unwrap_or(0);
        for idx in 0..max_len {
            for g in groups {
                if let Some(p) = g.get(idx) {
                    out.push(p.clone());
                }
            }
        }
        PaperDeduplicator::deduplicate(&out)
    }

    fn scoped(query: &str, domain: ResearchDomain) -> Option<String> {
        let q = EvidenceValidator::normalize(query);
        if q.is_empty() || q.chars().count() > 500 || !balanced_query(&q) {
            return None;
        }
        Some(format!("({}) AND ({q})", domain.query()))
    }

    fn validate_queries(
        queries: &[String],
        min: usize,
        max: usize,
        domain: ResearchDomain,
    ) -> Result<(), ResearchError> {
        let norm_set: HashSet<String> = queries
            .iter()
            .map(|q| EvidenceValidator::normalize(q).to_lowercase())
            .collect();
        if !(min..=max).contains(&queries.len())
            || norm_set.len() != queries.len()
            || !queries
                .iter()
                .all(|q| q.chars().count() <= 350 && Self::scoped(q, domain).is_some())
        {
            return Err(ResearchError::InvalidResponse(format!(
                "Supply {min}–{max} distinct, balanced queries of at most 350 characters."
            )));
        }
        Ok(())
    }

    fn validate_landscape(
        mapped: &LandscapePlan,
        known_ids: &HashSet<String>,
        domain: ResearchDomain,
    ) -> Result<(), ResearchError> {
        let inv_indices: HashSet<usize> = mapped
            .investigations
            .iter()
            .map(|i| i.direction_index)
            .collect();
        if mapped.directions.len() > 6
            || mapped.investigations.len() > 3
            || EvidenceValidator::normalize(&mapped.summary).is_empty()
            || inv_indices.len() != mapped.investigations.len()
        {
            return Err(ResearchError::InvalidResponse(
                "Return up to six directions, at most three distinct investigations, and an explicit selection summary.".to_string(),
            ));
        }
        for dir in &mapped.directions {
            let req = [
                &dir.title,
                &dir.question,
                &dir.known,
                &dir.gap,
                &dir.importance,
                &dir.selection_reason,
            ];
            let pid_set: HashSet<String> = dir.paper_ids.iter().cloned().collect();
            if !req.iter().all(|s| !EvidenceValidator::normalize(s).is_empty())
                || dir.paper_ids.is_empty()
                || !pid_set.is_subset(known_ids)
                || pid_set.len() != dir.paper_ids.len()
            {
                return Err(ResearchError::InvalidResponse(
                    "Each direction needs a concrete question, known observations, gap, importance, selection reason and distinct known source IDs.".to_string(),
                ));
            }
        }
        let selected: HashSet<usize> = mapped
            .directions
            .iter()
            .enumerate()
            .filter_map(|(i, d)| d.selected.then_some(i))
            .collect();
        if selected != inv_indices {
            return Err(ResearchError::InvalidResponse(
                "Every selected direction must have exactly one investigation, and unselected directions must have none.".to_string(),
            ));
        }
        for inv in &mapped.investigations {
            Self::validate_queries(&inv.queries, 3, 3, domain)?;
        }
        Ok(())
    }

    fn fallback_survey(domain: ResearchDomain) -> Vec<String> {
        if domain == ResearchDomain::Cancer {
            vec![
                "TITLE_ABS:review".to_string(),
                r#"(TITLE_ABS:immunotherapy OR TITLE_ABS:metastasis OR TITLE_ABS:"tumor microenvironment")"#.to_string(),
                "(TITLE_ABS:resistance OR TITLE_ABS:biomarker OR TITLE_ABS:survivorship OR TITLE_ABS:replication)".to_string(),
            ]
        } else {
            vec![
                "TITLE_ABS:review".to_string(),
                r#"(TITLE_ABS:"Lewy body" OR TITLE_ABS:frontotemporal OR TITLE_ABS:"vascular cognitive impairment")"#.to_string(),
                r#"(TITLE_ABS:resilience OR TITLE_ABS:"quality of life" OR TITLE_ABS:measurement OR TITLE_ABS:replication)"#.to_string(),
            ]
        }
    }
}

#[derive(Deserialize)]
struct QueryPlan {
    queries: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectionInvestigation {
    direction_index: usize,
    queries: Vec<String>,
}

#[derive(Deserialize)]
struct LandscapePlan {
    directions: Vec<ResearchDirection>,
    investigations: Vec<DirectionInvestigation>,
    summary: String,
}

#[derive(Deserialize)]
struct DraftEnvelope {
    hypotheses: Vec<HypothesisDraft>,
    reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiscoveryCandidate {
    paper_id: String,
    title: String,
    year: Option<i32>,
    publication_types: Vec<String>,
    is_preprint: bool,
    coverage: String,
    excerpt: String,
}

impl From<&Paper> for DiscoveryCandidate {
    fn from(paper: &Paper) -> Self {
        let body = EvidenceValidator::full_text_passages(paper);
        let coverage = if !body.is_empty() {
            "saved article-body excerpt"
        } else if paper.abstract_text.is_empty() {
            "metadata only"
        } else {
            "abstract excerpt only"
        };
        let raw_excerpt = if body.is_empty() {
            paper.abstract_text.clone()
        } else {
            body.into_iter().map(|p| p.text).collect::<Vec<_>>().join(" ")
        };
        Self {
            paper_id: paper.id.clone(),
            title: paper.title.chars().take(400).collect(),
            year: paper.year,
            publication_types: paper.publication_types.iter().take(10).cloned().collect(),
            is_preprint: paper.is_preprint,
            coverage: coverage.to_string(),
            excerpt: raw_excerpt.chars().take(1_000).collect(),
        }
    }
}

pub struct HypothesisValidationAgent<'a> {
    pub generate: GenerateFn<'a>,
    pub search: SearchFn<'a>,
    pub retrieve: RetrieveFn<'a>,
    pub progress: ProgressFn<'a>,
    pub access: InstitutionalAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum SearchLens {
    Support,
    Contradiction,
    Alternatives,
    WeakestClaim,
}

impl SearchLens {
    const ALL: [SearchLens; 4] = [
        SearchLens::Support,
        SearchLens::Contradiction,
        SearchLens::Alternatives,
        SearchLens::WeakestClaim,
    ];

    fn as_str(&self) -> &'static str {
        match self {
            SearchLens::Support => "support",
            SearchLens::Contradiction => "contradiction",
            SearchLens::Alternatives => "alternatives",
            SearchLens::WeakestClaim => "weakestClaim",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidationPlan {
    exact_scope: String,
    working_interpretation: String,
    hypothesis_type: String,
    claims: Vec<PlannedClaim>,
    searches: Vec<PlannedSearch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlannedClaim {
    id: String,
    statement: String,
    essential: bool,
    predicted_observation: String,
    weakening_observation: String,
    alternatives: Vec<String>,
    distinguishing_study: String,
    meaningful_effect: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlannedSearch {
    lens: SearchLens,
    query: String,
    broader_query: String,
    #[serde(rename = "claimIDs")]
    claim_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAssessment {
    verdict: ValidationVerdict,
    confidence: String,
    summary: String,
    claims: Vec<ClaimAssessment>,
    evidence: Vec<StudyEvidence>,
    can_conclude: String,
    cannot_conclude: String,
    would_change_assessment: String,
    next_test: String,
    limitations: Vec<String>,
    proposed_revision: Option<ProposedRevision>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProposedRevision {
    statement: String,
    explanation: String,
    next_test: String,
}

impl<'a> HypothesisValidationAgent<'a> {
    pub async fn validate(
        &self,
        item: &QueuedHypothesis,
        supplied_papers: &[Paper],
        provider: &str,
        model: &str,
        domain: ResearchDomain,
        dataset_context: &str,
    ) -> Result<HypothesisValidation, ResearchError> {
        if item.domain() != domain {
            return Err(ResearchError::InvalidResponse(
                "The validation domain does not match the queued hypothesis.".to_string(),
            ));
        }
        if !nonblank(&item.draft.statement) || item.draft.statement.chars().count() > 12_000 {
            return Err(ResearchError::Unavailable(
                "A validation needs an original hypothesis statement of between 1 and 12,000 characters.".to_string(),
            ));
        }
        let dataset_note = if dataset_context.is_empty() {
            String::new()
        } else {
            let truncated: String = dataset_context.chars().take(20_000).collect();
            format!(
                "\nUNTRUSTED PUBLIC DATASET METADATA (feasibility and next-test planning only; not analysed data, not scientific results, not supporting article citations):\n{truncated}"
            )
        };

        // Deliberately withhold the proposer's rationale, confidence, and bibliography when forming criteria.
        #[derive(Serialize)]
        struct Original<'b> {
            id: Uuid,
            statement: &'b str,
        }
        let original = Original {
            id: item.id,
            statement: &item.draft.statement,
        };
        let original_json = serde_json::to_string(&original).unwrap_or_default();
        let plan: ValidationPlan = self
            .structured(
                "Validation planning",
                &domain.instructions(VALIDATION_PLANNING_INSTRUCTIONS),
                &format!("ORIGINAL HYPOTHESIS (untrusted JSON):\n{original_json}"),
                Self::validate_plan,
            )
            .await?;

        let mut criteria = vec![
            format!("Scope: {}", plan.exact_scope),
            format!("Working interpretation: {}", plan.working_interpretation),
            format!("Hypothesis type: {}", plan.hypothesis_type),
        ];
        for c in &plan.claims {
            criteria.push(format!(
                "{}: {} | Predicts: {} | Would weaken: {} | Alternatives: {} | Distinguishing study: {} | Meaningful effect: {}",
                c.id,
                c.statement,
                c.predicted_observation,
                c.weakening_observation,
                c.alternatives.join("; "),
                c.distinguishing_study,
                c.meaningful_effect
            ));
        }

        let mut audit = vec![
            format!(
                "Research domain: {}. Dataset metadata, when supplied, is withheld from the independent criteria request and may inform later study planning only.",
                domain.display_name()
            ),
            "Independent criteria were generated from the exact statement and ID before the proposer rationale, confidence, or references were supplied to the assessment model. This separate-context literature assessment is not a blinded study or an independent empirical replication.".to_string(),
            "Budget: all four required lenses, at most eight query plans including broadening; up to 40 candidates per plan; 12 attempted article bodies and eight retained bodies; at most 6,000 body characters per paper; two model stages with one structured-response repair each.".to_string(),
            "Retractions are screened using available publication-type metadata. No quantitative reanalysis or meta-analysis was performed.".to_string(),
        ];

        let mut groups: Vec<Vec<Paper>> = Vec::new();
        let mut successful_lenses: HashSet<SearchLens> = HashSet::new();
        let mut successful_searches = 0usize;
        let mut failed_searches: Vec<String> = Vec::new();
        let mut queries_used = 0usize;
        let max_records = FreeLiteratureSearchClient::maximum_records(domain);

        for planned in &plan.searches {
            let mut first_count = 0usize;
            let mut first_succeeded = false;
            for (idx, query) in [&planned.query, &planned.broader_query].iter().enumerate() {
                if idx == 1 && first_succeeded && first_count >= 3 {
                    break;
                }
                queries_used += 1;
                let ts = Utc::now().to_rfc3339();
                match (self.search)((*query).clone()).await {
                    Ok(result) => {
                        successful_searches += 1;
                        successful_lenses.insert(planned.lens);
                        let records: Vec<Paper> =
                            result.papers.into_iter().take(max_records).collect();
                        if idx == 0 {
                            first_succeeded = true;
                            first_count = PaperDeduplicator::deduplicate(&records)
                                .into_iter()
                                .filter(|p| !p.is_retracted())
                                .count();
                        }
                        audit.push(format!(
                            "{ts} | {}{} | claims {} | query: {query} | {} retained before deduplication. Zero hits mean a bounded search limitation, not disproof.",
                            planned.lens.as_str(),
                            if idx == 1 { " broader fallback" } else { "" },
                            planned.claim_ids.join(", "),
                            records.len()
                        ));
                        audit.extend(result.notes);
                        groups.push(records);
                    }
                    Err(e) => {
                        let failure = format!(
                            "{ts} | {} | query: {query} | unavailable: {e}",
                            planned.lens.as_str()
                        );
                        failed_searches.push(failure.clone());
                        audit.push(failure);
                    }
                }
            }
        }

        if successful_searches == 0 {
            return Err(ResearchError::Unavailable(format!(
                "Every independent validation search failed. The hypothesis remains queued for retry; no scientific verdict was assigned. {}",
                failed_searches.join(" ")
            )));
        }

        let incomplete_lenses: Vec<SearchLens> = SearchLens::ALL
            .into_iter()
            .filter(|l| !successful_lenses.contains(l))
            .collect();
        let supplied = PaperDeduplicator::deduplicate(supplied_papers);
        let discovered = Self::interleave(&groups);
        let mut combined = supplied.clone();
        combined.extend(discovered);
        let all_papers = PaperDeduplicator::deduplicate(&combined);
        let supplied_ids: HashSet<String> = supplied.iter().map(|p| p.id.clone()).collect();
        let independently_discovered: Vec<Paper> = all_papers
            .iter()
            .filter(|p| !supplied_ids.contains(&p.id))
            .cloned()
            .collect();
        let retracted: Vec<Paper> = all_papers
            .iter()
            .filter(|p| p.is_retracted())
            .cloned()
            .collect();
        let new_candidates: Vec<Paper> = independently_discovered
            .iter()
            .filter(|p| !p.is_retracted() && !p.is_conference_abstract())
            .cloned()
            .collect();
        let supplied_candidates: Vec<Paper> = all_papers
            .iter()
            .filter(|p| {
                supplied_ids.contains(&p.id) && !p.is_retracted() && !p.is_conference_abstract()
            })
            .cloned()
            .collect();
        let candidates: Vec<Paper> = Self::interleave(&[new_candidates, supplied_candidates])
            .into_iter()
            .take(12)
            .collect();

        audit.push(format!(
            "Candidate audit: {} distinct source records, {} beyond the supplied bibliography, {} excluded retraction records, {} prioritized body candidates.",
            all_papers.len(),
            independently_discovered.len(),
            retracted.len(),
            candidates.len()
        ));

        let mut bodies: Vec<Paper> = Vec::new();
        let mut attempted = 0usize;
        let mut source_failures: Vec<String> = Vec::new();

        for mut paper in candidates {
            if bodies.len() >= 8 {
                break;
            }
            attempted += 1;
            if EvidenceValidator::full_text_passages(&paper).is_empty() {
                if !paper.has_retrieval_route(&self.access) {
                    let failure = format!(
                        "{} | metadata access only | body unavailable: The source does not report open-access or author-manuscript retrieval eligibility.",
                        paper.id
                    );
                    source_failures.push(failure.clone());
                    audit.push(failure);
                    continue;
                }
                match (self.retrieve)(paper.clone()).await {
                    Ok(ft) => paper.full_text = Some(ft),
                    Err(e) => {
                        let failure = format!(
                            "{} | metadata access only | body unavailable: {e} | citation: {}",
                            paper.id,
                            paper.citation()
                        );
                        source_failures.push(failure.clone());
                        audit.push(failure);
                        continue;
                    }
                }
            }
            if EvidenceValidator::full_text_passages(&paper).is_empty() {
                let failure = format!(
                    "{} | body unavailable: No usable article-body passages were returned; no abstract was substituted.",
                    paper.id
                );
                source_failures.push(failure.clone());
                audit.push(failure);
                continue;
            }
            if let Some(ref ft) = paper.full_text {
                audit.push(format!(
                    "{} | {} | {} | article-body access, {}, {}, checksum {}",
                    paper.id,
                    paper.citation(),
                    if supplied_ids.contains(&paper.id) {
                        "supplied-source audit"
                    } else {
                        "independently discovered source"
                    },
                    ft.format,
                    ft.source_url,
                    ft.checksum
                ));
            }
            bodies.push(paper);
        }

        let (supplied_checks, check_audit, check_limits) =
            Self::check_supplied_citations(&item.draft.citations, &bodies);
        audit.extend(check_audit);
        audit.push(format!(
            "Stopping reason: completed the bounded four-lens search with {queries_used} query plans and {attempted} body attempts; {} usable bodies retained.",
            bodies.len()
        ));

        let documents = EvidenceValidator::documents(&bodies, 6_000, true);
        let mut common_limits = vec![
            "This is an assessment of selected published evidence, not new empirical validation or clinical guidance.".to_string(),
            "At most 6,000 article-body characters per retained paper were supplied to the model. Full methods, supplementary results, corrections, registrations and study independence may remain unverified.".to_string(),
            "No quantitative reanalysis or meta-analysis was performed; missing sample sizes, effect estimates, uncertainty or prespecification must remain unknown.".to_string(),
        ];
        if !incomplete_lenses.is_empty() {
            common_limits.push(format!(
                "Required search lenses remain unavailable: {}. Positive validation is withheld.",
                incomplete_lenses
                    .iter()
                    .map(|l| l.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        common_limits.extend(check_limits);

        if documents.is_empty() {
            let mut limits = common_limits;
            limits.extend(source_failures);
            return Ok(HypothesisValidation {
                dataset_records: None,
                research_domain: Some(domain),
                id: Uuid::new_v4(),
                hypothesis_id: item.id,
                original_statement: item.draft.statement.clone(),
                created_at: Utc::now(),
                verdict: ValidationVerdict::NotAssessable,
                confidence: "The access limitation is documented; confidence in the scientific claim cannot be assessed.".to_string(),
                summary: "No readable article bodies were available within this search and retrieval budget. The hypothesis has not been disproved.".to_string(),
                criteria,
                claims: plan
                    .claims
                    .iter()
                    .map(|c| ClaimAssessment {
                        id: c.id.clone(),
                        statement: c.statement.clone(),
                        verdict: ValidationVerdict::NotAssessable,
                        rationale: "The necessary claim could not be appraised from accessible article bodies.".to_string(),
                        citations: Vec::new(),
                    })
                    .collect(),
                evidence: Vec::new(),
                can_conclude: "The bounded searches and source-access checks completed as recorded in the audit.".to_string(),
                cannot_conclude: "Whether the original hypothesis or any necessary claim is supported or contradicted.".to_string(),
                would_change_assessment: "Accessible, appropriately designed studies bearing on the prerecorded predictions, alternatives and weakening observations.".to_string(),
                next_test: plan
                    .claims
                    .iter()
                    .map(|c| format!("{}: {}", c.id, c.distinguishing_study))
                    .collect::<Vec<_>>()
                    .join("\n"),
                limitations: limits,
                papers: Vec::new(),
                audit,
                provider: provider.to_string(),
                model: model.to_string(),
                proposed_revision: None,
                supplied_citation_checks: Some(supplied_checks),
            });
        }

        let mut proposer_package = item.draft.clone();
        proposer_package.citations = proposer_package
            .citations
            .into_iter()
            .map(|c| EvidenceCitation::new(&c.paper_id, &c.passage_id, &c.quote, &c.interpretation))
            .collect();

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct AssessmentInput<'b> {
            original: Original<'b>,
            criteria: &'b ValidationPlan,
            proposer_package: HypothesisDraft,
            documents: &'b [EvidenceDocument],
            audit: &'b [String],
        }

        let input = AssessmentInput {
            original,
            criteria: &plan,
            proposer_package,
            documents: &documents,
            audit: &audit,
        };
        let input_json = serde_json::to_string(&input).unwrap_or_default();

        let mut assessment: RawAssessment = self
            .structured(
                "Evidence assessment",
                &domain.instructions(VALIDATION_ASSESSMENT_INSTRUCTIONS),
                &format!("UNTRUSTED RESEARCH PACKAGE (JSON):\n{input_json}{dataset_note}"),
                |raw| Self::validate_assessment(raw, &plan, &documents),
            )
            .await?;

        let mut safeguards = Vec::new();
        if assessment.verdict.is_supported() {
            if documents.len() < 2 {
                safeguards.push("Fewer than two distinct article bodies were accessible.".to_string());
            }
            if !assessment
                .claims
                .iter()
                .all(|c| c.verdict.is_supported() && !c.citations.is_empty())
            {
                safeguards.push(
                    "At least one necessary claim lacks a positive, cited assessment.".to_string(),
                );
            }
            let cited_paper_ids: HashSet<&str> = assessment
                .claims
                .iter()
                .flat_map(|c| &c.citations)
                .map(|cit| cit.paper_id.as_str())
                .collect();
            if cited_paper_ids.len() < 2 {
                safeguards.push(
                    "The necessary claims do not cite two distinct accessible article bodies."
                        .to_string(),
                );
            }
            if !incomplete_lenses.is_empty() {
                safeguards.push(
                    "At least one mandatory search lens could not be completed.".to_string(),
                );
            }
            if !safeguards.is_empty() {
                assessment.verdict = ValidationVerdict::Unresolved;
                assessment.summary = format!(
                    "Overall assessment remains unresolved. {} Model's bounded assessment: {}",
                    safeguards.join(" "),
                    assessment.summary
                );
                assessment.can_conclude = "Only the claim-level observations below can be considered within their stated limits. Overall support for the original hypothesis has not been established.".to_string();
                assessment.cannot_conclude = format!(
                    "That the original hypothesis is validated or that every essential link is supported. {}",
                    assessment.cannot_conclude
                );
                audit.push(format!(
                    "Automatic evidence gate withheld a positive overall verdict: {}",
                    safeguards.join(" ")
                ));
            }
        }

        if assessment.verdict == ValidationVerdict::StronglySupported
            && assessment
                .claims
                .iter()
                .any(|c| c.verdict == ValidationVerdict::ProvisionallySupported)
        {
            assessment.verdict = ValidationVerdict::ProvisionallySupported;
            assessment.summary = format!(
                "Overall support is provisional because at least one necessary claim remains provisional. {}",
                assessment.summary
            );
            audit.push(
                "Overall strong-support label reduced to provisional to match the weakest necessary claim."
                    .to_string(),
            );
        }

        let revision = assessment.proposed_revision.map(|rev| HypothesisDraft {
            title: format!("{} — proposed revision v2", item.draft.title),
            statement: rev.statement,
            r#type: plan.hypothesis_type.clone(),
            scope: "Separate proposed revision; scope must be independently assessed.".to_string(),
            rationale: rev.explanation,
            necessary_claims: Vec::new(),
            predictions: Vec::new(),
            falsification_criteria: Vec::new(),
            alternatives: Vec::new(),
            next_test: rev.next_test,
            novelty: "Not assessed".to_string(),
            support: "Not separately assessed; requires its own validation.".to_string(),
            importance: "Not assessed".to_string(),
            originality: "Not assessed".to_string(),
            feasibility: "Not assessed".to_string(),
            citations: assessment
                .claims
                .iter()
                .flat_map(|c| c.citations.clone())
                .collect(),
        });

        let mut all_limits = assessment.limitations;
        all_limits.extend(common_limits);
        all_limits.extend(safeguards);

        Ok(HypothesisValidation {
            dataset_records: None,
            research_domain: Some(domain),
            id: Uuid::new_v4(),
            hypothesis_id: item.id,
            original_statement: item.draft.statement.clone(),
            created_at: Utc::now(),
            verdict: assessment.verdict,
            confidence: assessment.confidence,
            summary: assessment.summary,
            criteria,
            claims: assessment.claims,
            evidence: assessment.evidence,
            can_conclude: assessment.can_conclude,
            cannot_conclude: assessment.cannot_conclude,
            would_change_assessment: assessment.would_change_assessment,
            next_test: assessment.next_test,
            limitations: all_limits,
            papers: bodies,
            audit,
            provider: provider.to_string(),
            model: model.to_string(),
            proposed_revision: revision,
            supplied_citation_checks: Some(supplied_checks),
        })
    }

    async fn structured<T: DeserializeOwned>(
        &self,
        label: &str,
        system: &str,
        prompt: &str,
        validate: impl Fn(T) -> Result<T, ResearchError>,
    ) -> Result<T, ResearchError> {
        let mut feedback = String::new();
        for attempt in 0..2 {
            (self.progress)(if attempt == 0 {
                format!("{label}: asking the model")
            } else {
                format!("{label}: asking the model to repair its output")
            });
            let response = (self.generate)(system.to_string(), format!("{prompt}{feedback}")).await?;
            let decoded: Result<T, ResearchError> =
                EvidenceValidator::decode_json(&response).and_then(&validate);
            match decoded {
                Ok(val) => return Ok(val),
                Err(ResearchError::InvalidResponse(msg)) if attempt == 0 => {
                    feedback = format!(
                        "\n\nSTRUCTURE/CITATION REPAIR: The previous response was rejected: {msg}. Return a corrected complete JSON object with the required schema and only exact citations from the supplied excerpts. Do not add prose outside JSON."
                    );
                }
                Err(err) => return Err(err),
            }
        }
        Err(ResearchError::InvalidResponse(
            "The validation response could not be read after one repair attempt.".to_string(),
        ))
    }

    fn validate_plan(plan: ValidationPlan) -> Result<ValidationPlan, ResearchError> {
        let ids: HashSet<String> = plan.claims.iter().map(|c| c.id.clone()).collect();
        let lenses: HashSet<SearchLens> = plan.searches.iter().map(|s| s.lens).collect();
        let valid = nonblank(&plan.exact_scope)
            && nonblank(&plan.working_interpretation)
            && nonblank(&plan.hypothesis_type)
            && (1..=6).contains(&plan.claims.len())
            && ids.len() == plan.claims.len()
            && plan.claims.iter().all(|c| {
                c.essential
                    && nonblank(&c.id)
                    && nonblank(&c.statement)
                    && nonblank(&c.predicted_observation)
                    && nonblank(&c.weakening_observation)
                    && nonblank(&c.distinguishing_study)
                    && nonblank(&c.meaningful_effect)
                    && !c.alternatives.is_empty()
                    && c.alternatives.iter().all(|a| nonblank(a))
            })
            && plan.searches.len() == SearchLens::ALL.len()
            && lenses.len() == SearchLens::ALL.len()
            && plan.searches.iter().all(|s| {
                valid_simple_query(&s.query)
                    && valid_simple_query(&s.broader_query)
                    && !s.query.eq_ignore_ascii_case(&s.broader_query)
                    && !s.claim_ids.is_empty()
                    && s.claim_ids.iter().all(|cid| ids.contains(cid))
            });
        if !valid {
            return Err(ResearchError::InvalidResponse(
                "The independent validation plan must define one to six uniquely identified necessary claims, predictions, falsifiers, alternatives, and all four distinct search lenses with broader fallback queries.".to_string(),
            ));
        }
        Ok(plan)
    }

    fn validate_assessment(
        mut assessment: RawAssessment,
        plan: &ValidationPlan,
        documents: &[EvidenceDocument],
    ) -> Result<RawAssessment, ResearchError> {
        let claim_ids: HashSet<String> = plan.claims.iter().map(|c| c.id.clone()).collect();
        let paper_ids: HashSet<String> = documents.iter().map(|d| d.paper_id.clone()).collect();
        let assessment_claim_ids: HashSet<String> =
            assessment.claims.iter().map(|c| c.id.clone()).collect();
        let evidence_paper_ids: HashSet<String> =
            assessment.evidence.iter().map(|e| e.paper_id.clone()).collect();

        let basic_ok = [
            &assessment.confidence,
            &assessment.summary,
            &assessment.can_conclude,
            &assessment.cannot_conclude,
            &assessment.would_change_assessment,
            &assessment.next_test,
        ]
        .iter()
        .all(|s| nonblank(s))
            && !assessment.limitations.is_empty()
            && assessment.limitations.iter().all(|l| nonblank(l))
            && assessment.claims.len() == plan.claims.len()
            && assessment_claim_ids == claim_ids
            && assessment.claims.iter().all(|claim| {
                plan.claims
                    .iter()
                    .find(|pc| pc.id == claim.id)
                    .is_some_and(|pc| pc.statement == claim.statement)
                    && nonblank(&claim.rationale)
            })
            && evidence_paper_ids.len() == assessment.evidence.len()
            && assessment.evidence.iter().all(|rec| {
                paper_ids.contains(&rec.paper_id)
                    && !rec.claim_ids.is_empty()
                    && rec.claim_ids.iter().all(|cid| claim_ids.contains(cid))
                    && [
                        &rec.stance,
                        &rec.design,
                        &rec.population,
                        &rec.sample_size,
                        &rec.exposure_comparator_outcome,
                        &rec.follow_up,
                        &rec.effect,
                        &rec.uncertainty,
                        &rec.analysis_status,
                        &rec.cohort_overlap,
                    ]
                    .iter()
                    .all(|s| nonblank(s))
                    && !rec.limitations.is_empty()
                    && rec.limitations.iter().all(|l| nonblank(l))
            });

        if !basic_ok {
            return Err(ResearchError::InvalidResponse(
                "The assessment must preserve every planned claim verbatim, use known claim and paper IDs, provide complete conclusion boundaries and next steps, and include a complete study ledger with unknown details explicitly marked unknown.".to_string(),
            ));
        }

        let citation_failure = "An assessment citation is not an exact quote of at least 20 characters from the supplied body passage, or its source is missing from the corresponding claim's evidence ledger.";
        for claim in &mut assessment.claims {
            if (claim.verdict.is_supported()
                || claim.verdict == ValidationVerdict::Weakened
                || claim.verdict == ValidationVerdict::Contradicted)
                && claim.citations.is_empty()
            {
                return Err(ResearchError::InvalidResponse(
                    "A supporting, weakened or contradicted claim verdict must cite its actual body evidence; absence of retrieved evidence is not counterevidence.".to_string(),
                ));
            }
            if !claim.citations.iter().all(|cit| {
                assessment.evidence.iter().any(|ev| {
                    ev.paper_id == cit.paper_id && ev.claim_ids.contains(&claim.id)
                })
            }) {
                return Err(ResearchError::InvalidResponse(citation_failure.to_string()));
            }
            claim.citations = EvidenceValidator::require_verified(
                &claim.citations,
                documents,
                citation_failure,
            )?;
        }

        if assessment.verdict == ValidationVerdict::Contradicted
            && !assessment
                .claims
                .iter()
                .any(|c| c.verdict == ValidationVerdict::Contradicted)
        {
            return Err(ResearchError::InvalidResponse(
                "An overall contradicted verdict requires a cited contradicted necessary claim; an unavailable or unresolved link is not contradiction.".to_string(),
            ));
        }
        if assessment.verdict == ValidationVerdict::Weakened
            && !assessment.claims.iter().any(|c| {
                c.verdict == ValidationVerdict::Weakened
                    || c.verdict == ValidationVerdict::Contradicted
            })
        {
            return Err(ResearchError::InvalidResponse(
                "An overall weakened verdict requires a cited weakened or contradicted necessary claim; missing evidence alone is not weakening evidence.".to_string(),
            ));
        }
        if let Some(ref rev) = assessment.proposed_revision {
            if !nonblank(&rev.statement) || !nonblank(&rev.explanation) || !nonblank(&rev.next_test)
            {
                return Err(ResearchError::InvalidResponse(
                    "A proposed revision must contain a separate statement, explanation of the change, and next-test plan; otherwise use null.".to_string(),
                ));
            }
        }
        Ok(assessment)
    }

    fn check_supplied_citations(
        citations: &[EvidenceCitation],
        papers: &[Paper],
    ) -> (Vec<EvidenceCitation>, Vec<String>, Vec<String>) {
        let sources = EvidenceValidator::verification_documents(papers, true);
        let checked: Vec<EvidenceCitation> = citations
            .iter()
            .map(|c| EvidenceValidator::verify(c, &sources, Utc::now()))
            .collect();
        let audit: Vec<String> = checked
            .iter()
            .map(|cit| {
                let label = format!("Supplied citation {}/{}", cit.paper_id, cit.passage_id);
                if cit.is_verified() {
                    format!("{label}: exact quoted text located in the retrieved body.")
                } else {
                    format!("{label}: {}", cit.verification_label())
                }
            })
            .collect();
        let has_unverified = checked.iter().any(|c| !c.is_verified());
        let limitations = if has_unverified {
            vec![format!(
                "Proposer citations checked against retrieved article bodies: {}. Unverified quotes and their interpretations were not confirmed.",
                EvidenceValidator::verification_summary(&checked)
            )]
        } else {
            Vec::new()
        };
        (checked, audit, limitations)
    }

    fn interleave(groups: &[Vec<Paper>]) -> Vec<Paper> {
        let mut out = Vec::new();
        let max_len = groups.iter().map(Vec::len).max().unwrap_or(0);
        for idx in 0..max_len {
            for g in groups {
                if let Some(p) = g.get(idx) {
                    out.push(p.clone());
                }
            }
        }
        PaperDeduplicator::deduplicate(&out)
    }
}

pub struct HypothesisConnectionAgent<'a> {
    pub generate: GenerateFn<'a>,
    pub search: SearchFn<'a>,
    pub retrieve: RetrieveFn<'a>,
    pub progress: ProgressFn<'a>,
    pub access: InstitutionalAccess,
}

impl<'a> HypothesisConnectionAgent<'a> {
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        &self,
        items: &[QueuedHypothesis],
        validations: &[HypothesisValidation],
        recent_papers: &[Paper],
        provider: &str,
        model: &str,
        review_offset: usize,
        domain: ResearchDomain,
        dataset_context: &str,
    ) -> Result<ConnectionReview, ResearchError> {
        let domain_items: Vec<QueuedHypothesis> = items
            .iter()
            .filter(|i| i.domain() == domain)
            .cloned()
            .collect();
        let item_ids: HashSet<Uuid> = domain_items.iter().map(|i| i.id).collect();
        let domain_validations: Vec<HypothesisValidation> = validations
            .iter()
            .filter(|v| v.domain() == domain && item_ids.contains(&v.hypothesis_id))
            .cloned()
            .collect();

        let mut latest: HashMap<Uuid, HypothesisValidation> = HashMap::new();
        for v in &domain_validations {
            if latest
                .get(&v.hypothesis_id)
                .is_none_or(|prev| prev.created_at <= v.created_at)
            {
                latest.insert(v.hypothesis_id, v.clone());
            }
        }

        let mut assessed: Vec<QueuedHypothesis> = domain_items
            .iter()
            .filter(|i| latest.contains_key(&i.id))
            .cloned()
            .collect();
        assessed.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
        });

        let positive = Self::rotated(
            &assessed
                .iter()
                .filter(|i| latest[&i.id].verdict.is_supported())
                .cloned()
                .collect::<Vec<_>>(),
            review_offset,
        );
        let other = Self::rotated(
            &assessed
                .iter()
                .filter(|i| !latest[&i.id].verdict.is_supported())
                .cloned()
                .collect::<Vec<_>>(),
            review_offset,
        );

        let mut audit = vec![
            format!(
                "Research domain: {}. Only hypotheses and assessments from this domain are compared; public dataset metadata cannot validate a hypothesis or count as new body evidence.",
                domain.display_name()
            ),
            format!(
                "Connection review on {}: narrative evidence review only; no statistical correlation calculation, empirical test, or upgrade of an existing verdict was performed.",
                Utc::now().to_rfc3339()
            ),
        ];

        if positive.len() < 2 && other.is_empty() {
            audit.push("No eligible connection: fewer than two positively assessed parents and no negative/inconclusive assessment to revisit.".to_string());
            return Ok(ConnectionReview {
                dataset_records: None,
                research_domain: Some(domain),
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                proposals: Vec::new(),
                papers: Vec::new(),
                audit,
                provider: provider.to_string(),
                model: model.to_string(),
            });
        }

        let mut balanced = Vec::new();
        for idx in 0..20.min(positive.len().max(other.len())) {
            if let Some(p) = positive.get(idx) {
                balanced.push(p.clone());
            }
            if let Some(o) = other.get(idx) {
                balanced.push(o.clone());
            }
        }

        let known: HashMap<Uuid, QueuedHypothesis> =
            balanced.iter().map(|i| (i.id, i.clone())).collect();
        let dataset_note = if dataset_context.is_empty() {
            String::new()
        } else {
            let truncated: String = dataset_context.chars().take(20_000).collect();
            format!(
                "\nUNTRUSTED PUBLIC DATASET METADATA (planning context only; no data analysis, independent replication or article-body evidence established):\n{truncated}"
            )
        };

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ParentSummary {
            id: Uuid,
            statement: String,
            verdict: ValidationVerdict,
            summary: String,
        }
        let roster: Vec<ParentSummary> = balanced
            .iter()
            .map(|i| ParentSummary {
                id: i.id,
                statement: i.draft.statement.chars().take(2_000).collect(),
                verdict: latest[&i.id].verdict,
                summary: latest[&i.id].summary.chars().take(800).collect(),
            })
            .collect();
        let roster_json = serde_json::to_string(&roster).unwrap_or_default();

        #[derive(Serialize, Deserialize, Clone)]
        #[serde(rename_all = "camelCase")]
        struct ConnectionPlan {
            #[serde(rename = "parentIDs")]
            parent_ids: Vec<Uuid>,
            reason: String,
            queries: Vec<String>,
        }
        #[derive(Deserialize)]
        struct PlanEnvelope {
            plans: Vec<ConnectionPlan>,
        }

        let plans: Vec<ConnectionPlan> = self
            .corrected(
                "connection planning",
                &domain.instructions(CONNECTION_PLANNING_INSTRUCTIONS),
                &format!("UNTRUSTED ASSESSED IDEAS:\n{roster_json}{dataset_note}"),
                &mut audit,
                |raw| {
                    let env: PlanEnvelope = EvidenceValidator::decode_json(raw)?;
                    if env.plans.len() > 3 {
                        return Err(ResearchError::InvalidResponse(
                            "At most three connection plans are permitted.".to_string(),
                        ));
                    }
                    for plan in &env.plans {
                        let ids: HashSet<Uuid> = plan.parent_ids.iter().copied().collect();
                        if ids.is_empty()
                            || ids.len() != plan.parent_ids.len()
                            || !ids.iter().all(|id| known.contains_key(id))
                            || EvidenceValidator::normalize(&plan.reason).chars().count() < 20
                            || !(1..=2).contains(&plan.queries.len())
                            || !plan.queries.iter().all(|q| balanced_query(q))
                        {
                            return Err(ResearchError::InvalidResponse(
                                "A connection plan needs known distinct parents, a specific reason, and one or two well-formed searches.".to_string(),
                            ));
                        }
                        let supported_count = plan
                            .parent_ids
                            .iter()
                            .filter(|id| latest[id].verdict.is_supported())
                            .count();
                        if supported_count < 2
                            && !plan
                                .parent_ids
                                .iter()
                                .any(|id| !latest[id].verdict.is_supported())
                        {
                            return Err(ResearchError::InvalidResponse(
                                "A connection requires two positive assessments or a negative/inconclusive assessment to investigate.".to_string(),
                            ));
                        }
                    }
                    Ok(env.plans)
                },
            )
            .await?;

        if plans.is_empty() {
            audit.push("The comparison identified no specific worthwhile bridge or reconsideration question. No proposals were fabricated.".to_string());
            return Ok(ConnectionReview {
                dataset_records: None,
                research_domain: Some(domain),
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                proposals: Vec::new(),
                papers: Vec::new(),
                audit,
                provider: provider.to_string(),
                model: model.to_string(),
            });
        }

        let max_records = FreeLiteratureSearchClient::maximum_records(domain);
        let mut groups: Vec<Vec<Paper>> = Vec::new();
        let mut successful_searches = 0usize;
        for plan in &plans {
            for q in &plan.queries {
                let scoped = format!("({}) AND ({q})", domain.query());
                if let Ok(found) = (self.search)(scoped).await {
                    successful_searches += 1;
                    groups.push(found.papers.into_iter().take(max_records).collect());
                }
            }
        }
        if successful_searches == 0 {
            return Err(ResearchError::Unavailable(
                "All connection evidence searches failed; retain this review for retry."
                    .to_string(),
            ));
        }

        groups.push(recent_papers.iter().rev().take(40).rev().cloned().collect());
        let mut interleaved = Vec::new();
        let max_len = groups.iter().map(Vec::len).max().unwrap_or(0);
        for idx in 0..max_len {
            for g in &groups {
                if let Some(p) = g.get(idx) {
                    interleaved.push(p.clone());
                }
            }
        }
        let candidates: Vec<Paper> = PaperDeduplicator::deduplicate(&interleaved)
            .into_iter()
            .filter(|p| !p.is_retracted() && !p.is_conference_abstract())
            .collect();

        let mut bodies: Vec<Paper> = Vec::new();
        let mut retrievals = 0usize;
        for mut paper in candidates {
            if bodies.len() >= 8 {
                break;
            }
            if EvidenceValidator::full_text_passages(&paper).is_empty() {
                if !paper.has_retrieval_route(&self.access) || retrievals >= 12 {
                    continue;
                }
                retrievals += 1;
                if let Ok(ft) = (self.retrieve)(paper.clone()).await {
                    paper.full_text = Some(ft);
                } else {
                    continue;
                }
            }
            if !EvidenceValidator::full_text_passages(&paper).is_empty() {
                bodies.push(paper);
            }
        }

        if bodies.len() < 2 {
            audit.push("No proposal: fewer than two distinct readable bodies were available in the bounded search.".to_string());
            return Ok(ConnectionReview {
                dataset_records: None,
                research_domain: Some(domain),
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                proposals: Vec::new(),
                papers: bodies,
                audit,
                provider: provider.to_string(),
                model: model.to_string(),
            });
        }

        let documents = EvidenceValidator::documents(&bodies, 6_000, true);
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct EvidencePlan {
            plan: ConnectionPlan,
            #[serde(rename = "eligibleNewEvidencePaperIDs")]
            eligible_new_evidence_paper_ids: Vec<String>,
        }

        let eligible_plans: Vec<EvidencePlan> = plans
            .into_iter()
            .map(|plan| {
                let reconsidered: Vec<Uuid> = plan
                    .parent_ids
                    .iter()
                    .copied()
                    .filter(|id| !latest[id].verdict.is_supported())
                    .collect();
                let prior_parent_ids: HashSet<Uuid> = if reconsidered.is_empty() {
                    plan.parent_ids.iter().copied().collect()
                } else {
                    reconsidered.into_iter().collect()
                };
                let inspected: Vec<Paper> = domain_validations
                    .iter()
                    .filter(|v| prior_parent_ids.contains(&v.hypothesis_id))
                    .flat_map(|v| v.papers.clone())
                    .collect();
                let new_ids: Vec<String> = bodies
                    .iter()
                    .filter(|b| Self::has_new_identity(b, &inspected))
                    .map(|b| b.id.clone())
                    .collect();
                EvidencePlan {
                    plan,
                    eligible_new_evidence_paper_ids: new_ids,
                }
            })
            .collect();

        #[derive(Deserialize)]
        struct ConnectionEnvelope {
            connections: Vec<LinkedHypothesis>,
        }

        let synthesis_prompt = format!(
            "UNTRUSTED PRIOR ASSESSMENTS:\n{roster_json}\nPLANS AND ELIGIBLE NEW BODY IDS:\n{}\nUNTRUSTED ARTICLE-BODY EVIDENCE:\n{}{dataset_note}",
            serde_json::to_string(&eligible_plans).unwrap_or_default(),
            serde_json::to_string(&documents).unwrap_or_default()
        );

        let proposals: Vec<LinkedHypothesis> = self
            .corrected(
                "connection synthesis",
                &domain.instructions(CONNECTION_SYNTHESIS_INSTRUCTIONS),
                &synthesis_prompt,
                &mut audit,
                |raw| {
                    let env: ConnectionEnvelope = EvidenceValidator::decode_json(raw)?;
                    if env.connections.len() > 3 {
                        return Err(ResearchError::InvalidResponse(
                            "At most three connection proposals are permitted.".to_string(),
                        ));
                    }
                    let mut out = Vec::new();
                    for mut conn in env.connections {
                        let ids: HashSet<Uuid> = conn.parent_ids.iter().copied().collect();
                        let Some(ep) = eligible_plans.iter().find(|p| {
                            p.plan.parent_ids.iter().copied().collect::<HashSet<_>>() == ids
                        }) else {
                            return Err(ResearchError::InvalidResponse(
                                "A proposed connection used unknown or unplanned parents."
                                    .to_string(),
                            ));
                        };
                        conn.draft =
                            EvidenceValidator::validate_discovery_draft(conn.draft, &documents)?;
                        let new_ids: HashSet<String> =
                            conn.new_evidence_paper_ids.iter().cloned().collect();
                        let cited_ids: HashSet<String> =
                            conn.draft.citations.iter().map(|c| c.paper_id.clone()).collect();
                        let eligible_set: HashSet<String> = ep
                            .eligible_new_evidence_paper_ids
                            .iter()
                            .cloned()
                            .collect();
                        if !new_ids.is_subset(&eligible_set) || !new_ids.is_subset(&cited_ids) {
                            return Err(ResearchError::InvalidResponse(
                                "New evidence must be a supplied, cited readable body absent from the earlier reconsidered assessments.".to_string(),
                            ));
                        }
                        if conn
                            .parent_ids
                            .iter()
                            .any(|id| !latest[id].verdict.is_supported())
                            && new_ids.is_empty()
                        {
                            return Err(ResearchError::InvalidResponse(
                                "Reconsidering a negative or inconclusive assessment requires at least one actual new cited body.".to_string(),
                            ));
                        }
                        out.push(conn);
                    }
                    Ok(out)
                },
            )
            .await?;

        Ok(ConnectionReview {
            dataset_records: None,
            research_domain: Some(domain),
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            proposals,
            papers: bodies,
            audit,
            provider: provider.to_string(),
            model: model.to_string(),
        })
    }

    async fn corrected<T>(
        &self,
        stage: &str,
        system: &str,
        prompt: &str,
        audit: &mut Vec<String>,
        decode: impl Fn(&str) -> Result<T, ResearchError>,
    ) -> Result<T, ResearchError> {
        let mut repair: Option<String> = None;
        for attempt in 0..2 {
            let full_prompt = match repair {
                Some(ref r) => format!(
                    "{prompt}\nCORRECTION REQUIRED: {r}\nReturn the complete corrected JSON only, with no invented evidence."
                ),
                None => prompt.to_string(),
            };
            (self.progress)(if attempt == 0 {
                format!("{stage}: asking the model")
            } else {
                format!("{stage}: asking the model to repair its output")
            });
            let response = (self.generate)(system.to_string(), full_prompt).await?;
            match decode(&response) {
                Ok(val) => return Ok(val),
                Err(e) if attempt == 0 => {
                    audit.push(format!(
                        "One structured-output correction requested for {stage}: {e}"
                    ));
                    repair = Some(e.to_string());
                }
                Err(e) => return Err(e),
            }
        }
        Err(ResearchError::InvalidResponse(
            "The connection worker could not decode a corrected response.".to_string(),
        ))
    }

    fn rotated<T: Clone>(values: &[T], offset: usize) -> Vec<T> {
        if values.is_empty() {
            return Vec::new();
        }
        let start = offset % values.len();
        let mut out = values[start..].to_vec();
        out.extend_from_slice(&values[..start]);
        out
    }

    fn aliases(paper: &Paper) -> HashSet<String> {
        let mut out = HashSet::new();
        out.insert(format!("id:{}", paper.id));
        if let Some(doi) = normalize_doi(paper.doi.as_deref()) {
            out.insert(format!("doi:{doi}"));
        }
        if let Some(ref pmid) = paper.pmid {
            if !pmid.trim().is_empty() {
                out.insert(format!("pmid:{}", pmid.trim()));
            }
        }
        if let Some(ref pmcid) = paper.pmcid {
            if !pmcid.trim().is_empty() {
                out.insert(format!("pmcid:{}", pmcid.trim().to_uppercase()));
            }
        }
        out
    }

    fn has_new_identity(paper: &Paper, prior: &[Paper]) -> bool {
        let candidate_aliases = Self::aliases(paper);
        let prior_aliases: HashSet<String> = prior.iter().flat_map(Self::aliases).collect();
        candidate_aliases.is_disjoint(&prior_aliases)
    }
}

fn nonblank(value: &str) -> bool {
    !EvidenceValidator::normalize(value).is_empty()
}

fn valid_simple_query(value: &str) -> bool {
    let lower = value.to_lowercase();
    nonblank(value)
        && value.chars().count() <= 300
        && !value.contains('\n')
        && !lower.contains("http:")
        && !lower.contains("https:")
}

fn balanced_query(query: &str) -> bool {
    if EvidenceValidator::normalize(query).is_empty() || query.chars().count() > 350 {
        return false;
    }
    let mut depth = 0i32;
    let mut quoted = false;
    let mut escaped = false;
    for ch in query.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            continue;
        }
        if !quoted {
            if ch == '(' {
                depth += 1;
            } else if ch == ')' {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
        }
    }
    depth == 0 && !quoted && !escaped
}

const DISCOVERY_PLANNING_INSTRUCTIONS: &str = r#"You are the discovery planner for an autonomous dementia research cycle. Choose the research areas yourself when no objective is supplied.
Return ONLY JSON {"queries":["...","...","..."]}. Provide three complementary Europe PMC queries of at most 350 characters. Use simple terms, quoted phrases, TITLE_ABS fields and balanced Boolean parentheses."#;

const DISCOVERY_LANDSCAPE_INSTRUCTIONS: &str = r#"Map the research opportunities present in the supplied survey records. Return ONLY JSON:
{"directions":[{"title":"...","question":"...","known":"...","gap":"...","importance":"...","selectionReason":"...","selected":true,"paperIDs":["knownID"]}],"investigations":[{"directionIndex":0,"queries":["primary query","novelty query","contradiction query"]}],"summary":"..."}
Provide 1 to 6 directions and select at most 3 for focused investigation."#;

const DISCOVERY_DRAFTING_INSTRUCTIONS: &str = r#"Formulate at most one specific, falsifiable dementia research hypothesis grounded in the supplied article-body excerpts. Return ONLY JSON:
{"hypotheses":[{"title":"...","statement":"...","type":"...","scope":"...","rationale":"...","necessaryClaims":["..."],"predictions":["...","..."],"falsificationCriteria":["..."],"alternatives":["..."],"nextTest":"...","novelty":"...","support":"...","importance":"...","originality":"...","feasibility":"...","citations":[{"paperID":"knownID","passageID":"knownPassageID","quote":"EXACT contiguous excerpt of at least 20 characters","interpretation":"..."}]}],"reason":"..."}
Require exact quotes from at least two distinct retrieved article bodies and at least two distinct predictions."#;

const VALIDATION_PLANNING_INSTRUCTIONS: &str = r#"You are an independent dementia research validation agent. Define evaluation criteria BEFORE seeing the proposing agent's rationale or bibliography.
Return ONLY JSON with this schema:
{"exactScope":"...","workingInterpretation":"...","hypothesisType":"...","claims":[{"id":"c1","statement":"...","essential":true,"predictedObservation":"...","weakeningObservation":"...","alternatives":["..."],"distinguishingStudy":"...","meaningfulEffect":"..."}],"searches":[{"lens":"support","query":"...","broaderQuery":"...","claimIDs":["c1"]},{"lens":"contradiction","query":"...","broaderQuery":"...","claimIDs":["c1"]},{"lens":"alternatives","query":"...","broaderQuery":"...","claimIDs":["c1"]},{"lens":"weakestClaim","query":"...","broaderQuery":"...","claimIDs":["c1"]}]}"#;

const VALIDATION_ASSESSMENT_INSTRUCTIONS: &str = r#"You are an independent dementia research validation agent. Assess the EXACT ORIGINAL statement against criteria formed before the proposer package was supplied.
Use only these verdict strings: stronglySupported, provisionallySupported, unresolved, weakened, contradicted, notAssessable. Return ONLY one JSON object:
{"verdict":"unresolved","confidence":"...","summary":"...","claims":[{"id":"c1","statement":"VERBATIM planned claim","verdict":"unresolved","rationale":"...","citations":[{"paperID":"known ID","passageID":"known passage ID","quote":"EXACT contiguous excerpt of at least 20 characters","interpretation":"..."}]}],"evidence":[{"paperID":"known ID","claimIDs":["c1"],"stance":"...","design":"...","population":"...","sampleSize":"...","exposureComparatorOutcome":"...","followUp":"...","effect":"...","uncertainty":"...","analysisStatus":"...","cohortOverlap":"...","limitations":["..."]}],"canConclude":"...","cannotConclude":"...","wouldChangeAssessment":"...","nextTest":"...","limitations":["..."],"proposedRevision":null}"#;

const CONNECTION_PLANNING_INSTRUCTIONS: &str = r#"Compare the supplied assessed dementia hypotheses and identify at most three worthwhile bridges or evidence-backed reconsiderations. Return ONLY JSON:
{"plans":[{"parentIDs":["uuid1","uuid2"],"reason":"specific mechanism or contradiction worth checking","queries":["query1","query2"]}]}"#;

const CONNECTION_SYNTHESIS_INSTRUCTIONS: &str = r#"Draft separate, testable connection or reconsideration hypotheses grounded in the supplied article-body excerpts. Return ONLY JSON:
{"connections":[{"draft":{"title":"...","statement":"...","type":"...","scope":"...","rationale":"...","necessaryClaims":["..."],"predictions":["...","..."],"falsificationCriteria":["..."],"alternatives":["..."],"nextTest":"...","novelty":"...","support":"...","importance":"...","originality":"...","feasibility":"...","citations":[{"paperID":"knownID","passageID":"knownPassageID","quote":"EXACT contiguous excerpt of at least 20 characters","interpretation":"..."}]},"parentIDs":["uuid1"],"reason":"...","newEvidencePaperIDs":["knownID"]}]}"#;
