use crate::models::{
    ConnectionReview, DiscoveryCycle, EvidenceCitation, HypothesisDraft, HypothesisValidation,
    LibrarySnapshot, Paper, QueuedHypothesis, ResearchDatasetRecord, ResearchDomain,
};
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use url::Url;

const SCOPE_DISCLAIMER: &str = "Exploratory research record. Literature support is not experimental validation, a statistical correlation or a patient-specific treatment recommendation.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResearchReportBlock {
    Heading(String, usize),
    Paragraph(String),
    Bullet(String),
    Quote(String),
    Link { label: String, url: Url },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResearchReport {
    pub title: String,
    pub subtitle: String,
    pub blocks: Vec<ResearchReportBlock>,
}

impl ResearchReport {
    pub fn new(title: impl Into<String>, subtitle: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            subtitle: subtitle.into(),
            blocks: Vec::new(),
        }
    }

    pub fn heading(&mut self, text: impl Into<String>, level: usize) {
        self.blocks
            .push(ResearchReportBlock::Heading(text.into(), level));
    }

    pub fn field(&mut self, label: &str, value: &str) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            self.blocks
                .push(ResearchReportBlock::Bullet(format!("{label}: {trimmed}")));
        }
    }

    pub fn section(&mut self, heading: &str, body: &str) {
        let trimmed = body.trim();
        if !trimmed.is_empty() {
            self.heading(heading, 2);
            self.blocks
                .push(ResearchReportBlock::Paragraph(trimmed.to_string()));
        }
    }

    pub fn list(&mut self, heading: &str, items: &[String]) {
        let non_empty: Vec<&str> = items
            .iter()
            .map(String::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if !non_empty.is_empty() {
            self.heading(heading, 2);
            for item in non_empty {
                self.blocks
                    .push(ResearchReportBlock::Bullet(item.to_string()));
            }
        }
    }

    pub fn metadata(&mut self, created: DateTime<Utc>, provider: &str, model: &str) {
        self.field("Created", &created.to_rfc3339());
        self.field("Provider", provider);
        self.field("Model", model);
    }

    pub fn plain_text(&self) -> String {
        let mut parts = vec![self.title.clone(), self.subtitle.clone()];
        for b in &self.blocks {
            match b {
                ResearchReportBlock::Heading(t, _)
                | ResearchReportBlock::Paragraph(t)
                | ResearchReportBlock::Quote(t) => parts.push(t.clone()),
                ResearchReportBlock::Bullet(t) => parts.push(format!("• {t}")),
                ResearchReportBlock::Link { label, url } => parts.push(format!("{label}\n{url}")),
            }
        }
        format!(
            "{}\n",
            parts
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("\n\n")
        )
    }

    pub fn markdown(&self) -> String {
        let mut parts = vec![format!("# {}", self.title), self.subtitle.clone()];
        for b in &self.blocks {
            match b {
                ResearchReportBlock::Heading(t, level) => {
                    let hashes = "#".repeat((*level + 1).clamp(2, 6));
                    parts.push(format!("{hashes} {t}"));
                }
                ResearchReportBlock::Paragraph(t) => parts.push(t.clone()),
                ResearchReportBlock::Bullet(t) => {
                    parts.push(format!("- {}", t.replace('\n', "\n  ")));
                }
                ResearchReportBlock::Quote(t) => {
                    parts.push(format!("> {}", t.replace('\n', "\n> ")));
                }
                ResearchReportBlock::Link { label, url } => {
                    let safe_label = label.replace('[', "\\[").replace(']', "\\]");
                    parts.push(format!("[{safe_label}](<{url}>)"));
                }
            }
        }
        format!(
            "{}\n",
            parts
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("\n\n")
        )
    }
}

pub struct ResearchReportBuilder;

impl ResearchReportBuilder {
    pub fn hypothesis(item: &QueuedHypothesis, papers: &[Paper]) -> ResearchReport {
        let mut report = ResearchReport::new(
            &item.draft.title,
            format!(
                "{} hypothesis · {}",
                item.domain().display_name(),
                item.origin.as_str()
            ),
        );
        report.field("Hypothesis ID", &item.id.to_string());
        report.field("Created", &item.created_at.to_rfc3339());
        report.field("Generation", &item.generation.to_string());
        report.field("Validation attempts", &item.attempts.to_string());
        if let Some(vid) = item.validation_id {
            report.field("Latest assessment ID", &vid.to_string());
        }
        if let Some(ref err) = item.last_error {
            report.field("Last issue", err);
        }
        report
            .blocks
            .push(ResearchReportBlock::Paragraph(SCOPE_DISCLAIMER.to_string()));
        Self::append_draft(&item.draft, papers, &mut report);
        report.list("Source paper identifiers", &item.source_paper_ids);
        let ids: HashSet<String> = item
            .source_paper_ids
            .iter()
            .cloned()
            .chain(item.draft.citations.iter().map(|c| c.paper_id.clone()))
            .collect();
        let relevant_papers: Vec<Paper> = papers
            .iter()
            .filter(|p| ids.contains(&p.id))
            .cloned()
            .collect();
        Self::append_papers(&relevant_papers, &mut report);
        report
    }

    pub fn validation(result: &HypothesisValidation) -> ResearchReport {
        let mut report = ResearchReport::new(
            "Hypothesis assessment",
            format!(
                "{} · {}",
                result.domain().display_name(),
                result.verdict.label()
            ),
        );
        report.field("Assessment ID", &result.id.to_string());
        report.field("Hypothesis ID", &result.hypothesis_id.to_string());
        report.metadata(result.created_at, &result.provider, &result.model);
        report
            .blocks
            .push(ResearchReportBlock::Paragraph(SCOPE_DISCLAIMER.to_string()));
        report.section("Exact original hypothesis", &result.original_statement);
        report.section("Overall verdict", result.verdict.label());
        report.section("Confidence", &result.confidence);
        report.section("Assessment summary", &result.summary);
        report.list("Independent evaluation criteria", &result.criteria);
        report.heading("Claim assessments", 1);
        for claim in &result.claims {
            report.heading(format!("Claim {}: {}", claim.id, claim.verdict.label()), 2);
            report
                .blocks
                .push(ResearchReportBlock::Paragraph(claim.statement.clone()));
            report
                .blocks
                .push(ResearchReportBlock::Paragraph(claim.rationale.clone()));
            Self::append_citations(&claim.citations, &result.papers, &mut report);
        }
        report.heading("Study evidence", 1);
        for study in &result.evidence {
            report.heading(&study.paper_id, 2);
            report.list("Claims addressed", &study.claim_ids);
            report.field("Stance", &study.stance);
            report.field("Study design", &study.design);
            report.field("Population", &study.population);
            report.field("Sample size", &study.sample_size);
            report.field(
                "Exposure, comparator and outcome",
                &study.exposure_comparator_outcome,
            );
            report.field("Follow-up", &study.follow_up);
            report.field("Effect", &study.effect);
            report.field("Uncertainty", &study.uncertainty);
            report.field("Analysis status", &study.analysis_status);
            report.field("Cohort overlap", &study.cohort_overlap);
            report.list("Study limitations", &study.limitations);
        }
        report.section("What can be concluded", &result.can_conclude);
        report.section("What cannot be concluded", &result.cannot_conclude);
        report.section(
            "What would change this assessment",
            &result.would_change_assessment,
        );
        report.section("Next test", &result.next_test);
        report.list("Limitations", &result.limitations);
        if let Some(ref rev) = result.proposed_revision {
            report.heading("Proposed revision — original assessment retained", 1);
            Self::append_draft(rev, &result.papers, &mut report);
        }
        report.heading("Supplied citation checks", 1);
        if let Some(ref checks) = result.supplied_citation_checks {
            Self::append_citations(checks, &result.papers, &mut report);
            if checks.is_empty() {
                report.blocks.push(ResearchReportBlock::Paragraph(
                    "No supplied citations were recorded for checking.".to_string(),
                ));
            }
        }
        Self::append_datasets(
            result.dataset_records.as_deref().unwrap_or(&[]),
            &mut report,
        );
        Self::append_papers(&result.papers, &mut report);
        report.list("Assessment audit", &result.audit);
        report
    }

    pub fn discovery(cycle: &DiscoveryCycle) -> ResearchReport {
        let mut report = ResearchReport::new(
            "Discovery cycle",
            format!("{} autonomous research", cycle.domain().display_name()),
        );
        report.field("Cycle ID", &cycle.id.to_string());
        report.metadata(cycle.created_at, &cycle.provider, &cycle.model);
        report
            .blocks
            .push(ResearchReportBlock::Paragraph(SCOPE_DISCLAIMER.to_string()));
        report.section("Research objective", &cycle.objective);
        report.heading("Research landscape", 1);
        for dir in &cycle.landscape {
            report.heading(&dir.title, 2);
            report.field(
                "Selected for investigation",
                if dir.selected { "Yes" } else { "No" },
            );
            report.field("Question", &dir.question);
            report.field("Known evidence", &dir.known);
            report.field("Unresolved gap", &dir.gap);
            report.field("Importance", &dir.importance);
            report.field("Selection rationale", &dir.selection_reason);
            report.list("Source paper identifiers", &dir.paper_ids);
        }
        report.heading("Generated hypotheses", 1);
        if cycle.hypotheses.is_empty() {
            report.blocks.push(ResearchReportBlock::Paragraph(
                "No hypotheses were proposed in this cycle.".to_string(),
            ));
        }
        for draft in &cycle.hypotheses {
            Self::append_draft(draft, &cycle.papers, &mut report);
        }
        Self::append_datasets(
            cycle.dataset_records.as_deref().unwrap_or(&[]),
            &mut report,
        );
        Self::append_papers(&cycle.papers, &mut report);
        report.list("Discovery audit", &cycle.audit);
        report
    }

    pub fn connection(review: &ConnectionReview) -> ResearchReport {
        let mut report = ResearchReport::new(
            "Connection and reconsideration review",
            format!("{} research", review.domain().display_name()),
        );
        report.field("Review ID", &review.id.to_string());
        report.metadata(review.created_at, &review.provider, &review.model);
        report
            .blocks
            .push(ResearchReportBlock::Paragraph(SCOPE_DISCLAIMER.to_string()));
        for proposal in &review.proposals {
            report.heading(&proposal.draft.title, 1);
            let parents: Vec<String> = proposal.parent_ids.iter().map(ToString::to_string).collect();
            report.list("Parent hypotheses", &parents);
            report.section("Reason for connection or reconsideration", &proposal.reason);
            report.list(
                "New evidence paper identifiers",
                &proposal.new_evidence_paper_ids,
            );
            Self::append_draft(&proposal.draft, &review.papers, &mut report);
        }
        Self::append_datasets(
            review.dataset_records.as_deref().unwrap_or(&[]),
            &mut report,
        );
        Self::append_papers(&review.papers, &mut report);
        report.list("Connection review audit", &review.audit);
        report
    }

    pub fn dataset(record: &ResearchDatasetRecord) -> ResearchReport {
        let mut report = ResearchReport::new(
            &record.title,
            format!("Public dataset resource · {}", record.provider),
        );
        report.field("Dataset identifier", &record.id);
        report.field("Retrieved", &record.retrieved_at.to_rfc3339());
        report.section("Resource description", &record.summary);
        report.list("Cancer types", &record.cancer_types);
        report.list("Data types", &record.data_types);
        if let Some(count) = record.sample_count {
            report.field("Reported cohort count", &count.to_string());
        }
        report.section("Access", &record.access);
        report.section("Reuse terms", &record.terms);
        report.section("Evidence boundary", &record.evidence_use);
        report.blocks.push(ResearchReportBlock::Link {
            label: "Dataset page".to_string(),
            url: record.source_url.clone(),
        });
        report
    }

    pub fn paper(paper: &Paper) -> ResearchReport {
        let mut report = ResearchReport::new(
            &paper.title,
            format!("Saved evidence · {}", paper.evidence_label()),
        );
        Self::append_paper(paper, &mut report);
        report.section(
            "Abstract",
            if paper.abstract_text.is_empty() {
                "No abstract was stored."
            } else {
                &paper.abstract_text
            },
        );
        if let Some(ref text) = paper.full_text {
            report.heading("Stored source passages", 1);
            if paper.is_body_redistribution_restricted() {
                report.blocks.push(ResearchReportBlock::Paragraph(format!(
                    "Article body passages ({}) were retrieved for local text mining and quote verification ({}; {}) and are omitted from exported reports because the source carries no open redistribution licence. Short verified quotations remain in hypothesis and validation sections.",
                    text.passages.len(),
                    text.format,
                    text.license.as_deref().unwrap_or("restricted terms")
                )));
            } else {
                report.blocks.push(ResearchReportBlock::Paragraph(
                    "These are stored source passages. Their inclusion does not establish that every passage was sent to an agent. Source reuse terms remain applicable.".to_string(),
                ));
                for passage in &text.passages {
                    report.heading(format!("{} · {}", passage.section, passage.id), 2);
                    report
                        .blocks
                        .push(ResearchReportBlock::Paragraph(passage.text.clone()));
                }
            }
        } else {
            report.blocks.push(ResearchReportBlock::Paragraph(
                "Article body was not stored; an abstract is not full-text evidence.".to_string(),
            ));
        }
        report
    }

    pub fn pipeline(library: &LibrarySnapshot) -> ResearchReport {
        let mut report = ResearchReport::new(
            "Research library",
            "All saved research fields · complete generated records",
        );
        report
            .blocks
            .push(ResearchReportBlock::Paragraph(SCOPE_DISCLAIMER.to_string()));
        report.field("Library schema", &library.schema_version.to_string());
        report.field(
            "Selected research field",
            library.pipeline.settings.domain().display_name(),
        );
        report.field(
            "Discovery interval (minutes)",
            &library.pipeline.settings.cycle_interval_minutes.to_string(),
        );
        report.field(
            "Daily attempted model request budget",
            &library.pipeline.settings.daily_model_budget.to_string(),
        );
        for domain in ResearchDomain::ALL {
            let state = library.pipeline.loop_state(domain);
            report.heading(format!("{} loop settings", domain.display_name()), 2);
            report.field(
                "Queue processing enabled",
                if state.processing_enabled { "Yes" } else { "No" },
            );
            report.field(
                "Autonomous discovery enabled",
                if state.autonomous_enabled { "Yes" } else { "No" },
            );
            report.list(
                &format!("Queued {} objectives", domain.display_name()),
                &library.pipeline.objectives(domain),
            );
        }
        for item in &library.pipeline.queue {
            let sub = Self::hypothesis(item, &library.papers);
            report.heading(&sub.title, 1);
            report.blocks.extend(sub.blocks);
        }
        for val in &library.pipeline.validations {
            let sub = Self::validation(val);
            report.heading(&sub.title, 1);
            report.blocks.extend(sub.blocks);
        }
        for cyc in &library.pipeline.cycles {
            let sub = Self::discovery(cyc);
            report.heading(&sub.title, 1);
            report.blocks.extend(sub.blocks);
        }
        for conn in &library.pipeline.connections {
            let sub = Self::connection(conn);
            report.heading(&sub.title, 1);
            report.blocks.extend(sub.blocks);
        }
        for p in &library.papers {
            let sub = Self::paper(p);
            report.heading(&sub.title, 1);
            report.blocks.extend(sub.blocks);
        }
        report
    }

    fn append_draft(draft: &HypothesisDraft, papers: &[Paper], report: &mut ResearchReport) {
        report.heading(&draft.title, 1);
        report.section("Testable statement", &draft.statement);
        report.field("Hypothesis type", &draft.r#type);
        report.field("Scope", &draft.scope);
        report.field("Novelty", &draft.novelty);
        report.field("Support", &draft.support);
        report.field("Importance", &draft.importance);
        report.field("Originality", &draft.originality);
        report.field("Feasibility", &draft.feasibility);
        report.section("Rationale", &draft.rationale);
        report.list("Necessary claims", &draft.necessary_claims);
        report.list("Predictions", &draft.predictions);
        report.list("Falsification criteria", &draft.falsification_criteria);
        report.list("Credible alternatives", &draft.alternatives);
        report.section("Next test", &draft.next_test);
        report.heading("Supporting quotations", 2);
        Self::append_citations(&draft.citations, papers, report);
    }

    fn append_citations(
        citations: &[EvidenceCitation],
        papers: &[Paper],
        report: &mut ResearchReport,
    ) {
        for cit in citations {
            report
                .blocks
                .push(ResearchReportBlock::Quote(format!("“{}”", cit.quote)));
            let paper = papers.iter().find(|p| p.id == cit.paper_id);
            let title = paper.map(|p| p.citation()).unwrap_or_default();
            report.field(
                "Source passage",
                &format!(
                    "{} · {}{}",
                    cit.paper_id,
                    cit.passage_id,
                    if title.is_empty() {
                        String::new()
                    } else {
                        format!(" · {title}")
                    }
                ),
            );
            report.field("Quote verification", &cit.verification_description());
            report.field("Interpretation", &cit.interpretation);
            if let Some(p) = paper {
                report.blocks.push(ResearchReportBlock::Link {
                    label: format!("Paper page ({})", p.id),
                    url: p.reader_page_url(),
                });
            }
        }
    }

    fn append_datasets(records: &[ResearchDatasetRecord], report: &mut ResearchReport) {
        if records.is_empty() {
            return;
        }
        report.heading("Public dataset resources", 1);
        for r in records {
            let sub = Self::dataset(r);
            report.heading(&sub.title, 2);
            report.blocks.extend(sub.blocks);
        }
    }

    fn append_papers(papers: &[Paper], report: &mut ResearchReport) {
        if papers.is_empty() {
            return;
        }
        report.heading("Source papers", 1);
        for p in papers {
            Self::append_paper(p, report);
        }
    }

    fn append_paper(paper: &Paper, report: &mut ResearchReport) {
        report.heading(format!("{} ({})", paper.title, paper.id), 2);
        report.field("Citation", &paper.citation());
        report.field("Evidence depth", paper.evidence_label());
        if let Some(ref doi) = paper.doi {
            report.field("DOI", doi);
        }
        if let Some(ref pmid) = paper.pmid {
            report.field("PMID", pmid);
        }
        if let Some(ref pmcid) = paper.pmcid {
            report.field("PMCID", pmcid);
        }
        report.blocks.push(ResearchReportBlock::Link {
            label: "Paper page".to_string(),
            url: paper.reader_page_url(),
        });
        if let Some(ref ft) = paper.full_text {
            report.field("Full-text format", &ft.format);
            report.field("Full-text SHA-256", &ft.checksum);
            if let Some(ref lic) = ft.license.as_ref().or(paper.license.as_ref()) {
                report.field("Reuse terms", lic);
            }
        }
    }
}
