use crate::citation::EvidenceValidator;
use chrono::Utc;
use crate::models::{
    ConnectionReview, DiscoveryCycle, HypothesisDraft, HypothesisOrigin, HypothesisQueueStatus,
    HypothesisValidation, LibrarySnapshot, Paper, QueuedHypothesis, ResearchDatasetRecord,
    ResearchDomain, ResearchError,
};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const CURRENT_SCHEMA_VERSION: u32 = 4;

/// Atomically replaces `path` with `payload` via a temporary file created with `0600`
/// (owner-only) permissions on Unix, creating the parent directory if needed.
pub(crate) fn write_private_file(path: &Path, payload: &[u8]) -> Result<(), ResearchError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            ResearchError::Unavailable(format!("Could not create data directory: {e}"))
        })?;
    }
    let tmp_path = path.with_extension(format!("json.tmp.{}", Uuid::new_v4()));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp_path)
        .map_err(|e| ResearchError::Unavailable(format!("Temp file open failed: {e}")))?;
    file.write_all(payload)
        .and_then(|_| file.sync_all())
        .map_err(|e| ResearchError::Unavailable(format!("Temp file write failed: {e}")))?;
    drop(file);

    fs::rename(&tmp_path, path)
        .map_err(|e| ResearchError::Unavailable(format!("Atomic rename failed: {e}")))?;
    Ok(())
}

/// The per-user directory for `library.json` and the ChatGPT credential files.
/// `DEMENTIA_RESEARCH_DATA_DIR` overrides it; otherwise:
/// - macOS: `~/Library/Application Support/DementiaResearch` (shared with the Swift app)
/// - Windows: `%APPDATA%\DementiaResearch`
/// - Linux and other Unix: `$XDG_DATA_HOME/dementia-research`, else `~/.local/share/dementia-research`
pub fn data_dir() -> PathBuf {
    data_dir_for(
        |name| std::env::var_os(name),
        cfg!(windows),
        cfg!(target_os = "macos"),
    )
}

/// [`data_dir`] with the environment and OS supplied, so every platform's rule is testable.
pub fn data_dir_for(
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
    windows: bool,
    macos: bool,
) -> PathBuf {
    let env_dir = |name: &str| env(name).map(PathBuf::from).filter(|p| p.is_absolute());
    if let Some(dir) = env_dir("DEMENTIA_RESEARCH_DATA_DIR") {
        return dir;
    }
    if windows {
        if let Some(app_data) = env_dir("APPDATA") {
            return app_data.join("DementiaResearch");
        }
        if let Some(profile) = env_dir("USERPROFILE") {
            return profile
                .join("AppData")
                .join("Roaming")
                .join("DementiaResearch");
        }
    }
    let home = env_dir("HOME");
    if macos {
        if let Some(home) = home {
            return home
                .join("Library")
                .join("Application Support")
                .join("DementiaResearch");
        }
    }
    if let Some(xdg) = env_dir("XDG_DATA_HOME") {
        return xdg.join("dementia-research");
    }
    match home {
        Some(home) => home.join(".local").join("share").join("dementia-research"),
        // Last resort when no home directory is known.
        None => PathBuf::from("dementia-research-data"),
    }
}

pub struct LibraryStore {
    file_path: PathBuf,
}

impl LibraryStore {
    pub fn new(file_path: impl Into<PathBuf>) -> Self {
        Self {
            file_path: file_path.into(),
        }
    }

    pub fn default_store() -> Self {
        Self {
            file_path: data_dir().join("library.json"),
        }
    }

    pub fn path(&self) -> &Path {
        &self.file_path
    }

    pub fn load(&self) -> Result<LibrarySnapshot, ResearchError> {
        if !self.file_path.exists() {
            return Ok(LibrarySnapshot::default());
        }
        let data = fs::read(&self.file_path)
            .map_err(|e| ResearchError::Unavailable(format!("Failed to read library: {e}")))?;
        let mut snapshot: LibrarySnapshot = serde_json::from_slice(&data).map_err(|e| {
            ResearchError::InvalidResponse(format!(
                "Saved library.json is unreadable and was preserved rather than overwritten: {e}"
            ))
        })?;
        if snapshot.schema_version > CURRENT_SCHEMA_VERSION {
            return Err(ResearchError::InvalidResponse(format!(
                "Saved library.json uses newer schema version {} (supported <= {CURRENT_SCHEMA_VERSION}). Refusing to overwrite.",
                snapshot.schema_version
            )));
        }
        snapshot.schema_version = CURRENT_SCHEMA_VERSION;
        for item in &mut snapshot.pipeline.queue {
            if item.status == HypothesisQueueStatus::Processing {
                item.status = HypothesisQueueStatus::Pending;
                item.last_error = Some(
                    "Interrupted work recovered; validation will restart from the original statement."
                        .to_string(),
                );
            }
        }
        Self::reverify_all_citations(&mut snapshot);
        Ok(snapshot)
    }

    pub fn save(&self, snapshot: &LibrarySnapshot) -> Result<(), ResearchError> {
        let payload = serde_json::to_vec_pretty(snapshot)
            .map_err(|e| ResearchError::InvalidResponse(format!("Serialization error: {e}")))?;
        write_private_file(&self.file_path, &payload)
    }

    pub fn reverify_all_citations(snapshot: &mut LibrarySnapshot) {
        let now = Utc::now();
        let mut all_papers: Vec<Paper> = snapshot.papers.clone();
        for v in &snapshot.pipeline.validations {
            for p in &v.papers {
                if !all_papers.iter().any(|existing| existing.id == p.id) {
                    all_papers.push(p.clone());
                }
            }
        }
        for c in &snapshot.pipeline.cycles {
            for p in &c.papers {
                if !all_papers.iter().any(|existing| existing.id == p.id) {
                    all_papers.push(p.clone());
                }
            }
        }
        let body_sources = EvidenceValidator::verification_documents(&all_papers, true);

        for item in &mut snapshot.pipeline.queue {
            item.draft.citations = item
                .draft
                .citations
                .iter()
                .map(|c| EvidenceValidator::reverify(c, &body_sources, now))
                .collect();
        }
        for val in &mut snapshot.pipeline.validations {
            let val_sources = EvidenceValidator::verification_documents(&val.papers, true);
            for claim in &mut val.claims {
                claim.citations = claim
                    .citations
                    .iter()
                    .map(|c| EvidenceValidator::reverify(c, &val_sources, now))
                    .collect();
            }
            if let Some(ref mut rev) = val.proposed_revision {
                rev.citations = rev
                    .citations
                    .iter()
                    .map(|c| EvidenceValidator::reverify(c, &val_sources, now))
                    .collect();
            }
            if let Some(ref mut checks) = val.supplied_citation_checks {
                *checks = checks
                    .iter()
                    .map(|c| EvidenceValidator::reverify(c, &val_sources, now))
                    .collect();
            }
        }
        for cyc in &mut snapshot.pipeline.cycles {
            let cyc_sources = EvidenceValidator::verification_documents(&cyc.papers, true);
            for draft in &mut cyc.hypotheses {
                draft.citations = draft
                    .citations
                    .iter()
                    .map(|c| EvidenceValidator::reverify(c, &cyc_sources, now))
                    .collect();
            }
        }
        for conn in &mut snapshot.pipeline.connections {
            let conn_sources = EvidenceValidator::verification_documents(&conn.papers, true);
            for prop in &mut conn.proposals {
                prop.draft.citations = prop
                    .draft
                    .citations
                    .iter()
                    .map(|c| EvidenceValidator::reverify(c, &conn_sources, now))
                    .collect();
            }
        }
    }

    pub fn enqueue_manual_hypothesis(
        snapshot: &mut LibrarySnapshot,
        title: &str,
        statement: &str,
        domain: ResearchDomain,
    ) -> Result<Uuid, ResearchError> {
        let clean_title = title.trim();
        let clean_statement = statement.trim();
        if clean_statement.is_empty() || clean_statement.chars().count() > 12_000 {
            return Err(ResearchError::Unavailable(
                "Enter a testable hypothesis statement between 1 and 12,000 characters.".to_string(),
            ));
        }
        let effective_title = if clean_title.is_empty() {
            clean_statement.chars().take(80).collect::<String>()
        } else {
            clean_title.chars().take(160).collect::<String>()
        };
        let draft = HypothesisDraft::minimal(&effective_title, clean_statement);
        let item = QueuedHypothesis::new(draft, HypothesisOrigin::Manual, domain);
        let id = item.id;
        if !snapshot.pipeline.enqueue(item) {
            return Err(ResearchError::InvalidResponse(
                "An identical hypothesis statement is already in this field's queue.".to_string(),
            ));
        }
        Ok(id)
    }

    pub fn complete_validation(
        snapshot: &mut LibrarySnapshot,
        mut validation: HypothesisValidation,
        datasets: Vec<ResearchDatasetRecord>,
    ) {
        let domain = validation.domain();
        if !datasets.is_empty() {
            validation.dataset_records = Some(datasets.clone());
            Self::merge_datasets(snapshot, datasets);
        }
        for p in &validation.papers {
            snapshot.upsert_paper(p.clone(), domain);
        }
        let val_id = validation.id;
        let hyp_id = validation.hypothesis_id;
        let verdict_label = validation.verdict.label();
        let revision = validation.proposed_revision.clone();
        snapshot.pipeline.validations.insert(0, validation);

        let mut parent_generation = 0usize;
        if let Some(item) = snapshot.pipeline.queue.iter_mut().find(|q| q.id == hyp_id) {
            item.status = HypothesisQueueStatus::Assessed;
            item.validation_id = Some(val_id);
            item.last_error = None;
            item.next_attempt_at = None;
            parent_generation = item.generation;
        }
        if let Some(rev_draft) = revision {
            if parent_generation < 4 {
                let mut child =
                    QueuedHypothesis::new(rev_draft, HypothesisOrigin::Generated, domain);
                child.parent_ids = vec![hyp_id];
                child.generation = parent_generation + 1;
                snapshot.pipeline.enqueue(child);
            }
        }
        snapshot
            .pipeline
            .update_loop_state(domain, |s| s.last_completed_stage = Some("validation".to_string()));
        snapshot
            .pipeline
            .record(format!("Assessed hypothesis {hyp_id}: {verdict_label}."));
        Self::reverify_all_citations(snapshot);
    }

    pub fn complete_discovery(
        snapshot: &mut LibrarySnapshot,
        mut cycle: DiscoveryCycle,
        datasets: Vec<ResearchDatasetRecord>,
    ) {
        let domain = cycle.domain();
        if !datasets.is_empty() {
            cycle.dataset_records = Some(datasets.clone());
            Self::merge_datasets(snapshot, datasets);
        }
        for p in &cycle.papers {
            snapshot.upsert_paper(p.clone(), domain);
        }
        let mut added = 0usize;
        for draft in &cycle.hypotheses {
            let mut item =
                QueuedHypothesis::new(draft.clone(), HypothesisOrigin::Generated, domain);
            item.source_paper_ids = draft
                .citations
                .iter()
                .map(|c| c.paper_id.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            if snapshot.pipeline.enqueue(item) {
                added += 1;
            }
        }
        let obj = cycle.objective.clone();
        snapshot.pipeline.remove_objective(&obj, domain);
        snapshot.pipeline.cycles.insert(0, cycle);
        snapshot.pipeline.update_loop_state(domain, |s| {
            s.discovery_failures = 0;
            s.last_completed_stage = Some("discovery".to_string());
        });
        snapshot.pipeline.record(format!(
            "Completed {} discovery cycle ({added} new hypotheses queued).",
            domain.display_name()
        ));
        Self::reverify_all_citations(snapshot);
    }

    pub fn complete_connection(
        snapshot: &mut LibrarySnapshot,
        mut review: ConnectionReview,
        datasets: Vec<ResearchDatasetRecord>,
    ) {
        let domain = review.domain();
        if !datasets.is_empty() {
            review.dataset_records = Some(datasets.clone());
            Self::merge_datasets(snapshot, datasets);
        }
        for p in &review.papers {
            snapshot.upsert_paper(p.clone(), domain);
        }
        let mut added = 0usize;
        for prop in &review.proposals {
            let origin = if prop.new_evidence_paper_ids.is_empty() {
                HypothesisOrigin::Correlation
            } else {
                HypothesisOrigin::Reconsideration
            };
            let mut item = QueuedHypothesis::new(prop.draft.clone(), origin, domain);
            item.parent_ids = prop.parent_ids.clone();
            item.source_paper_ids = prop
                .draft
                .citations
                .iter()
                .map(|c| c.paper_id.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            if snapshot.pipeline.enqueue(item) {
                added += 1;
            }
        }
        let domain_papers = snapshot.research_papers(domain);
        let sig = snapshot
            .pipeline
            .connection_signature(&domain_papers, Some(domain));
        snapshot.pipeline.connections.insert(0, review);
        snapshot.pipeline.update_loop_state(domain, |s| {
            s.connection_failures = 0;
            s.last_connection_signature = Some(sig);
            s.last_completed_stage = Some("connection".to_string());
        });
        snapshot.pipeline.record(format!(
            "Completed {} connection review ({added} proposals queued).",
            domain.display_name()
        ));
        Self::reverify_all_citations(snapshot);
    }

    pub fn merge_datasets(snapshot: &mut LibrarySnapshot, records: Vec<ResearchDatasetRecord>) {
        let existing = snapshot.dataset_records.get_or_insert_with(Vec::new);
        for rec in records {
            if let Some(slot) = existing.iter_mut().find(|r| r.id == rec.id) {
                *slot = rec;
            } else {
                existing.push(rec);
            }
        }
    }
}
