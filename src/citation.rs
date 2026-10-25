use crate::models::{
    CitationVerificationStatus, EvidenceCitation, HypothesisDraft, Paper, Passage,
    PassageTextRange, ResearchError,
};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteMatch {
    pub range: PassageTextRange,
    pub matched_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDocument {
    #[serde(rename = "paperID")]
    pub paper_id: String,
    pub title: String,
    pub evidence_type: String,
    pub is_preprint: bool,
    pub passages: Vec<Passage>,
    /// `ArticleText::checksum` of the stored text the passages came from; `None` without a body.
    /// Recorded on verified citations and never encoded into model prompts.
    #[serde(skip)]
    pub checksum: Option<String>,
}

/// The one exact-quote rule for every citation path. A quote matches when, after
/// collapsing whitespace and folding typographic quote marks and dashes, it is a
/// case-sensitive substring of the passage that:
/// - has at least `MINIMUM_LENGTH` characters,
/// - starts and ends on word boundaries (not inside "anti-amyloid", "Alzheimer's" or "0.05"),
/// - is not directly preceded by a negation it leaves out ("did not", "no", "without", "didn't").
pub struct QuoteMatcher;

impl QuoteMatcher {
    pub const MINIMUM_LENGTH: usize = 20;

    pub fn locate(quote: &str, passage: &str) -> Option<QuoteMatch> {
        let needle: Vec<char> = Self::comparable(quote).into_iter().map(|(c, _)| c).collect();
        if needle.len() < Self::MINIMUM_LENGTH {
            return None;
        }
        let haystack = Self::comparable(passage);
        let text: Vec<char> = haystack.iter().map(|(c, _)| *c).collect();
        if text.len() < needle.len() {
            return None;
        }
        let original: Vec<char> = passage.chars().collect();
        for start in 0..=(text.len() - needle.len()) {
            if text[start] != needle[0] {
                continue;
            }
            let end = start + needle.len();
            if text[start..end] != needle[..]
                || Self::inside_word(&text, start)
                || Self::inside_word(&text, end)
                || Self::follows_negation(&text, start)
            {
                continue;
            }
            let lower = haystack[start].1;
            let upper = haystack[end - 1].1 + 1;
            let matched_text: String = original[lower..upper].iter().collect();
            return Some(QuoteMatch {
                range: PassageTextRange {
                    start: lower,
                    end: upper,
                },
                matched_text,
            });
        }
        None
    }

    fn comparable(text: &str) -> Vec<(char, usize)> {
        let mut result: Vec<(char, usize)> = Vec::new();
        let mut pending_space: Option<usize> = None;
        for (offset, ch) in text.chars().enumerate() {
            if ch.is_whitespace() {
                if pending_space.is_none() && !result.is_empty() {
                    pending_space = Some(offset);
                }
                continue;
            }
            if let Some(space_offset) = pending_space.take() {
                result.push((' ', space_offset));
            }
            result.push((Self::folded(ch), offset));
        }
        result
    }

    fn folded(ch: char) -> char {
        match ch {
            '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' | '\u{2032}' | '\u{02BC}' => '\'',
            '\u{201C}' | '\u{201D}' | '\u{201E}' | '\u{201F}' | '\u{2033}' => '"',
            '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2212}' => '-',
            _ => ch,
        }
    }

    fn is_word_character(ch: char) -> bool {
        ch.is_alphabetic() || ch.is_numeric() || ch == '%'
    }

    fn joins(connector: char, left: char, right: char) -> bool {
        match connector {
            '-' | '\'' | '/' => Self::is_word_character(left) && Self::is_word_character(right),
            '.' | ',' => left.is_numeric() && right.is_numeric(),
            _ => false,
        }
    }

    fn inside_word(text: &[char], index: usize) -> bool {
        if index == 0 || index >= text.len() {
            return false;
        }
        let before = text[index - 1];
        let after = text[index];
        if Self::is_word_character(before) && Self::is_word_character(after) {
            return true;
        }
        if index >= 2 && Self::joins(before, text[index - 2], after) {
            return true;
        }
        if index + 1 < text.len() && Self::joins(after, before, text[index + 1]) {
            return true;
        }
        false
    }

    fn follows_negation(text: &[char], index: usize) -> bool {
        const NEGATIONS: &[&str] = &[
            "not", "no", "never", "without", "nor", "neither", "cannot", "none", "lack", "lacks",
            "lacked", "lacking",
        ];
        const NEGATING_PHRASES: &[(&str, &str)] = &[
            ("failed", "to"),
            ("fail", "to"),
            ("fails", "to"),
            ("unable", "to"),
            ("lack", "of"),
            ("absence", "of"),
        ];

        let mut words: Vec<String> = Vec::new();
        let mut cursor = index;
        while cursor > 0 && "\"([{".contains(text[cursor - 1]) {
            cursor -= 1;
        }
        while words.len() < 2 && cursor > 0 && text[cursor - 1] == ' ' {
            cursor -= 1;
            let mut start = cursor;
            while start > 0
                && (Self::is_word_character(text[start - 1]) || text[start - 1] == '\'')
            {
                start -= 1;
            }
            if start >= cursor {
                break;
            }
            let word: String = text[start..cursor].iter().collect();
            words.insert(0, word.to_lowercase());
            cursor = start;
        }
        let Some(last) = words.last() else {
            return false;
        };
        if NEGATIONS.contains(&last.as_str()) || last.ends_with("n't") {
            return true;
        }
        if words.len() == 2 {
            return NEGATING_PHRASES
                .iter()
                .any(|(a, b)| words[0] == *a && words[1] == *b);
        }
        false
    }
}

pub struct EvidenceValidator;

impl EvidenceValidator {
    pub fn normalize(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Supporting synthesis must contain actual article-body text. Abstracts remain useful
    /// for discovery and bounded related-work checks, but cannot substitute for a body.
    pub fn full_text_passages(paper: &Paper) -> Vec<Passage> {
        let Some(ref ft) = paper.full_text else {
            return Vec::new();
        };
        ft.passages
            .iter()
            .filter(|p| Self::is_body_passage(p))
            .cloned()
            .collect()
    }

    fn is_body_passage(p: &Passage) -> bool {
        let sec = Self::normalize(&p.section).to_lowercase();
        p.id.to_lowercase() != "abstract"
            && !["abstract", "title", "references", "bibliography", "acknowledg"]
                .iter()
                .any(|prefix| sec.starts_with(prefix))
            && Self::normalize(&p.text).chars().count() >= 20
    }

    /// Bounded excerpts supplied to the model: at most `character_budget` characters of
    /// passage text per paper. Papers with no usable excerpt are dropped.
    pub fn documents(
        papers: &[Paper],
        character_budget: usize,
        requiring_full_text: bool,
    ) -> Vec<EvidenceDocument> {
        papers
            .iter()
            .filter_map(|paper| {
                let mut remaining = character_budget;
                let mut excerpts = Vec::new();
                let passages = if requiring_full_text {
                    Self::full_text_passages(paper)
                } else {
                    paper.evidence_passages()
                };
                for passage in passages {
                    if remaining <= 100 {
                        break;
                    }
                    let text: String = passage.text.chars().take(remaining).collect();
                    if text.trim().is_empty() {
                        continue;
                    }
                    remaining -= text.chars().count();
                    excerpts.push(Passage {
                        id: passage.id,
                        section: passage.section,
                        text,
                    });
                }
                if excerpts.is_empty() {
                    return None;
                }
                let evidence_type = if requiring_full_text {
                    "selected article-body excerpts (not the entire paper)"
                } else if paper.full_text.is_none() {
                    "abstract only"
                } else {
                    "selected full-text excerpts (not the entire paper)"
                };
                Some(EvidenceDocument {
                    paper_id: paper.id.clone(),
                    title: paper.title.clone(),
                    evidence_type: evidence_type.to_string(),
                    is_preprint: paper.is_preprint,
                    passages: excerpts,
                    checksum: paper.full_text.as_ref().map(|ft| ft.checksum.clone()),
                })
            })
            .collect()
    }

    /// Decodes a model's JSON reply, tolerating a single surrounding Markdown code fence.
    pub fn decode_json<T: DeserializeOwned>(text: &str) -> Result<T, ResearchError> {
        let mut clean = text.trim();
        if clean.starts_with("```") && clean.ends_with("```") {
            if let Some(newline) = clean.find('\n') {
                clean = &clean[newline + 1..clean.len() - 3];
            }
        }
        serde_json::from_str(clean).map_err(|e| {
            ResearchError::InvalidResponse(format!(
                "The model did not return the required structured research output. No result was saved. {e}"
            ))
        })
    }

    /// Enforces the generated proposal contract and exact quote provenance against the
    /// article-body passages, rather than trusting model citations. Returns the draft with
    /// each citation's verification record.
    pub fn validate_discovery_draft(
        draft: HypothesisDraft,
        documents: &[EvidenceDocument],
    ) -> Result<HypothesisDraft, ResearchError> {
        let blank = |s: &String| Self::normalize(s).is_empty();
        let required = [
            &draft.title,
            &draft.statement,
            &draft.r#type,
            &draft.scope,
            &draft.rationale,
            &draft.next_test,
            &draft.novelty,
            &draft.support,
            &draft.importance,
            &draft.originality,
            &draft.feasibility,
        ];
        let distinct_predictions: HashSet<String> = draft
            .predictions
            .iter()
            .map(|p| Self::normalize(p).to_lowercase())
            .collect();
        if required.iter().any(|s| blank(s))
            || draft.necessary_claims.is_empty()
            || draft.predictions.len() < 2
            || distinct_predictions.len() < 2
            || draft.falsification_criteria.is_empty()
            || draft.alternatives.is_empty()
            || draft
                .necessary_claims
                .iter()
                .chain(&draft.predictions)
                .chain(&draft.falsification_criteria)
                .chain(&draft.alternatives)
                .any(blank)
        {
            return Err(ResearchError::InvalidResponse(
                "A generated hypothesis needs all scientific fields, necessary claims, two distinct predictions, a falsifier and credible alternatives.".to_string(),
            ));
        }

        let cited_papers: HashSet<&str> =
            draft.citations.iter().map(|c| c.paper_id.as_str()).collect();
        if draft.citations.len() < 2 || cited_papers.len() < 2 {
            return Err(ResearchError::InvalidResponse(
                "A hypothesis was incomplete or did not cite two distinct papers. Try another model or a more focused evidence set.".to_string(),
            ));
        }

        let body_documents: Vec<EvidenceDocument> = documents
            .iter()
            .filter_map(|d| {
                let passages: Vec<Passage> = d
                    .passages
                    .iter()
                    .filter(|p| Self::is_body_passage(p))
                    .cloned()
                    .collect();
                (!passages.is_empty()).then(|| EvidenceDocument {
                    passages,
                    ..d.clone()
                })
            })
            .collect();

        let mut checked = draft;
        checked.citations = Self::require_verified(
            &checked.citations,
            &body_documents,
            "A model citation could not be matched to the supplied paper passage. The output was rejected; no unsupported hypothesis was saved.",
        )?;
        Ok(checked)
    }

    pub fn verify(
        citation: &EvidenceCitation,
        documents: &[EvidenceDocument],
        date: DateTime<Utc>,
    ) -> EvidenceCitation {
        let mut checked = citation.clone();
        checked.verified_at = None;
        checked.matched_range = None;
        checked.matched_text = None;
        checked.source_checksum = None;

        let Some(document) = documents.iter().find(|d| d.paper_id == citation.paper_id) else {
            checked.verification_status = Some(CitationVerificationStatus::SourceUnread);
            return checked;
        };
        if document.passages.is_empty() {
            checked.verification_status = Some(CitationVerificationStatus::SourceUnread);
            return checked;
        }
        checked.source_checksum = document.checksum.clone();
        let Some(passage) = document.passages.iter().find(|p| p.id == citation.passage_id) else {
            checked.verification_status = Some(if document.checksum.is_none() {
                CitationVerificationStatus::SourceUnread
            } else {
                CitationVerificationStatus::NotLocated
            });
            return checked;
        };
        let Some(m) = QuoteMatcher::locate(&citation.quote, &passage.text) else {
            checked.verification_status = Some(CitationVerificationStatus::NotLocated);
            return checked;
        };
        checked.verification_status = Some(CitationVerificationStatus::Verified);
        checked.verified_at = Some(date);
        checked.matched_range = Some(m.range);
        checked.matched_text = Some(m.matched_text);
        checked
    }

    pub fn require_verified(
        citations: &[EvidenceCitation],
        documents: &[EvidenceDocument],
        failure: &str,
    ) -> Result<Vec<EvidenceCitation>, ResearchError> {
        let now = Utc::now();
        let mut out = Vec::with_capacity(citations.len());
        for citation in citations {
            let checked = Self::verify(citation, documents, now);
            if !checked.is_verified() || Self::normalize(&citation.interpretation).is_empty() {
                return Err(ResearchError::InvalidResponse(failure.to_string()));
            }
            out.push(checked);
        }
        Ok(out)
    }

    pub fn reverify(
        citation: &EvidenceCitation,
        documents: &[EvidenceDocument],
        date: DateTime<Utc>,
    ) -> EvidenceCitation {
        let mut checked = Self::verify(citation, documents, date);
        if checked.is_verified()
            && citation.is_verified()
            && citation.matched_range == checked.matched_range
            && citation.source_checksum == checked.source_checksum
            && citation.matched_text == checked.matched_text
        {
            checked.verified_at = citation.verified_at.or(Some(date));
        }
        checked
    }

    pub fn verification_documents(papers: &[Paper], body_only: bool) -> Vec<EvidenceDocument> {
        papers
            .iter()
            .map(|paper| EvidenceDocument {
                paper_id: paper.id.clone(),
                title: paper.title.clone(),
                evidence_type: "stored source text for citation checks".to_string(),
                is_preprint: paper.is_preprint,
                passages: if body_only {
                    Self::full_text_passages(paper)
                } else {
                    paper.evidence_passages()
                },
                checksum: paper.full_text.as_ref().map(|ft| ft.checksum.clone()),
            })
            .collect()
    }

    pub fn verification_summary(citations: &[EvidenceCitation]) -> String {
        let verified = citations
            .iter()
            .filter(|c| c.verification_status == Some(CitationVerificationStatus::Verified))
            .count();
        let not_located = citations
            .iter()
            .filter(|c| c.verification_status == Some(CitationVerificationStatus::NotLocated))
            .count();
        let unread = citations
            .iter()
            .filter(|c| c.verification_status == Some(CitationVerificationStatus::SourceUnread))
            .count();
        let unchecked = citations
            .iter()
            .filter(|c| c.verification_status.is_none())
            .count();
        [
            (verified, "verified"),
            (not_located, "not located"),
            (unread, "source unread"),
            (unchecked, "not yet checked"),
        ]
        .into_iter()
        .filter(|(c, _)| *c > 0)
        .map(|(c, label)| format!("{c} {label}"))
        .collect::<Vec<_>>()
        .join(" · ")
    }
}
