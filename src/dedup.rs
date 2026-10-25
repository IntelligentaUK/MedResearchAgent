use crate::models::{identifiers_conflict, normalize_doi, Paper};
use std::collections::HashSet;
use std::hash::Hash;

/// Identifier-based deduplication. Never conflates distinct versions or a preprint
/// with a published paper; those may still describe the same underlying study.
pub struct PaperDeduplicator;

impl PaperDeduplicator {
    pub fn deduplicate(papers: &[Paper]) -> Vec<Paper> {
        let mut groups: Vec<(Paper, HashSet<String>)> = Vec::new();
        for paper in papers {
            let mut merged = paper.clone();
            let mut aliases = Self::identifiers(paper);
            let mut insertion_index = groups.len();
            let mut found_existing = false;
            let mut index = 0;
            while index < groups.len() {
                if Self::compatible(&groups[index].0, &merged)
                    && !groups[index].1.is_disjoint(&aliases)
                {
                    let (group_paper, group_aliases) = groups.remove(index);
                    merged = if found_existing {
                        Self::combining(&merged, &group_paper)
                    } else {
                        Self::combining(&group_paper, &merged)
                    };
                    found_existing = true;
                    aliases.extend(group_aliases);
                    insertion_index = insertion_index.min(index);
                    index = 0;
                } else {
                    index += 1;
                }
            }
            let pos = insertion_index.min(groups.len());
            groups.insert(pos, (merged, aliases));
        }
        groups.into_iter().map(|(p, _)| p).collect()
    }

    /// Two records may be merged only when they describe the same version and no identifier
    /// they both state disagrees. A record carrying one paper's DOI and another's PMID is
    /// not a bridge between them; it is left on its own.
    fn compatible(a: &Paper, b: &Paper) -> bool {
        a.is_preprint == b.is_preprint && a.version == b.version && !identifiers_conflict(a, b)
    }

    fn identifiers(paper: &Paper) -> HashSet<String> {
        let mut keys = HashSet::new();
        keys.insert(format!("source:{}", paper.id));
        if let Some(doi) = normalize_doi(paper.doi.as_deref()) {
            keys.insert(format!("doi:{doi}"));
        } else if let Some(ref raw_doi) = paper.doi {
            let clean = raw_doi
                .trim()
                .to_lowercase()
                .trim_start_matches("https://doi.org/")
                .trim_start_matches("http://doi.org/")
                .trim_start_matches("https://dx.doi.org/")
                .trim_start_matches("doi:")
                .trim()
                .to_string();
            if !clean.is_empty() {
                keys.insert(format!("doi:{clean}"));
            }
        }
        if let Some(ref pmid) = paper.pmid {
            if !pmid.is_empty() {
                keys.insert(format!("pmid:{pmid}"));
            }
        }
        if let Some(ref pmcid) = paper.pmcid {
            if !pmcid.is_empty() {
                keys.insert(format!("pmcid:{}", pmcid.to_uppercase()));
            }
        }
        keys
    }

    fn combining(first: &Paper, second: &Paper) -> Paper {
        let mut result = first.clone();
        if result.doi.is_none() {
            result.doi = second.doi.clone();
        }
        if result.pmid.is_none() {
            result.pmid = second.pmid.clone();
        }
        if result.pmcid.is_none() {
            result.pmcid = second.pmcid.clone();
        }
        if result.license.is_none() {
            result.license = second.license.clone();
        }
        if result.license_url.is_none() {
            result.license_url = second.license_url.clone();
        }
        result.full_text_locations =
            Self::merge_opt_vec(&first.full_text_locations, &second.full_text_locations);
        result.journal_issns = Self::merge_opt_vec(&first.journal_issns, &second.journal_issns);
        result.catalog_source_ids =
            Self::merge_opt_vec(&first.catalog_source_ids, &second.catalog_source_ids);
        if result.year.is_none() {
            result.year = second.year;
        }
        if result.authors.is_empty() {
            result.authors = second.authors.clone();
        }
        if result.journal.is_empty() {
            result.journal = second.journal.clone();
        }
        if second.abstract_text.len() > result.abstract_text.len() {
            result.abstract_text = second.abstract_text.clone();
        }
        if result.full_text.is_none() {
            result.full_text = second.full_text.clone();
        }
        result.is_open_access = first.is_open_access || second.is_open_access;
        result.is_author_manuscript = first.is_author_manuscript || second.is_author_manuscript;
        for pt in &second.publication_types {
            if !result.publication_types.contains(pt) {
                result.publication_types.push(pt.clone());
            }
        }
        result
    }

    fn merge_opt_vec<T: Clone + Eq + Hash>(
        first: &Option<Vec<T>>,
        second: &Option<Vec<T>>,
    ) -> Option<Vec<T>> {
        if first.is_none() && second.is_none() {
            return None;
        }
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for item in first
            .iter()
            .flatten()
            .chain(second.iter().flatten())
        {
            if seen.insert(item.clone()) {
                out.push(item.clone());
            }
        }
        Some(out)
    }
}
