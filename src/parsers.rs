use crate::models::{normalize_doi, ArticleText, Paper, Passage, ResearchError};
use chrono::Utc;
use regex::Regex;
use roxmltree::{Document, Node, ParsingOptions};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use url::Url;

pub const AUTHOR_MANUSCRIPT_LICENSE: &str =
    "PMC author manuscript: text mining permitted through the PMC BioC service; no open licence, body not for redistribution";

static DOCTYPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<!DOCTYPE[^>]*>").expect("valid regex"));
static HTML_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<[^>]+>").expect("valid regex"));
static BLOCK_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)</?(p|h[1-6]|br|div|title)\b[^>]*>").expect("valid regex"));

/// Deepest element nesting accepted from remote XML. Articles nest a few dozen levels; the
/// recursive JATS walkers would overflow the stack on a document nested thousands deep while
/// still within the node limit.
pub const MAX_XML_DEPTH: usize = 256;

/// The deepest element nesting in XML text, found by scanning the markup without parsing it.
/// roxmltree's parser recurses once per nesting level, so this runs first. Comments, CDATA
/// sections and processing instructions are skipped; quoted attribute values may hold `>`.
/// On malformed markup it over-counts rather than under-counts.
pub fn xml_nesting_depth(text: &str) -> usize {
    let bytes = text.as_bytes();
    let (mut i, mut depth, mut deepest) = (0usize, 0usize, 0usize);
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &text[i..];
        let skip_to = |end: &str| rest.find(end).map_or(bytes.len(), |at| i + at + end.len());
        if rest.starts_with("<!--") {
            i = skip_to("-->");
            continue;
        }
        if rest.starts_with("<![CDATA[") {
            i = skip_to("]]>");
            continue;
        }
        if rest.starts_with("<?") {
            i = skip_to("?>");
            continue;
        }
        if rest.starts_with("<!") {
            i = skip_to(">");
            continue;
        }
        let closing = rest.starts_with("</");
        let mut j = i + 1;
        let mut quote: Option<u8> = None;
        while j < bytes.len() {
            let b = bytes[j];
            match quote {
                Some(q) if b == q => quote = None,
                Some(_) => {}
                None if b == b'"' || b == b'\'' => quote = Some(b),
                None if b == b'>' => break,
                None => {}
            }
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }
        if closing {
            depth = depth.saturating_sub(1);
        } else if bytes[j - 1] != b'/' {
            depth += 1;
            deepest = deepest.max(depth);
        }
        i = j + 1;
    }
    deepest
}

/// Parses XML within the node limit and refuses documents nested deeper than
/// `MAX_XML_DEPTH`, before the recursive parser sees them. The depth checks are iterative,
/// so they cannot overflow themselves.
fn parse_bounded_xml<'a>(text: &'a str, failure: &str) -> Result<Document<'a>, ResearchError> {
    if xml_nesting_depth(text) > MAX_XML_DEPTH {
        return Err(ResearchError::InvalidResponse(
            "The XML is nested too deeply to be an article and was not read.".to_string(),
        ));
    }
    let doc = Document::parse_with_options(
        text,
        ParsingOptions {
            allow_dtd: true,
            nodes_limit: 250_000,
        },
    )
    .map_err(|_| ResearchError::InvalidResponse(failure.to_string()))?;
    let mut pending = vec![(doc.root(), 0usize)];
    while let Some((node, depth)) = pending.pop() {
        if depth > MAX_XML_DEPTH {
            return Err(ResearchError::InvalidResponse(
                "The XML is nested too deeply to be an article and was not read.".to_string(),
            ));
        }
        pending.extend(node.children().map(|child| (child, depth + 1)));
    }
    Ok(doc)
}

/// Most text one collector call gathers from a subtree. Identity, licence and heading
/// strings are far shorter; this keeps a nested document from costing depth times its size.
const MAX_COLLECTED_TEXT_BYTES: usize = 8 * 1024 * 1024;

/// Most article text one parser may extract, across all passages: no more than the largest
/// accepted download, so overlapping markup cannot multiply a response in memory.
pub const MAX_EXTRACTED_TEXT_BYTES: usize = 24 * 1024 * 1024;

/// Most passages one article may yield.
pub const MAX_PASSAGES: usize = 50_000;

/// Longest heading, identifier, version or licence string kept from a document.
const MAX_METADATA_CHARS: usize = 1_000;

fn ensure_extraction_budget(passages: &[Passage]) -> Result<(), ResearchError> {
    let bytes: usize = passages.iter().map(|p| p.text.len()).sum();
    if passages.len() > MAX_PASSAGES || bytes > MAX_EXTRACTED_TEXT_BYTES {
        return Err(ResearchError::InvalidResponse(
            "The article text exceeds the extraction budget and was not stored.".to_string(),
        ));
    }
    Ok(())
}

fn bounded_metadata(text: String) -> String {
    if text.chars().count() > MAX_METADATA_CHARS {
        text.chars().take(MAX_METADATA_CHARS).collect()
    } else {
        text
    }
}

/// The digits of a PMC identifier, with any `PMC` prefix and surrounding space removed.
fn pmc_digits(value: &str) -> String {
    value.trim().to_uppercase().replace("PMC", "")
}

pub struct ArticleTextParser;

impl ArticleTextParser {
    pub fn checksum(data: &[u8]) -> String {
        let digest = Sha256::digest(data);
        format!("{digest:x}")
    }

    pub fn jats(
        data: &[u8],
        source_url: Url,
        fallback_license: Option<&str>,
    ) -> Result<ArticleText, ResearchError> {
        let raw_text = Self::decode_xml_bytes(data)?;
        if raw_text.to_ascii_lowercase().contains("<!entity") {
            return Err(ResearchError::InvalidResponse(
                "XML entity declarations are not accepted.".to_string(),
            ));
        }
        let cleaned = DOCTYPE_RE.replace_all(&raw_text, "");
        let doc = parse_bounded_xml(&cleaned, "The full-text XML could not be parsed.")?;

        let mut passages: Vec<Passage> = Vec::new();
        let mut body_passage_count = 0usize;
        let mut version: Option<String> = None;
        let mut license_text = String::new();
        let mut license_url: Option<String> = None;

        for node in doc.descendants().filter(|n| n.is_element()) {
            let name = node.tag_name().name();
            if name == "article-version"
                || (name == "article-id" && node.attribute("pub-id-type") == Some("pmcid-ver"))
            {
                let v = bounded_metadata(normalized_whitespace(&collect_all_text(node)));
                if !v.is_empty() {
                    version = Some(v);
                }
            }
            if name == "license" {
                for attr in node.attributes() {
                    if attr.name() == "href" || attr.name().ends_with(":href") {
                        license_url = Some(attr.value().to_string());
                    }
                }
                let l = bounded_metadata(normalized_whitespace(&collect_all_text(node)));
                if !l.is_empty() {
                    license_text = l;
                }
            }
        }

        // Collect abstract and body paragraphs in document order
        Self::walk_jats(
            doc.root_element(),
            &mut Vec::new(),
            &mut Vec::new(),
            &mut passages,
            &mut body_passage_count,
        );

        if body_passage_count == 0 {
            return Err(ResearchError::InvalidResponse(
                "The XML contains no article body. Abstracts and references alone are not full text."
                    .to_string(),
            ));
        }
        ensure_extraction_budget(&passages)?;

        let parsed_license_url = license_url.as_deref().and_then(|u| {
            let parsed = Url::parse(u).ok()?;
            matches!(parsed.scheme(), "https" | "http").then_some(parsed)
        });
        let combined_license = match (license_url.as_deref(), license_text.is_empty()) {
            (Some(u), false) => Some(format!("{u} — {license_text}")),
            (Some(u), true) => Some(u.to_string()),
            (None, false) => Some(license_text),
            (None, true) => fallback_license.map(ToString::to_string),
        };

        Ok(ArticleText {
            passages,
            format: "JATS XML".to_string(),
            source_url,
            retrieved_at: Utc::now(),
            checksum: Self::checksum(data),
            license: combined_license,
            version,
            license_url: parsed_license_url,
        })
    }

    fn walk_jats(
        node: Node<'_, '_>,
        stack: &mut Vec<String>,
        sections: &mut Vec<String>,
        passages: &mut Vec<Passage>,
        body_passage_count: &mut usize,
    ) {
        const EXCLUDED: &[&str] = &[
            "ref-list",
            "ref",
            "back",
            "sub-article",
            "supplementary-material",
            "fn-group",
            "ack",
        ];
        if !node.is_element() {
            return;
        }
        let tag = node.tag_name().name();
        if EXCLUDED.contains(&tag) {
            return;
        }
        stack.push(tag.to_string());
        let is_sec = tag == "sec";
        if is_sec {
            let title = node
                .children()
                .find(|c| c.is_element() && c.tag_name().name() == "title")
                .map(|t| bounded_metadata(normalized_whitespace(&collect_jats_text(t, EXCLUDED))))
                .unwrap_or_default();
            sections.push(title);
        }

        let readable = stack.iter().any(|s| s == "body" || s == "abstract");
        if readable && tag == "p" {
            let is_abstract = stack.iter().any(|s| s == "abstract");
            let sec_label = if is_abstract {
                "Abstract".to_string()
            } else {
                let joined = sections
                    .iter()
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" / ");
                if joined.is_empty() {
                    "Article body".to_string()
                } else {
                    joined
                }
            };
            let text = normalized_whitespace(&collect_jats_text(node, EXCLUDED));
            if !text.is_empty() {
                let id = format!("jats-{}", passages.len() + 1);
                passages.push(Passage {
                    id,
                    section: sec_label,
                    text,
                });
                if !is_abstract {
                    *body_passage_count += 1;
                }
            }
        } else {
            for child in node.children() {
                Self::walk_jats(child, stack, sections, passages, body_passage_count);
            }
        }

        if is_sec {
            sections.pop();
        }
        stack.pop();
    }

    /// Reads a PMC BioC document. With `expected_pmcid`, the document must identify itself
    /// as that article; a document with another or no PMC identifier is refused.
    pub fn bioc(
        data: &[u8],
        source_url: Url,
        fallback_license: Option<&str>,
        expected_pmcid: Option<&str>,
    ) -> Result<ArticleText, ResearchError> {
        let json: Value = match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(_) => {
                let prefix = String::from_utf8_lossy(&data[..data.len().min(4_000)]);
                if prefix.contains("No result can be found") {
                    return Err(ResearchError::Unavailable(
                        "PMC BioC has no document for this record; the body is not available through a supported route."
                            .to_string(),
                    ));
                }
                return Err(ResearchError::InvalidResponse(
                    "The BioC response is not valid JSON.".to_string(),
                ));
            }
        };

        let collections: Vec<&Value> = if let Some(arr) = json.as_array() {
            arr.iter().collect()
        } else if json.is_object() {
            vec![&json]
        } else {
            return Err(ResearchError::InvalidResponse(
                "The BioC response has no collection.".to_string(),
            ));
        };

        let documents: Vec<&Value> = collections
            .into_iter()
            .filter_map(|c| c.get("documents")?.as_array())
            .flatten()
            .collect();

        if documents.len() != 1 {
            return Err(ResearchError::InvalidResponse(
                "Expected exactly one BioC article with passages.".to_string(),
            ));
        }
        let doc = documents[0];
        if let Some(expected) = expected_pmcid {
            let expected = pmc_digits(expected);
            let found = doc
                .get("id")
                .and_then(Value::as_str)
                .or_else(|| {
                    doc.get("infons")
                        .and_then(|i| i.get("article-id_pmc"))
                        .and_then(Value::as_str)
                })
                .map(pmc_digits)
                .filter(|d| !d.is_empty());
            match found {
                Some(found) if found == expected => {}
                Some(found) => {
                    return Err(ResearchError::InvalidResponse(format!(
                        "The BioC document describes PMC{found}, not the requested PMC{expected}."
                    )))
                }
                None => {
                    return Err(ResearchError::InvalidResponse(
                        "The BioC document carries no PMC identifier, so it cannot be tied to the requested paper.".to_string(),
                    ))
                }
            }
        }
        let Some(raw_passages) = doc.get("passages").and_then(|p| p.as_array()) else {
            return Err(ResearchError::InvalidResponse(
                "Expected exactly one BioC article with passages.".to_string(),
            ));
        };

        let mut license = doc
            .get("infons")
            .and_then(|i| i.get("license"))
            .and_then(|l| l.as_str())
            .map(ToString::to_string);
        if license
            .as_deref()
            .is_some_and(|l| l.eq_ignore_ascii_case("author_manuscript"))
        {
            license = Some(AUTHOR_MANUSCRIPT_LICENSE.to_string());
        }

        let mut version: Option<String> = None;
        let mut passages: Vec<Passage> = Vec::new();
        let mut has_body = false;

        const EXCLUDED_SECTIONS: &[&str] = &[
            "TITLE",
            "REF",
            "REFERENCES",
            "ACK_FUND",
            "ACK",
            "COMP_INT",
            "AUTH_CONT",
            "SUPPL",
            "REVIEW_INFO",
        ];
        const ACCEPTED_TYPES: &[&str] = &[
            "paragraph",
            "abstract",
            "table",
            "table_caption",
            "fig_caption",
            "caption",
        ];

        for (index, raw) in raw_passages.iter().enumerate() {
            let infons = raw.get("infons");
            if license.is_none() {
                license = infons
                    .and_then(|i| i.get("license"))
                    .and_then(|l| l.as_str())
                    .map(|l| {
                        if l.eq_ignore_ascii_case("author_manuscript") {
                            AUTHOR_MANUSCRIPT_LICENSE.to_string()
                        } else {
                            l.to_string()
                        }
                    });
            }
            if version.is_none() {
                version = infons
                    .and_then(|i| i.get("article-id_pmcid-ver"))
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);
            }
            let section = infons
                .and_then(|i| i.get("section_type"))
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_uppercase();
            let ptype = infons
                .and_then(|i| i.get("type"))
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_lowercase();
            if EXCLUDED_SECTIONS.contains(&section.as_str())
                || !ACCEPTED_TYPES.contains(&ptype.as_str())
            {
                continue;
            }
            let Some(raw_text) = raw.get("text").and_then(|t| t.as_str()) else {
                continue;
            };
            let text = normalized_whitespace(raw_text);
            if text.is_empty() {
                continue;
            }
            let is_abstract = section == "ABSTRACT" || ptype == "abstract";
            if !is_abstract {
                has_body = true;
            }
            passages.push(Passage {
                id: format!("bioc-{}", index + 1),
                section: if is_abstract {
                    "Abstract".to_string()
                } else {
                    Self::section_name(&section)
                },
                text,
            });
        }

        if !has_body {
            return Err(ResearchError::InvalidResponse(
                "The BioC response contains no article body. This paper remains abstract only."
                    .to_string(),
            ));
        }
        ensure_extraction_budget(&passages)?;

        Ok(ArticleText {
            passages,
            format: "BioC JSON".to_string(),
            source_url,
            retrieved_at: Utc::now(),
            checksum: Self::checksum(data),
            license: license.or_else(|| fallback_license.map(ToString::to_string)),
            version,
            license_url: None,
        })
    }

    fn section_name(section: &str) -> String {
        match section {
            "INTRO" => "Introduction".to_string(),
            "METHODS" => "Methods".to_string(),
            "RESULTS" => "Results".to_string(),
            "DISCUSS" => "Discussion".to_string(),
            "CONCL" => "Conclusions".to_string(),
            "" => "Article body".to_string(),
            other => {
                let mut chars = other.chars();
                match chars.next() {
                    Some(first) => {
                        format!(
                            "{}{}",
                            first.to_uppercase(),
                            chars.as_str().to_lowercase()
                        )
                    }
                    None => "Article body".to_string(),
                }
            }
        }
    }

    pub fn validate_xml_identity(data: &[u8], paper: &Paper) -> Result<(), ResearchError> {
        let raw_text = Self::decode_xml_bytes(data)?;
        let cleaned = DOCTYPE_RE.replace_all(&raw_text, "");
        let doc = parse_bounded_xml(&cleaned, "The article identity could not be read from XML.")?;

        let mut xml_title = String::new();
        let mut xml_doi: Option<String> = None;
        let mut xml_pmid: Option<String> = None;
        let mut xml_pmcid: Option<String> = None;

        for node in doc.descendants().filter(|n| n.is_element()) {
            let in_meta = node
                .ancestors()
                .any(|a| a.is_element() && a.tag_name().name() == "article-meta")
                && !node
                    .ancestors()
                    .any(|a| a.is_element() && a.tag_name().name() == "sub-article");
            if !in_meta {
                continue;
            }
            let text = || bounded_metadata(collect_all_text(node));
            match node.tag_name().name() {
                "article-title" => xml_title = text(),
                "article-id" => match node.attribute("pub-id-type") {
                    Some("doi") => xml_doi = Some(text()),
                    Some("pmid") => xml_pmid = Some(text()),
                    Some("pmcid") | Some("pmc") => xml_pmcid = Some(text()),
                    _ => {}
                },
                _ => {}
            }
        }

        let nonblank = |s: String| (!s.is_empty()).then_some(s);
        let our_doi = normalize_doi(paper.doi.as_deref());
        let their_doi = normalize_doi(xml_doi.as_deref());
        let our_pmid = paper.pmid.as_deref().map(|p| p.trim().to_string()).and_then(nonblank);
        let their_pmid = xml_pmid.as_deref().map(|p| p.trim().to_string()).and_then(nonblank);
        let our_pmcid = paper.pmcid.as_deref().map(pmc_digits).and_then(nonblank);
        let their_pmcid = xml_pmcid.as_deref().map(pmc_digits).and_then(nonblank);

        // An identifier both sides state must agree; a matching title does not excuse a
        // conflicting DOI, PMID or PMCID.
        let conflicts = |ours: &Option<String>, theirs: &Option<String>| {
            matches!((ours, theirs), (Some(a), Some(b)) if a != b)
        };
        if conflicts(&our_doi, &their_doi)
            || conflicts(&our_pmid, &their_pmid)
            || conflicts(&our_pmcid, &their_pmcid)
        {
            return Err(ResearchError::InvalidResponse(
                "The XML identifiers describe a different article from the requested paper.".to_string(),
            ));
        }
        let agrees = |ours: &Option<String>, theirs: &Option<String>| ours.is_some() && ours == theirs;
        let norm_paper_title = normalize_alnum(&paper.title);
        let title_matches =
            norm_paper_title.len() >= 20 && norm_paper_title == normalize_alnum(&xml_title);

        if agrees(&our_doi, &their_doi)
            || agrees(&our_pmid, &their_pmid)
            || agrees(&our_pmcid, &their_pmcid)
            || title_matches
        {
            Ok(())
        } else {
            Err(ResearchError::InvalidResponse(
                "The XML title or identifiers do not match the requested paper.".to_string(),
            ))
        }
    }

    pub(crate) fn decode_xml_bytes(data: &[u8]) -> Result<String, ResearchError> {
        if data.starts_with(&[0xFF, 0xFE]) {
            let u16s: Vec<u16> = data[2..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            return String::from_utf16(&u16s).map_err(|_| {
                ResearchError::InvalidResponse("Invalid UTF-16 XML payload.".to_string())
            });
        }
        if data.starts_with(&[0xFE, 0xFF]) {
            let u16s: Vec<u16> = data[2..]
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            return String::from_utf16(&u16s).map_err(|_| {
                ResearchError::InvalidResponse("Invalid UTF-16 XML payload.".to_string())
            });
        }
        String::from_utf8(data.to_vec())
            .map_err(|_| ResearchError::InvalidResponse("Invalid UTF-8 XML payload.".to_string()))
    }
}

pub struct ElsevierArticleParser;

impl ElsevierArticleParser {
    pub fn parse(
        data: &[u8],
        source_url: Url,
        doi: &str,
        license: &str,
    ) -> Result<ArticleText, ResearchError> {
        let raw_text = ArticleTextParser::decode_xml_bytes(data)?;
        if raw_text.to_ascii_lowercase().contains("<!entity") {
            return Err(ResearchError::InvalidResponse(
                "XML entity declarations are not accepted.".to_string(),
            ));
        }
        let cleaned = DOCTYPE_RE.replace_all(&raw_text, "");
        let doc = parse_bounded_xml(&cleaned, "The Elsevier TDM response is not well-formed XML.")?;

        const EXCLUDED: &[&str] = &[
            "bibliography",
            "acknowledgment",
            "author-group",
            "floats",
            "meta",
            "further-reading",
            "footnote",
            "cross-ref",
            "cross-refs",
        ];

        // The response must say which article it is before any text is extracted; a body
        // with no readable DOI is not attached to the requested paper.
        let found_doi = doc
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "doi")
            .map(|n| bounded_metadata(collect_all_text(n).trim().to_string()))
            .find(|d| !d.is_empty());
        match normalize_doi(found_doi.as_deref()) {
            Some(found) if Some(found.as_str()) == normalize_doi(Some(doi)).as_deref() => {}
            Some(found) => {
                return Err(ResearchError::InvalidResponse(format!(
                    "The Elsevier TDM response describes a different DOI ({found})."
                )))
            }
            None => {
                return Err(ResearchError::InvalidResponse(
                    "The Elsevier TDM response carries no readable DOI, so it cannot be tied to the requested article.".to_string(),
                ))
            }
        }

        let is_paragraph = |n: &Node<'_, '_>| {
            n.is_element() && matches!(n.tag_name().name(), "para" | "simple-para")
        };
        let mut passages: Vec<Passage> = Vec::new();
        let mut has_body = false;
        let mut current_section = "Article body".to_string();

        for node in doc.descendants().filter(|n| n.is_element()) {
            let tag = node.tag_name().name();
            if node
                .ancestors()
                .filter(|a| a.is_element())
                .any(|a| EXCLUDED.contains(&a.tag_name().name()))
            {
                continue;
            }
            let in_abstract = node
                .ancestors()
                .filter(|a| a.is_element())
                .any(|a| a.tag_name().name() == "abstract");
            if tag == "section-title" && !in_abstract {
                let title = bounded_metadata(normalized_whitespace(&collect_all_text(node)));
                if !title.is_empty() {
                    current_section = title;
                }
            } else if is_paragraph(&node) {
                // A paragraph inside a paragraph is already part of its parent's text;
                // extracting it again would retain the same text once per level.
                if node.ancestors().skip(1).any(|a| is_paragraph(&a)) {
                    continue;
                }
                let text = normalized_whitespace(&collect_jats_text(node, EXCLUDED));
                if text.is_empty() {
                    continue;
                }
                if !in_abstract {
                    has_body = true;
                }
                passages.push(Passage {
                    id: format!("elsevier-{}", passages.len() + 1),
                    section: if in_abstract {
                        "Abstract".to_string()
                    } else {
                        current_section.clone()
                    },
                    text,
                });
            }
        }

        if !has_body {
            return Err(ResearchError::InvalidResponse(
                "The Elsevier TDM response contains no article body; the institution may not be entitled to this article's full text. Abstract-only responses are not used as evidence.".to_string(),
            ));
        }
        ensure_extraction_budget(&passages)?;

        Ok(ArticleText {
            passages,
            format: "Elsevier TDM XML".to_string(),
            source_url,
            retrieved_at: Utc::now(),
            checksum: ArticleTextParser::checksum(data),
            license: Some(license.to_string()),
            version: Some("publishedVersion".to_string()),
            license_url: None,
        })
    }
}

pub struct MarkupText;

impl MarkupText {
    pub fn plain(text: &str) -> String {
        if !text.contains('<') && !text.contains('&') {
            return normalized_whitespace(text);
        }
        let with_spaces = BLOCK_TAG_RE.replace_all(text, " ");
        let without_tags = HTML_TAG_RE.replace_all(&with_spaces, " ");
        let unescaped = without_tags
            .replace("&nbsp;", " ")
            .replace("&#160;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&apos;", "'");
        normalized_whitespace(&unescaped)
    }
}

/// The text of a node's text descendants, in order. Only text nodes are read: on an element,
/// `Node::text()` returns its first text child, which would be counted twice.
fn collect_all_text(node: Node<'_, '_>) -> String {
    let mut out = String::new();
    for text in node.descendants().filter(|d| d.is_text()).filter_map(|d| d.text()) {
        if out.len() >= MAX_COLLECTED_TEXT_BYTES {
            break;
        }
        out.push_str(text);
    }
    out
}

fn collect_jats_text(node: Node<'_, '_>, excluded: &[&str]) -> String {
    let mut out = String::new();
    fn visit(n: Node<'_, '_>, excluded: &[&str], out: &mut String) {
        if n.is_element() {
            let name = n.tag_name().name();
            if excluded.contains(&name) {
                return;
            }
            if name == "break" || name == "br" {
                out.push(' ');
                return;
            }
        }
        if n.is_text() {
            if let Some(t) = n.text() {
                if out.len() < MAX_COLLECTED_TEXT_BYTES {
                    out.push_str(t);
                }
            }
            return;
        }
        for child in n.children() {
            visit(child, excluded, out);
        }
    }
    visit(node, excluded, &mut out);
    out
}

pub fn normalized_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn normalize_alnum(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
