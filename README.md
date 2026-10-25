# Medical Research Agent — Hardened Rust Full-Stack Web Port (`Axum` + `rustls`)

This directory contains a complete, memory-safe, security-hardened Rust full-stack web application port of the `DementiaResearch` autonomous medical research agent (supporting both **Dementia** and **Cancer** research profiles).

## Why `Axum` + SSR + `rustls` + `#![forbid(unsafe_code)]`?

To minimize attack surface while handling untrusted scientific literature (JATS XML, PMC BioC JSON, Elsevier XML, OpenAlex metadata, NCI GDC & cBioPortal catalogs) and LLM outputs:

1. **Compiler-Enforced Memory Safety (`#![forbid(unsafe_code)]`)**:
   - Configured in [`Cargo.toml`](Cargo.toml) (`[lints.rust] unsafe_code = "forbid"`), [`src/lib.rs`](src/lib.rs), and [`src/main.rs`](src/main.rs).
   - Built on **Axum** (`tokio-rs/axum`) and **Tower**, which have `#![forbid(unsafe_code)]` at the HTTP routing and extractor layer (unlike frameworks that rely on internal `unsafe` actor/pointer abstractions).
2. **Pure-Rust TLS (`rustls`) — Zero OpenSSL C Surface**:
   - `reqwest` is compiled with `default-features = false` and `rustls-tls`, eliminating native OpenSSL/C memory-safety vulnerabilities.
3. **Zero Client-Side Wasm/JS State Surface + Contextual HTML Auto-Escaping**:
   - All 8 workspace views are server-rendered HTML with strict contextual escaping ([`html_escape`](src/web.rs)) and a locked-down Content Security Policy (`default-src 'self'; frame-ancestors 'none'`).
4. **Constant-Time CSRF & Same-Origin Enforcement**:
   - Every state-changing `POST` endpoint validates a 256-bit session CSRF token in constant time using `subtle::ConstantTimeEq` ([`verify_csrf`](src/web.rs)) and enforces `Sec-Fetch-Site` (`same-origin` / `none`) + loopback `Origin` verification ([`same_origin_allowed`](src/web.rs)).
5. **Loopback-Only Binding & Keychain Isolation**:
   - [`src/main.rs`](src/main.rs) binds exclusively to `127.0.0.1:8080` by default and refuses non-loopback interfaces.
   - API keys and institutional TDM tokens are stored in the macOS Keychain via `/usr/bin/security` ([`KeychainStore`](src/providers.rs)), redacted from all transport errors, and never written to `library.json` or echoed in HTML.
   - `library.json` is written atomically via a temporary file with `0600` (owner-only) permissions ([`LibraryStore::save`](src/store.rs)).
6. **Domain & Evidence Integrity**:
   - **Abstract Exclusion**: Every Europe PMC query includes `NOT PUB_TYPE:"Abstract"`, and `Paper::is_conference_abstract` drops any conference abstract before full-text retrieval attempts in discovery, validation, and connection agents.
   - **Deduplication Before Cap**: [`PaperDeduplicator`](src/dedup.rs) bridges shared DOIs, PMIDs, PMCIDs, and source IDs before applying per-search caps (`50` for Dementia across 8 field + 7 mechanism journals + wider Europe PMC; `36` for Cancer across 8 field journals + wider Europe PMC).
   - **Author-Manuscript & TDM Fallback + Export Redaction**: [`FreeFullTextClient`](src/literature.rs) falls back to configured institutional TDM when an `AUTH_MAN:Y` record is absent from PMC BioC, and [`ResearchReportBuilder::paper`](src/report.rs) omits restricted `AUTH_MAN:Y` and TDM article bodies from exported reports while preserving short verified quotes (`>= 20` characters, word-bounded, negation-checked, SHA-256 checksummed).

## Project Structure

- [`Cargo.toml`](Cargo.toml) — Package manifest with `unsafe_code = "forbid"` and `rustls-tls`.
- [`src/models.rs`](src/models.rs) — Core domain models (`Paper`, `InstitutionalAccess`, `EvidenceCitation`, `HypothesisDraft`, `HypothesisValidation`, `DiscoveryCycle`, `ConnectionReview`, `LibrarySnapshot`).
- [`src/catalog.rs`](src/catalog.rs) — `ResearchSourceCatalog` (8 Dementia field journals, 7 Dementia mechanism journals, 8 Cancer field journals, and computed caps `50` / `36`).
- [`src/dedup.rs`](src/dedup.rs) — `PaperDeduplicator` transitive alias-bridge deduplication.
- [`src/citation.rs`](src/citation.rs) — `QuoteMatcher` and `EvidenceValidator` (20-char minimum, typographic folding, word boundaries, preceding negation guard, SHA-256 provenance).
- [`src/parsers.rs`](src/parsers.rs) — `ArticleTextParser` (`jats` with `<!ENTITY` XXE rejection, `bioc` JSON parser, `ElsevierArticleParser` with DOI verification).
- [`src/literature.rs`](src/literature.rs) — `PublicLiteratureUrlPolicy`, `EuropePmcClient`, `OpenAccessResolver`, `InstitutionalFullTextClient`, `FreeFullTextClient`, and `FreeLiteratureSearchClient`.
- [`src/datasets.rs`](src/datasets.rs) — `CancerDatasetUrlPolicy` and `CancerDatasetClient` (public NCI GDC & cBioPortal catalogs).
- [`src/providers.rs`](src/providers.rs) — `KeychainStore`, `ClaudeProvider`, and `OpenAiProvider` (`store: false`, `Policy::none()`, secret redaction).
- [`src/agents.rs`](src/agents.rs) — `AutonomousDiscoveryAgent`, `HypothesisValidationAgent` (4 mandatory search lenses), and `HypothesisConnectionAgent`.
- [`src/report.rs`](src/report.rs) — `ResearchReportBuilder` (Markdown and plain-text export with TDM/`AUTH_MAN:Y` body redaction).
- [`src/store.rs`](src/store.rs) — Atomic `0600` `LibraryStore` persistence and citation re-verification on load.
- [`src/swift_date.rs`](src/swift_date.rs) — Serde date format shared with the Swift app's `library.json` (seconds since 2001-01-01).
- [`src/web.rs`](src/web.rs) — Axum router, CSP/security-header middleware, constant-time CSRF verification, and SSR HTML views.
- [`tests/core_tests.rs`](tests/core_tests.rs) — Unit and integration test suite.

## Building, Testing & Running

### 1. Install Rust

If `cargo --version` reports `command not found`, install Rust with `rustup` (recommended):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

or with Homebrew:

```bash
brew install rust
```

`rustup` installs into `~/.cargo/bin` and adds it to your shell profile, which only takes effect in **new** shells. Open a new terminal window, or run `source "$HOME/.cargo/env"` in the current one, before continuing.

### 2. Test and run

From this directory (the one containing `Cargo.toml`):

```bash
cargo test
cargo run --release
```

The first build downloads and compiles all dependencies and takes a few minutes. When the server prints `listening on http://127.0.0.1:8080`, open that address in your browser.

### Configuration

- **Address**: set `DEMENTIA_RESEARCH_ADDR` to change the listening address, e.g. `DEMENTIA_RESEARCH_ADDR=127.0.0.1:3000 cargo run --release`. Only loopback addresses (`127.0.0.1`, `::1`) are accepted; anything else exits with an error.
- **API keys**: enter Claude/OpenAI keys and institutional TDM tokens in the app. They are stored in the macOS Keychain, not in environment variables or files.
- **Library location**: research state is saved to `~/Library/Application Support/DementiaResearch/library.json` on macOS (`~/.local/share/dementia-research/library.json` elsewhere).

### Sharing `library.json` with the Swift app

On macOS the Rust server and the Swift `DementiaResearch` app use the same `library.json`, and either app can open and save it:

- **Dates** are written in Swift's default `JSONEncoder` format, seconds since 2001-01-01 (e.g. `814019254.801979`), and round-trip exactly ([`src/swift_date.rs`](src/swift_date.rs)). RFC 3339 strings written by earlier builds of this port are still accepted when reading.
- **Paper abstracts** use Swift's `abstract` key (the older `abstractText` key is still read).
- **Swift notebook `runs`** are not used by the Rust app but are preserved verbatim on save, so saving from Rust never drops them. They are left out of the Rust app's JSON export.

Avoid running both apps at once: each keeps the library in memory and the last one to save wins.
