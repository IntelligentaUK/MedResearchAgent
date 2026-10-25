# Medical Research Agent — Hardened Rust Full-Stack Web Port (`Axum` + `rustls`)

This directory contains a complete, memory-safe, security-hardened Rust full-stack web application port of the `DementiaResearch` autonomous medical research agent (supporting both **Dementia** and **Cancer** research profiles).

## Why `Axum` + SSR + `rustls` + `#![forbid(unsafe_code)]`?

To minimize attack surface while handling untrusted scientific literature (JATS XML, PMC BioC JSON, Elsevier XML, OpenAlex metadata, NCI GDC & cBioPortal catalogs) and LLM outputs:

1. **Compiler-Enforced Memory Safety (`#![forbid(unsafe_code)]`)**:
   - Configured in [`Cargo.toml`](Cargo.toml) (`[lints.rust] unsafe_code = "forbid"`), [`src/lib.rs`](src/lib.rs), and [`src/main.rs`](src/main.rs).
   - Built on **Axum** (`tokio-rs/axum`) and **Tower**, which have `#![forbid(unsafe_code)]` at the HTTP routing and extractor layer (unlike frameworks that rely on internal `unsafe` actor/pointer abstractions).
2. **Pure-Rust TLS (`rustls`) — Zero OpenSSL C Surface**:
   - `reqwest` is compiled with `default-features = false` and `rustls-tls`, eliminating native OpenSSL/C memory-safety vulnerabilities.
3. **Server-Rendered Views, Minimal Same-Origin Script + Contextual HTML Auto-Escaping**:
   - All 8 workspace views are server-rendered HTML with strict contextual escaping ([`html_escape`](src/web.rs)) and a locked-down Content Security Policy (`default-src 'self'; script-src 'self'; frame-ancestors 'none'`; no inline scripts).
   - One small same-origin script (`/static/app.js`) keeps the activity panel live. It builds every element with `textContent` and holds no application state; without it, the pages still work and show progress on reload.
4. **Constant-Time CSRF & Same-Origin Enforcement**:
   - Every state-changing `POST` endpoint validates a 256-bit session CSRF token in constant time using `subtle::ConstantTimeEq` ([`verify_csrf`](src/web.rs)) and enforces `Sec-Fetch-Site` (`same-origin` / `none`) + loopback `Origin` verification ([`same_origin_allowed`](src/web.rs)).
5. **Loopback-Only Binding & OS Secret Storage**:
   - [`src/main.rs`](src/main.rs) binds exclusively to `127.0.0.1:8080` by default and refuses non-loopback interfaces.
   - API keys and institutional TDM tokens are stored in the operating system's secret store ([`KeychainStore`](src/providers.rs)): the macOS Keychain (through the Apple-signed `/usr/bin/security`, with secrets passed on stdin rather than the command line), Windows Credential Manager, or the Linux Secret Service. They are redacted from all transport errors and never written to `library.json` or echoed in HTML.
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
- [`src/providers.rs`](src/providers.rs) — `KeychainStore`, `ClaudeProvider`, `OpenAiProvider` (`store: false`, `Policy::none()`, secret redaction), and `ChatGptPlanProvider` (streaming Responses API billed to a ChatGPT plan).
- [`src/chatgpt.rs`](src/chatgpt.rs) — "Sign in with ChatGPT" (OAuth 2.0 + PKCE + OpenID Connect, dynamic client registration, ID-token verification against OpenAI's JWKS, token refresh and revocation).
- [`src/agents.rs`](src/agents.rs) — `AutonomousDiscoveryAgent`, `HypothesisValidationAgent` (4 mandatory search lenses), and `HypothesisConnectionAgent`.
- [`src/report.rs`](src/report.rs) — `ResearchReportBuilder` (Markdown and plain-text export with TDM/`AUTH_MAN:Y` body redaction).
- [`src/store.rs`](src/store.rs) — Atomic `0600` `LibraryStore` persistence and citation re-verification on load.
- [`src/swift_date.rs`](src/swift_date.rs) — Serde date format shared with the Swift app's `library.json` (seconds since 2001-01-01).
- [`src/web.rs`](src/web.rs) — Axum router, CSP/security-header middleware, constant-time CSRF verification, SSR HTML views, and the `/events` progress stream.
- [`src/jobs.rs`](src/jobs.rs) — `JobRunner`: background research stages, one at a time, with progress broadcast to open pages.
- [`src/model_catalog.rs`](src/model_catalog.rs) — Live per-provider model lists and the remembered model choice.
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
- **Model access**: either **Continue with ChatGPT** (see below) or enter Claude/OpenAI API keys in **Sources & credentials**.
- **Data directory**: `library.json` and the ChatGPT credential files live in the per-user data directory, printed at startup. Set `DEMENTIA_RESEARCH_DATA_DIR` (an absolute path) to use another one.

  | OS | Data directory |
  |---|---|
  | macOS | `~/Library/Application Support/DementiaResearch` (shared with the Swift app) |
  | Windows | `%APPDATA%\DementiaResearch` |
  | Linux and other Unix | `$XDG_DATA_HOME/dementia-research`, else `~/.local/share/dementia-research` |

- **Where API keys are stored**: the startup output and **Sources & credentials** both say which store is in use.

  | OS | Secret store |
  |---|---|
  | macOS | Login Keychain (service `DementiaResearch`) |
  | Windows | Windows Credential Manager (DPAPI-encrypted, per user) |
  | Linux desktop | Secret Service: GNOME Keyring, KWallet or KeePassXC |
  | No secret store (servers, containers, WSL) | Owner-only `secrets.json` in the data directory, with a warning |

  The store is chosen when the app starts, so after installing or unlocking a keyring, restart the app to use it. Keys are never moved between stores automatically.

### Sign in with ChatGPT

**Sources & credentials → Continue with ChatGPT** signs in with a ChatGPT account using OpenAI's [open-source/local "Sign in with ChatGPT" flow](https://developers.openai.com/siwc/token-sharing-open-source), so model stages run on the user's ChatGPT plan instead of an API key. No client secret or API key is needed: OpenAI registers this installation during the first sign-in.

- **Where to sign in**: OpenAI redirects back to `http://127.0.0.1:<port>/auth/callback` on this server, so start sign-in from a browser on the computer running the app.
- **Plan usage**: requests count toward the user's ChatGPT plan, subject to OpenAI's eligibility rules (at launch: open-source projects, personal local projects and selected private apps). Users set per-app limits at [chatgpt.com/settings/usage](https://chatgpt.com/settings/usage). If plan usage was declined at sign-in, **Use your ChatGPT plan** asks again.
- **Plan errors** such as **Usage limit reached** stop the run; the app never switches to another billing path on its own.
- **Credentials**: tokens are stored in `chatgpt-auth.json` (and the installation's host ID in `chatgpt-host.json`) next to `library.json`, written atomically with `0600` permissions and never placed in the library, HTML or logs. Access tokens are refreshed automatically. **Sign out** revokes the session with OpenAI and deletes the tokens, keeping the registration for the next sign-in.

### Live progress

Discovery cycles, validations and connection reviews run in the background, one at a time. After you start one, an **activity panel** at the top of every page shows each step as it happens (model requests by phase, literature searches, full-text reads), streamed from `/events` (server-sent events). When the stage finishes, the panel shows the outcome and the page content updates in place with the new results; no manual refresh is needed. A stage keeps running if you close the page, and the panel shows its latest state when you return. Run buttons are disabled while a stage is running.

### Choosing a model

The research loop's **Model** menu lists, live from each provider's API, the models your ChatGPT plan, Claude key and OpenAI key can use (cached for an hour, refreshed when credentials change; OpenAI's list is limited to text-generation models).

- **A model you pick** is remembered in `preferences.json` in the data directory and is also used by **Validate** and **Connection review**. The page says which model those will use.
- **Automatic** forgets the remembered choice and uses the first provider that is set up (ChatGPT plan, then Claude, then OpenAI) with its default: `claude-opus-5-5` for Claude, otherwise the first model the provider lists.
- If a provider's list can't be fetched, the page says why; Claude then still offers `claude-opus-5-5`.
- Each discovery cycle, validation and connection review records the provider and model that produced it, shown on its card and in exports.

### Sharing `library.json` with the Swift app

On macOS the Rust server and the Swift `DementiaResearch` app use the same `library.json`, and either app can open and save it:

- **Dates** are written in Swift's default `JSONEncoder` format, seconds since 2001-01-01 (e.g. `814019254.801979`), and round-trip exactly ([`src/swift_date.rs`](src/swift_date.rs)). RFC 3339 strings written by earlier builds of this port are still accepted when reading.
- **Paper abstracts** use Swift's `abstract` key (the older `abstractText` key is still read).
- **Swift notebook `runs`** are not used by the Rust app but are preserved verbatim on save, so saving from Rust never drops them. They are left out of the Rust app's JSON export.

Avoid running both apps at once: each keeps the library in memory and the last one to save wins.
