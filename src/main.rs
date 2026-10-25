#![forbid(unsafe_code)]

use dementia_research_web::providers::KeychainStore;
use dementia_research_web::store::LibraryStore;
use dementia_research_web::web::{build_router, AppState};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = LibraryStore::default_store();
    let keychain = KeychainStore::system();
    let state = AppState::new(store, keychain)?;
    let app = build_router(state);

    // Loopback-only binding by default so local research state and Keychain-backed routes
    // are never exposed to LAN interfaces.
    let addr: SocketAddr = std::env::var("DEMENTIA_RESEARCH_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8080)));

    if !addr.ip().is_loopback() {
        eprintln!("Refusing to bind to non-loopback address {addr}. Use 127.0.0.1 or ::1.");
        std::process::exit(1);
    }

    println!("Medical Research Agent (Hardened Rust/Axum SSR) listening on http://{addr}");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
