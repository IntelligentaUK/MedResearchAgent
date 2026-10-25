#![forbid(unsafe_code)]

use dementia_research_web::providers::KeychainStore;
use dementia_research_web::store::{data_dir, LibraryStore};
use dementia_research_web::web::{build_router, AppState};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = data_dir();
    let store = LibraryStore::new(data_dir.join("library.json"));
    let keychain = KeychainStore::system(&data_dir);
    println!("Data directory: {}", data_dir.display());
    println!("Credentials are stored in {}.", keychain.backend().describe());
    if !keychain.backend().is_encrypted_store() {
        eprintln!("No system secret store was found, so API keys are kept in an owner-only file instead.");
    }
    let state = AppState::new(store, keychain)?;
    let app = build_router(state.clone());

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
    println!();
    println!("Open this start link in your browser (it sets the session cookie; every other");
    println!("local client, including other users on this computer, is refused):");
    println!("  {}", state.start_link(&addr));
    println!();
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
