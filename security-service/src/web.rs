use std::path::Path;

use axum::Router;
use tower_http::services::{ServeDir, ServeFile};

/// Serve the Vite build and let the client router handle unknown browser paths.
pub fn routes(directory: &Path) -> Router {
    let index = directory.join("index.html");
    Router::new()
        .fallback_service(ServeDir::new(directory).not_found_service(ServeFile::new(index)))
}
