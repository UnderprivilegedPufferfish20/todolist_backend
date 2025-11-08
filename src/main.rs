use std::{collections::HashMap, sync::Arc};
use axum::{
    body::Body, http::{Request, header}, middleware, response::{Html, IntoResponse}, routing::get
};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use crate::auth::User;
use crate::config::Config;

pub mod auth;
pub mod routes;
pub mod config;

pub struct AppState {
    pub users: HashMap<String, User>,
    pub username_to_id: HashMap<String, String>, // Index for O(1) username lookups
    pub config: Config,
}

#[tokio::main]
async fn main() {
    // Load configuration
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    println!("Starting server on {}:{}", config.server_host, config.server_port);

    // Configure CORS with specific allowed origins
    let cors = CorsLayer::new()
        .allow_origin(
            config.cors_origins
                .iter()
                .map(|o| o.parse().expect("Invalid CORS origin"))
                .collect::<Vec<_>>()
        )
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true);

    let init_state = AppState {
        users: HashMap::new(),
        username_to_id: HashMap::new(),
        config: config.clone(),
    };

    let state = Arc::new(RwLock::new(init_state));

    // Build the application router
    let app = axum::Router::new()
        .route("/", get(hello_route))
        .nest("/todos", routes::routes::routes())
        .nest("/auth", auth::routes::routes())
        .layer(middleware::from_fn(add_jwt_secrets))
        .with_state(state)
        .layer(cors);

    let addr = format!("{}:{}", config.server_host, config.server_port);
    let listener = TcpListener::bind(&addr).await
        .expect("Failed to bind to address");

    println!("Server listening on http://{}", addr);

    axum::serve(listener, app).await
        .expect("Failed to start server");
}

/// Middleware to inject JWT secrets into request extensions
async fn add_jwt_secrets(
    mut req: Request<Body>,
    next: middleware::Next,
) -> impl IntoResponse {
    // Get config from environment (in production, use a more efficient approach)
    if let Ok(config) = Config::from_env() {
        req.extensions_mut().insert(config.jwt_secret);
        req.extensions_mut().insert(config.jwt_refresh_secret);
    }
    next.run(req).await
}

async fn hello_route() -> impl IntoResponse {
    Html("<h1>Todo List API</h1><p>Status: <strong>Operational</strong></p>")
}