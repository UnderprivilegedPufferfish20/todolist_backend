use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use axum::{response::{Html, IntoResponse}, routing::get};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use crate::{auth::User};
use tower_http::cors::{CorsLayer, Any};

pub mod auth;
pub mod routes;


pub struct AppState {
    pub users: HashMap<String, User>
}


#[tokio::main]
async fn main() {

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let init_state = AppState {
        users: HashMap::new()
    };

    let app = axum::Router::new()
        .route("/", get(hello_route))
        .nest("/todos", routes::routes::routes())
        .nest("/auth", auth::routes::routes())
        .with_state(Arc::new(Mutex::new(init_state)))
        .layer(cors);

    let addr = SocketAddr::from(([127,0,0,1], 8080));

    let listener = TcpListener::bind(&addr).await.unwrap();

    axum::serve(
        listener,
        app
    ).await.unwrap();
}


async fn hello_route() -> impl IntoResponse {
    Html("Todolist Backend is <strong>operational</strong>")
}
