use std::sync::Arc;
use axum::{
    Json, Router, extract::{self, State}, http::StatusCode, response::IntoResponse, routing::{get, post}
};
use chrono::Duration;
use tokio::sync::Mutex;
use axum_extra::extract::{CookieJar, cookie::Cookie};
use uuid::Uuid;
use crate::{auth::{AuthenticatedRefToken, CreateAccount, JWT_REF_SECRET, JWT_SECRET, Login, User, gen_token}, routes::get_user_by_name};
use crate::AppState;

pub fn routes() -> Router<Arc<Mutex<AppState>>> {
    Router::new()
        .route("/login", post(login))
        .route("/logout", get(logout))
        .route("/signup", post(signup))
        .route("/users", get(get_users))
        .route("/refresh", post(refresh))
}

async fn get_users(
    State(st): State<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    let state = st.lock().await;

    let users: Vec<User> = state.users.values().cloned().collect();

    return (StatusCode::OK, Json(users)).into_response()
}

#[axum::debug_handler]
async fn login(
    State(st): State<Arc<Mutex<AppState>>>,
    jar: CookieJar,
    extract::Json(deets): extract::Json<Login>,
) -> impl IntoResponse {
    let state = st.lock().await;

    let user = get_user_by_name(deets.username, state.users.clone());

    match user {
        Some(user) => {

            if user.password != deets.password {
                return StatusCode::UNAUTHORIZED.into_response()
            };
            
            let auth_token = match gen_token(user.id.clone(), JWT_SECRET, Duration::hours(1)) {
                Ok(t) => t,
                Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate auth token").into_response()
            };

            let ref_token = match gen_token(user.id.clone(), JWT_REF_SECRET, Duration::hours(8)) {
                Ok(t) => t,
                Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate refresh token").into_response()
            };

            // Set the JWT as an HttpOnly cookie
            let cookie = Cookie::build(("session", auth_token))
                .path("/")
                .http_only(true)
                .secure(true) // Should be secure in production (HTTPS)
                .same_site(axum_extra::extract::cookie::SameSite::Strict)
                .build();

            let ref_cookie = Cookie::build(("refresh_session", ref_token))
                .path("/")
                .http_only(true)
                .secure(true) // Should be secure in production (HTTPS)
                .same_site(axum_extra::extract::cookie::SameSite::Strict)
                .build();

            // Return the CookieJar with the added cookie
            (StatusCode::OK, jar.add(cookie).add(ref_cookie), "Login successful, cookie set").into_response()

        },
        None => return StatusCode::NOT_FOUND.into_response()
    }
}


async fn refresh(
    jar: CookieJar,
    AuthenticatedRefToken(user_id): AuthenticatedRefToken
) -> impl IntoResponse {

    let no_auth_jar = jar.remove("session");
    let no_ref_jar = no_auth_jar.remove("refresh_session");

    let new_auth_token = match gen_token(user_id.clone(), JWT_SECRET, Duration::hours(1)) {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate new auth token").into_response()
    };

    let new_ref_token = match gen_token(user_id.clone(), JWT_REF_SECRET, Duration::hours(8)) {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate new auth token").into_response()
    };

    let cookie = Cookie::build(("session", new_auth_token))
        .path("/")
        .http_only(true)
        .secure(true) // Should be secure in production (HTTPS)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .build();

    let ref_cookie = Cookie::build(("refresh_session", new_ref_token))
        .path("/")
        .http_only(true)
        .secure(true) // Should be secure in production (HTTPS)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .build();

    (StatusCode::OK, no_ref_jar.add(cookie).add(ref_cookie), "Refresh successful, cookies set").into_response()
    
}

async fn logout(
    jar: CookieJar
) -> impl IntoResponse {

    if let Some(_c) = jar.get("session") {
        let new_jar = jar.remove("session");

        (StatusCode::OK, new_jar).into_response()
    } else {
        StatusCode::OK.into_response()
    }
}


async fn signup(
    State(st): State<Arc<Mutex<AppState>>>,
    extract::Json(accnt_info): extract::Json<CreateAccount>
) -> impl IntoResponse {
    let mut state = st.lock().await;

    let user = get_user_by_name(accnt_info.username.clone(), state.users.clone());

    match user {
        Some(_) => StatusCode::CONFLICT.into_response(),
        None => {
            let new_user = User {
                todos: vec![],
                id: Uuid::new_v4().to_string(),
                username: accnt_info.username,
                password: accnt_info.password
            };

            state.users.insert(new_user.id.clone(), new_user);

            StatusCode::CREATED.into_response()
        }
    }
}