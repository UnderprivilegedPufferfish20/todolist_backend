use std::sync::Arc;
use axum::{
    Json, Router, extract::{self, State}, http::StatusCode, response::IntoResponse, routing::{post}
};
use chrono::Duration;
use tokio::sync::RwLock;
use axum_extra::extract::{CookieJar, cookie::Cookie};
use uuid::Uuid;
use crate::{
    auth::{
        AuthenticatedRefToken, CreateAccount, Login, User, 
        gen_token, hash_password, validate_password, verify_password
    }
};
use crate::AppState;

pub fn routes() -> Router<Arc<RwLock<AppState>>> {
    Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/signup", post(signup))
        .route("/refresh", post(refresh))
}

/// Login endpoint - authenticates user and sets session cookies
async fn login(
    State(st): State<Arc<RwLock<AppState>>>,
    jar: CookieJar,
    extract::Json(credentials): extract::Json<Login>,
) -> impl IntoResponse {
    // Read lock for user lookup - allows concurrent reads
    let state = st.read().await;
    
    // Find user by username (O(1) with our new index)
    let user_id = match state.username_to_id.get(&credentials.username) {
        Some(id) => id,
        None => return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
    };

    let user = match state.users.get(user_id) {
        Some(u) => u,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "User data inconsistent").into_response()
    };

    // Verify password with constant-time comparison
    if let Err(_) = verify_password(&credentials.password, &user.password_hash) {
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
    }

    // Clone user ID and config before releasing lock
    let user_id = user.id.clone();
    let config = state.config.clone();
    drop(state); // Explicitly release lock before expensive operations

    // Generate tokens outside of lock (expensive operations)
    let auth_token = match gen_token(user_id.clone(), &config.jwt_secret, Duration::hours(1)) {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate auth token").into_response()
    };

    let ref_token = match gen_token(user_id, &config.jwt_refresh_secret, Duration::hours(8)) {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate refresh token").into_response()
    };

    // Build secure cookies
    let cookie = Cookie::build(("session", auth_token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .build();

    let ref_cookie = Cookie::build(("refresh_session", ref_token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .build();

    (StatusCode::OK, jar.add(cookie).add(ref_cookie), Json(serde_json::json!({
        "message": "Login successful"
    }))).into_response()
}

/// Refresh endpoint - generates new tokens from valid refresh token
async fn refresh(
    State(st): State<Arc<RwLock<AppState>>>,
    jar: CookieJar,
    AuthenticatedRefToken(user_id): AuthenticatedRefToken
) -> impl IntoResponse {
    // Verify user still exists
    let state = st.read().await;
    if !state.users.contains_key(&user_id) {
        return (StatusCode::UNAUTHORIZED, "User not found").into_response();
    }
    
    let config = state.config.clone();
    drop(state);

    // Remove old cookies
    let jar = jar.remove("session").remove("refresh_session");

    // Generate new tokens
    let new_auth_token = match gen_token(user_id.clone(), &config.jwt_secret, Duration::hours(1)) {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate auth token").into_response()
    };

    let new_ref_token = match gen_token(user_id, &config.jwt_refresh_secret, Duration::hours(8)) {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate refresh token").into_response()
    };

    let cookie = Cookie::build(("session", new_auth_token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .build();

    let ref_cookie = Cookie::build(("refresh_session", new_ref_token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .build();

    (StatusCode::OK, jar.add(cookie).add(ref_cookie), Json(serde_json::json!({
        "message": "Tokens refreshed"
    }))).into_response()
}

/// Logout endpoint - removes session cookies
async fn logout(jar: CookieJar) -> impl IntoResponse {
    let jar = jar.remove("session").remove("refresh_session");
    (StatusCode::OK, jar, Json(serde_json::json!({
        "message": "Logged out successfully"
    }))).into_response()
}

/// Signup endpoint - creates new user account
async fn signup(
    State(st): State<Arc<RwLock<AppState>>>,
    extract::Json(account_info): extract::Json<CreateAccount>
) -> impl IntoResponse {
    // Validate username
    if account_info.username.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "Username cannot be empty").into_response();
    }

    if account_info.username.len() < 3 {
        return (StatusCode::BAD_REQUEST, "Username must be at least 3 characters").into_response();
    }

    // Validate password strength
    if let Err(e) = validate_password(&account_info.password) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    // Hash password outside of lock
    let password_hash = match hash_password(&account_info.password) {
        Ok(h) => h,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password").into_response()
    };

    // Write lock for user creation
    let mut state = st.write().await;

    // Check if username already exists
    if state.username_to_id.contains_key(&account_info.username) {
        return (StatusCode::CONFLICT, "Username already taken").into_response();
    }

    let new_user = User {
        todos: Vec::new(),
        id: Uuid::new_v4().to_string(),
        username: account_info.username.clone(),
        password_hash,
    };

    // Insert into both maps
    state.username_to_id.insert(account_info.username, new_user.id.clone());
    state.users.insert(new_user.id.clone(), new_user);

    (StatusCode::CREATED, Json(serde_json::json!({
        "message": "Account created successfully"
    }))).into_response()
}