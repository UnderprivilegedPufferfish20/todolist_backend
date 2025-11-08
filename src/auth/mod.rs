use axum::{
    extract::FromRequestParts, http::StatusCode
};
use chrono::Duration;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use axum_extra::extract::CookieJar;
use jsonwebtoken::{decode, encode, Header, DecodingKey, EncodingKey, Validation};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2
};

use crate::routes::{TodoItem, get_date};

pub mod routes;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AuthClaims {
    pub uid: String,
    pub exp: usize,
    pub iat: usize
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)] // Never send password hash to client
    pub password_hash: String,
    pub todos: Vec<TodoItem>
}

#[derive(Deserialize, Debug)]
pub struct CreateAccount {
    pub username: String,
    pub password: String
}

#[derive(Deserialize, Debug, Clone)]
pub struct Login {
    pub username: String,
    pub password: String
}

/// Validates password strength
pub fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }
    if !password.chars().any(|c| c.is_numeric()) {
        return Err("Password must contain at least one number".to_string());
    }
    if !password.chars().any(|c| c.is_alphabetic()) {
        return Err("Password must contain at least one letter".to_string());
    }
    Ok(())
}

/// Hashes a password using Argon2
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {}", e))
        .map(|hash| hash.to_string())
}

/// Verifies a password against a hash using constant-time comparison
pub fn verify_password(password: &str, password_hash: &str) -> Result<(), String> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|e| format!("Invalid password hash: {}", e))?;
    
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| "Invalid password".to_string())
}

/// Generates a JWT token with the given user ID and secret key
pub fn gen_token(
    uid: String,
    secret: &str,
    ttl: Duration,
) -> Result<String, String> {
    let now = get_date();
    let expiration = now + ttl;
    let claims = AuthClaims {
        uid,
        exp: expiration.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| "Failed to generate token".to_string())
}

/// Validates a JWT token and returns the claims
pub fn validate_token<T: Clone + DeserializeOwned>(
    token: &str,
    secret: &str
) -> Result<T, String> {
    let claims = decode::<T>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| "Invalid token".to_string())?
    .claims;

    Ok(claims)
}

/// Extractor for authenticated users from session cookie
pub struct AuthenticatedUser(pub String);

/// Extractor for refresh token validation
pub struct AuthenticatedRefToken(pub String);

impl<S> FromRequestParts<S> for AuthenticatedUser
where 
    S: Send + Sync, 
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);

        let token = jar
            .get("session")
            .map(|cookie| cookie.value())
            .ok_or((StatusCode::UNAUTHORIZED, "Session cookie not found"))?;

        // Get JWT secret from extensions (added in main.rs)
        let jwt_secret = parts
            .extensions
            .get::<String>()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "JWT secret not configured"))?;

        let claims = validate_token::<AuthClaims>(token, jwt_secret)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid auth token"))?;

        Ok(AuthenticatedUser(claims.uid))
    }
}

impl<S> FromRequestParts<S> for AuthenticatedRefToken
where 
    S: Send + Sync, 
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);

        let token = jar
            .get("refresh_session")
            .map(|cookie| cookie.value())
            .ok_or((StatusCode::UNAUTHORIZED, "Refresh session cookie not found"))?;

        // Get JWT refresh secret from extensions
        let jwt_refresh_secret = parts
            .extensions
            .get::<String>()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "JWT refresh secret not configured"))?;

        let claims = validate_token::<AuthClaims>(token, jwt_refresh_secret)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid refresh token"))?;

        Ok(AuthenticatedRefToken(claims.uid))
    }
}