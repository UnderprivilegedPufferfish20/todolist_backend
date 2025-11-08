use axum::{
    extract::FromRequestParts, http::StatusCode
};
use chrono::Duration;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use axum_extra::extract::{CookieJar};
use jsonwebtoken::{decode, encode, Header, DecodingKey, EncodingKey, Validation};

use crate::routes::{TodoItem, get_date};

pub mod routes;

const JWT_SECRET: &[u8] = b"THE_JWT_SECRET";
const JWT_REF_SECRET: &[u8] = b"THE_REFRESH_SECRET";

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
    pub password: String,
    pub todos: Vec<TodoItem>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateAccount {
    username: String,
    password: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Login {
    username: String,
    password: String
}

pub fn gen_token(
    uid: String,
    key: &[u8],
    ttl: Duration,
) -> Result<String, String> {

    let now = get_date();
    let expiration = now + ttl;
    let claims = AuthClaims {
        uid,
        exp: expiration.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(key),
    ) {
        Ok(t) => return Ok(t),
        Err(_) => return Err("Failed to generate token".to_string()),
    };
}

pub fn validate_token<T: Clone + DeserializeOwned>(
    token: String,
    key: &[u8]
) -> Result<T, String> {
    let claims = decode::<T>(
        &token,
        &DecodingKey::from_secret(key),
        &Validation::default(),
    )
    .map_err(|_| "Invalid token".to_string())?
    .claims;

    Ok(claims.clone())
}




pub struct AuthenticatedUser(pub String);
pub struct AuthenticatedRefToken(pub String);

impl<S> FromRequestParts<S> for AuthenticatedUser
where 
    S: Send + Sync, 
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Cookie extraction failed"))?;

        // Get the token from the "session" cookie
        let token = jar
            .get("session")
            .map(|cookie| cookie.value().to_owned())
            .ok_or((StatusCode::UNAUTHORIZED, "Session Cookie Not Found"))?;


        let claims = validate_token::<AuthClaims>(token, JWT_SECRET);

        match claims {
            Ok(c) => return Ok(AuthenticatedUser(c.uid)),
            Err(_) => return Err((StatusCode::UNAUTHORIZED, "Invalid Auth Token"))
        }

    }
}

impl<S> FromRequestParts<S> for AuthenticatedRefToken
where 
    S: Send + Sync, 
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Cookie extraction failed"))?;

        // Get the token from the "session" cookie
        let token = jar
            .get("refresh_session")
            .map(|cookie| cookie.value().to_owned())
            .ok_or((StatusCode::UNAUTHORIZED, "Refresh Session Cookie Not Found"))?;


        let claims = validate_token::<AuthClaims>(token, JWT_REF_SECRET);

        match claims {
            Ok(c) => return Ok(AuthenticatedRefToken(c.uid)),
            Err(_) => return Err((StatusCode::UNAUTHORIZED, "Invalid Refresh Token"))
        }

    }
}



