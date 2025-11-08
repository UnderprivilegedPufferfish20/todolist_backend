use std::env;

#[derive(Clone)]
pub struct Config {
    pub jwt_secret: String,
    pub jwt_refresh_secret: String,
    pub server_host: String,
    pub server_port: u16,
    pub cors_origins: Vec<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        dotenvy::dotenv().ok(); // Load .env file if it exists

        let jwt_secret = env::var("JWT_SECRET")
            .map_err(|_| "JWT_SECRET must be set")?;
        
        if jwt_secret.len() < 32 {
            return Err("JWT_SECRET must be at least 32 characters".to_string());
        }

        let jwt_refresh_secret = env::var("JWT_REFRESH_SECRET")
            .map_err(|_| "JWT_REFRESH_SECRET must be set")?;
        
        if jwt_refresh_secret.len() < 32 {
            return Err("JWT_REFRESH_SECRET must be at least 32 characters".to_string());
        }

        let server_host = env::var("SERVER_HOST")
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        
        let server_port = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .map_err(|_| "Invalid SERVER_PORT")?;

        let cors_origins = env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        Ok(Config {
            jwt_secret,
            jwt_refresh_secret,
            server_host,
            server_port,
            cors_origins,
        })
    }
}