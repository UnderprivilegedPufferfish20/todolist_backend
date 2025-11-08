use serde::{Serialize, Deserialize};
use chrono::{Utc, DateTime, FixedOffset};

pub mod routes;

#[derive(Deserialize)]
pub struct CreateTodo {
    pub name: String,
    pub description: String
}

#[derive(Deserialize)]
pub struct UpdateTodo {
    pub name: Option<String>,
    pub archived: Option<bool>,
    pub done: Option<bool>,
    pub description: Option<String>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TodoItem {
    pub name: String,
    pub done: bool,
    pub description: String,
    pub archived: bool,
    pub cid: String,  // Creator/owner ID
    pub id: String,
    pub created_at: String,
    pub done_at: Option<String>,
    pub updated_at: Option<String>,
    pub archived_at: Option<String>
}

/// Gets current date/time in CST timezone
pub fn get_date() -> DateTime<FixedOffset> {
    let now_utc: DateTime<Utc> = Utc::now();
    let cst_offset = FixedOffset::west_opt(6 * 3600).unwrap(); 
    now_utc.with_timezone(&cst_offset)
}