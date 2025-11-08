use std::collections::HashMap;

use serde::{Serialize, Deserialize};
use chrono::{Utc, DateTime, FixedOffset};

use crate::auth::User;


pub mod routes;



#[derive(Deserialize)]
pub struct CreateTodo {
    name: String,
    description: String
}

#[derive(Deserialize)]
pub struct UpdateTodo {
    name: Option<String>,
    archived: Option<bool>,
    done: Option<bool>,
    description: Option<String>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TodoItem {
    name: String,
    done: bool,
    description: String,
    archived: bool,
    cid: String,
    id: String,
    created_at: String,
    done_at: String,
    updated_at: String,
    archived_at: String
}



pub fn get_date() -> DateTime<FixedOffset> {
    let now_utc: DateTime<Utc> = Utc::now();

    // Define the CST offset (UTC-6)
    let cst_offset = FixedOffset::west_opt(6 * 3600).unwrap(); 

    // Convert the UTC time to CST
    now_utc.with_timezone(&cst_offset)
}

pub fn get_user_by_name(
    username: String,
    users: HashMap<String, User>
) -> Option<User> {

    let user: Option<User> = users.values().find(|u| u.username == username).cloned();

    match user {
        Some(u) => return Some(u),
        None => return None
    }
}

pub fn get_todo_by_id(
    todo_id: String,
    todos: Vec<TodoItem>
) -> Option<TodoItem> {
    let requested_todo: Option<TodoItem> = todos.iter().find(|t| t.id == todo_id).cloned();

    return requested_todo
}
