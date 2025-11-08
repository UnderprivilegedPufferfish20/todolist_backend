use std::sync::Arc;
use tokio::sync::RwLock;
use axum::{
    Router, extract::{self, Path, State}, http::StatusCode, response::{IntoResponse, Json}, routing::{get}
};
use uuid::Uuid;
use crate::{AppState, auth::AuthenticatedUser, routes::{CreateTodo, TodoItem, UpdateTodo, get_date}};

pub fn routes() -> Router<Arc<RwLock<AppState>>> {
    Router::new()
        .route("/", get(get_all_todos).post(create_todo))
        .route("/{todo_id}", get(get_todo).patch(update_todo).delete(delete_todo))
}

/// Get all todos for the authenticated user
async fn get_all_todos(
    AuthenticatedUser(user_id): AuthenticatedUser,
    State(st): State<Arc<RwLock<AppState>>>,
) -> impl IntoResponse {
    let state = st.read().await;

    match state.users.get(&user_id) {
        Some(user) => (StatusCode::OK, Json(user.todos.clone())).into_response(),
        None => (StatusCode::NOT_FOUND, "User not found").into_response()
    }
}

/// Create a new todo for the authenticated user
async fn create_todo(
    AuthenticatedUser(user_id): AuthenticatedUser,
    State(st): State<Arc<RwLock<AppState>>>,
    extract::Json(new_todo): extract::Json<CreateTodo>
) -> impl IntoResponse {
    // Validate input
    if new_todo.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "Todo name cannot be empty").into_response();
    }

    let todo = TodoItem {
        archived: false,
        cid: user_id.clone(),
        id: Uuid::new_v4().to_string(),
        name: new_todo.name.trim().to_string(),
        description: new_todo.description.trim().to_string(),
        done: false,
        archived_at: None,
        created_at: get_date().to_string(),
        updated_at: None,
        done_at: None,
    };

    // Write lock to modify user's todos
    let mut state = st.write().await;

    match state.users.get_mut(&user_id) {
        Some(user) => {
            user.todos.push(todo.clone());
            (StatusCode::CREATED, Json(todo)).into_response()
        },
        None => (StatusCode::NOT_FOUND, "User not found").into_response()
    }
}

/// Get a specific todo by ID
async fn get_todo(
    AuthenticatedUser(user_id): AuthenticatedUser,
    Path(todo_id): Path<String>,
    State(st): State<Arc<RwLock<AppState>>>,
) -> impl IntoResponse {
    let state = st.read().await;

    let user = match state.users.get(&user_id) {
        Some(u) => u,
        None => return (StatusCode::NOT_FOUND, "User not found").into_response()
    };

    match user.todos.iter().find(|t| t.id == todo_id) {
        Some(todo) => {
            if todo.cid != user_id {
                (StatusCode::FORBIDDEN, "You do not own this todo").into_response()
            } else {
                (StatusCode::OK, Json(todo.clone())).into_response()
            }
        },
        None => (StatusCode::NOT_FOUND, "Todo not found").into_response()
    }
}

/// Delete a todo by ID
async fn delete_todo(
    AuthenticatedUser(user_id): AuthenticatedUser,
    Path(todo_id): Path<String>,
    State(st): State<Arc<RwLock<AppState>>>,
) -> impl IntoResponse {
    let mut state = st.write().await;

    let user = match state.users.get_mut(&user_id) {
        Some(u) => u,
        None => return (StatusCode::NOT_FOUND, "User not found").into_response()
    };

    // Find the todo
    let todo = match user.todos.iter().find(|t| t.id == todo_id) {
        Some(t) => t.clone(),
        None => return (StatusCode::NOT_FOUND, "Todo not found").into_response()
    };

    // Verify ownership
    if todo.cid != user_id {
        return (StatusCode::FORBIDDEN, "You do not own this todo").into_response();
    }

    // Remove the todo
    user.todos.retain(|t| t.id != todo_id);

    (StatusCode::OK, Json(todo)).into_response()
}

/// Update a todo by ID
async fn update_todo( 
    AuthenticatedUser(user_id): AuthenticatedUser,
    Path(todo_id): Path<String>,
    State(st): State<Arc<RwLock<AppState>>>,
    extract::Json(update): extract::Json<UpdateTodo>
) -> impl IntoResponse {
    let mut state = st.write().await;

    let user = match state.users.get_mut(&user_id) {
        Some(u) => u,
        None => return (StatusCode::NOT_FOUND, "User not found").into_response()
    };

    let todo = match user.todos.iter_mut().find(|t| t.id == todo_id) {
        Some(t) => t,
        None => return (StatusCode::NOT_FOUND, "Todo not found").into_response()
    };

    // Verify ownership
    if todo.cid != user_id {
        return (StatusCode::FORBIDDEN, "You do not own this todo").into_response();
    }

    // Update fields
    let mut updated = false;

    if let Some(name) = update.name {
        if !name.trim().is_empty() {
            todo.name = name.trim().to_string();
            updated = true;
        }
    }

    if let Some(description) = update.description {
        todo.description = description.trim().to_string();
        updated = true;
    }

    if let Some(done) = update.done {
        todo.done = done;
        todo.done_at = if done { Some(get_date().to_string()) } else { None };
        updated = true;
    }

    if let Some(archived) = update.archived {
        todo.archived = archived;
        todo.archived_at = if archived { Some(get_date().to_string()) } else { None };
        updated = true;
    }

    if updated {
        todo.updated_at = Some(get_date().to_string());
    }

    (StatusCode::OK, Json(todo.clone())).into_response()
}