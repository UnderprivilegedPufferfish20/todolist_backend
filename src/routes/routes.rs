use std::{sync::Arc};
use tokio::sync::Mutex;
use axum::{
    Router, extract::{self, Path, State}, http::StatusCode, response::{IntoResponse, Json}, routing::{get, patch}
};
use uuid::Uuid;
use crate::{AppState, auth::AuthenticatedUser, routes::{CreateTodo, TodoItem, UpdateTodo, get_date, get_todo_by_id}};


pub fn routes() -> Router<Arc<Mutex<AppState>>> {
    Router::new()
        .route("/", get(get_all_todos).post(create_todo))
        .route("/{todo_id}", patch(update_todo).delete(delete_todo).get(get_todo))
}

async fn get_all_todos(
    AuthenticatedUser(user_id): AuthenticatedUser,
    State(st): State<Arc<Mutex<AppState>>>,
) -> Json<Vec<TodoItem>> {
    let state = st.lock().await;

    Json(state.users[&user_id].todos.clone())
}

async fn create_todo(
    AuthenticatedUser(user_id): AuthenticatedUser,
    State(st): State<Arc<Mutex<AppState>>>,
    extract::Json(new_todo): extract::Json<CreateTodo>
) -> impl IntoResponse {
    let mut state = st.lock().await;

    let new_todo = TodoItem {
        archived: false,
        cid: user_id.clone(),
        id: Uuid::new_v4().to_string(),
        name: new_todo.name,
        description: new_todo.description,
        done: false,
        archived_at: "".to_string(),
        created_at: get_date().to_string(),
        updated_at: "".to_string(),
        done_at: "".to_string(),
    };

    let users_todos = state.users.get_mut(&user_id).cloned();

    match users_todos {
        Some(mut u) => {   
            u.todos.push(new_todo.clone());

            return (StatusCode::CREATED, Json(new_todo)).into_response()
        },
        None => return (StatusCode::NOT_FOUND, "User dones't exist").into_response()
    }

}

async fn get_todo(
    AuthenticatedUser(user_id): AuthenticatedUser,
    Path(todo_id): Path<String>,
    State(st): State<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    let state = st.lock().await;

    let user = state.users[&user_id].clone();

    if let Some(t) = get_todo_by_id(todo_id, user.todos) {
        if t.cid != user_id {
            (StatusCode::UNAUTHORIZED, "You do not own this todo").into_response()
        } else {
            (StatusCode::OK, Json(t.clone())).into_response()
        }


    } else {
        StatusCode::NOT_FOUND.into_response()
    }

}

async fn delete_todo(
    AuthenticatedUser(user_id): AuthenticatedUser,
    Path(todo_id): Path<String>,
    State(st): State<Arc<Mutex<AppState>>>,
) -> impl IntoResponse {
    let mut state = st.lock().await;

    let user = state.users.get_mut(&user_id);

    match user {
        Some(todos) => {
            let requested_todo = get_todo_by_id(todo_id, todos);
        
            if let Some(t) = requested_todo {
        
                if t.cid != user_id {
                    return (StatusCode::UNAUTHORIZED, "You do not own this todo").into_response()
                } else {
        
        
        
                    todos.retain(|t| t.id != todo_id);
                
                    return (StatusCode::OK, Json(t.clone())).into_response()
                }
        
            } else {
                return StatusCode::NOT_FOUND.into_response()
        
            }
        },
        None => return (StatusCode::NOT_FOUND, "User not found").into_response()
    }
    

    
    
    

}

async fn update_todo( 
    AuthenticatedUser(user_id): AuthenticatedUser,
    Path(todo_id): Path<String>,
    State(st): State<Arc<Mutex<AppState>>>,
    extract::Json(new_todo): extract::Json<UpdateTodo>
) -> impl IntoResponse {

    let mut state = st.lock().await;

    let requested_todo = state.todos.iter_mut().find(|t| t.id == todo_id).cloned();
    
    if let Some(mut t) = requested_todo {

        if t.cname != username {
            return (StatusCode::UNAUTHORIZED, "You do not own this todo").into_response()
        };

        t.updated_at = get_date().to_string();
         
        if let Some(n) = new_todo.name {
            t.name = n
        };

        if let Some(arch) = new_todo.archived {
            t.archived = arch;
            t.archived_at = get_date().to_string()
        };

        if let Some(desc) = new_todo.description {
            t.description = desc
        };

        if let Some(d) = new_todo.done {
            t.done = d;
            t.done_at = get_date().to_string()
        };

        state.todos.retain(|tod| tod.id != todo_id);

        state.todos.push(t.clone());

        (StatusCode::OK, Json(t)).into_response()

    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}