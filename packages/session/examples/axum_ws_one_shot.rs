//! axum WebSocket server with one-shot JWT tokens.
//!
//! Demonstrates the full auth chain:
//!   1. POST /login    → access token (long-lived)
//!   2. POST /ws-token → one-shot WS token (30s TTL, JTI-tracked)
//!   3. GET  /ws       → WebSocket upgrade with one-shot token (replay rejected)
//!
//! Run with:
//!   cargo run --example axum_ws_one_shot
//!
//! Then test:
//!   TOK=$(curl -s -X POST localhost:3000/login -d '{}' | jq -r .access_token)
//!   WS=$(curl -s -X POST localhost:3000/ws-token -H "Authorization: Bearer $TOK" | jq -r .ws_token)
//!   websocat "ws://localhost:3000/ws?token=$WS"

use std::sync::Arc;

use axum::{
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use kirino_session::{OneShotStore, SessionConfig, TokenClaims, TokenManager, TokenType};

// ── App state ────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    token_manager: Arc<TokenManager>,
    one_shot: OneShotStore,
}

// ── DTOs ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct WsQuery {
    token: String,
}

#[derive(Serialize)]
struct LoginResponse {
    access_token: String,
    expires_in: u64,
    user_id: String,
    username: String,
}

#[derive(Serialize)]
struct WsTokenResponse {
    ws_token: String,
    expires_in: u64,
}

// ── Handlers ─────────────────────────────────────────────────────

/// Simulated login — issues a long-lived access token.
async fn login(State(state): State<AppState>) -> Json<LoginResponse> {
    let user_id = Uuid::new_v4();
    let claims = TokenClaims::new(
        user_id,
        "demo-user".into(),
        TokenType::Access,
        3600,
        "kirino",
    );
    let access_token = state.token_manager.sign(&claims).unwrap();

    Json(LoginResponse {
        access_token,
        expires_in: 3600,
        user_id: user_id.to_string(),
        username: "demo-user".into(),
    })
}

/// Exchange an access token for a one-shot WS token.
///
/// The access token is verified, then a short-lived (30s) one-shot
/// token is issued.  Its JTI is pre-inserted into the OneShotStore
/// so the WS handler can reject replays.
async fn ws_token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<WsTokenResponse>, (StatusCode, String)> {
    let bearer = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "missing Bearer token".into()))?;

    let claims = state
        .token_manager
        .verify(bearer)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    let ws_claims = TokenClaims::new(
        Uuid::parse_str(&claims.sub).unwrap_or_default(),
        claims.username.clone(),
        TokenType::Access,
        30,
        "kirino",
    )
    .with_roles(claims.roles);

    let ws_token_str = state
        .token_manager
        .sign(&ws_claims)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(WsTokenResponse {
        ws_token: ws_token_str,
        expires_in: 30,
    }))
}

/// WebSocket upgrade — verifies the one-shot token and rejects replays.
async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let claims = state
        .token_manager
        .verify(&query.token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token".into()))?;

    // One-shot check — reject if JTI already used.
    if state.one_shot.check_and_mark(&claims.jti, claims.exp as i64) {
        return Err((StatusCode::UNAUTHORIZED, "token already used".into()));
    }

    Ok(ws.on_upgrade(move |socket| handle_ws(socket, claims.username)))
}

async fn handle_ws(mut socket: WebSocket, username: String) {
    let _ = socket
        .send(Message::Text(format!("Welcome, {username}!").into()))
        .await;

    while let Some(Ok(Message::Text(msg))) = socket.recv().await {
        if msg == "ping" {
            let _ = socket.send(Message::Text("pong".into())).await;
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let state = AppState {
        token_manager: Arc::new(TokenManager::new(SessionConfig::new("example-secret-do-not-use-in-prod"))),
        one_shot: OneShotStore::new(),
    };

    let app = Router::new()
        .route("/login", post(login))
        .route("/ws-token", post(ws_token))
        .route("/ws", get(ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}
