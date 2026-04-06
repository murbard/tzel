use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use starkprivacy_cli::*;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

type AppState = Arc<Mutex<Ledger>>;

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value = "8080")]
    port: u16,
}

fn err(s: String) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, s)
}

async fn fund_handler(
    State(st): State<AppState>,
    Json(req): Json<FundReq>,
) -> Json<serde_json::Value> {
    let mut ledger = st.lock().unwrap();
    ledger.fund(&req.addr, req.amount);
    eprintln!("[fund] {} += {}", req.addr, req.amount);
    Json(serde_json::json!({"ok": true}))
}

async fn shield_handler(
    State(st): State<AppState>,
    Json(req): Json<ShieldReq>,
) -> Result<Json<ShieldResp>, (StatusCode, String)> {
    let mut ledger = st.lock().unwrap();
    let resp = ledger.shield(&req).map_err(err)?;
    eprintln!(
        "[shield] {} deposited {} -> cm={} idx={}",
        req.sender,
        req.v,
        short(&resp.cm),
        resp.index
    );
    Ok(Json(resp))
}

async fn transfer_handler(
    State(st): State<AppState>,
    Json(req): Json<TransferReq>,
) -> Result<Json<TransferResp>, (StatusCode, String)> {
    let mut ledger = st.lock().unwrap();
    let n = req.nullifiers.len();
    let resp = ledger.transfer(&req).map_err(err)?;
    eprintln!(
        "[transfer] N={} -> idx={},{} (cm1={} cm2={})",
        n,
        resp.index_1,
        resp.index_2,
        short(&req.cm_1),
        short(&req.cm_2)
    );
    Ok(Json(resp))
}

async fn unshield_handler(
    State(st): State<AppState>,
    Json(req): Json<UnshieldReq>,
) -> Result<Json<UnshieldResp>, (StatusCode, String)> {
    let mut ledger = st.lock().unwrap();
    let n = req.nullifiers.len();
    let resp = ledger.unshield(&req).map_err(err)?;
    eprintln!(
        "[unshield] N={} -> {} to {} (change idx={:?})",
        n, req.v_pub, req.recipient, resp.change_index
    );
    Ok(Json(resp))
}

#[derive(serde::Deserialize)]
struct CursorParam {
    cursor: Option<usize>,
}

async fn notes_handler(
    State(st): State<AppState>,
    Query(params): Query<CursorParam>,
) -> Json<NotesFeedResp> {
    let ledger = st.lock().unwrap();
    let cursor = params.cursor.unwrap_or(0);
    let notes: Vec<NoteMemo> = ledger
        .memos
        .iter()
        .enumerate()
        .skip(cursor)
        .map(|(i, (cm, enc))| NoteMemo {
            index: i,
            cm: *cm,
            enc: enc.clone(),
        })
        .collect();
    let next_cursor = ledger.memos.len();
    Json(NotesFeedResp {
        notes,
        next_cursor,
    })
}

async fn tree_handler(State(st): State<AppState>) -> Json<TreeInfoResp> {
    let ledger = st.lock().unwrap();
    Json(TreeInfoResp {
        root: ledger.tree.root(),
        size: ledger.tree.leaves.len(),
        depth: DEPTH,
    })
}

async fn nullifiers_handler(State(st): State<AppState>) -> Json<NullifiersResp> {
    let ledger = st.lock().unwrap();
    Json(NullifiersResp {
        nullifiers: ledger.nullifiers.iter().cloned().collect(),
    })
}

async fn balances_handler(State(st): State<AppState>) -> Json<BalanceResp> {
    let ledger = st.lock().unwrap();
    Json(BalanceResp {
        balances: ledger.balances.clone(),
    })
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let state: AppState = Arc::new(Mutex::new(Ledger::new()));

    let app = Router::new()
        .route("/fund", post(fund_handler))
        .route("/shield", post(shield_handler))
        .route("/transfer", post(transfer_handler))
        .route("/unshield", post(unshield_handler))
        .route("/notes", get(notes_handler))
        .route("/tree", get(tree_handler))
        .route("/nullifiers", get(nullifiers_handler))
        .route("/balances", get(balances_handler))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cli.port);
    eprintln!("sp-ledger listening on {}", addr);
    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
