use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{
    inbox::ExternalMessageFrame, smart_rollup::SmartRollupAddress,
};
use tzel_core::operator_api::{
    RollupSubmission, RollupSubmissionKind, RollupSubmissionStatus, RollupSubmissionTransport,
    SubmitRollupMessageReq, SubmitRollupMessageResp,
};

#[derive(Parser, Debug)]
#[command(name = "tzel-operator", about = "TzEL rollup operator submission service")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
    #[arg(long)]
    source_alias: String,
    #[arg(long, default_value = "operator-state")]
    state_dir: String,
    #[arg(long, default_value_t = 4096)]
    direct_max_message_bytes: usize,
    #[arg(long, default_value = "octez-client")]
    octez_client_bin: String,
    #[arg(long)]
    octez_client_dir: Option<String>,
    #[arg(long)]
    octez_node_endpoint: Option<String>,
    #[arg(long)]
    octez_protocol: Option<String>,
}

#[derive(Clone)]
struct AppState {
    config: Arc<OperatorConfig>,
}

#[derive(Debug)]
struct OperatorConfig {
    source_alias: String,
    state_dir: PathBuf,
    direct_max_message_bytes: usize,
    octez_client_bin: String,
    octez_client_dir: Option<String>,
    octez_node_endpoint: Option<String>,
    octez_protocol: Option<String>,
    id_counter: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredSubmission {
    submission: RollupSubmission,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn run(cli: Cli) -> Result<(), String> {
    let state_dir = PathBuf::from(&cli.state_dir);
    std::fs::create_dir_all(submissions_dir(&state_dir))
        .map_err(|e| format!("create state dir: {}", e))?;

    let state = AppState {
        config: Arc::new(OperatorConfig {
            source_alias: cli.source_alias,
            state_dir,
            direct_max_message_bytes: cli.direct_max_message_bytes,
            octez_client_bin: cli.octez_client_bin,
            octez_client_dir: cli.octez_client_dir,
            octez_node_endpoint: cli.octez_node_endpoint,
            octez_protocol: cli.octez_protocol,
            id_counter: AtomicU64::new(0),
        }),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/rollup/submissions", post(submit_rollup_message))
        .route("/v1/rollup/submissions/{id}", get(get_rollup_submission))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.listen)
        .await
        .map_err(|e| format!("bind {}: {}", cli.listen, e))?;
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("serve: {}", e))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn submit_rollup_message(
    State(state): State<AppState>,
    Json(req): Json<SubmitRollupMessageReq>,
) -> Result<Json<SubmitRollupMessageResp>, (StatusCode, String)> {
    let submission =
        process_submission(&state.config, req).map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    Ok(Json(SubmitRollupMessageResp { submission }))
}

async fn get_rollup_submission(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<SubmitRollupMessageResp>, (StatusCode, String)> {
    let path = submission_path(&state.config.state_dir, &id);
    let body = std::fs::read_to_string(&path).map_err(|e| {
        let status = if e.kind() == std::io::ErrorKind::NotFound {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (status, format!("read submission {}: {}", id, e))
    })?;
    let stored: StoredSubmission = serde_json::from_str(&body)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("parse submission: {}", e)))?;
    Ok(Json(SubmitRollupMessageResp {
        submission: stored.submission,
    }))
}

fn process_submission(
    config: &OperatorConfig,
    req: SubmitRollupMessageReq,
) -> Result<RollupSubmission, String> {
    let id = next_submission_id(config);
    let targeted_bytes = encode_targeted_rollup_message(&req.rollup_address, &req.payload)?;
    let mut submission = RollupSubmission {
        id: id.clone(),
        kind: req.kind,
        rollup_address: req.rollup_address,
        status: RollupSubmissionStatus::PendingDal,
        transport: RollupSubmissionTransport::Dal,
        operation_hash: None,
        payload_len: req.payload.len(),
        detail: None,
    };

    if targeted_bytes.len() > config.direct_max_message_bytes {
        submission.detail = Some(format!(
            "message is {} bytes after framing, above direct inbox limit {}; DAL publication is required",
            targeted_bytes.len(),
            config.direct_max_message_bytes
        ));
        persist_submission(config, &submission)?;
        return Ok(submission);
    }

    match inject_direct_message(config, &targeted_bytes) {
        Ok(output) => {
            submission.status = RollupSubmissionStatus::SubmittedToL1;
            submission.transport = RollupSubmissionTransport::DirectInbox;
            submission.operation_hash = extract_operation_hash(&output);
            submission.detail = Some(output);
            persist_submission(config, &submission)?;
            Ok(submission)
        }
        Err(err) => {
            submission.status = RollupSubmissionStatus::Failed;
            submission.transport = RollupSubmissionTransport::DirectInbox;
            submission.detail = Some(err.clone());
            persist_submission(config, &submission)?;
            Err(err)
        }
    }
}

fn inject_direct_message(config: &OperatorConfig, bytes: &[u8]) -> Result<String, String> {
    let payload_file = write_temp_payload(bytes)?;
    let payload = format!("bin:{}", payload_file.display());
    let mut command = std::process::Command::new(&config.octez_client_bin);
    if let Some(dir) = &config.octez_client_dir {
        command.arg("-d").arg(dir);
    }
    if let Some(endpoint) = &config.octez_node_endpoint {
        command.arg("-E").arg(endpoint);
    }
    if let Some(protocol) = &config.octez_protocol {
        command.arg("-p").arg(protocol);
    }
    command
        .arg("-w")
        .arg("none")
        .arg("send")
        .arg("smart")
        .arg("rollup")
        .arg("message")
        .arg(payload)
        .arg("from")
        .arg(&config.source_alias);

    let output = command
        .output()
        .map_err(|e| format!("failed to start {}: {}", config.octez_client_bin, e))?;
    let _ = std::fs::remove_file(&payload_file);

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let combined = match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout,
        (true, false) => stderr,
        (false, false) => format!("{}\n{}", stdout, stderr),
    };

    if !output.status.success() {
        return Err(if combined.is_empty() {
            format!("{} exited with status {}", config.octez_client_bin, output.status)
        } else {
            combined
        });
    }
    Ok(combined)
}

fn encode_targeted_rollup_message(rollup_address: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    let address = SmartRollupAddress::from_b58check(rollup_address)
        .map_err(|_| format!("invalid rollup address: {}", rollup_address))?;
    let frame = ExternalMessageFrame::Targetted {
        address,
        contents: payload,
    };
    let mut output = Vec::new();
    frame
        .bin_write(&mut output)
        .map_err(|e| format!("failed to encode targeted rollup message: {}", e))?;
    Ok(output)
}

fn extract_operation_hash(output: &str) -> Option<String> {
    output
        .split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ';' | '(' | ')'))
        .find_map(|token| {
            if token.starts_with('o')
                && token.len() >= 20
                && token.chars().all(|ch| ch.is_ascii_alphanumeric())
            {
                Some(token.to_string())
            } else {
                None
            }
        })
}

fn write_temp_payload(bytes: &[u8]) -> Result<PathBuf, String> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "tzel-operator-{}-{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system clock error: {}", e))?
            .as_nanos()
    ));
    std::fs::write(&path, bytes).map_err(|e| format!("write payload file: {}", e))?;
    Ok(path)
}

fn next_submission_id(config: &OperatorConfig) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let seq = config.id_counter.fetch_add(1, Ordering::Relaxed);
    format!("sub-{}-{:04}", now, seq)
}

fn submissions_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("submissions")
}

fn submission_path(state_dir: &Path, id: &str) -> PathBuf {
    submissions_dir(state_dir).join(format!("{}.json", id))
}

fn persist_submission(config: &OperatorConfig, submission: &RollupSubmission) -> Result<(), String> {
    std::fs::create_dir_all(submissions_dir(&config.state_dir))
        .map_err(|e| format!("create submissions dir: {}", e))?;
    let path = submission_path(&config.state_dir, &submission.id);
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    let mut file = std::fs::File::create(&tmp).map_err(|e| format!("create tmp: {}", e))?;
    let body = serde_json::to_string_pretty(&StoredSubmission {
        submission: submission.clone(),
    })
    .map_err(|e| format!("serialize submission: {}", e))?;
    file.write_all(body.as_bytes())
        .map_err(|e| format!("write tmp: {}", e))?;
    file.sync_all().map_err(|e| format!("fsync tmp: {}", e))?;
    drop(file);
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename submission: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_client(script: &Path) -> OperatorConfig {
        let state_dir = std::env::temp_dir().join(format!(
            "tzel-operator-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&state_dir).unwrap();
        OperatorConfig {
            source_alias: "alice".into(),
            state_dir,
            direct_max_message_bytes: 1024,
            octez_client_bin: script.display().to_string(),
            octez_client_dir: None,
            octez_node_endpoint: None,
            octez_protocol: None,
            id_counter: AtomicU64::new(0),
        }
    }

    fn make_client_script(body: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("octez-client");
        std::fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        dir
    }

    #[test]
    fn large_message_is_parked_for_dal() {
        let script_dir = make_client_script("#!/bin/sh\nexit 1\n");
        let config = config_with_client(&script_dir.path().join("octez-client"));
        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::Shield,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: vec![7u8; 5000],
        };
        let submission = process_submission(&config, req).unwrap();
        assert_eq!(submission.status, RollupSubmissionStatus::PendingDal);
        assert_eq!(submission.transport, RollupSubmissionTransport::Dal);
        assert!(submission.operation_hash.is_none());
    }

    #[test]
    fn small_message_is_sent_directly() {
        let script_dir =
            make_client_script("#!/bin/sh\necho 'Operation hash is ooTestHash123456789ABCDEFG'\n");
        let config = config_with_client(&script_dir.path().join("octez-client"));
        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::Withdraw,
            rollup_address: "sr1C7caq3WfNfQMAri4QxNb9Fkxsn6WrgMQP".into(),
            payload: vec![1, 2, 3, 4],
        };
        let submission = process_submission(&config, req).unwrap();
        assert_eq!(submission.status, RollupSubmissionStatus::SubmittedToL1);
        assert_eq!(submission.transport, RollupSubmissionTransport::DirectInbox);
        assert_eq!(
            submission.operation_hash.as_deref(),
            Some("ooTestHash123456789ABCDEFG")
        );
    }
}
