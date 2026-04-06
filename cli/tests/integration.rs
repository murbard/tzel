//! Integration test: spawns sp-ledger, runs sp-client commands as subprocesses,
//! verifies the full shield → transfer → unshield flow including failure cases.

use std::process::{Command, Stdio};
use std::time::Duration;

const LEDGER_PORT: u16 = 19876;

fn ledger_url() -> String {
    format!("http://localhost:{}", LEDGER_PORT)
}

fn sp_client() -> String {
    env!("CARGO_BIN_EXE_sp-client").to_string()
}

fn sp_ledger() -> String {
    env!("CARGO_BIN_EXE_sp-ledger").to_string()
}

fn run(bin: &str, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to execute");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), stdout, stderr)
}

fn client(wallet: &str, args: &[&str]) -> (bool, String) {
    let mut full_args = vec!["-w", wallet];
    full_args.extend_from_slice(args);
    let (ok, stdout, stderr) = run(&sp_client(), &full_args);
    let combined = format!("{}{}", stdout, stderr);
    (ok, combined)
}

#[test]
fn test_full_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let alice_wallet = dir.join("alice.json").to_str().unwrap().to_string();
    let bob_wallet = dir.join("bob.json").to_str().unwrap().to_string();
    let bob_addr_file = dir.join("bob_addr.json").to_str().unwrap().to_string();
    let l = ledger_url();

    // Start ledger
    let mut ledger = Command::new(sp_ledger())
        .args(["--port", &LEDGER_PORT.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start ledger");

    std::thread::sleep(Duration::from_millis(500));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // ── Keygen ───────────────────────────────────────────────────
        let (ok, out) = client(&alice_wallet, &["keygen"]);
        assert!(ok, "alice keygen failed: {}", out);
        assert!(out.contains("Wallet created"));

        let (ok, out) = client(&bob_wallet, &["keygen"]);
        assert!(ok, "bob keygen failed: {}", out);

        // ── Generate bob's address ──────────────────────────────────
        let (ok, out) = client(&bob_wallet, &["address"]);
        assert!(ok, "bob address failed: {}", out);
        // Extract JSON (everything after first '{')
        let json_start = out.find('{').expect("no JSON in address output");
        let json = &out[json_start..];
        // Verify it parses as JSON with auth_root field
        let addr: serde_json::Value = serde_json::from_str(json).expect("bad address JSON");
        assert!(addr.get("auth_root").is_some(), "address missing auth_root");
        assert!(addr.get("nk_tag").is_some(), "address missing nk_tag");
        assert!(addr.get("d_j").is_some(), "address missing d_j");
        std::fs::write(&bob_addr_file, json).unwrap();

        // ── Fund alice ──────────────────────────────────────────────
        let (ok, out) = client(&alice_wallet, &["fund", "-l", &l, "--addr", "alice", "--amount", "2000"]);
        assert!(ok, "fund failed: {}", out);
        assert!(out.contains("Funded alice with 2000"));

        // ── Shield 1500 + 500 ───────────────────────────────────────
        let (ok, out) = client(&alice_wallet, &["shield", "-l", &l, "--sender", "alice", "--amount", "1500"]);
        assert!(ok, "shield 1500 failed: {}", out);
        assert!(out.contains("Shielded 1500"));

        let (ok, out) = client(&alice_wallet, &["shield", "-l", &l, "--sender", "alice", "--amount", "500"]);
        assert!(ok, "shield 500 failed: {}", out);
        assert!(out.contains("Shielded 500"));

        // ── Shield with insufficient balance should fail ────────────
        let (ok, _) = client(&alice_wallet, &["shield", "-l", &l, "--sender", "alice", "--amount", "1"]);
        assert!(!ok, "shield with 0 balance should fail");

        // ── Alice scan ──────────────────────────────────────────────
        let (ok, out) = client(&alice_wallet, &["scan", "-l", &l]);
        assert!(ok, "alice scan failed: {}", out);
        assert!(out.contains("2 new notes found"));
        assert!(out.contains("balance=2000"));

        // ── Alice balance ───────────────────────────────────────────
        let (ok, out) = client(&alice_wallet, &["balance"]);
        assert!(ok, "balance failed: {}", out);
        assert!(out.contains("Private balance: 2000"));
        assert!(out.contains("Notes: 2"));

        // ── Transfer 1200 to bob ────────────────────────────────────
        let (ok, out) = client(&alice_wallet, &[
            "transfer", "-l", &l, "--to", &bob_addr_file, "--amount", "1200",
        ]);
        assert!(ok, "transfer failed: {}", out);
        assert!(out.contains("Transferred 1200"));
        assert!(out.contains("change=300"));

        // ── Alice scan — should find change note ────────────────────
        let (ok, out) = client(&alice_wallet, &["scan", "-l", &l]);
        assert!(ok, "alice scan 2 failed: {}", out);
        assert!(out.contains("1 new notes found"));

        // ── Bob scan — should find received note ────────────────────
        let (ok, out) = client(&bob_wallet, &["scan", "-l", &l]);
        assert!(ok, "bob scan failed: {}", out);
        assert!(out.contains("1 new notes found"));
        assert!(out.contains("v=1200"));

        // ── Bob balance ─────────────────────────────────────────────
        let (ok, out) = client(&bob_wallet, &["balance"]);
        assert!(ok, "bob balance failed: {}", out);
        assert!(out.contains("Private balance: 1200"));

        // ── Bob unshields 500 ───────────────────────────────────────
        let (ok, out) = client(&bob_wallet, &[
            "unshield", "-l", &l, "--amount", "500", "--recipient", "bob_pub",
        ]);
        assert!(ok, "bob unshield failed: {}", out);
        assert!(out.contains("Unshielded 500 to bob_pub"));
        assert!(out.contains("change=700"));

        // ── Bob scan — should find change, spent note removed ───────
        let (ok, out) = client(&bob_wallet, &["scan", "-l", &l]);
        assert!(ok, "bob scan 2 failed: {}", out);

        let (ok, out) = client(&bob_wallet, &["balance"]);
        assert!(ok, "bob balance 2 failed: {}", out);
        assert!(out.contains("Private balance: 700"));

        // ── Alice balance check ─────────────────────────────────────
        let (ok, out) = client(&alice_wallet, &["balance"]);
        assert!(ok, "alice balance 2 failed: {}", out);
        assert!(out.contains("Private balance: 800"));

        // ── Double-spend: alice tries to transfer using already-spent notes ──
        // Alice has 800 (500 original + 300 change). The 1500 note was already spent.
        // Transferring more than 800 would require the spent notes.
        // But with TrustMeBro, the client selects from its local wallet, which
        // already removed spent notes. So this is more about "insufficient funds".
        let (ok, _) = client(&alice_wallet, &[
            "transfer", "-l", &l, "--to", &bob_addr_file, "--amount", "9999",
        ]);
        assert!(!ok, "transfer exceeding balance should fail");

        // ── Verify public balances via ledger API ───────────────────
        let resp: serde_json::Value = ureq::get(&format!("{}/balances", l))
            .call().unwrap()
            .into_body().read_json().unwrap();
        let balances = resp.get("balances").unwrap();
        assert_eq!(balances.get("alice").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(balances.get("bob_pub").and_then(|v| v.as_u64()), Some(500));

        // ── Value conservation ──────────────────────────────────────
        // alice_private(800) + bob_private(700) + bob_public(500) = 2000
        // (There's also a 0-value spent note from alice's original 500 that was
        // partially used in the 1200 transfer, leaving 300 change, plus the
        // remaining untouched 500 note.)
        // Total: 800 + 700 + 500 = 2000 ✓

        let tree: serde_json::Value = ureq::get(&format!("{}/tree", l))
            .call().unwrap()
            .into_body().read_json().unwrap();
        assert!(tree.get("size").unwrap().as_u64().unwrap() >= 5,
            "tree should have at least 5 commitments");
    }));

    // Cleanup: kill ledger
    let _ = ledger.kill();
    let _ = ledger.wait();

    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
