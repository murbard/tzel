use clap::{Parser, Subcommand};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use ml_kem::KeyExport;
use starkprivacy_cli::*;

// ═══════════════════════════════════════════════════════════════════════
// Wallet file
// ═══════════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize)]
struct WalletFile {
    #[serde(with = "hex_f")]
    master_sk: F,
    #[serde(with = "hex_bytes")]
    kem_seed_v: Vec<u8>,
    #[serde(with = "hex_bytes")]
    kem_seed_d: Vec<u8>,
    addr_counter: u32,
    notes: Vec<Note>,
    scanned: usize,
}

impl WalletFile {
    fn account(&self) -> Account {
        derive_account(&self.master_sk)
    }

    fn kem_keys(&self) -> (Ek, Dk, Ek, Dk) {
        let seed_v: [u8; 64] = self.kem_seed_v.as_slice().try_into().expect("bad kem_seed_v");
        let seed_d: [u8; 64] = self.kem_seed_d.as_slice().try_into().expect("bad kem_seed_d");
        let (ek_v, dk_v) = kem_keygen_from_seed(&seed_v);
        let (ek_d, dk_d) = kem_keygen_from_seed(&seed_d);
        (ek_v, dk_v, ek_d, dk_d)
    }

    fn next_address(&mut self) -> (F, F, F, u32) {
        let acc = self.account();
        let j = self.addr_counter;
        let d_j = derive_address(&acc.incoming_seed, j);
        let ak = derive_ak(&acc.ask_base, j);
        let nk_sp = derive_nk_spend(&acc.nk, &d_j);
        let nk_tg = derive_nk_tag(&nk_sp);
        self.addr_counter += 1;
        (d_j, ak, nk_tg, j)
    }

    fn balance(&self) -> u128 {
        self.notes.iter().map(|n| n.v as u128).sum()
    }

    /// Select notes to cover at least `amount`. Returns indices into self.notes.
    fn select_notes(&self, amount: u64) -> Result<Vec<usize>, String> {
        let mut indexed: Vec<(usize, u64)> =
            self.notes.iter().enumerate().map(|(i, n)| (i, n.v)).collect();
        indexed.sort_by(|a, b| b.1.cmp(&a.1)); // largest first
        let mut sum = 0u128;
        let mut selected = vec![];
        for (i, v) in indexed {
            selected.push(i);
            sum += v as u128;
            if sum >= amount as u128 {
                return Ok(selected);
            }
        }
        Err(format!(
            "insufficient funds: have {} need {}",
            self.balance(),
            amount
        ))
    }
}

fn load_wallet(path: &str) -> Result<WalletFile, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("read wallet: {}", e))?;
    serde_json::from_str(&data).map_err(|e| format!("parse wallet: {}", e))
}

fn save_wallet(path: &str, w: &WalletFile) -> Result<(), String> {
    let data = serde_json::to_string_pretty(w).map_err(|e| format!("serialize: {}", e))?;
    std::fs::write(path, data).map_err(|e| format!("write wallet: {}", e))
}

fn load_address(path: &str) -> Result<PaymentAddress, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("read address: {}", e))?;
    serde_json::from_str(&data).map_err(|e| format!("parse address: {}", e))
}

// ═══════════════════════════════════════════════════════════════════════
// HTTP helpers
// ═══════════════════════════════════════════════════════════════════════

fn post_json<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
    url: &str,
    body: &Req,
) -> Result<Resp, String> {
    let resp = ureq::post(url)
        .send_json(serde_json::to_value(body).unwrap())
        .map_err(|e| format!("HTTP error: {}", e))?;
    let status = resp.status();
    if status != 200 {
        let body = resp.into_body().read_to_string().unwrap_or_default();
        return Err(format!("HTTP {}: {}", status, body));
    }
    resp.into_body()
        .read_json()
        .map_err(|e| format!("parse response: {}", e))
}

fn get_json<Resp: for<'de> Deserialize<'de>>(url: &str) -> Result<Resp, String> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| format!("HTTP error: {}", e))?;
    resp.into_body()
        .read_json()
        .map_err(|e| format!("parse response: {}", e))
}

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

#[derive(Parser)]
#[command(name = "sp-client", about = "StarkPrivacy CLI wallet")]
struct Cli {
    #[arg(short, long, default_value = "wallet.json")]
    wallet: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new wallet
    Keygen,
    /// Derive a new payment address
    Address,
    /// Export detection key (for delegation)
    ExportDetect,
    /// Export viewing keys (incoming_seed + kem_seed_v)
    ExportView,
    /// Scan ledger for new notes
    Scan {
        #[arg(short, long, default_value = "http://localhost:8080")]
        ledger: String,
    },
    /// Show wallet balance
    Balance,
    /// Shield: deposit public tokens into a private note
    Shield {
        #[arg(short, long, default_value = "http://localhost:8080")]
        ledger: String,
        #[arg(long)]
        sender: String,
        #[arg(long)]
        amount: u64,
        /// Path to recipient address JSON (default: generate new self-address)
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        memo: Option<String>,
    },
    /// Transfer private notes to a recipient
    Transfer {
        #[arg(short, long, default_value = "http://localhost:8080")]
        ledger: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        memo: Option<String>,
    },
    /// Unshield: withdraw private notes to a public address
    Unshield {
        #[arg(short, long, default_value = "http://localhost:8080")]
        ledger: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        recipient: String,
    },
    /// Fund a public address (calls ledger /fund)
    Fund {
        #[arg(short, long, default_value = "http://localhost:8080")]
        ledger: String,
        #[arg(long)]
        addr: String,
        #[arg(long)]
        amount: u64,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Cmd::Keygen => cmd_keygen(&cli.wallet),
        Cmd::Address => cmd_address(&cli.wallet),
        Cmd::ExportDetect => cmd_export_detect(&cli.wallet),
        Cmd::ExportView => cmd_export_view(&cli.wallet),
        Cmd::Scan { ledger } => cmd_scan(&cli.wallet, &ledger),
        Cmd::Balance => cmd_balance(&cli.wallet),
        Cmd::Shield {
            ledger,
            sender,
            amount,
            to,
            memo,
        } => cmd_shield(&cli.wallet, &ledger, &sender, amount, to, memo),
        Cmd::Transfer {
            ledger,
            to,
            amount,
            memo,
        } => cmd_transfer(&cli.wallet, &ledger, &to, amount, memo),
        Cmd::Unshield {
            ledger,
            amount,
            recipient,
        } => cmd_unshield(&cli.wallet, &ledger, amount, &recipient),
        Cmd::Fund {
            ledger,
            addr,
            amount,
        } => cmd_fund(&ledger, &addr, amount),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Commands
// ═══════════════════════════════════════════════════════════════════════

fn cmd_keygen(path: &str) -> Result<(), String> {
    if std::path::Path::new(path).exists() {
        return Err(format!("{} already exists", path));
    }
    let mut rng = rand::rng();
    let master_sk: F = rng.random();
    let kem_seed_v: [u8; 64] = rng.random();
    let kem_seed_d: [u8; 64] = rng.random();

    let w = WalletFile {
        master_sk,
        kem_seed_v: kem_seed_v.to_vec(),
        kem_seed_d: kem_seed_d.to_vec(),
        addr_counter: 0,
        notes: vec![],
        scanned: 0,
    };
    save_wallet(path, &w)?;
    println!("Wallet created: {}", path);
    Ok(())
}

fn cmd_address(path: &str) -> Result<(), String> {
    let mut w = load_wallet(path)?;
    let (d_j, ak, nk_tag, j) = w.next_address();
    let (ek_v, _, ek_d, _) = w.kem_keys();

    let addr = PaymentAddress {
        d_j,
        ak,
        nk_tag,
        ek_v: ek_v.to_bytes().to_vec(),
        ek_d: ek_d.to_bytes().to_vec(),
    };

    save_wallet(path, &w)?;
    println!("Address #{}", j);
    println!("{}", serde_json::to_string_pretty(&addr).unwrap());
    Ok(())
}

fn cmd_export_detect(path: &str) -> Result<(), String> {
    let w = load_wallet(path)?;
    println!("{}", hex::encode(&w.kem_seed_d));
    Ok(())
}

fn cmd_export_view(path: &str) -> Result<(), String> {
    let w = load_wallet(path)?;
    let acc = w.account();
    println!(
        "{{\"incoming_seed\":\"{}\",\"kem_seed_v\":\"{}\"}}",
        hex::encode(acc.incoming_seed),
        hex::encode(&w.kem_seed_v)
    );
    Ok(())
}

fn cmd_scan(path: &str, ledger: &str) -> Result<(), String> {
    let mut w = load_wallet(path)?;
    let (_, dk_v, _, dk_d) = w.kem_keys();
    let acc = w.account();

    let url = format!("{}/notes?cursor={}", ledger, w.scanned);
    let feed: NotesFeedResp = get_json(&url)?;

    let mut found = 0usize;
    for nm in &feed.notes {
        // Stage 1: detection
        if !detect(&nm.enc, &dk_d) {
            continue;
        }
        // Stage 2: decrypt
        let Some((v, rseed, _memo)) = decrypt_memo(&nm.enc, &dk_v) else {
            continue;
        };
        // Stage 3: match address
        let rcm = derive_rcm(&rseed);
        for j in 0..w.addr_counter {
            let d_j = derive_address(&acc.incoming_seed, j);
            let ak = derive_ak(&acc.ask_base, j);
            let nk_sp = derive_nk_spend(&acc.nk, &d_j);
            let nk_tg = derive_nk_tag(&nk_sp);
            let otag = owner_tag(&ak, &nk_tg);
            if commit(&d_j, v, &rcm, &otag) == nm.cm {
                // Find the tree index for this commitment
                // memo index == tree leaf index (ledger posts one memo per tree append)
                // The NoteMemo.index is the memo index, we need the tree leaf index.
                // For now, use the memo index as a proxy — in our ledger, memos and tree
                // leaves are appended in lockstep, but multiple leaves can be added per tx.
                // We need a better way. Let's query the tree size and figure out the leaf index.
                // Actually, the ledger returns leaf indices in shield/transfer/unshield responses.
                // During scan, we need to find which tree leaf matches this cm.
                // The simplest approach: the ledger memo index doesn't directly correspond to tree index
                // because transfer adds 2 leaves but 2 memos. So memo index == tree leaf index
                // since post_note is called once per tree.append.
                let leaf_index = nm.index;
                w.notes.push(Note {
                    nk_spend: nk_sp,
                    nk_tag: nk_tg,
                    ak,
                    d_j,
                    v,
                    rseed,
                    cm: nm.cm,
                    index: leaf_index,
                });
                found += 1;
                println!("  found: v={} cm={} index={}", v, short(&nm.cm), leaf_index);
                break;
            }
        }
    }

    // Check which notes have been spent (nullified)
    let nf_resp: NullifiersResp = get_json(&format!("{}/nullifiers", ledger))?;
    let nf_set: std::collections::HashSet<F> = nf_resp.nullifiers.into_iter().collect();
    let before = w.notes.len();
    w.notes.retain(|n| {
        let nf = nullifier(&n.nk_spend, &n.cm, n.index as u64);
        !nf_set.contains(&nf)
    });
    let spent = before - w.notes.len();

    w.scanned = feed.next_cursor;
    save_wallet(path, &w)?;
    println!(
        "Scanned: {} new notes found, {} spent removed, balance={}",
        found,
        spent,
        w.balance()
    );
    Ok(())
}

fn cmd_balance(path: &str) -> Result<(), String> {
    let w = load_wallet(path)?;
    println!("Private balance: {}", w.balance());
    println!("Notes: {}", w.notes.len());
    for (i, n) in w.notes.iter().enumerate() {
        println!("  [{}] v={} cm={} index={}", i, n.v, short(&n.cm), n.index);
    }
    Ok(())
}

fn cmd_shield(
    path: &str,
    ledger: &str,
    sender: &str,
    amount: u64,
    to: Option<String>,
    memo: Option<String>,
) -> Result<(), String> {
    let mut w = load_wallet(path)?;
    let (ek_v, _, ek_d, _) = w.kem_keys();

    let address = if let Some(addr_path) = to {
        load_address(&addr_path)?
    } else {
        let (d_j, ak, nk_tag, _) = w.next_address();
        PaymentAddress {
            d_j,
            ak,
            nk_tag,
            ek_v: ek_v.to_bytes().to_vec(),
            ek_d: ek_d.to_bytes().to_vec(),
        }
    };

    let req = ShieldReq {
        sender: sender.into(),
        v: amount,
        address,
        memo,
        proof: Proof::TrustMeBro,
    };
    let resp: ShieldResp = post_json(&format!("{}/shield", ledger), &req)?;
    save_wallet(path, &w)?;
    println!("Shielded {} -> cm={} index={}", amount, short(&resp.cm), resp.index);
    println!("Run 'scan' to pick up the note.");
    Ok(())
}

fn cmd_transfer(
    path: &str,
    ledger: &str,
    to_path: &str,
    amount: u64,
    memo: Option<String>,
) -> Result<(), String> {
    let mut w = load_wallet(path)?;
    let recipient = load_address(to_path)?;
    let (ek_v, _, ek_d, _) = w.kem_keys();

    // Select notes
    let selected = w.select_notes(amount)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128) as u64;

    // Get current root
    let tree_info: TreeInfoResp = get_json(&format!("{}/tree", ledger))?;
    let root = tree_info.root;

    // Compute nullifiers
    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| {
            let n = &w.notes[i];
            nullifier(&n.nk_spend, &n.cm, n.index as u64)
        })
        .collect();

    // Build output 1: recipient
    let mut rng = rand::rng();
    let rseed_1: F = rng.random();
    let rcm_1 = derive_rcm(&rseed_1);
    let ek_v_recv = ml_kem::ml_kem_768::EncapsulationKey::new(
        recipient.ek_v.as_slice().try_into().map_err(|_| "bad ek_v")?,
    ).map_err(|_| "invalid ek_v")?;
    let ek_d_recv = ml_kem::ml_kem_768::EncapsulationKey::new(
        recipient.ek_d.as_slice().try_into().map_err(|_| "bad ek_d")?,
    ).map_err(|_| "invalid ek_d")?;
    let otag_1 = owner_tag(&recipient.ak, &recipient.nk_tag);
    let cm_1 = commit(&recipient.d_j, amount, &rcm_1, &otag_1);
    let memo_bytes = memo.as_deref().map(|s| s.as_bytes());
    let enc_1 = encrypt_note(amount, &rseed_1, memo_bytes, &ek_v_recv, &ek_d_recv);

    // Build output 2: change to self
    let (d_j_c, ak_c, nk_tag_c, _) = w.next_address();
    let rseed_2: F = rng.random();
    let rcm_2 = derive_rcm(&rseed_2);
    let otag_2 = owner_tag(&ak_c, &nk_tag_c);
    let cm_2 = commit(&d_j_c, change, &rcm_2, &otag_2);
    let enc_2 = encrypt_note(change, &rseed_2, None, &ek_v, &ek_d);

    let req = TransferReq {
        root,
        nullifiers,
        cm_1,
        cm_2,
        enc_1,
        enc_2,
        proof: Proof::TrustMeBro,
    };
    let resp: TransferResp = post_json(&format!("{}/transfer", ledger), &req)?;

    // Remove spent notes (sort descending to avoid index shift)
    let mut to_remove = selected.clone();
    to_remove.sort_unstable();
    for &i in to_remove.iter().rev() {
        w.notes.remove(i);
    }
    save_wallet(path, &w)?;

    println!(
        "Transferred {} to recipient, change={} (idx={},{})",
        amount, change, resp.index_1, resp.index_2
    );
    println!("Run 'scan' to pick up change note.");
    Ok(())
}

fn cmd_unshield(
    path: &str,
    ledger: &str,
    amount: u64,
    recipient: &str,
) -> Result<(), String> {
    let mut w = load_wallet(path)?;
    let (ek_v, _, ek_d, _) = w.kem_keys();

    let selected = w.select_notes(amount)?;
    let sum_in: u128 = selected.iter().map(|&i| w.notes[i].v as u128).sum();
    let change = (sum_in - amount as u128) as u64;

    let tree_info: TreeInfoResp = get_json(&format!("{}/tree", ledger))?;
    let root = tree_info.root;

    let nullifiers: Vec<F> = selected
        .iter()
        .map(|&i| {
            let n = &w.notes[i];
            nullifier(&n.nk_spend, &n.cm, n.index as u64)
        })
        .collect();

    let (cm_change, enc_change) = if change > 0 {
        let mut rng = rand::rng();
        let (d_j_c, ak_c, nk_tag_c, _) = w.next_address();
        let rseed_c: F = rng.random();
        let rcm_c = derive_rcm(&rseed_c);
        let otag_c = owner_tag(&ak_c, &nk_tag_c);
        let cm = commit(&d_j_c, change, &rcm_c, &otag_c);
        let enc = encrypt_note(change, &rseed_c, None, &ek_v, &ek_d);
        (cm, Some(enc))
    } else {
        (ZERO, None)
    };

    let req = UnshieldReq {
        root,
        nullifiers,
        v_pub: amount,
        recipient: recipient.into(),
        cm_change,
        enc_change,
        proof: Proof::TrustMeBro,
    };
    let resp: UnshieldResp = post_json(&format!("{}/unshield", ledger), &req)?;

    let mut to_remove = selected.clone();
    to_remove.sort_unstable();
    for &i in to_remove.iter().rev() {
        w.notes.remove(i);
    }
    save_wallet(path, &w)?;

    println!(
        "Unshielded {} to {}, change={} (change_idx={:?})",
        amount, recipient, change, resp.change_index
    );
    if change > 0 {
        println!("Run 'scan' to pick up change note.");
    }
    Ok(())
}

fn cmd_fund(ledger: &str, addr: &str, amount: u64) -> Result<(), String> {
    let req = FundReq {
        addr: addr.into(),
        amount,
    };
    let _: serde_json::Value = post_json(&format!("{}/fund", ledger), &req)?;
    println!("Funded {} with {}", addr, amount);
    Ok(())
}
