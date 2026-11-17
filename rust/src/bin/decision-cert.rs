//! `decision-cert verify <cert.json> --keys <keys.json> [--tenant <tenant>] [--now <ts>]`
//!
//! Exit 0: the certificate verifies against the trusted keys and has not expired at `--now`
//! (default: the current time); its id is printed on stdout.
//! Exit 1: it does not verify, or it has expired; the reason is printed on stderr.
//! Exit 2: usage error, an unreadable file, or a keys file that is not a JSON object of strings
//! (with `--tenant`: of key entries, spec v1.5 §4).
//! With `--tenant`, the certificate is verified for that expected tenant (any spec; a v1.5
//! certificate needs it). `python -m decision_cert verify` behaves the same.

use std::{collections::BTreeMap, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Verify decision-certificate.v1 certificates")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a certificate against trusted keys and check its expiry.
    Verify {
        /// The certificate, a JSON object.
        cert: PathBuf,
        /// Trusted keys: a JSON object of key id -> base64url raw Ed25519 public key (with
        /// --tenant, an entry may also be {"key", "mode", "host"}).
        #[arg(long)]
        keys: PathBuf,
        /// The tenant the certificate must be for (spec v1.5); its keys are the --keys file.
        #[arg(long)]
        tenant: Option<String>,
        /// The time to check expiry at, `YYYY-MM-DDTHH:MM:SSZ` (default: now).
        #[arg(long)]
        now: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() { 2 } else { 0 });
        }
    };
    let Command::Verify {
        cert,
        keys,
        tenant,
        now,
    } = cli.command;
    match run(&cert, &keys, tenant.as_deref(), now.as_deref()) {
        Ok(id) => {
            println!("{id}");
            ExitCode::SUCCESS
        }
        Err(Failure::Rejected(m)) => {
            eprintln!("{}: {m}", cert.display());
            ExitCode::from(1)
        }
        Err(Failure::Usage(m)) => {
            eprintln!("decision-cert: {m}");
            ExitCode::from(2)
        }
    }
}

enum Failure {
    Rejected(String),
    Usage(String),
}

enum Keys {
    Flat(BTreeMap<String, String>),
    Tenant(String, decision_cert::TenantKeys),
}

fn run(
    cert: &std::path::Path,
    keys: &std::path::Path,
    tenant: Option<&str>,
    now: Option<&str>,
) -> Result<String, Failure> {
    let read = |p: &std::path::Path| {
        std::fs::read_to_string(p).map_err(|e| Failure::Usage(format!("{}: {e}", p.display())))
    };
    let keys_text = read(keys)?;
    let keys = match tenant {
        None => Keys::Flat(serde_json::from_str(&keys_text).map_err(|e| {
            Failure::Usage(format!(
                "{}: not a JSON object of key id -> public key: {e}",
                keys.display()
            ))
        })?),
        Some(t) => {
            let usage = |e: String| {
                Failure::Usage(format!(
                    "{}: not a JSON object of key id -> key entry: {e}",
                    keys.display()
                ))
            };
            let v: serde_json::Value =
                serde_json::from_str(&keys_text).map_err(|e| usage(e.to_string()))?;
            let tk = decision_cert::tenant_keys_from_json(&v).map_err(|e| usage(e.to_string()))?;
            Keys::Tenant(t.to_string(), tk)
        }
    };
    let now = match now {
        Some(s) => decision_cert::timestamp(s)
            .map_err(|_| Failure::Usage(format!("--now {s:?} is not YYYY-MM-DDTHH:MM:SSZ")))?,
        None => chrono::Utc::now(),
    };
    let text = read(cert)?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        Failure::Rejected(format!(
            "certificate is not a valid decision certificate: not JSON: {e}"
        ))
    })?;
    let v = match &keys {
        Keys::Flat(k) => decision_cert::verify(&value, k),
        Keys::Tenant(t, k) => decision_cert::verify_for_tenant(&value, t, k),
    }
    .map_err(|e| Failure::Rejected(e.to_string()))?;
    if v.is_expired(now) {
        return Err(Failure::Rejected(format!(
            "certificate {} has expired (its expires_at is not after the check time)",
            v.id
        )));
    }
    Ok(v.id)
}
