//! Test entry point that parses a SUIT manifest and logs every operation performed.
//!
//! This binary is a thin orchestrator only: all logging behaviour lives in [`hooks`], all
//! manifest inspection lives in [`inspect`], digest/signature reporting lives in
//! [`digest_check`]/[`signature_check`], and the actual parsing/execution is delegated entirely
//! to the `dress-up` library. Nothing here re-implements library logic.
mod digest_check;
mod hooks;
mod inspect;
mod log;
mod signature_check;

use std::path::PathBuf;

use clap::Parser;
use dress_up::SuitManifest;

use crate::hooks::LoggingHooks;
use crate::log::{log_step, log_warn};

/// Parses a SUIT manifest and logs every operation, data read and command found.
#[derive(Parser, Debug)]
struct Args {
    /// Path to the SUIT envelope (CBOR) to process.
    manifest: PathBuf,
    /// Optional payload file, returned to the manifest whenever it fetches content.
    #[arg(long)]
    payload: Option<PathBuf>,
    /// Optional PEM-encoded EC public key used to verify a signature, if one is present.
    #[arg(long)]
    pubkey: Option<PathBuf>,
    /// Simulated capacity (in bytes) of the component storage backing this test run.
    #[arg(long, default_value_t = 4096)]
    capacity: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let args = Args::parse();

    log_step!("reading manifest file {:?}", args.manifest);
    let manifest_bytes = std::fs::read(&args.manifest)?;

    let payload = match &args.payload {
        Some(path) => {
            log_step!("reading payload file {path:?}");
            std::fs::read(path)?
        }
        None => {
            log_warn!("no --payload supplied, fetch operations will report zero bytes");
            Vec::new()
        }
    };

    log_step!("parsing SUIT envelope");
    let suit = SuitManifest::from_bytes(&manifest_bytes);

    // The envelope can be read out before authentication; used here purely to inspect and
    // report the digest/signature, ahead of the library's own mandatory digest check below.
    let envelope = suit.envelope()?;
    let num_signatures =
        digest_check::check(envelope.auth_object()?, envelope.manifest_bytes()?)?;
    signature_check::report_presence(num_signatures);
    let key = signature_check::load_key(args.pubkey.as_deref())?;

    let suit = suit.authenticate(|cose, payload| signature_check::verify(&key, cose, payload))?;

    log_step!("deriving envelope from authenticated manifest");
    let envelope = suit.envelope()?;
    inspect::log_envelope(&envelope)?;

    log_step!("deriving inner manifest from envelope");
    let manifest = envelope.manifest()?;
    inspect::log_manifest(&manifest)?;

    log_step!("executing all command sequences");
    let hooks = LoggingHooks::new(args.capacity, payload);
    manifest.execute_full(&hooks)?;

    let storage = hooks.storage_snapshot();
    log_step!("final simulated component contents: {} bytes", storage.len());

    Ok(())
}
