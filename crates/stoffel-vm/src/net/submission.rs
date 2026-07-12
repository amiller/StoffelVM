//! # External program submission endpoint (spec task W4)
//!
//! Thin external entrypoint that lets a client hand a compiled MPC program to a
//! node and have the committee run it by content hash:
//!
//! 1. Accept `(bytecode, entry_fn)` ([`SubmissionRequest`]).
//! 2. Compute the `blake3` program id ([`program_sync::program_id_from_bytes`]).
//! 3. **Validate** an optional client-claimed id — a mismatch is a hard
//!    [`SubmissionError::ProgramTampered`] rejection. There is **no
//!    error-masking fallback**: a tampered program never reaches the runner.
//! 4. **Seed** the bytecode into the content-addressed program cache
//!    (`program_sync`), so all parties can fetch it by hash.
//! 5. Hand the prepared [`SubmissionOutcome`] (whose `job_id` *is* the program
//!    id) to a host-supplied [`CommitteeRunner`] that triggers
//!    `agree_and_sync_program` + the committee run.
//!
//! Client inputs are **not** re-invented here: the runner reuses the existing
//! `client_store` hydration path, exactly as the in-process committee tests do.
//!
//! ## Scope
//!
//! This module is deliberately transport-light: [`prepare_submission`] is pure
//! (id + tamper check + cache seed) and [`handle_submission`] composes it with a
//! [`CommitteeRunner`]. [`serve_submission_tcp`] / [`submit_tcp`] add a minimal
//! length-prefixed TCP framing so a client can submit to one node over the
//! network. The runner — the part that actually builds and drives an MPC
//! committee — is supplied by the host (CLI/SDK/test), so this module stays
//! independent of the (large) committee-construction code and adds no new input
//! path.

#[cfg(test)]
use crate::net::program_sync::cache_dir;
use crate::net::program_sync::{
    ensure_cache_dir, program_id_from_bytes, program_path, ProgramSyncError,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::Path;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Upper bound on an accepted program payload (256 MiB). A real public endpoint
/// adds economic/spam metering (explicitly a non-goal per the spec); this guard
/// only prevents trivial memory exhaustion.
pub const MAX_PROGRAM_BYTES: usize = 256 * 1024 * 1024;

/// Upper bound on a single framed wire message (request or response). Covers
/// [`MAX_PROGRAM_BYTES`] plus serialization/entry overhead.
const MAX_FRAME_BYTES: u64 = (MAX_PROGRAM_BYTES as u64) + 64 * 1024 * 1024;

/// Length of the blake3 program id, in bytes.
const PROGRAM_ID_LEN: usize = 32;

/// External program submission.
///
/// `claimed_program_id`, when present, is the content id the client asserts the
/// bytecode hashes to. The node recomputes the blake3 id from `program_bytes`
/// and rejects on mismatch ([`SubmissionError::ProgramTampered`]) — there is no
/// fallback that runs a program whose hash does not match the claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionRequest {
    /// Compiled StoffelVM bytecode (a serialized `CompiledBinary`).
    pub program_bytes: Vec<u8>,
    /// Entry function the committee should invoke (e.g. `"main"`).
    pub entry: String,
    /// Optional content id the client asserts the bytecode hashes to.
    pub claimed_program_id: Option<[u8; PROGRAM_ID_LEN]>,
}

impl SubmissionRequest {
    /// Convenience constructor for an unverified (no claimed id) submission.
    pub fn new(program_bytes: Vec<u8>, entry: impl Into<String>) -> Self {
        Self {
            program_bytes,
            entry: entry.into(),
            claimed_program_id: None,
        }
    }

    /// Attach a client-claimed program id, enabling tamper detection.
    pub fn with_claimed_program_id(mut self, id: [u8; PROGRAM_ID_LEN]) -> Self {
        self.claimed_program_id = Some(id);
        self
    }
}

/// Successful preparation of a submission.
///
/// `job_id` is the blake3 program id — the same value the committee syncs by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionOutcome {
    pub job_id: [u8; PROGRAM_ID_LEN],
    pub program_size: usize,
    pub entry: String,
}

/// Typed submission failure. Note the explicit `ProgramTampered` variant: a
/// hash mismatch is reported, never masked.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SubmissionError {
    #[error("submitted program is empty")]
    EmptyBytecode,
    #[error("submitted program size {size} exceeds limit ({max} bytes)")]
    ProgramTooLarge { size: usize, max: usize },
    #[error(
        "program tampered: claimed id {} but recomputed {}",
        hex::encode(claimed),
        hex::encode(computed)
    )]
    ProgramTampered {
        claimed: [u8; PROGRAM_ID_LEN],
        computed: [u8; PROGRAM_ID_LEN],
    },
    #[error("failed to seed program cache: {0}")]
    Seed(ProgramSyncError),
    #[error("committee run failed: {0}")]
    CommitteeRun(String),
    #[error("submission wire {operation} failed: {reason}")]
    Wire {
        operation: &'static str,
        reason: String,
    },
    #[error("submission payload length {len} exceeds wire limit ({max} bytes)")]
    PayloadTooLarge { len: u64, max: u64 },
    #[error("malformed submission response from node: {0}")]
    BadResponse(String),
}

impl From<ProgramSyncError> for SubmissionError {
    fn from(error: ProgramSyncError) -> Self {
        SubmissionError::Seed(error)
    }
}

impl From<SubmissionError> for String {
    fn from(error: SubmissionError) -> Self {
        error.to_string()
    }
}

/// Stable wire code for a [`SubmissionError`], so clients can branch on the
/// rejection reason without parsing the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmissionErrorCode {
    EmptyBytecode,
    ProgramTooLarge,
    ProgramTampered,
    SeedFailed,
    CommitteeRunFailed,
    WireError,
    PayloadTooLarge,
    BadResponse,
}

impl SubmissionError {
    pub fn code(&self) -> SubmissionErrorCode {
        match self {
            SubmissionError::EmptyBytecode => SubmissionErrorCode::EmptyBytecode,
            SubmissionError::ProgramTooLarge { .. } => SubmissionErrorCode::ProgramTooLarge,
            SubmissionError::ProgramTampered { .. } => SubmissionErrorCode::ProgramTampered,
            SubmissionError::Seed(_) => SubmissionErrorCode::SeedFailed,
            SubmissionError::CommitteeRun(_) => SubmissionErrorCode::CommitteeRunFailed,
            SubmissionError::Wire { .. } => SubmissionErrorCode::WireError,
            SubmissionError::PayloadTooLarge { .. } => SubmissionErrorCode::PayloadTooLarge,
            SubmissionError::BadResponse(_) => SubmissionErrorCode::BadResponse,
        }
    }
}

/// Node-side response over the submission wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubmissionResponse {
    /// The committee agreed on the program (by hash), ran it, and produced a
    /// result. `result` is an opaque, host-serialized payload.
    Ok {
        job_id: [u8; PROGRAM_ID_LEN],
        result: Vec<u8>,
    },
    /// The submission was rejected before any committee run.
    Rejected {
        code: SubmissionErrorCode,
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Core: prepare a submission (id + tamper check + cache seed)
// ---------------------------------------------------------------------------

/// Compute the blake3 program id, validate an optional client-claimed id, and
/// seed the bytecode into the content-addressed program cache.
///
/// This is the thin, pure, host-agnostic core of the submission entrypoint. It
/// is the single place that decides whether submitted bytecode is trustworthy
/// enough to run: an empty payload, an oversized payload, or a hash mismatch
/// (tamper) each return a typed error and seed nothing. On success the program
/// is reachable by every party via [`program_sync::program_path`] using the
/// returned `job_id`.
///
/// Seeding is idempotent: an existing cache entry for the same hash is left
/// untouched (a re-submit of the same bytes is a no-op, never a corruption).
pub fn prepare_submission(req: &SubmissionRequest) -> Result<SubmissionOutcome, SubmissionError> {
    if req.program_bytes.is_empty() {
        return Err(SubmissionError::EmptyBytecode);
    }
    if req.program_bytes.len() > MAX_PROGRAM_BYTES {
        return Err(SubmissionError::ProgramTooLarge {
            size: req.program_bytes.len(),
            max: MAX_PROGRAM_BYTES,
        });
    }

    // Recompute the content id from the bytes we actually received. This is the
    // trust root: the rest of the system addresses the program by this hash.
    let computed = program_id_from_bytes(&req.program_bytes);

    // Tamper check: if the client asserted an id, it must match the recomputed
    // one. A mismatch is a hard reject — no fallback, no run.
    if let Some(claimed) = req.claimed_program_id {
        if claimed != computed {
            return Err(SubmissionError::ProgramTampered { claimed, computed });
        }
    }

    // Seed the content-addressed cache so any party can fetch the program by
    // hash via program_sync. ensure_cache_dir first so the write has a home.
    ensure_cache_dir()?;
    let path = program_path(&computed);
    if !Path::new(&path).exists() {
        std::fs::write(&path, &req.program_bytes).map_err(|error| {
            SubmissionError::Seed(ProgramSyncError::CacheIo {
                operation: "write",
                path: path.clone(),
                reason: error.to_string(),
            })
        })?;
    }

    Ok(SubmissionOutcome {
        job_id: computed,
        program_size: req.program_bytes.len(),
        entry: req.entry.clone(),
    })
}

// ---------------------------------------------------------------------------
// Committee run dispatch
// ---------------------------------------------------------------------------

/// Host-supplied committee driver.
///
/// The runner receives a [`SubmissionOutcome`] whose program is already seeded
/// in the content-addressed cache (reachable by `outcome.job_id`) and is
/// responsible for: agreeing on the program across the committee
/// (`agree_and_sync_program`), running it, and returning the serialized result.
///
/// The runner reuses the existing `client_store` input path; the submission
/// endpoint introduces no new input mechanism.
#[async_trait]
pub trait CommitteeRunner: Send + Sync {
    /// Run the program identified by `outcome.job_id` across the committee.
    /// Returns the host-serialized result on success.
    async fn run_program(&self, outcome: &SubmissionOutcome) -> Result<Vec<u8>, String>;
}

/// Prepare a submission and, only if it is trustworthy, dispatch it to the
/// committee runner.
///
/// A tampered program short-circuits: the runner is never called. The returned
/// `SubmissionOutcome` carries the `job_id` the committee agreed/synced by.
pub async fn handle_submission<R: CommitteeRunner + ?Sized>(
    req: &SubmissionRequest,
    runner: &R,
) -> Result<(SubmissionOutcome, Vec<u8>), SubmissionError> {
    let outcome = prepare_submission(req)?;
    let result = runner
        .run_program(&outcome)
        .await
        .map_err(SubmissionError::CommitteeRun)?;
    Ok((outcome, result))
}

// ---------------------------------------------------------------------------
// Minimal TCP wire (length-prefixed bincode)
// ---------------------------------------------------------------------------

fn wire_error(operation: &'static str, error: impl std::fmt::Display) -> SubmissionError {
    SubmissionError::Wire {
        operation,
        reason: error.to_string(),
    }
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, SubmissionError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|error| wire_error("read length", error))?;
    let len = u32::from_be_bytes(len_buf) as u64;
    if len > MAX_FRAME_BYTES {
        return Err(SubmissionError::PayloadTooLarge {
            len,
            max: MAX_FRAME_BYTES,
        });
    }
    let mut payload = vec![0u8; len as usize];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|error| wire_error("read payload", error))?;
    Ok(payload)
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), SubmissionError> {
    let len = u32::try_from(payload.len()).map_err(|_| SubmissionError::PayloadTooLarge {
        len: payload.len() as u64,
        max: MAX_FRAME_BYTES,
    })?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|error| wire_error("write length", error))?;
    stream
        .write_all(payload)
        .await
        .map_err(|error| wire_error("write payload", error))?;
    stream
        .flush()
        .await
        .map_err(|error| wire_error("flush", error))?;
    Ok(())
}

/// Serve a single accepted submission connection: decode the request, run it to
/// completion (prepare + committee run), and write the response.
async fn handle_connection<R: CommitteeRunner + ?Sized>(
    mut stream: TcpStream,
    runner: &R,
) -> Result<(), SubmissionError> {
    let req_payload = read_frame(&mut stream).await?;
    let request: SubmissionRequest =
        bincode::deserialize(&req_payload).map_err(|error| wire_error("decode request", error))?;

    let response = match handle_submission(&request, runner).await {
        Ok((outcome, result)) => SubmissionResponse::Ok {
            job_id: outcome.job_id,
            result,
        },
        Err(error) => SubmissionResponse::Rejected {
            code: error.code(),
            message: error.to_string(),
        },
    };

    let resp_payload =
        bincode::serialize(&response).map_err(|error| wire_error("encode response", error))?;
    write_frame(&mut stream, &resp_payload).await?;
    Ok(())
}

/// Run the submission TCP server: accept connections forever, dispatching each
/// through `runner`. Each connection runs exactly one submission.
///
/// Returns only on a fatal accept error. Intended to be `tokio::spawn`-ed by
/// the host node alongside its other duties.
pub async fn serve_submission_tcp<R: CommitteeRunner + 'static>(
    listener: TcpListener,
    runner: Arc<R>,
) -> Result<(), SubmissionError> {
    loop {
        let (stream, _peer) = listener
            .accept()
            .await
            .map_err(|error| wire_error("accept", error))?;
        let runner = runner.clone();
        tokio::spawn(async move {
            // A per-connection failure is reported to the client as a Rejected
            // response by `handle_connection`; only an error building that
            // response (e.g. a dropped socket) is logged here.
            if let Err(error) = handle_connection(stream, runner.as_ref()).await {
                tracing::warn!(?error, "submission connection failed");
            }
        });
    }
}

/// Client: submit a program to a node's submission endpoint over TCP and return
/// the agreed `job_id` plus the committee's serialized result.
///
/// A server-side rejection is surfaced as the corresponding typed
/// [`SubmissionError`].
pub async fn submit_tcp(
    addr: std::net::SocketAddr,
    request: SubmissionRequest,
) -> Result<(SubmissionOutcome, Vec<u8>), SubmissionError> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|error| wire_error("connect", error))?;
    let req_payload =
        bincode::serialize(&request).map_err(|error| wire_error("encode request", error))?;
    write_frame(&mut stream, &req_payload).await?;

    let resp_payload = read_frame(&mut stream).await?;
    let response: SubmissionResponse = bincode::deserialize(&resp_payload)
        .map_err(|error| SubmissionError::BadResponse(error.to_string()))?;

    match response {
        SubmissionResponse::Ok { job_id, result } => Ok((
            SubmissionOutcome {
                job_id,
                program_size: request.program_bytes.len(),
                entry: request.entry,
            },
            result,
        )),
        SubmissionResponse::Rejected { code, message } => Err(reconstruct_error(code, message)),
    }
}

/// Rebuild the most specific typed error from a wire code + message.
fn reconstruct_error(code: SubmissionErrorCode, message: String) -> SubmissionError {
    match code {
        SubmissionErrorCode::EmptyBytecode => SubmissionError::EmptyBytecode,
        SubmissionErrorCode::ProgramTooLarge => SubmissionError::ProgramTooLarge {
            size: 0,
            max: MAX_PROGRAM_BYTES,
        },
        SubmissionErrorCode::ProgramTampered => SubmissionError::ProgramTampered {
            claimed: [0u8; PROGRAM_ID_LEN],
            computed: [0u8; PROGRAM_ID_LEN],
        },
        SubmissionErrorCode::SeedFailed => {
            SubmissionError::Seed(ProgramSyncError::Encode { reason: message })
        }
        SubmissionErrorCode::CommitteeRunFailed => SubmissionError::CommitteeRun(message),
        SubmissionErrorCode::WireError => SubmissionError::Wire {
            operation: "remote",
            reason: message,
        },
        SubmissionErrorCode::PayloadTooLarge => SubmissionError::PayloadTooLarge {
            len: 0,
            max: MAX_FRAME_BYTES,
        },
        SubmissionErrorCode::BadResponse => SubmissionError::BadResponse(message),
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
use std::sync::{Mutex, MutexGuard};

/// Serialize tests that mutate the process-global `STOFFEL_CACHE` env var, so
/// parallel `cargo test` runs (and the hb_itest submission integration test)
/// never stomp on each other's cache root.
#[cfg(test)]
static CACHE_LOCK: Mutex<()> = Mutex::new(());

/// RAII scope that owns a temp cache dir AND the lock guarding the env var.
/// Shared by the submission unit tests and the program-submission integration
/// test (`hb_itest`).
#[cfg(test)]
pub(crate) struct CacheScope {
    _dir: tempfile::TempDir,
    _guard: MutexGuard<'static, ()>,
}

/// Point `STOFFEL_CACHE` at a fresh temp dir for one test so cache writes never
/// collide with other tests or the user's real cache. Holds the serialization
/// lock for the scope's lifetime.
#[cfg(test)]
pub(crate) fn scoped_cache() -> CacheScope {
    let guard = CACHE_LOCK
        .lock()
        .expect("submission cache test lock poisoned");
    let dir = tempfile::tempdir().expect("temp dir for submission cache");
    // SAFETY: process-local env mutation, serialized by CACHE_LOCK.
    std::env::set_var("STOFFEL_CACHE", dir.path());
    assert_eq!(cache_dir(), dir.path());
    CacheScope {
        _dir: dir,
        _guard: guard,
    }
}

/// A [`CommitteeRunner`] that records every invocation and returns a fixed
/// result derived from the job id. Used by the unit tests to prove the tamper
/// check short-circuits before the runner is called.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct RecordingRunner {
    pub(crate) invocations: AtomicU64,
}

#[cfg(test)]
#[async_trait]
impl CommitteeRunner for RecordingRunner {
    async fn run_program(&self, outcome: &SubmissionOutcome) -> Result<Vec<u8>, String> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(outcome.job_id.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_program() -> Vec<u8> {
        // A small, stable, non-trivial bytecode stand-in. The submission layer
        // never parses it; it only hashes it.
        b"stoffel-sample-program-v1\0padding-padding-padding".to_vec()
    }

    #[test]
    fn prepare_submission_computes_id_and_seeds_cache() {
        let _cache = scoped_cache();
        let bytes = sample_program();
        let expected_id = program_id_from_bytes(&bytes);

        let outcome = prepare_submission(&SubmissionRequest::new(bytes.clone(), "main"))
            .expect("valid submission prepares");

        assert_eq!(outcome.job_id, expected_id);
        assert_eq!(outcome.program_size, bytes.len());
        assert_eq!(outcome.entry, "main");
        // The program is now reachable by hash.
        assert!(
            Path::new(&program_path(&expected_id)).exists(),
            "program must be seeded into the content-addressed cache"
        );
    }

    #[test]
    fn prepare_submission_is_idempotent() {
        let _cache = scoped_cache();
        let bytes = sample_program();
        let id = program_id_from_bytes(&bytes);

        let first = prepare_submission(&SubmissionRequest::new(bytes.clone(), "main"))
            .expect("first prepare");
        let second = prepare_submission(&SubmissionRequest::new(bytes.clone(), "main"))
            .expect("second prepare");

        assert_eq!(first.job_id, second.job_id);
        assert_eq!(first.job_id, id);
        // Re-seeding must not corrupt the cached bytes.
        let on_disk = std::fs::read(program_path(&id)).unwrap();
        assert_eq!(on_disk, bytes);
    }

    #[test]
    fn prepare_submission_rejects_empty_bytecode() {
        let _cache = scoped_cache();
        let err = prepare_submission(&SubmissionRequest::new(Vec::new(), "main")).unwrap_err();
        assert_eq!(err, SubmissionError::EmptyBytecode);
        assert_eq!(err.code(), SubmissionErrorCode::EmptyBytecode);
    }

    #[test]
    fn prepare_submission_rejects_tampered_claimed_id() {
        let _cache = scoped_cache();
        let bytes = sample_program();
        let computed = program_id_from_bytes(&bytes);
        let claimed = match computed {
            [first, rest @ ..] => {
                let mut c = [first ^ 0xff; 32];
                c[1..].copy_from_slice(&rest);
                c
            }
        };
        assert_ne!(claimed, computed, "test precondition: claimed differs");

        let req = SubmissionRequest::new(bytes, "main").with_claimed_program_id(claimed);
        let err = prepare_submission(&req).unwrap_err();

        match err {
            SubmissionError::ProgramTampered {
                claimed: c,
                computed: comp,
            } => {
                assert_eq!(c, claimed);
                assert_eq!(comp, computed);
            }
            other => panic!("expected ProgramTampered, got {other:?}"),
        }
        assert_eq!(err.code(), SubmissionErrorCode::ProgramTampered);
        // A tampered submission must seed nothing.
        assert!(
            !Path::new(&program_path(&computed)).exists(),
            "tampered program must not be seeded"
        );
    }

    #[test]
    fn prepare_submission_accepts_matching_claimed_id() {
        let _cache = scoped_cache();
        let bytes = sample_program();
        let claimed = program_id_from_bytes(&bytes);
        let outcome = prepare_submission(
            &SubmissionRequest::new(bytes, "main").with_claimed_program_id(claimed),
        )
        .expect("matching claimed id is accepted");
        assert_eq!(outcome.job_id, claimed);
    }

    #[test]
    fn prepare_submission_rejects_oversized_bytecode() {
        let _cache = scoped_cache();
        let oversized = vec![0u8; MAX_PROGRAM_BYTES + 1];
        let err = prepare_submission(&SubmissionRequest::new(oversized, "main")).unwrap_err();
        assert_eq!(
            err,
            SubmissionError::ProgramTooLarge {
                size: MAX_PROGRAM_BYTES + 1,
                max: MAX_PROGRAM_BYTES,
            }
        );
    }

    #[tokio::test]
    async fn handle_submission_runs_committee_after_prepare() {
        let _cache = scoped_cache();
        let runner = RecordingRunner::default();
        let bytes = sample_program();
        let id = program_id_from_bytes(&bytes);

        let (outcome, result) = handle_submission(&SubmissionRequest::new(bytes, "main"), &runner)
            .await
            .expect("valid submission runs");
        assert_eq!(outcome.job_id, id);
        assert_eq!(result, id.to_vec());
        assert_eq!(runner.invocations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn handle_submission_short_circuits_on_tamper_without_running() {
        let _cache = scoped_cache();
        let runner = RecordingRunner::default();
        let bytes = sample_program();
        let computed = program_id_from_bytes(&bytes);
        let claimed = [0xffu8; 32];

        let err = handle_submission(
            &SubmissionRequest::new(bytes, "main").with_claimed_program_id(claimed),
            &runner,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), SubmissionErrorCode::ProgramTampered);
        assert_eq!(
            runner.invocations.load(Ordering::SeqCst),
            0,
            "a tampered submission must never reach the committee runner"
        );
        assert!(
            !Path::new(&program_path(&computed)).exists(),
            "tampered submission must seed nothing"
        );
    }
}
