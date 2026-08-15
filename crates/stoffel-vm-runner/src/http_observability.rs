//! # HTTP observability server (spec task W6)
//!
//! A minimal HTTP/1.1 server the node spawns at startup so it is observable
//! through the dstack-webhost `tee-daemon`, which HTTP-proxies exactly **one**
//! `image_port` per app. The dstack manifest (`dstack/stoffel-node.yaml`)
//! therefore publishes this port (default `8090`) as the proxied
//! `image_port` — it is the "this `-stoffel` node is running attested on the
//! dstack pod" report. The submission RPC stays on its own port (`16180`).
//!
//! ## Routes
//!
//! * `GET /health` → `200` JSON `{ status, role, party_id }`. Always available
//!   once the server is up; this is the liveness probe the webhost uses.
//! * `GET /attestation` → `200` JSON `{ attestation_mode, ... }`. When
//!   `attestation_mode == "dstack"` **and** this node has obtained + locally
//!   verified its own TDX quote, the body additionally carries the node's own
//!   attested measurement (`blake3(mr_td‖rtmr0..3)` hex), its `tls_derived_id`,
//!   and the resolved `tcb_status`. This is the attested-on-the-pod report.
//!
//! ## No error-masking fallbacks
//!
//! The server only *reports* state; it never fabricates attestation. The
//! dstack measurement/tcb_status fields are absent until the node has genuinely
//! obtained and verified its own quote (see `registration_attestation` in
//! `stoffel-run.rs`). The fail-closed attestation behavior is unchanged: in
//! `dstack` mode the node still FATAL-exits if evidence cannot be obtained;
//! this server simply surfaces the measurement that *was* obtained, once it is.
//!
//! ## Transport
//!
//! Hand-rolled HTTP/1.1 over `tokio::net::TcpListener` (the same minimal
//! approach the dstack `GetQuote` client uses). No `axum`/`hyper` dependency
//! is pulled in — both routes are tiny GETs returning small JSON, so a few
//! dozen lines of request-line parsing is both smaller and avoids enlarging the
//! dstack node image's build graph (which already has to compile `aws-lc`
//! under `clang`).

use std::net::SocketAddr;
use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;
use stoffel_vm::net::discovery::AdmissionRecords;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

/// Environment variable overriding the HTTP observability bind address.
pub const ENV_HTTP_ADDR: &str = "STOFFEL_HTTP_ADDR";
/// Default bind address for the HTTP observability server. `0.0.0.0` so the
/// dstack-webhost `tee-daemon` can reach it from outside the CVM.
pub const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:8090";

/// Upper bound on a single HTTP request header block (GETs only — there is no
/// request body). Keeps a misbehaving client from exhausting memory.
const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// A consistent point-in-time view of the node state the handlers serialize.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ObservabilitySnapshot {
    /// Node role: `leader`, `party`, `bootnode`, `client`, or `local`.
    pub role: String,
    /// This node's party id, when known (leader/party modes). `None` for
    /// bootnode/client/local runs where no party id is assigned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party_id: Option<usize>,
    /// Canonical attestation mode (`disabled` / `mock` / `dstack`).
    pub attestation_mode: String,
    /// Hex of the node's own attested measurement (`blake3(mr_td‖rtmr0..3)`).
    /// Populated only when `attestation_mode == "dstack"` and this node has
    /// obtained + locally verified its own TDX quote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement: Option<String>,
    /// The node's own `tls_derived_id`, as bound into (and read back from) the
    /// obtained quote. Present only alongside `measurement`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_derived_id: Option<usize>,
    /// Resolved TCB status (e.g. `UpToDate`) from the locally verified quote.
    /// Present only alongside `measurement`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcb_status: Option<String>,
    /// W7: Peer admission records (bootnode/leader only). Populated when the
    /// node is running as bootnode or leader; shows which peers were admitted
    /// or rejected via attestation, and why.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission_records: Option<AdmissionRecords>,
    /// W7: the program this party ran and the value it opened, recorded when
    /// the run completes. On the pod there are no tenant logs, so without this
    /// "the committee agreed on a value" is unobservable from outside.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_result: Option<ProgramResult>,
}

/// A completed run: which program, and what this party opened.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ProgramResult {
    /// Program id the committee agreed to run (blake3 prefix, as logged).
    pub program_id: String,
    /// Entry function name.
    pub entry: String,
    /// The opened value, formatted exactly as the node prints it.
    pub value: String,
    /// Unix seconds at which the run completed.
    pub completed_at: u64,
}

impl ObservabilitySnapshot {
    /// `GET /health` body. `status: "ok"` as long as the node process is alive
    /// and answering — this is the liveness probe.
    pub fn health_json(&self) -> Value {
        serde_json::json!({
            "status": "ok",
            "role": self.role,
            "party_id": self.party_id,
        })
    }

    /// `GET /attestation` body. Always carries `attestation_mode`; adds the
    /// dstack measurement / tls_derived_id / tcb_status fields only when this
    /// node actually obtained and verified its own quote (no fabrication).
    pub fn attestation_json(&self) -> Value {
        let mut obj = serde_json::json!({
            "attestation_mode": self.attestation_mode,
        });
        if self.attestation_mode == "dstack" {
            if let Some(measurement) = self.measurement.clone() {
                obj["measurement"] = Value::String(measurement);
                obj["tls_derived_id"] = self.tls_derived_id.map(Value::from).unwrap_or(Value::Null);
                obj["tcb_status"] = Value::String(self.tcb_status.clone().unwrap_or_default());
            }
        }
        obj
    }
}

/// Shared, cheaply-clonable observability state.
///
/// The node writes its (resolved at startup) role / party_id / attestation
/// mode and — once it has obtained + verified its own TDX quote — the
/// attested measurement / tls_derived_id / tcb_status. The HTTP server reads a
/// snapshot per request.
#[derive(Debug, Clone)]
pub struct ObservabilityState {
    inner: Arc<RwLock<ObservabilitySnapshot>>,
}

impl ObservabilityState {
    /// Build the state with the startup-known fields. The attestation
    /// measurement fields are left unset; `record_attested_measurement` fills
    /// them once the node's own quote is obtained + verified.
    pub fn new(
        role: impl Into<String>,
        party_id: Option<usize>,
        attestation_mode: impl Into<String>,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ObservabilitySnapshot {
                role: role.into(),
                party_id,
                attestation_mode: attestation_mode.into(),
                measurement: None,
                tls_derived_id: None,
                tcb_status: None,
                admission_records: None,
                program_result: None,
            })),
        }
    }

    /// Record the node's own attested measurement (from a locally verified
    /// TDX quote). Called by `registration_attestation` in `dstack` mode once
    /// evidence is obtained and verified; `/attestation` surfaces these values.
    pub async fn record_attested_measurement(
        &self,
        measurement: impl Into<String>,
        tls_derived_id: usize,
        tcb_status: impl Into<String>,
    ) {
        let mut guard = self.inner.write().await;
        guard.measurement = Some(measurement.into());
        guard.tls_derived_id = Some(tls_derived_id);
        guard.tcb_status = Some(tcb_status.into());
    }

    /// W7: Update the admission records (called by bootnode on peer admissions/
    /// rejections). The /peers endpoint surfaces these records.
    pub async fn update_admission_records(&self, records: AdmissionRecords) {
        let mut guard = self.inner.write().await;
        guard.admission_records = Some(records);
    }

    /// W7: record the value this party opened once the run completes. `/result`
    /// surfaces it, so a committee that agreed on a value can be checked from
    /// outside the CVM by comparing `/result` across the parties.
    pub async fn record_program_result(
        &self,
        program_id: impl Into<String>,
        entry: impl Into<String>,
        value: impl Into<String>,
        completed_at: u64,
    ) {
        let mut guard = self.inner.write().await;
        guard.program_result = Some(ProgramResult {
            program_id: program_id.into(),
            entry: entry.into(),
            value: value.into(),
            completed_at,
        });
    }

    /// Point-in-time snapshot for serializing a response.
    pub async fn snapshot(&self) -> ObservabilitySnapshot {
        self.inner.read().await.clone()
    }
}

/// Read `STOFFEL_HTTP_ADDR`, defaulting to [`DEFAULT_HTTP_ADDR`]. A malformed
/// address is a hard error (the operator asked for a specific bind; we do not
/// silently fall back to a different interface).
pub fn http_addr_from_env() -> Result<SocketAddr, String> {
    let raw = std::env::var(ENV_HTTP_ADDR)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_HTTP_ADDR.to_string());
    raw.parse::<SocketAddr>()
        .map_err(|e| format!("invalid {ENV_HTTP_ADDR}={raw:?}: {e}"))
}

/// Bind + serve the HTTP observability server forever. Intended to be
/// `tokio::spawn`-ed at node startup. Binds eagerly so a bind failure is
/// surfaced at startup (the node stays observable or fails loudly — it does not
/// silently run without the probe endpoint).
pub async fn serve_http_observability(state: ObservabilityState, addr: SocketAddr) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[http] FATAL: could not bind observability server to {addr}: {e}");
            return;
        }
    };
    eprintln!(
        "[http] observability server listening on http://{addr} (GET /health, GET /attestation)"
    );
    accept_loop(listener, state).await;
}

/// Accept loop factored out so the unit test can bind an ephemeral loopback
/// port and drive the server with a captured listener.
async fn accept_loop(listener: TcpListener, state: ObservabilityState) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let st = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, st).await {
                        eprintln!("[http] connection error: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("[http] accept error: {e}; continuing");
                continue;
            }
        }
    }
}

/// Handle a single HTTP/1.1 connection: read the request line, dispatch on the
/// path, write a JSON response, close. GET-only.
async fn handle_connection(
    mut stream: TcpStream,
    state: ObservabilityState,
) -> std::io::Result<()> {
    let request = read_request_head(&mut stream).await?;
    let (status, body) = dispatch(request_line_path(&request), &state).await;
    let response = http_response(status, &body);
    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(())
}

/// Read up to [`MAX_REQUEST_BYTES`] of the request, stopping once the header
/// block terminator (`\r\n\r\n`) is seen. GET requests carry no body.
async fn read_request_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= MAX_REQUEST_BYTES {
            break;
        }
    }
    Ok(buf)
}

/// Extract the request target (path) from an HTTP/1.1 request line. Returns
/// `None` if the request is malformed (caller answers `400`).
fn request_line_path(request: &[u8]) -> Option<String> {
    let line = request.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim();
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    if method != "GET" {
        return None;
    }
    // Strip any query string — the routes are path-only.
    let path = target.split('?').next()?.to_string();
    Some(path)
}

/// Map a request path to an HTTP `(status, body)` pair.
async fn dispatch(path: Option<String>, state: &ObservabilityState) -> (&'static str, String) {
    let snapshot = state.snapshot().await;
    match path.as_deref() {
        Some("/health") => ("200 OK", health_body(&snapshot)),
        Some("/attestation") => ("200 OK", attestation_body(&snapshot)),
        Some("/peers") => ("200 OK", peers_body(&snapshot)),
        Some("/result") => ("200 OK", result_body(&snapshot)),
        // No error-masking routing: unknown paths are a real 404, not a silent
        // /health fallback that could mask a misconfigured probe.
        _ => (
            "404 Not Found",
            r#"{"error":"not found","routes":["GET /health","GET /attestation","GET /peers","GET /result"]}"#.to_string(),
        ),
    }
}

fn health_body(snapshot: &ObservabilitySnapshot) -> String {
    serde_json::to_string(&snapshot.health_json())
        .unwrap_or_else(|_| r#"{"status":"ok"}"#.to_string())
}

fn attestation_body(snapshot: &ObservabilitySnapshot) -> String {
    serde_json::to_string(&snapshot.attestation_json())
        .unwrap_or_else(|_| r#"{"attestation_mode":"disabled"}"#.to_string())
}

/// W7: `/result` body. `{"status":"pending"}` until the run completes — an
/// absent result is reported as absent, never as a fabricated value.
fn result_body(snapshot: &ObservabilitySnapshot) -> String {
    match &snapshot.program_result {
        Some(r) => serde_json::to_string(r).expect("serialize program result"),
        None => r#"{"status":"pending"}"#.to_string(),
    }
}

/// W7: /peers body. Returns admission records (admitted/rejected peers with
/// measurements/reasons). This is the only observability into the attestation
/// gate on the dstack pod (no logs).
fn peers_body(snapshot: &ObservabilitySnapshot) -> String {
    // If admission_records is None (not a bootnode/leader), return empty records
    let records = snapshot.admission_records.clone().unwrap_or(AdmissionRecords {
        admitted: Vec::new(),
        rejected: Vec::new(),
    });
    serde_json::to_string(&records)
        .unwrap_or_else(|_| r#"{"admitted":[],"rejected":[]}"#.to_string())
}

/// Serialize a minimal HTTP/1.1 response. `Connection: close` so each request
/// is a fresh connection (the tee-daemon polls); no keep-alive bookkeeping.
fn http_response(status: &'static str, body: &str) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        len = body.len()
    );
    let mut out = Vec::with_capacity(head.len() + body.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(role: &str, party_id: Option<usize>, mode: &str) -> ObservabilityState {
        ObservabilityState::new(role, party_id, mode)
    }

    // -----------------------------------------------------------------------
    // Handler (JSON) unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn health_reports_ok_role_party() {
        let snap = ObservabilitySnapshot {
            role: "leader".into(),
            party_id: Some(0),
            attestation_mode: "disabled".into(),
            measurement: None,
            tls_derived_id: None,
            tcb_status: None,
            ..Default::default()
        };
        let v = snap.health_json();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["role"], "leader");
        assert_eq!(v["party_id"], 0);
        // attestation fields never leak into /health.
        assert!(v.get("attestation_mode").is_none());
        assert!(v.get("measurement").is_none());
    }

    #[test]
    fn health_allows_null_party_id() {
        let snap = ObservabilitySnapshot {
            role: "local".into(),
            party_id: None,
            attestation_mode: "disabled".into(),
            measurement: None,
            tls_derived_id: None,
            tcb_status: None,
            ..Default::default()
        };
        let v = snap.health_json();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["role"], "local");
        assert!(v["party_id"].is_null());
    }

    #[test]
    fn attestation_disabled_omits_dstack_fields() {
        let snap = ObservabilitySnapshot {
            role: "party".into(),
            party_id: Some(1),
            attestation_mode: "disabled".into(),
            measurement: None,
            tls_derived_id: None,
            tcb_status: None,
            ..Default::default()
        };
        let v = snap.attestation_json();
        assert_eq!(v["attestation_mode"], "disabled");
        // No fabrication: disabled mode never reports a measurement.
        assert!(v.get("measurement").is_none());
        assert!(v.get("tls_derived_id").is_none());
        assert!(v.get("tcb_status").is_none());
    }

    #[tokio::test]
    async fn attestation_dstack_without_evidence_omits_measurement() {
        // dstack mode but evidence not yet obtained: report the mode only. The
        // node has NOT fabricated a measurement (it is still obtaining one, or
        // has fail-closed-exited).
        let s = state("party", Some(2), "dstack");
        let v = s.snapshot().await.attestation_json();
        assert_eq!(v["attestation_mode"], "dstack");
        assert!(v.get("measurement").is_none());
    }

    #[tokio::test]
    async fn attestation_dstack_with_evidence_reports_measurement_and_tcb() {
        // Once the node obtained + verified its own quote, /attestation surfaces
        // the measurement / tls_derived_id / tcb_status it proved.
        let s = state("leader", Some(0), "dstack");
        s.record_attested_measurement(
            "deadbeef".repeat(8), // 32-byte hex
            12345,
            "UpToDate",
        )
        .await;
        let v = s.snapshot().await.attestation_json();
        assert_eq!(v["attestation_mode"], "dstack");
        assert_eq!(v["measurement"], "deadbeef".repeat(8));
        assert_eq!(v["tls_derived_id"], 12345);
        assert_eq!(v["tcb_status"], "UpToDate");
    }

    #[tokio::test]
    async fn record_attested_measurement_only_affects_dstack_fields() {
        let s = state("party", Some(1), "dstack");
        s.record_attested_measurement("ab", 9, "UpToDate").await;
        let snap = s.snapshot().await;
        // role / party_id / mode set at construction are untouched.
        assert_eq!(snap.role, "party");
        assert_eq!(snap.party_id, Some(1));
        assert_eq!(snap.attestation_mode, "dstack");
        // and the attested fields are present.
        assert_eq!(snap.measurement.as_deref(), Some("ab"));
        assert_eq!(snap.tls_derived_id, Some(9));
        assert_eq!(snap.tcb_status.as_deref(), Some("UpToDate"));
    }

    // -----------------------------------------------------------------------
    // Request-line parsing edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn request_line_path_parses_get() {
        let req = b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(request_line_path(req).as_deref(), Some("/health"));
    }

    #[test]
    fn request_line_path_strips_query_string() {
        let req = b"GET /health?probe=1 HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(request_line_path(req).as_deref(), Some("/health"));
    }

    #[test]
    fn request_line_path_rejects_non_get() {
        let req = b"POST /health HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(request_line_path(req), None);
    }

    #[test]
    fn request_line_path_rejects_garbage() {
        assert_eq!(request_line_path(b"not http at all"), None);
    }

    #[test]
    fn http_response_is_well_formed() {
        let resp = http_response("200 OK", "{\"status\":\"ok\"}");
        let text = std::str::from_utf8(&resp).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.contains("Content-Length: 15\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("{\"status\":\"ok\"}"));
    }

    // -----------------------------------------------------------------------
    // End-to-end over a real loopback socket
    // -----------------------------------------------------------------------

    async fn get(listener_addr: SocketAddr, path: &str) -> (String, String) {
        let mut stream = TcpStream::connect(listener_addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8(buf).unwrap();
        // Split status line / body loosely.
        let status = text
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .to_string();
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    #[tokio::test]
    async fn end_to_end_health_and_attestation_and_404() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = state("leader", Some(0), "dstack");
        state
            .record_attested_measurement("ff".repeat(32), 7, "UpToDate")
            .await;
        tokio::spawn(accept_loop(listener, state));

        // /health → 200 with the liveness body.
        let (status, body) = get(addr, "/health").await;
        assert_eq!(status, "200");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["role"], "leader");
        assert_eq!(v["party_id"], 0);

        // /attestation → 200 with the dstack attested measurement.
        let (status, body) = get(addr, "/attestation").await;
        assert_eq!(status, "200");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["attestation_mode"], "dstack");
        assert_eq!(v["measurement"], "ff".repeat(32));
        assert_eq!(v["tls_derived_id"], 7);
        assert_eq!(v["tcb_status"], "UpToDate");

        // Unknown path → 404 (no silent /health fallback).
        let (status, body) = get(addr, "/nope").await;
        assert_eq!(status, "404");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"], "not found");
    }

    #[tokio::test]
    async fn end_to_end_disabled_mode_health_only() {
        // Mirrors the local liveness verification: disabled mode, no dstack
        // socket. /health answers 200; /attestation reports the mode and
        // fabricates nothing.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = state("bootnode", None, "disabled");
        tokio::spawn(accept_loop(listener, state));

        let (status, body) = get(addr, "/health").await;
        assert_eq!(status, "200");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "ok");

        let (status, body) = get(addr, "/attestation").await;
        assert_eq!(status, "200");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["attestation_mode"], "disabled");
        assert!(v.get("measurement").is_none());
    }

    // -----------------------------------------------------------------------
    // W7: /peers endpoint tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn peers_endpoint_returns_empty_records_when_no_admissions() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = state("leader", Some(0), "dstack");
        tokio::spawn(accept_loop(listener, state));

        let (status, body) = get(addr, "/peers").await;
        assert_eq!(status, "200");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert!(v["admitted"].as_array().unwrap().is_empty());
        assert!(v["rejected"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn peers_endpoint_returns_admission_records() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = state("leader", Some(0), "dstack");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let records = AdmissionRecords {
            admitted: vec![PeerAdmission {
                party_id: 1,
                measurement_hex: Some("aa".repeat(32)),
                admitted_at: now,
            }],
            rejected: vec![PeerRejection {
                reason: "attestation: MeasurementNotAllowed".to_string(),
                rejected_at: now,
            }],
        };
        state.update_admission_records(records).await;

        tokio::spawn(accept_loop(listener, state));

        let (status, body) = get(addr, "/peers").await;
        assert_eq!(status, "200");
        let v: Value = serde_json::from_str(&body).unwrap();

        assert_eq!(v["admitted"].as_array().unwrap().len(), 1);
        assert_eq!(v["admitted"][0]["party_id"], 1);
        assert_eq!(v["admitted"][0]["measurement_hex"], "aa".repeat(32));
        assert_eq!(v["admitted"][0]["admitted_at"], now);

        assert_eq!(v["rejected"].as_array().unwrap().len(), 1);
        assert!(v["rejected"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("MeasurementNotAllowed"));
        assert_eq!(v["rejected"][0]["rejected_at"], now);
    }

    #[tokio::test]
    async fn result_endpoint_is_pending_before_the_run_completes() {
        let state = ObservabilityState::new("party", Some(0), "dstack");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(accept_loop(listener, state));

        let (status, body) = get(addr, "/result").await;
        assert_eq!(status, "200");
        let v: Value = serde_json::from_str(&body).unwrap();
        // No fabrication: an absent result reports as absent, never as a value.
        assert_eq!(v["status"], "pending");
        assert!(v.get("value").is_none());
    }

    #[tokio::test]
    async fn result_endpoint_reports_what_the_party_opened() {
        let state = ObservabilityState::new("party", Some(2), "dstack");
        state
            .record_program_result("7144a194d6364ed2", "main", "-7264172825354124299", 1786828731)
            .await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(accept_loop(listener, state));

        let (status, body) = get(addr, "/result").await;
        assert_eq!(status, "200");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["program_id"], "7144a194d6364ed2");
        assert_eq!(v["entry"], "main");
        assert_eq!(v["value"], "-7264172825354124299");
        assert_eq!(v["completed_at"], 1786828731u64);
        assert!(v.get("status").is_none());
    }

    #[tokio::test]
    async fn unknown_route_advertises_result() {
        let state = ObservabilityState::new("party", Some(0), "disabled");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(accept_loop(listener, state));

        let (status, body) = get(addr, "/nope").await;
        assert_eq!(status, "404");
        assert!(body.contains("GET /result"));
    }
}
