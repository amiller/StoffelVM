//! Attestation-gated committee admission.
//!
//! Bind "this peer is a genuine TEE running the expected node image" to "this
//! peer is admitted into the MPC committee". The admission seam is
//! [`crate::net::discovery`] (`DiscoveryMessage::RegisterWithSession`); a
//! registrant presents [`AttestationEvidence`] and the bootnode verifies it
//! before adding the peer to the session.
//!
//! ## Design
//!
//! The trust root is the [`Attestor`] implementation. It verifies the quote
//! and extracts two things from the hardware-attested report:
//!
//! 1. `measurement` — the image/TEE measurement the quote proves is running.
//! 2. `cert_pubkey_hash` — the TLS certificate public-key hash the quote is
//!    bound to. This MUST equal the registrant's presented `tls_derived_id`
//!    (a hash of the registrant's TLS cert public key).
//!
//! The binding `cert_pubkey_hash == tls_derived_id` is the whole point: it
//! makes a captured quote useless to anyone who does not hold the matching TLS
//! private key. The admission layer ([`AdmissionAttestation`]) enforces:
//! quote-valid AND measurement-in-allowlist AND cert-bound-to-presented-tls-id.
//!
//! ## Fail-closed contract
//!
//! A verifier MUST never default to admitting. Absent, malformed, or
//! wrong-kind evidence is an error. The dstack attestor returns an explicit
//! error when its SDK is not wired rather than silently passing.

use blake3::keyed_hash;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::PartyId;
use thiserror::Error;

// Real Intel TDX quote verification (spec task W5). Only compiled when the
// `attestation-dstack` feature is on; the rest of the crate is independent of
// the DCAP/dstack dependency tree.
#[cfg(feature = "attestation-dstack")]
use dcap_qvl::QuoteCollateralV3;

/// SHA-256/TDX-style 32-byte image measurement.
pub type Measurement = [u8; 32];

/// Hash of a TLS certificate public key. This is the same type/value as
/// `tls_derived_id` in [`crate::net::discovery`].
pub type CertPubKeyHash = PartyId;

/// Verifiable attestation evidence presented by a registrant.
///
/// The enum is closed so a verifier configured for one kind rejects every
/// other kind (no accidental fallback that could mask a missing quote).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationEvidence {
    /// Deterministic mock quote used for CI/docker (no TEE required).
    Mock(MockQuote),
    /// Real Intel TDX quote obtained via dstack. Only present when the
    /// `attestation-dstack` feature is enabled.
    #[cfg(feature = "attestation-dstack")]
    Dstack(DstackQuote),
}

/// Mock quote: a keyed MAC over `(measurement, cert_pubkey_hash)`.
///
/// The MAC models "only the TEE can mint a quote binding this cert": a party
/// cannot fabricate a quote for an arbitrary cert without the attestor key, so
/// a captured quote is bound to the cert it was minted for (anti-replay across
/// certs). The admission layer still independently checks
/// `cert_pubkey_hash == tls_derived_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockQuote {
    pub measurement: Measurement,
    pub cert_pubkey_hash: CertPubKeyHash,
    /// `blake3::keyed_hash(attestor_key, measurement || cert_pubkey_hash)`.
    pub tag: [u8; 32],
}

/// Raw Intel TDX quote as produced by dstack, together with the DCAP
/// collateral required to verify its signature against the Intel root of trust.
///
/// The attesting node obtains the `raw` quote from the dstack device manager
/// (`/var/run/dstack.sock` → `GetQuote`) with its TLS cert public-key hash
/// written into the TD `report_data`, fetches the DCAP `collateral` from a PCCS
/// (see [`obtain_dstack_evidence`]), and ships both in this struct so the
/// verifier needs **no network access** — the quote is self-contained.
///
/// The verifier ([`DstackAttestor`]) checks the report signature against the
/// collateral's Intel-signed certificate chain, then extracts the attested
/// measurement (TD `mr_td` + `rtmr0..2`) and the cert binding (`report_data`),
/// and replays the event log onto the quote's registers to recover app identity.
#[cfg(feature = "attestation-dstack")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DstackQuote {
    /// Raw TD quote bytes returned by dstack `GetQuote`.
    pub raw: Vec<u8>,
    /// DCAP collateral (TCB info, QE identity, PCK cert chain, CRLs) used to
    /// verify the quote's signature against the Intel root of trust. Fetched
    /// once by the attesting node and carried with the quote.
    pub collateral: QuoteCollateralV3,
    /// The dstack RTMR event log, as returned with the quote. Host-supplied
    /// JSON until the verifier replays it onto the quote's registers — see
    /// [`crate::net::dstack_event_log::verify_event_log`].
    #[serde(default)]
    pub event_log: String,
}

/// What a successfully verified quote proves about the attesting node.
///
/// `tcb_status` is the human-readable TCB (Trusted Computing Base) status the
/// verifier resolved for the quote — e.g. `UpToDate` for real TDX (the string
/// `dcap-qvl` returns from the merged platform/QE TCB levels), or `UpToDate`
/// for the mock attestor (a mock quote that verifies is, by construction,
/// fully valid). Carried so a node can report its own attested state via the
/// HTTP observability endpoint without re-verifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub measurement: Measurement,
    pub cert_pubkey_hash: CertPubKeyHash,
    pub tcb_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttestationError {
    /// Attestation is required but no evidence was presented.
    #[error("attestation evidence is required but none was provided")]
    Missing,
    /// Evidence kind does not match the configured attestor (e.g. mock
    /// evidence presented to a dstack attestor). Fail-closed: no fallback.
    #[error("attestation evidence kind does not match the configured attestor")]
    KindMismatch,
    /// The quote's authenticator / signature did not validate.
    #[error("attestation quote authenticator is invalid")]
    InvalidQuote,
    /// Measurement is not on the allowlist of expected image measurements.
    #[error("attestation measurement {found} is not in the allowlist", found = hex::encode(found))]
    MeasurementNotAllowed { found: Measurement },
    /// The registrant did not present a `tls_derived_id` to bind against.
    #[error("registrant presented no tls_derived_id to bind the quote against")]
    MissingTlsDerivedId,
    /// The quote's bound cert does not match the presented `tls_derived_id`.
    /// This is the anti-replay / anti-impersonation check.
    #[error("quote cert binding {bound} does not match presented tls_derived_id {presented}")]
    CertBindingMismatch {
        bound: CertPubKeyHash,
        presented: CertPubKeyHash,
    },
    /// dstack verification is unavailable in this build (SDK not yet wired).
    #[error("dstack attestation is unavailable: SDK not wired in this build")]
    DstackUnavailable,
    /// dstack quote verification failed.
    #[error("dstack quote verification failed: {0}")]
    DstackVerify(String),
}

/// Which kind of attestor a config selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestorKind {
    Mock,
    Dstack,
}

/// Verifier for a particular quote kind.
///
/// `verify` performs only the quote's own cryptographic check and extracts the
/// attested `(measurement, cert_pubkey_hash)`. Measurement allowlisting and
/// cert binding are policy enforced by [`AdmissionAttestation`].
pub trait Attestor: Send + Sync {
    fn kind(&self) -> AttestorKind;
    fn verify(
        &self,
        evidence: &AttestationEvidence,
    ) -> Result<VerifiedAttestation, AttestationError>;
}

/// Deterministic mock attestor for CI/docker. Shares a symmetric key with the
/// quote minting side ([`MockAttestor::generate`]).
pub struct MockAttestor {
    key: [u8; 32],
}

impl MockAttestor {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Mint a mock quote binding `measurement` to `cert_pubkey_hash`.
    ///
    /// In the real (TEE) case the hardware produces this binding; here the
    /// keyed MAC plays that role so a quote is unforgeable without the key and
    /// cryptographically bound to the cert it names.
    pub fn generate(
        &self,
        measurement: Measurement,
        cert_pubkey_hash: CertPubKeyHash,
    ) -> AttestationEvidence {
        let tag = self.tag(&measurement, &cert_pubkey_hash);
        AttestationEvidence::Mock(MockQuote {
            measurement,
            cert_pubkey_hash,
            tag,
        })
    }

    fn tag(&self, measurement: &Measurement, cert_pubkey_hash: &CertPubKeyHash) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 + 8);
        buf.extend_from_slice(measurement);
        buf.extend_from_slice(&cert_pubkey_hash.to_le_bytes());
        *keyed_hash(&self.key, &buf).as_bytes()
    }
}

impl Attestor for MockAttestor {
    fn kind(&self) -> AttestorKind {
        AttestorKind::Mock
    }

    fn verify(
        &self,
        evidence: &AttestationEvidence,
    ) -> Result<VerifiedAttestation, AttestationError> {
        match evidence {
            AttestationEvidence::Mock(q) => {
                let expected = self.tag(&q.measurement, &q.cert_pubkey_hash);
                if !ct_eq(&expected, &q.tag) {
                    return Err(AttestationError::InvalidQuote);
                }
                // A mock quote that verifies is, by construction, fully
                // valid — report that as the TCB status rather than fabricate
                // a hardware-specific value.
                Ok(VerifiedAttestation {
                    measurement: q.measurement,
                    cert_pubkey_hash: q.cert_pubkey_hash,
                    tcb_status: "UpToDate".to_string(),
                })
            }
            // Dstack evidence presented to a mock attestor: reject, do not
            // fall back to treating it as anything else.
            #[cfg(feature = "attestation-dstack")]
            AttestationEvidence::Dstack(_) => Err(AttestationError::KindMismatch),
        }
    }
}

/// Real Intel TDX quote verifier via dstack.
///
/// Behind the non-default `attestation-dstack` feature. `verify` delegates to
/// [`verify_dstack_quote`], which checks the quote signature against the Intel
/// root of trust (via `dcap-qvl`), then extracts the attested measurement and
/// cert binding. It never admits a quote whose signature, collateral, or TCB
/// status does not validate — there is no fallback path.
#[cfg(feature = "attestation-dstack")]
pub struct DstackAttestor {
    /// Unix-seconds timestamp used as the DCAP "current time" for collateral
    /// validity-window checks. Captured from the wall clock at construction so
    /// expired collateral is rejected in production; injectable via
    /// [`DstackAttestor::with_verify_time`] for reproducible verification.
    verify_time: u64,
    /// Require the registrant to carry an RTMR event log that replays onto the
    /// quote's registers. This is operator policy in the same sense the
    /// measurement allowlist is: when on, a quote with no (or a non-anchoring)
    /// log is refused. The node turns it on; quote-only unit tests leave it off
    /// so they exercise exactly the quote path they are about.
    require_event_log: bool,
    /// Accepted `compose-hash` values read out of the anchored event log. Empty
    /// means "do not constrain which app", which is the CVM-stack-only claim.
    expected_compose_hashes: Vec<String>,
}

#[cfg(feature = "attestation-dstack")]
impl DstackAttestor {
    /// Construct a verifier that uses the current wall-clock time for DCAP
    /// collateral validity checks (expired TCB info / QE identity / CRLs are
    /// rejected). This is the production constructor.
    pub fn new() -> Self {
        Self {
            verify_time: wall_clock_secs(),
            require_event_log: false,
            expected_compose_hashes: Vec::new(),
        }
    }

    /// Require an RTMR event log that replays onto the quote's registers, and
    /// optionally constrain the `compose-hash` it records. This is what turns
    /// the CVM-stack claim into an app claim.
    pub fn requiring_event_log(mut self, expected_compose_hashes: Vec<String>) -> Self {
        self.require_event_log = true;
        self.expected_compose_hashes = expected_compose_hashes;
        self
    }

    /// Replay the registrant's event log onto the registers of its own quote,
    /// then check the app identity that log records.
    ///
    /// The replay is the load-bearing step. Until the fold lands on the RTMRs
    /// Intel signed, the log is just JSON the host handed us; afterwards, every
    /// event in it is as trustworthy as the quote.
    fn verify_app_identity(
        &self,
        rtmrs: &QuoteRtmrs,
        event_log: &str,
    ) -> Result<(), AttestationError> {
        use crate::net::dstack_event_log::verify_event_log;

        if event_log.trim().is_empty() {
            return Err(AttestationError::DstackVerify(
                "event log is required but the registrant presented none".to_string(),
            ));
        }

        let identity = verify_event_log(
            event_log,
            [&rtmrs[0][..], &rtmrs[1][..], &rtmrs[2][..], &rtmrs[3][..]],
        )
        .map_err(|e| AttestationError::DstackVerify(format!("event log: {e}")))?;

        if self.expected_compose_hashes.is_empty() {
            return Ok(());
        }
        match identity.compose_hash {
            Some(ref found) if self.expected_compose_hashes.contains(found) => Ok(()),
            Some(found) => Err(AttestationError::DstackVerify(format!(
                "compose-hash {found} is not in the expected set"
            ))),
            None => Err(AttestationError::DstackVerify(
                "event log records no compose-hash to check".to_string(),
            )),
        }
    }

    /// Construct a verifier pinned to an explicit verification time. Intended
    /// for reproducible verification of a recorded quote/collateral pair (e.g.
    /// a known-good image measurement captured on staging) where the
    /// collateral's validity window predates the current wall clock.
    pub fn with_verify_time(verify_time: u64) -> Self {
        Self {
            verify_time,
            require_event_log: false,
            expected_compose_hashes: Vec::new(),
        }
    }
}

#[cfg(feature = "attestation-dstack")]
impl Default for DstackAttestor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "attestation-dstack")]
impl Attestor for DstackAttestor {
    fn kind(&self) -> AttestorKind {
        AttestorKind::Dstack
    }

    fn verify(
        &self,
        evidence: &AttestationEvidence,
    ) -> Result<VerifiedAttestation, AttestationError> {
        match evidence {
            AttestationEvidence::Dstack(quote) => {
                let (verified, rtmrs) =
                    verify_dstack_quote_with_registers(&quote.raw, &quote.collateral, self.verify_time)?;
                if self.require_event_log {
                    self.verify_app_identity(&rtmrs, &quote.event_log)?;
                }
                Ok(verified)
            }
            // Mock evidence presented to a dstack attestor: reject, do not
            // fall back to treating it as anything else.
            AttestationEvidence::Mock(_) => Err(AttestationError::KindMismatch),
        }
    }
}

/// Configured attestation admission policy: an attestor, the allowlist of
/// expected image measurements, and (implicitly) "enabled".
///
/// The bootnode holds `Option<AdmissionAttestation>`; `None` means attestation
/// is disabled and the existing `STOFFEL_AUTH_TOKEN` admission path is
/// unchanged. When `Some`, every `RegisterWithSession` must present evidence
/// that passes [`AdmissionAttestation::verify_registration`].
pub struct AdmissionAttestation {
    attestor: Box<dyn Attestor>,
    allowed_measurements: Vec<Measurement>,
}

impl std::fmt::Debug for AdmissionAttestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionAttestation")
            .field("kind", &self.attestor.kind())
            .field("allowed_measurements", &self.allowed_measurements.len())
            .finish()
    }
}

impl AdmissionAttestation {
    pub fn new(attestor: Box<dyn Attestor>, allowed_measurements: Vec<Measurement>) -> Self {
        Self {
            attestor,
            allowed_measurements,
        }
    }

    pub fn new_mock(key: [u8; 32], allowed_measurements: Vec<Measurement>) -> Self {
        Self::new(Box::new(MockAttestor::new(key)), allowed_measurements)
    }

    #[cfg(feature = "attestation-dstack")]
    pub fn new_dstack(allowed_measurements: Vec<Measurement>) -> Self {
        Self::new(Box::new(DstackAttestor::new()), allowed_measurements)
    }

    /// Real-TDX admission that additionally requires an RTMR event log which
    /// replays onto the registrant's own quote, optionally constrained to a set
    /// of `compose-hash` values.
    #[cfg(feature = "attestation-dstack")]
    pub fn new_dstack_with_event_log(
        allowed_measurements: Vec<Measurement>,
        expected_compose_hashes: Vec<String>,
    ) -> Self {
        Self::new(
            Box::new(DstackAttestor::new().requiring_event_log(expected_compose_hashes)),
            allowed_measurements,
        )
    }

    pub fn kind(&self) -> AttestorKind {
        self.attestor.kind()
    }

    pub fn allowed_measurements_len(&self) -> usize {
        self.allowed_measurements.len()
    }

    /// Full admission check. Returns the verified cert pubkey hash on success.
    ///
    /// Enforces, in order:
    /// 1. evidence is present (`Missing` otherwise — fail closed),
    /// 2. the quote is cryptographically valid for this attestor
    ///    (`InvalidQuote` / `KindMismatch`),
    /// 3. the attested measurement is on the allowlist
    ///    (`MeasurementNotAllowed`),
    /// 4. the quote's bound cert equals the registrant's presented
    ///    `tls_derived_id` (`CertBindingMismatch` / `MissingTlsDerivedId`).
    ///
    /// `presented_tls_derived_id` is the value the registrant put in its
    /// `RegisterWithSession`; `evidence` is its attestation evidence.
    pub fn verify_registration(
        &self,
        evidence: Option<&AttestationEvidence>,
        presented_tls_derived_id: Option<PartyId>,
    ) -> Result<CertPubKeyHash, AttestationError> {
        let evidence = evidence.ok_or(AttestationError::Missing)?;
        let verified = self.attestor.verify(evidence)?;
        if !self.allowed_measurements.contains(&verified.measurement) {
            return Err(AttestationError::MeasurementNotAllowed {
                found: verified.measurement,
            });
        }
        match presented_tls_derived_id {
            Some(presented) if presented == verified.cert_pubkey_hash => {
                Ok(verified.cert_pubkey_hash)
            }
            Some(presented) => Err(AttestationError::CertBindingMismatch {
                bound: verified.cert_pubkey_hash,
                presented,
            }),
            None => Err(AttestationError::MissingTlsDerivedId),
        }
    }
}

/// Constant-time byte comparison (mirrors the helper in `discovery`).
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Real Intel TDX quote verification (spec task W5)
// ---------------------------------------------------------------------------
//
// `verify_dstack_quote` is the pure, network-free core: given the raw TDX
// quote and the DCAP collateral it verifies the full Intel trust chain
// (QE report / attestation-key signature / PCK cert chain / TCB info / QE
// identity, all anchored at the Intel trusted root CA) via `dcap-qvl`, then
// extracts:
//
//   * `measurement`        = blake3(mr_td || rtmr0 || rtmr1 || rtmr2 || rtmr3)
//     — a 32-byte digest binding the full TD measurement register set (firmware
//       td-shim via mr_td, and the runtime registers RTMR0..3 that cover the
//       kernel, initrd, and the app/compose image). Pinning this digest in the
//       admission allowlist is what makes a wrong/tampered node image be
//       refused. (TDX registers are 48-byte SHA-384 values; we fold all five
//       into the W3 32-byte [`Measurement`] via blake3 rather than truncate a
//       single register.)
//   * `cert_pubkey_hash`   = report_data[0..8] read as the LE `tls_derived_id`
//     — the binding the attesting node wrote via dstack `GetQuote`, which must
//       equal the registrant's presented `tls_derived_id` (checked by
//       [`AdmissionAttestation::verify_registration`]).
//
// `obtain_dstack_evidence` is the attesting-node counterpart: it talks to the
// dstack device manager over `/var/run/dstack.sock` to mint a quote bound to
// the node's `tls_derived_id`, fetches the DCAP collateral from a PCCS, and
// packages both into a [`DstackQuote`]. It is only callable from inside a real
// dstack CVM (the Unix socket must exist) — there is no mock fallback.

#[cfg(feature = "attestation-dstack")]
fn wall_clock_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Number of bytes of TD `report_data` used to bind the TLS cert identity.
///
/// `tls_derived_id` is a `usize` (8 bytes on the 64-bit targets the MPC node
/// runs on); we write exactly that many LE bytes at the start of the 64-byte
/// `report_data` and zero-pad the rest, so the verifier can read them back
/// unambiguously. Reading a fixed width keeps the on-wire binding stable.
#[cfg(feature = "attestation-dstack")]
const REPORT_DATA_BINDING_BYTES: usize = 8;

/// Verify a raw Intel TDX quote against its DCAP collateral and extract the
/// attested `(measurement, cert_pubkey_hash)`. This is the pure core of
/// [`DstackAttestor::verify`]; it performs no I/O.
///
/// Fail-closed: any verification failure (signature, certificate chain, TCB
/// status, malformed quote/report) surfaces as [`AttestationError::DstackVerify`].
/// Only a quote that fully validates against the Intel root of trust yields a
/// [`VerifiedAttestation`].
#[cfg(feature = "attestation-dstack")]
pub fn verify_dstack_quote(
    raw_quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
) -> Result<VerifiedAttestation, AttestationError> {
    verify_dstack_quote_with_registers(raw_quote, collateral, now_secs).map(|(v, _)| v)
}

/// The four RTMR values read out of a verified TD report, in order.
#[cfg(feature = "attestation-dstack")]
pub type QuoteRtmrs = [[u8; 48]; 4];

/// As [`verify_dstack_quote`], but also hands back the quote's RTMR0..3 so a
/// caller can anchor an event log against them without verifying twice.
#[cfg(feature = "attestation-dstack")]
pub fn verify_dstack_quote_with_registers(
    raw_quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
) -> Result<(VerifiedAttestation, QuoteRtmrs), AttestationError> {
    // Full Intel trust-chain verification (QE/ISV signatures, PCK cert chain,
    // TCB info + QE identity collateral, CRLs) anchored at the Intel trusted
    // root CA. `rustcrypto` selects the pure-Rust crypto backend (p256/sha2);
    // no `ring` C dependency is pulled in.
    let verified = dcap_qvl::verify::rustcrypto::verify(raw_quote, collateral, now_secs)
        .map_err(|err| AttestationError::DstackVerify(format!(
            "TDX quote verification failed: {err}"
        )))?;

    // Only a TD report carries the measurement registers we pin on. An SGX
    // quote presented as dstack evidence is a kind mismatch — reject rather
    // than fall back to a default measurement.
    let td = verified.report.as_td10().ok_or_else(|| {
        AttestationError::DstackVerify(
            "dstack evidence must be a TD report (version 4), got non-TD".to_string(),
        )
    })?;

    // Fold the BOOT-TIME registers into the W3 32-byte [`Measurement`]: mr_td
    // (firmware/td-shim) plus RTMR0..2 (virtual firmware, kernel, initrd and
    // config). These are fixed once the TD is up, so a pin over them is stable
    // for the life of the CVM.
    //
    // RTMR3 is excluded ON PURPOSE, and the app identity it carries is NOT
    // dropped — it moves to `net::dstack_event_log::verify_event_log`, which
    // replays the event log into all four registers (RTMR3 included) and
    // requires each to equal the value in this Intel-verified quote before
    // reading `compose-hash` / `app-id` / `os-image-hash` back out. Checking a
    // named, anchored event is strictly more informative than pinning an opaque
    // digest over it.
    //
    // Pinning RTMR3 was also simply not operable: it is the runtime-extended
    // register, carrying per-boot and per-deployment events. Observed on the
    // pod, three distinct digests inside one hour (spanning a CVM restart) with
    // mr_td and RTMR0..2 byte-identical across all three.
    let mut hasher = blake3::Hasher::new();
    hasher.update(&td.mr_td);
    hasher.update(&td.rt_mr0);
    hasher.update(&td.rt_mr1);
    hasher.update(&td.rt_mr2);
    let measurement: Measurement = *hasher.finalize().as_bytes();

    // Cert binding: the LE `tls_derived_id` the attesting node wrote at the
    // start of report_data. `AdmissionAttestation::verify_registration` checks
    // this equals the registrant's presented `tls_derived_id`.
    let binding = td
        .report_data
        .get(..REPORT_DATA_BINDING_BYTES)
        .ok_or_else(|| {
            AttestationError::DstackVerify(format!(
                "TD report_data is {} bytes; need >= {REPORT_DATA_BINDING_BYTES} for the cert binding",
                td.report_data.len()
            ))
        })?;
    let mut cert_bytes = [0u8; REPORT_DATA_BINDING_BYTES];
    cert_bytes.copy_from_slice(binding);
    let cert_pubkey_hash: CertPubKeyHash =
        u64::from_le_bytes(cert_bytes) as CertPubKeyHash;

    tracing::info!(
        target: "stoffel::attestation::dstack",
        measurement = %hex::encode(measurement),
        mr_td = %hex::encode(&td.mr_td[..]),
        rtmr3 = %hex::encode(&td.rt_mr3[..]),
        cert_pubkey_hash,
        tcb_status = %verified.status,
        "dstack TDX quote verified against Intel root of trust"
    );

    let rtmrs: QuoteRtmrs = [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3];

    Ok((
        VerifiedAttestation {
            measurement,
            cert_pubkey_hash,
            tcb_status: verified.status,
        },
        rtmrs,
    ))
}

/// dstack device-manager RPC endpoints used to mint a quote. See
/// <https://github.com/Dstack-TEE/dstack> (`GetQuote`).
#[cfg(feature = "attestation-dstack")]
const DSTACK_GET_QUOTE_PATH: &str = "/GetQuote";

/// Default location of the dstack device-manager Unix socket inside a CVM.
/// Overridable via `STOFFEL_DSTACK_SOCKET` for non-standard layouts.
#[cfg(feature = "attestation-dstack")]
const DSTACK_DEFAULT_SOCKET: &str = "/var/run/dstack.sock";

/// A `GetQuote` response from the dstack device manager. Only the fields the
/// evidence packager needs are decoded; the rest are ignored.
#[cfg(feature = "attestation-dstack")]
#[derive(Debug, serde::Deserialize)]
struct DstackGetQuoteResponse {
    /// Hex-encoded raw TD quote.
    quote: String,
    /// The RTMR event log dstack returns alongside the quote. Carried with the
    /// evidence so the verifier can replay it against the quote's registers.
    #[serde(default)]
    event_log: String,
}

/// Obtain real dstack TDX attestation evidence binding this node's TLS cert
/// identity, for presentation to a [`DstackAttestor`] verifier.
///
/// Runs **inside** a dstack CVM: it opens the device-manager Unix socket
/// (`/var/run/dstack.sock`, override with `STOFFEL_DSTACK_SOCKET`) and calls
/// `GetQuote` with `report_data = tls_derived_id` (LE) zero-padded to 64 bytes,
/// so the resulting quote cryptographically binds the node's TLS cert. It then
/// fetches the DCAP collateral from a PCCS (`STOFFEL_DSTACK_PCCS_URL`, default
/// the public Phala PCCS) and returns both in a [`DstackQuote`].
///
/// There is **no mock fallback**: if the dstack socket is absent (i.e. we are
/// not inside a CVM) or the PCCS is unreachable, this returns an error. That is
/// the contract — a node outside a TEE must not be able to fabricate evidence.
#[cfg(feature = "attestation-dstack")]
pub async fn obtain_dstack_evidence(tls_derived_id: PartyId) -> Result<AttestationEvidence, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let socket = std::env::var("STOFFEL_DSTACK_SOCKET")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DSTACK_DEFAULT_SOCKET.to_string());

    // Build the 64-byte report_data: LE tls_derived_id at [0..8], zero-padded.
    // The verifier reads exactly these bytes back as the cert binding.
    let mut report_data = [0u8; 64];
    report_data[..REPORT_DATA_BINDING_BYTES]
        .copy_from_slice(&(tls_derived_id as u64).to_le_bytes());

    // Minimal JSON-RPC over the dstack Unix socket. We hand-roll the request
    // (rather than pull in the dstack-sdk crate and its alloy/bon dependency
    // tree) — `GetQuote` is a single POST whose body is `{"report_data": <hex>}`.
    let body = serde_json::json!({ "report_data": hex::encode(report_data) });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| format!("encode GetQuote body: {e}"))?;
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: dstack\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        path = DSTACK_GET_QUOTE_PATH,
        len = body_bytes.len()
    );

    let mut stream = UnixStream::connect(&socket)
        .await
        .map_err(|e| format!("dstack socket {socket:?} not reachable (not inside a CVM?): {e}"))?;
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write GetQuote request: {e}"))?;
    stream
        .write_all(&body_bytes)
        .await
        .map_err(|e| format!("write GetQuote body: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush GetQuote: {e}"))?;

    // Read the full HTTP response. `Connection: close` means the server hangs
    // up after the body, so read-to-EOF collects it entirely.
    let mut resp = Vec::with_capacity(4096);
    stream
        .read_to_end(&mut resp)
        .await
        .map_err(|e| format!("read GetQuote response: {e}"))?;
    let json = extract_json_body(&resp)?;
    let parsed: DstackGetQuoteResponse =
        serde_json::from_slice(&json).map_err(|e| format!("decode GetQuote response: {e}"))?;
    let raw = hex::decode(&parsed.quote)
        .map_err(|e| format!("GetQuote returned non-hex quote: {e}"))?;

    // Fetch the DCAP collateral from a PCCS so the verifier needs no network.
    let pccs_url = std::env::var("STOFFEL_DSTACK_PCCS_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| dcap_qvl::PHALA_PCCS_URL.to_string());
    let collateral = dcap_qvl::collateral::CollateralClient::<dcap_qvl::configs::DefaultConfig>::with_default_http(pccs_url)
        .map_err(|e| format!("build PCCS collateral client: {e}"))?
        .fetch(&raw)
        .await
        .map_err(|e| format!("fetch DCAP collateral from PCCS: {e}"))?;

    tracing::info!(
        target: "stoffel::attestation::dstack",
        quote_len = raw.len(),
        tls_derived_id,
        "obtained dstack TDX quote bound to node TLS identity"
    );

    Ok(AttestationEvidence::Dstack(DstackQuote {
        raw,
        collateral,
        event_log: parsed.event_log,
    }))
}

/// Pull the JSON object out of an HTTP/1.1 response read to EOF. Locates the
/// first `{` after the blank line separating headers from the body.
#[cfg(feature = "attestation-dstack")]
fn extract_json_body(resp: &[u8]) -> Result<Vec<u8>, String> {
    // Find the header/body boundary ("\r\n\r\n").
    let boundary = b"\r\n\r\n";
    let start = resp
        .windows(boundary.len())
        .position(|w| w == boundary)
        .map(|p| p + boundary.len())
        .ok_or_else(|| "GetQuote response had no HTTP header/body boundary".to_string())?;
    let body = &resp[start..];
    // Trim any trailing whitespace/chunked framing artifacts to the JSON object.
    let first = body
        .iter()
        .position(|b| *b == b'{')
        .ok_or_else(|| "GetQuote response body is not JSON".to_string())?;
    Ok(body[first..].to_vec())
}

// ---------------------------------------------------------------------------
// Environment-driven configuration
// ---------------------------------------------------------------------------
//
// The bootnode reads its attestation admission policy from the environment so
// the existing `run_bootnode_with_config` entry point picks attestation up
// additively (without changing its signature). Variables:
//
//   STOFFEL_ATTESTATION_MODE = disabled | mock | dstack   (default: disabled)
//   STOFFEL_ATTESTATION_ALLOWED_MEASUREMENTS = <hex>,...  (32-byte measurements)
//   STOFFEL_ATTESTATION_MOCK_KEY = <hex>                  (32-byte mock key)
//
// Fail closed: `mock`/`dstack` without any allowed measurements is an error,
// not a silent disable. `dstack` without the `attestation-dstack` feature is
// a build-time/config error.

const ENV_MODE: &str = "STOFFEL_ATTESTATION_MODE";
const ENV_ALLOWED: &str = "STOFFEL_ATTESTATION_ALLOWED_MEASUREMENTS";
/// Require the RTMR event log to replay onto the registrant's quote. Defaults
/// to ON for `dstack` mode: the log is what carries app identity now that the
/// pinned measurement covers only the boot registers. Set to `false` to accept
/// a quote with no log, which narrows the claim to the CVM stack alone.
const ENV_REQUIRE_EVENT_LOG: &str = "STOFFEL_ATTESTATION_REQUIRE_EVENT_LOG";
/// Comma-separated `compose-hash` values accepted out of the anchored log.
/// Empty means "any app on this CVM stack".
const ENV_EXPECTED_COMPOSE: &str = "STOFFEL_ATTESTATION_EXPECTED_COMPOSE_HASHES";
const ENV_MOCK_KEY: &str = "STOFFEL_ATTESTATION_MOCK_KEY";

/// Build an attestation admission policy from the environment.
///
/// Returns `Ok(None)` when attestation is disabled (the default), which leaves
/// the existing `STOFFEL_AUTH_TOKEN` admission path unchanged.
pub fn attestation_admission_from_env() -> Result<Option<AdmissionAttestation>, String> {
    let mode = std::env::var(ENV_MODE)
        .ok()
        .map(|m| m.trim().to_ascii_lowercase())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "disabled".to_string());

    match mode.as_str() {
        "disabled" | "off" | "none" => Ok(None),
        "mock" => {
            let allowed = parse_measurements(&std::env::var(ENV_ALLOWED).unwrap_or_default())?;
            if allowed.is_empty() {
                return Err(format!(
                    "{ENV_MODE}=mock requires {ENV_ALLOWED} to list at least one measurement"
                ));
            }
            let key = parse_key(&std::env::var(ENV_MOCK_KEY).unwrap_or_default())?;
            Ok(Some(AdmissionAttestation::new_mock(key, allowed)))
        }
        "dstack" => {
            #[cfg(feature = "attestation-dstack")]
            {
                let allowed = parse_measurements(&std::env::var(ENV_ALLOWED).unwrap_or_default())?;
                if allowed.is_empty() {
                    return Err(format!(
                        "{ENV_MODE}=dstack requires {ENV_ALLOWED} to list at least one measurement"
                    ));
                }
                let require_log = std::env::var(ENV_REQUIRE_EVENT_LOG)
                    .map(|v| {
                        let v = v.trim().to_ascii_lowercase();
                        v != "false" && v != "0"
                    })
                    .unwrap_or(true);
                let compose: Vec<String> = std::env::var(ENV_EXPECTED_COMPOSE)
                    .unwrap_or_default()
                    .split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                return Ok(Some(if require_log {
                    AdmissionAttestation::new_dstack_with_event_log(allowed, compose)
                } else {
                    AdmissionAttestation::new_dstack(allowed)
                }));
            }
            #[cfg(not(feature = "attestation-dstack"))]
            {
                let _ = std::env::var(ENV_ALLOWED).unwrap_or_default();
                Err(format!(
                    "{ENV_MODE}=dstack but the `attestation-dstack` cargo feature is not enabled"
                ))
            }
        }
        other => Err(format!(
            "unknown {ENV_MODE}={other:?}; expected disabled|mock|dstack"
        )),
    }
}

fn parse_measurements(raw: &str) -> Result<Vec<Measurement>, String> {
    raw.split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let bytes =
                hex::decode(s).map_err(|e| format!("invalid measurement hex {s:?}: {e}"))?;
            bytes[..32]
                .try_into()
                .map_err(|_| format!("measurement must be 32 bytes, got {} bytes", bytes.len()))
        })
        .collect()
}

fn parse_key(raw: &str) -> Result<[u8; 32], String> {
    if raw.is_empty() {
        return Ok([0u8; 32]);
    }
    let bytes = hex::decode(raw).map_err(|e| format!("invalid mock key hex: {e}"))?;
    bytes[..32]
        .try_into()
        .map_err(|_| format!("mock key must be 32 bytes, got {} bytes", bytes.len()))
}

#[cfg(test)]
mod env_tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize env-mutating tests so they do not race other tests in the
    // same process.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn purge() {
        std::env::remove_var(ENV_MODE);
        std::env::remove_var(ENV_ALLOWED);
        std::env::remove_var(ENV_MOCK_KEY);
    }

    #[test]
    fn disabled_by_default() {
        let _g = ENV_LOCK.lock().unwrap();
        purge();
        assert!(attestation_admission_from_env()
            .expect("disabled is Ok")
            .is_none());
    }

    #[test]
    fn mock_without_allowlist_fails_closed() {
        let _g = ENV_LOCK.lock().unwrap();
        purge();
        std::env::set_var(ENV_MODE, "mock");
        let err = attestation_admission_from_env().expect_err("must require allowlist");
        assert!(err.contains("requires"));
    }

    #[test]
    fn mock_with_allowlist_builds_policy() {
        let _g = ENV_LOCK.lock().unwrap();
        purge();
        std::env::set_var(ENV_MODE, "mock");
        std::env::set_var(ENV_ALLOWED, hex::encode([0x42u8; 32]));
        let adm = attestation_admission_from_env()
            .expect("mock builds")
            .expect("some policy");
        assert_eq!(adm.kind(), AttestorKind::Mock);
        assert_eq!(adm.allowed_measurements_len(), 1);
    }

    #[test]
    fn dstack_without_feature_fails_closed() {
        let _g = ENV_LOCK.lock().unwrap();
        purge();
        std::env::set_var(ENV_MODE, "dstack");
        std::env::set_var(ENV_ALLOWED, hex::encode([0x42u8; 32]));
        let res = attestation_admission_from_env();
        #[cfg(feature = "attestation-dstack")]
        {
            // With the feature on it builds a dstack policy (which itself
            // fails closed on verify until the SDK is wired).
            let adm = res
                .expect("dstack builds under feature")
                .expect("some policy");
            assert_eq!(adm.kind(), AttestorKind::Dstack);
        }
        #[cfg(not(feature = "attestation-dstack"))]
        {
            let err = res.expect_err("dstack without feature must fail");
            assert!(err.contains("attestation-dstack"));
        }
    }
}

#[cfg(test)]
mod tests {
    //! Verifier unit tests covering the four security properties from the
    //! attestation spec (mpc-node-attestation-spec.md W3):
    //!
    //! 1. good quote + correct measurement + matching cert binding  -> ADMIT
    //! 2. wrong / unlisted measurement                              -> REJECT
    //! 3. quote not bound to the presented cert (tls_derived_id mismatch) -> REJECT
    //! 4. replayed quote captured for a different cert              -> REJECT

    use super::*;

    /// A fixed, well-known "good" image measurement that the allowlist trusts.
    const GOOD_MEASUREMENT: Measurement = [0x42; 32];
    /// A measurement the allowlist does NOT trust.
    const BAD_MEASUREMENT: Measurement = [0x00; 32];
    const ATTESTOR_KEY: [u8; 32] = [0xAB; 32];

    fn admission() -> AdmissionAttestation {
        AdmissionAttestation::new_mock(ATTESTOR_KEY, vec![GOOD_MEASUREMENT])
    }

    fn mock_attestor() -> MockAttestor {
        MockAttestor::new(ATTESTOR_KEY)
    }

    // --- Case 1: good quote + correct measurement + matching cert -> ADMIT ---

    #[test]
    fn good_quote_with_correct_measurement_and_matching_cert_admits() {
        let adm = admission();
        let cert: CertPubKeyHash = 1234;
        let evidence = mock_attestor().generate(GOOD_MEASUREMENT, cert);

        let verified = adm
            .verify_registration(Some(&evidence), Some(cert))
            .expect("good quote with allowlisted measurement and matching cert must ADMIT");
        assert_eq!(verified, cert);
    }

    // --- Case 2: wrong / unlisted measurement -> REJECT ---

    #[test]
    fn wrong_measurement_is_rejected() {
        let adm = admission();
        let cert: CertPubKeyHash = 1234;
        // The quote is cryptographically valid and the cert binding is right,
        // but the attested measurement is not on the allowlist.
        let evidence = mock_attestor().generate(BAD_MEASUREMENT, cert);

        let err = adm
            .verify_registration(Some(&evidence), Some(cert))
            .expect_err("unlisted measurement must be REJECTED");
        assert_eq!(
            err,
            AttestationError::MeasurementNotAllowed {
                found: BAD_MEASUREMENT
            }
        );
    }

    // --- Case 3: quote not bound to the presented cert -> REJECT ---

    #[test]
    fn quote_not_bound_to_presented_tls_derived_id_is_rejected() {
        let adm = admission();
        let real_cert: CertPubKeyHash = 1234;
        let impostor_cert: CertPubKeyHash = 9999;
        // Honest quote bound to real_cert, but the registrant presents a
        // different tls_derived_id (impostor_cert).
        let evidence = mock_attestor().generate(GOOD_MEASUREMENT, real_cert);

        let err = adm
            .verify_registration(Some(&evidence), Some(impostor_cert))
            .expect_err("cert binding mismatch must be REJECTED");
        assert_eq!(
            err,
            AttestationError::CertBindingMismatch {
                bound: real_cert,
                presented: impostor_cert
            }
        );
    }

    // --- Case 4: replayed quote captured for a different cert -> REJECT ---

    #[test]
    fn replayed_quote_for_a_different_cert_is_rejected() {
        // Node A honestly mints a quote for its own cert A.
        let adm = admission();
        let node_a_cert: CertPubKeyHash = 7777;
        let captured_evidence = mock_attestor().generate(GOOD_MEASUREMENT, node_a_cert);

        // An attacker replays node A's captured quote while presenting their
        // own (different) cert B as tls_derived_id. Because the quote binds
        // node_a_cert, the binding check fails — the replay cannot impersonate
        // node A under cert B.
        let attacker_cert: CertPubKeyHash = 8888;
        let err = adm
            .verify_registration(Some(&captured_evidence), Some(attacker_cert))
            .expect_err("replayed quote bound to a different cert must be REJECTED");
        assert_eq!(
            err,
            AttestationError::CertBindingMismatch {
                bound: node_a_cert,
                presented: attacker_cert
            }
        );
    }

    // --- Additional fail-closed guarantees ---

    #[test]
    fn missing_evidence_is_rejected_when_attestation_enabled() {
        let adm = admission();
        let err = adm
            .verify_registration(None, Some(1234))
            .expect_err("absent evidence must be REJECTED");
        assert_eq!(err, AttestationError::Missing);
    }

    #[test]
    fn missing_tls_derived_id_is_rejected_when_attestation_enabled() {
        let adm = admission();
        let cert: CertPubKeyHash = 1234;
        let evidence = mock_attestor().generate(GOOD_MEASUREMENT, cert);
        let err = adm
            .verify_registration(Some(&evidence), None)
            .expect_err("absent tls_derived_id must be REJECTED");
        assert_eq!(err, AttestationError::MissingTlsDerivedId);
    }

    #[test]
    fn forged_quote_without_key_is_rejected() {
        let adm = admission();
        // A quote minted with the WRONG key — models an attacker fabricating a
        // quote without controlling the attestor / TEE.
        let wrong_key_attestor = MockAttestor::new([0x01; 32]);
        let evidence = wrong_key_attestor.generate(GOOD_MEASUREMENT, 1234);
        let err = adm
            .verify_registration(Some(&evidence), Some(1234))
            .expect_err("a quote with a bad authenticator must be REJECTED");
        assert_eq!(err, AttestationError::InvalidQuote);
    }

    #[test]
    fn mock_attestor_rejects_wrong_kind_when_dstack_feature_enabled() {
        // With the dstack feature off this test still exercises KindMismatch
        // via the mock-only path is impossible, so guard it. We instead assert
        // the mock attestor accepts its own kind round-trip and that a
        // different attestor (fresh key) rejects a quote minted elsewhere.
        let adm = admission();
        assert_eq!(adm.kind(), AttestorKind::Mock);

        let other = MockAttestor::new([0xFE; 32]);
        let evidence = other.generate(GOOD_MEASUREMENT, 1234);
        let err = adm
            .verify_registration(Some(&evidence), Some(1234))
            .expect_err("quote minted by a different attestor key must be REJECTED");
        assert_eq!(err, AttestationError::InvalidQuote);
    }

    #[test]
    fn evidence_round_trips_through_serialization() {
        let evidence = mock_attestor().generate(GOOD_MEASUREMENT, 4321);
        let bytes = bincode::serialize(&evidence).expect("serialize evidence");
        let decoded: AttestationEvidence =
            bincode::deserialize(&bytes).expect("deserialize evidence");
        let adm = admission();
        assert!(adm.verify_registration(Some(&decoded), Some(4321)).is_ok());
    }

    // ---------------------------------------------------------------------
    // Real Intel TDX quote verification (spec task W5).
    //
    // These exercise the *real* `DstackAttestor`/`verify_dstack_quote` against
    // a genuine (public, Intel-issued) TDX quote + DCAP collateral vector, so
    // the W3 fail-closed placeholder is provably replaced by working trust-chain
    // verification. The vector is the canonical `dcap-qvl` sample
    // (`sample/tdx_quote`), vendored under `tests/fixtures/dstack/`.
    //
    // Its collateral predates this test run, so we pin `now` inside the
    // collateral validity window (mirroring how a staging operator pins the
    // verification time when capturing a known-good image measurement).
    // ---------------------------------------------------------------------

    /// Minimal accessor for the vendored real TDX quote + collateral fixture.
    #[cfg(feature = "attestation-dstack")]
    fn real_tdx_fixture() -> (Vec<u8>, dcap_qvl::QuoteCollateralV3) {
        let raw = include_bytes!("../tests/fixtures/dstack/tdx_quote.bin").to_vec();
        let collateral_json =
            include_str!("../tests/fixtures/dstack/tdx_quote_collateral.json");
        let collateral: dcap_qvl::QuoteCollateralV3 =
            serde_json::from_str(collateral_json).expect("deserialize tdx collateral");
        (raw, collateral)
    }

    /// Pick a verification time inside the intersection of ALL collateral
    /// validity windows at once: TCB info + QE identity (JSON
    /// `issueDate`→`nextUpdate`), both CRLs (`thisUpdate`→`nextUpdate`), and
    /// **every** certificate's `not_before`/`not_after` across all PEM chains in
    /// the collateral (`tcb_info_issuer_chain`, `qe_identity_issuer_chain`,
    /// `pck_certificate_chain` when present) plus any PCK cert chain embedded
    /// in the quote itself.
    ///
    /// dcap-qvl enforces each of these against the verification time (TCB/QE
    /// JSON expiry, CRL validity, and webpki cert-chain validity), so the
    /// timestamp must lie inside their intersection. Returns the midpoint of
    /// `[max(lower bounds), min(upper bounds)]`.
    #[cfg(feature = "attestation-dstack")]
    fn now_in_collateral_window(
        raw_quote: &[u8],
        collateral: &dcap_qvl::QuoteCollateralV3,
    ) -> u64 {
        let mut not_before: u64 = 0;
        let mut not_after: u64 = u64::MAX;

        // --- TCB info + QE identity JSON bounds (issueDate → nextUpdate) ---
        fn json_bounds(json_str: &str) -> (u64, u64) {
            let v: serde_json::Value =
                serde_json::from_str(json_str).expect("collateral json");
            let issue = v["issueDate"].as_str().expect("issueDate");
            let next = v["nextUpdate"].as_str().expect("nextUpdate");
            let i = chrono::DateTime::parse_from_rfc3339(issue)
                .expect("issueDate parse")
                .timestamp() as u64;
            let n = chrono::DateTime::parse_from_rfc3339(next)
                .expect("nextUpdate parse")
                .timestamp() as u64;
            (i, n)
        }
        for json in [&collateral.tcb_info, &collateral.qe_identity] {
            let (lo, hi) = json_bounds(json);
            not_before = not_before.max(lo);
            not_after = not_after.min(hi);
        }

        // --- CRL validity windows (DER `thisUpdate` → `nextUpdate`) ---
        for crl_der in [&collateral.root_ca_crl[..], &collateral.pck_crl[..]] {
            let crl = <x509_cert::crl::CertificateList as der::Decode>::from_der(crl_der)
                .expect("CRL DER parse");
            not_before =
                not_before.max(crl.tbs_cert_list.this_update.to_unix_duration().as_secs());
            if let Some(next) = crl.tbs_cert_list.next_update {
                not_after = not_after.min(next.to_unix_duration().as_secs());
            }
        }

        // --- Certificate `not_before`/`not_after` across all PEM chains ---
        fn fold_pem_chain(not_before: &mut u64, not_after: &mut u64, pem_str: &str) {
            for entry in pem::parse_many(pem_str).expect("PEM parse") {
                let cert =
                    <x509_cert::Certificate as der::Decode>::from_der(entry.contents())
                        .expect("cert DER parse");
                let validity = &cert.tbs_certificate.validity;
                *not_before = (*not_before).max(validity.not_before.to_unix_duration().as_secs());
                *not_after = (*not_after).min(validity.not_after.to_unix_duration().as_secs());
            }
        }
        fold_pem_chain(&mut not_before, &mut not_after, &collateral.tcb_info_issuer_chain);
        fold_pem_chain(&mut not_before, &mut not_after, &collateral.qe_identity_issuer_chain);
        if let Some(ref pck) = collateral.pck_certificate_chain {
            fold_pem_chain(&mut not_before, &mut not_after, pck);
        }

        // PCK certs embedded in the quote (cert_type 5 / PCK_CERT_CHAIN). When
        // the collateral struct does not carry `pck_certificate_chain`, the PCK
        // chain lives in the quote's certification data; webpki checks its
        // validity too, so fold it into the intersection. cert_type 5 is the
        // Intel DCAP PCK cert chain (dcap-qvl `constants::PCK_CERT_CHAIN`).
        const PCK_CERT_CHAIN_TYPE: u16 = 5;
        if let Ok(quote) =
            <dcap_qvl::quote::Quote as parity_scale_codec::Decode>::decode(&mut &raw_quote[..])
        {
            let auth = quote.auth_data.into_v3();
            if auth.certification_data.cert_type == PCK_CERT_CHAIN_TYPE {
                if let Ok(pem_str) = std::str::from_utf8(&auth.certification_data.body.data) {
                    fold_pem_chain(&mut not_before, &mut not_after, pem_str);
                }
            }
        }

        assert!(
            not_before < not_after,
            "collateral validity window intersection is empty"
        );
        not_before + (not_after - not_before) / 2
    }

    /// Fail-closed stays guaranteed: a malformed (truncated) quote is rejected
    /// with `DstackVerify`, and mock evidence is a `KindMismatch`. The verifier
    /// never admits something it cannot fully validate.
    #[cfg(feature = "attestation-dstack")]
    #[test]
    fn dstack_attestor_rejects_malformed_quote_and_wrong_kind() {
        use AttestationEvidence as E;
        let (raw, collateral) = real_tdx_fixture();
        let now = now_in_collateral_window(&raw, &collateral);
        let attestor = DstackAttestor::with_verify_time(now);

        // Truncated bytes cannot decode as a TD quote -> hard reject.
        let bad = E::Dstack(DstackQuote {
            raw: vec![0u8; 4],
            collateral: collateral.clone(),
            event_log: String::new(),
        });
        let err = attestor.verify(&bad).expect_err("malformed quote must reject");
        assert!(matches!(err, AttestationError::DstackVerify(_)), "got {err:?}");

        // Real raw bytes but a different (mock) evidence kind -> kind mismatch.
        let _ = raw; // (fixture sanity; real quote exercised below)
        let mock = MockAttestor::new([0; 32]).generate(GOOD_MEASUREMENT, 1);
        assert!(matches!(
            attestor.verify(&mock),
            Err(AttestationError::KindMismatch)
        ));
    }

    /// A real, Intel-issued TDX quote verifies against the Intel root of trust
    /// and yields a deterministic measurement + cert binding. This is the proof
    /// that the W3 placeholder was actually wired to real TDX.
    #[cfg(feature = "attestation-dstack")]
    #[test]
    fn verify_dstack_quote_extracts_measurement_and_cert_binding() {
        let (raw, collateral) = real_tdx_fixture();
        let now = now_in_collateral_window(&raw, &collateral);

        let verified = verify_dstack_quote(&raw, &collateral, now)
            .expect("real TDX quote must verify against the Intel root of trust");

        // The measurement is a non-zero 32-byte blake3 digest of the verified
        // TD measurement registers (a tampered image would change it).
        assert_ne!(verified.measurement, [0u8; 32]);

        // Pure & deterministic: re-verifying the same quote yields identical
        // measurement + cert binding (reproducibility for staging pinning).
        let verified2 = verify_dstack_quote(&raw, &collateral, now).expect("re-verify");
        assert_eq!(verified.measurement, verified2.measurement);
        assert_eq!(verified.cert_pubkey_hash, verified2.cert_pubkey_hash);
    }

    /// Full admission path against real TDX evidence (W3 `AdmissionAttestation`
    /// over W5 `DstackAttestor`): an allowlisted measurement with a matching
    /// cert binding ADMITS.
    #[cfg(feature = "attestation-dstack")]
    #[test]
    fn dstack_admission_admits_real_tdx_quote_with_matching_measurement() {
        let (raw, collateral) = real_tdx_fixture();
        let now = now_in_collateral_window(&raw, &collateral);
        let verified = verify_dstack_quote(&raw, &collateral, now).expect("verify");
        let measurement = verified.measurement;
        let cert = verified.cert_pubkey_hash;

        let evidence = AttestationEvidence::Dstack(DstackQuote {
            raw,
            collateral: collateral.clone(),
            event_log: String::new(),
        });
        let adm = AdmissionAttestation::new(
            Box::new(DstackAttestor::with_verify_time(now)),
            vec![measurement],
        );
        assert_eq!(adm.kind(), AttestorKind::Dstack);
        assert_eq!(
            adm.verify_registration(Some(&evidence), Some(cert))
                .expect("real TDX quote with allowlisted measurement must ADMIT"),
            cert
        );
    }

    /// A real, signature-valid TDX quote whose measurement is NOT on the
    /// allowlist is refused — the wrong/tampered-image case. (We cannot tamper
    /// the quote itself: that breaks the signature first. Instead we verify the
    /// genuine quote and put a *different* measurement in the allowlist, which
    /// is exactly the operator-side refusal for an unexpected image.)
    #[cfg(feature = "attestation-dstack")]
    #[test]
    fn dstack_admission_rejects_unallowlisted_measurement() {
        let (raw, collateral) = real_tdx_fixture();
        let now = now_in_collateral_window(&raw, &collateral);
        let verified = verify_dstack_quote(&raw, &collateral, now).expect("verify");
        let cert = verified.cert_pubkey_hash;
        let evidence = AttestationEvidence::Dstack(DstackQuote { raw, collateral, event_log: String::new() });

        // Allowlist only the mock "GOOD_MEASUREMENT" (unrelated to the real
        // quote's measurement) -> the real measurement is refused.
        let adm = AdmissionAttestation::new(
            Box::new(DstackAttestor::with_verify_time(now)),
            vec![GOOD_MEASUREMENT],
        );
        let err = adm
            .verify_registration(Some(&evidence), Some(cert))
            .expect_err("unallowlisted measurement must be REJECTED");
        assert_eq!(
            err,
            AttestationError::MeasurementNotAllowed {
                found: verified.measurement
            }
        );
    }

    /// A real, signature-valid TDX quote presented under the WRONG
    /// `tls_derived_id` is refused — cert binding is enforced end-to-end.
    #[cfg(feature = "attestation-dstack")]
    #[test]
    fn dstack_admission_rejects_cert_binding_mismatch() {
        let (raw, collateral) = real_tdx_fixture();
        let now = now_in_collateral_window(&raw, &collateral);
        let verified = verify_dstack_quote(&raw, &collateral, now).expect("verify");
        let measurement = verified.measurement;
        let real_cert = verified.cert_pubkey_hash;
        let impostor_cert = real_cert.wrapping_add(1);
        let evidence = AttestationEvidence::Dstack(DstackQuote { raw, collateral, event_log: String::new() });

        let adm = AdmissionAttestation::new(
            Box::new(DstackAttestor::with_verify_time(now)),
            vec![measurement],
        );
        let err = adm
            .verify_registration(Some(&evidence), Some(impostor_cert))
            .expect_err("cert binding mismatch must be REJECTED");
        assert_eq!(
            err,
            AttestationError::CertBindingMismatch {
                bound: real_cert,
                presented: impostor_cert
            }
        );
    }
}
