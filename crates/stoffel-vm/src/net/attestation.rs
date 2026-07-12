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

/// Raw Intel TDX quote as produced by dstack.
///
/// Verification (report signature against the Intel root of trust, attestation
/// report data parsing, event-log correlation) is W5 work. Until then the
/// [`DstackAttestor`] returns an explicit error — it never admits.
#[cfg(feature = "attestation-dstack")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DstackQuote {
    /// Raw TD quote bytes returned by `get_quote`.
    pub raw: Vec<u8>,
    /// User-defined report data (64 bytes per the TDX spec). The node writes
    /// the TLS cert public-key hash here so the quote binds the cert.
    pub report_data: Vec<u8>,
}

/// What a successfully verified quote proves about the attesting node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub measurement: Measurement,
    pub cert_pubkey_hash: CertPubKeyHash,
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
                Ok(VerifiedAttestation {
                    measurement: q.measurement,
                    cert_pubkey_hash: q.cert_pubkey_hash,
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
/// Behind the non-default `attestation-dstack` feature. Until the dstack SDK
/// is wired (W5), [`Attestor::verify`] returns an explicit
/// [`AttestationError::DstackVerify`] — it never admits.
#[cfg(feature = "attestation-dstack")]
pub struct DstackAttestor {
    // Placeholder for future dstack verifier config (root cert bundle,
    // minimum TDX version, expected attestation report data layout, ...).
    _priv: (),
}

#[cfg(feature = "attestation-dstack")]
impl DstackAttestor {
    pub fn new() -> Self {
        Self { _priv: () }
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
            AttestationEvidence::Dstack(_quote) => {
                // TODO(W5): verify the TDX quote signature against the Intel
                // root of trust, extract `measurement` (MR TD/MRTD) and
                // `cert_pubkey_hash` from the report data, and correlate the
                // event log. Until the SDK is wired this MUST return an error
                // rather than admit — fail closed.
                Err(AttestationError::DstackVerify(
                    "dstack quote verification is not yet implemented".to_string(),
                ))
            }
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
                return Ok(Some(AdmissionAttestation::new_dstack(allowed)));
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

    /// When the dstack feature is enabled, the DstackAttestor must return an
    /// explicit error (never admit) until the SDK is actually wired.
    #[cfg(feature = "attestation-dstack")]
    #[test]
    fn dstack_attestor_fails_closed_until_sdk_wired() {
        use AttestationEvidence as E;
        let attestor = DstackAttestor::new();
        // A (placeholder) dstack quote.
        let evidence = E::Dstack(DstackQuote {
            raw: vec![0u8; 4],
            report_data: vec![0u8; 64],
        });
        let err = attestor
            .verify(&evidence)
            .expect_err("unwired dstack must not admit");
        assert!(matches!(err, AttestationError::DstackVerify(_)));

        // And it rejects mock evidence outright (kind mismatch).
        let mock = MockAttestor::new([0; 32]).generate(GOOD_MEASUREMENT, 1);
        assert!(matches!(
            attestor.verify(&mock),
            Err(AttestationError::KindMismatch)
        ));
    }
}
