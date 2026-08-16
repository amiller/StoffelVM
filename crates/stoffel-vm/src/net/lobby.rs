//! Lobby record types — the wire schema shared by the verifier (L2), the lobby
//! service (L3), and the webapp (L5).
//!
//! **This schema is frozen.** Three work items are being built against it in
//! parallel; changing a field name or a signing preimage here breaks the other
//! two silently. If something genuinely needs to change, say so rather than
//! changing it locally.
//!
//! ## The trust story these types encode
//!
//! The lobby is an untrusted index. A reader never takes the service's word for
//! anything: every record carries a signature by the key that made it, and the
//! attestation evidence travels inline, so the reader re-verifies. What the
//! service can still do is *omit* — censorship and equivocation are the residual
//! trust, and are out of scope for v1.
//!
//! The chain that makes a signature mean something:
//!
//! 1. A node holds a long-term Ed25519 key that survives restarts (L1).
//! 2. Its TDX quote binds `hash(long_term_pubkey)` in `report_data[8..40]`, so
//!    the hardware attests to *that key*, not to a per-process one.
//! 3. Every [`JoinRecord`] and [`ResultRecord`] it signs is therefore
//!    attributable to an attested node running a known measurement.
//!
//! Break any link and the record is worthless — which is why the verifier checks
//! all of them rather than just the signature.
//!
//! ## Signing
//!
//! Every signed type implements [`Signed`]. The preimage is the canonical JSON
//! of the record with `signature` set to the empty string, domain-separated by a
//! per-type prefix. Domain separation is not decorative: without it, a
//! `JoinRecord` for job X could be replayed as some other record type that
//! happens to serialize the same way.

use serde::{Deserialize, Serialize};

/// Hex-encoded 32-byte Ed25519 public key.
pub type PubKeyHex = String;
/// Hex-encoded 64-byte Ed25519 signature.
pub type SigHex = String;
/// Hex-encoded blake3 digest.
pub type DigestHex = String;

/// Domain-separation prefixes. Never reuse a value.
pub mod domain {
    pub const NODE: &str = "stoffel-lobby/node/v1";
    pub const JOB: &str = "stoffel-lobby/job/v1";
    pub const JOIN: &str = "stoffel-lobby/join/v1";
    pub const RESULT: &str = "stoffel-lobby/result/v1";
}

/// A record that carries its own signature.
pub trait Signed {
    /// Domain-separation prefix for this record type.
    fn domain() -> &'static str;
    /// The signature as stored.
    fn signature(&self) -> &str;
    /// Replace the signature (used to build the preimage, and to fill it in).
    fn set_signature(&mut self, sig: SigHex);
    /// The key expected to have signed this record.
    fn signer(&self) -> &str;
}

/// Attestation evidence for one node, self-contained so a verifier needs no
/// network: the quote, the DCAP collateral that validates it against the Intel
/// root, and the RTMR event log that replays onto the quote's own registers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationBlob {
    /// Hex-encoded raw TDX quote.
    pub quote_hex: String,
    /// DCAP collateral, serialized as the JSON `dcap-qvl` accepts.
    pub collateral_json: String,
    /// The dstack RTMR event log, verbatim.
    pub event_log: String,
}

/// A node advertising itself. Signed by its long-term key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRecord {
    /// `blake3(long_term_pubkey)`, hex. Stable across restarts — this is the
    /// identity the whole lobby indexes on.
    pub node_id: DigestHex,
    /// The long-term Ed25519 public key, hex. The quote binds its hash.
    pub pubkey: PubKeyHex,
    /// Where peers reach this node, `host:port`.
    pub endpoint: String,
    /// Largest committee size this node will serve.
    pub max_parties: usize,
    /// Byzantine thresholds it supports.
    pub supported_thresholds: Vec<usize>,
    /// Operator-chosen label. Untrusted, display only.
    pub operator_label: String,
    /// Evidence that this node is what it says it is.
    pub attestation: AttestationBlob,
    /// Unix seconds. Announce/heartbeat time, per the node's own clock.
    pub announced_at: u64,
    pub signature: SigHex,
}

/// Which nodes a job will accept. Empty means "unconstrained", which is a real
/// and dangerous choice — say so at the UI rather than hiding it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobPolicy {
    /// Accepted boot-register measurements, hex `blake3(mr_td||rtmr0..2)`.
    pub allowed_measurements: Vec<DigestHex>,
    /// Accepted `compose-hash` values, read out of the anchored event log.
    pub allowed_compose_hashes: Vec<DigestHex>,
}

/// Lifecycle of a job. Advances forward only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    /// Accepting joins.
    Open,
    /// Enough joins; committee fixed.
    Forming,
    /// Committee is executing.
    Running,
    /// Every party published a result.
    Finished,
    /// Abandoned, timed out, or the results disagreed.
    Failed,
}

/// A proposed computation. Signed by the proposer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobRecord {
    /// `blake3(program_id || entry || n || t)`, hex.
    pub job_id: DigestHex,
    /// `blake3` of the program bytecode, hex — the same id the committee agrees
    /// on when syncing a program.
    pub program_id: DigestHex,
    /// Where the bytecode can be fetched. The verifier does not follow this;
    /// it checks `program_id` against what the parties reported running.
    pub program_url: Option<String>,
    /// Entry function.
    pub entry: String,
    /// Committee size. Must satisfy `n >= 3t + 1`.
    pub n_parties: usize,
    /// Byzantine threshold.
    pub threshold: usize,
    pub policy: JobPolicy,
    /// Unix seconds before which the job must not start. This is what
    /// "scheduled" means — there is no separate scheduler.
    pub not_before: Option<u64>,
    pub state: JobState,
    /// Proposer's public key, hex.
    pub proposer: PubKeyHex,
    pub created_at: u64,
    pub signature: SigHex,
}

/// A node committing to serve a job as a particular party. Signed by the node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinRecord {
    pub job_id: DigestHex,
    pub node_id: DigestHex,
    /// Node's long-term public key, hex. Must match the `NodeRecord`.
    pub pubkey: PubKeyHex,
    /// Party index within the committee.
    pub party_id: usize,
    pub joined_at: u64,
    pub signature: SigHex,
}

/// What one party opened. Signed by the node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResultRecord {
    pub job_id: DigestHex,
    pub node_id: DigestHex,
    pub pubkey: PubKeyHex,
    pub party_id: usize,
    /// The opened value, formatted exactly as the node prints it. Compared as a
    /// string across parties: any difference at all is a disagreement.
    pub value: String,
    /// The program the party actually ran. Checked against `JobRecord`.
    pub program_id: DigestHex,
    pub completed_at: u64,
    pub signature: SigHex,
}

/// Everything needed to verify one job offline. This is what `GET
/// /jobs/{id}/bundle` returns and what `stoffel-verify` consumes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceBundle {
    /// Schema version. Bump on any breaking change to these types.
    pub version: u32,
    pub job: JobRecord,
    /// One per committee member, in no particular order.
    pub nodes: Vec<NodeRecord>,
    pub joins: Vec<JoinRecord>,
    pub results: Vec<ResultRecord>,
}

/// Current bundle schema version.
pub const BUNDLE_VERSION: u32 = 1;

macro_rules! impl_signed {
    ($t:ty, $d:expr, $signer:ident) => {
        impl Signed for $t {
            fn domain() -> &'static str {
                $d
            }
            fn signature(&self) -> &str {
                &self.signature
            }
            fn set_signature(&mut self, sig: SigHex) {
                self.signature = sig;
            }
            fn signer(&self) -> &str {
                &self.$signer
            }
        }
    };
}

impl_signed!(NodeRecord, domain::NODE, pubkey);
impl_signed!(JobRecord, domain::JOB, proposer);
impl_signed!(JoinRecord, domain::JOIN, pubkey);
impl_signed!(ResultRecord, domain::RESULT, pubkey);

/// Bytes that get signed for `record`: the domain prefix, a separator, then the
/// record's canonical JSON with an empty signature field.
///
/// Blanking the signature is what makes this well-defined — signing a structure
/// that contains its own signature is otherwise circular.
pub fn signing_preimage<T>(record: &T) -> Result<Vec<u8>, String>
where
    T: Signed + Clone + Serialize,
{
    let mut blanked = record.clone();
    blanked.set_signature(String::new());
    let body = serde_json::to_vec(&blanked)
        .map_err(|e| format!("serialize record for signing: {e}"))?;
    let mut out = Vec::with_capacity(T::domain().len() + 1 + body.len());
    out.extend_from_slice(T::domain().as_bytes());
    out.push(b':');
    out.extend_from_slice(&body);
    Ok(out)
}

/// Verify a record's signature under the key the record names as its signer.
///
/// Note what this does NOT establish: that the signer is attested, or allowed.
/// Those are separate checks the verifier performs against the `NodeRecord`'s
/// quote and the job's policy. A valid signature by an unattested key is
/// worthless, and it is a mistake to treat this function's `Ok` as admission.
pub fn verify_signature<T>(record: &T) -> Result<(), String>
where
    T: Signed + Clone + Serialize,
{
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key_bytes: [u8; 32] = hex::decode(record.signer())
        .map_err(|e| format!("signer key is not hex: {e}"))?
        .try_into()
        .map_err(|_| "signer key is not 32 bytes".to_string())?;
    let key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|e| format!("bad Ed25519 key: {e}"))?;

    let sig_bytes: [u8; 64] = hex::decode(record.signature())
        .map_err(|e| format!("signature is not hex: {e}"))?
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())?;
    let sig = Signature::from_bytes(&sig_bytes);

    let preimage = signing_preimage(record)?;
    key.verify(&preimage, &sig)
        .map_err(|e| format!("signature does not verify: {e}"))
}

/// Sign a record in place with `key`.
pub fn sign_record<T>(record: &mut T, key: &ed25519_dalek::SigningKey) -> Result<(), String>
where
    T: Signed + Clone + Serialize,
{
    use ed25519_dalek::Signer;
    let preimage = signing_preimage(record)?;
    let sig = key.sign(&preimage);
    record.set_signature(hex::encode(sig.to_bytes()));
    Ok(())
}

/// `node_id` for a public key: `blake3(pubkey)`, hex.
pub fn node_id_for(pubkey: &[u8; 32]) -> DigestHex {
    hex::encode(blake3::hash(pubkey).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key() -> SigningKey {
        // Fixed seed: these tests are about the signing scheme, not randomness.
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn join(job: &str) -> JoinRecord {
        let k = key();
        let pk = k.verifying_key().to_bytes();
        JoinRecord {
            job_id: job.to_string(),
            node_id: node_id_for(&pk),
            pubkey: hex::encode(pk),
            party_id: 2,
            joined_at: 1786836064,
            signature: String::new(),
        }
    }

    #[test]
    fn a_signed_record_verifies() {
        let mut r = join("abc123");
        sign_record(&mut r, &key()).unwrap();
        assert!(!r.signature.is_empty());
        verify_signature(&r).unwrap();
    }

    #[test]
    fn mutating_any_field_breaks_the_signature() {
        let mut r = join("abc123");
        sign_record(&mut r, &key()).unwrap();
        for mutate in [
            (|r: &mut JoinRecord| r.party_id = 3) as fn(&mut JoinRecord),
            |r: &mut JoinRecord| r.job_id = "deadbeef".to_string(),
            |r: &mut JoinRecord| r.joined_at += 1,
        ] {
            let mut bad = r.clone();
            mutate(&mut bad);
            assert!(verify_signature(&bad).is_err(), "mutation was not caught");
        }
    }

    #[test]
    fn a_signature_from_another_key_is_refused() {
        let mut r = join("abc123");
        sign_record(&mut r, &SigningKey::from_bytes(&[9u8; 32])).unwrap();
        assert!(verify_signature(&r).is_err());
    }

    #[test]
    fn domains_are_distinct_so_records_cannot_be_replayed_across_types() {
        let domains = [domain::NODE, domain::JOB, domain::JOIN, domain::RESULT];
        for (i, a) in domains.iter().enumerate() {
            for b in &domains[i + 1..] {
                assert_ne!(a, b, "domain separation prefixes must be unique");
            }
        }
        let r = join("abc123");
        let pre = signing_preimage(&r).unwrap();
        assert!(pre.starts_with(domain::JOIN.as_bytes()));
    }

    #[test]
    fn preimage_ignores_the_stored_signature() {
        let mut a = join("abc123");
        let before = signing_preimage(&a).unwrap();
        a.signature = "ff".repeat(64);
        let after = signing_preimage(&a).unwrap();
        assert_eq!(before, after, "preimage must not depend on the signature");
    }

    #[test]
    fn node_id_is_the_hash_of_the_key() {
        let pk = key().verifying_key().to_bytes();
        assert_eq!(node_id_for(&pk), hex::encode(blake3::hash(&pk).as_bytes()));
    }
}
