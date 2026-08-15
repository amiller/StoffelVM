//! dstack RTMR event log: replay it, anchor it in the quote, read app identity.
//!
//! ## Why this exists
//!
//! The admission gate pins a measurement. The obvious digest to pin — one over
//! `mr_td` and all four RTMRs — is **not stable**: RTMR3 is the runtime-extended
//! register, and the platform keeps appending deployment events to it. Measured
//! directly on the pod: three different values inside one hour, with `mr_td` and
//! RTMR0..2 byte-identical across all three. A pin over RTMR3 therefore goes
//! stale between deploying the bootnode and deploying the parties, and every
//! party is refused against a value nobody could have pinned in advance.
//!
//! Dropping RTMR3 from the pin fixes the stability problem but throws away what
//! RTMR3 actually carries — the app identity dstack records at boot
//! (`compose-hash`, `os-image-hash`, `app-id`, `mr-kms`). So instead of pinning
//! it, this module *verifies* it:
//!
//! 1. Replay the event log into each RTMR and require every one to equal the
//!    register in the hardware-signed quote. That is what makes the log
//!    trustworthy — it is not a side channel the host can edit, because the
//!    fold has to land exactly on a value Intel signed.
//! 2. Read the named boot events out of the now-anchored log and hand them back
//!    as an [`AppIdentity`] the caller can check against expected values.
//!
//! The volatile part of RTMR3 (one `tee-daemon/promote` event per app
//! deployment) still moves, but it no longer matters: it is covered by the
//! replay, and nothing pins it.
//!
//! ## Digest convention
//!
//! Boot events (RTMR0..2) carry their `digest` in the log. Runtime events
//! (RTMR3) carry an empty `digest` and are hashed from their contents as
//! `sha384(le32(event_type) || ":" || event || ":" || event_payload)`. Both
//! folds are `RTMR <- sha384(RTMR || digest)` from a 48-byte zero seed.
//! Verified against the live pod: all four registers reconstruct exactly.

use serde::Deserialize;
use sha2::{Digest, Sha384};

/// One entry of the dstack `event_log` returned alongside `GetQuote`.
#[derive(Debug, Clone, Deserialize)]
pub struct DstackEvent {
    /// Which measurement register this event extends (0..=3).
    pub imr: u32,
    /// TCG event type. Part of the runtime digest preimage.
    pub event_type: u32,
    /// Hex SHA-384 for boot events; empty for runtime events, which derive it.
    #[serde(default)]
    pub digest: String,
    /// Event name, e.g. `compose-hash`.
    #[serde(default)]
    pub event: String,
    /// Hex-encoded payload.
    #[serde(default)]
    pub event_payload: String,
}

/// The identity dstack records into RTMR3 at boot, recovered from a log that
/// has been anchored against the quote. Every field is `None` when the platform
/// did not record that event — absent is reported as absent, never guessed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppIdentity {
    /// dstack application id.
    pub app_id: Option<String>,
    /// Hash of the app's compose definition — the closest thing to "which app
    /// is this", and the field worth checking against an expected value.
    pub compose_hash: Option<String>,
    /// Per-CVM instance id. Changes on redeploy; do not pin it.
    pub instance_id: Option<String>,
    /// Hash of the guest OS image.
    pub os_image_hash: Option<String>,
    /// Measurement of the key-management service the CVM is bound to.
    pub mr_kms: Option<String>,
}

/// Why an event log could not be trusted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventLogError {
    #[error("event log is not valid JSON: {0}")]
    Malformed(String),
    #[error("event log is empty")]
    Empty,
    #[error("event {index} has a {field} that is not hex: {value}")]
    NotHex {
        index: usize,
        field: &'static str,
        value: String,
    },
    #[error("event {index} digest is {len} bytes; SHA-384 registers need 48")]
    BadDigestLength { index: usize, len: usize },
    #[error(
        "event log does not reconstruct RTMR{imr}: replayed {replayed}, quote says {expected}"
    )]
    RegisterMismatch {
        imr: u32,
        replayed: String,
        expected: String,
    },
}

/// SHA-384 digest of one event, per the dstack convention.
fn event_digest(index: usize, event: &DstackEvent) -> Result<[u8; 48], EventLogError> {
    if !event.digest.is_empty() {
        let bytes = hex::decode(&event.digest).map_err(|_| EventLogError::NotHex {
            index,
            field: "digest",
            value: event.digest.clone(),
        })?;
        let len = bytes.len();
        return bytes
            .try_into()
            .map_err(|_| EventLogError::BadDigestLength { index, len });
    }

    let payload = hex::decode(&event.event_payload).map_err(|_| EventLogError::NotHex {
        index,
        field: "event_payload",
        value: event.event_payload.clone(),
    })?;
    let mut hasher = Sha384::new();
    hasher.update(event.event_type.to_le_bytes());
    hasher.update(b":");
    hasher.update(event.event.as_bytes());
    hasher.update(b":");
    hasher.update(&payload);
    Ok(hasher.finalize().into())
}

/// Fold every event for `imr` into a register value, from a zero seed.
fn replay_register(events: &[DstackEvent], imr: u32) -> Result<[u8; 48], EventLogError> {
    let mut acc = [0u8; 48];
    for (index, event) in events.iter().enumerate() {
        if event.imr != imr {
            continue;
        }
        let digest = event_digest(index, event)?;
        let mut hasher = Sha384::new();
        hasher.update(acc);
        hasher.update(digest);
        acc = hasher.finalize().into();
    }
    Ok(acc)
}

/// Verify a dstack event log against the measurement registers of a quote that
/// has *already* passed Intel trust-chain verification, and return the app
/// identity it records.
///
/// `rtmrs` must be the RTMR0..3 values read out of that verified quote. Every
/// register must reconstruct exactly; a single mismatch rejects the whole log
/// rather than trusting the events that happened to agree.
pub fn verify_event_log(
    raw_log: &str,
    rtmrs: [&[u8]; 4],
) -> Result<AppIdentity, EventLogError> {
    let events: Vec<DstackEvent> =
        serde_json::from_str(raw_log).map_err(|e| EventLogError::Malformed(e.to_string()))?;
    if events.is_empty() {
        return Err(EventLogError::Empty);
    }

    for (imr, expected) in rtmrs.iter().enumerate() {
        let imr = imr as u32;
        let replayed = replay_register(&events, imr)?;
        if replayed.as_slice() != *expected {
            return Err(EventLogError::RegisterMismatch {
                imr,
                replayed: hex::encode(replayed),
                expected: hex::encode(expected),
            });
        }
    }

    // Only now — with every register anchored — are these events evidence.
    let mut identity = AppIdentity::default();
    for event in events.iter().filter(|e| e.imr == 3) {
        let value = || Some(event.event_payload.clone());
        match event.event.as_str() {
            "app-id" => identity.app_id = value(),
            "compose-hash" => identity.compose_hash = value(),
            "instance-id" => identity.instance_id = value(),
            "os-image-hash" => identity.os_image_hash = value(),
            "mr-kms" => identity.mr_kms = value(),
            _ => {}
        }
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An event log whose shape and digest convention were captured from a live
    /// dstack CVM, with deployment-identifying payloads replaced and the
    /// registers recomputed so the fixture stays internally consistent.
    fn fixture() -> (String, serde_json::Value) {
        let log = include_str!("../../tests/fixtures/dstack/pod_event_log.json");
        let regs: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/dstack/pod_registers.json"))
                .expect("registers fixture");
        (log.to_string(), regs)
    }

    fn rtmr_bytes(regs: &serde_json::Value) -> Vec<Vec<u8>> {
        regs["rtmr"]
            .as_array()
            .expect("rtmr array")
            .iter()
            .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
            .collect()
    }

    #[test]
    fn captured_log_reconstructs_every_register() {
        let (log, regs) = fixture();
        let r = rtmr_bytes(&regs);
        let identity = verify_event_log(&log, [&r[0], &r[1], &r[2], &r[3]]).expect("verify");
        // RTMR3 is the one that only reconstructs via the derived-digest rule.
        assert_eq!(
            identity.compose_hash.as_deref(),
            Some("ea07fc3d1894fe056c43d21ad1b57bc626f43a1b2b9aef1d974907a1fee68eba")
        );
        assert_eq!(identity.app_id.as_deref(), Some(&"a".repeat(40)[..]));
        assert_eq!(
            identity.os_image_hash.as_deref(),
            Some("de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9")
        );
        assert!(identity.mr_kms.is_some());
    }

    #[test]
    fn a_tampered_event_is_rejected() {
        let (log, regs) = fixture();
        let r = rtmr_bytes(&regs);
        // Flip the compose-hash the platform recorded. The fold no longer lands
        // on the register Intel signed, so the whole log is refused.
        let tampered = log.replace(
            "ea07fc3d1894fe056c43d21ad1b57bc626f43a1b2b9aef1d974907a1fee68eba",
            "dead00003d1894fe056c43d21ad1b57bc626f43a1b2b9aef1d974907a1fee68e",
        );
        assert_ne!(tampered, log, "fixture should contain the compose hash");
        let err = verify_event_log(&tampered, [&r[0], &r[1], &r[2], &r[3]])
            .expect_err("tampered log must not verify");
        assert!(matches!(
            err,
            EventLogError::RegisterMismatch { imr: 3, .. }
        ));
    }

    #[test]
    fn a_dropped_event_is_rejected() {
        let (log, regs) = fixture();
        let r = rtmr_bytes(&regs);
        let mut events: Vec<serde_json::Value> = serde_json::from_str(&log).unwrap();
        let before = events.len();
        events.retain(|e| e["event"].as_str() != Some("os-image-hash"));
        assert_eq!(events.len(), before - 1);
        let shortened = serde_json::to_string(&events).unwrap();
        assert!(verify_event_log(&shortened, [&r[0], &r[1], &r[2], &r[3]]).is_err());
    }

    #[test]
    fn empty_and_malformed_logs_are_refused() {
        let (_, regs) = fixture();
        let r = rtmr_bytes(&regs);
        let refs = [&r[0][..], &r[1][..], &r[2][..], &r[3][..]];
        assert!(matches!(
            verify_event_log("[]", refs).unwrap_err(),
            EventLogError::Empty
        ));
        assert!(matches!(
            verify_event_log("not json", refs).unwrap_err(),
            EventLogError::Malformed(_)
        ));
    }
}
