//! `stoffel-dstack-measurement` — capture a node image's attestation
//! measurement from a running dstack CVM (spec task W5).
//!
//! This is the staging operator's "trust the first image" tool. It obtains a
//! real TDX quote from the dstack device manager bound to a throwaway identity,
//! runs the SAME verifier the bootnode admission gate uses
//! ([`stoffel_vm::net::attestation::verify_dstack_quote`]) against it, and
//! prints the resulting 32-byte image measurement. The operator pins that hex
//! value as `STOCKEL_ATTESTATION_ALLOWED_MEASUREMENTS` for the N-replica
//! deployment, so any node whose image differs (wrong/tampered) is refused
//! admission.
//!
//! Runs **inside** a dstack CVM (the `/var/run/dstack.sock` must be reachable).
//! Outside a CVM it fails closed — there is no mock measurement.
//!
//! Usage:
//!   stoffel-dstack-measurement                # prints the measurement hex
//!   STOFFEL_DSTACK_SOCKET=/run/dstack.sock stoffel-dstack-measurement

#[cfg(not(feature = "attestation-dstack"))]
fn main() {
    eprintln!(
        "stoffel-dstack-measurement: this binary was built WITHOUT the attestation-dstack cargo\n\
         feature. Rebuild with --features attestation-dstack (the dstack node image already does)."
    );
    std::process::exit(1);
}

#[cfg(feature = "attestation-dstack")]
#[tokio::main]
async fn main() {
    use stoffel_vm::net::attestation::{obtain_dstack_evidence, verify_dstack_quote, Attestor};

    // A throwaway identity is enough: we only need a valid quote to read the
    // image measurement back. The measurement is independent of report_data.
    let evidence = match obtain_dstack_evidence(0).await {
        Ok(e) => e,
        Err(err) => {
            eprintln!("FATAL: could not obtain a dstack TDX quote: {err}");
            std::process::exit(2);
        }
    };
    let quote = match &evidence {
        stoffel_vm::net::attestation::AttestationEvidence::Dstack(q) => q.clone(),
        other => {
            eprintln!("internal error: expected dstack evidence, got {other:?}");
            std::process::exit(3);
        }
    };

    // Verify against the Intel root of trust using wall-clock time, exactly as
    // the bootnode does. This both proves the local quote is genuine and gives
    // us the parsed measurement.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let verified = match verify_dstack_quote(&quote.raw, &quote.collateral, now) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("FATAL: local TDX quote failed verification: {err}");
            std::process::exit(4);
        }
    };

    let attestor = stoffel_vm::net::attestation::DstackAttestor::new();
    // Cross-check: the full Attestor trait path agrees with the free function.
    assert_eq!(
        attestor.verify(&evidence).map(|v| v.measurement),
        Ok(verified.measurement),
    );

    println!(
        "stoffel dstack image measurement:\n  {}\n\n\
         Pin this as STOFFEL_ATTESTATION_ALLOWED_MEASUREMENTS for the N-replica\n\
         attestation admission gate. A node whose image measures differently\n\
         (wrong/tampered) will be refused admission.",
        hex::encode(verified.measurement),
    );
}
