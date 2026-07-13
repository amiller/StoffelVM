# Stoffel MPC node on dstack (attestation-gated committee)

Spec task W5 — package the slim Stoffel node as a dstack TEE container image and
bring up an N-node committee on staging CVMs, where each node admits the others
**only after** verifying their Intel TDX attestation against the expected image
measurement. This directory holds the dstack app manifest and the staging
bring-up procedure; the verifier itself lives in
`crates/stoffel-vm/src/net/attestation.rs` (`DstackAttestor`, W3 seam wired in
W5 to `dcap-qvl` for real TDX).

## What changed (W5)

| Piece | Where | What |
|---|---|---|
| Real TDX quote verification | `net/attestation.rs` `verify_dstack_quote` | Verifies the full Intel DCAP trust chain (QE/ISV signatures → PCK cert chain → TCB info + QE identity → Intel root CA) via `dcap-qvl`, then extracts the image measurement (`blake3(mr_td‖rtmr0..3)`) and the cert binding (`report_data[0..8]`). No fallback; an unverifiable quote is rejected. |
| Evidence obtainer (CVM-side) | `net/attestation.rs` `obtain_dstack_evidence` | Talks to the dstack device manager (`/var/run/dstack.sock` → `GetQuote`) to mint a quote bound to the node's TLS identity, fetches DCAP collateral from a PCCS, packages both into `DstackQuote`. Fails closed outside a CVM. |
| Runner wiring | `stoffel-vm-runner/.../stoffel-run.rs` `registration_attestation` | When `STOFFEL_ATTESTATION_MODE=dstack`, each node obtains evidence and presents it at admission; exits if evidence is unavailable. |
| Measurement capture | `stoffel-dstack-measurement` bin | Operator tool: prints a known-good image's measurement to pin in the allowlist. |
| Node image | `docker/dstack.Dockerfile` | Slim node build (`stoffel-run`) with `--features attestation-dstack`, `CC=clang`. |
| dstack app manifest | `dstack/stoffel-node.yaml` | Compose the dstack CVM runs; mounts the dstack socket, sets the attestation env. |
| CI proof | `docker/dstack-attestation-test.Dockerfile`, `docker/test-dstack-attestation.sh` | Runs the verifier against a real, Intel-issued TDX quote vector — captures the measurement-match log without TEE hardware. |

## The measurement binding

The verifier folds the TD measurement registers into a single 32-byte W3
`Measurement`:

```
measurement = blake3( mr_td ‖ rt_mr0 ‖ rt_mr1 ‖ rt_mr2 ‖ rt_mr3 )
```

Every register is hardware-attested (`mr_td` = td-shim/firmware; `rtmr0..1` =
firmware/bootloader; `rtmr2` = kernel+initrd; `rtmr3` = the app/compose image).
Pinning this digest means a node whose image differs in **any** layer — a
tampered container image, a different kernel, an unexpected firmware — measures
differently and is refused admission. The cert binding (`report_data[0..8]` =
the node's `tls_derived_id`) additionally makes a captured quote useless to
anyone lacking the matching TLS private key.

## Staging bring-up (real TDX)

Prerequisites: staging CVMs with Intel TDX + the dstack device manager, and a
PCCS reachable for DCAP collateral.

### 1. Build the node image

```bash
docker build -f docker/dstack.Dockerfile -t stoffel-dstack-node:dev .
```

(`CC=clang` is set in the Dockerfile — gcc 9.x trips aws-lc's memcmp guard.)

### 2. Capture the expected measurement from a known-good instance

Boot **one** instance of the image on a staging CVM and run the capture tool
(inside the CVM, where `/var/run/dstack.sock` exists):

```bash
# inside the booted CVM:
stoffel-dstack-measurement
# -> stoffel dstack image measurement:
#      <32-byte hex>
```

Pin that hex as `STOFFEL_ATTESTATION_ALLOWED_MEASUREMENTS` for the committee.
This is the "trust the first image" step; the verifier then refuses anything
that measures differently.

### 3. Launch N replicas (1 leader + N−1 parties)

The leader runs the bootnode (which enforces the admission gate) + party 0; the
other N−1 CVMs run parties that register with it. Each replica runs the same
image and the same manifest; the role is selected by env.

Leader CVM:
```bash
STOFFEL_ROLE=leader STOFFEL_PARTY_ID=0 \
STOFFEL_N_PARTIES=3 STOFFEL_THRESHOLD=1 \
STOFFEL_AUTH_TOKEN=$TOKEN \
STOFFEL_ATTESTATION_ALLOWED_MEASUREMENTS=$MEASUREMENT \
dstack compose -f dstack/stoffel-node.yaml up
```

Party CVMs (i=1..N−1), each pointed at the leader's bootnode address:
```bash
STOFFEL_ROLE=party STOFFEL_PARTY_ID=$i \
STOFFEL_BOOTSTRAP_ADDR=$LEADER_ADDR:9000 \
STOFFEL_N_PARTIES=3 STOFFEL_THRESHOLD=1 \
STOFFEL_AUTH_TOKEN=$TOKEN \
STOFFEL_ATTESTATION_ALLOWED_MEASUREMENTS=$MEASUREMENT \
dstack compose -f dstack/stoffel-node.yaml up
```

### 4. Verify admission + the demo

On the leader's bootnode log you should see, per registering peer, the W5
measurement-match line (emitted by `verify_dstack_quote`):

```
INFO stoffel::attestation::dstack: dstack TDX quote verified against Intel root of trust \
    measurement=… mr_td=… rtmr3=… cert_pubkey_hash=… tcb_status=UpToDate
```

and `[bootnode] Party i registering for session (… attestation=on)`. A peer
whose image measures differently is refused:

```
[bootnode] Rejected RegisterWithSession from party i (attestation: attestation \
    measurement <found> is not in the allowlist)
```

Once all N attested peers are admitted, the committee forms and the W4
submit→sync-by-hash→run→result demo runs end-to-end against the submission
endpoint (port 16180) — exactly as the W4 harness does, now gated on
attestation.

### 5. Negative control (wrong/tampered image refused)

Rebuild the image with any change (or run a different image) and launch an
(N+1)-th replica against the same allowlist: its measurement differs and the
bootnode refuses admission with `MeasurementNotAllowed`. The committee continues
to run with only the N attested, allowlisted peers.

## CI-runnable proof (no TEE required)

`docker/test-dstack-attestation.sh` runs the verifier against a real,
Intel-issued TDX quote + DCAP collateral vector (vendored under
`crates/stoffel-vm/src/tests/fixtures/dstack/`). It asserts:

* a real TDX quote verifies against the Intel root of trust and yields a
  deterministic measurement;
* an allowlisted measurement with a matching cert binding **admits**;
* an unallowlisted measurement is **rejected** (`MeasurementNotAllowed`);
* a cert-binding mismatch is **rejected** (`CertBindingMismatch`).

…and captures the measurement-match log line. This is the offline proof that
the W3 `DstackAttestor` is genuinely wired to real TDX.
