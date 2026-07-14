# Stoffel MPC node on dstack (attestation-gated committee)

Spec task W5 — package the slim Stoffel node as a dstack TEE container image and
bring up an N-node committee on staging CVMs, where each node admits the others
**only after** verifying their Intel TDX attestation against the expected image
measurement. This directory holds the dstack app manifest and the staging
bring-up procedure; the verifier itself lives in
`crates/stoffel-vm/src/net/attestation.rs` (`DstackAttestor`, W3 seam wired in
W5 to `dcap-qvl` for real TDX).

**W6** adds an HTTP observability server (`GET /health`, `GET /attestation`)
that the dstack-webhost `tee-daemon` proxies as the app's single `image_port`
(8090), so each node is reachable and self-reports its own attested
measurement from outside the CVM. See [What changed (W6)](#what-changed-w6).

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

## What changed (W6)

| Piece | Where | What |
|---|---|---|
| HTTP observability server | `stoffel-vm-runner/src/http_observability.rs` + `stoffel-run.rs` | Minimal hand-rolled HTTP/1.1 server (`tokio::net::TcpListener`, no `axum`/`hyper`) spawned at startup, bound to `STOFFEL_HTTP_ADDR` (default `0.0.0.0:8090`). `GET /health` → `200 {status,role,party_id}` liveness probe; `GET /attestation` → `200 {attestation_mode, ...}` running-attested report. |
| Self-reported measurement | `stoffel-run.rs` `registration_attestation` | In `dstack` mode, once evidence is obtained it is **locally pre-verified** (`verify_dstack_quote`, same step `stoffel-dstack-measurement` performs) and the node's own attested measurement / `tls_derived_id` / `tcb_status` are recorded into shared state, so `GET /attestation` surfaces them. Fail-closed obtain behavior is unchanged; the report only ever reflects a genuinely verified quote. |
| `tcb_status` on `VerifiedAttestation` | `net/attestation.rs` | The verifier now returns the resolved TCB status (e.g. `UpToDate`) alongside the measurement / cert binding, so the running-attested report can carry it. |
| Node image | `docker/dstack.Dockerfile` | `EXPOSE 8090` + `ENV STOFFEL_HTTP_ADDR=0.0.0.0:8090`. (`CC=clang`/`CXX=clang++` were already set — gcc 9.x trips aws-lc's memcmp guard.) |
| dstack app manifest | `dstack/stoffel-node.yaml` | Adds top-level `image_port: 8090` (the ONE port the `tee-daemon` HTTP-proxies), the `STOFFEL_HTTP_ADDR`/`STOFFEL_DSTACK_SOCKET` env, the `8090:8090` port mapping, and bind-mounts the filtered broker socket `/run/broker/dstack.sock` (GetQuote-only). |

### Why one proxied port

dstack-webhost's `tee-daemon` HTTP-proxies **exactly one** `image_port` per
app. That port is the HTTP observability server (8090): it is how an operator
(outside the CVM) confirms a Stoffel node is alive (`GET /health`) and genuinely
running the attested image (`GET /attestation`). The submission RPC stays on its
own port (`16180`) and is reached directly — it is not the proxied port.

### `GET /attestation` shape

Always carries `attestation_mode`. When `attestation_mode == "dstack"` **and**
this node has obtained + locally verified its own TDX quote, the body also
carries the node's own attested state:

```json
{
  "attestation_mode": "dstack",
  "measurement": "<blake3(mr_td‖rtmr0..3) hex>",
  "tls_derived_id": <usize>,
  "tcb_status": "UpToDate"
}
```

Before evidence is obtained (or in `disabled`/`mock` mode) the dstack-specific
fields are absent — the server never fabricates a measurement.

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

#### Observe a node through the webhost (W6)

The dstack-webhost `tee-daemon` HTTP-proxies the app's single `image_port`
(8090, set in `dstack/stoffel-node.yaml`). Once a CVM is up, hit the proxied
endpoint to confirm it is alive and running the attested image:

```bash
# Liveness probe (always available once the server is up):
curl -s https://<webhost-gateway>/health
# {"status":"ok","role":"leader","party_id":0}

# Running-attested report (mode +, once evidence is obtained, the node's own
# measurement / tls_derived_id / tcb_status):
curl -s https://<webhost-gateway>/attestation
# {"attestation_mode":"dstack","measurement":"…","tls_derived_id":0,"tcb_status":"UpToDate"}
```

(Inside the CVM, the same is reachable at `http://127.0.0.1:8090/...`. From a
bare `docker run` without the webhost, port 8090 is published directly.) The
`measurement` a node reports for itself equals the value the bootnode admission
gate matches against `STOFFEL_ATTESTATION_ALLOWED_MEASUREMENTS`.

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
