# Spec: Attestation-gated Stoffel MPC node ("submit-a-program" demo)

Status: DRAFT for review. Target executor: Paseo swarm (parallel coding agents, docker + staging CVM).

## 1. Motivation

Build a public-facing demo where anyone can **submit a compiled MPC program** and have a
**committee of Stoffel nodes run it jointly** without any single node seeing the plaintext inputs.

Deployment model:
- **(a)** is the real product: N nodes run by mutually-distrusting operators.
- **(b)** is what we ship as the demo: all N nodes are hosted by us on **dstack TEE CVMs**.

(b) is only acceptable as a stand-in for (a) if the trust is discharged by **hardware remote
attestation**, not by knowing the operators. So the core question this demo answers is:

> How do you *select and coordinate* MPC nodes you must trust — i.e. admit a node into a committee
> only after verifying it is a genuine TEE running the expected, unmodified node image?

## 2. What already exists (build on, do not rebuild)

Verified against the code as of this spec:

| Capability | Where | Notes |
|---|---|---|
| Peer discovery + admission | `crates/stoffel-vm/src/net/discovery.rs` | `DiscoveryMessage::Register` / `RegisterWithSession`; `tls_derived_id` = hash of cert pubkey for allowlisting; shared `STOFFEL_AUTH_TOKEN` gate via `registration_token_is_valid` + `constant_time_eq`. **This is the admission seam.** |
| Content-addressed program distribution | `net/program_sync.rs` | Bytecode addressed by `blake3` hash; `agree_and_sync_program`; on-demand fetch + local cache. Compile is client-side; node runs bytecode by hash. |
| Persistent preprocessing store | `storage/preproc.rs` | LMDB (`heed`), stores `ShamirBeaverTriple` + random/prandbit/prandint keyed by program hash + params. **This is issue #70 (Node persistence).** |
| Preprocessing reservation | `net/reservation.rs` | Sequential-cursor index allocation, Reserved/Consumed per client identity, serializable snapshot. |
| Compile-time demand analysis | `crates/stoffel-lang/src/preprocessing_planner.rs` | Interprocedural abstract interpretation → `PreprocessingDemand`; sizes triples/bits/ints per run; sets `dynamic=true` when unsizable. |
| Demand-driven replenish | `net/mpc/honeybadger/preprocessing.rs` | `reserve_*` pull from pool; auto-regenerate over network on `NotEnoughPreprocessing`. |
| Docker multi-node harnesses | `docker-compose*.yml`, `docker/` | nat, coordinator+reserve-index+preproc, avss, benchmark. |
| In-process multi-node e2e | `src/tests/{vm_turmoil_e2e,vm_mesh_integration,leader_bootnode_integration}.rs` | Committee behavior testable without real network. |

**Gap:** nothing binds "this peer is a real dstack TEE running the expected measurement" to
"this peer is admitted as party i." That binding is the deliverable.

## 3. Work items (each independently ownable + testable)

Provider assignment (swarm): **5.2** for design/security/crypto-glue items (W3, W5); **5.1** for
mechanical/wiring items (W1, W4). W2 straddles but was run on 5.1 and did competent work.

### W1 — Node image slimming (precondition) — ALREADY SATISFIED at baseline
- CORRECTION: `stoffellang` is already under `[dev-dependencies]` (Cargo.toml line 75+), NOT
  `[dependencies]`, and is referenced only from test code (`core_vm/tests.rs`, integration tests).
  The node build already excludes the compiler; the original premise here was wrong. Commit
  `b6d61fd` (`w1-node-slim`) only adds a regression-guard comment.
- **Success (met):** `cargo tree -p stoffel-vm` shows no `stoffellang` in the non-test build; tests pass.

### W2 — Node persistence hardening (issue #70)
- Ensure a node restart preserves: preprocessing pool (`storage/preproc.rs`) **and** reservation
  cursor/state (`net/reservation.rs` serializable snapshot).
- **Success:** docker test — start committee, run a job that consumes K triples, kill+restart one
  node, run a second job; the restarted node resumes with the correct cursor and does NOT
  re-generate or double-spend preprocessing. Assert triple counts + reservation cursor across restart.

### W3 — Attestation admission gate (core deliverable)
- Define an `AttestationEvidence` type and a `verify(evidence, expected_measurement) -> Result<CertPubkeyHash>`
  trait, with two impls:
  - `MockAttestor` (deterministic, for docker/CI — no TEE needed).
  - `DstackAttestor` (real TDX quote via dstack; behind a feature flag).
- Extend `RegisterWithSession` so a registering party presents attestation evidence that **binds its
  TLS cert pubkey** (the existing `tls_derived_id`). Bootnode/peers verify the quote's measurement
  against an allowlist of expected image measurements before admitting to the committee allowlist.
- Keep the existing `STOFFEL_AUTH_TOKEN` path working (attestation is additive, selected by config).
- **Success:** unit tests for verify (good quote admits; wrong measurement rejects; quote not bound
  to the presented cert rejects; replayed quote for a different cert rejects). Extend a bootnode
  integration test (`leader_bootnode_integration.rs`) so a peer with `MockAttestor` bad-measurement
  is refused and the committee forms only from good-measurement peers.

### W4 — Program submission endpoint (thin)
- Minimal external entrypoint: accept `(bytecode, entry_fn)`, compute `blake3` program id, seed it via
  `program_sync`, trigger `agree_and_sync_program` + a run across the committee, return a job id / result.
- Reuse `client_store` for external client inputs; do not invent a new input path.
- **Success:** docker harness — `curl`/client submits a small program to one node; committee syncs by
  hash and runs; result returned; a tampered program (wrong hash) is rejected.

### W5 — dstack packaging + staging CVM bring-up
- Node container image (from W1 slim build) + dstack app manifest; N replicas; attestation via W3's
  `DstackAttestor`.
- **Success (staging):** N-node committee comes up on staging CVMs, each admits the others only after
  attestation, submits+runs the W4 demo program end-to-end. Capture attestation logs showing measurement
  match.

Dependency order: **W1, W2 in parallel → W3 → W4 → W5.** W3 depends on W1 (slim identity story) and
benefits from W2. W5 depends on all.

## 4. System-level success conditions

1. **Docker (CI, no TEE):** `MockAttestor` committee forms; a bad-measurement node is refused;
   submit→sync-by-hash→run→result works; node restart preserves preprocessing + reservation state.
2. **Staging CVM (real TEE):** `DstackAttestor` committee forms only from attested nodes running the
   expected measurement; the same submit→run demo passes; wrong/again-tampered image is refused admission.
3. **No regressions:** existing `cargo test -p stoffel-vm` + docker harnesses stay green; the
   `STOFFEL_AUTH_TOKEN` admission path is unchanged when attestation is disabled.

## 5. Non-goals (for this demo)

- No economic/spam metering on the public endpoint (note it, don't build it).
- No cross-operator (a) deployment — (b) on our own dstack CVMs, modelling (a) via attestation.
- No new MPC protocol work — HoneyBadger as-is.
