# Spec: lobby for attested MPC committees (L1–L5)

Design: `stoffel-tee-runner/docs/lobby-design.md`. Executor: Paseo swarm on zed.
Baseline: branch `w7-committee-demo` (tip `ab75122`), which already has real-TDX
attestation, event-log verification, the admission gate, and `/health /attestation
/peers /result`.

## 1. What already exists — build on, do not rebuild

- `net::attestation` — quote verification against the Intel root, boot-register
  measurement `blake3(mr_td||rtmr0..2)`, cert binding via `report_data`, admission
  allowlist. Fail-closed.
- `net::dstack_event_log` — replay a dstack event log onto a verified quote's
  registers and read `compose-hash` / `app-id` / `os-image-hash` out of it.
- `http_observability` — the four JSON routes and `ObservabilityState`.
- `docker/entrypoint.sh` — advertise-address selection, role wiring.
- `dstack/w7-final.sh` — a working pod deploy that produces an attested committee.

Do not re-derive measurements, re-implement quote parsing, or add a second HTTP
server. Extend what is there.

## 2. Hard rules for every task

- **No bare `cargo` on zed or the laptop.** Both have OOM-frozen. Build only inside
  a capped container:
  `docker run --rm --memory=8g --cpus=2 -e CARGO_BUILD_JOBS=2 -e CC=clang -e CXX=clang++ -v $HOME/stoffel-build:/build -w /build rustlang/rust:nightly-bookworm`
  Prefer `cargo check` / targeted `cargo test -p <crate> --lib <filter>` over full builds.
- **No fallbacks that mask errors.** Absent evidence is an error, never a downgrade.
  A previous agent draft passed `attestation=None` at two call sites and silently
  disabled the gate; that class of change is an automatic reject.
- Commit on your worktree branch. **Do not push.**
- Every task states its own success test. A task is not done until that test runs.
- Never hardcode a secret. Read tokens from the environment.

## 3. Work items

### L1 — Durable node identity
A node's identity is currently `tls_derived_id`, derived from a per-process TLS key,
so it changes on every restart.

Generate a long-term Ed25519 keypair once, persist it under the node's data volume
(`/data`), and bind its public key into the quote: `report_data` is 64 bytes and
only `[0..8]` is used today, so put `hash(long_term_pubkey)` at `[8..40]` and leave
the existing cert binding untouched. Expose `node_id` on `/attestation`.

The verifier must check the new binding when present. Keep the existing
`tls_derived_id` check exactly as is — this adds a binding, it does not replace one.

**Success:** kill and restart a node; `node_id` is unchanged across the restart and a
fresh quote still binds it. A node whose `report_data` binds a different key than the
`NodeRecord` it signs is refused.

### L2 — Evidence bundle + offline verifier
Define a self-contained `EvidenceBundle` (serde) carrying: the `JobRecord`, the
`NodeRecord`s, and the `JoinRecord`/`ResultRecord`s, with each node's quote,
collateral and event log inline.

Add a `stoffel-verify` binary: takes a bundle path, exits 0 if every check in
design §Verification passes, non-zero with a specific reason otherwise. **No network
access** — collateral travels in the bundle.

**Success:** verifies a bundle captured from a real run; rejects, with distinct
errors, a bundle with (a) a tampered measurement, (b) a mutated event log,
(c) a bad Join signature, (d) results that disagree, (e) a quote whose `report_data`
binds the wrong key.

This is the highest-value task and depends on nothing. Start here.

### L3 — Lobby service (untrusted index)
A small HTTP service storing signed records append-only. Routes:

```
POST /nodes            NodeRecord        announce / heartbeat
GET  /nodes            list, filterable by measurement + freshness
POST /jobs             JobRecord         propose
GET  /jobs             list, filterable by state
POST /jobs/{id}/join   JoinRecord
POST /jobs/{id}/result ResultRecord
GET  /jobs/{id}/bundle EvidenceBundle    what L2 verifies
```

The service verifies signatures on write and rejects malformed records, but is
**not** trusted for correctness — a reader re-verifies everything. State may be a
single append-only file to start. Deployable as a dstack tenant on one proxied port.

**Success:** two nodes announce; a job is proposed, joined by both, results posted;
`GET /jobs/{id}/bundle` returns a bundle that `stoffel-verify` accepts. A record with
a forged signature is rejected on write *and* would be caught by the verifier.

### L4 — Job lifecycle in the node
Replace deploy-and-immediately-run with announce → poll for a matching job → join →
run → publish result + evidence. Node config gains a lobby URL and a policy for which
jobs it will accept.

The existing baked-program path stays working, selected by config, so the current
deploy scripts do not break.

**Success:** four nodes pointed at a lobby, a job proposed externally, committee forms
and runs without redeploying anything, and the published bundle verifies.

Depends on L1, L2, L3. Not an overnight task — this is the integration.

### L5 — Webapp
Read-only page over L3: nodes, jobs, and per-job evidence with a verdict the page
computes itself. Build against a fixture bundle and a mock of the L3 API so it does
not block on L3 landing.

Do **not** display a verification verdict the page did not compute. If in-browser
verification (wasm build of the L2 verifier) does not work, show the bundle and the
exact command that checks it.

**Success:** page renders live committee state from the API; the verdict changes to a
failure when pointed at a tampered bundle fixture.

## 4. System-level success

Someone who operates none of this can fetch a bundle for a finished job and verify,
offline, that n distinct TDX-attested nodes running an allowed measurement agreed on
a value — without asking any of those nodes to vouch for themselves.

## 5. Non-goals

Transparency log / inclusion proofs; payments, staking, slashing; reputation beyond
attested-and-recently-seen; committee selection beyond first-n-eligible; resharing.

## 6. Overnight wave

Parallel, no interdependencies: **L2**, **L3**, **L1**, **L5-against-mock**.
Stagger container builds; do not run four full Rust builds at once.
**L4 is the next-day integration** and needs the other three reviewed first.
