# RESUME: attestation-gated MPC node swarm

State as of this file. Spec: `tasks/mpc-node-attestation-spec.md`. Executor: Paseo swarm on **zed**
(W1–W6); W7 finished laptop-side after zed OOM incidents — see W7 section.

## W7 (2026-07-22): committee demo — DONE, verified locally, deploying to pod
Branch `w7-committee-demo` (laptop `~/projects/stoffel-w7`; zed mirror branch `w7b`, build tree `~/stoffel-build`).
- **/peers on the bootnode HTTP server** (the only observability on the pod — no tenant logs):
  `{"admitted":[{party_id, admitted_at, measurement_hex?}], "rejected":[{reason, rejected_at}]}`.
  Wired via `run_bootnode_with_config_and_callback` (discovery.rs) — env-driven auth+attestation
  gate is mandatory at that entry point. (First agent draft bypassed the gate with attestation=None
  at both stoffel-run call sites — fixed in `dbf5587`; watch for this bug class in agent code.)
- **Demo program** `docker/programs/demo_program.stfl` (valid StoffelLang: typed `Share.random()`,
  `Share.mul`, `.reveal()`), compiled from source in the image builder stage via `stoffellang -b`
  → `/app/programs/program.stflb`. Program is committee-size-agnostic (no n/t flags in stoffellang).
- **Committee = n=4 t=1.** t=0 is NOT compilable (CLI rejects `--threshold 0`), so the n=2/t=0 idea
  is dead. `n>=3t+1` enforced in `validate_honeybadger_topology`.
- **entrypoint.sh**: `STOFFEL_ADVERTISE_HOST` resolved via docker DNS (getent retry, hard-fail);
  fixed `local`-outside-function bash bug.
- **e2e (zed, capped container, attestation disabled — mock is CI-only by design):** standing
  bootnode + 4 parties: all admitted in /peers, program opened identical value on all 4, bad-token
  party recorded as `{"reason":"invalid auth token"}`. Benign oddity: "Rejected program bytes
  (hash mismatch)" per party during upload — run unaffected; report upstream.
- **Pod topology:** parties are run-to-completion (leader/party exit after the run) — the STANDING
  tenant must be role=bootnode (it's the gatekeeper + /peers server). Party↔bootnode QUIC only works
  with all tenants `egress:true` (shared `tee-egress` bridge; image tenants are otherwise isolated
  per-project). Bootstrap = `tee-image-stoffel-node-attested:9000`, advertise = own container name.
- **Measurement pinning:** computed OFFLINE from the pod's public `/_api/verification/<project>`
  platform_quote — `blake3(mr_td‖rtmr0..3)`, script `measurement_from_quote.py` (session scratchpad;
  copy into repo if needed). Pod CVM measurement 2026-07-22:
  `f24fe216de770b5ab25536cf9038b895af71efa56623b847adc9c058b45230b0` (CVM-level: shared by all
  tenants on the pod — pin says "this CVM stack", image binding stays with the daemon).
- **Build ops (hard rules):** NO bare cargo on zed or laptop (both OOM-froze 2026-07-22). Build in
  capped containers: `docker run --memory=10g --cpus=3 -e CARGO_BUILD_JOBS=2 rust:1-bookworm`;
  image build has `ARG CARGO_BUILD_JOBS=2`. zed binaries built in bookworm do NOT run on the 20.04
  host (glibc) — run them inside the same image. Image: `ghcr.io/amiller/stoffel-dstack:w7`,
  push from laptop (`DOCKER_HOST=ssh://zed-mesh docker push` — creds stay on laptop).
- **Deploy sequence** (script `w7-deploy.sh`, runs on zed, token from `.staging-env`): bootnode with
  ZEROS pin + 4 parties → parties REFUSED (negative test, visible in /peers) → redeploy bootnode
  with real measurement → redeploy parties → admitted, program runs. Auth token reused from the
  7/14 deployment.

## W7 pod bring-up — DONE on the pod 2026-08-15 (attested committee verified)
The 7/22 deploy went out but was never verified; it had in fact never worked. Two blockers,
both found and fixed on 8/15:

1. **Stale measurement pin.** The pod CVM was upgraded since 7/22, so the pinned
   `f24fe216…` no longer matched. Current: `3dbc0ef7a6766c3d2739920f280d821cf343b5b0a3a111825daad9779923aa3f`
   (recompute with `measurement_from_quote.py` off `/_api/verification/<project>` after any pod upgrade).
2. **`ALL_PROXY` kills the DCAP collateral fetch.** `egress:true` — required for party↔bootnode
   QUIC — makes tee-daemon inject `ALL_PROXY=socks5://egress-vpn:1080`. The `reqwest` under
   `dcap-qvl` is built WITHOUT the socks feature (no `tokio-socks` in Cargo.lock), so
   `obtain_dstack_evidence` fails at the PCCS fetch and the party `exit(13)`s in ~1s — before it
   registers, so `/peers` showed neither an admission nor a rejection. Fix: set
   `NO_PROXY`/`no_proxy` for the PCCS hosts (now in `w7-deploy.sh:common_env`). PCCS is reachable
   directly from a tenant, so bypassing the proxy is enough.

**Verified on the pod (n=4, t=1, real TDX):**
- real pin → all 4 parties admitted in `/peers`, no rejections
- zeros pin → all 4 rejected: `attestation: attestation measurement 3dbc0ef7… is not in the allowlist`
  (fail-closed gate proven, and the measurement the parties present matches the offline computation)
- `/stoffel-p0/attestation` → `{"measurement":"3dbc0ef7…","tls_derived_id":17731227442834126731,"tcb_status":"UpToDate"}`

**Still unverified: the program result.** Parties are run-to-completion and the daemon restarts
them (~66s cycle, visible as repeat admissions + `duplicate party_id` rejections), so admission is
proven but "all 4 opened the same value" is not — that needs container logs. The pod daemon
predates `e8bb9a2d` (`GET /_api/projects/<name>/logs`), so it has no logs route; deploying that
daemon build is the unblock. Debug method used instead: a throwaway attested image tenant
(`ghcr.io/amiller/stoffel-dstack:probe`, source in the session scratchpad) that reports
`/run/broker` contents, a raw `GetQuote` over the socket, and PCCS reachability as JSON on 8090.

Other notes: pod OCI runtime is `runc`, not gVisor (`/_api/substrate`) — the `11ac89f` commit
message's gVisor attribution for ping/nc is wrong; `nc` is simply absent from the image. Local
two-network docker repro of the pod topology (bootnode + party on separate project networks +
shared egress net, attestation disabled) passes and is the fastest non-pod check.

## Paseo access (zed)
```bash
ssh zed 'echo ok'
export NVM_DIR=$HOME/.nvm; . $NVM_DIR/nvm.sh
H='tcp://localhost:6767?password=rb1oP3u94mL4R6Oxbemuiy8068Un'
paseo ls --host "$H"     # status of all agents
```
Repo on zed: `~/projects/stoffel`. Worktrees under `~/.paseo/worktrees/*`.

## Status
- **W1** node-slim — DONE (no-op; premise was already satisfied). Branch `w1-node-slim` (`b6d61fd`).
- **W2** node persistence #70 — DONE. Branch `w2-node-persistence` (`6f33a28`). Real fix: preproc pool
  wasn't re-snapshotted after `mul`; added capability-gated `persist_preprocessing` + N=4 kill/restart test.
- **Integration branch `integration-wave1`** = W2 + W1 guard + corrected spec (tip `75a1f07`). Base for W3.
- **W3** attestation gate — RUNNING on GLM-5.2, agent `2c673f2d-f84a-4811-9a89-188ef118b3df`,
  worktree `w3-attestation-gate`, base `integration-wave1`.

## To continue (fresh session)
1. Check W3: `paseo ls --host "$H"` → wait for `2c673f2d` to be `idle`.
2. Review: `paseo logs 2c673f2d-f84a-4811-9a89-188ef118b3df --host "$H"`; inspect its worktree
   `git log/diff` vs `integration-wave1`; confirm the four security tests exist and pass, and that the
   verifier fails closed (no admit-by-default). Reject + re-prompt if not.
3. Make `integration-wave2` from W3's branch (mirror the wave-1 integration steps), keeping the spec.
4. Spawn **W4 (submission endpoint) on GLM-5.1** and, after it lands+reviews, **W5 (dstack) on GLM-5.2**,
   each `--base integration-wave<n>` in its own `--worktree`. Provider convention: `pi/zai/glm-5.1|5.2`,
   `--thinking medium`, `--detach`, mode default.

### W4 prompt (5.1)
> StoffelVM repo, task W4 from tasks/mpc-node-attestation-spec.md. Add a thin external submission entry:
> accept `(bytecode, entry_fn)`, compute the blake3 program id, seed it via `net/program_sync.rs`, trigger
> `agree_and_sync_program` + a committee run, return a job id/result. Reuse `client_store` for external
> client inputs — do NOT invent a new input path. Success (verify): a docker/integration test where a client
> submits a small program, the committee syncs by hash and runs, result returned, and a tampered program
> (wrong hash) is rejected. Minimal changes, no error-masking fallbacks. Commit on the worktree branch, do
> not push. Full context in the spec.

### W5 prompt (5.2)
> StoffelVM repo, task W5 from tasks/mpc-node-attestation-spec.md. Package the slim node as a container
> image + a dstack app manifest for N replicas, wired to W3's `DstackAttestor` (real TDX). Success (staging):
> an N-node committee comes up on staging CVMs, each admits the others only after attestation against the
> expected measurement, and the W4 demo program runs end-to-end; a wrong/tampered image is refused admission.
> Capture attestation logs showing measurement match. Minimal changes, no fallbacks that mask errors. Commit
> on the worktree branch, do not push. Full context in the spec.
