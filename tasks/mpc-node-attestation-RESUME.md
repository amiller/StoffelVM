# RESUME: attestation-gated MPC node swarm

State as of this file. Spec: `tasks/mpc-node-attestation-spec.md`. Executor: Paseo swarm on **zed**.

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
