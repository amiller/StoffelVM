//! Node persistence across kill+restart (issue #70 / spec task W2).
//!
//! These tests prove that a Stoffel MPC node, after consuming preprocessing
//! material for a job, can be killed and restarted while preserving BOTH:
//!   (a) the preprocessing pool (`storage/preproc.rs`, LMDB via `heed`) — the
//!       restarted node resumes from the *remaining* triples and neither
//!       regenerates them nor replays the already-spent ones; and
//!   (b) the reservation cursor/state (`net/reservation.rs`) — the restarted
//!       node continues allocating mask indices from the advanced cursor.
//!
//! The tests exercise the real `HoneyBadgerMpcEngine` + real `LmdbPreprocStore`
//! durability paths (the same ones the docker
//! `docker-compose.coordinator.reserve-index.preproc.yml` stack relies on) but
//! avoid the cost of a live network by pre-seeding the store with deterministic
//! triples and consuming them through the same in-memory pool API the
//! multiplication protocol uses. The persistence layer is agnostic to *how*
//! triples are consumed — `node.mul()` drains the pool via
//! `take_beaver_triples`, which is exactly what these tests call.

#![allow(clippy::needless_range_loop)]

use crate::net::engine_config::MpcSessionConfig;
use crate::net::hb_engine::{
    HoneyBadgerEngineConfig, HoneyBadgerMpcEngine, HoneyBadgerPreprocessingConfig,
};
use crate::net::mpc_engine::{DurableIdentityDigest, MpcEngine};
use crate::net::open_registry::OpenMessageRouter;
use crate::storage::preproc::{
    self, LmdbPreprocStore, MaterialKind, PreprocBlob, PreprocKey, PreprocKeyScope, PreprocStore,
};
use ark_bls12_381::{Fr, G1Projective};
use std::sync::Arc;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::triple_gen::ShamirBeaverTriple;
use stoffelnet::network_utils::ClientId;
use stoffelnet::transports::quic::QuicNetworkManager;

/// Committee shape used by the restart tests.
const N_PARTIES: usize = 4;
const THRESHOLD: usize = 1;
/// Preprocessing pool size each node starts with (models a prior generation
/// that was persisted to LMDB).
const POOL_SIZE: usize = 8;
/// Mask reservation capacity each node provisions.
const RESERVATION_CAPACITY: u64 = 16;
/// Number of triples / mask indices the first job consumes.
const CONSUMED: usize = 3;

/// Distinct instance ids per "run" so engines never collide on per-instance
/// open-share registries. The durable store keys are party-scoped, not
/// instance-scoped, so the persisted state is shared across these ids.
const FIRST_RUN_INSTANCE: u64 = 0x7700_0000_0001;
const SECOND_RUN_INSTANCE: u64 = 0x7700_0000_0002;

/// Program hash under which all preprocessing material is keyed.
const PROGRAM_HASH: [u8; 32] = [0x77; 32];

/// Distinct client identities that reserve mask indices.
const CLIENT_A: ClientId = 9001;
const CLIENT_B: ClientId = 9002;

type Engine = HoneyBadgerMpcEngine<Fr, G1Projective>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a fresh, unattached engine for `party_id` (mirrors the construction
/// path used by the honeybadger unit tests — no network is bound).
fn fresh_engine(party_id: usize, instance_id: u64) -> Arc<Engine> {
    let session = MpcSessionConfig::try_new(
        instance_id,
        party_id,
        N_PARTIES,
        THRESHOLD,
        Arc::new(QuicNetworkManager::new()),
    )
    .expect("test topology should be valid")
    .with_open_message_router(Arc::new(OpenMessageRouter::new()));
    let config = HoneyBadgerEngineConfig::new(session, HoneyBadgerPreprocessingConfig::new(1, 1));
    HoneyBadgerMpcEngine::<Fr, G1Projective>::from_config(config)
        .expect("engine construction should succeed")
}

/// Per-party durable identity used for store keys. `from_config` derives this
/// deterministically from the party id, so it is stable across a restart.
fn party_identity(party_id: usize) -> DurableIdentityDigest {
    DurableIdentityDigest::from_legacy_party_id(party_id)
}

/// Beaver-triple store key for a party.
fn triple_key(party_id: usize) -> PreprocKey {
    PreprocKeyScope::new(
        PROGRAM_HASH,
        crate::net::curve::MpcFieldKind::Bls12_381Fr,
        N_PARTIES,
        THRESHOLD,
        party_identity(party_id),
    )
    .key(MaterialKind::BeaverTriple)
}

/// Build a deterministic triple whose `a` share encodes `seed`, so the
/// surviving pool can be identified exactly after a restart (a regenerated
/// triple would carry a random field element, not `Fr::from(seed)`).
fn deterministic_triple(seed: u64) -> ShamirBeaverTriple<Fr> {
    let a_value = Fr::from(seed);
    let b_value = Fr::from(1_000 + seed);
    // mult = a * b in the field, matching the Beaver triple invariant.
    let mult_value = a_value * b_value;
    ShamirBeaverTriple::new(
        RobustShare::new(a_value, 1, THRESHOLD),
        RobustShare::new(b_value, 1, THRESHOLD),
        RobustShare::new(mult_value, 1, THRESHOLD),
    )
}

/// Seed a party's store with a full pool of deterministic triples (models a
/// prior network preprocessing generation that was persisted).
async fn seed_pool(store: &Arc<LmdbPreprocStore>, party_id: usize) {
    let triples: Vec<_> = (1..=POOL_SIZE as u64).map(deterministic_triple).collect();
    let (data, item_size) = preproc::serialize_beaver_triples::<Fr>(&triples).unwrap();
    store
        .store(
            &triple_key(party_id),
            &PreprocBlob::try_new(data, item_size, triples.len()).unwrap(),
        )
        .await
        .unwrap();
}

/// Attach `store` + program hash to `engine`.
fn attach_store(engine: &Engine, store: Arc<dyn PreprocStore>) {
    engine
        .preproc_persistence_ops()
        .expect("engine supports preproc persistence")
        .set_preproc_store(store, PROGRAM_HASH)
        .expect("set_preproc_store should succeed");
}

/// Drain and return `n` beaver triples from the engine's in-memory
/// preprocessing pool (the same API the multiplication protocol consumes via).
async fn drain_pool_triples(engine: &Engine, n: usize) -> Vec<ShamirBeaverTriple<Fr>> {
    let material = engine
        .node_handle()
        .lock()
        .await
        .preprocessing_material
        .clone();
    let mut guard = material.lock().await;
    guard
        .take_beaver_triples(n)
        .expect("pool should hold the expected number of triples")
}

/// Number of beaver triples currently held in the engine's in-memory pool.
async fn pool_triple_count(engine: &Engine) -> usize {
    let material = engine
        .node_handle()
        .lock()
        .await
        .preprocessing_material
        .clone();
    let count = material.lock().await.length().beaver_triples;
    count
}

/// Assert the pool's `a` shares are exactly `Fr::from(s)` for `s` in `seeds`,
/// and contain no other values.
fn assert_pool_a_shares(triples: &[ShamirBeaverTriple<Fr>], seeds: &[u64]) {
    assert_eq!(
        triples.len(),
        seeds.len(),
        "pool triple count must match the expected survivors"
    );
    for &s in seeds {
        assert!(
            triples.iter().any(|t| t.a.share[0] == Fr::from(s)),
            "expected surviving triple with a = Fr::from({s}) must be present"
        );
    }
    // No duplicate / extra triples: every pool entry must map to a seed.
    for t in triples {
        assert!(
            seeds.iter().any(|&s| t.a.share[0] == Fr::from(s)),
            "pool holds an unexpected triple not in the expected survivor set"
        );
    }
}

// ---------------------------------------------------------------------------
// Restart contract
// ---------------------------------------------------------------------------

/// Asserts the full issue-#70 restart contract for the preprocessing pool and
/// reservation cursor against a freshly-constructed (restarted) node.
async fn assert_restart_contract(store: &Arc<LmdbPreprocStore>, restarted_party: usize) {
    // --- Restart the node: brand-new engine bound to the same durable store. ---
    let restarted = fresh_engine(restarted_party, SECOND_RUN_INSTANCE);
    attach_store(restarted.as_ref(), store.clone());

    // `preprocess()` must LOAD the remaining pool from the store rather than
    // regenerate it over the network (no live network is configured here, so a
    // regeneration attempt would fail outright).
    restarted
        .preprocess()
        .await
        .expect("restart preprocess loads the persisted pool");

    // (a) Preprocessing pool: exactly the *remaining* triples survived.
    assert_eq!(
        pool_triple_count(&restarted).await,
        POOL_SIZE - CONSUMED,
        "restarted node must resume with the remaining pool, not regenerate"
    );

    // The surviving triples must be exactly the unconsumed ones, proving no
    // regeneration (deterministic seeds, not random field elements) and no
    // double-spend (consumed seeds are absent).
    let surviving = drain_pool_triples(&restarted, POOL_SIZE - CONSUMED).await;
    let expected_survivor_seeds: Vec<u64> = ((CONSUMED as u64) + 1..=(POOL_SIZE as u64)).collect();
    assert_pool_a_shares(&surviving, &expected_survivor_seeds);
    for seed in 1..=(CONSUMED as u64) {
        assert!(
            !surviving.iter().any(|t| t.a.share[0] == Fr::from(seed)),
            "consumed triple a = Fr::from({seed}) must not be replayed after restart"
        );
    }

    // The store blob must have been drained on load, so the consumed triples
    // cannot be loaded again by a further restart.
    assert!(
        store
            .load(&triple_key(restarted_party))
            .await
            .unwrap()
            .is_none(),
        "loaded preprocessing material must be drained from the store"
    );

    // (b) Reservation cursor: must resume from where the killed node left off.
    let reservations = restarted
        .reservation_ops()
        .expect("engine supports reservations");
    reservations
        .init_reservations(PROGRAM_HASH, RESERVATION_CAPACITY)
        .await
        .expect("init_reservations restores persisted cursor");

    assert_eq!(
        reservations.available_masks().await,
        RESERVATION_CAPACITY - CONSUMED as u64,
        "reservation cursor must reflect indices already reserved before the kill"
    );

    let next = reservations
        .reserve_masks(CLIENT_B, 1)
        .await
        .expect("reserve_masks after restart");
    assert_eq!(
        next.start, CONSUMED as u64,
        "restarted node must continue allocating mask indices from the advanced cursor"
    );
    assert_eq!(
        reservations.available_masks().await,
        RESERVATION_CAPACITY - CONSUMED as u64 - 1,
        "post-restart reservation must advance the persisted cursor"
    );
}

/// Run the "first job" lifecycle for `party_id`: load the seeded pool, reserve
/// mask indices, consume triples, then durably snapshot the reduced state.
async fn run_first_job(store: &Arc<LmdbPreprocStore>, party_id: usize) {
    let engine = fresh_engine(party_id, FIRST_RUN_INSTANCE);
    attach_store(engine.as_ref(), store.clone());

    // Load the persisted pool into the runtime.
    engine
        .preprocess()
        .await
        .expect("first-job preprocess loads the seeded pool");
    assert_eq!(
        pool_triple_count(&engine).await,
        POOL_SIZE,
        "seeded pool must load into the runtime"
    );

    // Reservation: a client reserves CONSUMED mask indices. This persists the
    // reservation cursor immediately (mirrors the masked-input protocol).
    let reservations = engine
        .reservation_ops()
        .expect("engine supports reservations");
    reservations
        .init_reservations(PROGRAM_HASH, RESERVATION_CAPACITY)
        .await
        .expect("init_reservations for first job");
    let grant = reservations
        .reserve_masks(CLIENT_A, CONSUMED as u64)
        .await
        .expect("reserve_masks for first job");
    assert_eq!(grant.start, 0, "first reservation starts at index 0");

    // The job consumes CONSUMED triples via the same in-memory pool API the
    // multiplication protocol uses (`node.mul` -> `take_beaver_triples`).
    let consumed = drain_pool_triples(&engine, CONSUMED).await;
    assert_pool_a_shares(&consumed, &(1..=(CONSUMED as u64)).collect::<Vec<_>>());

    // Durably snapshot the reduced pool + the already-persisted reservation
    // cursor. This is the restart-durability point the runner performs after a
    // job (`MpcRunner::persist_durability_state`).
    engine
        .preproc_persistence_ops()
        .expect("engine supports preproc persistence")
        .persist_preprocessing()
        .await
        .expect("persist_preprocessing snapshots the remaining pool");
    reservations
        .persist_reservations()
        .await
        .expect("persist_reservations snapshots the cursor");

    // Sanity: the store now holds only the remaining pool (consumed=0,
    // count=POOL_SIZE-CONSUMED).
    let blob = store
        .load(&triple_key(party_id))
        .await
        .expect("store read after persist")
        .expect("remaining pool must be persisted");
    assert_eq!(
        blob.meta.count as usize,
        POOL_SIZE - CONSUMED,
        "persisted snapshot must contain only the unconsumed triples"
    );
}

// ---------------------------------------------------------------------------
// Committee restart: kill + restart ONE node mid-committee
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committee_restart_preserves_preproc_pool_and_reservation_cursor() {
    crate::tests::test_utils::init_crypto_provider();

    // One durable store per party (models independent node volumes, as in the
    // docker-compose.coordinator.reserve-index.preproc.yml stack).
    let dir = tempfile::tempdir().expect("temp dir for committee stores");
    let stores: Vec<Arc<LmdbPreprocStore>> = (0..N_PARTIES)
        .map(|party_id| {
            let path = dir.path().join(format!("party{party_id}"));
            Arc::new(LmdbPreprocStore::open(path).expect("open party store"))
        })
        .collect();

    // Seed every committee member with a persisted preprocessing pool, as if a
    // prior network generation had completed and been snapshotted.
    for party_id in 0..N_PARTIES {
        seed_pool(&stores[party_id], party_id).await;
    }

    // --- Phase 1: the whole committee runs the first job. ---
    for party_id in 0..N_PARTIES {
        run_first_job(&stores[party_id], party_id).await;
    }

    // Every committee member durably reduced its pool and advanced its cursor.
    for party_id in 0..N_PARTIES {
        let blob = stores[party_id]
            .load(&triple_key(party_id))
            .await
            .unwrap()
            .expect("party pool snapshot present after first job");
        assert_eq!(blob.meta.count as usize, POOL_SIZE - CONSUMED);
    }

    // --- Phase 2: kill + restart ONE node (party 0) and run a second job. ---
    //
    // Parties 1..N keep their state untouched; only party 0 is reconstructed
    // against the same durable store and must resume correctly.
    assert_restart_contract(&stores[0], 0).await;

    // The non-restarted members' durable state is unaffected by party 0's
    // restart — their stores still hold the phase-1 snapshots.
    for party_id in 1..N_PARTIES {
        let blob = stores[party_id]
            .load(&triple_key(party_id))
            .await
            .unwrap()
            .expect("non-restarted party snapshot still present");
        assert_eq!(blob.meta.count as usize, POOL_SIZE - CONSUMED);
    }
}
