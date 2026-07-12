//! External program submission endpoint end-to-end (spec task W4).
//!
//! Proves the full submit→sync-by-hash→committee-run→result path against a
//! real HoneyBadger committee over QUIC, plus the tampered-program rejection:
//!
//! 1. A small MPC program (client[0] * client[1]) is compiled to bytecode and
//!    submitted to a node's submission TCP endpoint — the *external entry*.
//! 2. [`submission::prepare_submission`] computes the blake3 program id,
//!    validates it, and seeds the content-addressed cache.
//! 3. The host [`CommitteeRunner`] loads the program **by hash** from the cache
//!    (`program_sync::program_path`), registers it on every party, and runs it
//!    concurrently across the committee via the async MPC scheduler — reusing
//!    the existing `client_store` input path, with no new input mechanism.
//! 4. The result is returned to the submitting client over the TCP wire.
//! 5. A second submission whose *claimed* program id differs from the
//!    recomputed blake3 id is rejected as `ProgramTampered` **before** the
//!    runner is ever invoked — no error-masking fallback.
//!
//! Client inputs flow through the standard HoneyBadger input protocol into the
//! VM `client_store` exactly as in `vm_mesh_integration`; this test only adds
//! the submission wrapper around that existing path.

#![allow(clippy::needless_range_loop)]

use ark_bls12_381::Fr;
use ark_std::rand::SeedableRng;
use async_trait::async_trait;
use std::collections::HashMap;
use std::fs::File;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use stoffel_vm_types::compiled_binary::CompiledBinary;
use stoffel_vm_types::core_types::Value;
use stoffel_vm_types::functions::VMFunction;
use stoffel_vm_types::instructions::Instruction;
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelnet::network_utils::ClientId;
use tokio::net::TcpListener;
use tracing::info;

use crate::core_vm::VirtualMachine;
use crate::net::hb_engine::HoneyBadgerMpcEngine;
use crate::net::program_sync::program_path;
use crate::net::submission::{
    handle_submission, scoped_cache, serve_submission_tcp, submit_tcp, CommitteeRunner,
    SubmissionOutcome, SubmissionRequest,
};
use crate::tests::mpc_multiplication_integration::{
    assign_topological_client_ids, register_topological_client_connections,
    setup_honeybadger_quic_clients, setup_honeybadger_quic_network, HoneyBadgerQuicConfig,
    RoutedNetwork,
};
use crate::tests::test_utils::{acquire_hb_itest_lock, init_crypto_provider, setup_test_tracing};

type HbEngine = HoneyBadgerMpcEngine<Fr, ark_bls12_381::G1Projective>;

const CLIENT_PROGRAM_REGISTERS: usize = 19;
const ENTRY: &str = "multiply_client_inputs";

/// Build the small `client[0] * client[1]` MPC program (same shape as
/// `vm_mesh_integration`).
fn build_client_mul_program() -> Vec<Instruction> {
    vec![
        Instruction::CALL("ClientStore.get_number_clients".to_string()),
        Instruction::MOV(2, 0),
        Instruction::LDI(0, Value::I64(0)),
        Instruction::PUSHARG(0),
        Instruction::LDI(1, Value::I64(0)),
        Instruction::PUSHARG(1),
        Instruction::CALL("ClientStore.take_share".to_string()),
        Instruction::MOV(16, 0),
        Instruction::LDI(0, Value::I64(1)),
        Instruction::PUSHARG(0),
        Instruction::LDI(1, Value::I64(0)),
        Instruction::PUSHARG(1),
        Instruction::CALL("ClientStore.take_share".to_string()),
        Instruction::MOV(17, 0),
        Instruction::MUL(18, 16, 17),
        Instruction::MOV(0, 18),
        Instruction::RET(0),
    ]
}

/// Serialize the program into the bytecode blob a client submits.
fn build_client_mul_bytecode() -> Vec<u8> {
    let function = VMFunction::new(
        ENTRY.to_string(),
        vec![],
        Vec::new(),
        None,
        CLIENT_PROGRAM_REGISTERS,
        build_client_mul_program(),
        HashMap::new(),
    );
    let binary = CompiledBinary::from_vm_functions(&[function]);
    let mut buffer = Vec::new();
    binary
        .serialize(&mut buffer)
        .expect("serialize client_mul bytecode");
    buffer
}

/// One party's runnable state: its VM (async-locked so MPC operations can yield
/// to the scheduler across awaits) and its async-capable MPC engine.
struct Party {
    vm: Arc<tokio::sync::Mutex<VirtualMachine>>,
    engine: Arc<HbEngine>,
}

/// Host committee runner: loads the submitted program by hash from the
/// content-addressed cache and runs it across the committee concurrently via
/// the async MPC scheduler (the production-preferred path).
struct Committee {
    parties: Vec<Party>,
    invocations: AtomicU64,
}

#[async_trait]
impl CommitteeRunner for Committee {
    async fn run_program(&self, outcome: &SubmissionOutcome) -> Result<Vec<u8>, String> {
        self.invocations.fetch_add(1, Ordering::SeqCst);

        // Load the program BY HASH from the program_sync cache — this is the
        // "committee syncs by hash" step. Every party reads the same path.
        let path = program_path(&outcome.job_id);
        let functions = {
            let mut file =
                File::open(&path).map_err(|e| format!("open synced program {path:?}: {e}"))?;
            let compiled = CompiledBinary::deserialize(&mut file)
                .map_err(|e| format!("deserialize synced program: {e:?}"))?;
            compiled
                .try_to_vm_functions()
                .map_err(|e| format!("resolve vm functions: {e:?}"))?
        };
        assert_eq!(
            outcome.entry, ENTRY,
            "entry function must round-trip through the submission wire"
        );

        // Register the program on every party.
        for party in &self.parties {
            let mut vm = party.vm.lock().await;
            for function in &functions {
                vm.register_function(function.clone());
            }
        }

        // Run all parties concurrently through the async MPC scheduler. Secret
        // operations yield to the runtime instead of blocking a sync bridge, so
        // the committee progresses naturally; HoneyBadger still requires every
        // party to run at once, satisfied by the per-party spawned tasks.
        let handles: Vec<_> = self
            .parties
            .iter()
            .enumerate()
            .map(|(pid, party)| {
                let vm = party.vm.clone();
                let engine = party.engine.clone();
                tokio::spawn(async move {
                    let mut vm = vm.lock().await;
                    vm.execute_async(ENTRY, engine.as_ref())
                        .await
                        .map_err(|e| format!("VM execution failed at party {pid}: {e}"))
                })
            })
            .collect();

        let joined =
            tokio::time::timeout(Duration::from_secs(120), futures::future::join_all(handles))
                .await
                .map_err(|_| "timed out waiting for committee VM execution".to_string())?;

        // Every party must reveal the same clear result.
        let mut results = Vec::new();
        for res in joined {
            let value = res.map_err(|e| format!("join error: {e:?}"))??;
            results.push(value);
        }
        let product = match results.first() {
            Some(Value::I64(v)) => *v,
            other => return Err(format!("unexpected committee result: {other:?}")),
        };
        for value in &results {
            match value {
                Value::I64(v) => assert_eq!(
                    *v, product,
                    "all parties must reveal the same committee result"
                ),
                other => return Err(format!("non-i64 committee result: {other:?}")),
            }
        }
        info!("committee revealed result: {product}");
        Ok(product.to_le_bytes().to_vec())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn submission_endpoint_runs_committee_and_rejects_tampered_program() {
    init_crypto_provider();
    setup_test_tracing();
    let _hb_itest_lock = acquire_hb_itest_lock().await;
    let _cache = scoped_cache();

    info!("=== W4: program submission endpoint end-to-end ===");

    // --- The program a client will submit. ---
    let program_bytecode = build_client_mul_bytecode();

    // Committee shape and preprocessing demand derived from the program (one
    // secret multiplication → 3 triples, 2 + 2*3 random shares, mirroring
    // vm_mesh_integration). Use the same n=5, t=1 topology vm_mesh proves
    // stable; HoneyBadger requires n >= 3*threshold + 1.
    let n_parties = 5;
    let threshold = 1;
    let n_triples = 3;
    let n_random_shares = 2 + 2 * n_triples;
    let instance_id = 88881;
    let base_port = 12300;
    let config = HoneyBadgerQuicConfig {
        mpc_timeout: Duration::from_secs(90),
        connection_retry_delay: Duration::from_millis(100),
        ..Default::default()
    };

    let client_ids: Vec<ClientId> = vec![0, 1];
    let client_scalar_inputs = [15u64, 25u64];
    let client_inputs: Vec<Vec<Fr>> = client_scalar_inputs
        .iter()
        .map(|v| vec![Fr::from(*v)])
        .collect();
    let expected_product = (client_scalar_inputs[0] * client_scalar_inputs[1]) as i64;

    // --- Bring up the HB committee and client inputs (existing path). ---
    info!("setting up {n_parties}-party HB committee");
    let (mut servers, mut recv) = setup_honeybadger_quic_network::<Fr>(
        n_parties,
        threshold,
        n_triples,
        n_random_shares,
        instance_id,
        base_port,
        config.clone(),
        None,
    )
    .await
    .expect("create HB servers");

    let server_addresses: Vec<SocketAddr> = (0..n_parties)
        .map(|i| {
            format!("127.0.0.1:{}", base_port + i as u16)
                .parse()
                .unwrap()
        })
        .collect();

    for server in servers.iter_mut() {
        server.start().await.expect("start server");
    }
    for server in &mut servers {
        server.connect_to_peers().await.expect("connect peers");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    for server in servers.iter_mut() {
        server.expected_client_ids = client_ids.clone();
    }
    for server in servers.iter_mut() {
        let pid = server.finalize_network().expect("finalize network");
        server.spawn_server_receive_loops();
        info!("server finalized party_id={pid}");
    }

    // Spawn the message-dispatch receive loops.
    for (i, server) in servers.iter().enumerate() {
        let mut node = server.node.clone();
        let network: Arc<RoutedNetwork> = server
            .routed_network
            .clone()
            .expect("routed_network set after finalize");
        let open_message_router = server.open_message_router.clone();
        let mut rx = recv.remove(0);
        tokio::spawn(async move {
            while let Some((sender_id, raw_msg)) = rx.recv().await {
                match open_message_router.try_handle_wire_message(sender_id, &raw_msg) {
                    Ok(true) => continue,
                    Err(e) => {
                        tracing::warn!("node {i} open wire message: {e}");
                        continue;
                    }
                    Ok(false) => {}
                }
                match open_message_router.try_handle_hb_open_exp_wire_message(sender_id, &raw_msg) {
                    Ok(true) => continue,
                    Err(e) => {
                        tracing::warn!("node {i} open_exp wire message: {e}");
                        continue;
                    }
                    Ok(false) => {}
                }
                if let Err(e) = node.process(sender_id, raw_msg, network.clone()).await {
                    tracing::error!("node {i} process: {e:?}");
                }
            }
        });
    }

    // Clients submit their secret shares through the standard HB input protocol.
    let mut clients = setup_honeybadger_quic_clients::<Fr>(
        client_ids.clone(),
        server_addresses,
        n_parties,
        threshold,
        instance_id,
        client_inputs,
        1,
        config.clone(),
    )
    .await
    .expect("create HB clients");
    for client in &mut clients {
        client.connect_to_servers().await.expect("client connect");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assign_topological_client_ids(&mut clients)
        .await
        .expect("assign topological client ids");
    register_topological_client_connections(&servers);

    // Preprocessing.
    info!("running preprocessing");
    let preprocessing_handles: Vec<_> = servers
        .iter()
        .map(|server| {
            let mut node = server.node.clone();
            let network: Arc<RoutedNetwork> = server
                .routed_network
                .clone()
                .expect("routed_network set after finalize");
            tokio::spawn(async move {
                let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
                node.run_preprocessing(network, &mut rng)
                    .await
                    .expect("preprocessing");
            })
        })
        .collect();
    futures::future::join_all(preprocessing_handles).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Initialize the HB input protocol so client stores hydrate from real shares.
    for server in servers.iter_mut() {
        for client_id in &client_ids {
            let local_shares = server
                .node
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(1)
                .expect("take random shares for input");
            server
                .node
                .preprocess
                .input
                .init(
                    *client_id,
                    local_shares,
                    1,
                    server
                        .routed_network
                        .clone()
                        .expect("routed_network set after finalize"),
                )
                .await
                .expect("input.init");
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Build one Party (VM + async engine) per committee member, then hydrate
    // client stores from the HB input protocol (existing path).
    let mut parties: Vec<Party> = Vec::new();
    for server in servers.iter() {
        let sorted_pid = server.party_id.expect("party_id set after finalize");
        let mut vm = VirtualMachine::new();
        let engine = HoneyBadgerMpcEngine::<Fr, ark_bls12_381::G1Projective>::try_from_existing_node_with_router(
            server.open_message_router.clone(),
            instance_id,
            sorted_pid,
            n_parties,
            threshold,
            server.network.clone().expect("network set"),
            server.node.clone(),
        )
        .expect("engine topology valid");
        vm.set_mpc_engine(engine.clone());
        parties.push(Party {
            vm: Arc::new(tokio::sync::Mutex::new(vm)),
            engine,
        });
    }
    for (party_id, party) in parties.iter().enumerate() {
        let shares_for_party: Vec<(ClientId, Vec<RobustShare<Fr>>)> = {
            let input_store = servers[party_id]
                .node
                .preprocess
                .input
                .wait_for_all_inputs(Duration::from_secs(90))
                .await
                .expect("client inputs");
            input_store
                .iter()
                .map(|(client, shares)| (*client, shares.clone()))
                .collect()
        };
        let vm = party.vm.lock().await;
        vm.try_replace_client_inputs(shares_for_party)
            .expect("hydrate VM client store");
    }

    // --- The submission endpoint: a node accepts external submissions and
    //     dispatches them to the committee runner. ---
    let committee = Arc::new(Committee {
        parties,
        invocations: AtomicU64::new(0),
    });
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind submission endpoint");
    let submission_addr = listener.local_addr().expect("submission local addr");
    let server_task = tokio::spawn(serve_submission_tcp(listener, committee.clone()));

    // (1) Valid submission: client submits the bytecode; the committee syncs by
    //     hash and runs; the result is returned over the wire.
    info!("submitting valid program to endpoint {submission_addr}");
    let (outcome, result_bytes) = submit_tcp(
        submission_addr,
        SubmissionRequest::new(program_bytecode.clone(), ENTRY),
    )
    .await
    .expect("valid submission returns a result");

    // The job id is the program's blake3 id, and the program is now cached by hash.
    let expected_id = crate::net::program_id_from_bytes(&program_bytecode);
    assert_eq!(
        outcome.job_id, expected_id,
        "job id must be the blake3 program id"
    );
    assert!(
        program_path(&expected_id).exists(),
        "program cached by hash"
    );
    let revealed = i64::from_le_bytes(result_bytes.try_into().expect("i64 result"));
    assert_eq!(
        revealed, expected_product,
        "committee result must equal client[0] * client[1]"
    );
    assert_eq!(
        committee.invocations.load(Ordering::SeqCst),
        1,
        "valid submission runs the committee exactly once"
    );

    // (2) Tampered submission: the client claims a program id that does NOT
    //     match the bytecode's blake3 id. The node must reject it before any
    //     committee run.
    info!("submitting tampered program (wrong claimed id)");
    let wrong_claim = match expected_id {
        [first, rest @ ..] => {
            let mut c = [first ^ 0xff; 32];
            c[1..].copy_from_slice(&rest);
            c
        }
    };
    assert_ne!(wrong_claim, expected_id);
    let tampered_req = SubmissionRequest::new(program_bytecode.clone(), ENTRY)
        .with_claimed_program_id(wrong_claim);
    let err = submit_tcp(submission_addr, tampered_req)
        .await
        .expect_err("tampered submission must be rejected");
    assert_eq!(
        err.code(),
        crate::net::submission::SubmissionErrorCode::ProgramTampered,
        "tampered program must be rejected as ProgramTampered"
    );

    // Also verify the in-process entrypoint path rejects a tampered request
    // without invoking the runner (defence-in-depth: the wire layer is a thin
    // wrapper over `handle_submission`).
    let before = committee.invocations.load(Ordering::SeqCst);
    let in_proc_err = handle_submission(
        &SubmissionRequest::new(program_bytecode, ENTRY).with_claimed_program_id(wrong_claim),
        committee.as_ref(),
    )
    .await
    .expect_err("in-process tampered submission must be rejected");
    assert_eq!(
        in_proc_err.code(),
        crate::net::submission::SubmissionErrorCode::ProgramTampered
    );
    assert_eq!(
        committee.invocations.load(Ordering::SeqCst),
        before,
        "a tampered submission must never reach the committee runner"
    );

    info!("=== W4 program submission endpoint test PASSED ===");

    server_task.abort();
    for mut server in servers {
        server.stop().await;
    }
    for client in clients {
        let _ = client.stop().await;
    }
}
