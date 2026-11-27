// SPDX-License-Identifier: LGPL-3.0-only

//! One CLI request on a private Anvil chain with fixture randomness, compute and DA.
//! Committee slots, signing contexts, public-key chunks and proof receipts come from the chain.

use super::super::{runner::TimeoutEnvGuard, scenario::Preset, zk_fixture::setup_test_zk_backend};
use alloy::{
    node_bindings::Anvil,
    primitives::{keccak256, Address, Bytes, B256, U256},
    providers::{ext::AnvilApi, DynProvider, Provider, ProviderBuilder},
    rpc::types::{Filter, Log, TransactionReceipt, TransactionRequest},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolEvent, SolValue},
};
use anyhow::{ensure, Context, Result};
use e3_ciphernode_builder::{CiphernodeBuilder, CiphernodeHandle};
use e3_ciphernode_config::NetworkProfile;
use e3_committee::CiphernodesCommitteeSize::Minimum;
use e3_crypto::Cipher;
use e3_event_system::EventSystem;
use e3_events::{prelude::*, E3id, EventType, InterfoldEventData, StoreKeys};
use e3_evm::ICiphernodeRegistry;
use e3_evm_config::{
    ChainConfig, Contract, ContractAddresses, DataAvailabilityConfig, DataAvailabilityMode,
};
use e3_fhe_params::{decode_bfv_params_arc, BfvProfile};
use e3_multithread::Multithread;
use e3_sdk::evm::contracts::{E3Stage, Interfold};
use e3_test_support::{derive_shared_rng, with_tracing, BenchmarkInstant};
use e3_zk_config::output_layout::DecryptionAggregatorLayout;
use fhe::bfv::Ciphertext;
use fhe_traits::{DeserializeParametrized, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    time::{sleep, timeout},
};

sol! {
    #[sol(rpc)]
    interface Routes {
        function setDecryptionVerifier(bytes32 scheme, address next) external;
        function getDecryptionVerifier(bytes32 scheme) external view returns (address);
    }
}

const CHAIN_ID: u64 = 31337;
const POLL: Duration = Duration::from_millis(200);

async fn start_node(
    builder: CiphernodeBuilder,
    signer: PrivateKeySigner,
    cipher: &Cipher,
    config: &ChainConfig,
    work: &Path,
    peers: &mut Vec<String>,
) -> Result<CiphernodeHandle> {
    let directory = work.join(signer.address().to_string());
    fs::create_dir(&directory)?;
    let (log, kv) = (directory.join("log"), directory.join("kv"));
    // Seed the same encrypted wallet pair the node CLI creates, before opening the fresh stores.
    let mut key = signer.to_bytes().to_vec();
    let network_key =
        libp2p::identity::Keypair::ed25519_from_bytes(key.clone())?.try_into_ed25519()?;
    EventSystem::persisted(log.clone(), kv.clone())
        .store()?
        .write_batch_sync([
            (StoreKeys::eth_private_key(), cipher.encrypt_data(&mut key)?),
            (
                StoreKeys::libp2p_keypair(),
                cipher.encrypt_data(&mut network_key.to_bytes().to_vec())?,
            ),
        ])
        .await?;
    let port = std::net::UdpSocket::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port();
    let node = builder
        .with_persistence(&log, &kv)
        .with_chains(std::slice::from_ref(config))
        .with_signer(signer)
        .with_network(NetworkProfile::local(), peers.clone(), port)
        .build()
        .await?;
    peers.push(format!(
        "/ip4/127.0.0.1/udp/{port}/quic-v1/p2p/{}",
        node.peer_id
    ));
    Ok(node)
}

async fn hardhat(
    root: &Path,
    work: &Path,
    rpc: &str,
    profile: BfvProfile,
    args: &[&str],
) -> Result<String> {
    let out = Command::new("pnpm")
        .current_dir(root.join("packages/interfold-contracts"))
        .args([
            "exec",
            "hardhat",
            "--config",
            "hardhat.benchmark.config.ts",
            "--network",
            "benchmark",
        ])
        .args(args)
        .env("E3_BENCHMARK_RPC", rpc)
        .env("E3_BENCHMARK_PROFILE", profile.name())
        .env("E3_BENCHMARK_DEPLOYMENTS", work.join("deployments.json"))
        .env("E3_BENCHMARK_IGNITION", work.join("ignition"))
        .kill_on_drop(true)
        .output()
        .await?;
    ensure!(
        out.status.success(),
        "Hardhat {args:?}: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?)
}

async fn mock_da(root: &Path, work: &Path) -> Result<(Child, DataAvailabilityConfig)> {
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port();
    let mut child = Command::new("node")
        .arg(root.join("tests/integration/lib/mock-data-availability.mjs"))
        .env("DATA_AVAILABILITY_DIRECTORY", work)
        .env("PORT", port.to_string())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let stdout = child.stdout.take().context("DA stdout missing")?;
    let ready = timeout(
        Duration::from_secs(15),
        BufReader::new(stdout).lines().next_line(),
    )
    .await??;
    ensure!(ready.is_some(), "DA fixture exited before listening");
    Ok((
        child,
        DataAvailabilityConfig {
            mode: DataAvailabilityMode::MockHttp,
            rpc_url: format!("http://127.0.0.1:{port}/availability"),
        },
    ))
}

async fn receipt(provider: &DynProvider, tx: B256) -> Result<TransactionReceipt> {
    let receipt = provider
        .get_transaction_receipt(tx)
        .await?
        .context("missing mined receipt")?;
    ensure!(receipt.status(), "transaction {tx} reverted");
    Ok(receipt)
}

/// Observe the matching mined event without including node indexing or post-receipt assertions in the clock.
async fn until_log<E: SolEvent>(
    provider: &DynProvider,
    address: Address,
    id: U256,
    mut from: u64,
    mut accept: impl FnMut(&E) -> bool,
) -> Result<(E, Log)> {
    let filter = Filter::new()
        .address(address)
        .event_signature(E::SIGNATURE_HASH)
        .topic1(B256::from(id));
    loop {
        let head = provider.get_block_number().await?;
        if head >= from {
            for log in provider
                .get_logs(&filter.clone().from_block(from).to_block(head))
                .await?
            {
                let event = log.log_decode::<E>()?.inner.data;
                if accept(&event) {
                    return Ok((event, log));
                }
            }
            from = head + 1;
        }
        sleep(POLL).await;
    }
}

/// Replay the exact successful verifier subcall as a standalone estimate after stopping the timer.
async fn verifier_gas(
    provider: &DynProvider,
    tx: B256,
    verifier: Address,
    signature: &str,
) -> Result<u64> {
    let trace: Value = provider
        .client()
        .request(
            "debug_traceTransaction",
            (tx, json!({"tracer":"callTracer"})),
        )
        .await?;
    let selector = &keccak256(signature).to_string()[..10];
    let mut frames = vec![&trace];
    while let Some(frame) = frames.pop() {
        if frame["to"]
            .as_str()
            .is_some_and(|addr| addr.eq_ignore_ascii_case(&verifier.to_string()))
            && frame["input"]
                .as_str()
                .is_some_and(|input| input.starts_with(selector))
        {
            ensure!(frame["error"].is_null(), "mined verifier call failed");
            let input: Bytes = serde_json::from_value(frame["input"].clone())?;
            return Ok(provider
                .estimate_gas(
                    TransactionRequest::default()
                        .to(verifier)
                        .input(input.into()),
                )
                .await?);
        }
        if let Some(calls) = frame["calls"].as_array() {
            frames.extend(calls);
        }
    }
    anyhow::bail!("no {signature} call to frozen verifier {verifier} in {tx}")
}

fn check_finalization(stage: u8) -> Result<()> {
    // A live node can publish the key before this read. Only this driver submits ciphertext.
    let stage = E3Stage::try_from(stage)?;
    ensure!(
        matches!(stage, E3Stage::CommitteeFinalized | E3Stage::KeyPublished),
        "unexpected stage after committee finalization: {stage:?}"
    );
    Ok(())
}

fn write_receipt(path: &Path, record: &Value) -> Result<()> {
    let temp = tempfile::NamedTempFile::new_in(path.parent().context("missing receipt parent")?)?;
    serde_json::to_writer_pretty(temp.as_file(), record)?;
    temp.as_file().sync_all()?;
    temp.persist(path)?;
    Ok(())
}

async fn save_receipt_with_estimates(
    path: &Path,
    mut record: Value,
    estimates: [(&str, impl std::future::Future<Output = Result<u64>>); 2],
) -> Result<()> {
    write_receipt(path, &record)?;
    let mut result = Ok(());
    for (field, estimate) in estimates {
        match estimate.await {
            Ok(gas) => record[field] = gas.into(),
            Err(error) => {
                record[field] = Value::Null;
                record[format!("{field}_error")] = format!("{error:#}").into();
                result = Err(error.context(field.to_owned()));
            }
        }
        write_receipt(path, &record)?;
    }
    println!("{record}");
    result
}

pub async fn run() -> Result<()> {
    let _tracing = with_tracing("info");
    let preset = Preset::from_mode(&std::env::var("BENCHMARK_MODE")?)?;
    let _timeouts = TimeoutEnvGuard::set(preset.collection_timeouts_secs(false));
    let profile = match preset {
        Preset::Insecure => BfvProfile::SsInsecure64,
        Preset::Secure => BfvProfile::SsSecure8192,
    };
    let jobs: usize = std::env::var("BENCHMARK_MULTITHREAD_JOBS")?.parse()?;
    ensure!(jobs > 0);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let work = tempfile::tempdir()?;
    let (backend, _artifacts) = setup_test_zk_backend(profile.threshold_preset(), Minimum).await?;
    let anvil = Anvil::new().chain_id(CHAIN_ID).try_spawn()?;
    let rpc = format!("http://127.0.0.1:{}", anvil.port());
    let signer = |i: usize| PrivateKeySigner::from_slice(&anvil.keys()[i].to_bytes());
    let provider = ProviderBuilder::new()
        .wallet(signer(0)?)
        .connect_http(anvil.endpoint_url())
        .erased();
    hardhat(
        &root,
        work.path(),
        &rpc,
        profile,
        &["run", "--no-compile", "scripts/deploySsBenchmark.ts"],
    )
    .await?;
    let deployments: Value =
        serde_json::from_slice(&fs::read(work.path().join("deployments.json"))?)?;
    let address = |name: &str| -> Result<Address> {
        Ok(serde_json::from_value(
            deployments["benchmark"][name]["address"].clone(),
        )?)
    };
    let contract =
        |name: &str| -> Result<Contract> { Ok(Contract::AddressOnly(address(name)?.to_string())) };
    let controller = address("Interfold")?;
    let registry = address("CiphernodeRegistryOwnable")?;
    let pk = address("BfvPkVerifier")?;
    let dec = address("BfvDecryptionVerifier")?;
    let future = address("MockDecryptionVerifier")?;
    let (_http, da) = mock_da(&root, work.path()).await?;
    let config = ChainConfig {
        enabled: Some(true),
        name: "benchmark".into(),
        chain_id: Some(CHAIN_ID),
        rpc_url: anvil.ws_endpoint(),
        rpc_auth: Default::default(),
        contracts: ContractAddresses {
            interfold: contract("Interfold")?,
            ciphernode_registry: contract("CiphernodeRegistryOwnable")?,
            bonding_registry: contract("BondingRegistry")?,
            e3_program: None,
            fee_token: None,
            slashing_manager: Some(contract("SlashingManager")?),
            dkg_fold_attestation_verifier: Some(contract("DkgFoldAttestationVerifier")?),
            faucet: None,
        },
        finalization_ms: Some(0),
        ingestion_confirmations: Some(0),
        rpc_poll_interval_ms: Some(250),
        rpc_log_range_blocks: None,
        data_availability: Some(da),
    };
    let pool = Multithread::create_taskpool(Multithread::get_max_threads_minus(2), jobs);
    let cipher = Arc::new(Cipher::from_password("private benchmark").await?);
    // The full nodes require a peer that can serve the chain's history during startup.
    let mut peers = Vec::new();
    let _seed = start_node(
        CiphernodeBuilder::bootstrap(derive_shared_rng(42, 1), cipher.clone()),
        signer(1)?,
        &cipher,
        &config,
        work.path(),
        &mut peers,
    )
    .await?;
    let mut nodes = Vec::new();
    for i in 2..5 {
        let builder = CiphernodeBuilder::full(
            derive_shared_rng(42, i as u64),
            cipher.clone(),
            backend.clone(),
        )
        .with_shared_taskpool(&pool)
        .with_multithread_concurrent_jobs(jobs);
        nodes.push(
            start_node(
                builder,
                signer(i)?,
                &cipher,
                &config,
                work.path(),
                &mut peers,
            )
            .await?,
        );
    }
    let confirmed_key = nodes[0].bus().wait_for(EventType::CommitteePublished);
    // Keep accelerated windows inside the nodes' clock-drift allowance even for a long proof.
    provider.anvil_set_block_timestamp_interval(1).await?;
    provider.evm_mine(None).await?;
    let now = provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await?
        .context("missing chain head")?
        .header
        .timestamp;
    let invoked = BenchmarkInstant::now();
    let stdout = hardhat(
        &root,
        work.path(),
        &rpc,
        profile,
        &[
            "committee:new",
            "--committee-size",
            "0",
            "--profile",
            profile.name(),
            "--input-window-start",
            &(now + 30).to_string(),
            "--input-window-end",
            &(now + 180).to_string(),
        ],
    )
    .await?;
    println!("{stdout}");
    let value = |prefix: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .with_context(|| format!("committee:new omitted {prefix}"))
    };
    let submitted = invoked.child_hrtime(value("REQUEST_SUBMITTED_NS=").ok());
    let id: U256 = value("E3_ID=")?.parse()?;
    let request = receipt(&provider, value("REQUEST_TX=")?.parse()?).await?;
    let e3 = request
        .logs()
        .iter()
        .filter(|l| l.address() == controller)
        .find_map(|l| l.log_decode::<Interfold::E3Requested>().ok())
        .context("missing E3Requested")?
        .inner
        .data;
    ensure!(
        e3.e3Id == id
            && e3.cryptoConfigId == profile.crypto_config_id(Minimum)?
            && e3.e3.pkVerifier == pk
            && e3.e3.decryptionVerifier == dec
            && e3.e3.committeeSize == 0,
        "CLI request did not freeze the SS Minimum routes"
    );
    let from = request.block_number.context("unmined request")?;
    let routes = Routes::new(controller, &provider);
    ensure!(
        future != dec
            && routes
                .setDecryptionVerifier(e3.e3.encryptionSchemeId, future)
                .send()
                .await?
                .get_receipt()
                .await?
                .status()
    );
    let r = ICiphernodeRegistry::new(registry, &provider);
    let lifecycle = Interfold::new(controller, &provider);
    let mut ticket_holders = HashSet::new();
    timeout(
        Duration::from_secs(55),
        until_log::<ICiphernodeRegistry::TicketSubmitted>(
            &provider,
            registry,
            id,
            from,
            |ticket| {
                ticket_holders.insert(ticket.node);
                ticket_holders.len() == nodes.len()
            },
        ),
    )
    .await
    .context("three live nodes did not submit their tickets")??;
    let deadline: u64 = r.getCommitteeDeadline(id).call().await?.try_into()?;
    provider
        .anvil_set_next_block_timestamp(deadline + 1)
        .await?;
    provider.evm_mine(None).await?;
    if lifecycle.getE3Stage(id).call().await? == u8::from(E3Stage::Requested) {
        let finalized = r.finalizeCommittee(id).send().await;
        if let Ok(tx) = finalized {
            tx.get_receipt().await?;
        }
    }
    check_finalization(lifecycle.getE3Stage(id).call().await?)?;
    let mut committee = Vec::new();
    for slot in 0..Minimum.values().n {
        let member = r
            .canonicalCommitteeNodeAt(id, U256::from(slot))
            .call()
            .await?;
        ensure!(ticket_holders.remove(&member), "unknown canonical member");
        committee.push(member);
    }
    let (key_event, log) = timeout(
        Duration::from_secs(3600),
        until_log::<ICiphernodeRegistry::CommitteePublicKeyChunkPublished>(
            &provider,
            registry,
            id,
            from,
            |chunk| chunk.chunkIndex + 1 == chunk.chunkCount,
        ),
    )
    .await
    .context("no complete mined SS public key")??;
    let last_chunk = receipt(
        &provider,
        log.transaction_hash.context("missing chunk transaction")?,
    )
    .await?;
    let key_at = BenchmarkInstant::now();
    let InterfoldEventData::CommitteePublished(key) =
        timeout(Duration::from_secs(45), confirmed_key)
            .await??
            .into_data()
    else {
        unreachable!()
    };
    ensure!(
        key.e3_id == E3id::new(id.to_string(), CHAIN_ID)
            && keccak256(&key.public_key[..]) == key_event.candidateHash
    );
    let (proof_event, log) = until_log::<ICiphernodeRegistry::CommitteeProofPublished>(
        &provider,
        registry,
        id,
        from,
        |_| true,
    )
    .await?;
    ensure!(proof_event.pkCommitment == key_event.pkCommitment && proof_event.nodes == committee);
    let dkg = receipt(
        &provider,
        log.transaction_hash.context("missing DKG transaction")?,
    )
    .await?;

    let params = decode_bfv_params_arc(&lifecycle.paramSetRegistry(e3.e3.paramSet).call().await?)?;
    let encrypt = |n: u64| -> Result<Ciphertext> {
        let bytes = e3_bfv_client::bfv_encrypt(
            vec![n],
            key.public_key.to_vec(),
            params.degree(),
            params.plaintext(),
            params.moduli(),
        )?;
        Ok(Ciphertext::from_bytes(&bytes, &params)?)
    };
    let ct = (&encrypt(19)? + &encrypt(18)?).to_bytes();
    let hash = keccak256(&ct);
    let commitment: B256 = e3_bfv_client::compute_ct_commitment_with_params(&ct, &params)?.into();
    fs::write(work.path().join(hex::encode(hash)), &ct)?;
    provider
        .anvil_set_next_block_timestamp(e3.e3.inputWindow[1].try_into()?)
        .await?;
    provider.evm_mine(None).await?;
    let reference = Interfold::CiphertextOutputReference {
        contentHash: hash,
        ciphertextCommitment: commitment,
        computeProof: Bytes::from_static(&[1]),
        availabilityProof: ct.into(),
    };
    let ciphertext = lifecycle
        .publishCiphertextOutput(id, reference.abi_encode().into())
        .send()
        .await?
        .get_receipt()
        .await?;
    let ciphertext_at = BenchmarkInstant::now();
    ensure!(ciphertext.status());
    let (output, log) = timeout(
        Duration::from_secs(900),
        until_log::<Interfold::PlaintextOutputPublished>(
            &provider,
            controller,
            id,
            ciphertext.block_number.context("unmined ciphertext")?,
            |_| true,
        ),
    )
    .await
    .context("no SS plaintext receipt")??;
    let plaintext = receipt(
        &provider,
        log.transaction_hash
            .context("missing plaintext transaction")?,
    )
    .await?;
    let end = BenchmarkInstant::now();
    let state = lifecycle.getE3(id).call().await?;
    ensure!(
        state.pkVerifier == pk
            && state.decryptionVerifier == dec
            && state.ciphertextCommitment == commitment
            && state.plaintextOutput == output.plaintextOutput
            && lifecycle.getE3Stage(id).call().await? == u8::from(E3Stage::Complete)
    );
    ensure!(
        routes
            .getDecryptionVerifier(e3.e3.encryptionSchemeId)
            .call()
            .await?
            == future
    );
    let coefficients = e3_bfv_client::decode_bytes_to_vec_u64(&output.plaintextOutput)?;
    ensure!(
        coefficients.first() == Some(&37) && coefficients[1..].iter().all(|&x| x == 0),
        "unexpected decrypted sum"
    );
    let (_, fields) = <(Bytes, Vec<B256>)>::abi_decode_params(&output.proof)?;
    let layout = DecryptionAggregatorLayout::current();
    let size = Minimum.values();
    ensure!(fields.len() == layout.public_inputs_length(size.threshold));
    let anchors = r.getDkgAnchors(id).call().await?;
    let mut owners = Vec::new();
    for field in &fields[layout.party_id_offset()..layout.sk_offset(size.threshold)] {
        // SS uses one-based interpolation coordinates; registry and SyncDec slots are zero-based.
        let owner = u64::try_from(U256::from_be_slice(field.as_slice()))?
            .checked_sub(1)
            .context("zero SS interpolation coordinate")?;
        ensure!(anchors.partyIds.contains(&U256::from(owner)) && !owners.contains(&owner));
        owners.push(owner);
    }
    let path = PathBuf::from(
        std::env::var_os("E3_BENCHMARK_REQUEST_OUTPUT").context("missing receipt output")?,
    );
    let record = json!({
        "profile": profile.name(),
        "committee": "minimum",
        "chain_id": CHAIN_ID,
        "controller": controller,
        "registry": registry,
        "crypto_config_id": e3.cryptoConfigId,
        "e3_id": id.to_string(),
        "canonical_committee": committee,
        "owners": owners,
        "pk_verifier": pk,
        "decryption_verifier": dec,
        "fold_attestation_verifier": address("DkgFoldAttestationVerifier")?,
        "rotated_decryption_default": future,
        "plaintext": coefficients[0],
        "ciphertext_commitment": commitment,
        "cli_invocation_to_receipt_seconds": end.seconds_since(invoked),
        "submission_to_receipt_seconds": submitted.and_then(|at| end.seconds_since(at)),
        "submission_to_published_key_seconds": submitted.and_then(|at| key_at.seconds_since(at)),
        "published_key_to_ciphertext_seconds": ciphertext_at.seconds_since(key_at),
        "ciphertext_to_plaintext_seconds": end.seconds_since(ciphertext_at),
        "request_tx": request.transaction_hash,
        "request_gas": request.gas_used,
        "dkg_tx": dkg.transaction_hash,
        "dkg_gas": dkg.gas_used,
        "last_key_chunk_tx": last_chunk.transaction_hash,
        "ciphertext_tx": ciphertext.transaction_hash,
        "ciphertext_gas": ciphertext.gas_used,
        "plaintext_tx": plaintext.transaction_hash,
        "plaintext_gas": plaintext.gas_used,
    });
    save_receipt_with_estimates(
        &path,
        record,
        [
            (
                "standalone_dkg_verifier_gas",
                verifier_gas(
                    &provider,
                    dkg.transaction_hash,
                    pk,
                    "verify(uint256,uint256,address[],bytes32,bytes32,bytes)",
                ),
            ),
            (
                "standalone_decryption_verifier_gas",
                verifier_gas(
                    &provider,
                    plaintext.transaction_hash,
                    dec,
                    "verify(uint256,bytes32,bytes32,bytes32,bytes32,bytes)",
                ),
            ),
        ],
    )
    .await
}

#[test]
fn finalization_allows_an_already_published_key_but_not_ciphertext_or_failure() {
    for stage in [E3Stage::CommitteeFinalized, E3Stage::KeyPublished] {
        assert!(check_finalization(stage.into()).is_ok());
    }
    for stage in [
        E3Stage::None,
        E3Stage::Requested,
        E3Stage::CiphertextReady,
        E3Stage::Complete,
        E3Stage::Failed,
    ] {
        assert!(check_finalization(stage.into()).is_err());
    }
    assert!(check_finalization(u8::MAX).is_err());
}

#[tokio::test]
async fn failed_estimate_preserves_the_mined_receipt_and_the_other_estimate() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("request_receipt.json");
    let mined = json!({"plaintext_tx": "mined", "submission_to_receipt_seconds": null});
    for failed in ["dkg", "dec"] {
        let initial_receipt = std::cell::OnceCell::new();
        let estimate = |field: &'static str| {
            let (path, mined, initial_receipt) = (&path, &mined, &initial_receipt);
            async move {
                let saved: Value = serde_json::from_slice(&fs::read(path)?)?;
                assert_eq!(saved["plaintext_tx"], mined["plaintext_tx"]);
                if field == "dkg" {
                    assert_eq!(&saved, mined);
                    initial_receipt.set(fs::File::open(path)?).unwrap();
                } else {
                    assert!(
                        saved.get("dkg").is_some(),
                        "DKG estimate was not saved first"
                    );
                }
                ensure!(field != failed, "RPC unavailable");
                Ok(123)
            }
        };
        let error = save_receipt_with_estimates(
            &path,
            mined.clone(),
            [("dkg", estimate("dkg")), ("dec", estimate("dec"))],
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("RPC unavailable"));
        // A reader that opened the initial receipt still sees a complete, unchanged document.
        assert_eq!(
            serde_json::from_reader::<_, Value>(initial_receipt.into_inner().unwrap())?,
            mined
        );
        let saved: Value = serde_json::from_slice(&fs::read(&path)?)?;
        assert_eq!(saved[if failed == "dkg" { "dec" } else { "dkg" }], 123);
        assert_eq!(saved.get(failed), Some(&Value::Null));
        assert_eq!(saved[format!("{failed}_error")], "RPC unavailable");
        assert_eq!(saved["plaintext_tx"], "mined");
        assert_eq!(
            saved.get("submission_to_receipt_seconds"),
            Some(&Value::Null)
        );
    }
    Ok(())
}
