// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! A start against a chain node that answers over real HTTP.

use super::*;
use crate::{
    dir::Inventory,
    launch::{Availability, Network, Prover},
};
use alloy_primitives::{Bytes, B256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolValue};
use e3_crypto::Cipher;
use e3_entrypoint::fence::ProcessFence;
use e3_evm_contracts::{IBondingRegistry, INodeReleaseRegistry};
use e3_zk_prover::BBPath;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const INTERFOLD: Address = Address::repeat_byte(1);
const REGISTRY: Address = Address::repeat_byte(2);
const BONDING: Address = Address::repeat_byte(3);
const RELEASE_REGISTRY: Address = Address::repeat_byte(4);
const RANDOMNESS: Address = Address::repeat_byte(5);
const SLASHING: Address = Address::repeat_byte(6);

/// What the chain node says, and how many requests it fails first.
struct FakeChain {
    id: u64,
    bonding: Address,
    registry: Address,
    randomness: Address,
    fail_first: AtomicUsize,
    answered: Mutex<BTreeMap<String, usize>>,
}

impl Default for FakeChain {
    fn default() -> Self {
        Self {
            id: 31337,
            bonding: BONDING,
            registry: REGISTRY,
            randomness: RANDOMNESS,
            fail_first: AtomicUsize::new(0),
            answered: Mutex::default(),
        }
    }
}

impl FakeChain {
    fn answer(&self, method: &str, params: &Value) -> Value {
        match method {
            "eth_chainId" => json!(format!("{:#x}", self.id)),
            "eth_call" => {
                let call = &params[0];
                let input = call["input"].as_str().or(call["data"].as_str()).unwrap();
                let input: Bytes = input.parse().unwrap();
                let word = |value: Vec<u8>| json!(format!("0x{}", alloy::hex::encode(value)));
                let selector: [u8; 4] = input[..4].try_into().unwrap();
                let release = e3_ciphernode_config::current_node_release();
                word(match selector {
                    IInterfold::bondingRegistryCall::SELECTOR => self.bonding.abi_encode(),
                    IInterfold::ciphernodeRegistryCall::SELECTOR => self.registry.abi_encode(),
                    IInterfold::slashingManagerCall::SELECTOR => SLASHING.abi_encode(),
                    ICiphernodeRegistry::randomnessProviderCall::SELECTOR => {
                        self.randomness.abi_encode()
                    }
                    IInterfold::nodeReleaseRegistryCall::SELECTOR => RELEASE_REGISTRY.abi_encode(),
                    INodeReleaseRegistry::requiredProtocolVersionCall::SELECTOR => {
                        release.protocol_version.abi_encode()
                    }
                    INodeReleaseRegistry::requiredNodeGenerationCall::SELECTOR => {
                        release.node_generation.abi_encode()
                    }
                    INodeReleaseRegistry::operatorNodeReleaseCall::SELECTOR => {
                        INodeReleaseRegistry::OperatorNodeRelease {
                            releaseId: B256::ZERO,
                            protocolVersion: 0,
                            nodeGeneration: 0,
                        }
                        .abi_encode()
                    }
                    IBondingRegistry::isRegisteredCall::SELECTOR
                    | IBondingRegistry::isActiveCall::SELECTOR => false.abi_encode(),
                    other => panic!("no answer for selector {other:?}"),
                })
            }
            other => panic!("no answer for {other}"),
        }
    }

    fn reads_of(&self, method: &str) -> usize {
        let answered = self.answered.lock().unwrap();
        answered.get(method).copied().unwrap_or_default()
    }
}

/// Answers one HTTP connection's JSON-RPC requests until it closes.
async fn serve(mut socket: TcpStream, chain: Arc<FakeChain>) {
    let mut request = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let (head, length) = loop {
            let text = String::from_utf8_lossy(&request).into_owned();
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text[..end]
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                break (end + 4, length);
            }
            match socket.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(read) => request.extend_from_slice(&buffer[..read]),
            }
        };
        while request.len() < head + length {
            match socket.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(read) => request.extend_from_slice(&buffer[..read]),
            }
        }
        let body: Value = serde_json::from_slice(&request[head..head + length]).unwrap();
        request.drain(..head + length);
        let response = if chain.fail_first.load(Ordering::SeqCst) > 0 {
            chain.fail_first.fetch_sub(1, Ordering::SeqCst);
            "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n".to_string()
        } else {
            let method = body["method"].as_str().unwrap();
            *chain
                .answered
                .lock()
                .unwrap()
                .entry(method.to_string())
                .or_default() += 1;
            let result = chain.answer(method, &body["params"]);
            let answer = json!({"jsonrpc": "2.0", "id": body["id"], "result": result}).to_string();
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{answer}",
                answer.len()
            )
        };
        if socket.write_all(response.as_bytes()).await.is_err() {
            return;
        }
    }
}

async fn chain_node(chain: Arc<FakeChain>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(serve(socket, chain.clone()));
        }
    });
    url
}

async fn config(url: String, dir: &Path) -> Config {
    Config {
        rpc_url: url,
        rpc_auth: None,
        chain_id: Some(31337),
        interfold: INTERFOLD,
        registry: REGISTRY,
        bonding: BONDING,
        start_block: 0,
        confirmations: 0,
        max_log_range: 100,
        poll_interval: Duration::from_millis(50),
        startup_timeout: Duration::from_secs(30),
        availability: Availability::Http("http://127.0.0.1:1".to_string()),
        data_dir: dir.join("node"),
        inventory: Inventory::beside(&dir.join("key")),
        fence: ProcessFence::acquire_at(&dir.join("lock"), "test").unwrap(),
        operator: PrivateKeySigner::random(),
        cipher: Cipher::from_password("node").await.unwrap(),
        proving: Proving::Placeholder,
        reserved_threads: 1,
        network: Network {
            id: "test".to_string(),
            identity: [1; 32],
            deployment: "local".to_string(),
            listen: Vec::new(),
            peers: Vec::new(),
        },
        status_port: None,
    }
}

async fn refusal_of(chain: FakeChain, change: impl FnOnce(&mut Config)) -> anyhow::Error {
    let dir = tempfile::tempdir().unwrap();
    let url = chain_node(Arc::new(chain)).await;
    let mut config = config(url, dir.path()).await;
    change(&mut config);
    match verify(config).await {
        Ok(_) => panic!("the configuration should be refused"),
        Err(refusal) => refusal,
    }
}

#[tokio::test]
async fn a_chain_that_fits_is_verified() {
    let dir = tempfile::tempdir().unwrap();
    let url = chain_node(Arc::default()).await;
    let config = config(url, dir.path()).await;
    let operator = config.operator.address();
    let verified = verify(config).await.unwrap();
    assert_eq!(verified.contracts.randomness, BTreeSet::from([RANDOMNESS]));
    assert_eq!(verified.contracts.slashing, BTreeSet::from([SLASHING]));
    assert!(matches!(verified.standing, Standing::Unacknowledged(_)));
    let identity = Identity {
        chain_id: 31337,
        interfold: INTERFOLD,
        operator,
    };
    assert!(matches!(
        NodeDir::new(dir.path().join("node")).state(Some(&identity)),
        crate::dir::State::Current(_)
    ));
}

/// One failed RPC read at launch is not a reason to stop.
#[tokio::test]
async fn a_chain_node_that_is_not_ready_yet_is_waited_for() {
    let dir = tempfile::tempdir().unwrap();
    let chain = Arc::new(FakeChain {
        fail_first: AtomicUsize::new(3),
        ..Default::default()
    });
    let url = chain_node(chain.clone()).await;
    verify(config(url, dir.path()).await).await.unwrap();
    assert_eq!(chain.fail_first.load(Ordering::SeqCst), 0);
    assert!(chain.reads_of("eth_chainId") > 0);
    let list = Inventory::beside(&dir.path().join("key"));
    assert_eq!(list.read().folders, [dir.path().join("node")]);
}

#[tokio::test(start_paused = true)]
async fn a_chain_node_that_never_answers_ends_the_start_at_its_deadline() {
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", silent.local_addr().unwrap());
    let dir = tempfile::tempdir().unwrap();
    let Err(refusal) = verify(config(url, dir.path()).await).await else {
        panic!("nothing answered");
    };
    assert!(
        matches!(
            refusal.downcast_ref(),
            Some(Refused::TimedOut {
                what: "reading the contracts",
                ..
            })
        ),
        "{refusal}"
    );
    // A folder that never held anything must not read later as a volume that is not mounted.
    let list = Inventory::beside(&dir.path().join("key"));
    assert!(list.read().folders.is_empty());
}

#[tokio::test]
async fn another_chain_behind_the_rpc_url_is_refused() {
    let chain = FakeChain {
        id: 1,
        ..Default::default()
    };
    let refusal = refusal_of(chain, |_| {}).await;
    assert!(
        matches!(
            refusal.downcast_ref(),
            Some(Refused::WrongChain {
                configured: 31337,
                actual: 1
            })
        ),
        "{refusal}"
    );
}

#[tokio::test]
async fn a_chain_without_the_release_s_randomness_is_refused() {
    let chain = FakeChain {
        id: 42_161,
        ..Default::default()
    };
    let refusal = refusal_of(chain, |config| config.chain_id = None).await;
    assert!(
        matches!(
            refusal.downcast_ref(),
            Some(Refused::UnsupportedChain(42_161))
        ),
        "{refusal}"
    );
}

#[tokio::test]
async fn addresses_interfold_does_not_use_are_refused() {
    for chain in [
        FakeChain {
            bonding: Address::repeat_byte(9),
            ..Default::default()
        },
        FakeChain {
            registry: Address::repeat_byte(9),
            ..Default::default()
        },
    ] {
        let refusal = refusal_of(chain, |_| {}).await;
        assert!(
            matches!(refusal.downcast_ref(), Some(Refused::Miswired { .. })),
            "{refusal}"
        );
    }
}

#[tokio::test]
async fn a_registry_without_a_randomness_provider_is_refused() {
    let chain = FakeChain {
        randomness: Address::ZERO,
        ..Default::default()
    };
    let refusal = refusal_of(chain, |_| {}).await;
    assert!(
        matches!(refusal.downcast_ref(), Some(Refused::NoRandomness)),
        "{refusal}"
    );
}

type Change = Box<dyn FnOnce(&mut Config)>;

#[tokio::test]
async fn zero_durations_and_ranges_are_refused() {
    let prover = |change: fn(&mut Prover)| {
        move |config: &mut Config| {
            let mut prover = Prover {
                bb: BBPath::Custom("bb".into()),
                circuits: "circuits".into(),
                concurrent: 1,
                bb_timeout: Duration::from_secs(1),
            };
            change(&mut prover);
            config.proving = Proving::AsInstalled(prover);
        }
    };
    let changes: Vec<Change> = vec![
        Box::new(|config: &mut Config| config.poll_interval = Duration::ZERO),
        Box::new(|config: &mut Config| config.startup_timeout = Duration::ZERO),
        Box::new(|config: &mut Config| config.max_log_range = 0),
        Box::new(prover(|prover| prover.bb_timeout = Duration::ZERO)),
        Box::new(prover(|prover| prover.concurrent = 0)),
    ];
    for change in changes {
        let refusal = refusal_of(FakeChain::default(), change).await;
        assert!(
            matches!(refusal.downcast_ref(), Some(Refused::NotPositive(_))),
            "{refusal}"
        );
    }
}
