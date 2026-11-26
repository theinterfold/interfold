// SPDX-License-Identifier: LGPL-3.0-only

//! Private Anvil deployment; only committee:new creates the request. Ticket submission and
//! finalization run before the signed actors consume the mined configuration and canonical slots.
use super::*;
use alloy::{providers::ext::AnvilApi, sol_types::SolEvent};
use e3_evm_contracts::IInterfold;
use e3_request::canonical_key::SynchronizedDecryptionPlan;
use std::{
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

sol! {
    #[sol(rpc)]
    interface FutureRoutes {
        function setDecryptionVerifier(bytes32 scheme,address verifier) external;
        function getDecryptionVerifier(bytes32 scheme) external view returns (address);
    }
}

pub(in super::super) struct CliRequest {
    pub id: E3id,
    pub signers: Vec<PrivateKeySigner>,
    pub registry: Address,
    pub dkg: Address,
    pub decryption: Address,
    future_decryption: Address,
    pub history: Vec<InterfoldEvent<Unsequenced>>,
    pub receipt: TransactionReceipt,
    pub submitted_ms: u64,
    pub invoked: Instant,
}

pub(super) fn wall_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

/// Observe each boundary on the host; Anvil advances its block clock across the local test windows.
pub(super) struct Publication<'a> {
    pub receipt: &'a TransactionReceipt,
    pub observed: Instant,
}

impl CliRequest {
    pub(super) fn record(
        &self,
        controller: Address,
        plan: &SynchronizedDecryptionPlan,
        value: u64,
        [key, ciphertext, plaintext]: [Publication<'_>; 3],
        receipt_ms: u64,
    ) -> Result<()> {
        let context = plan.authority().context;
        ensure!(
            plan.e3_id() == &self.id
                && context.registry == self.registry
                && context.verifying_contract == self.dkg,
            "recovered decryption plan differs from the mined request"
        );
        let submission_seconds = receipt_ms
            .checked_sub(self.submitted_ms)
            .context("local clock moved backwards")? as f64
            / 1000.0;
        let after_key = plaintext
            .observed
            .duration_since(key.observed)
            .as_secs_f64();
        let result = serde_json::json!({
            "profile": plan.profile().name(),
            "committee": plan.committee().as_str(),
            "owners": plan.designated(),
            "controller": controller,
            "registry": context.registry,
            "crypto_config_id": B256::from(context.crypto_config_id),
            "e3_id": self.id.e3_id(),
            "plaintext": value,
            "ciphertext_commitment": B256::from(plan.ciphertext_commitment()),
            "pk_verifier": self.dkg,
            "decryption_verifier": self.decryption,
            "rotated_decryption_default": self.future_decryption,
            "cli_invocation_to_receipt_seconds": plaintext.observed.duration_since(self.invoked).as_secs_f64(),
            "submission_to_receipt_seconds": submission_seconds,
            "submission_to_published_key_seconds": submission_seconds - after_key,
            "published_key_to_ciphertext_seconds": ciphertext.observed.duration_since(key.observed).as_secs_f64(),
            "ciphertext_to_plaintext_seconds": plaintext.observed.duration_since(ciphertext.observed).as_secs_f64(),
            "request_tx": self.receipt.transaction_hash, "request_gas": self.receipt.gas_used,
            "dkg_tx": key.receipt.transaction_hash, "dkg_gas": key.receipt.gas_used,
            "ciphertext_tx": ciphertext.receipt.transaction_hash, "ciphertext_gas": ciphertext.receipt.gas_used,
            "plaintext_tx": plaintext.receipt.transaction_hash, "plaintext_gas": plaintext.receipt.gas_used,
        });
        fs::write(
            std::env::var("E3_BENCHMARK_REQUEST_OUTPUT")?,
            serde_json::to_vec_pretty(&result)?,
        )?;
        println!("{result}");
        Ok(())
    }
}

impl Chain {
    pub(in super::super) async fn request(
        profile: BfvProfile,
        pair: &Path,
        work: &Path,
    ) -> Result<Self> {
        let anvil = Anvil::new().chain_id(31337).try_spawn()?;
        let signer = PrivateKeySigner::from_slice(&anvil.keys()[0].to_bytes())?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(anvil.endpoint_url())
            .erased();
        let deployments = work.join("deployments.json");
        let hardhat = || {
            let mut cmd = Command::new("pnpm");
            cmd.current_dir(package())
                .args([
                    "exec",
                    "hardhat",
                    "--config",
                    "hardhat.benchmark.config.ts",
                    "--network",
                    "benchmark",
                ])
                .env(
                    "E3_BENCHMARK_RPC",
                    format!("http://127.0.0.1:{}", anvil.port()),
                )
                .env("E3_BENCHMARK_PAIR", pair)
                .env("E3_BENCHMARK_DEPLOYMENTS", &deployments)
                .env("E3_BENCHMARK_IGNITION", work.join("ignition"));
            cmd
        };
        run(hardhat().args([
            "run",
            "--no-compile",
            "scripts/deploySynchronizedBenchmark.ts",
        ]))?;
        let doc: Value = serde_json::from_slice(&fs::read(&deployments)?)?;
        let address = |name: &str| -> Result<Address> {
            Ok(serde_json::from_value(
                doc["benchmark"][name]["address"].clone(),
            )?)
        };
        let controller = address("Interfold")?;
        let registry = address("CiphernodeRegistryOwnable")?;
        let dkg = address("SynchronizedDkgPublicationVerifier")?;
        let decryption = address("SynchronizedDecryptionVerifier")?;
        provider.anvil_increase_time(2).await?;
        provider.evm_mine(None).await?;
        let now = provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await?
            .context("missing head")?
            .header
            .timestamp;
        let invoked = Instant::now();
        let output = run(hardhat().args([
            "committee:new",
            "--committee-size",
            "0",
            "--profile",
            profile.name(),
            "--input-window-start",
            &(now + 300).to_string(),
            "--input-window-end",
            &(now + 2 * 86400).to_string(),
        ]))?;
        let stdout = String::from_utf8(output.stdout)?;
        println!("{stdout}");
        let value = |prefix: &str| {
            stdout
                .lines()
                .find_map(|line| line.strip_prefix(prefix))
                .with_context(|| format!("committee:new omitted {prefix}"))
        };
        let submitted_ms = value("REQUEST_SUBMITTED_MS=")?.parse()?;
        let receipt = provider
            .get_transaction_receipt(value("REQUEST_TX=")?.parse()?)
            .await?
            .context("missing CLI request receipt")?;
        ensure!(receipt.status());
        let log = receipt
            .logs()
            .iter()
            .find(|l| {
                l.address() == controller
                    && l.topic0() == Some(&IInterfold::E3Requested::SIGNATURE_HASH)
            })
            .context("missing request log")?;
        let event = log.log_decode::<IInterfold::E3Requested>()?.inner.data;
        let numeric = event.e3Id;
        ensure!(
            numeric == value("E3_ID=")?.parse::<U256>()?
                && event.e3.pkVerifier == dkg
                && event.e3.decryptionVerifier == decryption
        );
        let committee = e3_committee::CiphernodesCommitteeSize::try_from(event.e3.committeeSize)?;
        ensure!(
            committee == COMMITTEE
                && BfvProfile::from_crypto_config_id(
                    event.e3.paramSet,
                    committee,
                    event.cryptoConfigId
                )? == profile
        );
        let id = E3id::new(numeric.to_string(), 31337);
        let lifecycle = IInterfold::new(controller, &provider);
        let stored = lifecycle.getE3(numeric).call().await?;
        ensure!(
            stored.pkVerifier == dkg
                && stored.decryptionVerifier == decryption
                && lifecycle.e3CryptoConfigIds(numeric).call().await? == event.cryptoConfigId
        );
        // Rotate the default after the mined snapshot. Even the subsequent DKG signature domain
        // must still come from this request's own context event.
        let routes = FutureRoutes::new(controller, &provider);
        let future_decryption = address("MockDecryptionVerifier")?;
        ensure!(future_decryption != decryption);
        ensure!(routes
            .setDecryptionVerifier(stored.encryptionSchemeId, future_decryption)
            .send()
            .await?
            .get_receipt()
            .await?
            .status());
        ensure!(
            routes
                .getDecryptionVerifier(stored.encryptionSchemeId)
                .call()
                .await?
                == future_decryption
        );
        let params = lifecycle.paramSetRegistry(event.e3.paramSet).call().await?;
        let request = E3Requested {
            e3_id: id.clone(),
            params_profile: profile,
            crypto_config_id: event.cryptoConfigId.0,
            params: ArcBytes::from_bytes(&params),
            threshold_m: committee.values().threshold,
            threshold_n: committee.values().n,
            seed: event.e3.seed.into(),
            request_block: event.e3.requestBlock.try_into()?,
            ..Default::default()
        };
        e3_request::E3Meta::from(&request).validate_identity()?;
        let mut history = vec![InterfoldEvent::new_with_timestamp(
            request.into(),
            None,
            event.e3.requestBlock.try_into()?,
            receipt.block_number,
            EventSource::Evm,
        )];
        let mut candidates = HashMap::new();
        for key in &anvil.keys()[2..5] {
            let signer = PrivateKeySigner::from_slice(&key.to_bytes())?;
            candidates.insert(signer.address(), signer.clone());
            let writer = ProviderBuilder::new()
                .wallet(signer)
                .connect_http(anvil.endpoint_url());
            ensure!(ICiphernodeRegistry::new(registry, &writer)
                .submitTicket(numeric, U256::from(1))
                .send()
                .await?
                .get_receipt()
                .await?
                .status());
        }
        let contract = ICiphernodeRegistry::new(registry, &provider);
        let deadline: u64 = contract
            .getCommitteeDeadline(numeric)
            .call()
            .await?
            .try_into()?;
        provider
            .anvil_set_next_block_timestamp(deadline + 1)
            .await?;
        provider.evm_mine(None).await?;
        let finalized = contract
            .finalizeCommittee(numeric)
            .send()
            .await?
            .get_receipt()
            .await?;
        ensure!(finalized.status());
        let mut signers = Vec::new();
        for slot in 0..committee.values().n {
            let member = contract
                .canonicalCommitteeNodeAt(numeric, U256::from(slot))
                .call()
                .await?;
            signers.push(
                candidates
                    .remove(&member)
                    .context("unexpected canonical committee member")?,
            );
        }
        let mut chain = Self {
            anvil,
            provider,
            controller,
            cli: None,
        };
        history.extend(chain.decode(&receipt, registry).await?);
        history.extend(chain.decode(&finalized, registry).await?);
        ensure!(history.iter().any(|fact| matches!(fact.get_data(),
            InterfoldEventData::SynchronizedDkgContextEstablished(frozen)
            if frozen.e3_id == id && frozen.context.registry == registry
                && frozen.context.verifying_contract == dkg && frozen.context.crypto_config_id == event.cryptoConfigId.0)),
            "request receipt did not establish the selected signing context");
        chain.cli = Some(CliRequest {
            id,
            signers,
            registry,
            dkg,
            decryption,
            future_decryption,
            history,
            submitted_ms,
            receipt,
            invoked,
        });
        Ok(chain)
    }
}
