// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import SafeApiKit from "@safe-global/api-kit";
import Safe from "@safe-global/protocol-kit";
import { MetaTransactionData, OperationType } from "@safe-global/types-kit";
import { ethers as ethersLib } from "ethers";
import fs from "fs";
import hre from "hardhat";
import path from "path";
import poseidon from "poseidon-solidity";

import { CiphernodeRegistryOwnable__factory as CiphernodeRegistryOwnableFactory } from "../types";
import { getProxyAdmin } from "./proxy";

const ZERO = ethersLib.ZeroAddress;
const ADDRESS_ONE = "0x0000000000000000000000000000000000000001";

const BFV_PARAMS = {
  insecure512: {
    degree: 512n,
    plaintextModulus: 100n,
    moduli: [0xffffee001n, 0xffffc4001n],
    error1Variance: "3",
  },
  secure8192: {
    degree: 8192n,
    plaintextModulus: 131072n,
    moduli: [0x0400000001460001n, 0x0400000000ea0001n, 0x0400000000920001n],
    error1Variance: "2331171231419734472395201298275918858425592709120",
  },
} as const;

interface TimeoutConfig {
  dkgWindow: string;
  computeWindow: string;
  decryptionWindow: string;
}

interface PricingConfig {
  keyGenFixedPerNode: string;
  keyGenPerEncryptionProof: string;
  coordinationPerPair: string;
  availabilityPerNodePerSec: string;
  decryptionPerNode: string;
  publicationBase: string;
  verificationPerProof: string;
  protocolTreasury: string;
  marginBps: string;
  protocolShareBps: string;
  dkgUtilizationBps: string;
  computeUtilizationBps: string;
  decryptUtilizationBps: string;
  minCommitteeSize: string;
  minThreshold: string;
}

interface ProtocolConfigFile {
  name: string;
  chainId: number;
  safe: string;
  fold: string;
  bondingRegistryProxy: string;
  bondingRegistryProxyAdmin: string;
  feeToken: string;
  protocolTreasury: string;
  slashedFundsTreasury: string;
  slasher: string;
  ticketToken: {
    lockRegistry: boolean;
  };
  bonding: {
    ticketPrice: string;
    licenseRequiredBond: string;
    minTicketBalance: string;
    exitDelay: string;
  };
  registry: {
    sortitionSubmissionWindow: string;
  };
  slashing: {
    initialDelay: string;
  };
  interfold: {
    maxDuration: string;
    markFailedGracePeriod: string;
    timeoutConfig: TimeoutConfig;
    pricing: PricingConfig;
    committeeThresholds: Array<{
      size: string;
      quorum: string;
      total: string;
    }>;
    registerDefaultBfvParamSets: boolean;
    allowFeeToken: boolean;
  };
  verifiers?: {
    decryptionVerifier?: string;
    pkVerifier?: string;
    dkgFoldAttestationVerifier?: string;
  };
  e3Programs?: string[];
}

interface ProtocolDeployment {
  name: string;
  chainId: number;
  operator: string;
  safe: string;
  fold: string;
  feeToken: string;
  bondingRegistryProxy: string;
  bondingRegistryProxyAdmin: string;
  bondingRegistryImplementation: string;
  ticketToken: string;
  slashingManager: string;
  poseidonT3: string;
  ciphernodeRegistry: string;
  ciphernodeRegistryImplementation: string;
  ciphernodeRegistryProxyAdmin: string;
  interfold: string;
  interfoldImplementation: string;
  interfoldProxyAdmin: string;
  interfoldPricing: string;
  e3RefundManager: string;
  e3RefundManagerImplementation: string;
  e3RefundManagerProxyAdmin: string;
  safeTransactions: string;
  safeProposal?: SafeProposal;
}

interface SafeTransaction {
  to: string;
  value: string;
  data: string;
  operation: number;
  contractMethod: null;
  contractInputsValues: null;
}

interface SafeProposal {
  safeTxHash: string;
  safeAddress: string;
  proposer: string;
  nonce: number;
  transactionCount: number;
  origin: string;
  url?: string;
  proposedAt: string;
}

const abi = ethersLib.AbiCoder.defaultAbiCoder();
const proxyAdminInterface = new ethersLib.Interface([
  "function owner() view returns (address)",
  "function upgradeAndCall(address proxy,address implementation,bytes data) payable",
]);

const scriptArgs = process.argv.slice(2);

function arg(name: string): string | undefined {
  const flag = `--${name}`;
  const withEquals = `${flag}=`;
  for (let i = 0; i < scriptArgs.length; i++) {
    const value = scriptArgs[i];
    if (value === flag) return scriptArgs[i + 1];
    if (value.startsWith(withEquals)) return value.slice(withEquals.length);
  }
  return undefined;
}

function hasFlag(name: string): boolean {
  return scriptArgs.includes(`--${name}`);
}

function findRepoRoot(): string {
  let dir = process.cwd();
  while (true) {
    if (
      fs.existsSync(path.join(dir, "AGENTS.md")) &&
      fs.existsSync(path.join(dir, "packages", "interfold-contracts"))
    ) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return process.cwd();
    dir = parent;
  }
}

const repoRoot = findRepoRoot();
const protocolDir = path.join(
  repoRoot,
  "packages",
  "interfold-contracts",
  "deploy",
  "protocol",
);

function networkName(): string {
  return (
    arg("network") ??
    (hre.globalOptions as unknown as { network?: string }).network ??
    process.env.HARDHAT_NETWORK ??
    "network"
  );
}

async function connect() {
  const requested =
    arg("network") ??
    (hre.globalOptions as unknown as { network?: string }).network ??
    process.env.HARDHAT_NETWORK;
  return requested ? hre.network.connect(requested) : hre.network.connect();
}

function resolvePath(input: string): string {
  if (path.isAbsolute(input)) return input;
  const cwdPath = path.resolve(input);
  if (fs.existsSync(cwdPath)) return cwdPath;
  return path.join(repoRoot, input);
}

function defaultConfigPath(): string {
  return path.join(protocolDir, `${networkName()}-protocol.config.json`);
}

function configPath(required = true): string {
  const file = arg("config")
    ? resolvePath(arg("config")!)
    : defaultConfigPath();
  if (required && !fs.existsSync(file)) {
    throw new Error(
      `Protocol config not found: ${file}. Pass --config or create it from packages/interfold-contracts/deploy/protocol/example.protocol.config.json.`,
    );
  }
  return file;
}

function deploymentPath(config: ProtocolConfigFile): string {
  return arg("deployment")
    ? resolvePath(arg("deployment")!)
    : path.join(protocolDir, `${config.name}.deployment.json`);
}

function safeBatchPath(config: ProtocolConfigFile): string {
  return arg("safe-batch")
    ? resolvePath(arg("safe-batch")!)
    : path.join(protocolDir, `${config.name}.safe-transactions.json`);
}

function safeProposalPath(config: ProtocolConfigFile): string {
  return arg("safe-proposal")
    ? resolvePath(arg("safe-proposal")!)
    : path.join(protocolDir, `${config.name}.safe-proposal.json`);
}

function readJson<T>(file: string): T {
  return JSON.parse(fs.readFileSync(file, "utf8")) as T;
}

function writeJson(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(
    file,
    `${JSON.stringify(
      value,
      (_key, v) => (typeof v === "bigint" ? v.toString() : v),
      2,
    )}\n`,
    "utf8",
  );
}

function address(value: string, label: string): string {
  try {
    return ethersLib.getAddress(value);
  } catch {
    throw new Error(`${label} is not a valid address: ${value}`);
  }
}

function optionalAddress(
  value: string | undefined,
  label: string,
): string | undefined {
  if (!value || value === ZERO) return undefined;
  return address(value, label);
}

async function requireContract(
  provider: ethersLib.Provider,
  target: string,
  label: string,
): Promise<void> {
  const code = await provider.getCode(target);
  if (code === "0x") throw new Error(`${label} has no code: ${target}`);
}

async function deployedAddress(contract: {
  target?: unknown;
  getAddress?: () => Promise<string>;
}): Promise<string> {
  if (typeof contract.target === "string") {
    return address(contract.target, "contract");
  }
  if (contract.getAddress)
    return address(await contract.getAddress(), "contract");
  throw new Error("Could not determine deployed contract address");
}

function encodeBfvParams(params: {
  degree: bigint;
  plaintextModulus: bigint;
  moduli: readonly bigint[];
  error1Variance: string;
}): string {
  return abi.encode(
    [
      "tuple(uint256 degree, uint256 plaintext_modulus, uint256[] moduli, string error1_variance)",
    ],
    [
      [
        params.degree,
        params.plaintextModulus,
        [...params.moduli],
        params.error1Variance,
      ],
    ],
  );
}

function timeoutConfig(config: TimeoutConfig) {
  return {
    dkgWindow: BigInt(config.dkgWindow),
    computeWindow: BigInt(config.computeWindow),
    decryptionWindow: BigInt(config.decryptionWindow),
  };
}

function pricingConfig(config: PricingConfig) {
  return {
    keyGenFixedPerNode: BigInt(config.keyGenFixedPerNode),
    keyGenPerEncryptionProof: BigInt(config.keyGenPerEncryptionProof),
    coordinationPerPair: BigInt(config.coordinationPerPair),
    availabilityPerNodePerSec: BigInt(config.availabilityPerNodePerSec),
    decryptionPerNode: BigInt(config.decryptionPerNode),
    publicationBase: BigInt(config.publicationBase),
    verificationPerProof: BigInt(config.verificationPerProof),
    protocolTreasury: address(
      config.protocolTreasury,
      "interfold.pricing.protocolTreasury",
    ),
    marginBps: BigInt(config.marginBps),
    protocolShareBps: BigInt(config.protocolShareBps),
    dkgUtilizationBps: BigInt(config.dkgUtilizationBps),
    computeUtilizationBps: BigInt(config.computeUtilizationBps),
    decryptUtilizationBps: BigInt(config.decryptUtilizationBps),
    minCommitteeSize: BigInt(config.minCommitteeSize),
    minThreshold: BigInt(config.minThreshold),
  };
}

function loadConfig(file = configPath()): ProtocolConfigFile {
  const config = readJson<ProtocolConfigFile>(file);
  const safeOverride = arg("safe") ?? process.env.SAFE_ADDRESS;
  if (safeOverride && config.safe === ZERO) config.safe = safeOverride;
  validateConfig(config);
  return config;
}

function validateConfig(config: ProtocolConfigFile): void {
  if (!config.name) throw new Error("Config name is required");
  config.safe = address(config.safe, "safe");
  config.fold = address(config.fold, "fold");
  config.bondingRegistryProxy = address(
    config.bondingRegistryProxy,
    "bondingRegistryProxy",
  );
  config.bondingRegistryProxyAdmin = address(
    config.bondingRegistryProxyAdmin,
    "bondingRegistryProxyAdmin",
  );
  config.feeToken = address(config.feeToken, "feeToken");
  config.protocolTreasury = address(
    config.protocolTreasury,
    "protocolTreasury",
  );
  config.slashedFundsTreasury = address(
    config.slashedFundsTreasury,
    "slashedFundsTreasury",
  );
  if (config.slasher !== ZERO)
    config.slasher = address(config.slasher, "slasher");
  config.interfold.pricing.protocolTreasury = address(
    config.interfold.pricing.protocolTreasury,
    "interfold.pricing.protocolTreasury",
  );
  for (const program of config.e3Programs ?? []) address(program, "e3Program");
  optionalAddress(config.verifiers?.decryptionVerifier, "decryptionVerifier");
  optionalAddress(config.verifiers?.pkVerifier, "pkVerifier");
  optionalAddress(
    config.verifiers?.dkgFoldAttestationVerifier,
    "dkgFoldAttestationVerifier",
  );
}

async function ensurePoseidonT3(
  ethers: Awaited<ReturnType<typeof hre.network.connect>>["ethers"],
): Promise<string> {
  if ((await ethers.provider.getCode(poseidon.proxy.address)) === "0x") {
    const [sender] = await ethers.getSigners();
    await (
      await sender.sendTransaction({
        to: poseidon.proxy.from,
        value: poseidon.proxy.gas,
      })
    ).wait();
    await (
      await ethers.provider.broadcastTransaction(poseidon.proxy.tx)
    ).wait();
  }
  if ((await ethers.provider.getCode(poseidon.PoseidonT3.address)) === "0x") {
    const [sender] = await ethers.getSigners();
    await (
      await sender.sendTransaction({
        to: poseidon.proxy.address,
        data: poseidon.PoseidonT3.data,
      })
    ).wait();
  }
  return poseidon.PoseidonT3.address;
}

async function deployProxy(
  ethers: Awaited<ReturnType<typeof hre.network.connect>>["ethers"],
  implementation: string,
  owner: string,
  initData: string,
) {
  const proxyFactory = await ethers.getContractFactory(
    "TransparentUpgradeableProxy",
  );
  const proxy = await proxyFactory.deploy(implementation, owner, initData);
  await proxy.waitForDeployment();
  const proxyAddress = await deployedAddress(proxy);
  const proxyAdmin = await getProxyAdmin(ethers.provider, proxyAddress);
  return { proxy: proxyAddress, proxyAdmin };
}

function safeTx(to: string, data: string): SafeTransaction {
  return {
    to,
    value: "0",
    data,
    operation: 0,
    contractMethod: null,
    contractInputsValues: null,
  };
}

function safeBatch(
  config: ProtocolConfigFile,
  transactions: SafeTransaction[],
) {
  return {
    version: "1.0",
    chainId: config.chainId.toString(),
    createdAt: Date.now(),
    meta: {
      name: `${config.name} protocol wiring`,
      description:
        "Upgrade the existing bonding registry proxy and wire the Interfold protocol contracts.",
      txBuilderVersion: "1.18.0",
      createdFromSafeAddress: config.safe,
    },
    transactions,
  };
}

function readSafeBatch(config: ProtocolConfigFile): SafeTransaction[] {
  const file = safeBatchPath(config);
  if (!fs.existsSync(file)) {
    throw new Error(
      `Safe batch not found: ${file}. Run --action deploy first.`,
    );
  }
  const batch = readJson<{ transactions?: SafeTransaction[] }>(file);
  if (!Array.isArray(batch.transactions)) {
    throw new Error(`Safe batch has no transactions array: ${file}`);
  }
  return batch.transactions;
}

function safeAppPrefix(chainId: number): string | undefined {
  if (chainId === 1) return "eth";
  if (chainId === 11155111) return "sep";
  if (chainId === 8453) return "base";
  if (chainId === 84532) return "basesep";
  if (chainId === 42161) return "arb1";
  if (chainId === 10) return "oeth";
  if (chainId === 137) return "matic";
  return undefined;
}

function safeTransactionUrl(
  chainId: number,
  safeAddress: string,
  safeTxHash: string,
): string | undefined {
  const prefix = safeAppPrefix(chainId);
  if (!prefix) return undefined;
  return `https://app.safe.global/transactions/tx?safe=${prefix}:${safeAddress}&id=multisig_${safeAddress}_${safeTxHash}`;
}

function privateKeyForSafeProposal(): string {
  if (process.env.PRIVATE_KEY) return process.env.PRIVATE_KEY;
  if (process.env.MNEMONIC) {
    return ethersLib.HDNodeWallet.fromPhrase(
      process.env.MNEMONIC,
      undefined,
      "m/44'/60'/0'/0/0",
    ).privateKey;
  }
  throw new Error(
    "Set PRIVATE_KEY or MNEMONIC so the Safe SDK can sign the proposal hash.",
  );
}

function rpcUrlForSafeProposal(): string {
  const rpcUrl = process.env.RPC_URL;
  if (!rpcUrl) {
    throw new Error("Set RPC_URL so the Safe SDK can read the Safe.");
  }
  return rpcUrl;
}

function toMetaTransaction(tx: SafeTransaction): MetaTransactionData {
  return {
    to: tx.to,
    value: tx.value,
    data: tx.data,
    operation:
      tx.operation === 1 ? OperationType.DelegateCall : OperationType.Call,
  };
}

async function proposeSafeBatch(
  config: ProtocolConfigFile,
  transactions: SafeTransaction[],
): Promise<SafeProposal> {
  if (transactions.length === 0) {
    throw new Error("Safe batch has no transactions to propose");
  }

  const privateKey = privateKeyForSafeProposal();
  const proposer = address(
    new ethersLib.Wallet(privateKey).address,
    "Safe proposal signer",
  );
  const apiKit = new SafeApiKit({
    chainId: BigInt(config.chainId),
    apiKey: process.env.SAFE_API_KEY || undefined,
    txServiceUrl: process.env.SAFE_TX_SERVICE_URL || undefined,
  });
  const protocolKit = await Safe.init({
    provider: rpcUrlForSafeProposal(),
    signer: privateKey,
    safeAddress: config.safe,
  });

  const nonce = Number(
    arg("safe-nonce") ?? (await apiKit.getNextNonce(config.safe)),
  );
  const origin = arg("origin") ?? `Interfold ${config.name} protocol wiring`;
  const safeTransaction = await protocolKit.createTransaction({
    transactions: transactions.map(toMetaTransaction),
    onlyCalls: true,
    options: { nonce },
  });
  const safeTxHash = await protocolKit.getTransactionHash(safeTransaction);
  const signature = await protocolKit.signHash(safeTxHash);

  await apiKit.proposeTransaction({
    safeAddress: config.safe,
    safeTransactionData: safeTransaction.data,
    safeTxHash,
    senderAddress: proposer,
    senderSignature: signature.data,
    origin,
  });

  const proposal: SafeProposal = {
    safeTxHash,
    safeAddress: config.safe,
    proposer,
    nonce,
    transactionCount: transactions.length,
    origin,
    url: safeTransactionUrl(config.chainId, config.safe, safeTxHash),
    proposedAt: new Date().toISOString(),
  };
  writeJson(safeProposalPath(config), proposal);
  return proposal;
}

async function actionDeploy(): Promise<void> {
  const { ethers } = await connect();
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  const config = loadConfig();
  if (chainId !== config.chainId) {
    throw new Error(
      `Connected chainId ${chainId} != config.chainId ${config.chainId}`,
    );
  }

  await Promise.all([
    requireContract(ethers.provider, config.safe, "safe"),
    requireContract(ethers.provider, config.fold, "fold"),
    requireContract(ethers.provider, config.feeToken, "feeToken"),
    requireContract(
      ethers.provider,
      config.bondingRegistryProxy,
      "bondingRegistryProxy",
    ),
    requireContract(
      ethers.provider,
      config.bondingRegistryProxyAdmin,
      "bondingRegistryProxyAdmin",
    ),
  ]);

  const proxyAdmin = new ethersLib.Contract(
    config.bondingRegistryProxyAdmin,
    proxyAdminInterface,
    ethers.provider,
  );
  const proxyAdminOwner = address(await proxyAdmin.owner(), "proxyAdmin.owner");
  if (proxyAdminOwner !== config.safe) {
    throw new Error(
      `BondingRegistry ProxyAdmin owner mismatch: expected ${config.safe}, got ${proxyAdminOwner}`,
    );
  }

  const [operator] = await ethers.getSigners();
  const operatorAddress = await operator.getAddress();
  const poseidonT3 = await ensurePoseidonT3(ethers);

  console.log(`Deploying protocol contracts for ${config.name}`);

  const ticketFactory = await ethers.getContractFactory("InterfoldTicketToken");
  const ticket = await ticketFactory.deploy(
    config.feeToken,
    ADDRESS_ONE,
    config.safe,
  );
  await ticket.waitForDeployment();
  const ticketToken = await deployedAddress(ticket);

  const slashingFactory = await ethers.getContractFactory("SlashingManager");
  const slashing = await slashingFactory.deploy(
    BigInt(config.slashing.initialDelay),
    config.safe,
  );
  await slashing.waitForDeployment();
  const slashingManager = await deployedAddress(slashing);

  const registryFactory = await ethers.getContractFactory(
    CiphernodeRegistryOwnableFactory.abi,
    CiphernodeRegistryOwnableFactory.linkBytecode({
      "npm/poseidon-solidity@0.0.5/PoseidonT3.sol:PoseidonT3": poseidonT3,
    }),
    operator,
  );
  const registryImpl = await registryFactory.deploy();
  await registryImpl.waitForDeployment();
  const ciphernodeRegistryImplementation = await deployedAddress(registryImpl);
  const registryInitData = registryFactory.interface.encodeFunctionData(
    "initialize",
    [config.safe, BigInt(config.registry.sortitionSubmissionWindow)],
  );
  const registryProxy = await deployProxy(
    ethers,
    ciphernodeRegistryImplementation,
    config.safe,
    registryInitData,
  );

  const pricingLibFactory = await ethers.getContractFactory("InterfoldPricing");
  const pricingLib = await pricingLibFactory.deploy();
  await pricingLib.waitForDeployment();
  const interfoldPricing = await deployedAddress(pricingLib);

  const interfoldFactory = await ethers.getContractFactory("Interfold", {
    libraries: { InterfoldPricing: interfoldPricing },
  });
  const interfoldImpl = await interfoldFactory.deploy();
  await interfoldImpl.waitForDeployment();
  const interfoldImplementation = await deployedAddress(interfoldImpl);
  const interfoldInitData = interfoldFactory.interface.encodeFunctionData(
    "initialize",
    [
      config.safe,
      registryProxy.proxy,
      config.bondingRegistryProxy,
      ADDRESS_ONE,
      config.feeToken,
      BigInt(config.interfold.maxDuration),
      timeoutConfig(config.interfold.timeoutConfig),
    ],
  );
  const interfoldProxy = await deployProxy(
    ethers,
    interfoldImplementation,
    config.safe,
    interfoldInitData,
  );

  const refundFactory = await ethers.getContractFactory("E3RefundManager");
  const refundImpl = await refundFactory.deploy();
  await refundImpl.waitForDeployment();
  const e3RefundManagerImplementation = await deployedAddress(refundImpl);
  const refundInitData = refundFactory.interface.encodeFunctionData(
    "initialize",
    [config.safe, interfoldProxy.proxy, config.protocolTreasury],
  );
  const refundProxy = await deployProxy(
    ethers,
    e3RefundManagerImplementation,
    config.safe,
    refundInitData,
  );

  const bondingFactory = await ethers.getContractFactory("BondingRegistry");
  const bondingImpl = await bondingFactory.deploy();
  await bondingImpl.waitForDeployment();
  const bondingRegistryImplementation = await deployedAddress(bondingImpl);

  const bondingInitData = bondingFactory.interface.encodeFunctionData(
    "initialize",
    [
      config.safe,
      ticketToken,
      config.fold,
      registryProxy.proxy,
      config.slashedFundsTreasury,
      BigInt(config.bonding.ticketPrice),
      BigInt(config.bonding.licenseRequiredBond),
      BigInt(config.bonding.minTicketBalance),
      BigInt(config.bonding.exitDelay),
    ],
  );

  const txs: SafeTransaction[] = [];
  txs.push(
    safeTx(
      config.bondingRegistryProxyAdmin,
      proxyAdminInterface.encodeFunctionData("upgradeAndCall", [
        config.bondingRegistryProxy,
        bondingRegistryImplementation,
        bondingInitData,
      ]),
    ),
  );
  txs.push(
    safeTx(
      interfoldProxy.proxy,
      interfoldFactory.interface.encodeFunctionData("setE3RefundManager", [
        refundProxy.proxy,
      ]),
    ),
    safeTx(
      interfoldProxy.proxy,
      interfoldFactory.interface.encodeFunctionData("setSlashingManager", [
        slashingManager,
      ]),
    ),
  );

  if (BigInt(config.interfold.markFailedGracePeriod) > 0n) {
    txs.push(
      safeTx(
        interfoldProxy.proxy,
        interfoldFactory.interface.encodeFunctionData(
          "setMarkFailedGracePeriod",
          [BigInt(config.interfold.markFailedGracePeriod)],
        ),
      ),
    );
  }

  if (config.interfold.allowFeeToken) {
    txs.push(
      safeTx(
        interfoldProxy.proxy,
        interfoldFactory.interface.encodeFunctionData("setFeeTokenAllowed", [
          config.feeToken,
          true,
        ]),
      ),
    );
  }

  for (const threshold of config.interfold.committeeThresholds) {
    txs.push(
      safeTx(
        interfoldProxy.proxy,
        interfoldFactory.interface.encodeFunctionData(
          "setCommitteeThresholds",
          [
            BigInt(threshold.size),
            [BigInt(threshold.quorum), BigInt(threshold.total)],
          ],
        ),
      ),
    );
  }

  if (config.interfold.registerDefaultBfvParamSets) {
    txs.push(
      safeTx(
        interfoldProxy.proxy,
        interfoldFactory.interface.encodeFunctionData("setParamSet", [
          0,
          encodeBfvParams(BFV_PARAMS.insecure512),
        ]),
      ),
      safeTx(
        interfoldProxy.proxy,
        interfoldFactory.interface.encodeFunctionData("setParamSet", [
          1,
          encodeBfvParams(BFV_PARAMS.secure8192),
        ]),
      ),
    );
  }

  txs.push(
    safeTx(
      interfoldProxy.proxy,
      interfoldFactory.interface.encodeFunctionData("setPricingConfig", [
        pricingConfig(config.interfold.pricing),
      ]),
    ),
  );

  const decryptionVerifier = optionalAddress(
    config.verifiers?.decryptionVerifier,
    "decryptionVerifier",
  );
  if (decryptionVerifier) {
    txs.push(
      safeTx(
        interfoldProxy.proxy,
        interfoldFactory.interface.encodeFunctionData("setDecryptionVerifier", [
          ethersLib.id("fhe.rs:BFV"),
          decryptionVerifier,
        ]),
      ),
    );
  }

  const pkVerifier = optionalAddress(
    config.verifiers?.pkVerifier,
    "pkVerifier",
  );
  if (pkVerifier) {
    txs.push(
      safeTx(
        interfoldProxy.proxy,
        interfoldFactory.interface.encodeFunctionData("setPkVerifier", [
          ethersLib.id("fhe.rs:BFV"),
          pkVerifier,
        ]),
      ),
    );
  }

  for (const program of config.e3Programs ?? []) {
    txs.push(
      safeTx(
        interfoldProxy.proxy,
        interfoldFactory.interface.encodeFunctionData("registerE3Program", [
          address(program, "e3Program"),
        ]),
      ),
    );
  }

  txs.push(
    safeTx(
      registryProxy.proxy,
      registryFactory.interface.encodeFunctionData("setInterfold", [
        interfoldProxy.proxy,
      ]),
    ),
    safeTx(
      registryProxy.proxy,
      registryFactory.interface.encodeFunctionData("setBondingRegistry", [
        config.bondingRegistryProxy,
      ]),
    ),
    safeTx(
      registryProxy.proxy,
      registryFactory.interface.encodeFunctionData("setSlashingManager", [
        slashingManager,
      ]),
    ),
  );

  const dkgFoldVerifier = optionalAddress(
    config.verifiers?.dkgFoldAttestationVerifier,
    "dkgFoldAttestationVerifier",
  );
  if (dkgFoldVerifier) {
    txs.push(
      safeTx(
        registryProxy.proxy,
        registryFactory.interface.encodeFunctionData(
          "setInitialDkgFoldAttestationVerifier",
          [dkgFoldVerifier],
        ),
      ),
    );
  }

  txs.push(
    safeTx(
      ticketToken,
      ticketFactory.interface.encodeFunctionData("setRegistry", [
        config.bondingRegistryProxy,
      ]),
    ),
  );
  if (config.ticketToken.lockRegistry) {
    txs.push(
      safeTx(
        ticketToken,
        ticketFactory.interface.encodeFunctionData("lockRegistry", []),
      ),
    );
  }

  txs.push(
    safeTx(
      slashingManager,
      slashingFactory.interface.encodeFunctionData("setInterfold", [
        interfoldProxy.proxy,
      ]),
    ),
    safeTx(
      slashingManager,
      slashingFactory.interface.encodeFunctionData("setBondingRegistry", [
        config.bondingRegistryProxy,
      ]),
    ),
    safeTx(
      slashingManager,
      slashingFactory.interface.encodeFunctionData("setCiphernodeRegistry", [
        registryProxy.proxy,
      ]),
    ),
    safeTx(
      slashingManager,
      slashingFactory.interface.encodeFunctionData("setE3RefundManager", [
        refundProxy.proxy,
      ]),
    ),
  );

  if (config.slasher !== ZERO) {
    txs.push(
      safeTx(
        slashingManager,
        slashingFactory.interface.encodeFunctionData("addSlasher", [
          config.slasher,
        ]),
      ),
    );
  }

  txs.push(
    safeTx(
      config.bondingRegistryProxy,
      bondingFactory.interface.encodeFunctionData("setSlashingManager", [
        slashingManager,
      ]),
    ),
    safeTx(
      config.bondingRegistryProxy,
      bondingFactory.interface.encodeFunctionData("setRewardDistributor", [
        interfoldProxy.proxy,
        true,
      ]),
    ),
    safeTx(
      config.bondingRegistryProxy,
      bondingFactory.interface.encodeFunctionData("setRewardDistributor", [
        refundProxy.proxy,
        true,
      ]),
    ),
  );

  const batchFile = safeBatchPath(config);
  writeJson(batchFile, safeBatch(config, txs));

  const deployment: ProtocolDeployment = {
    name: config.name,
    chainId,
    operator: operatorAddress,
    safe: config.safe,
    fold: config.fold,
    feeToken: config.feeToken,
    bondingRegistryProxy: config.bondingRegistryProxy,
    bondingRegistryProxyAdmin: config.bondingRegistryProxyAdmin,
    bondingRegistryImplementation,
    ticketToken,
    slashingManager,
    poseidonT3,
    ciphernodeRegistry: registryProxy.proxy,
    ciphernodeRegistryImplementation,
    ciphernodeRegistryProxyAdmin: registryProxy.proxyAdmin,
    interfold: interfoldProxy.proxy,
    interfoldImplementation,
    interfoldProxyAdmin: interfoldProxy.proxyAdmin,
    interfoldPricing,
    e3RefundManager: refundProxy.proxy,
    e3RefundManagerImplementation,
    e3RefundManagerProxyAdmin: refundProxy.proxyAdmin,
    safeTransactions: batchFile,
  };
  const deploymentFile = deploymentPath(config);
  writeJson(deploymentFile, deployment);

  if (hasFlag("propose-safe")) {
    const proposal = await proposeSafeBatch(config, txs);
    deployment.safeProposal = proposal;
    writeJson(deploymentFile, deployment);
    console.log(`
Safe transaction proposed
  hash: ${proposal.safeTxHash}
  nonce: ${proposal.nonce}
  url:  ${proposal.url ?? "(open the Safe UI pending queue)"}
`);
  }

  console.log(`
Protocol contracts deployed
  ticketToken:            ${ticketToken}
  slashingManager:        ${slashingManager}
  ciphernodeRegistry:     ${registryProxy.proxy}
  interfold:              ${interfoldProxy.proxy}
  e3RefundManager:        ${refundProxy.proxy}
  bonding implementation: ${bondingRegistryImplementation}

Safe batch required
  file: ${batchFile}
  txs:  ${txs.length}

Deployment file
  ${deploymentFile}
`);
}

async function actionProposeSafe(): Promise<void> {
  const config = loadConfig();
  const transactions = readSafeBatch(config);
  const proposal = await proposeSafeBatch(config, transactions);

  if (fs.existsSync(deploymentPath(config))) {
    const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
    deployment.safeProposal = proposal;
    writeJson(deploymentPath(config), deployment);
  }

  console.log(`
Safe transaction proposed
  hash: ${proposal.safeTxHash}
  nonce: ${proposal.nonce}
  txs:  ${proposal.transactionCount}
  url:  ${proposal.url ?? "(open the Safe UI pending queue)"}
`);
}

async function actionValidate(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<ProtocolDeployment>(deploymentPath(config));
  const network = await ethers.provider.getNetwork();
  if (Number(network.chainId) !== deployment.chainId) {
    throw new Error("Connected to the wrong network for this deployment file");
  }

  const ticket = await ethers.getContractAt(
    "InterfoldTicketToken",
    deployment.ticketToken,
  );
  const registry = await ethers.getContractAt(
    "CiphernodeRegistryOwnable",
    deployment.ciphernodeRegistry,
  );
  const interfold = await ethers.getContractAt(
    "Interfold",
    deployment.interfold,
  );
  const refund = await ethers.getContractAt(
    "E3RefundManager",
    deployment.e3RefundManager,
  );
  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    deployment.bondingRegistryProxy,
  );
  const slashing = await ethers.getContractAt(
    "SlashingManager",
    deployment.slashingManager,
  );

  const checks: Array<[string, Promise<unknown>, unknown]> = [
    ["ticket.owner", ticket.owner(), config.safe],
    ["ticket.registry", ticket.registry(), deployment.bondingRegistryProxy],
    ["registry.owner", registry.owner(), config.safe],
    ["registry.interfold", registry.interfold(), deployment.interfold],
    [
      "registry.bondingRegistry",
      registry.bondingRegistry(),
      deployment.bondingRegistryProxy,
    ],
    [
      "registry.slashingManager",
      registry.slashingManager(),
      deployment.slashingManager,
    ],
    ["interfold.owner", interfold.owner(), config.safe],
    [
      "interfold.bondingRegistry",
      interfold.bondingRegistry(),
      deployment.bondingRegistryProxy,
    ],
    [
      "interfold.ciphernodeRegistry",
      interfold.ciphernodeRegistry(),
      deployment.ciphernodeRegistry,
    ],
    [
      "interfold.e3RefundManager",
      interfold.e3RefundManager(),
      deployment.e3RefundManager,
    ],
    [
      "interfold.slashingManager",
      interfold.slashingManager(),
      deployment.slashingManager,
    ],
    ["refund.owner", refund.owner(), config.safe],
    ["bonding.owner", bonding.owner(), config.safe],
    ["bonding.ticketToken", bonding.ticketToken(), deployment.ticketToken],
    ["bonding.licenseToken", bonding.licenseToken(), config.fold],
    ["bonding.registry", bonding.registry(), deployment.ciphernodeRegistry],
    [
      "bonding.slashingManager",
      bonding.slashingManager(),
      deployment.slashingManager,
    ],
    ["slashing.interfold", slashing.interfold(), deployment.interfold],
    [
      "slashing.bondingRegistry",
      slashing.bondingRegistry(),
      deployment.bondingRegistryProxy,
    ],
    [
      "slashing.ciphernodeRegistry",
      slashing.ciphernodeRegistry(),
      deployment.ciphernodeRegistry,
    ],
    [
      "slashing.e3RefundManager",
      slashing.e3RefundManager(),
      deployment.e3RefundManager,
    ],
  ];

  for (const [label, actualPromise, expected] of checks) {
    const actual = await actualPromise;
    if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
      throw new Error(`${label}: expected ${expected}, got ${actual}`);
    }
    console.log(`  ok ${label}`);
  }

  const defaultAdmin = ethersLib.ZeroHash;
  if (!(await slashing.hasRole(defaultAdmin, config.safe))) {
    throw new Error("Safe does not have SlashingManager DEFAULT_ADMIN_ROLE");
  }
  console.log("Protocol validation complete");
}

function printHelp(): void {
  console.log(`
Interfold protocol deployment

Actions:
  --action deploy      Deploy protocol contracts and write one Safe wiring batch
  --action propose-safe Propose the written Safe batch through the Safe SDK
  --action validate    Validate after the Safe batch executes

Examples:
  pnpm protocol --network sepolia --action deploy --config packages/interfold-contracts/deploy/protocol/sepolia-protocol.config.json --propose-safe
  pnpm protocol --network sepolia --action propose-safe --config packages/interfold-contracts/deploy/protocol/sepolia-protocol.config.json
  pnpm protocol --network sepolia --action validate --config packages/interfold-contracts/deploy/protocol/sepolia-protocol.config.json
`);
}

async function main(): Promise<void> {
  const action = (arg("action") ?? "help").toLowerCase();
  if (action === "help") return printHelp();
  if (action === "deploy") return actionDeploy();
  if (action === "propose-safe") return actionProposeSafe();
  if (action === "validate") return actionValidate();
  throw new Error(`Unknown --action: ${action}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
