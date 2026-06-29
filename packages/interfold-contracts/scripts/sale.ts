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

import { getProxyAdmin } from "./proxy";

const ZERO = ethersLib.ZeroAddress;
const MSG_SENDER_SENTINEL = "0x0000000000000000000000000000000000000001";
const DAY = 24n * 60n * 60n;
const FORTY_DAYS = 40n * DAY;
const FOUR_YEARS = 4n * 365n * DAY;
const DEFAULT_SALE_AMOUNT = ethersLib.parseEther("1000").toString();

type CcaVersion = "v1.1.0" | "v2.0.0";

const CCA_FACTORY_ADDRESSES: Record<CcaVersion, string> = {
  "v1.1.0": "0xCCccCcCAE7503Cac057829BF2811De42E16e0bD5",
  "v2.0.0": "0x00cCa200BF124dBfA848937c553864f4B4CE0632",
};

const AUCTION_PARAMETERS_TUPLE =
  "tuple(" +
  "address currency," +
  "address tokensRecipient," +
  "address fundsRecipient," +
  "uint64 startBlock," +
  "uint64 endBlock," +
  "uint64 claimBlock," +
  "uint256 tickSpacing," +
  "address validationHook," +
  "uint256 floorPrice," +
  "uint128 requiredCurrencyRaised," +
  "bytes auctionStepsData" +
  ")";

const CCA_FACTORY_V1_ABI = [
  "function initializeDistribution(address token,uint256 amount,bytes configData,bytes32 salt) returns (address)",
  "function getAuctionAddress(address token,uint256 amount,bytes configData,bytes32 salt,address sender) view returns (address)",
];

const CCA_FACTORY_V2_ABI = [
  "function create(address token,uint256 amount,bytes configData,bytes32 salt) returns (address)",
  "function getAddress(address token,uint256 amount,bytes configData,bytes32 salt,address sender) view returns (address)",
  "function protocolFeeController() view returns (address)",
];

const CCA_AUCTION_ABI = [
  "function token() view returns (address)",
  "function totalSupply() view returns (uint128)",
  "function tokensRecipient() view returns (address)",
  "function fundsRecipient() view returns (address)",
  "function currency() view returns (address)",
  "function startBlock() view returns (uint64)",
  "function endBlock() view returns (uint64)",
  "function claimBlock() view returns (uint64)",
  "function validationHook() view returns (address)",
  "function tokensReceived() view returns (bool)",
  "function isGraduated() view returns (bool)",
  "function currencyRaised() view returns (uint256)",
  "function checkpoint() returns (tuple(uint256 clearingPrice,uint224 currencyRaisedAtClearingPriceQ96X7,uint256 cumulativeMpsPerPrice,uint24 cumulativeMps,uint64 prev,uint64 next))",
  "function bids(uint256 bidId) view returns (tuple(uint64 startBlock,uint24 startCumulativeMps,uint64 exitedBlock,uint256 maxPrice,address owner,uint256 amountQ96,uint256 tokensFilled))",
  "function submitBid(uint256 maxPrice,uint128 amount,address owner,bytes hookData) payable returns (uint256 bidId)",
  "function exitBid(uint256 bidId)",
  "function exitPartiallyFilledBid(uint256 bidId,uint64 lastFullyFilledCheckpointBlock,uint64 outbidBlock)",
  "function claimTokens(uint256 bidId)",
  "event BidSubmitted(uint256 indexed id,address indexed owner,uint256 price,uint256 amount)",
  "function bid() payable",
  "function claim() returns (uint256)",
];

const abi = ethersLib.AbiCoder.defaultAbiCoder();

interface FoldTokenConfig {
  ccaStart: string;
  ccaEnd: string;
  noMoreLocks?: string;
  bondingRegistry: string;
}

interface AuctionConfig {
  currency: string;
  tokensRecipient: string;
  fundsRecipient: string;
  startBlock: string;
  endBlock: string;
  claimBlock: string;
  tickSpacing: string;
  validationHook: string;
  floorPrice: string;
  requiredCurrencyRaised: string;
  auctionStepsData: string;
}

interface SaleConfigFile {
  name: string;
  chainId: number;
  saleDeployer: string;
  safe: string;
  ccaVersion: CcaVersion;
  ccaFactory?: string;
  saleAmount: string;
  ccaSalt: string;
  saleLabel: string;
  fold: FoldTokenConfig;
  auction: AuctionConfig;
}

interface AuctionParameters {
  currency: string;
  tokensRecipient: string;
  fundsRecipient: string;
  startBlock: bigint;
  endBlock: bigint;
  claimBlock: bigint;
  tickSpacing: bigint;
  validationHook: string;
  floorPrice: bigint;
  requiredCurrencyRaised: bigint;
  auctionStepsData: string;
}

export interface SalePlan {
  name: string;
  chainId: number;
  saleDeployer: string;
  safe: string;
  factoryNonce: number;
  ccaFactory: string;
  predictedFold: string;
  predictedAuction: string;
  fold: {
    initialOwner: string;
    ccaStart: string;
    ccaEnd: string;
    noMoreLocks: string;
    claimSource: string;
    bondingRegistry: string;
  };
  auction: AuctionParameters;
  saleConfig: {
    ccaFactory: string;
    ccaUseV2: boolean;
    saleAmount: string;
    ccaSalt: string;
    ccaConfigData: string;
    saleLabel: string;
    foldInitCodeHash: string;
  };
  foldInitCode: string;
  configHash?: string;
  configDigest?: string;
}

interface DeploymentFile {
  name: string;
  chainId: number;
  txHash: string;
  blockNumber: number;
  operator: string;
  safe: string;
  saleDeployer: string;
  fold: string;
  auction: string;
  bondingRegistry: string;
  bondingRegistryProxyAdmin?: string;
  ccaFactory: string;
  mockCcaFactory?: string;
  testBidId?: string;
  safeProposal?: SafeProposal;
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
const saleDir = path.join(
  repoRoot,
  "packages",
  "interfold-contracts",
  "deploy",
  "sale",
);

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

function networkName(): string {
  return (
    arg("network") ??
    (hre.network as unknown as { name?: string }).name ??
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
  return path.join(saleDir, `${networkName()}-sale.config.json`);
}

function configPath(required = true): string {
  const cliConfig = arg("config");
  const file = cliConfig ? resolvePath(cliConfig) : defaultConfigPath();
  if (required && !fs.existsSync(file)) {
    throw new Error(
      `Sale config not found: ${file}. Run --action prepare or pass --config.`,
    );
  }
  return file;
}

function planPath(config: SaleConfigFile): string {
  const cliPlan = arg("plan");
  return cliPlan
    ? resolvePath(cliPlan)
    : path.join(saleDir, `${config.name}.plan.json`);
}

function deploymentPath(config: SaleConfigFile): string {
  const cliDeployment = arg("deployment");
  return cliDeployment
    ? resolvePath(cliDeployment)
    : path.join(saleDir, `${config.name}.deployment.json`);
}

function safeProposalPath(config: SaleConfigFile): string {
  return arg("safe-proposal")
    ? resolvePath(arg("safe-proposal")!)
    : path.join(saleDir, `${config.name}.safe-proposal.json`);
}

function saleUiDir(): string {
  return path.join(repoRoot, "packages", "interfold-sale", "public", "sale");
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

async function proposeSafeTransactions(
  config: SaleConfigFile,
  transactions: MetaTransactionData[],
  origin: string,
): Promise<SafeProposal> {
  if (transactions.length === 0) {
    throw new Error("No Safe transactions to propose");
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
  const safeTransaction = await protocolKit.createTransaction({
    transactions,
    onlyCalls: true,
    options: { nonce },
  });
  const safeTxHash = await protocolKit.getTransactionHash(safeTransaction);
  const signature = await protocolKit.signHash(safeTxHash);

  let url: string | undefined;
  await apiKit.proposeTransaction({
    safeAddress: config.safe,
    safeTransactionData: safeTransaction.data,
    safeTxHash,
    senderAddress: proposer,
    senderSignature: signature.data,
    origin,
  });
  url = safeTransactionUrl(config.chainId, config.safe, safeTxHash);
  console.log(
    `Safe proposal URL: ${url ?? "(open the Safe UI pending queue)"}`,
  );

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

function address(value: string, label: string): string {
  try {
    return ethersLib.getAddress(value);
  } catch {
    throw new Error(`${label} is not a valid address: ${value}`);
  }
}

function requireBytes32(value: string, label: string): string {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be a 0x-prefixed bytes32`);
  }
  return value;
}

function loadConfig(file = configPath()): SaleConfigFile {
  const config = readJson<SaleConfigFile>(file);
  const safeOverride = arg("safe") ?? process.env.SAFE_ADDRESS;
  const saleDeployerOverride = arg("sale-deployer");
  const bondingOverride = arg("bonding-registry");
  const ccaFactoryOverride = arg("cca-factory");

  if (safeOverride && config.safe === ZERO) config.safe = safeOverride;
  if (saleDeployerOverride && config.saleDeployer === ZERO) {
    config.saleDeployer = saleDeployerOverride;
  }
  if (bondingOverride && config.fold.bondingRegistry === ZERO) {
    config.fold.bondingRegistry = bondingOverride;
  }
  if (ccaFactoryOverride) config.ccaFactory = ccaFactoryOverride;

  validateConfig(config);
  return config;
}

function validateConfig(config: SaleConfigFile): void {
  if (!config.name) throw new Error("Config name is required");
  if (config.ccaVersion !== "v1.1.0" && config.ccaVersion !== "v2.0.0") {
    throw new Error("ccaVersion must be v1.1.0 or v2.0.0");
  }
  config.safe = address(config.safe, "safe");
  config.saleDeployer = address(config.saleDeployer, "saleDeployer");
  if (config.ccaFactory)
    config.ccaFactory = address(config.ccaFactory, "ccaFactory");
  config.fold.bondingRegistry = address(
    config.fold.bondingRegistry,
    "fold.bondingRegistry",
  );
  config.auction.tokensRecipient = address(
    config.auction.tokensRecipient,
    "auction.tokensRecipient",
  );
  config.auction.fundsRecipient = address(
    config.auction.fundsRecipient,
    "auction.fundsRecipient",
  );
  config.auction.validationHook = address(
    config.auction.validationHook || ZERO,
    "auction.validationHook",
  );
  requireBytes32(config.ccaSalt, "ccaSalt");
  ethersLib.encodeBytes32String(config.saleLabel);
  BigInt(config.saleAmount);
  BigInt(config.fold.ccaStart);
  BigInt(config.fold.ccaEnd);
  if (config.fold.noMoreLocks?.trim()) BigInt(config.fold.noMoreLocks);
}

function resolveCurrency(currency: string): string {
  if (!currency || currency.toUpperCase() === "ETH") return ZERO;
  return address(currency, "auction.currency");
}

function toAuctionParameters(config: AuctionConfig): AuctionParameters {
  const startBlock = BigInt(config.startBlock);
  const endBlock = BigInt(config.endBlock);
  const claimBlock = BigInt(config.claimBlock);
  if (endBlock <= startBlock) {
    throw new Error("auction.endBlock must be greater than auction.startBlock");
  }
  if (claimBlock < endBlock) {
    throw new Error("auction.claimBlock must be >= auction.endBlock");
  }
  const auctionStepsData = config.auctionStepsData || "0x";
  if (!ethersLib.isHexString(auctionStepsData)) {
    throw new Error("auction.auctionStepsData must be 0x-prefixed hex");
  }
  return {
    currency: resolveCurrency(config.currency),
    tokensRecipient: address(config.tokensRecipient, "auction.tokensRecipient"),
    fundsRecipient: address(config.fundsRecipient, "auction.fundsRecipient"),
    startBlock,
    endBlock,
    claimBlock,
    tickSpacing: BigInt(config.tickSpacing),
    validationHook: address(
      config.validationHook || ZERO,
      "auction.validationHook",
    ),
    floorPrice: BigInt(config.floorPrice),
    requiredCurrencyRaised: BigInt(config.requiredCurrencyRaised),
    auctionStepsData,
  };
}

function encodeAuctionConfigData(params: AuctionParameters): string {
  return abi.encode(
    [AUCTION_PARAMETERS_TUPLE],
    [
      [
        params.currency,
        params.tokensRecipient,
        params.fundsRecipient,
        params.startBlock,
        params.endBlock,
        params.claimBlock,
        params.tickSpacing,
        params.validationHook,
        params.floorPrice,
        params.requiredCurrencyRaised,
        params.auctionStepsData,
      ],
    ],
  );
}

function resolveCcaFactory(config: SaleConfigFile): string {
  return address(
    config.ccaFactory ?? CCA_FACTORY_ADDRESSES[config.ccaVersion],
    "ccaFactory",
  );
}

function deriveNoMoreLocks(ccaEnd: bigint, explicit?: string): bigint {
  if (explicit?.trim()) {
    const value = BigInt(explicit);
    const minimum = ccaEnd + FORTY_DAYS;
    if (value <= minimum) {
      throw new Error(
        `fold.noMoreLocks must be greater than ccaEnd + 40 days (${minimum})`,
      );
    }
    return value;
  }
  return ccaEnd + FORTY_DAYS + FOUR_YEARS;
}

function buildFoldInitCode(opts: {
  creationCode: string;
  initialOwner: string;
  ccaStart: bigint;
  ccaEnd: bigint;
  noMoreLocks: bigint;
  claimSource: string;
  bondingRegistry: string;
}): string {
  const encodedCtor = abi.encode(
    ["address", "uint64", "uint64", "uint64", "address", "address"],
    [
      opts.initialOwner,
      opts.ccaStart,
      opts.ccaEnd,
      opts.noMoreLocks,
      opts.claimSource,
      opts.bondingRegistry,
    ],
  );
  return ethersLib.concat([opts.creationCode, encodedCtor]);
}

function saleConfigStruct(plan: SalePlan) {
  return {
    ccaFactory: plan.saleConfig.ccaFactory,
    ccaUseV2: plan.saleConfig.ccaUseV2,
    saleAmount: BigInt(plan.saleConfig.saleAmount),
    ccaSalt: plan.saleConfig.ccaSalt,
    ccaConfigData: plan.saleConfig.ccaConfigData,
    saleLabel: plan.saleConfig.saleLabel,
    foldInitCodeHash: plan.saleConfig.foldInitCodeHash,
  };
}

function resolvedRecipient(value: string, sender: string): string {
  return value.toLowerCase() === MSG_SENDER_SENTINEL
    ? address(sender, "sender")
    : address(value, "recipient");
}

async function codeAt(
  provider: ethersLib.Provider,
  target: string,
): Promise<string> {
  return provider.getCode(target);
}

async function requireContract(
  provider: ethersLib.Provider,
  target: string,
  label: string,
): Promise<void> {
  const code = await codeAt(provider, target);
  if (code === "0x") throw new Error(`${label} has no code: ${target}`);
}

async function deployedAddress(contract: {
  target?: unknown;
  getAddress?: () => Promise<string>;
}): Promise<string> {
  if (typeof contract.target === "string")
    return address(contract.target, "contract");
  if (contract.getAddress)
    return address(await contract.getAddress(), "contract");
  throw new Error("Could not determine deployed contract address");
}

async function buildSalePlan(
  ethers: Awaited<ReturnType<typeof hre.network.connect>>["ethers"],
  config: SaleConfigFile,
): Promise<SalePlan> {
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  if (chainId !== config.chainId) {
    throw new Error(
      `Connected chainId ${chainId} != config.chainId ${config.chainId}`,
    );
  }

  await requireContract(ethers.provider, config.saleDeployer, "saleDeployer");
  await requireContract(
    ethers.provider,
    config.fold.bondingRegistry,
    "fold.bondingRegistry",
  );

  const saleDeployer = await ethers.getContractAt(
    "InterfoldTokenSaleDeployer",
    config.saleDeployer,
  );
  const protocolAdmin = address(
    await saleDeployer.protocolAdmin(),
    "protocolAdmin",
  );
  if (protocolAdmin !== config.safe) {
    throw new Error(
      `saleDeployer.protocolAdmin mismatch: expected ${config.safe}, got ${protocolAdmin}`,
    );
  }

  const ccaFactory = resolveCcaFactory(config);
  await requireContract(ethers.provider, ccaFactory, "ccaFactory");

  const latest = await ethers.provider.getBlock("latest");
  if (!latest) throw new Error("Could not read latest block");
  const ccaStart = BigInt(config.fold.ccaStart);
  const ccaEnd = BigInt(config.fold.ccaEnd);
  if (ccaStart <= BigInt(latest.timestamp)) {
    throw new Error(
      `fold.ccaStart (${ccaStart}) must be in the future; latest timestamp is ${latest.timestamp}`,
    );
  }
  if (ccaEnd <= ccaStart)
    throw new Error("fold.ccaEnd must be after fold.ccaStart");
  const noMoreLocks = deriveNoMoreLocks(ccaEnd, config.fold.noMoreLocks);

  const factoryNonce = await ethers.provider.getTransactionCount(
    config.saleDeployer,
  );
  const predictedFold = ethersLib.getCreateAddress({
    from: config.saleDeployer,
    nonce: BigInt(factoryNonce),
  });
  const auctionParams = toAuctionParameters(config.auction);
  const ccaConfigData = encodeAuctionConfigData(auctionParams);
  const saleAmount = BigInt(config.saleAmount);
  if (saleAmount > (1n << 128n) - 1n) {
    throw new Error("saleAmount exceeds uint128 max");
  }

  const factoryAbi =
    config.ccaVersion === "v2.0.0" ? CCA_FACTORY_V2_ABI : CCA_FACTORY_V1_ABI;
  const cca = new ethersLib.Contract(ccaFactory, factoryAbi, ethers.provider);
  const predictedAuction =
    config.ccaVersion === "v2.0.0"
      ? await cca["getAddress(address,uint256,bytes,bytes32,address)"](
          predictedFold,
          saleAmount,
          ccaConfigData,
          config.ccaSalt,
          config.saleDeployer,
        )
      : await cca.getAuctionAddress(
          predictedFold,
          saleAmount,
          ccaConfigData,
          config.ccaSalt,
          config.saleDeployer,
        );

  const foldFactory = await ethers.getContractFactory("InterfoldToken");
  const foldInitCode = buildFoldInitCode({
    creationCode: foldFactory.bytecode,
    initialOwner: config.saleDeployer,
    ccaStart,
    ccaEnd,
    noMoreLocks,
    claimSource: predictedAuction,
    bondingRegistry: config.fold.bondingRegistry,
  });
  const foldInitCodeHash = ethersLib.keccak256(foldInitCode);

  const plan: SalePlan = {
    name: config.name,
    chainId,
    saleDeployer: config.saleDeployer,
    safe: config.safe,
    factoryNonce,
    ccaFactory,
    predictedFold,
    predictedAuction: address(predictedAuction, "predictedAuction"),
    fold: {
      initialOwner: config.saleDeployer,
      ccaStart: ccaStart.toString(),
      ccaEnd: ccaEnd.toString(),
      noMoreLocks: noMoreLocks.toString(),
      claimSource: address(predictedAuction, "predictedAuction"),
      bondingRegistry: config.fold.bondingRegistry,
    },
    auction: auctionParams,
    saleConfig: {
      ccaFactory,
      ccaUseV2: config.ccaVersion === "v2.0.0",
      saleAmount: saleAmount.toString(),
      ccaSalt: config.ccaSalt,
      ccaConfigData,
      saleLabel: ethersLib.encodeBytes32String(config.saleLabel),
      foldInitCodeHash,
    },
    foldInitCode,
  };
  plan.configHash = await saleDeployer.hashConfig(saleConfigStruct(plan));
  return plan;
}

function printPlan(plan: SalePlan, planFile: string): void {
  console.log(`
Interfold sale plan
  config:        ${plan.name}
  chainId:       ${plan.chainId}
  safe:          ${plan.safe}
  saleDeployer:  ${plan.saleDeployer}
  factoryNonce:  ${plan.factoryNonce}
  ccaFactory:    ${plan.ccaFactory}
  FOLD:          ${plan.predictedFold}
  CCA auction:   ${plan.predictedAuction}
  bondingRegistry proxy: ${plan.fold.bondingRegistry}
  FOLD timestamps: start=${plan.fold.ccaStart} end=${plan.fold.ccaEnd} noMoreLocks=${plan.fold.noMoreLocks}
  CCA blocks:    start=${plan.auction.startBlock} end=${plan.auction.endBlock} claim=${plan.auction.claimBlock}
  config hash:   ${planConfigHash(plan)}
  plan file:     ${planFile}
`);
}

function planConfigHash(plan: SalePlan): string {
  const hash = plan.configHash ?? plan.configDigest;
  if (!hash)
    throw new Error("Plan is missing configHash. Run --action plan again.");
  return hash;
}

function writeSaleUiManifest(
  config: SaleConfigFile,
  plan: SalePlan,
  deployment: DeploymentFile,
): void {
  const dir = saleUiDir();
  writeJson(path.join(dir, "config.json"), config);
  writeJson(path.join(dir, "plan.json"), plan);
  writeJson(path.join(dir, "deployment.json"), {
    ...deployment,
    saleAmount: config.saleAmount,
    saleLabel: config.saleLabel,
    ccaVersion: config.ccaVersion,
    auctionConfig: config.auction,
    foldSchedule: {
      ccaStart: config.fold.ccaStart,
      ccaEnd: config.fold.ccaEnd,
      noMoreLocks: plan.fold.noMoreLocks,
    },
  });
}

async function deployMockBondingRegistryProxy(
  ethers: Awaited<ReturnType<typeof hre.network.connect>>["ethers"],
  safe: string,
) {
  const implFactory = await ethers.getContractFactory("MockBondingRegistry");
  const impl = await implFactory.deploy();
  await impl.waitForDeployment();
  const implementation = await deployedAddress(impl);

  const proxyFactory = await ethers.getContractFactory(
    "TransparentUpgradeableProxy",
  );
  const proxy = await proxyFactory.deploy(implementation, safe, "0x");
  await proxy.waitForDeployment();
  const proxyAddress = await deployedAddress(proxy);
  const proxyAdmin = await getProxyAdmin(ethers.provider, proxyAddress);

  return { implementation, proxy: proxyAddress, proxyAdmin };
}

async function deploySaleDeployer(
  ethers: Awaited<ReturnType<typeof hre.network.connect>>["ethers"],
  safe: string,
): Promise<string> {
  const factory = await ethers.getContractFactory("InterfoldTokenSaleDeployer");
  const deployer = await factory.deploy(safe);
  await deployer.waitForDeployment();
  return deployedAddress(deployer);
}

async function deployMockCcaFactory(
  ethers: Awaited<ReturnType<typeof hre.network.connect>>["ethers"],
  useV2: boolean,
): Promise<string> {
  const factory = await ethers.getContractFactory("MockCCAFactory");
  const mock = await factory.deploy(useV2, ZERO);
  await mock.waitForDeployment();
  return deployedAddress(mock);
}

function packAuctionStep(mps: bigint, blockDelta: bigint): string {
  if (mps <= 0n || mps > 0xffffffn) {
    throw new Error(`auction step mps out of uint24 range: ${mps}`);
  }
  if (blockDelta <= 0n || blockDelta > 0xffffffffffn) {
    throw new Error(
      `auction step blockDelta out of uint40 range: ${blockDelta}`,
    );
  }
  return ethersLib.zeroPadValue(
    ethersLib.toBeHex((mps << 40n) | blockDelta),
    8,
  );
}

function makeTemplateConfig(opts: {
  name: string;
  chainId: number;
  safe: string;
  saleDeployer: string;
  bondingRegistry: string;
  ccaFactory: string;
  ccaVersion: CcaVersion;
  currentBlock: bigint;
  currentTimestamp: bigint;
}): SaleConfigFile {
  const offsetSeconds = BigInt(arg("cca-offset-seconds") ?? String(DAY));
  const durationSeconds = BigInt(
    arg("cca-duration-seconds") ?? String(7n * DAY),
  );
  const ccaStart = opts.currentTimestamp + offsetSeconds;
  const ccaEnd = ccaStart + durationSeconds;
  const startBlock = opts.currentBlock + 2n;
  const endBlock = startBlock + BigInt(arg("auction-duration-blocks") ?? "40");
  const auctionBlocks = endBlock - startBlock;
  const mps = (10_000_000n + auctionBlocks - 1n) / auctionBlocks;
  const floorPrice = "4295000000";
  return {
    name: opts.name,
    chainId: opts.chainId,
    safe: opts.safe,
    saleDeployer: opts.saleDeployer,
    ccaVersion: opts.ccaVersion,
    ccaFactory: opts.ccaFactory,
    saleAmount: arg("sale-amount") ?? DEFAULT_SALE_AMOUNT,
    ccaSalt: ethersLib.id(`${opts.name}:${opts.chainId}:${Date.now()}`),
    saleLabel: arg("sale-label") ?? "cca-sale",
    fold: {
      ccaStart: ccaStart.toString(),
      ccaEnd: ccaEnd.toString(),
      noMoreLocks: "",
      bondingRegistry: opts.bondingRegistry,
    },
    auction: {
      currency: "ETH",
      tokensRecipient: opts.safe,
      fundsRecipient: opts.safe,
      startBlock: startBlock.toString(),
      endBlock: endBlock.toString(),
      claimBlock: (endBlock + 1n).toString(),
      tickSpacing: "100000",
      validationHook: ZERO,
      floorPrice,
      requiredCurrencyRaised: "0",
      auctionStepsData: packAuctionStep(mps, auctionBlocks),
    },
  };
}

async function actionPrepare(): Promise<void> {
  const { ethers } = await connect();
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  const safe = address(arg("safe") ?? process.env.SAFE_ADDRESS ?? "", "safe");
  if (!hasFlag("allow-eoa-safe")) {
    await requireContract(ethers.provider, safe, "safe");
  }

  const useMockCca = hasFlag("mock-cca");
  const ccaVersion = (arg("cca-version") as CcaVersion | undefined) ?? "v1.1.0";
  if (ccaVersion !== "v1.1.0" && ccaVersion !== "v2.0.0") {
    throw new Error("CCA_VERSION must be v1.1.0 or v2.0.0");
  }

  const registry = await deployMockBondingRegistryProxy(ethers, safe);
  const saleDeployer = await deploySaleDeployer(ethers, safe);
  const ccaFactory = useMockCca
    ? await deployMockCcaFactory(ethers, ccaVersion === "v2.0.0")
    : CCA_FACTORY_ADDRESSES[ccaVersion];

  const latest = await ethers.provider.getBlock("latest");
  if (!latest) throw new Error("Could not read latest block");

  const file = configPath(false);
  const config = fs.existsSync(file)
    ? loadConfig(file)
    : makeTemplateConfig({
        name: arg("name") ?? `${networkName()}-fold-cca`,
        chainId,
        safe,
        saleDeployer,
        bondingRegistry: registry.proxy,
        ccaFactory,
        ccaVersion,
        currentBlock: BigInt(latest.number),
        currentTimestamp: BigInt(latest.timestamp),
      });

  config.chainId = chainId;
  config.safe = safe;
  config.saleDeployer = saleDeployer;
  config.ccaVersion = ccaVersion;
  config.ccaFactory = ccaFactory;
  config.fold.bondingRegistry = registry.proxy;

  writeJson(file, config);
  const infraFile = path.join(saleDir, `${config.name}.infra.json`);
  writeJson(infraFile, {
    chainId,
    safe,
    saleDeployer,
    bondingRegistryProxy: registry.proxy,
    bondingRegistryImplementation: registry.implementation,
    bondingRegistryProxyAdmin: registry.proxyAdmin,
    ccaFactory,
    mockCcaFactory: useMockCca ? ccaFactory : undefined,
  });

  console.log(`
Prepared sale infrastructure
  safe:                         ${safe}
  saleDeployer:                 ${saleDeployer}
  MockBondingRegistry impl:     ${registry.implementation}
  bondingRegistry proxy:        ${registry.proxy}
  bondingRegistry ProxyAdmin:   ${registry.proxyAdmin}
  ccaFactory:                   ${ccaFactory}
  config:                       ${file}
  infra:                        ${infraFile}

Review the config schedule and economics, then run --action plan.
`);
}

async function actionPlan(): Promise<SalePlan> {
  const { ethers } = await connect();
  const config = loadConfig();
  const plan = await buildSalePlan(ethers, config);
  const file = planPath(config);
  writeJson(file, plan);
  printPlan(plan, file);
  return plan;
}

async function readPlanForConfig(config: SaleConfigFile): Promise<SalePlan> {
  const file = planPath(config);
  if (!fs.existsSync(file)) {
    throw new Error(`Plan file not found: ${file}. Run --action plan first.`);
  }
  return readJson<SalePlan>(file);
}

async function deployFromPlan(
  ethers: Awaited<ReturnType<typeof hre.network.connect>>["ethers"],
  config: SaleConfigFile,
  plan: SalePlan,
): Promise<DeploymentFile> {
  const liveNonce = await ethers.provider.getTransactionCount(
    config.saleDeployer,
  );
  if (liveNonce !== plan.factoryNonce) {
    throw new Error(
      `saleDeployer nonce moved: plan=${plan.factoryNonce}, live=${liveNonce}. Run --action plan again.`,
    );
  }

  const deployer = await ethers.getContractAt(
    "InterfoldTokenSaleDeployer",
    config.saleDeployer,
  );
  const [operator] = await ethers.getSigners();
  const operatorAddress = await operator.getAddress();

  console.log(`Submitting deploySale for ${config.name}`);
  console.log(`  expected FOLD:    ${plan.predictedFold}`);
  console.log(`  expected auction: ${plan.predictedAuction}`);

  const tx = await deployer.deploySale(
    saleConfigStruct(plan),
    plan.foldInitCode,
  );
  console.log(`  tx: ${tx.hash}`);
  const receipt = await tx.wait();
  if (!receipt) throw new Error("deploySale transaction was not mined");

  const event = receipt.logs
    .map((log: { topics: ReadonlyArray<string>; data: string }) => {
      try {
        return deployer.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((parsed: { name: string } | null) => parsed?.name === "SaleDeployed");

  const fold = address(event?.args?.fold as string, "SaleDeployed.fold");
  const auction = address(
    event?.args?.auction as string,
    "SaleDeployed.auction",
  );
  if (fold !== plan.predictedFold || auction !== plan.predictedAuction) {
    throw new Error(`Address mismatch: got fold=${fold}, auction=${auction}`);
  }

  const deployment: DeploymentFile = {
    name: config.name,
    chainId: config.chainId,
    txHash: tx.hash,
    blockNumber: receipt.blockNumber,
    operator: operatorAddress,
    safe: config.safe,
    saleDeployer: config.saleDeployer,
    fold,
    auction,
    bondingRegistry: config.fold.bondingRegistry,
    bondingRegistryProxyAdmin: await getProxyAdmin(
      ethers.provider,
      config.fold.bondingRegistry,
    ),
    ccaFactory: plan.ccaFactory,
  };
  writeJson(deploymentPath(config), deployment);
  writeSaleUiManifest(config, plan, deployment);
  if (hasFlag("propose-safe")) {
    const proposal = await proposeSaleSafeActions(config, deployment);
    deployment.safeProposal = proposal;
    writeJson(deploymentPath(config), deployment);
    writeSaleUiManifest(config, plan, deployment);
    console.log(`
Safe transaction proposed
  hash: ${proposal.safeTxHash}
  nonce: ${proposal.nonce}
  url:  ${proposal.url ?? "(open the Safe UI pending queue)"}
`);
  }
  console.log(`
Sale deployed
  FOLD:    ${fold}
  auction: ${auction}
  tx:      ${tx.hash}

Safe action still required:
  to:   ${fold}
  data: 0x79ba5097
  desc: FOLD.acceptOwnership()
`);
  return deployment;
}

async function proposeSaleSafeActions(
  config: SaleConfigFile,
  deployment: DeploymentFile,
): Promise<SafeProposal> {
  const acceptOwnership: MetaTransactionData = {
    to: deployment.fold,
    value: "0",
    data: "0x79ba5097",
    operation: OperationType.Call,
  };
  return proposeSafeTransactions(
    config,
    [acceptOwnership],
    `Interfold ${config.name} FOLD ownership acceptance`,
  );
}

async function actionDeploy(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const plan = await readPlanForConfig(config);
  await deployFromPlan(ethers, config, plan);
}

async function actionAcceptOwnership(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<DeploymentFile>(deploymentPath(config));
  const fold = await ethers.getContractAt("InterfoldToken", deployment.fold);
  const tx = await fold.acceptOwnership();
  await tx.wait();
  console.log(`Accepted FOLD ownership: ${deployment.fold}`);
}

async function actionProposeSafe(): Promise<void> {
  const config = loadConfig();
  const deployment = readJson<DeploymentFile>(deploymentPath(config));
  const proposal = await proposeSaleSafeActions(config, deployment);
  deployment.safeProposal = proposal;
  writeJson(deploymentPath(config), deployment);
  if (fs.existsSync(planPath(config))) {
    writeSaleUiManifest(
      config,
      readJson<SalePlan>(planPath(config)),
      deployment,
    );
  }

  console.log(`
Safe transaction proposed
  hash: ${proposal.safeTxHash}
  nonce: ${proposal.nonce}
  txs:  ${proposal.transactionCount}
  url:  ${proposal.url ?? "(open the Safe UI pending queue)"}
`);
}

async function waitForBlock(
  provider: ethersLib.Provider,
  target: bigint,
): Promise<void> {
  let current = BigInt(await provider.getBlockNumber());
  const network = await provider.getNetwork();
  if (network.chainId === 31337n) {
    while (current < target) {
      await (provider as ethersLib.JsonRpcApiProvider).send("evm_mine", []);
      current = BigInt(await provider.getBlockNumber());
    }
    return;
  }
  while (current < target) {
    console.log(`  waiting for block ${target} (current ${current})`);
    await new Promise((resolve) => setTimeout(resolve, 6000));
    try {
      current = BigInt(await provider.getBlockNumber());
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.log(`  provider retry after block read failure: ${message}`);
    }
  }
}

async function actionBidClaim(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<DeploymentFile>(deploymentPath(config));
  await bidClaim(ethers, config, deployment);
}

async function bidClaim(
  ethers: Awaited<ReturnType<typeof hre.network.connect>>["ethers"],
  config: SaleConfigFile,
  deployment: DeploymentFile,
): Promise<void> {
  const signers = await ethers.getSigners();
  const buyer = signers[1] ?? signers[0];
  const buyerAddress = await buyer.getAddress();

  const auction = new ethersLib.Contract(
    deployment.auction,
    CCA_AUCTION_ABI,
    buyer,
  );
  const fold = await ethers.getContractAt("InterfoldToken", deployment.fold);
  const startBlock = BigInt(await auction.startBlock());
  const endBlock = BigInt(await auction.endBlock());
  const claimBlock = BigInt(await auction.claimBlock());
  const isMockCca =
    hasFlag("mock-cca") || deployment.mockCcaFactory !== undefined;
  const resumeBidId = arg("bid-id") ?? deployment.testBidId;

  const bidValue = ethersLib.parseEther(arg("bid-eth") ?? "0.001");
  let bidId = resumeBidId === undefined ? undefined : BigInt(resumeBidId);
  if (bidId !== undefined) {
    console.log(`Resuming existing bid ${bidId}`);
  } else {
    await waitForBlock(ethers.provider, startBlock);
    try {
      const floorPrice = BigInt(config.auction.floorPrice);
      const tickSpacing = BigInt(config.auction.tickSpacing);
      const maxPrice = BigInt(
        arg("max-price") ?? String(floorPrice + tickSpacing),
      );
      const bidTx = await auction["submitBid(uint256,uint128,address,bytes)"](
        maxPrice,
        bidValue,
        buyerAddress,
        "0x",
        {
          value:
            resolveCurrency(config.auction.currency) === ZERO ? bidValue : 0n,
        },
      );
      const receipt = await bidTx.wait();
      const event = receipt.logs
        .map((log: { topics: ReadonlyArray<string>; data: string }) => {
          try {
            return auction.interface.parseLog(log);
          } catch {
            return null;
          }
        })
        .find(
          (parsed: { name: string } | null) => parsed?.name === "BidSubmitted",
        );
      bidId = BigInt(event?.args?.id ?? 0);
      deployment.testBidId = bidId.toString();
      writeJson(deploymentPath(config), deployment);
      console.log(`Buyer bid submitted: ${bidTx.hash} (bid ${bidId})`);
    } catch (error) {
      if (!isMockCca) throw error;
      const bidTx = await auction.bid({ value: bidValue });
      await bidTx.wait();
      console.log(`Mock buyer bid submitted: ${bidTx.hash}`);
    }
  }

  await waitForBlock(ethers.provider, endBlock + 1n);
  if (bidId !== undefined) {
    if (!isMockCca) {
      try {
        const checkpointTx = await auction.checkpoint();
        await checkpointTx.wait();
        console.log(`Auction checkpoint submitted: ${checkpointTx.hash}`);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.log(`Auction checkpoint skipped: ${message}`);
      }
    }
    try {
      const exitTx = await auction.exitBid(bidId);
      await exitTx.wait();
      console.log(`Buyer bid exited: ${exitTx.hash}`);
    } catch (error) {
      if (isMockCca) throw error;
      const bid = await auction.bids(bidId);
      const partialExitTx = await auction.exitPartiallyFilledBid(
        bidId,
        bid.startBlock,
        0,
      );
      await partialExitTx.wait();
      console.log(`Buyer partially filled bid exited: ${partialExitTx.hash}`);
    }
  }
  await waitForBlock(ethers.provider, claimBlock);
  const claimTx =
    bidId !== undefined
      ? await auction.claimTokens(bidId)
      : await auction.claim();
  await claimTx.wait();
  console.log(`Buyer claim submitted: ${claimTx.hash}`);

  const balance = await fold.balanceOf(buyerAddress);
  const lockCount = await fold.lockCount(buyerAddress);
  if (balance === 0n) throw new Error("Buyer did not receive FOLD");
  if (lockCount === 0n)
    throw new Error("Buyer claim did not create a FOLD lock");
  await expectTransferRestricted(fold.connect(buyer), deployment.safe);
  console.log(
    `Buyer ${buyerAddress} claimed ${balance} FOLD wei with ${lockCount} lock entry`,
  );
  if (bidId !== undefined) {
    deployment.testBidId = bidId.toString();
    writeJson(deploymentPath(config), deployment);
    if (fs.existsSync(planPath(config))) {
      writeSaleUiManifest(
        config,
        readJson<SalePlan>(planPath(config)),
        deployment,
      );
    }
  }
}

async function expectTransferRestricted(fold: any, to: string): Promise<void> {
  try {
    await fold.transfer.staticCall(to, 1n);
  } catch {
    return;
  }
  throw new Error("Expected claimed FOLD to be transfer-restricted before TGE");
}

function assertEq(label: string, actual: unknown, expected: unknown): void {
  if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
  console.log(`  ok ${label}`);
}

async function optionalView<T>(
  label: string,
  read: () => Promise<T>,
): Promise<T | undefined> {
  try {
    return await read();
  } catch {
    console.log(`  skip ${label} (view not available)`);
    return undefined;
  }
}

async function actionValidate(): Promise<void> {
  const { ethers } = await connect();
  const config = loadConfig();
  const deployment = readJson<DeploymentFile>(deploymentPath(config));
  const plan = fs.existsSync(planPath(config))
    ? await readPlanForConfig(config)
    : await buildSalePlan(ethers, config);
  await validateDeployment(ethers, config, deployment, plan);
}

async function validateDeployment(
  ethers: Awaited<ReturnType<typeof hre.network.connect>>["ethers"],
  config: SaleConfigFile,
  deployment: DeploymentFile,
  plan: SalePlan,
  allowPendingOwner = hasFlag("allow-pending-owner"),
): Promise<void> {
  const saleDeployer = await ethers.getContractAt(
    "InterfoldTokenSaleDeployer",
    deployment.saleDeployer,
  );
  const fold = await ethers.getContractAt("InterfoldToken", deployment.fold);
  const auction = new ethersLib.Contract(
    deployment.auction,
    CCA_AUCTION_ABI,
    ethers.provider,
  );

  console.log(`Validating ${deployment.name}`);
  assertEq(
    "saleDeployer.protocolAdmin",
    await saleDeployer.protocolAdmin(),
    config.safe,
  );
  assertEq("FOLD.CLAIM_SOURCE", await fold.CLAIM_SOURCE(), deployment.auction);
  assertEq(
    "FOLD.BONDING_REGISTRY",
    await fold.BONDING_REGISTRY(),
    config.fold.bondingRegistry,
  );
  await requireContract(
    ethers.provider,
    config.fold.bondingRegistry,
    "bondingRegistry",
  );
  assertEq("auction.token", await auction.token(), deployment.fold);
  assertEq(
    "auction.totalSupply",
    await auction.totalSupply(),
    config.saleAmount,
  );
  assertEq(
    "auction.currency",
    await auction.currency(),
    resolveCurrency(config.auction.currency),
  );
  assertEq(
    "auction.tokensRecipient",
    await auction.tokensRecipient(),
    resolvedRecipient(config.auction.tokensRecipient, config.saleDeployer),
  );
  assertEq(
    "auction.fundsRecipient",
    await auction.fundsRecipient(),
    resolvedRecipient(config.auction.fundsRecipient, config.saleDeployer),
  );
  assertEq(
    "auction.startBlock",
    await auction.startBlock(),
    config.auction.startBlock,
  );
  assertEq(
    "auction.endBlock",
    await auction.endBlock(),
    config.auction.endBlock,
  );
  assertEq(
    "auction.claimBlock",
    await auction.claimBlock(),
    config.auction.claimBlock,
  );
  const hook = await optionalView("auction.validationHook", () =>
    auction.validationHook(),
  );
  if (hook !== undefined)
    assertEq("auction.validationHook", hook, config.auction.validationHook);
  const tokensReceived = await optionalView("auction.tokensReceived", () =>
    auction.tokensReceived(),
  );
  if (tokensReceived !== undefined)
    assertEq("auction.tokensReceived", tokensReceived, true);
  const auctionBalance = await fold.balanceOf(deployment.auction);
  const saleAmount = BigInt(config.saleAmount);
  if (auctionBalance > saleAmount) {
    throw new Error(
      `FOLD auction balance exceeds sale amount: ${auctionBalance} > ${saleAmount}`,
    );
  }
  const currentBlock = BigInt(await ethers.provider.getBlockNumber());
  const claimBlock = BigInt(config.auction.claimBlock);
  if (currentBlock < claimBlock) {
    assertEq("FOLD auction balance", auctionBalance, saleAmount);
  } else {
    console.log(`  ok FOLD auction balance <= sale amount (${auctionBalance})`);
  }
  assertEq("FOLD.CCA_START", await fold.CCA_START(), config.fold.ccaStart);
  assertEq("FOLD.CCA_END", await fold.CCA_END(), config.fold.ccaEnd);
  assertEq(
    "FOLD.NO_MORE_LOCKS",
    await fold.NO_MORE_LOCKS(),
    plan.fold.noMoreLocks,
  );
  assertEq("FOLD.tgeTimestamp", await fold.tgeTimestamp(), 0);
  assertEq(
    "used config hash",
    await saleDeployer.usedConfigHashes(planConfigHash(plan)),
    true,
  );

  const owner = address(await fold.owner(), "FOLD.owner");
  if (owner === config.safe) {
    const defaultAdminRole = ethersLib.ZeroHash;
    assertEq(
      "Safe DEFAULT_ADMIN_ROLE",
      await fold.hasRole(defaultAdminRole, config.safe),
      true,
    );
    if (address(deployment.operator, "deployment.operator") !== config.safe) {
      assertEq(
        "operator DEFAULT_ADMIN_ROLE",
        await fold.hasRole(defaultAdminRole, deployment.operator),
        false,
      );
    } else {
      console.log(
        "  skip operator DEFAULT_ADMIN_ROLE (operator is Safe in this run)",
      );
    }
    assertEq(
      "factory DEFAULT_ADMIN_ROLE",
      await fold.hasRole(defaultAdminRole, config.saleDeployer),
      false,
    );
    assertEq(
      "Safe MINTER_ROLE",
      await fold.hasRole(ethersLib.id("MINTER_ROLE"), config.safe),
      true,
    );
    assertEq(
      "Safe WHITELIST_ROLE",
      await fold.hasRole(ethersLib.id("WHITELIST_ROLE"), config.safe),
      true,
    );
    assertEq(
      "Safe LOCK_MANAGER_ROLE",
      await fold.hasRole(ethersLib.id("LOCK_MANAGER_ROLE"), config.safe),
      true,
    );
  } else {
    const pendingOwner = address(
      await fold.pendingOwner(),
      "FOLD.pendingOwner",
    );
    if (allowPendingOwner && pendingOwner === config.safe) {
      console.log("  ok FOLD ownership is pending Safe acceptance");
    } else {
      throw new Error(
        `FOLD owner is ${owner}; expected accepted Safe ${config.safe}`,
      );
    }
  }

  console.log("Validation complete");
}

async function actionFullTest(): Promise<void> {
  const { ethers } = await connect();
  const network = await ethers.provider.getNetwork();
  if (
    network.chainId === 1n &&
    process.env.ALLOW_MAINNET_FULL_TEST !== "true"
  ) {
    throw new Error("Refusing to run mock full-test on mainnet");
  }
  const [operator] = await ethers.getSigners();
  const operatorAddress = await operator.getAddress();

  const safeInput = arg("safe") ?? process.env.SAFE_ADDRESS;
  const safe = safeInput ? address(safeInput, "safe") : operatorAddress;
  const registry = await deployMockBondingRegistryProxy(ethers, safe);
  const useMockCca = hasFlag("mock-cca") || network.chainId === 31337n;
  const ccaFactory = useMockCca
    ? await deployMockCcaFactory(ethers, false)
    : CCA_FACTORY_ADDRESSES["v1.1.0"];
  const saleDeployer = await deploySaleDeployer(ethers, safe);
  const latest = await ethers.provider.getBlock("latest");
  if (!latest) throw new Error("Could not read latest block");
  const name = arg("name") ?? `${networkName()}-sale-dry-run-${Date.now()}`;
  const config = makeTemplateConfig({
    name,
    chainId: Number(network.chainId),
    safe,
    saleDeployer,
    bondingRegistry: registry.proxy,
    ccaFactory,
    ccaVersion: "v1.1.0",
    currentBlock: BigInt(latest.number),
    currentTimestamp: BigInt(latest.timestamp),
  });
  const configFile = path.join(saleDir, `${name}.config.json`);
  writeJson(configFile, config);

  const plan = await buildSalePlan(ethers, config);
  const planFile = planPath(config);
  writeJson(planFile, plan);
  printPlan(plan, planFile);

  const deployment = await deployFromPlan(ethers, config, plan);
  if (useMockCca) deployment.mockCcaFactory = ccaFactory;
  deployment.bondingRegistryProxyAdmin = registry.proxyAdmin;
  writeJson(deploymentPath(config), deployment);
  writeSaleUiManifest(config, plan, deployment);
  if (safe === operatorAddress) {
    const fold = await ethers.getContractAt("InterfoldToken", deployment.fold);
    await (await fold.acceptOwnership()).wait();
    console.log(`Accepted FOLD ownership: ${deployment.fold}`);
  } else {
    console.log(
      `FOLD ownership is pending Safe acceptance. Run acceptOwnership from ${safe}.`,
    );
  }
  await validateDeployment(
    ethers,
    config,
    deployment,
    plan,
    safe !== operatorAddress,
  );
  await bidClaim(ethers, config, deployment);

  console.log(`
Full Sepolia/local rehearsal complete
  config:     ${configFile}
  plan:       ${planFile}
  deployment: ${deploymentPath(config)}
  FOLD:       ${deployment.fold}
  auction:    ${deployment.auction}
`);
}

function printHelp(): void {
  console.log(`
Interfold FOLD sale pipeline

One script, selected by --action:
  --action prepare      Deploy Safe-owned MockBondingRegistry proxy + sale deployer
  --action plan         Predict FOLD/CCA and write the plan
  --action deploy       Operator submits deploySale
  --action propose-safe Propose FOLD.acceptOwnership() through the Safe SDK
  --action validate     Check FOLD/CCA/Safe invariants
  --action bid-claim    Submit a CCA bid, exit, and claim FOLD
  --action full-test    Self-contained Sepolia/local rehearsal

Common flags:
  --safe 0x...              Required for --action prepare unless SAFE_ADDRESS is set
  --config <file>           Defaults to packages/interfold-contracts/deploy/sale/<network>-sale.config.json
  --plan <file>             Optional plan path override
  --deployment <file>       Optional deployment path override
  --mock-cca                Local fallback only; Sepolia/mainnet use real CCA factories by default
  --auction-duration-blocks N  CCA length in blocks (default 40)
  --cca-offset-seconds N    Seconds until FOLD CCA_START from now (default 86400 = 1 day)
  --cca-duration-seconds N  Seconds FOLD CCA lasts (default 604800 = 7 days)

Examples:
  pnpm sale --network sepolia --action full-test
  pnpm sale --network mainnet --action prepare --safe 0xSafe --config packages/interfold-contracts/deploy/sale/mainnet-sale.config.json
  pnpm sale --network mainnet --action plan --config packages/interfold-contracts/deploy/sale/mainnet-sale.config.json
  pnpm sale --network mainnet --action deploy --config packages/interfold-contracts/deploy/sale/mainnet-sale.config.json --propose-safe
  pnpm sale --network mainnet --action propose-safe --config packages/interfold-contracts/deploy/sale/mainnet-sale.config.json
`);
}

async function main(): Promise<void> {
  const action = (arg("action") ?? "help").toLowerCase();
  if (action === "help") return printHelp();
  if (action === "prepare") return actionPrepare();
  if (action === "plan") return void (await actionPlan());
  if (action === "deploy") return actionDeploy();
  if (action === "propose-safe") return actionProposeSafe();
  if (action === "accept-ownership") return actionAcceptOwnership();
  if (action === "validate") return actionValidate();
  if (action === "bid-claim") return actionBidClaim();
  if (action === "full-test") return actionFullTest();
  throw new Error(`Unknown --action: ${action}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
