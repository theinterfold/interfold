// packages/ckks-fedavg-sdk/src/types.ts
var FEDAVG_PARAM_SET = 5;
var N = 512;
var D = 8;
var WEIGHT_FRAC_BITS = 16;
var WEIGHT_SCALE = 2 ** WEIGHT_FRAC_BITS;
var ENTRY_BOUND = 1;
var NORM_FRAC_BITS = 32;
var NORM_SCALE = 2 ** NORM_FRAC_BITS;
var COUNT_BOUND = 1024;
var OUTPUT_COUNT = 64;
var OUTPUT_DECIMALS = 4;
var CIRCUIT_NAMES = {
  ct0: "user_data_encryption_ckks_ct0_ps5",
  ct1: "user_data_encryption_ckks_ct1_ps5",
  app: "ckks_fedavg_validity_ps5"
};

// packages/ckks-fedavg-sdk/src/circuits.ts
var registered = null;
var setCircuits = (bundle) => {
  registered = bundle;
};
var requireCircuits = () => {
  if (!registered) {
    throw new Error("No CKKS fedavg circuits registered. Load the three compiled circuits and call setCircuits() before proving.");
  }
  return registered;
};

// packages/ckks-fedavg-sdk/src/apply.ts
import { Barretenberg, BackendType, UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { getAddress } from "viem";
var SRS_SIZE = 2 ** 18;
var _api = null;
var _apiInit = null;
var getBBApi = async () => {
  if (_api) return _api;
  if (!_apiInit) {
    _apiInit = (async () => {
      const backend = typeof window === "undefined" ? { backend: BackendType.Wasm } : {};
      const api = await Barretenberg.new({ srsSize: SRS_SIZE, ...backend });
      _api = api;
      return api;
    })();
  }
  return _apiInit;
};
var destroyBBApi = async () => {
  if (_api) await _api.destroy();
  _api = null;
  _apiInit = null;
};
var _wasm = null;
var loadWasm = async () => {
  if (_wasm) return _wasm;
  const init = (await import("@interfold/ckks-zk-inputs/init")).default;
  await init();
  _wasm = await import("@interfold/ckks-zk-inputs");
  return _wasm;
};
var word = (value) => `0x${value.toString(16).padStart(64, "0")}`;
var bytesToHex = (bytes) => `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
var normalizeWords = (inputs) => inputs.map((h) => word(BigInt(h)));
var BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
var signedField = (v) => {
  const b = BigInt(v);
  return b >= 0n ? b : BN254_R + b;
};
var signedWord = (v) => word(signedField(v));
var toFixedPointUpdate = (g) => g.map((v) => Math.round(v * WEIGHT_SCALE));
var fromFixedPointUpdate = (fixed) => fixed.map((v) => v / WEIGHT_SCALE);
var squaredNormFixedPoint = (fixed) => fixed.reduce((acc, g) => acc + BigInt(g) * BigInt(g), 0n);
var squaredNorm = (fixed) => Number(squaredNormFixedPoint(fixed)) / NORM_SCALE;
var normBoundFixedPoint = (bound) => Math.floor(bound * NORM_SCALE);
var gradientBlockLayout = (g, n = N) => {
  if (g.length + 2 > 64) throw new Error("gradient block does not fit the 64-coefficient output window");
  const c = new Array(n).fill(0);
  g.forEach((v, j) => {
    c[j + 1] = v;
  });
  c[g.length + 1] = 1;
  return c;
};
var constantLayout = (v, n = N) => {
  const c = new Array(n).fill(0);
  c[0] = v;
  return c;
};
var checkUpdate = (slot, update, count, sender) => {
  if (slot.d !== D) throw new Error(`round d = ${slot.d} but the circuit is compiled for d = ${D}`);
  if (update.length !== D) throw new Error(`expected ${D} update entries, got ${update.length}`);
  for (const [j, g] of update.entries()) {
    if (!Number.isFinite(g) || Math.abs(g) > ENTRY_BOUND) throw new Error(`entry ${j} = ${g} outside \xB1${ENTRY_BOUND} (the circuit rejects it)`);
  }
  const fixed = toFixedPointUpdate(update);
  const boundFp = BigInt(normBoundFixedPoint(slot.normBound));
  if (BigInt(slot.normBoundFixedPoint) !== boundFp) throw new Error(`server bound ${slot.normBoundFixedPoint} \u2260 floor(${slot.normBound} \xB7 2^32)`);
  const norm = squaredNormFixedPoint(fixed);
  if (norm > boundFp) throw new Error(`squared norm ${Number(norm) / NORM_SCALE} exceeds the round bound ${slot.normBound} (the circuit rejects it)`);
  if (!Number.isInteger(count) || count < 1 || count >= COUNT_BOUND) throw new Error(`sample count ${count} is not in [1, ${COUNT_BOUND})`);
  if (!Number.isInteger(slot.index) || slot.index < 0 || slot.index >= 1 << 16) throw new Error(`slot index ${slot.index} out of range`);
  if (getAddress(slot.address) !== getAddress(sender)) throw new Error("slot is for a different address than the sender");
  return fixed;
};
var encryptAndProveUpdate = async (publicKey, slot, update, count, sender, onProgress = () => {
}) => {
  const fixed = checkUpdate(slot, update, count, sender);
  const circuits = requireCircuits();
  const t0 = performance.now();
  const elapsed = () => performance.now() - t0;
  const zero = { ct0G: 0, ct1G: 0, ct0C: 0, ct1C: 0, app: 0 };
  const timings = { encryptMs: 0, executeMs: { ...zero }, proveMs: { ...zero }, backendInitMs: 0, totalMs: 0 };
  onProgress({ stage: "encrypt" }, elapsed());
  const wasm = await loadWasm();
  let t = performance.now();
  const grad = wasm.encryptCoefficientsAndWitness(FEDAVG_PARAM_SET, publicKey, Float64Array.from(gradientBlockLayout(fromFixedPointUpdate(fixed))), void 0);
  const cnt = wasm.encryptCoefficientsAndWitness(FEDAVG_PARAM_SET, publicKey, Float64Array.from(constantLayout(count)), void 0);
  timings.encryptMs = performance.now() - t;
  const appInputs = {
    m_grad: grad.ct0_inputs.m,
    m_count: cnt.ct0_inputs.m,
    g: fixed.map((v) => signedField(v).toString()),
    count: count.toString(),
    norm_bound: slot.normBoundFixedPoint.toString(),
    address: BigInt(getAddress(sender)).toString(),
    index: slot.index.toString()
  };
  onProgress({ stage: "backend" }, elapsed());
  t = performance.now();
  const api = await getBBApi();
  timings.backendInitMs = performance.now() - t;
  const legs = [
    { name: "app", circuit: "app", inputs: appInputs, expectPublic: 5 },
    { name: "ct1G", circuit: "ct1", inputs: grad.ct1_inputs, expectPublic: 3 },
    { name: "ct0G", circuit: "ct0", inputs: grad.ct0_inputs, expectPublic: 4 },
    { name: "ct1C", circuit: "ct1", inputs: cnt.ct1_inputs, expectPublic: 3 },
    { name: "ct0C", circuit: "ct0", inputs: cnt.ct0_inputs, expectPublic: 4 }
  ];
  const proven = {};
  for (const leg of legs) {
    const circuit = circuits[leg.circuit];
    onProgress({ stage: "execute", leg: leg.name }, elapsed());
    t = performance.now();
    const { witness } = await new Noir(circuit).execute(leg.inputs);
    timings.executeMs[leg.name] = performance.now() - t;
    onProgress({ stage: "prove", leg: leg.name }, elapsed());
    t = performance.now();
    const backend = new UltraHonkBackend(circuit.bytecode, api);
    const proof = await backend.generateProof(witness, { verifierTarget: "evm" });
    timings.proveMs[leg.name] = performance.now() - t;
    if (proof.publicInputs.length !== leg.expectPublic) {
      throw new Error(`${leg.name}: expected ${leg.expectPublic} public inputs, got ${proof.publicInputs.length}`);
    }
    proven[leg.name] = { proof: bytesToHex(proof.proof), publicInputs: normalizeWords(proof.publicInputs) };
  }
  const uG = word(BigInt(grad.u_commitment_hex));
  const uC = word(BigInt(cnt.u_commitment_hex));
  const mG = word(BigInt(grad.m_commitment_hex));
  const mC = word(BigInt(cnt.m_commitment_hex));
  if (proven.ct0G.publicInputs[3] !== uG || proven.ct1G.publicInputs[2] !== uG) throw new Error("u_commitment mismatch on the gradient legs");
  if (proven.ct0C.publicInputs[3] !== uC || proven.ct1C.publicInputs[2] !== uC) throw new Error("u_commitment mismatch on the count legs");
  if (proven.ct0G.publicInputs[2] !== mG || proven.app.publicInputs[3] !== mG) throw new Error("m_commitment_grad mismatch between the ct0 and app legs");
  if (proven.ct0C.publicInputs[2] !== mC || proven.app.publicInputs[4] !== mC) throw new Error("m_commitment_count mismatch between the ct0 and app legs");
  if (proven.app.publicInputs[0] !== word(BigInt(slot.normBoundFixedPoint))) throw new Error("norm bound differs from the circuit public input");
  if (proven.app.publicInputs[2] !== word(BigInt(slot.index))) throw new Error("slot index differs from the circuit public input");
  timings.totalMs = elapsed();
  onProgress({ stage: "done" }, timings.totalMs);
  return {
    ciphertextG: `0x${grad.ciphertext_hex}`,
    ciphertextC: `0x${cnt.ciphertext_hex}`,
    ct0G: proven.ct0G,
    ct1G: proven.ct1G,
    ct0C: proven.ct0C,
    ct1C: proven.ct1C,
    app: proven.app,
    mCommitmentG: mG,
    mCommitmentC: mC,
    uCommitmentG: uG,
    uCommitmentC: uC,
    index: slot.index,
    fixedPointUpdate: fixed,
    squaredNorm: squaredNorm(fixed),
    count,
    timings
  };
};
var weightedMean = (opened, d) => {
  if (opened.length < d + 2) throw new Error(`opened output has ${opened.length} coefficients, need ${d + 2}`);
  const totalCount = opened[d + 1];
  if (!(totalCount > 0.5)) throw new Error(`total sample count ${totalCount} is not positive`);
  return { mean: opened.slice(1, d + 1).map((v) => v / totalCount), totalCount };
};
var expectedWeightedMean = (updates) => {
  const d = updates[0]?.update.length ?? 0;
  const totalCount = updates.reduce((a, u) => a + u.count, 0);
  const mean = new Array(d).fill(0);
  for (const { update, count } of updates) update.forEach((g, j) => mean[j] += count * g);
  return { mean: mean.map((m) => m / totalCount), totalCount };
};

// packages/ckks-fedavg-sdk/src/chain.ts
import { decodeAbiParameters, encodeAbiParameters, parseAbi, parseAbiParameters } from "viem";
var FIVE_LEG_ENVELOPE = parseAbiParameters(
  "((bytes, bytes, bytes32[], bytes, bytes32[]), (bytes, bytes, bytes32[], bytes, bytes32[]), bytes, bytes32[])"
);
var FEDAVG_PROGRAM_ABI = parseAbi([
  "struct Round { uint256 normBound; uint256 minClients; bool registered; }",
  "function publishInput(uint256 e3Id, bytes data)",
  "function registerRound(uint256 e3Id, uint256 normBound, uint256 minClients, address[] clientList)",
  "function round(uint256 e3Id) view returns (Round)",
  "function clients(uint256 e3Id) view returns (address[])",
  "function clientSlot(uint256 e3Id, address client) view returns (uint256)",
  "function submissionCount(uint256 e3Id) view returns (uint256)",
  "function hasSubmitted(uint256 e3Id, address client) view returns (bool)",
  "function seenUCommitments(uint256 e3Id, bytes32 u) view returns (bool)",
  "function meanFromOutput(bytes plaintextOutput) pure returns (int128[8] mean, int128 totalCount)",
  "event UpdatePublished(uint256 indexed e3Id, address indexed client, uint256 index, bytes32 gradientCiphertextHash, bytes32 countCiphertextHash, bytes32 mCommitmentGrad, bytes32 mCommitmentCount)",
  "event RoundRegistered(uint256 indexed e3Id, uint256 normBound, uint256 minClients, uint256 clients)",
  "error InvalidVerifierAddress()",
  "error NotOwner()",
  "error InvalidNormBound()",
  "error InvalidMinClients(uint256 minClients, uint256 clients)",
  "error RoundAlreadyRegistered(uint256 e3Id)",
  "error RoundNotRegistered(uint256 e3Id)",
  "error NoClients()",
  "error DuplicateClient(address client)",
  "error InvalidInputEncoding()",
  "error WrongPublicInputCount(uint256 leg, uint256 got, uint256 want)",
  "error UCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 ct1Leg)",
  "error MCommitmentMismatch(uint256 ciphertext, bytes32 ct0Leg, bytes32 appLeg)",
  "error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment)",
  "error AlreadySubmitted(uint256 e3Id, address client)",
  "error WrongNormBound(uint256 got, uint256 want)",
  "error WrongSender(address proven, address sender)",
  "error NotRegistered(uint256 e3Id, address client)",
  "error WrongIndex(uint256 got, uint256 want)",
  "error Ct0ProofInvalid(uint256 ciphertext)",
  "error Ct1ProofInvalid(uint256 ciphertext)",
  "error AppProofInvalid()",
  "error InvalidOutputLength(uint256 length)",
  "error ZeroTotalCount()"
]);
var PUBLISH_GAS_LIMIT = 29000000n;
var encodeUpdateEnvelope = (s) => encodeAbiParameters(FIVE_LEG_ENVELOPE, [
  [
    [s.ciphertextG, s.ct0G.proof, s.ct0G.publicInputs, s.ct1G.proof, s.ct1G.publicInputs],
    [s.ciphertextC, s.ct0C.proof, s.ct0C.publicInputs, s.ct1C.proof, s.ct1C.publicInputs],
    s.app.proof,
    s.app.publicInputs
  ]
]);
var decodeCiphertextsFromCalldata = (input) => {
  const args = decodeAbiParameters(parseAbiParameters("uint256, bytes"), `0x${input.slice(10)}`);
  const decoded = decodeAbiParameters(FIVE_LEG_ENVELOPE, args[1]);
  return { gradient: decoded[0][0][0], count: decoded[0][1][0] };
};
var publishUpdate = async (walletClient, publicClient, program, e3Id, submission) => {
  const account = walletClient.account;
  if (!account) throw new Error("wallet has no account");
  const data = encodeUpdateEnvelope(submission);
  const { request } = await publicClient.simulateContract({
    account,
    address: program,
    abi: FEDAVG_PROGRAM_ABI,
    functionName: "publishInput",
    args: [e3Id, data],
    gas: PUBLISH_GAS_LIMIT
  });
  const hash = await walletClient.writeContract(request);
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error(`update transaction reverted: ${hash}`);
  return { hash, gasUsed: receipt.gasUsed, blockNumber: receipt.blockNumber };
};

// packages/ckks-fedavg-sdk/src/api.ts
var FedAvgApi = class {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
  }
  async get(path) {
    const res = await fetch(`${this.baseUrl}${path}`);
    if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`);
    return await res.json();
  }
  async post(path, body) {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`);
    return await res.json();
  }
  status = () => this.get("/status");
  rounds = () => this.get("/rounds");
  round = (e3Id) => this.get(`/rounds/${e3Id}`);
  slot = (e3Id, address) => this.get(`/rounds/${e3Id}/slot/${address}`);
  publicKey = async (e3Id) => {
    const { publicKeyHex } = await this.get(`/rounds/${e3Id}/public-key`);
    const hex = publicKeyHex.slice(2);
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
    return out;
  };
  /** Admin: open a round with a registered client list and the public parameters. */
  createRound = (clients, params, durationSecs) => this.post("/rounds/request", { clients, ...params, durationSecs });
  /** Admin: run the federated-average policy + publish the ciphertext output (requires minClients). */
  evaluate = (e3Id) => this.post(`/rounds/${e3Id}/evaluate`, {});
};
export {
  BN254_R,
  CIRCUIT_NAMES,
  COUNT_BOUND,
  D,
  ENTRY_BOUND,
  FEDAVG_PARAM_SET,
  FEDAVG_PROGRAM_ABI,
  FIVE_LEG_ENVELOPE,
  FedAvgApi,
  N,
  NORM_FRAC_BITS,
  NORM_SCALE,
  OUTPUT_COUNT,
  OUTPUT_DECIMALS,
  PUBLISH_GAS_LIMIT,
  SRS_SIZE,
  WEIGHT_FRAC_BITS,
  WEIGHT_SCALE,
  checkUpdate,
  constantLayout,
  decodeCiphertextsFromCalldata,
  destroyBBApi,
  encodeUpdateEnvelope,
  encryptAndProveUpdate,
  expectedWeightedMean,
  fromFixedPointUpdate,
  getBBApi,
  gradientBlockLayout,
  normBoundFixedPoint,
  publishUpdate,
  requireCircuits,
  setCircuits,
  signedField,
  signedWord,
  squaredNorm,
  squaredNormFixedPoint,
  toFixedPointUpdate,
  weightedMean,
  word
};
