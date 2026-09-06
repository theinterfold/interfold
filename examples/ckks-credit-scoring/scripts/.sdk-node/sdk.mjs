// packages/ckks-credit-sdk/src/types.ts
var CREDIT_PARAM_SET = 4;
var FEATURES = 8;
var MASK_BITS = 20;
var MASK_FRAC_BITS = 10;
var MASK_SCALE = 2 ** MASK_FRAC_BITS;
var APPLICANT_STRIDE = 16;
var MERKLE_MAX_DEPTH = 20;
var CIRCUIT_NAMES = {
  ct0: "user_data_encryption_ckks_ct0_ps4",
  ct1: "user_data_encryption_ckks_ct1_ps4",
  app: "ckks_credit_validity_ps4"
};

// packages/ckks-credit-sdk/src/featureTree.ts
import { poseidon2, poseidon9 } from "poseidon-lite";
import { getAddress } from "viem";
var featureLeaf = (address, features) => {
  if (features.length !== FEATURES) throw new Error(`expected ${FEATURES} features`);
  return poseidon9([BigInt(address), ...features.map((x) => BigInt(x))]);
};
var toRootHex = (root) => `0x${root.toString(16).padStart(64, "0")}`;
var FeatureTree = class {
  depth;
  levels;
  entries;
  constructor(entries) {
    if (entries.length === 0) throw new Error("feature tree needs a leaf");
    this.entries = entries.map((e) => ({ address: getAddress(e.address), features: e.features }));
    this.depth = Math.max(1, Math.ceil(Math.log2(entries.length)));
    if (this.depth > MERKLE_MAX_DEPTH) throw new Error(`tree depth ${this.depth} exceeds circuit max ${MERKLE_MAX_DEPTH}`);
    const leaves = this.entries.map((e) => featureLeaf(e.address, e.features));
    while (leaves.length < 1 << this.depth) leaves.push(0n);
    this.levels = [leaves];
    for (let l = 0; l < this.depth; l++) {
      const prev = this.levels[l];
      const next = [];
      for (let i = 0; i < prev.length; i += 2) next.push(poseidon2([prev[i], prev[i + 1]]));
      this.levels.push(next);
    }
  }
  root() {
    return this.levels[this.depth][0];
  }
  rootHex() {
    return toRootHex(this.root());
  }
};
var rootFromProof = (proof) => {
  let node = featureLeaf(proof.address, proof.features);
  for (let i = 0; i < proof.depth; i++) {
    const sibling = BigInt(proof.siblings[i]);
    node = proof.indices[i] ? poseidon2([sibling, node]) : poseidon2([node, sibling]);
  }
  return toRootHex(node);
};

// packages/ckks-credit-sdk/src/circuits.ts
var registered = null;
var setCircuits = (bundle) => {
  registered = bundle;
};
var requireCircuits = () => {
  if (!registered) {
    throw new Error("No CKKS credit circuits registered. Load the three compiled circuits and call setCircuits() before proving.");
  }
  return registered;
};

// packages/ckks-credit-sdk/src/apply.ts
import { Barretenberg, BackendType, UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { getAddress as getAddress2 } from "viem";
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
var sampleMasks = () => {
  const out = new Uint32Array(FEATURES);
  crypto.getRandomValues(out);
  return Array.from(out, (v) => v % (1 << MASK_BITS));
};
var checkApplication = (proof, masks, sender) => {
  if (proof.features.length !== FEATURES) throw new Error(`expected ${FEATURES} features`);
  if (!Number.isInteger(proof.cap) || proof.cap <= 0) throw new Error("cap must be a positive integer");
  for (const [j, x] of proof.features.entries()) {
    if (!Number.isInteger(x) || x < 0) throw new Error(`feature ${j} must be a non-negative integer`);
    if (x > proof.cap) throw new Error(`feature ${j} = ${x} exceeds the cap ${proof.cap} (the circuit rejects it)`);
  }
  if (masks.length !== FEATURES) throw new Error(`expected ${FEATURES} masks`);
  for (const [j, m] of masks.entries()) {
    if (!Number.isInteger(m) || m < 0 || m >= 1 << MASK_BITS) throw new Error(`mask ${j} = ${m} is not in [0, 2^${MASK_BITS})`);
  }
  if (getAddress2(proof.address) !== getAddress2(sender)) throw new Error("feature proof is for a different address than the sender");
  if (proof.depth > MERKLE_MAX_DEPTH) throw new Error(`feature proof depth ${proof.depth} exceeds ${MERKLE_MAX_DEPTH}`);
  if (proof.indices.length !== proof.depth || proof.siblings.length !== proof.depth) throw new Error("feature proof path length mismatch");
  if (rootFromProof(proof).toLowerCase() !== proof.merkleRoot.toLowerCase()) throw new Error("feature proof does not open to its root");
};
var buildAppInputs = (credit, proof) => {
  const indices = new Array(MERKLE_MAX_DEPTH).fill(false);
  const siblings = new Array(MERKLE_MAX_DEPTH).fill("0");
  for (let i = 0; i < proof.depth; i++) {
    indices[i] = proof.indices[i];
    siblings[i] = proof.siblings[i];
  }
  return {
    m: credit.m,
    features: credit.features,
    masks: credit.masks,
    cap: credit.cap,
    address: BigInt(getAddress2(proof.address)).toString(),
    merkle_root: BigInt(proof.merkleRoot).toString(),
    depth: String(proof.depth),
    indices,
    siblings
  };
};
var encryptAndProveApplication = async (publicKey, featureProof, sender, masks = sampleMasks(), onProgress = () => {
}) => {
  checkApplication(featureProof, masks, sender);
  const circuits = requireCircuits();
  const t0 = performance.now();
  const elapsed = () => performance.now() - t0;
  const timings = {
    encryptMs: 0,
    executeMs: { ct0: 0, ct1: 0, app: 0 },
    proveMs: { ct0: 0, ct1: 0, app: 0 },
    backendInitMs: 0,
    totalMs: 0
  };
  onProgress({ stage: "encrypt" }, elapsed());
  const wasm = await loadWasm();
  let t = performance.now();
  const credit = wasm.encryptCreditAndWitness(
    publicKey,
    Uint32Array.from(featureProof.features),
    featureProof.cap,
    Uint32Array.from(masks),
    void 0
  );
  timings.encryptMs = performance.now() - t;
  const bundle = credit.bundle;
  onProgress({ stage: "backend" }, elapsed());
  t = performance.now();
  const api = await getBBApi();
  timings.backendInitMs = performance.now() - t;
  const legs = [
    { name: "app", inputs: buildAppInputs(credit.credit_inputs, featureProof), expectPublic: 4 },
    { name: "ct1", inputs: bundle.ct1_inputs, expectPublic: 3 },
    { name: "ct0", inputs: bundle.ct0_inputs, expectPublic: 4 }
  ];
  const proven = {};
  for (const leg of legs) {
    const circuit = circuits[leg.name];
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
  const uCommitment = word(BigInt(bundle.u_commitment_hex));
  const mCommitment = word(BigInt(bundle.m_commitment_hex));
  if (proven.ct0.publicInputs[3] !== uCommitment || proven.ct1.publicInputs[2] !== uCommitment) {
    throw new Error("u_commitment mismatch between the ct0 and ct1 legs");
  }
  if (proven.ct0.publicInputs[2] !== mCommitment || proven.app.publicInputs[3] !== mCommitment) {
    throw new Error("m_commitment mismatch between the ct0 and app legs");
  }
  timings.totalMs = elapsed();
  onProgress({ stage: "done" }, timings.totalMs);
  return {
    ciphertext: `0x${bundle.ciphertext_hex}`,
    ct0: proven.ct0,
    ct1: proven.ct1,
    app: proven.app,
    mCommitment,
    uCommitment,
    masks,
    timings
  };
};
var logistic = (z) => 1 / (1 + Math.exp(-z));
var maskDot = (model, masks) => model.weights.reduce((acc, w, j) => acc + w * (masks[j] / MASK_SCALE), 0);
var recoverScore = (opened, index, model, masks) => {
  if (index < 0 || index >= opened.length) throw new Error(`no opened coefficient for application #${index}`);
  const dot = maskDot(model, masks);
  const linear = opened[index] - dot;
  return { index, opened: opened[index], maskDot: dot, linear, probability: logistic(linear) };
};
var linearScore = (model, features, cap) => model.weights.reduce((acc, w, j) => acc + w * (features[j] / cap), 0) + model.bias;

// packages/ckks-credit-sdk/src/chain.ts
import { decodeAbiParameters, encodeAbiParameters, parseAbi, parseAbiParameters } from "viem";
var THREE_LEG_ENVELOPE = parseAbiParameters("bytes, bytes, bytes32[], bytes, bytes32[], bytes, bytes32[]");
var CREDIT_PROGRAM_ABI = parseAbi([
  "function publishInput(uint256 e3Id, bytes data)",
  "function setIssuerRoot(uint256 e3Id, bytes32 root)",
  "function issuerRoots(uint256 e3Id) view returns (bytes32)",
  "function featureCap() view returns (uint256)",
  "function submissionCount(uint256 e3Id) view returns (uint256)",
  "function seenUCommitments(uint256 e3Id, bytes32 u) view returns (bool)",
  "event VerifiedInputPublished(uint256 indexed e3Id, address indexed publisher, bytes32 ciphertextHash, bytes32 ct0Commitment, bytes32 ct1Commitment, bytes32 mCommitment, bytes32 uCommitment)",
  "event IssuerRootSet(uint256 indexed e3Id, bytes32 root)",
  "error RootAlreadySet(uint256 e3Id)",
  "error InvalidRoot()",
  "error NotOwner()",
  "error DuplicateSubmission(uint256 e3Id, bytes32 uCommitment)",
  "error WrongSender(address proven, address sender)",
  "error WrongRoot(bytes32 got, bytes32 want)",
  "error WrongCap(uint256 got, uint256 want)",
  "error RootNotSet(uint256 e3Id)",
  "error UCommitmentMismatch(bytes32 ct0Leg, bytes32 ct1Leg)",
  "error MCommitmentMismatch(bytes32 ct0Leg, bytes32 appLeg)",
  "error Ct0ProofInvalid()",
  "error Ct1ProofInvalid()",
  "error AppProofInvalid()"
]);
var PUBLISH_GAS_LIMIT = 29000000n;
var encodeApplicationEnvelope = (s) => encodeAbiParameters(THREE_LEG_ENVELOPE, [
  s.ciphertext,
  s.ct0.proof,
  s.ct0.publicInputs,
  s.ct1.proof,
  s.ct1.publicInputs,
  s.app.proof,
  s.app.publicInputs
]);
var decodeCiphertextFromCalldata = (input) => {
  const args = decodeAbiParameters(parseAbiParameters("uint256, bytes"), `0x${input.slice(10)}`);
  const [ciphertext] = decodeAbiParameters(THREE_LEG_ENVELOPE, args[1]);
  return ciphertext;
};
var publishApplication = async (walletClient, publicClient, program, e3Id, submission) => {
  const account = walletClient.account;
  if (!account) throw new Error("wallet has no account");
  const data = encodeApplicationEnvelope(submission);
  const { request } = await publicClient.simulateContract({
    account,
    address: program,
    abi: CREDIT_PROGRAM_ABI,
    functionName: "publishInput",
    args: [e3Id, data],
    gas: PUBLISH_GAS_LIMIT
  });
  const hash = await walletClient.writeContract(request);
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error(`application transaction reverted: ${hash}`);
  return { hash, gasUsed: receipt.gasUsed, blockNumber: receipt.blockNumber };
};

// packages/ckks-credit-sdk/src/api.ts
var CreditApi = class {
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
  featureProof = (e3Id, address) => this.get(`/rounds/${e3Id}/feature-proof/${address}`);
  publicKey = async (e3Id) => {
    const { publicKeyHex } = await this.get(`/rounds/${e3Id}/public-key`);
    const hex = publicKeyHex.slice(2);
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
    return out;
  };
  /** Admin: request a new E3 with an issuer snapshot + public model (server signs with its key and sets the root). */
  createRound = (snapshot, model, durationSecs) => this.post("/rounds/request", { snapshot, model, durationSecs });
  /** Admin: run the scoring policy + publish the ciphertext output. */
  evaluate = (e3Id) => this.post(`/rounds/${e3Id}/evaluate`, {});
};
export {
  APPLICANT_STRIDE,
  CIRCUIT_NAMES,
  CREDIT_PARAM_SET,
  CREDIT_PROGRAM_ABI,
  CreditApi,
  FEATURES,
  FeatureTree,
  MASK_BITS,
  MASK_FRAC_BITS,
  MASK_SCALE,
  MERKLE_MAX_DEPTH,
  PUBLISH_GAS_LIMIT,
  SRS_SIZE,
  THREE_LEG_ENVELOPE,
  buildAppInputs,
  checkApplication,
  decodeCiphertextFromCalldata,
  destroyBBApi,
  encodeApplicationEnvelope,
  encryptAndProveApplication,
  featureLeaf,
  getBBApi,
  linearScore,
  logistic,
  maskDot,
  publishApplication,
  recoverScore,
  requireCircuits,
  rootFromProof,
  sampleMasks,
  setCircuits,
  toRootHex,
  word
};
