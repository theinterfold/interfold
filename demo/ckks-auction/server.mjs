// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// CKKS auction demo server: a thin local bridge between the dashboard
// (index.html) and the REAL stack booted by tests/integration/
// ckks-demo-env.sh. Every action shells out to the same binaries and
// hardhat tasks the passing e2e test (ckks-auction.sh) uses — the webapp
// adds no crypto of its own, it only shows the real thing happening.
//
// Zero npm dependencies; run with: node demo/ckks-auction/server.mjs

import { execFile } from "node:child_process";
import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..", "..");
const CONTRACTS = join(ROOT, "packages", "interfold-contracts");
const OUT = join(__dirname, "out");
// CKKS_TOOLS_PROFILE=release selects the release tools (matches the env
// script; release strongly recommended for the 39-limb winner mode).
const TOOLS_PROFILE = process.env.CKKS_TOOLS_PROFILE || "debug";
const BIN = (name) => join(ROOT, "target", TOOLS_PROFILE, name);
const RPC = "http://localhost:8545";
const PORT = 8090;
const CHAIN_ID = 31337;

// CKKS sign-extraction ladder — on-chain ParamSet 2 (crates/fhe-params
// ckks_presets): 45-bit base + 37×40-bit rescale limbs, delta 2^40.
// `pack_ckks_params --param-set 2` derives byte-identical params to what
// every ciphernode uses for this ParamSet.
const PARAM_SET = 2;
const CKKS_PARAMS_ARGS = ["--param-set", String(PARAM_SET)];
// Winner mode: iterated sign extraction. `BID_CAP` is the bound B the
// pair differences are normalized by (1/B) before the cubic sign map —
// it must be ≥ every possible bid, and 12 iterations binarize gaps down
// to ~2% of it (a 1000 cap resolves 20-unit gaps).
const BID_CAP = 1000;
const SIGN_ITERATIONS = 12;
// Where the ciphernodes write the joint relin-ceremony keys (any single
// node's dir works — every honest party derives identical keys). Keyed
// per E3 as `<dir>/<chain_id>:<e3_id>/rlk_hybrid.bin` (ONE hybrid key for every level).
const RELIN_KEY_DIR = process.env.CKKS_RELIN_KEY_DIR ?? "/tmp/ckks-relin-keys";
const DECIMALS = 2;

mkdirSync(OUT, { recursive: true });

// ── helpers ─────────────────────────────────────────────────────────────

function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(
      cmd,
      args,
      { cwd: opts.cwd ?? ROOT, timeout: opts.timeout ?? 180_000, maxBuffer: 16e6 },
      (err, stdout, stderr) => {
        resolve({
          ok: !err,
          code: err?.code ?? 0,
          stdout: String(stdout),
          stderr: String(stderr),
        });
      },
    );
  });
}

const hardhat = (args) =>
  run("npx", ["hardhat", ...args, "--network", "localhost"], { cwd: CONTRACTS });

async function rpc(method, params = []) {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return (await res.json()).result;
}

function deployedAddress(name) {
  const path = join(CONTRACTS, "deployed_contracts.json");
  const d = JSON.parse(readFileSync(path, "utf8"));
  return d.localhost?.[name]?.address;
}

const json = (res, code, body) => {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
};

const readBody = (req) =>
  new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data ? JSON.parse(data) : {}));
  });

// Cached params hex (packed once per server run).
let paramsHex = null;
async function ckksParams() {
  if (!paramsHex) {
    const r = await run(BIN("pack_ckks_params"), CKKS_PARAMS_ARGS);
    if (!r.ok) throw new Error(`pack_ckks_params failed: ${r.stderr}`);
    paramsHex = r.stdout.trim();
  }
  return paramsHex;
}

function decodeFixedPoint(hex, decimals) {
  const bytes = Buffer.from(hex.replace(/^0x/, ""), "hex");
  const values = [];
  for (let i = 0; i + 16 <= bytes.length; i += 16) {
    let v = 0n;
    for (let j = 0; j < 16; j++) v = (v << 8n) | BigInt(bytes[i + j]);
    if (v >= 1n << 127n) v -= 1n << 128n;
    values.push(Number(v) / 10 ** decimals);
  }
  return values;
}

// ── demo state (mirrors what the dashboard shows; chain stays canonical) ─

const state = {
  e3Id: null,
  pubkeyHex: null,
  bids: [], // {bidder, value, file, ciphertextBytes}
  pairs: [],
  evaluated: null, // {file, commitmentHex, bytes}
  published: false,
  plaintext: null, // {values, signs, outcome}
  log: [],
};

function log(stage, message) {
  state.log.push({ t: Date.now(), stage, message });
  if (state.log.length > 400) state.log.shift();
  console.log(`[${stage}] ${message}`);
}

// ── API ─────────────────────────────────────────────────────────────────

const routes = {
  // Environment health: chain block + ciphernode count + program address.
  "GET /api/status": async () => {
    let block = null;
    try {
      block = parseInt(await rpc("eth_blockNumber"), 16);
    } catch {
      /* chain down */
    }
    // macOS pgrep has no -c; count lines instead. 6 matches = 5 nodes + supervisor.
    const nodes = await run("bash", ["-c", "pgrep -f 'target/(debug|release)/interfold' | wc -l"]);
    let ckksProgram = null;
    try {
      ckksProgram = deployedAddress("MockCkksE3Program");
    } catch {
      /* not deployed yet */
    }
    return {
      chain: block !== null ? { up: true, block } : { up: false },
      ciphernodes: parseInt(nodes.stdout.trim() || "0", 10),
      ckksProgram,
      state,
    };
  },

  // Step 1: request a committee THROUGH the CKKS program address.
  "POST /api/request-committee": async () => {
    const program = deployedAddress("MockCkksE3Program");
    if (!program) throw new Error("CKKS program not deployed — is the env up?");
    const ts = parseInt(
      (await rpc("eth_getBlockByNumber", ["latest", false])).timestamp,
      16,
    );
    log("request", `committee:new through CKKS program ${program} (paramSet ${PARAM_SET}: sign-extraction ladder)`);
    const r = await hardhat([
      "committee:new",
      "--input-window-start", String(ts + 20),
      "--input-window-end", String(ts + 30),
      "--e3-address", program,
      "--committee-size", "0",
      "--param-set", String(PARAM_SET),
    ]);
    if (!r.ok) throw new Error(`committee:new failed: ${r.stderr.slice(-800)}`);
    const m = r.stdout.match(/^E3_ID=(\d+)$/m);
    if (!m) throw new Error("no E3_ID in committee:new output");
    state.e3Id = m[1];
    state.pubkeyHex = null;
    state.bids = [];
    state.evaluated = null;
    state.published = false;
    state.plaintext = null;
    log("request", `E3 requested: id ${state.e3Id} — scheme bound by program address`);
    return { e3Id: state.e3Id, program };
  },

  // Step 2: poll for the DKG result (the committee's joint CKKS pk).
  "GET /api/pubkey": async () => {
    if (!state.e3Id) throw new Error("no E3 requested yet");
    if (state.pubkeyHex) return { ready: true, pubkey: state.pubkeyHex };
    const r = await hardhat([
      "committee:getPublicKey",
      "--e3-id", state.e3Id,
      "--out-file", join(OUT, "pubkey.bin"),
    ]);
    if (!r.ok) return { ready: false };
    const hex = r.stdout.trim().split("\n").pop();
    if (!hex?.startsWith("0x") || hex === "0x") return { ready: false };
    state.pubkeyHex = hex;
    log("dkg", `joint CKKS public key published on-chain (${(hex.length - 2) / 2} bytes)`);
    return { ready: true, pubkey: hex };
  },

  // Step 3: encrypt REAL bids under the committee pk (ckks_encrypt CLI).
  "POST /api/bids": async (body) => {
    if (!state.pubkeyHex) throw new Error("committee pk not ready");
    const bids = (body.bids ?? []).map(Number);
    if (bids.length < 2 || bids.length > 8 || bids.some((b) => !isFinite(b) || b <= 0))
      throw new Error("need 2-8 positive numeric bids");
    if (bids.some((b) => b > BID_CAP))
      throw new Error(`bids must be ≤ the bid cap ${BID_CAP} (sign-extraction bound)`);
    const params = await ckksParams();
    state.bids = [];
    for (let i = 0; i < bids.length; i++) {
      const file = join(OUT, `bid_${i}.bin`);
      const r = await run(BIN("ckks_encrypt"), [
        "--pubkey", join(OUT, "pubkey.bin"),
        "--params", params,
        "--value", String(bids[i]),
        "--output", file,
      ]);
      if (!r.ok) throw new Error(`ckks_encrypt bid ${i}: ${r.stderr.slice(-400)}`);
      const bytes = (await run("wc", ["-c", file])).stdout.trim().split(/\s+/)[0];
      state.bids.push({ bidder: i, value: bids[i], file, ciphertextBytes: Number(bytes) });
      log("encrypt", `bidder ${i}: ${bids[i]} -> ${bytes}-byte CKKS ciphertext (slot-replicated)`);
    }
    // Single-shot mode: ALL i<j comparisons packed into one ciphertext —
    // the whole auction resolves from ONE threshold opening.
    state.pairs = [];
    for (let i = 0; i < bids.length; i++)
      for (let j = i + 1; j < bids.length; j++) state.pairs.push([i, j]);
    return { bids: state.bids, pairs: state.pairs };
  },

  // Step 4: evaluate the auction homomorphically — leak-free WINNER mode.
  // All i<j differences are packed into ONE ciphertext (normalized by the
  // bid cap) and the iterated cubic sign map drives every pair slot to
  // exactly ±1: the single threshold opening reveals the comparison BITS
  // and nothing about the gaps. Needs the committee's relin-ceremony keys
  // (written by the nodes to CKKS_RELIN_KEY_DIR at DKG time).
  "POST /api/evaluate": async () => {
    if (!state.bids.length) throw new Error("no bids encrypted");
    const params = await ckksParams();
    const outFile = join(OUT, "auction_round.bin");
    const commitFile = join(OUT, "auction_commitment.bin");
    const rlkDir = join(RELIN_KEY_DIR, `${CHAIN_ID}:${state.e3Id}`);
    if (!existsSync(rlkDir))
      throw new Error(
        `relin ceremony keys not found at ${rlkDir} — are the nodes running with CKKS_RELIN_LEVELS set?`,
      );
    log("evaluate", `sign extraction over ${state.pairs.length} pairs (bound ${BID_CAP}, ${SIGN_ITERATIONS} iterations, ceremony keys from ${rlkDir}) — bids never decrypted, gaps never revealed`);
    const r = await run(BIN("ckks_auction_eval"), [
      "--params", params,
      "--bids", state.bids.map((b) => b.file).join(","),
      "--output", outFile,
      "--commitment-output", commitFile,
      "--mode", "winner",
      "--rlk-dir", rlkDir,
      "--bound", String(BID_CAP),
      "--iterations", String(SIGN_ITERATIONS),
    ], { timeout: 600_000 });
    if (!r.ok) throw new Error(`ckks_auction_eval: ${r.stderr.slice(-400)}`);
    const commitmentHex = "0x" + readFileSync(commitFile).toString("hex");
    const bytes = readFileSync(outFile).length;
    state.evaluated = { file: outFile, commitmentHex, bytes };
    log("evaluate", `evaluated ciphertext ${bytes} bytes, commitment ${commitmentHex.slice(0, 18)}…`);
    return state.evaluated;
  },

  // Step 5: publish the evaluated ciphertext on-chain (triggers threshold
  // decryption by the real ciphernodes).
  "POST /api/publish": async () => {
    if (!state.evaluated) throw new Error("nothing evaluated");
    log("publish", "publishInput + publishCiphertextOutput on-chain");
    const r1 = await hardhat([
      "e3-program:publishInput",
      "--e3-id", state.e3Id,
      "--data", "0x12345678",
    ]);
    if (!r1.ok) throw new Error(`publishInput: ${r1.stderr.slice(-400)}`);
    const r2 = await hardhat([
      "e3:publishCiphertext",
      "--e3-id", state.e3Id,
      "--data-file", state.evaluated.file,
      "--ciphertext-commitment-file", join(OUT, "auction_commitment.bin"),
      "--proof", "0x12345678",
    ]);
    if (!r2.ok) throw new Error(`publishCiphertext: ${r2.stderr.slice(-400)}`);
    state.published = true;
    log("publish", "ciphertext on-chain — committee threshold-decrypting…");
    return { published: true };
  },

  // Step 6: poll for the on-chain plaintext and interpret the round.
  "GET /api/plaintext": async () => {
    if (!state.published) throw new Error("ciphertext not published");
    if (state.plaintext) return { ready: true, ...state.plaintext };
    const r = await hardhat(["e3:getCkksPlaintext", "--e3-id", state.e3Id]);
    if (!r.ok) return { ready: false };
    const csv = r.stdout.trim().split("\n").pop();
    if (!csv) return { ready: false };
    const values = csv.split(",").map(Number);
    const k = state.bids.length;
    // Winner mode: each pair slot is the SIGN of the comparison, driven to
    // exactly ±1 by the iterated sign map — the magnitude carries no bid
    // information (leak-free). A slot far from ±1 means the gap was below
    // the binarization floor (~2% of the bid cap) — flag it.
    const signs = state.pairs.map((_, p) => Math.sign(values[p]));
    const binarized = state.pairs.map(
      (_, p) => Math.abs(Math.abs(values[p]) - 1) < 0.05,
    );
    // Dominance matrix: winner = bidder that wins every comparison.
    const wins = new Array(k).fill(0);
    state.pairs.forEach(([a, b], p) => {
      if (signs[p] > 0) wins[a] += 1;
      else wins[b] += 1;
    });
    const byWins = [...wins.keys()].sort((a, b) => wins[b] - wins[a] || a - b);
    const champion = byWins[0];
    const second = byWins[1];
    // Verification against the submitted cleartext bids (demo-only check;
    // a real auction never sees them).
    const clear = [...state.bids.keys()].sort(
      (a, b) => state.bids[b].value - state.bids[a].value || a - b,
    );
    const correct = champion === clear[0] && second === clear[1];
    state.plaintext = {
      values: values.slice(0, Math.max(state.pairs.length, 2)),
      signs,
      binarized,
      wins,
      champion,
      second,
      correct,
    };
    log(
      "decrypt",
      `on-chain plaintext: ±1 comparison signs only (no gap magnitudes) — WINNER bidder ${champion} (${wins[champion]} wins), second bidder ${second} (${correct ? "matches" : "MISMATCH vs"} cleartext bids)${binarized.every(Boolean) ? "" : " — WARNING: some slots not saturated (gap below ~2% of cap)"}`,
    );
    return { ready: true, ...state.plaintext };
  },

  // Full reset for another run.
  "POST /api/reset": async () => {
    Object.assign(state, {
      e3Id: null, pubkeyHex: null, bids: [], pairs: [],
      evaluated: null, published: false, plaintext: null,
    });
    log("reset", "demo state cleared (chain keeps its history)");
    return { ok: true };
  },
};

// ── server ──────────────────────────────────────────────────────────────

createServer(async (req, res) => {
  const key = `${req.method} ${new URL(req.url, "http://x").pathname}`;
  if (routes[key]) {
    try {
      json(res, 200, await routes[key](await readBody(req)));
    } catch (e) {
      json(res, 500, { error: String(e.message ?? e) });
    }
    return;
  }
  if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(readFileSync(join(__dirname, "index.html")));
    return;
  }
  json(res, 404, { error: "not found" });
}).listen(PORT, () => {
  console.log(`\n  CKKS auction demo:  http://localhost:${PORT}\n`);
  if (!existsSync(BIN("ckks_encrypt")))
    console.warn(`  WARNING: target/${TOOLS_PROFILE}/ckks_encrypt missing — run the env script first.`);
});
