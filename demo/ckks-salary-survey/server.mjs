// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// CKKS salary-survey demo server: a thin local bridge between the
// dashboard (index.html) and the REAL stack booted by tests/integration/
// ckks-salary-env.sh. Every action shells out to the same binaries and
// hardhat tasks the passing e2e tests use — the webapp adds no crypto of
// its own, it only shows the real thing happening.
//
// Zero npm dependencies; run with: node demo/ckks-salary-survey/server.mjs

import { execFile, spawn } from "node:child_process";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..", "..");
const CONTRACTS = join(ROOT, "packages", "interfold-contracts");
const OUT = join(__dirname, "out");
// CKKS_TOOLS_PROFILE=release selects the release tools (matches the env
// script; release strongly recommended).
const TOOLS_PROFILE = process.env.CKKS_TOOLS_PROFILE || "debug";
const BIN = (name) => join(ROOT, "target", TOOLS_PROFILE, name);
const RPC = "http://localhost:8545";
const PORT = 8091;
const CHAIN_ID = 31337;

// CKKS statistics preset — on-chain ParamSet 3 (crates/fhe-params
// ckks_presets): three 36-bit transport-fit moduli, delta 2^40, ONE
// genuine ct×ct multiplication level. `pack_ckks_params --param-set 3`
// derives byte-identical params to what every ciphernode uses.
const PARAM_SET = 3;
const CKKS_PARAMS_ARGS = ["--param-set", String(PARAM_SET)];
// Salaries are normalized by this PUBLIC cap before encryption
// (`ckks_encrypt --value salary/CAP`); the policy computes on normalized
// values and the decode step multiplies the aggregates back. Purely an
// encoding-headroom device — not a crypto bound.
const SALARY_CAP = 500000;
// Public output scale S baked into ckks_stats_eval: opened slots carry
// S*sum/CAP and S*sumsq/CAP^2, so the canonical 2-decimal on-chain
// fixed-point output keeps 6+ significant digits.
const OUTPUT_SCALE = 10000;
// Where the ciphernodes write the joint relin-ceremony key (any single
// node's dir works — every honest party derives identical keys). Keyed
// per E3 as `<dir>/<chain_id>:<e3_id>/rlk_level_0.bin`.
const RELIN_KEY_DIR = process.env.CKKS_RELIN_KEY_DIR ?? "/tmp/ckks-relin-keys";
const DECIMALS = 2;
// INSECURE legacy path: server-side plaintext encryption (the pre-Greco
// demo flow). Off by default — participants encrypt+prove in their OWN
// processes via the ckks_participant CLI and every submission is
// verified on-chain. Set DEMO_INSECURE=1 to re-enable the old path
// (red banner in the UI).
const DEMO_INSECURE = process.env.DEMO_INSECURE === "1";

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

// ── demo state (mirrors what the dashboard shows; chain stays canonical) ─

const state = {
  e3Id: null,
  pubkeyHex: null,
  salaries: [], // eval seam: {participant, file, ciphertextBytes, ...}
  participants: [], // verified submissions: {participant, file, uCommitment, tx}
  // Demo-only: values typed into the "simulate participant" form, keyed
  // by u_commitment, so the dashboard can cross-check the homomorphic
  // result. A REAL survey never sees these.
  simValues: {},
  evaluated: null, // {file, commitmentHex, bytes}
  published: false,
  plaintext: null, // {count, mean, variance, stddev, ...}
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
      ckksProgram = deployedAddress("CkksE3ProgramPs3");
    } catch {
      /* not deployed yet */
    }
    return {
      chain: block !== null ? { up: true, block } : { up: false },
      ciphernodes: parseInt(nodes.stdout.trim() || "0", 10),
      ckksProgram,
      salaryCap: SALARY_CAP,
      demoInsecure: DEMO_INSECURE,
      state,
    };
  },

  // Step 1: request a committee THROUGH the Greco-gated CKKS program
  // (ParamSet 3 verifiers): every node derives the 3-limb params and,
  // seeing CKKS_RELIN_LEVELS=0, runs the relin ceremony after DKG.
  // Because the program is `CkksE3Program`, every published input must
  // carry valid Honk proofs for both encryption legs.
  "POST /api/request-committee": async () => {
    const program = deployedAddress("CkksE3ProgramPs3");
    if (!program)
      throw new Error("CkksE3ProgramPs3 not deployed — is the env up?");
    const ts = parseInt(
      (await rpc("eth_getBlockByNumber", ["latest", false])).timestamp,
      16,
    );
    log("request", `committee:new through CKKS program ${program} (paramSet ${PARAM_SET}: statistics 3-limb, standard DKG transport)`);
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
    state.salaries = [];
    state.participants = [];
    state.simValues = {};
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

  // LEGACY (INSECURE) path: server-side encryption of plaintext salaries.
  // Only available with DEMO_INSECURE=1 — the real flow is
  // /api/simulate-participant + /api/submit-encrypted, where the value
  // never reaches this bridge in clear and every ciphertext is verified
  // on-chain.
  "POST /api/salaries": async (body) => {
    if (!DEMO_INSECURE)
      throw new Error(
        "plaintext submission is disabled: participants encrypt+prove locally " +
          "(ckks_participant CLI) and submit via /api/submit-encrypted. " +
          "Set DEMO_INSECURE=1 to re-enable the legacy path.",
      );
    if (!state.pubkeyHex) throw new Error("committee pk not ready");
    const salaries = (body.salaries ?? []).map(Number);
    if (salaries.length < 2 || salaries.length > 8 || salaries.some((v) => !isFinite(v) || v <= 0))
      throw new Error("need 2-8 positive numeric salaries");
    if (salaries.some((v) => v > SALARY_CAP))
      throw new Error(`salaries must be ≤ the cap ${SALARY_CAP} (encoding headroom)`);
    const params = await ckksParams();
    state.salaries = [];
    for (let i = 0; i < salaries.length; i++) {
      const file = join(OUT, `salary_${i}.bin`);
      const r = await run(BIN("ckks_encrypt"), [
        "--pubkey", join(OUT, "pubkey.bin"),
        "--params", params,
        "--value", String(salaries[i] / SALARY_CAP),
        "--output", file,
      ]);
      if (!r.ok) throw new Error(`ckks_encrypt salary ${i}: ${r.stderr.slice(-400)}`);
      const bytes = (await run("wc", ["-c", file])).stdout.trim().split(/\s+/)[0];
      state.salaries.push({ participant: i, value: salaries[i], file, ciphertextBytes: Number(bytes) });
      log("encrypt", `participant ${i}: salary -> ${bytes}-byte CKKS ciphertext (INSECURE legacy path: the value crossed the demo bridge in clear)`);
    }
    return { salaries: state.salaries.map(({ value, ...rest }) => rest), count: state.salaries.length };
  },

  // Step 3a (real flow): SIMULATE a remote participant — spawn the
  // ckks_participant CLI as a SEPARATE child process (exactly what a
  // real participant runs on their own machine against the public
  // committee pk). The bridge reads back ONLY the resulting
  // submission.json; the salary value exists in this server solely
  // because the browser typed it into the simulation form.
  "POST /api/simulate-participant": async (body) => {
    if (!state.pubkeyHex) throw new Error("committee pk not ready");
    const value = Number(body.value);
    if (!isFinite(value) || value <= 0)
      throw new Error("need a positive numeric salary");
    if (value > SALARY_CAP)
      throw new Error(`salary must be ≤ the cap ${SALARY_CAP} (encoding headroom)`);
    const idx = state.participants.length;
    const outDir = join(OUT, `participant_${state.e3Id}_${idx}_${Date.now()}`);
    const cli = BIN("ckks_participant");
    const args = [
      "--param-set", String(PARAM_SET),
      "--pubkey", join(OUT, "pubkey.bin"),
      "--value", String(value),
      "--cap", String(SALARY_CAP),
      "--replicate-slots",
      "--out-dir", outDir,
      "--circuits-dir", join(ROOT, "circuits", "bin", "threshold"),
    ];
    const shown = `ckks_participant ${args.map((a) => (a.startsWith("--") ? a : JSON.stringify(a))).join(" ")}`;
    log("participant", `spawning participant process ${idx}: ${shown}`);
    const r = await new Promise((resolve) => {
      const child = spawn(cli, args, { cwd: ROOT });
      let stdout = "", stderr = "";
      child.stdout.on("data", (c) => (stdout += c));
      child.stderr.on("data", (c) => (stderr += c));
      child.on("close", (code) => resolve({ code, stdout, stderr }));
      child.on("error", (e) => resolve({ code: -1, stdout, stderr: String(e) }));
    });
    if (r.code !== 0)
      throw new Error(`ckks_participant failed: ${r.stderr.slice(-600)}`);
    const submission = JSON.parse(
      readFileSync(join(outDir, "submission.json"), "utf8"),
    );
    const uCommitment = submission.ct0.publicInputs[3];
    state.simValues[uCommitment] = value;
    log(
      "participant",
      `participant ${idx}: encrypted + proved BOTH Greco legs in its own process (u_commitment ${uCommitment.slice(0, 18)}…) — value never entered this bridge`,
    );
    return { participant: idx, command: shown, uCommitment, submission };
  },

  // Step 3b (real flow): accept a participant's submission.json and
  // publish it ON-CHAIN through the Greco gate. The tx REVERTS unless
  // both Honk proofs verify and the u-commitment is fresh
  // (DuplicateSubmission dedup). Only ACCEPTED ciphertexts are stored
  // for the eval step — the seam ckks_stats_eval reads is unchanged.
  "POST /api/submit-encrypted": async (body) => {
    if (!state.e3Id) throw new Error("no E3 requested yet");
    const submission = body.submission ?? body;
    if (!submission?.ciphertextHex || !submission?.ct0 || !submission?.ct1)
      throw new Error("body must carry a ckks_participant submission.json");
    if (Number(submission.paramSet) !== PARAM_SET)
      throw new Error(
        `submission is for paramSet ${submission.paramSet}, survey runs paramSet ${PARAM_SET}`,
      );
    const idx = state.participants.length;
    const subFile = join(OUT, `submission_${state.e3Id}_${idx}.json`);
    writeFileSync(subFile, JSON.stringify(submission));
    log("verify", `participant ${idx}: publishing input on-chain through the Greco gate (2 Honk verifies)…`);
    const r = await hardhat([
      "program:publish-input",
      "--e3-id", state.e3Id,
      "--data-file", subFile,
    ]);
    if (!r.ok) {
      if (r.stderr.includes("DUPLICATE_SUBMISSION") || r.stdout.includes("DUPLICATE_SUBMISSION")) {
        log("verify", `participant ${idx}: REJECTED — this exact encryption was already submitted (on-chain DuplicateSubmission dedup)`);
        const err = new Error(
          "this exact encryption was already submitted — the on-chain gate " +
            "rejects repeated randomness commitments; re-encrypt (fresh randomness) to submit again",
        );
        err.duplicate = true;
        throw err;
      }
      throw new Error(`on-chain verification failed: ${(r.stderr || r.stdout).slice(-600)}`);
    }
    const tx = (r.stdout.match(/ACCEPTED tx=(0x[0-9a-fA-F]+)/) ?? [])[1] ?? null;
    const uCommitment = submission.ct0.publicInputs[3];
    // Store the VERIFIED ciphertext for the eval step (same file seam
    // the pre-Greco flow used).
    const file = join(OUT, `salary_${idx}.bin`);
    writeFileSync(file, Buffer.from(submission.ciphertextHex.slice(2), "hex"));
    const entry = {
      participant: idx,
      file,
      ciphertextBytes: (submission.ciphertextHex.length - 2) / 2,
      uCommitment,
      tx,
    };
    state.participants.push(entry);
    state.salaries.push(entry); // eval seam: state.salaries[].file
    log(
      "verify",
      `participant ${idx}: ACCEPTED on-chain (tx ${tx?.slice(0, 14)}…, u_commitment ${uCommitment.slice(0, 18)}…) — VerifiedInputPublished emitted`,
    );
    return { accepted: true, ...entry };
  },

  // Step 4: evaluate the statistics homomorphically. The PACKED policy
  // computes sum (slot 0) and the RELINEARIZED sum-of-squares (slot 1,
  // genuine ct×ct multiplication with the committee's joint level-0
  // ceremony key) in ONE output ciphertext — one threshold opening
  // reveals ONLY the aggregates.
  "POST /api/evaluate": async () => {
    if (!state.salaries.length) throw new Error("no salaries encrypted");
    const params = await ckksParams();
    const outFile = join(OUT, "stats.bin");
    const commitFile = join(OUT, "stats_commitment.bin");
    const rlkDir = join(RELIN_KEY_DIR, `${CHAIN_ID}:${state.e3Id}`);
    if (!existsSync(rlkDir))
      throw new Error(
        `relin ceremony key not found at ${rlkDir} — are the nodes running with CKKS_RELIN_LEVELS=0?`,
      );
    log("evaluate", `packed statistics over ${state.salaries.length} ciphertexts (relinearized ct×ct sum-of-squares, ceremony key from ${rlkDir}) — individual salaries never decrypted`);
    const r = await run(BIN("ckks_stats_eval"), [
      "--params", params,
      "--inputs", state.salaries.map((b) => b.file).join(","),
      "--rlk-dir", rlkDir,
      "--output", outFile,
      "--commitment-output", commitFile,
      "--output-scale", String(OUTPUT_SCALE),
    ], { timeout: 600_000 });
    if (!r.ok) throw new Error(`ckks_stats_eval: ${r.stderr.slice(-400)}`);
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
    log("publish", "publishCiphertextOutput on-chain");
    if (!state.participants.length) {
      // Legacy path only: verified submissions already ran publishInput
      // through the Greco-gated program, one tx per participant.
      const r1 = await hardhat([
        "e3-program:publishInput",
        "--e3-id", state.e3Id,
        "--data", "0x12345678",
      ]);
      if (!r1.ok) throw new Error(`publishInput: ${r1.stderr.slice(-400)}`);
    }
    const r2 = await hardhat([
      "e3:publishCiphertext",
      "--e3-id", state.e3Id,
      "--data-file", state.evaluated.file,
      "--ciphertext-commitment-file", join(OUT, "stats_commitment.bin"),
      "--proof", "0x12345678",
    ]);
    if (!r2.ok) throw new Error(`publishCiphertext: ${r2.stderr.slice(-400)}`);
    state.published = true;
    log("publish", "ciphertext on-chain — committee threshold-decrypting…");
    return { published: true };
  },

  // Step 6: poll for the on-chain plaintext and derive the statistics.
  "GET /api/plaintext": async () => {
    if (!state.published) throw new Error("ciphertext not published");
    if (state.plaintext) return { ready: true, ...state.plaintext };
    const r = await hardhat(["e3:getCkksPlaintext", "--e3-id", state.e3Id]);
    if (!r.ok) return { ready: false };
    const csv = r.stdout.trim().split("\n").pop();
    if (!csv) return { ready: false };
    const values = csv.split(",").map(Number);
    // Slot 0 = S*sum/CAP, slot 1 = S*sumsq/CAP^2 — the ONLY two numbers
    // ever decrypted. Count n is public (submissions are visible);
    // mean/variance/stddev are derived CLIENT-side from the aggregates.
    const n = state.salaries.length;
    const sum = (values[0] / OUTPUT_SCALE) * SALARY_CAP;
    const sumsq = (values[1] / OUTPUT_SCALE) * SALARY_CAP * SALARY_CAP;
    const mean = sum / n;
    const variance = Math.max(0, sumsq / n - mean * mean);
    const stddev = Math.sqrt(variance);
    // Verification against known cleartext values (demo-only check; a
    // real survey never sees them). In the verified flow the values are
    // known only for SIMULATED participants (typed into the dashboard);
    // externally-produced submissions have no cleartext here, so the
    // check is skipped unless every submission's value is known.
    const clear = state.salaries
      .map((s) => (s.uCommitment ? state.simValues[s.uCommitment] : s.value))
      .filter((v) => typeof v === "number");
    let checked = clear.length === n && n > 0;
    let trueMean = null, trueVar = null, meanErr = null, varErr = null, correct = null;
    if (checked) {
      trueMean = clear.reduce((a, b) => a + b, 0) / n;
      trueVar = clear.reduce((a, x) => a + (x - trueMean) ** 2, 0) / n;
      meanErr = Math.abs(mean - trueMean) / trueMean;
      varErr = trueVar > 0 ? Math.abs(variance - trueVar) / trueVar : 0;
      correct = meanErr < 0.001 && varErr < 0.02;
    }
    state.plaintext = {
      openedSlots: values.slice(0, 2),
      count: n,
      sum, sumsq, mean, variance, stddev,
      checked, trueMean, trueVar, meanErr, varErr, correct,
    };
    log(
      "decrypt",
      `on-chain plaintext: TWO aggregate slots only — count ${n} (public), mean ${mean.toFixed(2)}, variance ${variance.toFixed(2)}, stddev ${stddev.toFixed(2)}${checked ? ` (${correct ? "matches" : "MISMATCH vs"} cleartext check; mean err ${(meanErr * 100).toFixed(4)}%, var err ${(varErr * 100).toFixed(2)}%)` : " (no cleartext check: external submissions)"}. Individual salaries were never decrypted.`,
    );
    return { ready: true, ...state.plaintext };
  },

  // Full reset for another run.
  "POST /api/reset": async () => {
    Object.assign(state, {
      e3Id: null, pubkeyHex: null, salaries: [], participants: [],
      simValues: {}, evaluated: null, published: false, plaintext: null,
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
  console.log(`\n  CKKS salary-survey demo:  http://localhost:${PORT}\n`);
  if (!existsSync(BIN("ckks_encrypt")))
    console.warn(`  WARNING: target/${TOOLS_PROFILE}/ckks_encrypt missing — run the env script first.`);
});
