// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * On-chain CKKS committee-key and decrypted-output verification.
 *
 * These specs drive `CkksPkVerifier` and `CkksDecryptionVerifier` with REAL Honk
 * proofs: three C1-CKKS (`pk_generation_ckks_ps<N>`) party proofs and one C7-CKKS
 * (`decrypted_shares_aggregation_ckks_ps<N>`) proof per fixture set (ps2, ps5), all
 * produced by `scripts/ckks-onchain-verifier-fixtures.sh <N> 3` from the same `nargo compile` the
 * committed Solidity verifiers were generated from.
 *
 * Together they are the evidence that CKKS E3s no longer need MockPkVerifier or
 * MockDecryptionVerifier.
 */
import { expect } from "chai";
import { readFileSync } from "fs";
import { network } from "hardhat";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

import type { LegFixture } from "./helpers/ckksApp";
import { HONK_VERIFY_GAS_LIMIT, deployVerifier, tamperProof } from "./helpers/ckksApp";

interface OnchainFixture {
  paramSet: number;
  committeeSize: number;
  parties: LegFixture[];
  c7: LegFixture;
  /** hi||lo of the C7 proof's two domain public inputs — the ONLY
   *  decryptionDomain the verifier accepts this proof under. */
  c7DecryptionDomain: string;
}

/** `minimum` committee: N=3 parties, T=1 reconstruction threshold. */
const COMMITTEE_N = 3;
const THRESHOLD_T = 1;
const E3_ID = 42n;

/**
 * Every param set with committed fixtures (`scripts/ckks-onchain-verifier-fixtures.sh <set> 3`).
 * ps2 = auction ladder (38 limbs at level 0, opens at level 37); ps5 = the coefficient
 * inner-product preset shared by matching / treasury / federated averaging (3 limbs,
 * opens at level 1). `other` is a set whose C1 AND C7 verification keys both differ
 * from `paramSet`'s, used to prove the dispatch table really selects by VK.
 *
 * VK-COINCIDENCE FACT (measured, not a bug): ps3, ps4 and ps5 all open at a level
 * where exactly `[0xffffee001, 0xffffc4001]` remain, so their C6/C7 circuits are the
 * SAME statement and `DecryptedSharesAggregationCkksPs{3,4,5}Verifier` share one
 * `VK_HASH` (0x0002fdd0…). A ps5 C7 proof therefore verifies under the ps3 table
 * entry — correctly, it proves the same relation, and domain binding pins it to its
 * own E3. Only the C1 keys (level 0, different chains) differ between them. So the
 * ps5 negative case must use ps2 (different opening ring), not ps3.
 */
const FIXTURE_SETS: ReadonlyArray<{ paramSet: number; other: number }> = [
  { paramSet: 2, other: 3 },
  { paramSet: 5, other: 2 },
];

for (const { paramSet: PARAM_SET, other: OTHER_PARAM_SET } of FIXTURE_SETS) {
const fixtureDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  `ckks_onchain_ps${PARAM_SET}`,
);
const fixture: OnchainFixture = JSON.parse(
  readFileSync(join(fixtureDir, "verifier_input.json"), "utf8"),
);

describe(`CKKS on-chain verifiers (ParamSet ${PARAM_SET})`, () => {
  describe("CkksPkVerifier", () => {
    async function deploy() {
      const { ethers } = await network.connect();
      const circuitVerifier = await deployVerifier(
        ethers,
        `PkGenerationCkksPs${PARAM_SET}Verifier.sol`,
        `PkGenerationCkksPs${PARAM_SET}Verifier`,
      );
      // A different param set's circuit, to prove dispatch really selects by VK.
      const otherCircuitVerifier = await deployVerifier(
        ethers,
        `PkGenerationCkksPs${OTHER_PARAM_SET}Verifier.sol`,
        `PkGenerationCkksPs${OTHER_PARAM_SET}Verifier`,
      );
      const paramSetSource = await (
        await ethers.getContractFactory("MockParamSetSource")
      ).deploy();
      await paramSetSource.setParamSet(E3_ID, PARAM_SET);

      const verifier = await (
        await ethers.getContractFactory("CkksPkVerifier")
      ).deploy(
        await paramSetSource.getAddress(),
        [PARAM_SET, OTHER_PARAM_SET],
        [
          await circuitVerifier.getAddress(),
          await otherCircuitVerifier.getAddress(),
        ],
        COMMITTEE_N,
      );
      await verifier.waitForDeployment();
      return { ethers, verifier, paramSetSource };
    }

    /** The blob the aggregator publishes: per-party proofs + the aggregate key bytes. */
    function encode(
      ethers: Awaited<ReturnType<typeof network.connect>>["ethers"],
      parties: LegFixture[],
      publicKey: string,
    ): string {
      return ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes[]", "bytes32[][]", "bytes"],
        [
          parties.map((p) => p.proof),
          parties.map((p) => p.publicInputs),
          publicKey,
        ],
      );
    }

    const nodes = (ethers: { getAddress?: unknown }) =>
      Array.from(
        { length: COMMITTEE_N },
        (_, i) => "0x" + (i + 1).toString(16).padStart(40, "0"),
      );

    it("accepts a full committee of real C1-CKKS proofs", async () => {
      const { ethers, verifier } = await deploy();
      const publicKey = "0x" + "ab".repeat(96);
      const pkCommitment = ethers.keccak256(publicKey);
      expect(
        await verifier.verify.staticCall(
          E3_ID,
          0n,
          nodes(ethers),
          pkCommitment,
          ethers.ZeroHash,
          encode(ethers, fixture.parties, publicKey),
          { gasLimit: HONK_VERIFY_GAS_LIMIT },
        ),
      ).to.equal(true);
    });

    it("reports gas for a 3-party committee", async () => {
      const { ethers, verifier } = await deploy();
      const publicKey = "0x" + "ab".repeat(96);
      const gas = await verifier.verify.estimateGas(
        E3_ID,
        0n,
        nodes(ethers),
        ethers.keccak256(publicKey),
        ethers.ZeroHash,
        encode(ethers, fixture.parties, publicKey),
        { gasLimit: HONK_VERIFY_GAS_LIMIT },
      );
      console.log(`      CkksPkVerifier.verify (n=3): ${gas} gas`);
      expect(gas).to.be.greaterThan(0n);
    });

    it("rejects a tampered party proof", async () => {
      const { ethers, verifier } = await deploy();
      const publicKey = "0x" + "ab".repeat(96);
      const parties = fixture.parties.map((p, i) =>
        i === 1 ? { ...p, proof: tamperProof(p.proof) } : p,
      );
      await expect(
        verifier.verify.staticCall(
          E3_ID,
          0n,
          nodes(ethers),
          ethers.keccak256(publicKey),
          ethers.ZeroHash,
          encode(ethers, parties, publicKey),
          { gasLimit: HONK_VERIFY_GAS_LIMIT },
        ),
      ).to.be.revert(ethers);
    });

    it("rejects a short party array (a missing committee member)", async () => {
      const { ethers, verifier } = await deploy();
      const publicKey = "0x" + "ab".repeat(96);
      await expect(
        verifier.verify.staticCall(
          E3_ID,
          0n,
          nodes(ethers),
          ethers.keccak256(publicKey),
          ethers.ZeroHash,
          encode(ethers, fixture.parties.slice(0, 2), publicKey),
          { gasLimit: HONK_VERIFY_GAS_LIMIT },
        ),
      )
        .to.be.revertedWithCustomError(verifier, "PartyProofCountMismatch")
        .withArgs(2, COMMITTEE_N);
    });

    it("rejects a mismatched pkCommitment", async () => {
      const { ethers, verifier } = await deploy();
      const publicKey = "0x" + "ab".repeat(96);
      await expect(
        verifier.verify.staticCall(
          E3_ID,
          0n,
          nodes(ethers),
          ethers.keccak256("0x" + "cd".repeat(96)), // commits to other bytes
          ethers.ZeroHash,
          encode(ethers, fixture.parties, publicKey),
          { gasLimit: HONK_VERIFY_GAS_LIMIT },
        ),
      ).to.be.revertedWithCustomError(verifier, "PkCommitmentMismatch");
    });

    it("rejects one party's proof replayed to fill the committee", async () => {
      const { ethers, verifier } = await deploy();
      const publicKey = "0x" + "ab".repeat(96);
      const replayed = [
        fixture.parties[0],
        fixture.parties[0],
        fixture.parties[2],
      ];
      await expect(
        verifier.verify.staticCall(
          E3_ID,
          0n,
          nodes(ethers),
          ethers.keccak256(publicKey),
          ethers.ZeroHash,
          encode(ethers, replayed, publicKey),
          { gasLimit: HONK_VERIFY_GAS_LIMIT },
        ),
      )
        .to.be.revertedWithCustomError(verifier, "DuplicatePartyCommitment")
        .withArgs(1);
    });

    it(`rejects ParamSet ${PARAM_SET} proofs when the E3 declares ParamSet ${OTHER_PARAM_SET}`, async () => {
      const { ethers, verifier, paramSetSource } = await deploy();
      await paramSetSource.setParamSet(E3_ID, OTHER_PARAM_SET);
      const publicKey = "0x" + "ab".repeat(96);
      // Dispatch picks the ps3 circuit, whose VK does not match these proofs.
      await expect(
        verifier.verify.staticCall(
          E3_ID,
          0n,
          nodes(ethers),
          ethers.keccak256(publicKey),
          ethers.ZeroHash,
          encode(ethers, fixture.parties, publicKey),
          { gasLimit: HONK_VERIFY_GAS_LIMIT },
        ),
      ).to.be.revert(ethers);
    });

    it("rejects an E3 on an unregistered param set", async () => {
      const { ethers, verifier, paramSetSource } = await deploy();
      await paramSetSource.setParamSet(E3_ID, 7);
      const publicKey = "0x" + "ab".repeat(96);
      await expect(
        verifier.verify.staticCall(
          E3_ID,
          0n,
          nodes(ethers),
          ethers.keccak256(publicKey),
          ethers.ZeroHash,
          encode(ethers, fixture.parties, publicKey),
          { gasLimit: HONK_VERIFY_GAS_LIMIT },
        ),
      )
        .to.be.revertedWithCustomError(verifier, "UnsupportedParamSet")
        .withArgs(7);
    });

    it("exposes the compiled committee size", async () => {
      const { verifier } = await deploy();
      expect(await verifier.h()).to.equal(COMMITTEE_N);
    });
  });

  describe("CkksDecryptionVerifier", () => {
    async function deploy() {
      const { ethers } = await network.connect();
      const circuitVerifier = await deployVerifier(
        ethers,
        `DecryptedSharesAggregationCkksPs${PARAM_SET}Verifier.sol`,
        `DecryptedSharesAggregationCkksPs${PARAM_SET}Verifier`,
      );
      const otherCircuitVerifier = await deployVerifier(
        ethers,
        `DecryptedSharesAggregationCkksPs${OTHER_PARAM_SET}Verifier.sol`,
        `DecryptedSharesAggregationCkksPs${OTHER_PARAM_SET}Verifier`,
      );
      const paramSetSource = await (
        await ethers.getContractFactory("MockParamSetSource")
      ).deploy();
      await paramSetSource.setParamSet(E3_ID, PARAM_SET);

      const verifier = await (
        await ethers.getContractFactory("CkksDecryptionVerifier")
      ).deploy(
        await paramSetSource.getAddress(),
        [PARAM_SET, OTHER_PARAM_SET],
        [
          await circuitVerifier.getAddress(),
          await otherCircuitVerifier.getAddress(),
        ],
        THRESHOLD_T,
      );
      await verifier.waitForDeployment();
      return { ethers, verifier, paramSetSource };
    }

    function encode(
      ethers: Awaited<ReturnType<typeof network.connect>>["ethers"],
      leg: LegFixture,
    ): string {
      return ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes", "bytes32[]"],
        [leg.proof, leg.publicInputs],
      );
    }

    // The verifier binds `decryptionDomain` to the proof's domain_hi/lo public
    // inputs (same hi/lo split as BFV's CommitteeHashLib). The fixture proof
    // was produced for `fixture.c7DecryptionDomain`; anything else must revert.
    const call = (
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      verifier: any,
      ethers: { ZeroHash: string },
      blob: string,
      decryptionDomain: string = fixture.c7DecryptionDomain,
    ) =>
      verifier.verify.staticCall(
        E3_ID,
        decryptionDomain,
        ethers.ZeroHash,
        ethers.ZeroHash,
        ethers.ZeroHash,
        blob,
        { gasLimit: HONK_VERIFY_GAS_LIMIT },
      );

    it("accepts the real C7-CKKS aggregation proof under its own decryption domain", async () => {
      const { ethers, verifier } = await deploy();
      expect(await call(verifier, ethers, encode(ethers, fixture.c7))).to.equal(
        true,
      );
    });

    it("rejects the proof replayed under a DIFFERENT E3's decryption domain", async () => {
      // Anti-replay: a valid C7-CKKS proof for one (chain, deployment, e3Id,
      // committee, ciphertext, key) tuple is not accepted for any other.
      // Before domain binding existed this call succeeded.
      const { ethers, verifier } = await deploy();
      const otherDomain = ethers.keccak256(ethers.toUtf8Bytes("some other E3"));
      await expect(
        call(verifier, ethers, encode(ethers, fixture.c7), otherDomain),
      ).to.be.revertedWithCustomError(verifier, "DomainBindingMismatch");
      // And the all-zero domain the old (unbound) verifier was tested with:
      await expect(
        call(verifier, ethers, encode(ethers, fixture.c7), ethers.ZeroHash),
      ).to.be.revertedWithCustomError(verifier, "DomainBindingMismatch");
    });

    it("rejects a forged u_global (the vacuous-CRT attack the circuit now blocks)", async () => {
      // Flip one u_global coefficient word. With an unconstrained CRT quotient
      // a prover could have re-proved ANY u_global; with the range-constrained
      // lift the proof is bound to the unique canonical reconstruction, so a
      // changed u_global word cannot carry a valid proof. The generated Honk
      // verifier REVERTS from inside `verify` (Errors.SumcheckFailed) rather
      // than returning false, so the failure surfaces as the Honk library's
      // error, not the wrapper's InvalidProof — assert that precise error.
      const { ethers, verifier } = await deploy();
      const publicInputs = [...fixture.c7.publicInputs];
      const uGlobalStart = 2 * (THRESHOLD_T + 1) + 2;
      const w = BigInt(publicInputs[uGlobalStart]) ^ 1n;
      publicInputs[uGlobalStart] = "0x" + w.toString(16).padStart(64, "0");
      const honkErrors = new ethers.Interface(["error SumcheckFailed()"]);
      await expect(
        call(verifier, ethers, encode(ethers, { ...fixture.c7, publicInputs })),
      ).to.be.revertedWithCustomError(
        { interface: honkErrors },
        "SumcheckFailed",
      );
    });

    it("reports gas for one C7-CKKS verification", async () => {
      const { ethers, verifier } = await deploy();
      const gas = await verifier.verify.estimateGas(
        E3_ID,
        fixture.c7DecryptionDomain,
        ethers.ZeroHash,
        ethers.ZeroHash,
        ethers.ZeroHash,
        encode(ethers, fixture.c7),
        { gasLimit: HONK_VERIFY_GAS_LIMIT },
      );
      console.log(`      CkksDecryptionVerifier.verify: ${gas} gas`);
      expect(gas).to.be.greaterThan(0n);
    });

    it("rejects a tampered proof", async () => {
      const { ethers, verifier } = await deploy();
      const blob = encode(ethers, {
        ...fixture.c7,
        proof: tamperProof(fixture.c7.proof),
      });
      await expect(call(verifier, ethers, blob)).to.be.revert(ethers);
    });

    it("rejects a wrong-length public-input array", async () => {
      const { ethers, verifier } = await deploy();
      const blob = encode(ethers, {
        ...fixture.c7,
        publicInputs: fixture.c7.publicInputs.slice(0, -1),
      });
      await expect(
        call(verifier, ethers, blob),
      ).to.be.revertedWithCustomError(verifier, "InvalidPublicInputsLength");
    });

    it("rejects duplicated decryption-share commitments", async () => {
      const { ethers, verifier } = await deploy();
      const publicInputs = [...fixture.c7.publicInputs];
      publicInputs[1] = publicInputs[0]; // one party's share counted twice
      const blob = encode(ethers, { ...fixture.c7, publicInputs });
      await expect(call(verifier, ethers, blob))
        .to.be.revertedWithCustomError(verifier, "DuplicateShareCommitment")
        .withArgs(1);
    });

    it("rejects non-increasing party ids", async () => {
      const { ethers, verifier } = await deploy();
      const publicInputs = [...fixture.c7.publicInputs];
      // party_ids occupy [T+1 .. 2T+2); swap them so they descend.
      const a = publicInputs[THRESHOLD_T + 1];
      publicInputs[THRESHOLD_T + 1] = publicInputs[THRESHOLD_T + 2];
      publicInputs[THRESHOLD_T + 2] = a;
      const blob = encode(ethers, { ...fixture.c7, publicInputs });
      await expect(
        call(verifier, ethers, blob),
      ).to.be.revertedWithCustomError(
        verifier,
        "PartyIdsNotStrictlyIncreasing",
      );
    });

    it(`rejects ParamSet ${PARAM_SET} proofs when the E3 declares ParamSet ${OTHER_PARAM_SET}`, async () => {
      const { ethers, verifier, paramSetSource } = await deploy();
      await paramSetSource.setParamSet(E3_ID, OTHER_PARAM_SET);
      await expect(call(verifier, ethers, encode(ethers, fixture.c7))).to.be.revert(ethers);
    });

    it("rejects an E3 on an unregistered param set", async () => {
      const { ethers, verifier, paramSetSource } = await deploy();
      await paramSetSource.setParamSet(E3_ID, 9);
      await expect(call(verifier, ethers, encode(ethers, fixture.c7)))
        .to.be.revertedWithCustomError(verifier, "UnsupportedParamSet")
        .withArgs(9);
    });

    it("exposes the compiled threshold", async () => {
      const { verifier } = await deploy();
      expect(await verifier.threshold()).to.equal(THRESHOLD_T);
    });
  });

  it("fixture shape matches the circuits' public-input layouts", () => {
    expect(fixture.parties).to.have.length(COMMITTEE_N);
    // C1-CKKS: (sk_commitment, pk_commitment, e_sm_commitment).
    for (const party of fixture.parties) {
      expect(party.publicInputs).to.have.length(3);
    }
    // Distinct dealers: the replay guard depends on this.
    const pks = fixture.parties.map((p) => p.publicInputs[1]);
    const sks = fixture.parties.map((p) => p.publicInputs[0]);
    expect(new Set(pks).size).to.equal(COMMITTEE_N);
    expect(new Set(sks).size).to.equal(COMMITTEE_N);
    // C7-CKKS: 2*(T+1) commitments/party_ids + 2 domain words + N=512
    // u_global coefficients (the FULL ring, matching C6-CKKS's d_commitment
    // window — not BFV's sparse 100).
    expect(fixture.c7.publicInputs).to.have.length(
      2 * (THRESHOLD_T + 1) + 2 + 512,
    );
    // The fixture's domain words are what c7DecryptionDomain packs.
    const hi = BigInt(fixture.c7.publicInputs[2 * (THRESHOLD_T + 1)]);
    const lo = BigInt(fixture.c7.publicInputs[2 * (THRESHOLD_T + 1) + 1]);
    expect(BigInt(fixture.c7DecryptionDomain)).to.equal((hi << 128n) | lo);
  });
});
}
