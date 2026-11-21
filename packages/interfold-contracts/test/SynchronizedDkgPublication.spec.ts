// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";
import { network } from "hardhat";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  compileSynchronized,
  deployCompiled,
} from "./fixtures/synchronizedSolidity";

// Prepared only by the explicit Rust real-proof suite. Ordinary contract runs do not replace
// missing proofs with mocks or accept a stale committed fixture.
const fixturePath = process.env.E3_SYNC_PUBLICATION_FIXTURE;
const prepared = fixturePath ? describe : describe.skip;
const { ethers } = await network.connect();
const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

prepared("SynchronizedDkgPublication real proof", function () {
  this.timeout(180_000);

  it("accepts the exact setup and rejects context, roster, anchors and proof substitutions", async () => {
    const fixture = JSON.parse(fs.readFileSync(fixturePath!, "utf8"));
    const source = fs.readFileSync(
      process.env.E3_SYNC_PUBLICATION_VERIFIER_SOURCE!,
      "utf8",
    );
    const names = [
      "contracts/verifiers/bfv/SynchronizedDkgPublicationVerifier.sol",
      "contracts/interfaces/ICircuitVerifier.sol",
      "contracts/lib/CommitteeHashLib.sol",
      "contracts/lib/BfvProtocol.sol",
      "contracts/verifiers/bfv/BfvPkVerifier.sol",
      "contracts/interfaces/IPkVerifier.sol",
    ];
    const sources = Object.fromEntries(
      names.map((name) => [
        name,
        {
          content: fs.readFileSync(
            path.join(root, "packages/interfold-contracts", name),
            "utf8",
          ),
        },
      ]),
    );
    sources["SynchronizedHonk.sol"] = { content: source };
    const contracts = compileSynchronized(sources);
    // Retain this exact temporary verifier for the Rust recovered-setup/registry campaign.
    fs.writeFileSync(
      path.join(path.dirname(fixturePath!), "SynchronizedHonk.json"),
      JSON.stringify(
        Object.fromEntries(
          Object.entries(contracts["SynchronizedHonk.sol"]).map(
            ([name, value]) => {
              const compiled = value as {
                abi: unknown;
                evm: {
                  bytecode: { object: string; linkReferences: unknown };
                  deployedBytecode: { object: string };
                };
              };
              return [
                name,
                {
                  contractName: name,
                  abi: compiled.abi,
                  bytecode: `0x${compiled.evm.bytecode.object}`,
                  deployedBytecode: `0x${compiled.evm.deployedBytecode.object}`,
                  linkReferences: compiled.evm.bytecode.linkReferences,
                },
              ];
            },
          ),
        ),
      ),
    );
    const [signer] = await ethers.getSigners();
    const deploy = deployCompiled(contracts, signer);
    const honk = await deploy("SynchronizedHonk.sol", "DkgAggregatorVerifier");
    const wrapperFile = names[0];
    const configuration = [
      await honk.getAddress(),
      fixture.interfold,
      fixture.crypto_config_id,
      fixture.setup_tree,
      fixture.c5_key_hash,
      fixture.committee.length,
      fixture.dealers.length,
    ];
    const wrapper = await deploy(
      wrapperFile,
      "SynchronizedDkgPublicationVerifier",
      configuration,
    );
    const encode = (fields: string[], proof = fixture.proof) =>
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes", "bytes32[]"],
        [proof, fields],
      );
    const call = (
      proof = encode(fixture.public_inputs),
      e3 = fixture.e3_id,
      committee = fixture.committee,
      dealers = fixture.dealers,
      pk = fixture.pk_commitment,
      batch = fixture.dealer_batch,
    ) =>
      wrapper
        .getFunction("verify")
        .staticCall(e3, committee, dealers, pk, batch, proof);
    const accepted = await call();
    expect([...accepted[0]]).to.deep.equal(fixture.sk_commitments);
    expect([...accepted[1]]).to.deep.equal(fixture.key_bundles);
    expect([...accepted[2]]).to.deep.equal(
      fixture.public_inputs.slice(
        5 + fixture.dealers.length,
        5 + 2 * fixture.dealers.length,
      ),
    );
    const ss = await deploy(
      "contracts/verifiers/bfv/BfvPkVerifier.sol",
      "BfvPkVerifier",
      [
        await honk.getAddress(),
        fixture.setup_tree,
        fixture.c5_key_hash,
        fixture.dealers.length,
      ],
    );
    await expect(
      ss
        .getFunction("verify")
        .staticCall(
          fixture.e3_id,
          0,
          fixture.committee,
          fixture.pk_commitment,
          ethers.keccak256(ethers.concat(fixture.committee)),
          encode(fixture.public_inputs),
        ),
    ).to.be.revertedWithCustomError(ss, "InvalidPublicInputsLength");
    await expect(
      call(undefined, (BigInt(fixture.e3_id) + 1n).toString()),
    ).to.be.revert(ethers);
    await expect(
      call(undefined, (BigInt(fixture.e3_id) + (1n << 200n)).toString()),
    ).to.be.revert(ethers);
    await expect(call(encode(fixture.public_inputs.slice(0, -1)))).to.be.revert(
      ethers,
    );
    await expect(
      call(undefined, undefined, [...fixture.committee].reverse()),
    ).to.be.revert(ethers);
    const otherCommittee = [...fixture.committee];
    otherCommittee[0] = "0x0000000000000000000000000000000000000001";
    await expect(call(undefined, undefined, otherCommittee)).to.be.revert(
      ethers,
    );
    await expect(call(undefined, undefined, undefined, [0, 1])).to.be.revert(
      ethers,
    );
    await expect(call(undefined, undefined, undefined, [0, 0])).to.be.revert(
      ethers,
    );
    await expect(call(undefined, undefined, undefined, [0, 3])).to.be.revert(
      ethers,
    );
    await expect(
      call(undefined, undefined, undefined, undefined, ethers.ZeroHash),
    ).to.be.revert(ethers);
    await expect(
      call(
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        ethers.ZeroHash,
      ),
    ).to.be.revert(ethers);
    const alias = [...fixture.public_inputs];
    alias[2] = ethers.toBeHex(
      BigInt(alias[2]) +
        21888242871839275222246405745257275088548364400416034343698204186575808495617n,
      32,
    );
    await expect(call(encode(alias))).to.be.revert(ethers);
    for (const slot of [0, 1, 6, 9, 11, 13]) {
      const altered = [...fixture.public_inputs];
      altered[slot] = ethers.toBeHex(BigInt(altered[slot]) ^ 1n, 32);
      await expect(call(encode(altered))).to.be.revert(ethers);
    }
    const corrupted = ethers.getBytes(fixture.proof);
    corrupted[corrupted.length - 1] ^= 1;
    await expect(
      call(encode(fixture.public_inputs, ethers.hexlify(corrupted))),
    ).to.be.revert(ethers);
    const wrongConfig = [...configuration];
    wrongConfig[2] = ethers.toBeHex(123, 32);
    await expect(
      deploy(wrapperFile, "SynchronizedDkgPublicationVerifier", wrongConfig),
    ).to.be.revert(ethers);
    const other = [...configuration];
    other[1] = "0x1212121212121212121212121212121212121212";
    const changed = await deploy(
      wrapperFile,
      "SynchronizedDkgPublicationVerifier",
      other,
    );
    await expect(
      changed
        .getFunction("verify")
        .staticCall(
          fixture.e3_id,
          fixture.committee,
          fixture.dealers,
          fixture.pk_commitment,
          fixture.dealer_batch,
          encode(fixture.public_inputs),
        ),
    ).to.be.revert(ethers);
  });
});
