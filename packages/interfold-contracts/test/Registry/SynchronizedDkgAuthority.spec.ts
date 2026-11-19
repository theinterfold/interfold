// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";
import type { TypedDataDomain } from "ethers";
import { readFileSync } from "node:fs";

import {
  buildRequestParams,
  deployInterfoldSystem,
  ethers,
  networkHelpers,
} from "../fixtures";
import {
  synchronizedDkgAttestationDomain,
  synchronizedDkgAttestationTypes,
} from "../fixtures/synchronizedDkgAttestation";

const coder = ethers.AbiCoder.defaultAbiCoder();
const field = (value: number | bigint) => ethers.toBeHex(value, 32);
const config = readFileSync("contracts/lib/BfvProtocol.sol", "utf8").match(
  /SYNC_INSECURE_64_MINIMUM_CONFIG_ID\s*=\s*(0x[0-9a-f]+);/,
)![1]!;

describe("Synchronized DKG registry authority", function () {
  async function setup() {
    const circuit = await ethers.deployContract("MockCircuitVerifier");
    await circuit.setReturnValue(true);
    const controller = await ethers.deployContract(
      "SynchronizedDkgControllerHarness",
    );
    const libraries: Record<string, string> = {};
    for (const name of [
      "PoseidonT3",
      "RegistrySortitionLib",
      "DkgPublicationLib",
    ]) {
      const library = await ethers.deployContract(name);
      libraries[name] = await library.getAddress();
    }
    const factory = await ethers.getContractFactory(
      "SynchronizedDkgRegistryHarness",
      { libraries },
    );
    const registry = await factory.deploy();
    const wrapper = await ethers.deployContract(
      "SynchronizedDkgPublicationVerifier",
      [
        await circuit.getAddress(),
        await controller.getAddress(),
        config,
        field(10),
        field(11),
        3,
        2,
      ],
    );
    const signers = (await ethers.getSigners())
      .slice(0, 3)
      .sort((a, b) =>
        a.address.toLowerCase().localeCompare(b.address.toLowerCase()),
      );
    const nodes = signers.map((signer) => signer.address);
    const e3Id = (1n << 200n) + 8n;
    await controller.configure(
      e3Id,
      await registry.getAddress(),
      await wrapper.getAddress(),
      config,
    );
    await registry.seed(e3Id, await controller.getAddress(), nodes);
    const { chainId } = await ethers.provider.getNetwork();
    const binding = await wrapper.setupBinding(e3Id, nodes);
    const ids = [0, 2];
    // Synthetic public fields and a mock circuit outcome test authority, not proof validity.
    const fields = [
      field(10),
      field(11),
      field(BigInt(binding) >> 128n),
      field(BigInt(binding) & ((1n << 128n) - 1n)),
      ...ids.map(field),
      field(71),
      field(20),
      field(21),
      field(30),
      field(31),
      field(40),
      field(41),
      field(70),
    ];
    return {
      registry,
      circuit,
      controller,
      wrapper,
      signers,
      nodes,
      chainId,
      binding,
      e3Id,
      ids,
      fields,
    };
  }

  type Fixture = Awaited<ReturnType<typeof setup>>;

  async function publication(
    f: Fixture,
    changes: Record<string, unknown> = {},
    domainChanges: Partial<TypedDataDomain> = {},
  ) {
    const signatures: string[] = [];
    for (let row = 0; row < f.ids.length; ++row) {
      const partyId = f.ids[row]!;
      signatures.push(
        await f.signers[partyId]!.signTypedData(
          {
            ...synchronizedDkgAttestationDomain(
              f.chainId,
              await f.wrapper.getAddress(),
            ),
            ...domainChanges,
          },
          synchronizedDkgAttestationTypes,
          {
            registry: await f.registry.getAddress(),
            e3Id: f.e3Id,
            cryptoConfigId: config,
            setupBinding: f.binding,
            rosterHash: ethers.keccak256(coder.encode(["uint256[]"], [f.ids])),
            dealerBatch: field(71),
            pkCommitment: field(70),
            partyId,
            skAggCommit: field(30 + row),
            keyBundleCommit: field(40 + row),
            ...changes,
          },
        ),
      );
    }
    return {
      pkCommitment: field(70),
      dealerBatch: field(71),
      partyIds: f.ids,
      proof: coder.encode(["bytes", "bytes32[]"], ["0x01", f.fields]),
      signatures,
    };
  }

  async function unchanged(f: Fixture) {
    expect(
      (await f.registry.getSynchronizedDkgAuthority(f.e3Id)).version,
    ).to.equal(0);
    expect(await f.registry.publicKeyHashes(f.e3Id)).to.equal(ethers.ZeroHash);
    await expect(
      f.registry.committeePublicKey(f.e3Id),
    ).to.be.revertedWithCustomError(f.registry, "CommitteeNotPublished");
    expect((await f.controller.getE3(f.e3Id)).committeePublicKey).to.equal(
      ethers.ZeroHash,
    );
  }

  it("publishes distinct immutable anchors with consent of every selected recipient", async () => {
    const f = await networkHelpers.loadFixture(setup);
    // Frozen pre-extension ICiphernodeRegistry ERC-165 ID.
    expect(await f.registry.supportsInterface("0xe921dc0e")).to.equal(true);
    const candidate = await publication(f);
    await expect(
      f.registry.publishSynchronizedCommittee(f.e3Id, candidate),
    ).to.emit(f.registry, "SynchronizedDkgAuthorityPublished");
    const authority = await f.registry.getSynchronizedDkgAuthority(f.e3Id);
    expect(authority.version).to.equal(1);
    expect(authority.verifier).to.equal(await f.wrapper.getAddress());
    expect(authority.cryptoConfigId).to.equal(config);
    expect(authority.setupBinding).to.equal(f.binding);
    expect(authority.dealerBatch).to.equal(candidate.dealerBatch);
    expect(authority.pkCommitment).to.equal(candidate.pkCommitment);
    expect([...authority.partyIds]).to.deep.equal([0n, 2n]);
    expect([...authority.thresholdPkCommits]).to.deep.equal([
      field(20),
      field(21),
    ]);
    expect([...authority.skAggCommits]).to.deep.equal([field(30), field(31)]);
    expect([...authority.keyBundleCommits]).to.deep.equal([
      field(40),
      field(41),
    ]);
    expect(
      (await f.registry.getDkgAnchors(f.e3Id)).map(
        (column: readonly unknown[]) => [...column],
      ),
    ).to.deep.equal([[], [], []]);
    await expect(
      f.registry.publishSynchronizedCommittee(f.e3Id, candidate),
    ).to.be.revertedWithCustomError(f.registry, "CommitteeAlreadyPublished");
  });

  for (const [name, value] of [
    ["registry", "0x1212121212121212121212121212121212121212"],
    ["e3Id", 9n],
    ["cryptoConfigId", field(1)],
    ["setupBinding", field(2)],
    ["rosterHash", field(3)],
    ["dealerBatch", field(4)],
    ["pkCommitment", field(5)],
    ["partyId", 1],
    ["skAggCommit", field(6)],
    ["keyBundleCommit", field(7)],
  ] as const) {
    it(`rejects consent for another ${name} without reserving the key`, async () => {
      const f = await networkHelpers.loadFixture(setup);
      await expect(
        f.registry.publishSynchronizedCommittee(
          f.e3Id,
          await publication(f, { [name]: value }),
        ),
      ).to.be.revertedWithCustomError(
        f.registry,
        "InvalidSynchronizedDkgPublication",
      );
      await unchanged(f);
      await f.registry.publishSynchronizedCommittee(
        f.e3Id,
        await publication(f),
      );
    });
  }

  for (const domain of [
    { chainId: 1n },
    { verifyingContract: "0x1212121212121212121212121212121212121212" },
    { name: "InterfoldDkgFoldAttestation" },
    { version: "2" },
  ]) {
    it(`rejects a different attestation domain ${Object.keys(domain)[0]}`, async () => {
      const f = await networkHelpers.loadFixture(setup);
      await expect(
        f.registry.publishSynchronizedCommittee(
          f.e3Id,
          await publication(f, {}, domain),
        ),
      ).to.be.revertedWithCustomError(
        f.registry,
        "InvalidSynchronizedDkgPublication",
      );
      await unchanged(f);
    });
  }

  it("requires exactly H correctly ordered signatures, not duplicates or a quorum shortcut", async () => {
    const f = await networkHelpers.loadFixture(setup);
    const candidate = await publication(f);
    for (const signatures of [
      candidate.signatures.slice(0, 1),
      [...candidate.signatures, candidate.signatures[0]!],
      [candidate.signatures[0]!, candidate.signatures[0]!],
      [...candidate.signatures].reverse(),
    ]) {
      await expect(
        f.registry.publishSynchronizedCommittee(f.e3Id, {
          ...candidate,
          signatures,
        }),
      ).to.be.revertedWithCustomError(
        f.registry,
        "InvalidSynchronizedDkgPublication",
      );
      await unchanged(f);
    }
  });

  it("rejects an inactive canonical signer, invalid proof, and the legacy SS publication entry", async () => {
    const f = await networkHelpers.loadFixture(setup);
    const candidate = await publication(f);
    await expect(
      f.registry.publishCommittee(
        f.e3Id,
        candidate.pkCommitment,
        candidate.proof,
        "0x01",
      ),
    ).to.be.revertedWithCustomError(
      f.registry,
      "SynchronizedDkgPublicationRequired",
    );
    await f.circuit.setReturnValue(false);
    await expect(
      f.registry.publishSynchronizedCommittee(f.e3Id, candidate),
    ).to.be.revertedWithCustomError(f.wrapper, "InvalidPublication");
    await f.circuit.setReturnValue(true);
    await f.registry.exclude(f.e3Id, f.nodes[2]!);
    await expect(
      f.registry.publishSynchronizedCommittee(f.e3Id, candidate),
    ).to.be.revertedWithCustomError(
      f.registry,
      "InvalidSynchronizedDkgPublication",
    );
    await unchanged(f);
  });

  it("uses request-frozen configuration/verifier and rolls back a rejected lifecycle callback", async () => {
    const f = await networkHelpers.loadFixture(setup);
    const candidate = await publication(f);
    await f.controller.configure(
      f.e3Id,
      await f.registry.getAddress(),
      await f.wrapper.getAddress(),
      field(1),
    );
    await expect(
      f.registry.publishSynchronizedCommittee(f.e3Id, candidate),
    ).to.be.revertedWithCustomError(
      f.registry,
      "InvalidSynchronizedDkgPublication",
    );
    await f.controller.configure(
      f.e3Id,
      await f.registry.getAddress(),
      await f.wrapper.getAddress(),
      config,
    );
    await f.controller.setReject(true);
    await expect(
      f.registry.publishSynchronizedCommittee(f.e3Id, candidate),
    ).to.be.revertedWithCustomError(f.controller, "CallbackRejected");
    await unchanged(f);
    await f.controller.setReject(false);
    await f.registry.publishSynchronizedCommittee(f.e3Id, candidate);
  });

  it("requires consent for the exact request verifier, not another identical deployment", async () => {
    const f = await networkHelpers.loadFixture(setup);
    const candidate = await publication(f);
    const replacement = await ethers.deployContract(
      "SynchronizedDkgPublicationVerifier",
      [
        await f.circuit.getAddress(),
        await f.controller.getAddress(),
        config,
        field(10),
        field(11),
        3,
        2,
      ],
    );
    await f.controller.configure(
      f.e3Id,
      await f.registry.getAddress(),
      await replacement.getAddress(),
      config,
    );
    await expect(
      f.registry.publishSynchronizedCommittee(f.e3Id, candidate),
    ).to.be.revertedWithCustomError(
      f.registry,
      "InvalidSynchronizedDkgPublication",
    );
    await unchanged(f);
    await f.registry.publishSynchronizedCommittee(
      f.e3Id,
      await publication({ ...f, wrapper: replacement }),
    );
    expect(
      (await f.registry.getSynchronizedDkgAuthority(f.e3Id)).verifier,
    ).to.equal(await replacement.getAddress());
  });

  it("rejects an SS identity and noncanonical N/H before any proof can be accepted", async () => {
    const f = await networkHelpers.loadFixture(setup);
    for (const [identity, n, h] of [
      [field(1), 3, 2],
      [config, 4, 2],
      [config, 3, 1],
    ] as const) {
      await expect(
        ethers.deployContract("SynchronizedDkgPublicationVerifier", [
          await f.circuit.getAddress(),
          await f.controller.getAddress(),
          identity,
          field(10),
          field(11),
          n,
          h,
        ]),
      ).to.be.revertedWithCustomError(f.wrapper, "InvalidConfiguration");
    }
  });

  it("does not admit synchronized requests or change the existing Interfold interface ID", async () => {
    const system = await deployInterfoldSystem();
    expect(await system.interfold.supportsInterface("0x1befd4d3")).to.equal(
      true,
    );
    const params = await buildRequestParams(
      system.mocks.e3Program,
      system.mocks.decryptionVerifier,
    );
    await expect(
      system.interfold.request({
        ...params,
        expectedCryptoConfigId: config,
        expectedFeeToken: await system.usdcToken.getAddress(),
        maxFee: ethers.MaxUint256,
      }),
    ).to.be.revertedWithCustomError(system.interfold, "CryptoConfigChanged");
  });
});
