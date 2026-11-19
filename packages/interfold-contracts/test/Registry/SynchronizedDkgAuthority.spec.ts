// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";
import type {
  ContractTransactionReceipt,
  LogDescription,
  TypedDataDomain,
} from "ethers";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

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
import {
  compileSynchronized,
  deployCompiled,
} from "../fixtures/synchronizedSolidity";

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
      "SynchronizedDkgSeedLib",
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
    const nodes = signers.map((signer) => signer.address) as [
      string,
      string,
      string,
    ];
    const e3Id = (1n << 200n) + 8n;
    await controller.configure(
      e3Id,
      await registry.getAddress(),
      await wrapper.getAddress(),
      config,
    );
    const contextReceipt: ContractTransactionReceipt | null = await (
      await registry.seed(e3Id, await controller.getAddress(), nodes)
    ).wait();
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
      contextReceipt,
    };
  }

  type Fixture = Awaited<ReturnType<typeof setup>>;

  it("establishes the distinct request-frozen synchronized signing domain", async () => {
    const f = await networkHelpers.loadFixture(setup);
    const events = f.contextReceipt!.logs.map((log): LogDescription | null => {
      try {
        return f.registry.interface.parseLog(log);
      } catch {
        return null;
      }
    });
    const context = events.find(
      (event) => event?.name === "SynchronizedDkgContextEstablished",
    )!;
    expect(context.args).to.deep.equal([
      f.e3Id,
      await f.registry.getAddress(),
      await f.wrapper.getAddress(),
      config,
    ]);
    expect(
      events.some(
        (event) => event?.name === "DkgFoldAttestationContextEstablished",
      ),
    ).to.equal(false);
  });

  async function publication(
    f: Fixture,
    changes: Record<string, unknown> = {},
    domainChanges: Partial<TypedDataDomain> = {},
  ) {
    const signatures: string[] = [];
    const pkCommitment = f.fields[13]!;
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
            dealerBatch: f.fields[6],
            pkCommitment,
            partyId,
            skAggCommit: f.fields[9 + row],
            keyBundleCommit: f.fields[11 + row],
            ...changes,
          },
        ),
      );
    }
    return {
      pkCommitment,
      dealerBatch: f.fields[6]!,
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

  (process.env.E3_SYNC_DECRYPTION_PROOFS === "1" ? it : it.skip)(
    "binds a real synchronized decryption to the signed registry publication",
    async function () {
      // Includes the locked Rust build on cold CI workers.
      this.timeout(50 * 60_000);
      // A separate finalized request is seeded below with the real DKG verifier.
      const base = await networkHelpers.loadFixture(setup);
      const f = { ...base, e3Id: base.e3Id + 1n };
      const root = resolve("../..");
      const dir = mkdtempSync(join(tmpdir(), "sync-decryption-"));
      try {
        const fixture = join(dir, "export");
        const context = join(dir, "context.json");
        const interfold = await f.controller.getAddress();
        const committee = ethers.keccak256(ethers.concat(f.nodes));
        writeFileSync(
          context,
          JSON.stringify({
            chain_id: Number(f.chainId),
            e3_id: ethers.toBeHex(f.e3Id),
            interfold,
            nodes: f.nodes,
          }),
        );
        execFileSync("pnpm", ["rust:test:sync-dkg:proofs"], {
          cwd: root,
          env: {
            ...process.env,
            E3_ZK_PROVER_SKIP_FIXTURE_BUILD: "1",
            E3_SYNC_DECRYPTION_CONTEXT: context,
            E3_SYNC_DECRYPTION_EXPORT: fixture,
            E3_SYNC_DKG_EXPORT: join(dir, "dkg"),
          },
          stdio: "inherit",
        });
        execFileSync(
          "pnpm",
          ["exec", "tsx", "scripts/circuits/render-sync-honk.ts", fixture],
          { cwd: root, stdio: "inherit" },
        );
        const source = "SynchronizedHonk.sol";
        const deployHonk = (path: string, name: string) =>
          deployCompiled(
            compileSynchronized({
              [source]: { content: readFileSync(join(path, source), "utf8") },
            }),
            f.signers[0]!,
          )(source, name);
        const honk = await deployHonk(fixture, "DecryptionAggregatorVerifier");
        const expected = JSON.parse(
          readFileSync(join(fixture, "expected.json"), "utf8"),
        );
        const fields = ethers
          .hexlify(readFileSync(join(fixture, "public_inputs")))
          .slice(2)
          .match(/.{64}/g)!
          .map((x) => "0x" + x);
        const raw = readFileSync(join(fixture, "proof"));
        const bytes = (x: number[]) => ethers.hexlify(Uint8Array.from(x));
        const wrapper = await ethers.deployContract(
          "SynchronizedDecryptionVerifier",
          [
            await honk.getAddress(),
            await f.registry.getAddress(),
            expected.pins[0],
            expected.pins[1],
          ],
        );
        const dkg = JSON.parse(
          readFileSync(join(dir, "dkg", "publication.json"), "utf8"),
        );
        const dkgHonk = await deployHonk(
          join(dir, "dkg"),
          "DkgAggregatorVerifier",
        );
        f.wrapper = await ethers.deployContract(
          "SynchronizedDkgPublicationVerifier",
          [
            await dkgHonk.getAddress(),
            interfold,
            config,
            dkg.setup_tree,
            dkg.c5_key_hash,
            3,
            2,
          ],
        );
        await f.controller.configure(
          f.e3Id,
          await f.registry.getAddress(),
          await f.wrapper.getAddress(),
          config,
        );
        await f.registry.seed(f.e3Id, interfold, f.nodes);
        f.binding = await f.wrapper.setupBinding(f.e3Id, f.nodes);
        f.fields = dkg.public_inputs;
        expect(dkg.sk_commitments).to.deep.equal(expected.sk.map(bytes));
        expect(dkg.key_bundles).to.deep.equal(expected.bundles.map(bytes));
        expect(dkg.pk_commitment).to.equal(expected.pk);
        const signed = await publication(f);
        await f.registry.publishSynchronizedCommittee(f.e3Id, {
          ...signed,
          proof: coder.encode(["bytes", "bytes32[]"], [dkg.proof, f.fields]),
        });
        const pk = (await f.controller.getE3(f.e3Id)).committeePublicKey;
        const domain = ethers.keccak256(
          coder.encode(
            ["uint256", "address", "uint256", "bytes32", "bytes32", "bytes32"],
            [
              f.chainId,
              interfold,
              f.e3Id,
              committee,
              expected.ciphertext_hash,
              pk,
            ],
          ),
        );
        const plaintext = ethers.keccak256(bytes(expected.plaintext));
        const ct = bytes(expected.ciphertext);
        const call = (
          inputs = fields,
          id = f.e3Id,
          d = domain,
          p = plaintext,
          c = committee,
          cipher = ct,
        ) =>
          wrapper.verify(
            id,
            d,
            p,
            c,
            cipher,
            coder.encode(["bytes", "bytes32[]"], [raw, inputs]),
          );
        expect(await call()).to.equal(true);
        await expect(
          call(undefined, f.e3Id + 1n),
        ).to.be.revertedWithCustomError(
          wrapper,
          "InvalidSynchronizedAuthority",
        );
        await expect(
          call(undefined, undefined, field(1)),
        ).to.be.revertedWithCustomError(wrapper, "DomainBindingMismatch");
        await expect(
          call(undefined, undefined, undefined, field(1)),
        ).to.be.revertedWithCustomError(wrapper, "PlaintextHashMismatch");
        await expect(
          call(undefined, undefined, undefined, undefined, field(1)),
        ).to.be.revertedWithCustomError(wrapper, "DomainBindingMismatch");
        await expect(
          call(undefined, undefined, undefined, undefined, undefined, field(1)),
        ).to.be.revertedWithCustomError(
          wrapper,
          "CiphertextCommitmentMismatch",
        );
        await expect(call(fields.slice(0, -1))).to.be.revertedWithCustomError(
          wrapper,
          "InvalidPublicInputsLength",
        );
        const changed = (
          idx: number,
          value: bigint = BigInt(fields[idx]!) ^ 1n,
        ) => fields.map((v, i) => (i === idx ? field(value) : v));
        for (const [idx, error] of [
          [0, "VkHashMismatch"],
          [1, "VkHashMismatch"],
          [14, "DomainBindingMismatch"],
          [16, "DkgAnchorMismatch"],
          [17, "DkgAnchorMismatch"],
          [19, "DomainBindingMismatch"],
          [21, "DkgAnchorMismatch"],
          [22, "DkgAnchorMismatch"],
          [23, "CiphertextCommitmentMismatch"],
        ] as const) {
          await expect(call(changed(idx))).to.be.revertedWithCustomError(
            wrapper,
            error,
          );
        }
        await expect(
          call(changed(12, 1n << 255n)),
        ).to.be.revertedWithCustomError(wrapper, "NonCanonicalPublicInput");
        await expect(
          call(changed(26, 1n << 64n)),
        ).to.be.revertedWithCustomError(
          wrapper,
          "MessageCoefficientOutOfRange",
        );
        // d has no independent registry value. Its authenticity comes from the actual Honk proof.
        await expect(call(changed(12))).to.be.revert(ethers);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );

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
