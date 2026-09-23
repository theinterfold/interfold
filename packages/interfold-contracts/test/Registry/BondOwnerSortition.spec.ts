// SPDX-License-Identifier: LGPL-3.0-only
import { expect } from "chai";
import type { Signer } from "ethers";

import {
  deployInterfoldSystem,
  ethers,
  networkHelpers,
  setupOperatorForSortition,
} from "../fixtures";

const { loadFixture, time, setStorageAt, setBalance, takeSnapshot } =
  networkHelpers;
const coder = ethers.AbiCoder.defaultAbiCoder();

function namespace(name: string): bigint {
  return (
    BigInt(
      ethers.keccak256(
        coder.encode(["uint256"], [BigInt(ethers.id(name)) - 1n]),
      ),
    ) & ~255n
  );
}

async function setup() {
  const sys = await deployInterfoldSystem({
    setupOperators: 0,
    submissionWindow: 600,
  });
  const signers = await ethers.getSigners();
  const owners = signers.slice(0, 4);
  const operators = signers.slice(5, 13);
  const ownerIndexes = [0, 0, 0, 1, 1, 1, 2, 3];
  for (const [i, operator] of operators.entries()) {
    await setupOperatorForSortition(
      operator,
      owners[ownerIndexes[i]],
      sys.bondingRegistry,
      sys.ciphernodeBondToken,
      sys.usdcToken,
      sys.ticketToken,
      sys.ciphernodeRegistry,
      sys.nodeReleaseRegistry,
    );
  }
  await time.increase(1);
  return { ...sys, candidates: operators, owners, ownerIndexes };
}

type Context = Awaited<ReturnType<typeof setup>>;

async function request(
  sys: Awaited<ReturnType<typeof deployInterfoldSystem>>,
  committeeSize = 0,
) {
  const now = await time.latest();
  const e3Id = await sys.interfold.nexte3Id();
  const params = {
    ...sys.request,
    committeeSize,
    inputWindow: [now + 100, now + 10_000] as [number, number],
  };
  const fee = await sys.interfold.getE3Quote(params);
  await sys.usdcToken.approve(await sys.interfold.getAddress(), fee);
  await expect(sys.interfold.request(params))
    .to.emit(sys.ciphernodeRegistry, "CommitteeBondOwnerCapEnabled")
    .withArgs(e3Id);
  await time.increase(1);
  return e3Id;
}

async function finalize(
  sys: Awaited<ReturnType<typeof deployInterfoldSystem>>,
  e3Id: bigint,
) {
  const registry = sys.ciphernodeRegistry;
  await time.increaseTo((await registry.getCommitteeDeadline(e3Id)) + 1n);
  return registry.finalizeCommittee(e3Id);
}

async function ranked(ctx: Context, e3Id: bigint) {
  const [, seed] = await ctx.ciphernodeRegistry.sortitionSeed(e3Id);
  return ctx.candidates
    .map((node, i) => ({
      node,
      owner: ctx.ownerIndexes[i],
      score: BigInt(
        ethers.solidityPackedKeccak256(
          ["address", "uint256", "uint256", "uint256"],
          [node.address, 1, e3Id, seed],
        ),
      ),
    }))
    .sort((a, b) =>
      a.score < b.score
        ? -1
        : a.score > b.score
          ? 1
          : BigInt(a.node.address) < BigInt(b.node.address)
            ? -1
            : 1,
    );
}

function addresses(nodes: { address: string }[]) {
  return nodes
    .map((n) => n.address)
    .sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
}

async function ownerCandidate(ctx: Context, e3Id: bigint, owner: string) {
  const perE3 = ethers.keccak256(
    coder.encode(
      ["uint256", "uint256"],
      [e3Id, namespace("interfold.storage.RegistrySortitionRandomness") + 4n],
    ),
  );
  const entry = ethers.keccak256(
    coder.encode(["address", "bytes32"], [owner, perE3]),
  );
  return ethers.provider.getStorage(
    await ctx.ciphernodeRegistry.getAddress(),
    entry,
  );
}

describe("One committee seat per request-time bond owner", function () {
  it("selects the best distinct owners regardless of submission order", async function () {
    const ctx = await loadFixture(setup);
    const e3Id = await request(ctx);
    const scores = await ranked(ctx, e3Id);
    const seen = new Set<number>();
    const expected = scores
      .filter((candidate) => {
        if (seen.has(candidate.owner)) return false;
        seen.add(candidate.owner);
        return true;
      })
      .slice(0, 3);

    const orders = [
      ctx.candidates,
      [...ctx.candidates].reverse(),
      scores.map((c) => c.node),
      [...scores].reverse().map((c) => c.node),
    ];
    const checkpoint = await takeSnapshot();
    for (const order of orders) {
      for (const node of order)
        await ctx.ciphernodeRegistry.connect(node).submitTicket(e3Id, 1);
      await finalize(ctx, e3Id);
      const [nodes] =
        await ctx.ciphernodeRegistry.getActiveCommitteeNodes(e3Id);
      expect([...nodes]).to.deep.equal(addresses(expected.map((c) => c.node)));
      for (const [i, node] of nodes.entries()) {
        expect(
          await ctx.ciphernodeRegistry.canonicalCommitteeNodeAt(e3Id, i),
        ).to.equal(node);
      }
      await checkpoint.restore();
    }
  });

  it("replaces the same owner's worse ticket and releases only the displaced obligation", async function () {
    const ctx = await loadFixture(setup);
    const e3Id = await request(ctx);
    const own = (await ranked(ctx, e3Id)).filter((c) => c.owner === 0);
    const [best, middle, worst] = own;
    const registryAddress = await ctx.ciphernodeRegistry.getAddress();
    await ctx.ciphernodeRegistry.connect(worst.node).submitTicket(e3Id, 1);
    await expect(
      ctx.ciphernodeRegistry.connect(best.node).submitTicket(e3Id, 1),
    )
      .to.emit(ctx.bondingRegistry, "CommitteeObligationUpdated")
      .withArgs(e3Id, registryAddress, best.node.address, true)
      .and.to.emit(ctx.bondingRegistry, "CommitteeObligationUpdated")
      .withArgs(e3Id, registryAddress, worst.node.address, false);
    await expect(
      ctx.ciphernodeRegistry.connect(middle.node).submitTicket(e3Id, 1),
    ).not.to.emit(ctx.bondingRegistry, "CommitteeObligationUpdated");
    await expect(
      ctx.ciphernodeRegistry.connect(best.node).submitTicket(e3Id, 1),
    ).to.be.revertedWithCustomError(
      ctx.ciphernodeRegistry,
      "NodeAlreadySubmitted",
    );
    for (const node of ctx.candidates.slice(6)) {
      await ctx.ciphernodeRegistry.connect(node).submitTicket(e3Id, 1);
    }
    await finalize(ctx, e3Id);
    const [nodes] = await ctx.ciphernodeRegistry.getActiveCommitteeNodes(e3Id);
    expect([...nodes]).to.deep.equal(
      addresses([best.node, ...ctx.candidates.slice(6)]),
    );
  });

  it("fails formation instead of filling missing seats with the same owner", async function () {
    const ctx = await loadFixture(setup);
    const e3Id = await request(ctx);
    for (const node of ctx.candidates.slice(0, 6)) {
      await ctx.ciphernodeRegistry.connect(node).submitTicket(e3Id, 1);
    }
    const retainedSeed = await ctx.ciphernodeRegistry.sortitionSeed(e3Id);
    expect(await ownerCandidate(ctx, e3Id, ctx.owners[0].address)).not.to.equal(
      ethers.ZeroHash,
    );
    await expect(finalize(ctx, e3Id))
      .to.emit(ctx.ciphernodeRegistry, "CommitteeFormationFailed")
      .withArgs(e3Id, 2, 3);
    expect(await ctx.interfold.getE3Stage(e3Id)).to.equal(6);
    expect(await ctx.bondingRegistry.unresolvedCommitteeCount()).to.equal(0);
    for (const owner of ctx.owners) {
      expect(await ownerCandidate(ctx, e3Id, owner.address)).to.equal(
        ethers.ZeroHash,
      );
    }
    expect(await ctx.ciphernodeRegistry.sortitionSeed(e3Id)).to.deep.equal(
      retainedSeed,
    );
  });

  it("clears finalized candidates by snapshot owner without touching another E3", async function () {
    const ctx = await loadFixture(setup);
    const e3Id = await request(ctx);
    const nextId = await request(ctx);
    const nodes = [ctx.candidates[0], ctx.candidates[6], ctx.candidates[7]];
    for (const node of nodes) {
      await ctx.ciphernodeRegistry.connect(node).submitTicket(e3Id, 1);
      await ctx.ciphernodeRegistry.connect(node).submitTicket(nextId, 1);
    }
    await finalize(ctx, e3Id);
    const seed = await ctx.ciphernodeRegistry.sortitionSeed(e3Id);
    const otherCandidate = await ownerCandidate(
      ctx,
      nextId,
      ctx.owners[0].address,
    );
    await ctx.bondingRegistry
      .connect(ctx.owners[0])
      .proposeBondOwner(nodes[0].address, ctx.owners[1].address);
    await ctx.bondingRegistry
      .connect(ctx.owners[1])
      .acceptBondOwner(nodes[0].address);
    const timeouts = await ctx.interfold.getE3TimeoutConfig(e3Id);
    await time.increase(timeouts.dkgWindow + 1n);
    await ctx.interfold.markE3Failed(e3Id);
    await expect(
      ctx.ciphernodeRegistry.releaseCommittee(e3Id),
    ).to.be.revertedWithCustomError(
      ctx.ciphernodeRegistry,
      "CommitteeAccusationWindowOpen",
    );
    expect(await ownerCandidate(ctx, e3Id, ctx.owners[0].address)).not.to.equal(
      ethers.ZeroHash,
    );
    await time.increaseTo(
      (await ctx.slashingManager.accusationSubmissionDeadline(e3Id)) + 1n,
    );
    await ctx.ciphernodeRegistry.releaseCommittee(e3Id);
    for (const owner of ctx.owners) {
      expect(await ownerCandidate(ctx, e3Id, owner.address)).to.equal(
        ethers.ZeroHash,
      );
    }
    expect(await ownerCandidate(ctx, nextId, ctx.owners[0].address)).to.equal(
      otherCandidate,
    );
    expect(await ctx.ciphernodeRegistry.sortitionSeed(e3Id)).to.deep.equal(
      seed,
    );
    await expect(
      ctx.ciphernodeRegistry.releaseCommittee(e3Id),
    ).to.be.revertedWithCustomError(
      ctx.ciphernodeRegistry,
      "CommitteeObligationsAlreadyReleased",
    );
  });

  it("does not let an owner transfer after the request create another seat", async function () {
    const ctx = await loadFixture(setup);
    const e3Id = await request(ctx);
    const moved = ctx.candidates[1];
    await ctx.bondingRegistry
      .connect(ctx.owners[0])
      .proposeBondOwner(moved.address, ctx.owners[2].address);
    await ctx.bondingRegistry
      .connect(ctx.owners[2])
      .acceptBondOwner(moved.address);
    for (const node of ctx.candidates.slice(0, 3)) {
      await ctx.ciphernodeRegistry.connect(node).submitTicket(e3Id, 1);
    }
    await expect(finalize(ctx, e3Id))
      .to.emit(ctx.ciphernodeRegistry, "CommitteeFormationFailed")
      .withArgs(e3Id, 1, 3);
    const nextId = await request(ctx);
    for (const node of [ctx.candidates[0], moved, ctx.candidates[7]]) {
      await ctx.ciphernodeRegistry.connect(node).submitTicket(nextId, 1);
    }
    await finalize(ctx, nextId);
    expect(
      (await ctx.ciphernodeRegistry.getActiveCommitteeNodes(nextId))[0],
    ).to.have.length(3);
  });

  it("keeps pre-upgrade requests uncapped when their appended policy field is zero", async function () {
    const ctx = await loadFixture(setup);
    const e3Id = await request(ctx);
    // Reproduce an existing request's storage: the old struct ended at slot 5.
    // No production method can clear this field.
    const requestSlot = BigInt(
      ethers.keccak256(
        coder.encode(
          ["uint256", "uint256"],
          [
            e3Id,
            namespace("interfold.storage.RegistrySortitionRandomness") + 2n,
          ],
        ),
      ),
    );
    await setStorageAt(
      await ctx.ciphernodeRegistry.getAddress(),
      requestSlot + 6n,
      0n,
    );
    for (const node of ctx.candidates.slice(0, 3)) {
      await ctx.ciphernodeRegistry.connect(node).submitTicket(e3Id, 1);
    }
    await finalize(ctx, e3Id);
    expect(
      (await ctx.ciphernodeRegistry.getActiveCommitteeNodes(e3Id))[0],
    ).to.have.length(3);
    const nextId = await request(ctx);
    for (const node of ctx.candidates.slice(0, 3)) {
      await ctx.ciphernodeRegistry.connect(node).submitTicket(nextId, 1);
    }
    await expect(finalize(ctx, nextId))
      .to.emit(ctx.ciphernodeRegistry, "CommitteeFormationFailed")
      .withArgs(nextId, 1, 3);
  });

  it("caps 28 funded operators to one of the 19 Small committee seats", async function () {
    const sys = await deployInterfoldSystem({
      setupOperators: 0,
      submissionWindow: 600,
      committeeThresholds: [[2, [14, 19]]],
    });
    const owners = (await ethers.getSigners()).slice(0, 19);
    const nodes: { operator: Signer; owner: string }[] = [];
    for (let i = 0; i < 46; i++) {
      const operator = ethers.Wallet.createRandom().connect(ethers.provider);
      await setBalance(operator.address, ethers.parseEther("10"));
      const owner = owners[i < 28 ? 0 : i - 27];
      await setupOperatorForSortition(
        operator,
        owner,
        sys.bondingRegistry,
        sys.ciphernodeBondToken,
        sys.usdcToken,
        sys.ticketToken,
        sys.ciphernodeRegistry,
        sys.nodeReleaseRegistry,
      );
      nodes.push({ operator, owner: owner.address });
    }
    const e3Id = await request(sys, 2);
    for (const node of nodes)
      await sys.ciphernodeRegistry.connect(node.operator).submitTicket(e3Id, 1);
    await finalize(sys, e3Id);
    const [selected] =
      await sys.ciphernodeRegistry.getActiveCommitteeNodes(e3Id);
    expect(selected).to.have.length(19);
    const selectedOwners = await Promise.all(
      selected.map((node) => sys.bondingRegistry.bondOwnerOf(node)),
    );
    expect(new Set(selectedOwners).size).to.equal(19);
    expect(
      selectedOwners.filter((owner) => owner === owners[0].address),
    ).to.have.length(1);
  });

  it("checkpoints both transfer paths, including unchanged legacy owners", async function () {
    const ctx = await loadFixture(setup);
    const operator = ctx.candidates[0];
    const registry = ctx.bondingRegistry;
    const before = await time.latest();
    expect(await registry.bondOwnerAt(operator.address, before)).to.equal(
      ctx.owners[0].address,
    );
    expect(await registry.bondOwnerAt(operator.address, 0)).to.equal(
      ethers.ZeroAddress,
    );

    // An operator registered before this upgrade has no ownership checkpoints.
    const historySlot = BigInt(
      ethers.keccak256(
        coder.encode(
          ["address", "uint256"],
          [operator.address, namespace("interfold.storage.BondOwnerHistory")],
        ),
      ),
    );
    await setStorageAt(await registry.getAddress(), historySlot, 0n);
    expect(await registry.bondOwnerAt(operator.address, before)).to.equal(
      ctx.owners[0].address,
    );
    await registry
      .connect(ctx.owners[0])
      .proposeBondOwner(operator.address, ctx.owners[1].address);
    const proposedAt = await time.latest();
    expect(await registry.bondOwnerAt(operator.address, proposedAt)).to.equal(
      ctx.owners[0].address,
    );
    await registry.connect(ctx.owners[1]).acceptBondOwner(operator.address);
    const acceptedAt = await time.latest();
    expect(
      await registry.bondOwnerAt(operator.address, acceptedAt - 1),
    ).to.equal(ctx.owners[0].address);
    expect(await registry.bondOwnerAt(operator.address, acceptedAt)).to.equal(
      ctx.owners[1].address,
    );
    expect(await registry.totalBonded(ctx.owners[0].address)).to.equal(
      ethers.parseEther("2000"),
    );
    expect(await registry.totalBonded(ctx.owners[1].address)).to.equal(
      ethers.parseEther("4000"),
    );
  });
});
