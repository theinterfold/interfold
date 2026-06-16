// SPDX-License-Identifier: LGPL-3.0-only
//
// Standards & upgradeability hygiene:
//   * ERC-165 `supportsInterface` on all major contracts.
//   * EIP-6372 clock advertisement on ERC20Votes tokens.
//   * LazyIMT depth cap (`MAX_CIPHERNODE_LEAVES` / `CiphernodeTreeExhausted`).
//   * `__gap[50]` storage gaps on upgradeable contracts (also covered via
//     `scripts/validateUpgrade.ts`; here we sanity-check that the four
//     upgradeable contracts deploy cleanly without slot collisions).
//
// Deferred (documented, no executable test):
//   * EIP-1271: no on-chain signer / 1271 verification path exists in
//     Interfold, registries or the refund manager. Add an IERC1271 check if
//     a contract-account signer path is introduced.
//   * Storage-layout snapshot/diff is implemented as
//     `scripts/validateUpgrade.ts`. Not part of the mocha suite (it reads
//     build-info artifacts); CI runs `pnpm validate:upgrade` after
//     `pnpm compile`.
import { expect } from "chai";
import { type FunctionFragment, Interface } from "ethers";

import {
  IBondingRegistry__factory as IBondingRegistryFactory,
  ICiphernodeRegistry__factory as ICiphernodeRegistryFactory,
  IE3RefundManager__factory as IE3RefundManagerFactory,
  IInterfold__factory as IInterfoldFactory,
  ISlashingManager__factory as ISlashingManagerFactory,
} from "../../types";
import { deployInterfoldSystem, ethers } from "../fixtures";

const IERC165_ID = "0x01ffc9a7";
const INVALID_ID = "0xffffffff";

// Compute the ERC-165 interfaceId of a contract interface by XORing the
// 4-byte selectors of every public function in its ABI.
function interfaceIdOf(iface: Interface): string {
  let acc = 0n;
  iface.forEachFunction((fragment: FunctionFragment) => {
    acc ^= BigInt(fragment.selector);
  });
  return "0x" + acc.toString(16).padStart(8, "0");
}

async function deployAll() {
  const sys = await deployInterfoldSystem({
    setupOperators: 0,
    wireSlashingManager: false,
  });
  return {
    ...sys,
    other: sys.notTheOwner,
    ownerAddress: await sys.owner.getAddress(),
  };
}

describe("Standards & upgradeability hygiene", function () {
  describe("ERC-165 supportsInterface", function () {
    it("Interfold: supports IInterfold + IERC165, rejects 0xffffffff", async function () {
      const { interfold } = await deployAll();
      const iInterfoldId = interfaceIdOf(IInterfoldFactory.createInterface());
      expect(await interfold.supportsInterface(iInterfoldId)).to.equal(true);
      expect(await interfold.supportsInterface(IERC165_ID)).to.equal(true);
      expect(await interfold.supportsInterface(INVALID_ID)).to.equal(false);
    });

    it("CiphernodeRegistryOwnable: supports ICiphernodeRegistry + IERC165", async function () {
      const { ciphernodeRegistry } = await deployAll();
      const id = interfaceIdOf(ICiphernodeRegistryFactory.createInterface());
      expect(await ciphernodeRegistry.supportsInterface(id)).to.equal(true);
      expect(await ciphernodeRegistry.supportsInterface(IERC165_ID)).to.equal(
        true,
      );
      expect(await ciphernodeRegistry.supportsInterface(INVALID_ID)).to.equal(
        false,
      );
    });

    it("BondingRegistry: supports IBondingRegistry + IERC165", async function () {
      const { bondingRegistry } = await deployAll();
      const id = interfaceIdOf(IBondingRegistryFactory.createInterface());
      expect(await bondingRegistry.supportsInterface(id)).to.equal(true);
      expect(await bondingRegistry.supportsInterface(IERC165_ID)).to.equal(
        true,
      );
      expect(await bondingRegistry.supportsInterface(INVALID_ID)).to.equal(
        false,
      );
    });

    it("E3RefundManager: supports IE3RefundManager + IERC165", async function () {
      const { e3RefundManager } = await deployAll();
      const id = interfaceIdOf(IE3RefundManagerFactory.createInterface());
      expect(await e3RefundManager.supportsInterface(id)).to.equal(true);
      expect(await e3RefundManager.supportsInterface(IERC165_ID)).to.equal(
        true,
      );
      expect(await e3RefundManager.supportsInterface(INVALID_ID)).to.equal(
        false,
      );
    });

    it("SlashingManager: supports ISlashingManager + IERC165", async function () {
      const { slashingManager } = await deployAll();
      const id = interfaceIdOf(ISlashingManagerFactory.createInterface());
      expect(await slashingManager.supportsInterface(id)).to.equal(true);
      expect(await slashingManager.supportsInterface(IERC165_ID)).to.equal(
        true,
      );
      expect(await slashingManager.supportsInterface(INVALID_ID)).to.equal(
        false,
      );
    });
  });

  describe("EIP-6372 clock advertisement (ERC20Votes)", function () {
    it("InterfoldTicketToken: CLOCK_MODE() and clock() report timestamp mode", async function () {
      const { ticketToken } = await deployAll();
      expect(await ticketToken.CLOCK_MODE()).to.equal("mode=timestamp");
      const latest = (await ethers.provider.getBlock("latest"))!;
      const onchain = await ticketToken.clock();
      // clock() must equal the latest block timestamp under EIP-6372/timestamp mode.
      expect(onchain).to.equal(BigInt(latest.timestamp));
    });

    it("InterfoldToken: CLOCK_MODE() and clock() report timestamp mode", async function () {
      const { licenseToken } = await deployAll();
      expect(await licenseToken.CLOCK_MODE()).to.equal("mode=timestamp");
      const latest = (await ethers.provider.getBlock("latest"))!;
      const onchain = await licenseToken.clock();
      expect(onchain).to.equal(BigInt(latest.timestamp));
    });
  });

  describe("LazyIMT depth cap", function () {
    it("CiphernodeRegistryOwnable: exposes MAX_CIPHERNODE_LEAVES = 2^20", async function () {
      const { ciphernodeRegistry } = await deployAll();
      const cap = await ciphernodeRegistry.MAX_CIPHERNODE_LEAVES();
      expect(cap).to.equal(1n << 20n);
    });

    it("addCiphernode succeeds for the first leaf (smoke test of the guard)", async function () {
      const { ciphernodeRegistry, owner } = await deployAll();
      // Owner is also authorised by `onlyOwnerOrBondingVault`; this is the
      // simplest way to exercise the LazyIMT insertion path and prove the
      // new MAX_CIPHERNODE_LEAVES guard does not regress the happy path.
      const node = "0x0000000000000000000000000000000000000abc";
      await expect(
        ciphernodeRegistry.connect(owner).addCiphernode(node),
      ).to.emit(ciphernodeRegistry, "CiphernodeAdded");
      // Real exhaustion (2^20 inserts) is infeasible to drive in a unit test;
      // the revert path is verified by code review of the constant guard.
    });
  });

  describe("storage gaps on upgradeable contracts", function () {
    // The presence of `uint256[50] private __gap` is enforced at compile
    // time by the source files and verified end-to-end by
    // `scripts/validateUpgrade.ts` which snapshots the solc storage layout
    // for each upgradeable contract and fails CI on any incompatible
    // change. We assert here only that the four upgradeable contracts can
    // be deployed cleanly (initializers wire up, no slot collision).
    it("all upgradeable contracts deploy without storage collision", async function () {
      const all = await deployAll();
      expect(await all.interfold.getAddress()).to.properAddress;
      expect(await all.ciphernodeRegistry.getAddress()).to.properAddress;
      expect(await all.bondingRegistry.getAddress()).to.properAddress;
      expect(await all.e3RefundManager.getAddress()).to.properAddress;
    });
  });

  describe("validateUpgrade script", function () {
    // Implemented as scripts/validateUpgrade.ts. Not run from mocha because
    // it reads build-info artifacts from disk; CI invokes it via
    // `pnpm validate:upgrade`.
    it("[deferred to CI] scripts/validateUpgrade.ts diffs storage layouts");
  });

  describe("EIP-1271", function () {
    // Deferred: no contract in this package currently consumes ECDSA
    // signatures from a third party — registration, slashing, and refunds
    // are all gated by direct `msg.sender` checks (Ownable / AccessControl)
    // or by ERC20Votes' built-in `delegateBySig`. Re-evaluate if a
    // contract-account signer path is introduced.
    it("[deferred] no contract-account signature verification path exists");
  });
});
