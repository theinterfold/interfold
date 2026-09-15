// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import { configureLocalSlashingPolicies } from "../../scripts/configureLocalSlashingPolicies";
import type { SlashingManager } from "../../types";
import { ethers } from "../fixtures/connection";

describe("Local slashing policies", function () {
  it("configures the l-BFV proof types as DKG failures", async function () {
    const policies = new Map<string, { failureReason: number }>();
    const manager = {
      setSlashPolicy: async (
        reason: string,
        policy: { failureReason: number },
      ) => {
        policies.set(reason, policy);
        return { wait: async () => undefined };
      },
    } as unknown as SlashingManager;
    const hre = {
      globalOptions: { network: "localhost" },
      network: { connect: async () => ({ ethers }) },
    } as unknown as HardhatRuntimeEnvironment;

    await configureLocalSlashingPolicies(hre, manager);

    for (const proofType of [11, 12, 13, 14]) {
      const reason = ethers.keccak256(
        ethers.solidityPacked(["uint256"], [proofType]),
      );
      expect(policies.get(reason)?.failureReason).to.equal(2);
    }
  });
});
