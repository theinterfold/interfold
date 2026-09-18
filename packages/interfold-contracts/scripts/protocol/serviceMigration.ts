// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

import { ZERO } from "./constants";
import { safeTx } from "./safe";
import { PROOF_TYPES, slashReasonForProofType } from "./slashPolicies";
import type {
  ProtocolConfigFile,
  ProtocolDeployment,
  SafeTransaction,
} from "./types";
import { deployedAddress } from "./values";

export interface SlashingManagerDeployment {
  manager: string;
  evidenceLibrary: string;
  contract: any;
}

export async function deploySlashingManagerReplacement(
  ethers: any,
  config: ProtocolConfigFile,
): Promise<SlashingManagerDeployment> {
  const evidenceFactory = await ethers.getContractFactory(
    "SlashingEvidenceLib",
  );
  const evidenceLibrary = await evidenceFactory.deploy();
  await evidenceLibrary.waitForDeployment();
  const evidenceLibraryAddress = await deployedAddress(evidenceLibrary);
  const managerFactory = await ethers.getContractFactory("SlashingManager", {
    libraries: { SlashingEvidenceLib: evidenceLibraryAddress },
  });
  const contract = await managerFactory.deploy(
    BigInt(config.slashing.initialDelay),
    config.protocolOwner,
  );
  await contract.waitForDeployment();
  return {
    manager: await deployedAddress(contract),
    evidenceLibrary: evidenceLibraryAddress,
    contract,
  };
}

export function slashPolicyReasons(config: ProtocolConfigFile): string[] {
  const reasons = PROOF_TYPES.map(slashReasonForProofType);
  for (const reason of config.slashing.policyReasons ?? []) {
    if (!ethersLib.isHexString(reason, 32)) {
      throw new Error(`Invalid slash-policy reason: ${reason}`);
    }
    reasons.push(reason);
  }
  return [...new Set(reasons.map((reason) => reason.toLowerCase()))];
}

async function appendSlashPolicyTransactions(
  ethers: any,
  config: ProtocolConfigFile,
  previousManagerAddress: string,
  replacement: SlashingManagerDeployment,
  txs: SafeTransaction[],
): Promise<string[]> {
  const previous = await ethers.getContractAt(
    "SlashingManager",
    previousManagerAddress,
  );
  const migrated: string[] = [];
  for (const reason of slashPolicyReasons(config)) {
    const policy = await previous.getSlashPolicy(reason);
    const configured =
      policy.ticketPenalty !== 0n || policy.ciphernodeBondPenalty !== 0n;
    if (!configured) continue;
    txs.push(
      safeTx(
        replacement.manager,
        replacement.contract.interface.encodeFunctionData("setSlashPolicy", [
          reason,
          {
            ticketPenalty: policy.ticketPenalty,
            ciphernodeBondPenalty: policy.ciphernodeBondPenalty,
            requiresProof: policy.requiresProof,
            proofVerifier: policy.proofVerifier,
            banNode: policy.banNode,
            appealWindow: policy.appealWindow,
            enabled: policy.enabled,
            affectsCommittee: policy.affectsCommittee,
            failureReason: policy.failureReason,
          },
        ]),
      ),
    );
    migrated.push(reason);
  }
  return migrated;
}

/**
 * Build the ordered calls for an operator-preserving slashing-manager cutover.
 *
 * The protocol proxies must already run implementations that support service
 * migration. The registry call is last because it validates the completed
 * dependency graph. Revoking the previous manager is the final slashing call.
 */
export async function buildSlashingManagerMigrationTransactions(
  ethers: any,
  config: ProtocolConfigFile,
  deployment: ProtocolDeployment,
  replacement: SlashingManagerDeployment,
): Promise<{
  transactions: SafeTransaction[];
  migratedSlashPolicyReasons: string[];
}> {
  const interfold = await ethers.getContractAt(
    "Interfold",
    deployment.interfold,
  );
  const registry = await ethers.getContractAt(
    "CiphernodeRegistryOwnable",
    deployment.ciphernodeRegistry,
  );
  const bonding = await ethers.getContractAt(
    "BondingRegistry",
    deployment.bondingRegistryProxy,
  );
  const txs: SafeTransaction[] = [
    safeTx(
      replacement.manager,
      replacement.contract.interface.encodeFunctionData("setInterfold", [
        deployment.interfold,
      ]),
    ),
    safeTx(
      replacement.manager,
      replacement.contract.interface.encodeFunctionData("setBondingRegistry", [
        deployment.bondingRegistryProxy,
      ]),
    ),
    safeTx(
      replacement.manager,
      replacement.contract.interface.encodeFunctionData(
        "setCiphernodeRegistry",
        [deployment.ciphernodeRegistry],
      ),
    ),
    safeTx(
      replacement.manager,
      replacement.contract.interface.encodeFunctionData("setE3RefundManager", [
        deployment.e3RefundManager,
      ]),
    ),
  ];
  const migratedSlashPolicyReasons = await appendSlashPolicyTransactions(
    ethers,
    config,
    deployment.slashingManager,
    replacement,
    txs,
  );
  if (config.slasher.toLowerCase() !== ZERO.toLowerCase()) {
    txs.push(
      safeTx(
        replacement.manager,
        replacement.contract.interface.encodeFunctionData("addSlasher", [
          config.slasher,
        ]),
      ),
    );
  }
  txs.push(
    safeTx(
      deployment.bondingRegistryProxy,
      bonding.interface.encodeFunctionData("setSlashingManager", [
        replacement.manager,
      ]),
    ),
    safeTx(
      deployment.interfold,
      interfold.interface.encodeFunctionData("setSlashingManager", [
        replacement.manager,
      ]),
    ),
    safeTx(
      deployment.ciphernodeRegistry,
      registry.interface.encodeFunctionData("setSlashingManager", [
        replacement.manager,
      ]),
    ),
    safeTx(
      deployment.bondingRegistryProxy,
      bonding.interface.encodeFunctionData("revokeSlashingManager", [
        deployment.slashingManager,
      ]),
    ),
  );
  return { transactions: txs, migratedSlashPolicyReasons };
}
