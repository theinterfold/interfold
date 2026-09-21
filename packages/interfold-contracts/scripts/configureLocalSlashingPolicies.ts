// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import type { ethers as EthersTypes } from "ethers";
import type { HardhatRuntimeEnvironment } from "hardhat/types/hre";

import {
  SlashingManager,
  SlashingManager__factory as SlashingManagerFactory,
} from "../types";
import type { ISlashingManager } from "../types/contracts/interfaces/ISlashingManager";
import {
  DECRYPTION_PROOF_TYPES,
  DKG_PROOF_TYPES,
  slashReasonForProofType,
} from "./protocol/slashPolicies";
import { getDeploymentChain, readDeploymentArgs } from "./utils";

/** `IInterfold.FailureReason.InsufficientCommitteeMembers` */
const FAILURE_REASON_INSUFFICIENT_COMMITTEE_MEMBERS = 2;

function localAttestationSlashPolicy(
  ethers: typeof EthersTypes,
  failureReason: number,
): ISlashingManager.SlashPolicyStruct {
  // Lane A (`proposeSlash`): committee attestation is verified in SlashingManager;
  // `proofVerifier` is unused (reserved for future ZK verifier wiring). ZeroAddress is intentional.
  return {
    ticketPenalty: ethers.parseUnits("10", 6),
    ciphernodeBondPenalty: ethers.parseEther("50"),
    requiresProof: true,
    proofVerifier: ethers.ZeroAddress,
    banNode: false,
    appealWindow: 0,
    enabled: true,
    affectsCommittee: true,
    failureReason,
  };
}

/**
 * Enables Lane A (`proposeSlash`) policies for all `ProofType` values (0–14).
 * Local dev deploys omit this by default, which causes `SlashReasonDisabled` reverts.
 */
export async function configureLocalSlashingPolicies(
  hre: HardhatRuntimeEnvironment,
  slashingManager?: SlashingManager,
): Promise<void> {
  const { ethers } = await hre.network.connect();
  const chain = getDeploymentChain(hre);

  const contract =
    slashingManager ??
    SlashingManagerFactory.connect(
      readDeploymentArgs("SlashingManager", chain)?.address ??
        (() => {
          throw new Error(
            "SlashingManager address not found; deploy contracts first",
          );
        })(),
      (await ethers.getSigners())[0],
    );

  console.log(
    "Configuring local SlashingManager policies (proof types 0–14)...",
  );

  for (const proofType of DKG_PROOF_TYPES) {
    const reason = slashReasonForProofType(proofType);
    const tx = await contract.setSlashPolicy(
      reason,
      localAttestationSlashPolicy(
        ethers,
        FAILURE_REASON_INSUFFICIENT_COMMITTEE_MEMBERS,
      ),
    );
    await tx.wait();
    console.log(`  proofType ${proofType} (DKG) -> ${reason}`);
  }

  for (const proofType of DECRYPTION_PROOF_TYPES) {
    const reason = slashReasonForProofType(proofType);
    const tx = await contract.setSlashPolicy(
      reason,
      localAttestationSlashPolicy(
        ethers,
        FAILURE_REASON_INSUFFICIENT_COMMITTEE_MEMBERS,
      ),
    );
    await tx.wait();
    console.log(`  proofType ${proofType} (decryption) -> ${reason}`);
  }

  console.log("Local slashing policies configured.");
}
