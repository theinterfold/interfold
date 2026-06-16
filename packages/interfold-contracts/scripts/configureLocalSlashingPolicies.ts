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
import { getDeploymentChain, readDeploymentArgs } from "./utils";

/** Proof types 0–7: DKG-stage proofs (C0–C4). */
const DKG_PROOF_TYPES = [0, 1, 2, 3, 4, 5, 6, 7] as const;
/** Proof types 8–10: aggregation / decryption (C5–C7). */
const DECRYPTION_PROOF_TYPES = [8, 9, 10] as const;

/** `IInterfold.FailureReason.DKGInvalidShares` */
const FAILURE_REASON_DKG_INVALID_SHARES = 4;
/** `IInterfold.FailureReason.DecryptionInvalidShares` */
const FAILURE_REASON_DECRYPTION_INVALID_SHARES = 11;

function slashReasonForProofType(
  ethers: typeof EthersTypes,
  proofType: number,
): string {
  return ethers.keccak256(ethers.solidityPacked(["uint256"], [proofType]));
}

function localAttestationSlashPolicy(
  ethers: typeof EthersTypes,
  failureReason: number,
): ISlashingManager.SlashPolicyStruct {
  // Lane A (`proposeSlash`): committee attestation is verified in SlashingManager;
  // `proofVerifier` is unused (reserved for future ZK verifier wiring). ZeroAddress is intentional.
  return {
    ticketPenalty: ethers.parseUnits("10", 6),
    licensePenalty: ethers.parseEther("50"),
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
 * Enables Lane A (`proposeSlash`) policies for all `ProofType` values (0–10).
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
    "Configuring local SlashingManager policies (proof types 0–10)...",
  );

  for (const proofType of DKG_PROOF_TYPES) {
    const reason = slashReasonForProofType(ethers, proofType);
    const tx = await contract.setSlashPolicy(
      reason,
      localAttestationSlashPolicy(ethers, FAILURE_REASON_DKG_INVALID_SHARES),
    );
    await tx.wait();
    console.log(`  proofType ${proofType} (DKG) -> ${reason}`);
  }

  for (const proofType of DECRYPTION_PROOF_TYPES) {
    const reason = slashReasonForProofType(ethers, proofType);
    const tx = await contract.setSlashPolicy(
      reason,
      localAttestationSlashPolicy(
        ethers,
        FAILURE_REASON_DECRYPTION_INVALID_SHARES,
      ),
    );
    await tx.wait();
    console.log(`  proofType ${proofType} (decryption) -> ${reason}`);
  }

  console.log("Local slashing policies configured.");
}
