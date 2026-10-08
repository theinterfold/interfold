// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

import type { BfvVerifierRouteDeployment } from "../protocol/types";
import {
  activeBfvConfigForChain,
  bfvConfigsForChain,
  bfvDecExpectedPublicInputsLen,
  getBfvDecryptionSubCircuitVkHashPaths,
  getBfvPkSubCircuitVkHashPaths,
  readVkRecursiveHash,
} from "../utils";

export function equalAddress(
  actual: string,
  expected: string,
  label: string,
): void {
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(`${label} mismatch: expected ${expected}, got ${actual}`);
  }
}

export function equalValue(
  actual: unknown,
  expected: unknown,
  label: string,
): void {
  if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
    throw new Error(`${label} mismatch: expected ${expected}, got ${actual}`);
  }
}

export async function readContract(
  provider: any,
  target: string,
  contractInterface: ethersLib.Interface,
  functionName: string,
  args: readonly unknown[] = [],
): Promise<any> {
  const data = contractInterface.encodeFunctionData(functionName, args);
  const result = await provider.call({ to: target, data });
  return contractInterface.decodeFunctionResult(functionName, result)[0];
}

/** The installed BFV routers and the routes they were built from. */
export interface InstalledBfvRoutes {
  pkVerifier: string;
  decryptionVerifier: string;
  bfvVerifierRoutes: BfvVerifierRouteDeployment[];
  registry: string;
}

/**
 * Check both BFV routers against the release matrix of `chainId`: the default route, each route's
 * verifier, threshold, aggregator and registry, and the VK anchors from the circuit artifacts.
 */
export async function validateBfvRoutes(
  ethers: any,
  chainId: number,
  installed: InstalledBfvRoutes,
): Promise<void> {
  const verifierDefault = activeBfvConfigForChain(chainId);
  const verifierConfigs = bfvConfigsForChain(chainId);
  if (installed.bfvVerifierRoutes.length !== verifierConfigs.length) {
    throw new Error(
      `Expected ${verifierConfigs.length} BFV routes, got ${installed.bfvVerifierRoutes.length}`,
    );
  }
  const pkRouter = await ethers.getContractAt(
    "BfvPkVerifierRouter",
    installed.pkVerifier,
  );
  const decryptionRouter = await ethers.getContractAt(
    "BfvDecryptionVerifierRouter",
    installed.decryptionVerifier,
  );
  equalValue(await pkRouter.h(), verifierDefault.h, "PK router default h");
  equalValue(
    await decryptionRouter.threshold(),
    verifierDefault.t,
    "decryption router default threshold",
  );
  const expectedRouteCount = BigInt(verifierConfigs.length);
  equalValue(await pkRouter.routeCount(), expectedRouteCount, "PK route count");
  equalValue(
    await decryptionRouter.routeCount(),
    expectedRouteCount,
    "decryption route count",
  );

  for (let index = 0; index < verifierConfigs.length; index += 1) {
    const expected = verifierConfigs[index];
    const recorded = installed.bfvVerifierRoutes[index];
    if (
      recorded.preset !== expected.preset ||
      recorded.committee !== expected.committee ||
      recorded.paramSet !== expected.paramSet ||
      recorded.committeeSize !== expected.committeeSize
    ) {
      throw new Error(
        `Recorded BFV route ${index} does not match the release matrix`,
      );
    }

    const pkRoute = await pkRouter.routeAt(index);
    const decryptionRoute = await decryptionRouter.routeAt(index);
    equalAddress(pkRoute[0], recorded.pkVerifier, `PK route ${index}`);
    equalValue(
      pkRoute[1],
      3 * expected.h + 6,
      `PK route ${index} public input count`,
    );
    equalAddress(
      decryptionRoute[0],
      recorded.decryptionVerifier,
      `decryption route ${index}`,
    );
    equalValue(
      decryptionRoute[1],
      bfvDecExpectedPublicInputsLen(expected.t),
      `decryption route ${index} public input count`,
    );

    const pkVerifier = await ethers.getContractAt(
      "BfvPkVerifier",
      recorded.pkVerifier,
    );
    const decryptionVerifier = await ethers.getContractAt(
      "BfvDecryptionVerifier",
      recorded.decryptionVerifier,
    );
    equalValue(await pkVerifier.h(), expected.h, `PK route ${index} h`);
    equalValue(
      await decryptionVerifier.threshold(),
      expected.t,
      `decryption route ${index} threshold`,
    );
    equalAddress(
      await pkVerifier.circuitVerifier(),
      recorded.dkgAggregatorVerifier,
      `PK route ${index} aggregator`,
    );
    equalAddress(
      await decryptionVerifier.circuitVerifier(),
      recorded.decryptionAggregatorVerifier,
      `decryption route ${index} aggregator`,
    );
    equalAddress(
      await decryptionVerifier.ciphernodeRegistry(),
      installed.registry,
      `decryption route ${index} registry`,
    );
    const pkPaths = getBfvPkSubCircuitVkHashPaths(expected);
    const decryptionPaths = getBfvDecryptionSubCircuitVkHashPaths(expected);
    equalValue(
      pkRoute[2],
      readVkRecursiveHash(pkPaths.nodesFold, expected),
      `PK route ${index} nodes-fold VK`,
    );
    equalValue(
      pkRoute[3],
      readVkRecursiveHash(pkPaths.c5, expected),
      `PK route ${index} C5 VK`,
    );
    equalValue(
      decryptionRoute[2],
      readVkRecursiveHash(decryptionPaths.c6Fold, expected),
      `decryption route ${index} C6-fold VK`,
    );
    equalValue(
      decryptionRoute[3],
      readVkRecursiveHash(decryptionPaths.c7, expected),
      `decryption route ${index} C7 VK`,
    );
  }
}
