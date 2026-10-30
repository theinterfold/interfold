// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

import type { BfvVerifierRouteDeployment } from "../protocol/types";
import {
  activeBfvConfigForChain,
  bfvConfigsForChain,
  bfvDecExpectedPublicInputsLen,
  bfvPkExpectedPublicInputsLen,
  bfvPkV2PublicInputLayout,
  getBfvV2SubCircuitVkHashPaths,
  getBfvVkCommitments,
  isLbfvParamSet,
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
  equalAddress(
    await pkRouter.ciphernodeRegistry(),
    installed.registry,
    "PK router registry",
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
    // Parameter sets 3 and 4 run the l-BFV path, which the V2 PK verifier and aggregator serve.
    const isV2 = isLbfvParamSet(expected.paramSet);
    const expectedPkVerifier = isV2
      ? recorded.pkVerifierV2
      : recorded.pkVerifier;
    if (!expectedPkVerifier) {
      throw new Error(`Recorded BFV route ${index} is missing its V2 verifier`);
    }
    equalAddress(pkRoute[0], expectedPkVerifier, `PK route ${index}`);
    equalValue(
      pkRoute[3],
      expected.paramSet,
      `PK route ${index} parameter set`,
    );
    equalValue(
      pkRoute[1],
      // secure-16384 compiles six l-BFV rows, one per CRT modulus; insecure compiles three.
      isV2
        ? bfvPkV2PublicInputLayout(
            expected.h,
            expected.preset === "secure-16384" ? 6 : 3,
          ).length
        : bfvPkExpectedPublicInputsLen(expected.h),
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
      isV2 ? "BfvPkVerifierV2" : "BfvPkVerifier",
      expectedPkVerifier,
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
    const expectedDkgAggregator = isV2
      ? recorded.dkgAggregatorV2Verifier
      : recorded.dkgAggregatorVerifier;
    if (!expectedDkgAggregator) {
      throw new Error(
        `Recorded BFV route ${index} is missing its DKG aggregator verifier`,
      );
    }
    equalAddress(
      await pkVerifier.circuitVerifier(),
      expectedDkgAggregator,
      `PK route ${index} aggregator`,
    );
    if (isV2) {
      equalAddress(
        await pkVerifier.ciphernodeRegistry(),
        installed.registry,
        `PK route ${index} registry`,
      );
    }
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
    const commitments = getBfvVkCommitments(expected);
    equalValue(
      pkRoute[2],
      isV2
        ? readVkRecursiveHash(
            getBfvV2SubCircuitVkHashPaths(expected).nodesFold,
            expected,
          )
        : commitments.nodesFold,
      `PK route ${index} nodes-fold VK`,
    );
    if (!isV2) {
      equalValue(
        await pkVerifier.expectedC5KeyHash(),
        commitments.c5,
        `PK route ${index} C5 VK`,
      );
    }
    equalValue(
      decryptionRoute[2],
      commitments.c6Fold,
      `decryption route ${index} C6-fold VK`,
    );
    equalValue(
      decryptionRoute[3],
      commitments.c7,
      `decryption route ${index} C7 VK`,
    );
  }
}
