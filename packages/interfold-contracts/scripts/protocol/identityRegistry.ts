// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { ethers as ethersLib } from "ethers";

import { IDENTITY_TAG } from "../../zkpassport";
import { deployProxy } from "./proxies";
import type { IdentityGateConfig } from "./types";
import { deployedAddress } from "./values";

/** The identifier namespace of a verifier with this domain and scope. */
export function identityNamespace(domain: string, scope: string): string {
  return ethersLib.keccak256(
    ethersLib.AbiCoder.defaultAbiCoder().encode(
      ["string", "string", "string"],
      [IDENTITY_TAG, domain, scope],
    ),
  );
}

/** Deploys a ZKPassportIdentityVerifier with `settings`; returns its address. */
export async function deployZKPassportIdentityVerifier(
  ethers: any,
  settings: IdentityGateConfig,
): Promise<string> {
  const factory = await ethers.getContractFactory("ZKPassportIdentityVerifier");
  const verifier = await factory.deploy(
    settings.zkPassportRootVerifier,
    settings.zkPassportVersion,
    settings.domain,
    settings.scope,
    settings.nullifierType,
    settings.oprfKeyHash,
    settings.faceMatchRequired,
    settings.proofValidity,
    settings.maxValidity,
  );
  await verifier.waitForDeployment();
  return deployedAddress(verifier);
}

/**
 * Deploys OwnerIdentityRegistry behind a transparent proxy. `owner` owns the registry and the
 * proxy admin; `verifier` is the first verifier (the zero address leaves registration closed).
 */
export async function deployOwnerIdentityRegistry(
  ethers: any,
  owner: string,
  verifier: string,
) {
  const factory = await ethers.getContractFactory("OwnerIdentityRegistry");
  const implementation = await factory.deploy();
  await implementation.waitForDeployment();
  const implementationAddress = await deployedAddress(implementation);
  const { proxy, proxyAdmin } = await deployProxy(
    ethers,
    implementationAddress,
    owner,
    factory.interface.encodeFunctionData("initialize", [owner, verifier]),
  );
  return {
    registry: factory.attach(proxy),
    proxy,
    proxyAdmin,
    implementation: implementationAddress,
  };
}
