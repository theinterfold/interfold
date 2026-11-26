// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Replays a real ZKPassport proof against ZKPassport's mainnet verifier on an Anvil mainnet fork.
// The proof is the JSON that the dashboard's identity panel downloads. The script deploys
// ZKPassportIdentityVerifier with the proof's settings and an OwnerIdentityRegistry, registers the
// proof as its bound owner, and checks the identifier, the expiry, and the owner binding.
//
//   anvil --fork-url <mainnet RPC>
//   CONFIRM_MAINNET_FORK=1 RPC_URL=http://127.0.0.1:8545 PRIVATE_KEY=<Anvil's first test key> \
//     pnpm upgrade:identity:proof-fork -- --network mainnet --proof <file>
//
// The `mainnet` network reads RPC_URL and PRIVATE_KEY, so it reaches the fork; the script refuses
// any chain that is not an Anvil mainnet fork.
//
// Options: --proof-validity <seconds> and --max-validity <seconds>, by default the example protocol
// config's.
import { ethers as ethersLib } from "ethers";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import type { OwnerIdentityRegistry } from "../../types";
import {
  IDENTITY_TAG,
  PLANNED_IDENTITY,
  PROOF_BUNDLE_KIND,
  type ProofBundle,
  credentialEnd,
  readPublicInputs,
} from "../../zkpassport";
import { arg, connect } from "../protocol/cli";
import { resolvePath } from "../protocol/files";
import {
  deployOwnerIdentityRegistry,
  deployZKPassportIdentityVerifier,
} from "../protocol/identityRegistry";

export function readProofBundle(file: string): ProofBundle {
  const bundle = JSON.parse(fs.readFileSync(file, "utf8")) as ProofBundle;
  if (bundle.kind !== PROOF_BUNDLE_KIND) {
    throw new Error(`${file} is not a proof download of the identity panel`);
  }
  return bundle;
}

/** The verifier settings that the proof was made for. */
export function bundleSettings(bundle: ProofBundle) {
  return {
    zkPassportVersion: bundle.version,
    domain: bundle.domain,
    scope: bundle.scope,
    nullifierType: bundle.nullifierType,
    oprfKeyHash: bundle.oprfKeyHash,
    faceMatchRequired: bundle.faceMatch,
  };
}

/**
 * The credential that a verifier for the proof's domain and scope, with this maximum validity,
 * records for the proof, if ZKPassport's unique identifier is the proof's scoped nullifier. The
 * namespace is derived here, not read from a verifier, so a comparison with a verifier's result
 * also checks the verifier's derivation.
 */
export function expectedCredential(
  bundle: Pick<ProofBundle, "domain" | "scope" | "validUntil" | "params"> & {
    version: string;
  },
  maxValidity: bigint,
): { identityId: string; expiresAt: bigint } {
  const coder = ethersLib.AbiCoder.defaultAbiCoder();
  const { proofDate, scopedNullifier } = readPublicInputs(
    bundle.version,
    bundle.params.proofVerificationData.publicInputs,
  );
  // ZKPassportIdentityVerifier.IDENTITY_NAMESPACE
  const namespace = ethersLib.keccak256(
    coder.encode(
      ["string", "string", "string"],
      [IDENTITY_TAG, bundle.domain, bundle.scope],
    ),
  );
  return {
    identityId: ethersLib.keccak256(
      coder.encode(["bytes32", "bytes32"], [namespace, scopedNullifier]),
    ),
    expiresAt: credentialEnd(BigInt(bundle.validUntil), proofDate, maxValidity),
  };
}

async function requireAnvilMainnetFork(ethers: any): Promise<void> {
  const network = await ethers.provider.getNetwork();
  const client = String(
    await ethers.provider.send("web3_clientVersion", []),
  ).toLowerCase();
  if (
    process.env.CONFIRM_MAINNET_FORK !== "1" ||
    network.chainId !== 1n ||
    !client.includes("anvil")
  ) {
    throw new Error(
      "This replay runs only on an Anvil mainnet fork with CONFIRM_MAINNET_FORK=1",
    );
  }
}

export async function replayProof(): Promise<void> {
  const file = arg("proof");
  if (!file) throw new Error("Pass --proof <the identity panel's download>");
  const bundle = readProofBundle(resolvePath(file));
  const connection = await connect();
  const { ethers } = connection;
  await requireAnvilMainnetFork(ethers);
  if (connection.networkConfig.type !== "http") {
    throw new Error("This replay requires an HTTP network");
  }
  if (bundle.chainId !== 1) {
    throw new Error(`The proof binds chain ${bundle.chainId}, not mainnet`);
  }
  const proofValidity = BigInt(
    arg("proof-validity") ?? PLANNED_IDENTITY.proofValidity,
  );
  const maxValidity = BigInt(
    arg("max-validity") ?? PLANNED_IDENTITY.maxValidity,
  );
  const [deployer] = await ethers.getSigners();
  // Impersonated accounts sign through a plain provider, as in the service-migration simulation.
  const forkProvider = new ethersLib.JsonRpcProvider(
    await connection.networkConfig.url.get(),
  );
  try {
    // A fresh fork's first local account may hold no ether.
    await fund(forkProvider, await deployer.getAddress());
    await register(
      ethers,
      forkProvider,
      deployer,
      bundle,
      proofValidity,
      maxValidity,
    );
  } finally {
    forkProvider.destroy();
  }
}

async function register(
  ethers: any,
  forkProvider: ethersLib.JsonRpcProvider,
  deployer: any,
  bundle: ProofBundle,
  proofValidity: bigint,
  maxValidity: bigint,
): Promise<void> {
  const verifierAddress = await deployZKPassportIdentityVerifier(ethers, {
    zkPassportRootVerifier: PLANNED_IDENTITY.rootVerifier,
    ...bundleSettings(bundle),
    proofValidity: proofValidity.toString(),
    maxValidity: maxValidity.toString(),
  });
  const verifier = await ethers.getContractAt(
    "ZKPassportIdentityVerifier",
    verifierAddress,
  );
  const registry = (
    await deployOwnerIdentityRegistry(
      ethers,
      await deployer.getAddress(),
      verifierAddress,
    )
  ).registry as unknown as OwnerIdentityRegistry;

  // A proof for one owner must not register another.
  const stranger = ethersLib.Wallet.createRandom().address;
  const strangerError = await revertName(
    registry
      .connect(await impersonate(forkProvider, stranger))
      .register.staticCall(bundle.evidence),
    verifier.interface,
  );
  if (strangerError !== "WrongBinding") {
    throw new Error(
      `Another owner's registration ended with ${strangerError}, not WrongBinding`,
    );
  }

  const owner = await impersonate(forkProvider, bundle.owner);
  const tx = await registry.connect(owner).register(bundle.evidence);
  const receipt = await tx.wait();
  if (receipt?.status !== 1) throw new Error("Registration reverted");
  const [identityId, expiresAt] = await registry.identityOf(bundle.owner);
  const expected = expectedCredential(bundle, maxValidity);
  if (identityId !== expected.identityId) {
    throw new Error(
      `Identifier ${identityId} differs from the scoped nullifier's ${expected.identityId}`,
    );
  }
  if (BigInt(expiresAt) !== expected.expiresAt) {
    throw new Error(`Expiry ${expiresAt} differs from ${expected.expiresAt}`);
  }
  const block = await ethers.provider.getBlock(receipt.blockNumber);
  if (!block || !(await registry.isVerifiedAt(bundle.owner, block.timestamp))) {
    throw new Error("The owner is not verified after registration");
  }

  console.log(`
Real ZKPassport proof registered on the mainnet fork
  owner:            ${bundle.owner}
  version:          ${bundle.version}
  identifier type:  ${bundle.nullifierType === 1 ? "salted" : "non-salted"}
  FaceMatch:        ${bundle.faceMatch}
  identity:         ${identityId}
  expires:          ${new Date(Number(expiresAt) * 1000).toISOString()}
  gas:              ${receipt.gasUsed}
  other owner:      rejected
`);
}

/**
 * The custom error of a reverted call, decoded with `iface`; otherwise the revert reason or data
 * that the node returned. "success" when the call did not revert.
 */
async function revertName(
  call: Promise<unknown>,
  iface: ethersLib.Interface,
): Promise<string> {
  try {
    await call;
    return "success";
  } catch (error) {
    const failure = error as {
      data?: string;
      reason?: string;
      shortMessage?: string;
    };
    // A revert without data leaves "0x", and parseError throws on data shorter than a selector.
    // ethers decodes Error(string) and Panic(uint256) too; keep their reason.
    const data =
      failure.data && ethersLib.dataLength(failure.data) >= 4
        ? failure.data
        : undefined;
    const parsed = data ? iface.parseError(data) : null;
    const decoded =
      parsed && (parsed.name === "Error" || parsed.name === "Panic")
        ? `${parsed.name}(${parsed.args[0]})`
        : parsed?.name;
    return (
      decoded ??
      failure.reason ??
      (data ? `revert data ${data.slice(0, 74)}` : undefined) ??
      failure.shortMessage ??
      String(error)
    );
  }
}

async function fund(
  forkProvider: ethersLib.JsonRpcProvider,
  account: string,
): Promise<void> {
  await forkProvider.send("anvil_setBalance", [
    account,
    ethersLib.toBeHex(ethersLib.parseEther("10")),
  ]);
}

/** A funded signer for `account` on the fork. */
async function impersonate(
  forkProvider: ethersLib.JsonRpcProvider,
  account: string,
): Promise<ethersLib.JsonRpcSigner> {
  await forkProvider.send("anvil_impersonateAccount", [account]);
  await fund(forkProvider, account);
  return forkProvider.getSigner(account);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  replayProof().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
