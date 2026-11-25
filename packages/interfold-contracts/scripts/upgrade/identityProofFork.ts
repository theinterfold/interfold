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
  PLANNED_IDENTITY,
  PROOF_BUNDLE_KIND,
  type ProofBundle,
  credentialEnd,
  readPublicInputs,
} from "../../zkpassport";
import { arg, connect } from "../protocol/cli";
import { resolvePath } from "../protocol/files";
import { deployOwnerIdentityRegistry } from "../protocol/identityRegistry";
import { deployedAddress } from "../protocol/values";

export function readProofBundle(file: string): ProofBundle {
  const bundle = JSON.parse(fs.readFileSync(file, "utf8")) as ProofBundle;
  if (bundle.kind !== PROOF_BUNDLE_KIND) {
    throw new Error(`${file} is not a proof download of the identity panel`);
  }
  return bundle;
}

/**
 * The identifier that a verifier with this identifier namespace derives for the proof, if
 * ZKPassport's unique identifier is the proof's scoped nullifier.
 */
export function expectedIdentityId(
  namespace: string,
  bundle: ProofBundle,
): string {
  const { scopedNullifier } = readPublicInputs(
    bundle.version,
    bundle.params.proofVerificationData.publicInputs,
  );
  return ethersLib.keccak256(
    ethersLib.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32"],
      [namespace, scopedNullifier],
    ),
  );
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
  const verifier = await (
    await ethers.getContractFactory("ZKPassportIdentityVerifier")
  ).deploy(
    PLANNED_IDENTITY.rootVerifier,
    bundle.version,
    bundle.domain,
    bundle.scope,
    bundle.nullifierType,
    bundle.oprfKeyHash,
    bundle.faceMatch,
    proofValidity,
    maxValidity,
  );
  await verifier.waitForDeployment();
  const registry = (
    await deployOwnerIdentityRegistry(
      ethers,
      await deployer.getAddress(),
      await deployedAddress(verifier),
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
  const expectedId = expectedIdentityId(
    await verifier.IDENTITY_NAMESPACE(),
    bundle,
  );
  const expectedExpiry = credentialEnd(
    BigInt(bundle.validUntil),
    BigInt(bundle.proofDate),
    maxValidity,
  );
  if (identityId !== expectedId) {
    throw new Error(
      `Identifier ${identityId} differs from the scoped nullifier's ${expectedId}`,
    );
  }
  if (BigInt(expiresAt) !== expectedExpiry) {
    throw new Error(`Expiry ${expiresAt} differs from ${expectedExpiry}`);
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
    // ethers decodes Error(string) and Panic(uint256) too; keep their reason.
    const parsed = failure.data ? iface.parseError(failure.data) : null;
    const decoded =
      parsed && (parsed.name === "Error" || parsed.name === "Panic")
        ? `${parsed.name}(${parsed.args[0]})`
        : parsed?.name;
    return (
      decoded ??
      failure.reason ??
      (failure.data ? `revert data ${failure.data.slice(0, 74)}` : undefined) ??
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
