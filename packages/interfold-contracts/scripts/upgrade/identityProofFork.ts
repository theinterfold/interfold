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
//   CONFIRM_MAINNET_FORK=1 pnpm upgrade:identity:proof-fork -- --network localhost --proof <file>
//
// Options: --proof-validity <seconds> (default 7 days), --max-validity <seconds> (default 365 days).
import { ethers as ethersLib } from "ethers";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import type { OwnerIdentityRegistry } from "../../types";
import { arg, connect } from "../protocol/cli";
import { resolvePath } from "../protocol/files";
import { deployedAddress } from "../protocol/values";

const ZKPASSPORT_ROOT_VERIFIER = "0x1D000001000EFD9a6371f4d90bB8920D5431c0D8";
const IDENTITY_TAG = "interfold.identity.zkpassport.v1";

/** The fields of the dashboard's proof download that the replay reads. */
export interface ProofBundle {
  kind: string;
  chainId: number;
  owner: string;
  domain: string;
  scope: string;
  faceMatch: boolean;
  validUntil: string;
  proofDate: string;
  nullifierType: number;
  oprfKeyHash: string;
  version: string;
  evidence: string;
  params: { proofVerificationData: { publicInputs: string[] } };
}

export function readProofBundle(file: string): ProofBundle {
  const bundle = JSON.parse(fs.readFileSync(file, "utf8")) as ProofBundle;
  if (bundle.kind !== "interfold.identity.zkpassport-proof") {
    throw new Error(`${file} is not a proof download of the identity panel`);
  }
  return bundle;
}

/** The identifier that ZKPassportIdentityVerifier derives for the proof's scoped nullifier. */
export function expectedIdentityId(bundle: ProofBundle): string {
  const coder = ethersLib.AbiCoder.defaultAbiCoder();
  const inputs = bundle.params.proofVerificationData.publicInputs;
  const namespace = ethersLib.keccak256(
    coder.encode(
      ["string", "string", "string"],
      [IDENTITY_TAG, bundle.domain, bundle.scope],
    ),
  );
  return ethersLib.keccak256(
    coder.encode(
      ["bytes32", "bytes32"],
      [namespace, inputs[inputs.length - 2]],
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
  const { ethers } = await connect();
  await requireAnvilMainnetFork(ethers);
  if (bundle.chainId !== 1) {
    throw new Error(`The proof binds chain ${bundle.chainId}, not mainnet`);
  }
  const proofValidity = BigInt(arg("proof-validity") ?? 7 * 86_400);
  const maxValidity = BigInt(arg("max-validity") ?? 365 * 86_400);
  const [deployer] = await ethers.getSigners();

  const verifier = await (
    await ethers.getContractFactory("ZKPassportIdentityVerifier")
  ).deploy(
    ZKPASSPORT_ROOT_VERIFIER,
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
  const registry = (await (
    await ethers.getContractFactory("OwnerIdentityRegistry")
  ).deploy(
    await deployer.getAddress(),
    await deployedAddress(verifier),
  )) as unknown as OwnerIdentityRegistry;
  await registry.waitForDeployment();

  // A proof for one owner must not register another.
  const stranger = ethersLib.Wallet.createRandom().address;
  await impersonate(ethers, stranger);
  const strangerError = await revertName(
    registry
      .connect(await ethers.getSigner(stranger))
      .register.staticCall(bundle.evidence),
    verifier.interface,
  );
  if (strangerError !== "WrongBinding") {
    throw new Error(
      `Another owner's registration ended with ${strangerError}, not WrongBinding`,
    );
  }

  await impersonate(ethers, bundle.owner);
  const owner = await ethers.getSigner(bundle.owner);
  const tx = await registry.connect(owner).register(bundle.evidence);
  const receipt = await tx.wait();
  if (receipt?.status !== 1) throw new Error("Registration reverted");
  const [identityId, expiresAt] = await registry.identityOf(bundle.owner);
  const proofDate = BigInt(bundle.proofDate);
  const validUntil = BigInt(bundle.validUntil);
  const expectedExpiry =
    validUntil < proofDate + maxValidity ? validUntil : proofDate + maxValidity;
  if (identityId !== expectedIdentityId(bundle)) {
    throw new Error(
      `Identifier ${identityId} differs from the scoped nullifier's ${expectedIdentityId(bundle)}`,
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

/** The custom error of a reverted call, decoded with `iface`, or "success". */
async function revertName(
  call: Promise<unknown>,
  iface: ethersLib.Interface,
): Promise<string> {
  try {
    await call;
    return "success";
  } catch (error) {
    const data = (error as { data?: string }).data;
    return (data && iface.parseError(data)?.name) || String(error);
  }
}

async function impersonate(ethers: any, account: string): Promise<void> {
  await ethers.provider.send("anvil_impersonateAccount", [account]);
  await ethers.provider.send("anvil_setBalance", [
    account,
    ethersLib.toBeHex(ethersLib.parseEther("10")),
  ]);
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
