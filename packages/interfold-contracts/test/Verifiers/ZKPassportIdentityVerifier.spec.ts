// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import type { OwnerIdentityRegistry } from "../../types";
import { ethers, networkHelpers } from "../fixtures";

const { loadFixture, time } = networkHelpers;

// ZKPassport encodes version 0.20.0 as three big-endian uint16 values at the start of a bytes32.
const VERSION = ethers.zeroPadBytes("0x000000140000", 32);
const OTHER_VERSION = ethers.zeroPadBytes("0x000000130000", 32);
const DOMAIN = "dashboard.theinterfold.com";
const SCOPE = "interfold-bond-owner";
const NullifierType = {
  NON_SALTED: 0,
  SALTED: 1,
  NON_SALTED_MOCK: 2,
  SALTED_MOCK: 3,
  NONE: 4,
} as const;
const FaceMatchMode = { NONE: 0, REGULAR: 1, STRICT: 2 } as const;
const DAY = 24 * 60 * 60;
const PROOF_VALIDITY = 7 * DAY;
const MAX_VALIDITY = 365 * DAY;
const DOCUMENT_ID = ethers.id("document scoped nullifier");
const abiCoder = ethers.AbiCoder.defaultAbiCoder();
const PARAMS_TYPE =
  "tuple(bytes32 version, tuple(bytes32 vkeyHash, bytes proof, bytes32[] publicInputs) proofVerificationData, bytes committedInputs, tuple(uint256 validityPeriodInSeconds, string domain, string scope, bool devMode) serviceConfig)";
const IDENTITY_ID = ethers.keccak256(
  abiCoder.encode(
    ["bytes32", "bytes32"],
    [
      ethers.keccak256(
        abiCoder.encode(
          ["string", "string", "string"],
          ["interfold.identity.zkpassport.v1", DOMAIN, SCOPE],
        ),
      ),
      DOCUMENT_ID,
    ],
  ),
);

async function setup() {
  const [governance, owner, otherOwner] = await ethers.getSigners();
  const helper = await ethers.deployContract("MockZKPassportHelper");
  const rootVerifier = await ethers.deployContract(
    "MockZKPassportRootVerifier",
    [await helper.getAddress(), DOCUMENT_ID],
  );
  const verifierArgs = [
    await rootVerifier.getAddress(),
    VERSION,
    DOMAIN,
    SCOPE,
    NullifierType.NON_SALTED,
    true,
    PROOF_VALIDITY,
    MAX_VALIDITY,
  ];
  const verifier = await ethers.deployContract(
    "ZKPassportIdentityVerifier",
    verifierArgs,
  );
  const registry = (await ethers.deployContract("OwnerIdentityRegistry", [
    governance.address,
    await verifier.getAddress(),
  ])) as unknown as OwnerIdentityRegistry;
  const { chainId } = await ethers.provider.getNetwork();
  return {
    owner,
    otherOwner,
    helper,
    rootVerifier,
    verifier,
    verifierArgs,
    registry,
    chainId,
  };
}
type Context = Awaited<ReturnType<typeof setup>>;

// Public inputs follow ZKPassport's layout: index 2 is the proof date, and the last three are the
// nullifier type, the scoped nullifier and the OPRF key hash.
function evidence(
  validUntil: number,
  proofDate: number,
  {
    version = VERSION,
    nullifierType = NullifierType.NON_SALTED,
  }: { version?: string; nullifierType?: number } = {},
) {
  const publicInputs = [
    ethers.id("certificate root"),
    ethers.id("circuit root"),
    ethers.toBeHex(proofDate, 32),
    ethers.id("domain"),
    ethers.id("scope"),
    ethers.id("parameter commitment"),
    ethers.toBeHex(nullifierType, 32),
    DOCUMENT_ID,
    ethers.ZeroHash,
  ];
  // The caller asks for dev mode, another domain and a long window; none of them may reach
  // ZKPassport's verifier.
  const params = [
    version,
    [ethers.id("vkey"), "0x1234", publicInputs],
    "0xc0ffee",
    [10 * MAX_VALIDITY, "attacker.example", "other-scope", true],
  ];
  return abiCoder.encode([PARAMS_TYPE, "uint256"], [params, validUntil]);
}

async function proveFor(ctx: Context, owner: string, validUntil: number) {
  await ctx.helper.setBinding(owner, ctx.chainId);
  await ctx.helper.setExpiryLowerBound(validUntil);
}

describe("ZKPassportIdentityVerifier", function () {
  it("registers the document for the bound owner with the fixed service settings", async function () {
    const ctx = await loadFixture(setup);
    const proofDate = await time.latest();
    const validUntil = proofDate + 30 * DAY;
    await proveFor(ctx, ctx.owner.address, validUntil);

    await expect(
      ctx.registry.connect(ctx.owner).register(evidence(validUntil, proofDate)),
    )
      .to.emit(ctx.registry, "IdentityRegistered")
      .withArgs(ctx.owner.address, IDENTITY_ID, validUntil);

    expect(await ctx.rootVerifier.lastDomain()).to.equal(DOMAIN);
    expect(await ctx.rootVerifier.lastScope()).to.equal(SCOPE);
    expect(await ctx.rootVerifier.lastValidityPeriod()).to.equal(
      BigInt(PROOF_VALIDITY),
    );
    expect(await ctx.rootVerifier.lastDevMode()).to.equal(false);
  });

  it("ends the credential at the maximum validity after the proof date", async function () {
    const ctx = await loadFixture(setup);
    const proofDate = await time.latest();
    const validUntil = proofDate + 2 * MAX_VALIDITY;
    await proveFor(ctx, ctx.owner.address, validUntil);

    const [, expiresAt] = await ctx.verifier.verify.staticCall(
      ctx.owner.address,
      evidence(validUntil, proofDate),
    );

    expect(expiresAt).to.equal(BigInt(proofDate + MAX_VALIDITY));
  });

  it("rejects the same document for a second owner", async function () {
    const ctx = await loadFixture(setup);
    const proofDate = await time.latest();
    const validUntil = proofDate + 30 * DAY;
    await proveFor(ctx, ctx.owner.address, validUntil);
    await ctx.registry
      .connect(ctx.owner)
      .register(evidence(validUntil, proofDate));

    await proveFor(ctx, ctx.otherOwner.address, validUntil);
    await expect(
      ctx.registry
        .connect(ctx.otherOwner)
        .register(evidence(validUntil, proofDate)),
    )
      .to.be.revertedWithCustomError(ctx.registry, "IdentityInUse")
      .withArgs(IDENTITY_ID, ctx.owner.address);
  });

  const rejections: {
    name: string;
    change: (
      ctx: Context,
      validUntil: number,
      proofDate: number,
    ) => Promise<string>;
    error: string;
    args: (ctx: Context, validUntil: number) => unknown[];
  }[] = [
    {
      name: "a proof that ZKPassport rejects",
      change: async (ctx, validUntil, proofDate) => {
        await ctx.rootVerifier.setResult(false, DOCUMENT_ID);
        return evidence(validUntil, proofDate);
      },
      error: "InvalidProof",
      args: () => [],
    },
    {
      name: "another ZKPassport version",
      change: async (_ctx, validUntil, proofDate) =>
        evidence(validUntil, proofDate, { version: OTHER_VERSION }),
      error: "UnsupportedVersion",
      args: () => [OTHER_VERSION],
    },
    ...(
      [
        NullifierType.SALTED,
        NullifierType.NON_SALTED_MOCK,
        NullifierType.SALTED_MOCK,
        NullifierType.NONE,
      ] as const
    ).map((nullifierType) => ({
      name: `identifier type ${nullifierType}`,
      change: async (_ctx: Context, validUntil: number, proofDate: number) =>
        evidence(validUntil, proofDate, { nullifierType }),
      error: "UnexpectedNullifierType",
      args: () => [nullifierType],
    })),
    {
      name: "a proof without an identifier",
      change: async (ctx, validUntil, proofDate) => {
        await ctx.rootVerifier.setResult(true, ethers.ZeroHash);
        return evidence(validUntil, proofDate);
      },
      error: "MissingIdentifier",
      args: () => [],
    },
    {
      name: "a proof bound to another owner",
      change: async (ctx, validUntil, proofDate) => {
        await ctx.helper.setBinding(ctx.otherOwner.address, ctx.chainId);
        return evidence(validUntil, proofDate);
      },
      error: "WrongBinding",
      args: (ctx) => [ctx.otherOwner.address, ctx.chainId],
    },
    {
      name: "a proof bound to another chain",
      change: async (ctx, validUntil, proofDate) => {
        await ctx.helper.setBinding(ctx.owner.address, 1);
        return evidence(validUntil, proofDate);
      },
      error: "WrongBinding",
      args: (ctx) => [ctx.owner.address, 1],
    },
    {
      name: "an expiry check below the credential end",
      change: async (ctx, validUntil, proofDate) => {
        await ctx.helper.setExpiryLowerBound(validUntil - DAY);
        return evidence(validUntil, proofDate);
      },
      error: "ExpiryNotProven",
      args: (_ctx, validUntil) => [validUntil],
    },
    ...(
      [
        ["without FaceMatch", FaceMatchMode.NONE],
        ["with only regular FaceMatch", FaceMatchMode.REGULAR],
      ] as const
    ).map(([label, mode]) => ({
      name: `a proof ${label}`,
      change: async (ctx: Context, validUntil: number, proofDate: number) => {
        await ctx.helper.setFaceMatchMode(mode);
        return evidence(validUntil, proofDate);
      },
      error: "FaceMatchMissing",
      args: () => [],
    })),
  ];

  for (const { name, change, error, args } of rejections) {
    it(`rejects ${name}`, async function () {
      const ctx = await loadFixture(setup);
      const proofDate = await time.latest();
      const validUntil = proofDate + 30 * DAY;
      await proveFor(ctx, ctx.owner.address, validUntil);
      const data = await change(ctx, validUntil, proofDate);

      await expect(ctx.verifier.verify.staticCall(ctx.owner.address, data))
        .to.be.revertedWithCustomError(ctx.verifier, error)
        .withArgs(...args(ctx, validUntil));
    });
  }

  it("refuses a root verifier without code and an unsafe configuration", async function () {
    const ctx = await loadFixture(setup);
    const factory = await ethers.getContractFactory(
      "ZKPassportIdentityVerifier",
    );
    const noCode = ctx.owner.address;
    await expect(factory.deploy(noCode, ...ctx.verifierArgs.slice(1)))
      .to.be.revertedWithCustomError(factory, "InvalidRootVerifier")
      .withArgs(noCode);

    const unsafe: [number, unknown][] = [
      [1, ethers.ZeroHash],
      [2, ""],
      [3, ""],
      [4, NullifierType.NON_SALTED_MOCK],
      [4, NullifierType.NONE],
      [6, 0],
      [7, 0],
    ];
    for (const [index, value] of unsafe) {
      const args: unknown[] = [...ctx.verifierArgs];
      args[index] = value;
      await expect(factory.deploy(...args)).to.be.revertedWithCustomError(
        factory,
        "InvalidConfiguration",
      );
    }
  });
});
