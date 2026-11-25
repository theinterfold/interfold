// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import { deployOwnerIdentityRegistry } from "../../scripts/protocol/identityRegistry";
import type { OwnerIdentityRegistry } from "../../types";
import {
  ICAO_CHIP,
  IDENTITY_TAG,
  credentialEnd,
  publicInputLayout,
  readPublicInputs,
  zkPassportVersion,
} from "../../zkpassport";
import { ethers, networkHelpers } from "../fixtures";

const { loadFixture, time } = networkHelpers;

const VERSION = zkPassportVersion(0, 20, 0);
const OTHER_VERSION = zkPassportVersion(0, 19, 0);
const VERSION_0_23 = zkPassportVersion(0, 23, 0);
// ZKPassport's verification methods that do not read the document's chip.
const NON_CHIP_METHODS = {
  UIDAI_AADHAAR: 101,
  ATTESTED_CAPTURE_IOS: 200,
  ATTESTED_CAPTURE_ANDROID: 201,
} as const;
const OPRF_KEY = ethers.id("OPRF public key hash");
const OTHER_OPRF_KEY = ethers.id("rotated OPRF public key hash");
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
          [IDENTITY_TAG, DOMAIN, SCOPE],
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
    ethers.ZeroHash,
    true,
    PROOF_VALIDITY,
    MAX_VALIDITY,
  ];
  const verifier = await ethers.deployContract(
    "ZKPassportIdentityVerifier",
    verifierArgs,
  );
  const registry = (
    await deployOwnerIdentityRegistry(
      ethers,
      governance.address,
      await verifier.getAddress(),
    )
  ).registry as unknown as OwnerIdentityRegistry;
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

type InputOptions = {
  nullifierType?: number;
  oprfKeyHash?: string;
  verificationMethod?: number;
};

// ZKPassport's layout: index 2 is the proof date, and the last three are the nullifier type, the
// scoped nullifier and the OPRF key hash. From 0.23.0 the verification method follows them.
function publicInputs(
  proofDate: number,
  {
    nullifierType = NullifierType.NON_SALTED,
    oprfKeyHash = ethers.ZeroHash,
    verificationMethod,
  }: InputOptions = {},
) {
  return [
    ethers.id("certificate root"),
    ethers.id("circuit root"),
    ethers.toBeHex(proofDate, 32),
    ethers.id("domain"),
    ethers.id("scope"),
    ethers.id("parameter commitment"),
    ethers.toBeHex(nullifierType, 32),
    DOCUMENT_ID,
    oprfKeyHash,
    ...(verificationMethod === undefined
      ? []
      : [ethers.toBeHex(verificationMethod, 32)]),
  ];
}

function evidence(
  validUntil: number,
  proofDate: number,
  { version = VERSION, ...inputs }: { version?: string } & InputOptions = {},
) {
  // The caller asks for dev mode, another domain and a long window; none of them may reach
  // ZKPassport's verifier.
  const params = [
    version,
    [ethers.id("vkey"), "0x1234", publicInputs(proofDate, inputs)],
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
      name: "a proof that carries an OPRF key",
      change: async (_ctx, validUntil, proofDate) =>
        evidence(validUntil, proofDate, { oprfKeyHash: OPRF_KEY }),
      error: "UnexpectedOPRFKey",
      args: () => [OPRF_KEY],
    },
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

  it("accepts only the pinned OPRF key in a salted deployment", async function () {
    const ctx = await loadFixture(setup);
    const args: unknown[] = [...ctx.verifierArgs];
    args[4] = NullifierType.SALTED;
    args[5] = OPRF_KEY;
    const salted = await ethers.deployContract(
      "ZKPassportIdentityVerifier",
      args,
    );
    const proofDate = await time.latest();
    const validUntil = proofDate + 30 * DAY;
    await proveFor(ctx, ctx.owner.address, validUntil);
    const options = { nullifierType: NullifierType.SALTED };

    const [identityId] = await salted.verify.staticCall(
      ctx.owner.address,
      evidence(validUntil, proofDate, { ...options, oprfKeyHash: OPRF_KEY }),
    );
    expect(identityId).to.equal(IDENTITY_ID);

    await expect(
      salted.verify.staticCall(
        ctx.owner.address,
        evidence(validUntil, proofDate, {
          ...options,
          oprfKeyHash: OTHER_OPRF_KEY,
        }),
      ),
    )
      .to.be.revertedWithCustomError(salted, "UnexpectedOPRFKey")
      .withArgs(OTHER_OPRF_KEY);
  });

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
      // A salted deployment needs ZKPassport's OPRF key; a non-salted one must not have a key.
      [4, NullifierType.SALTED],
      [5, OPRF_KEY],
      [7, 0],
      [8, 0],
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

  it("reads every version's public inputs and ends its credential as the zkpassport module does", async function () {
    const ctx = await loadFixture(setup);
    const factory = await ethers.getContractFactory(
      "ZKPassportIdentityVerifier",
    );
    const proofDate = await time.latest();
    // Salted, so every value that the verifier checks differs from the others.
    const salted = {
      nullifierType: NullifierType.SALTED,
      oprfKeyHash: OPRF_KEY,
    };
    const versions = [
      zkPassportVersion(0, 19, 0),
      zkPassportVersion(0, 20, 0),
      zkPassportVersion(0, 21, 1),
      zkPassportVersion(0, 22, 0),
      zkPassportVersion(0, 23, 0),
      zkPassportVersion(0, 24, 0),
      zkPassportVersion(1, 0, 0),
      ethers.zeroPadBytes("0x00000017000001", 32), // 0.23.0 with trailing data
      ethers.zeroPadValue("0x17", 32), // right-aligned, not ZKPassport's encoding
    ];
    for (const version of versions) {
      const args: unknown[] = [...ctx.verifierArgs];
      args[1] = version;
      args[4] = salted.nullifierType;
      args[5] = salted.oprfKeyHash;
      const layout = publicInputLayout(version);
      if (layout === null) {
        await expect(factory.deploy(...args))
          .to.be.revertedWithCustomError(factory, "UnsupportedVersion")
          .withArgs(version);
        continue;
      }
      const inputs = {
        ...salted,
        verificationMethod:
          layout.verificationMethodFromEnd === null ? undefined : ICAO_CHIP,
      };
      expect(
        readPublicInputs(version, publicInputs(proofDate, inputs)),
      ).to.deep.equal({
        proofDate: BigInt(proofDate),
        nullifierType: salted.nullifierType,
        scopedNullifier: DOCUMENT_ID,
        oprfKeyHash: salted.oprfKeyHash,
        verificationMethod: ICAO_CHIP,
      });
      const verifier = await ethers.deployContract(
        "ZKPassportIdentityVerifier",
        args,
      );
      for (const validUntil of [
        proofDate + DAY,
        proofDate + 2 * MAX_VALIDITY,
      ]) {
        await proveFor(ctx, ctx.owner.address, validUntil);
        const [, expiresAt] = await verifier.verify.staticCall(
          ctx.owner.address,
          evidence(validUntil, proofDate, { version, ...inputs }),
        );
        expect(expiresAt).to.equal(
          credentialEnd(
            BigInt(validUntil),
            BigInt(proofDate),
            BigInt(MAX_VALIDITY),
          ),
        );
      }
    }
  });

  describe("ZKPassport 0.23", function () {
    async function setup023() {
      const ctx = await setup();
      const args: unknown[] = [...ctx.verifierArgs];
      args[1] = VERSION_0_23;
      args[4] = NullifierType.SALTED;
      args[5] = OPRF_KEY;
      const verifier = await ethers.deployContract(
        "ZKPassportIdentityVerifier",
        args,
      );
      return { ...ctx, verifier };
    }
    const salted = {
      version: VERSION_0_23,
      nullifierType: NullifierType.SALTED,
      oprfKeyHash: OPRF_KEY,
    };

    for (const method of Object.values(NON_CHIP_METHODS)) {
      it(`rejects verification method ${method}, which does not read the document's chip`, async function () {
        const ctx = await loadFixture(setup023);
        const proofDate = await time.latest();
        const validUntil = proofDate + 30 * DAY;
        await proveFor(ctx, ctx.owner.address, validUntil);

        await expect(
          ctx.verifier.verify.staticCall(
            ctx.owner.address,
            evidence(validUntil, proofDate, {
              ...salted,
              verificationMethod: method,
            }),
          ),
        )
          .to.be.revertedWithCustomError(
            ctx.verifier,
            "UnsupportedVerificationMethod",
          )
          .withArgs(method);
      });
    }
  });
});
