// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import {
  InterfoldToken__factory as InterfoldTokenFactory,
  MockBondingRegistry__factory as MockBondingRegistryFactory,
  MockCCAFactory__factory as MockCCAFactoryFactory,
  InterfoldTokenSaleDeployer__factory as SaleDeployerFactory,
} from "../../types";
import { ethers, networkHelpers } from "../fixtures";

const { time } = networkHelpers;

const DAY = 24n * 60n * 60n;
const FORTY_DAYS = 40n * DAY;
const FOUR_YEARS = 4n * 365n * DAY;
const SALE_AMOUNT = ethers.parseEther("120000000"); // 120M FOLD

const AUCTION_PARAMETERS_TUPLE =
  "tuple(" +
  "address currency," +
  "address tokensRecipient," +
  "address fundsRecipient," +
  "uint64 startBlock," +
  "uint64 endBlock," +
  "uint64 claimBlock," +
  "uint256 tickSpacing," +
  "address validationHook," +
  "uint256 floorPrice," +
  "uint128 requiredCurrencyRaised," +
  "bytes auctionStepsData" +
  ")";

/** Read a deployed mock auction's shared views (version-agnostic). */
function auctionAt(
  address: string,
  runner: Parameters<typeof InterfoldTokenFactory.connect>[1],
) {
  const abi = [
    "function token() view returns (address)",
    "function totalSupply() view returns (uint128)",
    "function tokensReceived() view returns (bool)",
  ];
  return new ethers.Contract(address, abi, runner);
}

interface TestConfig {
  name: string;
  chainId: number;
  saleDeployer: string;
  safe: string;
  ccaVersion: "v1.1.0" | "v2.0.0";
  ccaFactory: string;
  saleAmount: string;
  ccaSalt: string;
  saleLabel: string;
  fold: {
    ccaStart: string;
    ccaEnd: string;
    bondingRegistry: string;
  };
  auction: {
    currency: string;
    tokensRecipient: string;
    fundsRecipient: string;
    startBlock: string;
    endBlock: string;
    claimBlock: string;
    tickSpacing: string;
    validationHook: string;
    floorPrice: string;
    requiredCurrencyRaised: string;
    auctionStepsData: string;
  };
}

interface TestSalePlan {
  predictedFold: string;
  predictedAuction: string;
  foldInitCode: string;
  saleConfig: {
    ccaFactory: string;
    ccaUseV2: boolean;
    saleAmount: bigint;
    ccaSalt: string;
    ccaConfigData: string;
    saleLabel: string;
    foldInitCodeHash: string;
  };
}

describe("InterfoldTokenSaleDeployer", function () {
  async function buildConfig(opts: {
    saleDeployer: string;
    safe: string;
    bondingRegistry: string;
    ccaFactory: string;
    useV2: boolean;
  }): Promise<TestConfig> {
    const now = BigInt(await time.latest());
    const ccaStart = now + 10n * DAY;
    const ccaEnd = ccaStart + 7n * DAY;
    const currentBlock = BigInt(await ethers.provider.getBlockNumber());

    return {
      name: "test-sale",
      chainId: Number((await ethers.provider.getNetwork()).chainId),
      saleDeployer: opts.saleDeployer,
      safe: opts.safe,
      ccaVersion: opts.useV2 ? "v2.0.0" : "v1.1.0",
      ccaFactory: opts.ccaFactory,
      saleAmount: SALE_AMOUNT.toString(),
      ccaSalt: ethers.ZeroHash,
      saleLabel: "cca-sale",
      fold: {
        ccaStart: ccaStart.toString(),
        ccaEnd: ccaEnd.toString(),
        bondingRegistry: opts.bondingRegistry,
      },
      auction: {
        currency: "ETH",
        tokensRecipient: opts.safe,
        fundsRecipient: opts.safe,
        startBlock: (currentBlock + 100n).toString(),
        endBlock: (currentBlock + 200n).toString(),
        claimBlock: (currentBlock + 210n).toString(),
        tickSpacing: "1000000000000",
        validationHook: ethers.ZeroAddress,
        floorPrice: "1000000000000",
        requiredCurrencyRaised: "0",
        auctionStepsData: "0x",
      },
    };
  }

  async function setup(useV2 = false) {
    const [deployer, operator, safeAdmin, stranger] = await ethers.getSigners();

    const safeAddress = await safeAdmin.getAddress();

    const bondingRegistry = await new MockBondingRegistryFactory(
      deployer,
    ).deploy();
    await bondingRegistry.waitForDeployment();
    const bondingRegistryAddress = await bondingRegistry.getAddress();

    const ccaFactory = await new MockCCAFactoryFactory(deployer).deploy(
      useV2,
      ethers.ZeroAddress,
    );
    await ccaFactory.waitForDeployment();
    // NB: the mock exposes a `getAddress(token,...)` method (v2 ABI) which
    // shadows ethers' BaseContract.getAddress(); read `.target` instead.
    const ccaFactoryAddress = ccaFactory.target as string;

    // Operator/gas payer deploys the sale factory, but the immutable
    // protocolAdmin is the Safe.
    const saleDeployerContract = await new SaleDeployerFactory(operator).deploy(
      safeAddress,
    );
    await saleDeployerContract.waitForDeployment();
    const saleDeployerAddress = await saleDeployerContract.getAddress();
    const saleDeployer = SaleDeployerFactory.connect(
      saleDeployerAddress,
      operator,
    );

    return {
      deployer,
      operator,
      safeAdmin,
      stranger,
      safeAddress,
      bondingRegistryAddress,
      ccaFactory,
      ccaFactoryAddress,
      saleDeployer,
      saleDeployerAddress,
      useV2,
    };
  }

  async function makePlan(
    ctx: Awaited<ReturnType<typeof setup>>,
    nonceOverride?: number,
  ) {
    const config = await buildConfig({
      saleDeployer: ctx.saleDeployerAddress,
      safe: ctx.safeAddress,
      bondingRegistry: ctx.bondingRegistryAddress,
      ccaFactory: ctx.ccaFactoryAddress,
      useV2: ctx.useV2,
    });

    const factoryNonce =
      nonceOverride ??
      (await ethers.provider.getTransactionCount(ctx.saleDeployerAddress));

    const salePlan = await computeTestSalePlan(config, factoryNonce, ctx);

    return { config, salePlan };
  }

  async function computeTestSalePlan(
    config: TestConfig,
    factoryNonce: number,
    ctx: Awaited<ReturnType<typeof setup>>,
  ): Promise<TestSalePlan> {
    const predictedFold = ethers.getCreateAddress({
      from: config.saleDeployer,
      nonce: BigInt(factoryNonce),
    });
    const auctionValues = [
      ethers.ZeroAddress,
      config.auction.tokensRecipient,
      config.auction.fundsRecipient,
      BigInt(config.auction.startBlock),
      BigInt(config.auction.endBlock),
      BigInt(config.auction.claimBlock),
      BigInt(config.auction.tickSpacing),
      config.auction.validationHook,
      BigInt(config.auction.floorPrice),
      BigInt(config.auction.requiredCurrencyRaised),
      config.auction.auctionStepsData,
    ] as const;
    const ccaConfigData = ethers.AbiCoder.defaultAbiCoder().encode(
      [AUCTION_PARAMETERS_TUPLE],
      [auctionValues],
    );
    const predictedAuction = ctx.useV2
      ? await (ctx.ccaFactory as any)[
          "getAddress(address,uint256,bytes,bytes32,address)"
        ](
          predictedFold,
          SALE_AMOUNT,
          ccaConfigData,
          config.ccaSalt,
          config.saleDeployer,
        )
      : await ctx.ccaFactory.getAuctionAddress(
          predictedFold,
          SALE_AMOUNT,
          ccaConfigData,
          config.ccaSalt,
          config.saleDeployer,
        );
    const noMoreLocks = BigInt(config.fold.ccaEnd) + FORTY_DAYS + FOUR_YEARS;
    const foldInitCode = ethers.concat([
      InterfoldTokenFactory.bytecode,
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["address", "uint64", "uint64", "uint64", "address", "address"],
        [
          config.saleDeployer,
          BigInt(config.fold.ccaStart),
          BigInt(config.fold.ccaEnd),
          noMoreLocks,
          predictedAuction,
          config.fold.bondingRegistry,
        ],
      ),
    ]);

    return {
      predictedFold,
      predictedAuction,
      foldInitCode,
      saleConfig: {
        ccaFactory: config.ccaFactory,
        ccaUseV2: ctx.useV2,
        saleAmount: SALE_AMOUNT,
        ccaSalt: config.ccaSalt,
        ccaConfigData,
        saleLabel: ethers.encodeBytes32String(config.saleLabel),
        foldInitCodeHash: ethers.keccak256(foldInitCode),
      },
    };
  }

  function structFrom(salePlan: TestSalePlan) {
    const sc = salePlan.saleConfig;
    return {
      ccaFactory: sc.ccaFactory,
      ccaUseV2: sc.ccaUseV2,
      saleAmount: sc.saleAmount,
      ccaSalt: sc.ccaSalt,
      ccaConfigData: sc.ccaConfigData,
      saleLabel: sc.saleLabel,
      foldInitCodeHash: sc.foldInitCodeHash,
    };
  }

  it("captures the Safe as protocolAdmin (no hardcoded address)", async function () {
    const ctx = await setup();
    expect(await ctx.saleDeployer.protocolAdmin()).to.equal(ctx.safeAddress);
  });

  it("deploys FOLD + CCA at the predicted addresses (v1.1.0)", async function () {
    const ctx = await setup(false);
    const { salePlan } = await makePlan(ctx);
    const digest = await ctx.saleDeployer.hashConfig(structFrom(salePlan));

    await expect(
      ctx.saleDeployer
        .connect(ctx.operator)
        .deploySale(structFrom(salePlan), salePlan.foldInitCode),
    )
      .to.emit(ctx.saleDeployer, "SaleDeployed")
      .withArgs(
        digest,
        salePlan.predictedFold,
        salePlan.predictedAuction,
        SALE_AMOUNT,
        await ctx.operator.getAddress(),
      );

    const fold = InterfoldTokenFactory.connect(
      salePlan.predictedFold,
      ctx.operator,
    );
    expect(await fold.CLAIM_SOURCE()).to.equal(salePlan.predictedAuction);
    expect(await fold.balanceOf(salePlan.predictedAuction)).to.equal(
      SALE_AMOUNT,
    );

    const auction = auctionAt(salePlan.predictedAuction, ctx.operator);
    expect(await auction.token()).to.equal(salePlan.predictedFold);
    expect(await auction.totalSupply()).to.equal(SALE_AMOUNT);
    expect(await auction.tokensReceived()).to.equal(true);
  });

  it("deploys FOLD + CCA at the predicted addresses (v2.0.0)", async function () {
    const ctx = await setup(true);
    const { salePlan } = await makePlan(ctx);

    await ctx.saleDeployer
      .connect(ctx.operator)
      .deploySale(structFrom(salePlan), salePlan.foldInitCode);

    const fold = InterfoldTokenFactory.connect(
      salePlan.predictedFold,
      ctx.operator,
    );
    expect(await fold.CLAIM_SOURCE()).to.equal(salePlan.predictedAuction);
    const auction = auctionAt(salePlan.predictedAuction, ctx.operator);
    expect(await auction.token()).to.equal(salePlan.predictedFold);
  });

  it("hands FOLD ownership to the Safe (pending until acceptOwnership)", async function () {
    const ctx = await setup();
    const { salePlan } = await makePlan(ctx);
    await ctx.saleDeployer
      .connect(ctx.operator)
      .deploySale(structFrom(salePlan), salePlan.foldInitCode);

    const fold = InterfoldTokenFactory.connect(
      salePlan.predictedFold,
      ctx.operator,
    );

    expect(await fold.owner()).to.equal(ctx.saleDeployerAddress);
    expect(await fold.pendingOwner()).to.equal(ctx.safeAddress);

    await (await fold.connect(ctx.safeAdmin).acceptOwnership()).wait();

    expect(await fold.owner()).to.equal(ctx.safeAddress);
    const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
    expect(await fold.hasRole(DEFAULT_ADMIN_ROLE, ctx.safeAddress)).to.equal(
      true,
    );
    expect(
      await fold.hasRole(DEFAULT_ADMIN_ROLE, ctx.saleDeployerAddress),
    ).to.equal(false);
  });

  it("reverts when the sale amount does not match the FOLD init-code claim-source plan", async function () {
    const ctx = await setup();
    const { salePlan } = await makePlan(ctx);

    const tampered = {
      ...structFrom(salePlan),
      saleAmount: SALE_AMOUNT + 1n,
    };
    await expect(
      ctx.saleDeployer
        .connect(ctx.operator)
        .deploySale(tampered, salePlan.foldInitCode),
    ).to.be.revertedWithCustomError(ctx.saleDeployer, "AuctionMismatch");
  });

  it("reverts when FOLD init code does not match its hash", async function () {
    const ctx = await setup();
    const { salePlan } = await makePlan(ctx);

    const lastByte = salePlan.foldInitCode.slice(-2);
    const flipped = lastByte === "00" ? "01" : "00";
    const badInitCode = salePlan.foldInitCode.slice(0, -2) + flipped;
    await expect(
      ctx.saleDeployer
        .connect(ctx.operator)
        .deploySale(structFrom(salePlan), badInitCode),
    ).to.be.revertedWithCustomError(ctx.saleDeployer, "FoldInitCodeMismatch");
  });

  it("prevents replaying the same approved config twice", async function () {
    const ctx = await setup();
    const { salePlan } = await makePlan(ctx);

    await ctx.saleDeployer
      .connect(ctx.operator)
      .deploySale(structFrom(salePlan), salePlan.foldInitCode);

    await expect(
      ctx.saleDeployer
        .connect(ctx.operator)
        .deploySale(structFrom(salePlan), salePlan.foldInitCode),
    ).to.be.revertedWithCustomError(ctx.saleDeployer, "ConfigAlreadyUsed");
  });

  it("reverts (AuctionMismatch) when the predicted nonce is wrong", async function () {
    const ctx = await setup();
    // Build a plan assuming the wrong factory nonce -> wrong predicted FOLD ->
    // wrong predicted auction baked as claimSource -> on-chain mismatch.
    const liveNonce = await ethers.provider.getTransactionCount(
      ctx.saleDeployerAddress,
    );
    const { salePlan } = await makePlan(ctx, liveNonce + 5);

    await expect(
      ctx.saleDeployer
        .connect(ctx.operator)
        .deploySale(structFrom(salePlan), salePlan.foldInitCode),
    ).to.be.revertedWithCustomError(ctx.saleDeployer, "AuctionMismatch");
  });
});
