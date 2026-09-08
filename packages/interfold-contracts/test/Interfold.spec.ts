// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import {
  ACTIVE_CRYPTO_CONFIG_ID,
  ADDRESS_TWO as AddressTwo,
  BFV_PARAMS_DEFAULT,
  BFV_PARAMS_SECURE,
  PRODUCTION_CRYPTO_CONFIG_ID,
  buildMockAggregationPublishArgs,
  deployInterfoldSystem,
  ENCRYPTION_SCHEME_ID as encryptionSchemeId,
  ethers,
  makeRequest,
  networkHelpers,
  publishAvailableCiphertextOutput,
  setupAndPublishCommittee,
  DEFAULT_TIMEOUT_CONFIG as timeoutConfig,
} from "./fixtures";

const { loadFixture, time, mine } = networkHelpers;

const uint256ControllerPrefix = (controller: string): bigint =>
  BigInt(controller) << 96n;

describe("Interfold", function () {
  let firstE3Id: bigint;
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();
  const newEncryptionSchemeId =
    "0x0000000000000000000000000000000000000000000000000000000000000002";

  const data = "0xda7a";
  const proof = "0x1337";
  const ciphertextCommitment = ethers.keccak256(data);

  const inputWindowDuration = 300;

  const setup = async () => {
    const sys = await deployInterfoldSystem({ wireSlashingManager: true });
    firstE3Id = await sys.interfold.nexte3Id();
    return {
      owner: sys.owner,
      notTheOwner: sys.notTheOwner,
      operator1: sys.operator1!,
      operator2: sys.operator2!,
      operator3: sys.operator3!,
      interfold: sys.interfold,
      ciphernodeRegistryContract: sys.ciphernodeRegistry,
      bondingRegistry: sys.bondingRegistry,
      ciphernodeBondToken: sys.ciphernodeBondToken,
      ticketToken: sys.ticketToken,
      usdcToken: sys.usdcToken,
      slashingManager: sys.slashingManager,
      request: sys.request,
      mocks: {
        ciphertextVerifier: sys.mocks.ciphertextVerifier,
        decryptionVerifier: sys.mocks.decryptionVerifier,
        e3Program: sys.mocks.e3Program,
        mockComputeProvider: sys.mocks.mockComputeProvider,
      },
    };
  };

  const deployUnregisteredE3Program = async () => {
    const e3Program = await ethers.deployContract("MockE3Program");
    await e3Program.waitForDeployment();
    return e3Program;
  };

  describe("constructor / initialize()", function () {
    it("correctly sets owner", async function () {
      const { interfold, owner } = await loadFixture(setup);
      expect(await interfold.owner()).to.equal(await owner.getAddress());
    });

    it("correctly sets ciphernodeRegistry address", async function () {
      const { interfold, ciphernodeRegistryContract } =
        await loadFixture(setup);
      expect(await interfold.ciphernodeRegistry()).to.equal(
        await ciphernodeRegistryContract.getAddress(),
      );
    });

    it("correctly sets max duration", async function () {
      const { interfold } = await loadFixture(setup);
      expect(await interfold.maxDuration()).to.equal(60 * 60 * 24 * 30);
    });

    it("namespaces E3 IDs by the controller address", async function () {
      const { interfold } = await loadFixture(setup);
      expect(await interfold.nexte3Id()).to.equal(
        uint256ControllerPrefix(await interfold.getAddress()),
      );
    });

    it("exposes the production default crypto configuration", async function () {
      const { interfold } = await loadFixture(setup);
      expect(await interfold.activeCryptoConfigId()).to.equal(
        PRODUCTION_CRYPTO_CONFIG_ID,
      );
    });

    it("registers the initial E3 Program", async function () {
      const {
        interfold,
        mocks: { e3Program },
      } = await loadFixture(setup);
      expect(await interfold.e3Programs(await e3Program.getAddress())).to.be
        .true;
    });
  });

  describe("setMaxDuration()", function () {
    it("reverts if not called by owner", async function () {
      const { interfold, notTheOwner } = await loadFixture(setup);

      await expect(
        interfold
          .connect(notTheOwner)
          .setMaxDuration(1, { from: await notTheOwner.getAddress() }),
      )
        .to.be.revertedWithCustomError(interfold, "OwnableUnauthorizedAccount")
        .withArgs(notTheOwner);
    });
    it("set max duration correctly", async function () {
      const { interfold } = await loadFixture(setup);
      await interfold.setMaxDuration(1);
      expect(await interfold.maxDuration()).to.equal(1);
    });
    it("emits MaxDurationSet event", async function () {
      const { interfold } = await loadFixture(setup);
      await expect(interfold.setMaxDuration(1))
        .to.emit(interfold, "MaxDurationSet")
        .withArgs(1);
    });
  });

  describe("setCiphernodeRegistry()", function () {
    it("reverts if not called by owner", async function () {
      const { interfold, notTheOwner } = await loadFixture(setup);

      await expect(
        interfold.connect(notTheOwner).setCiphernodeRegistry(AddressTwo),
      )
        .to.be.revertedWithCustomError(interfold, "OwnableUnauthorizedAccount")
        .withArgs(notTheOwner);
    });

    it("reverts if given address(0)", async function () {
      const { interfold } = await loadFixture(setup);
      await expect(interfold.setCiphernodeRegistry(ethers.ZeroAddress))
        .to.be.revertedWithCustomError(interfold, "InvalidCiphernodeRegistry")
        .withArgs(ethers.ZeroAddress);
    });

    it("reverts if given address is the same as the current ciphernodeRegistry", async function () {
      const { interfold, ciphernodeRegistryContract } =
        await loadFixture(setup);
      await expect(
        interfold.setCiphernodeRegistry(
          await ciphernodeRegistryContract.getAddress(),
        ),
      )
        .to.be.revertedWithCustomError(interfold, "InvalidCiphernodeRegistry")
        .withArgs(await ciphernodeRegistryContract.getAddress());
    });

    it("sets ciphernodeRegistry correctly", async function () {
      const { interfold } = await deployInterfoldSystem({ setupOperators: 0 });
      const replacement = await ethers.deployContract("MockCiphernodeRegistry");
      const replacementAddress = await replacement.getAddress();

      await interfold.setRequestsPaused(true);
      await interfold.setCiphernodeRegistry(replacementAddress);
      expect(await interfold.ciphernodeRegistry()).to.equal(replacementAddress);
    });

    it("rejects a replacement registry with existing members", async function () {
      const { interfold } = await deployInterfoldSystem({ setupOperators: 0 });
      const replacement = await ethers.deployContract("MockCiphernodeRegistry");

      await replacement.addCiphernode(AddressTwo);
      await interfold.setRequestsPaused(true);

      await expect(
        interfold.setCiphernodeRegistry(await replacement.getAddress()),
      ).to.be.revertedWithCustomError(
        interfold,
        "DependencyGenerationNotDrained",
      );
    });

    it("emits CiphernodeRegistrySet event", async function () {
      const { interfold } = await deployInterfoldSystem({ setupOperators: 0 });
      const replacement = await ethers.deployContract("MockCiphernodeRegistry");
      const replacementAddress = await replacement.getAddress();

      await interfold.setRequestsPaused(true);
      await expect(interfold.setCiphernodeRegistry(replacementAddress))
        .to.emit(interfold, "CiphernodeRegistrySet")
        .withArgs(replacementAddress);
    });
  });

  describe("setParamSet()", function () {
    it("reverts if not called by owner", async function () {
      const { interfold, notTheOwner } = await loadFixture(setup);

      await expect(
        interfold.connect(notTheOwner).setParamSet(0, BFV_PARAMS_DEFAULT),
      )
        .to.be.revertedWithCustomError(interfold, "OwnableUnauthorizedAccount")
        .withArgs(notTheOwner);
    });

    it("accepts only supported circuit parameter sets", async function () {
      const { interfold } = await loadFixture(setup);

      expect(await interfold.paramSetRegistry(0)).to.equal(BFV_PARAMS_DEFAULT);
      await expect(interfold.setParamSet(1, BFV_PARAMS_SECURE))
        .to.emit(interfold, "ParamSetRegistered")
        .withArgs(1, BFV_PARAMS_SECURE);
      await expect(
        interfold.setParamSet(2, BFV_PARAMS_DEFAULT),
      ).to.be.revertedWithCustomError(interfold, "UnsupportedCryptoConfig");
    });

    it("does not overwrite the active parameter set", async function () {
      const { interfold } = await loadFixture(setup);

      await expect(interfold.setParamSet(0, BFV_PARAMS_DEFAULT))
        .to.be.revertedWithCustomError(interfold, "ParamSetAlreadyRegistered")
        .withArgs(0);
    });

    it("rejects parameter bytes that do not match the active circuit", async function () {
      const { interfold } = await loadFixture(setup);

      await expect(
        interfold.setParamSet(1, "0x"),
      ).to.be.revertedWithCustomError(interfold, "UnsupportedCryptoConfig");
    });
  });

  describe("getE3()", function () {
    it("reverts if E3 does not exist", async function () {
      const { interfold } = await loadFixture(setup);

      await expect(interfold.getE3(1))
        .to.be.revertedWithCustomError(interfold, "E3DoesNotExist")
        .withArgs(1);
    });

    it("returns correct E3 details", async function () {
      const { interfold, request, usdcToken } = await loadFixture(setup);

      await makeRequest(interfold, usdcToken, {
        committeeSize: request.committeeSize,
        inputWindow: request.inputWindow,
        e3Program: request.e3Program,
        paramSet: request.paramSet,
        computeProviderParams: request.computeProviderParams,
        customParams: request.customParams,
      });

      const e3 = await interfold.getE3(firstE3Id);

      expect(e3.committeeSize).to.equal(request.committeeSize);
      expect(e3.inputWindow[0]).to.equal(request.inputWindow[0]);
      expect(e3.inputWindow[1]).to.equal(request.inputWindow[1]);
      expect(e3.e3Program).to.equal(request.e3Program);
      expect(e3.paramSet).to.equal(request.paramSet);
      expect(await interfold.e3CryptoConfigIds(firstE3Id)).to.equal(
        ACTIVE_CRYPTO_CONFIG_ID,
      );
      expect(e3.decryptionVerifier).to.equal(
        abiCoder.decode(["address"], request.computeProviderParams)[0],
      );
      expect(e3.committeePublicKey).to.equal(ethers.ZeroHash);
      expect(e3.ciphertextOutput).to.equal(ethers.ZeroHash);
      expect(e3.plaintextOutput).to.equal("0x");
    });
  });

  describe("getDecryptionVerifier()", function () {
    it("returns true if encryption scheme is enabled", async function () {
      const { interfold, mocks } = await loadFixture(setup);
      expect(
        await interfold.getDecryptionVerifier(encryptionSchemeId),
      ).to.equal(await mocks.decryptionVerifier.getAddress());
    });

    it("returns false if encryption scheme is not enabled", async function () {
      const { interfold } = await loadFixture(setup);
      expect(
        await interfold.getDecryptionVerifier(newEncryptionSchemeId),
      ).to.equal(ethers.ZeroAddress);
    });
  });

  describe("setDecryptionVerifier()", function () {
    it("reverts if caller is not owner", async function () {
      const { interfold, mocks, notTheOwner } = await loadFixture(setup);

      await expect(
        interfold
          .connect(notTheOwner)
          .setDecryptionVerifier(
            encryptionSchemeId,
            await mocks.decryptionVerifier.getAddress(),
          ),
      )
        .to.be.revertedWithCustomError(interfold, "OwnableUnauthorizedAccount")
        .withArgs(notTheOwner);
    });

    it("reverts if encryption scheme is already enabled", async function () {
      const { interfold, mocks } = await loadFixture(setup);

      await expect(
        interfold.setDecryptionVerifier(
          encryptionSchemeId,
          await mocks.decryptionVerifier.getAddress(),
        ),
      )
        .to.be.revertedWithCustomError(interfold, "InvalidEncryptionScheme")
        .withArgs(encryptionSchemeId);
    });

    it("enabled decryption verifier", async function () {
      const { interfold, mocks } = await loadFixture(setup);

      expect(
        await interfold.setDecryptionVerifier(
          newEncryptionSchemeId,
          await mocks.decryptionVerifier.getAddress(),
        ),
      );
      expect(
        await interfold.getDecryptionVerifier(newEncryptionSchemeId),
      ).to.equal(await mocks.decryptionVerifier.getAddress());
    });

    it("emits EncryptionSchemeEnabled", async function () {
      const { interfold, mocks } = await loadFixture(setup);

      await expect(
        await interfold.setDecryptionVerifier(
          newEncryptionSchemeId,
          await mocks.decryptionVerifier.getAddress(),
        ),
      )
        .to.emit(interfold, "EncryptionSchemeEnabled")
        .withArgs(newEncryptionSchemeId);
    });
  });

  describe("setCiphertextVerifier()", function () {
    it("allows only the owner to set a verifier", async function () {
      const { interfold, mocks, notTheOwner } = await loadFixture(setup);

      await expect(
        interfold
          .connect(notTheOwner)
          .setCiphertextVerifier(
            newEncryptionSchemeId,
            await mocks.ciphertextVerifier.getAddress(),
          ),
      )
        .to.be.revertedWithCustomError(interfold, "OwnableUnauthorizedAccount")
        .withArgs(notTheOwner);
    });

    it("rejects an address without verifier code", async function () {
      const { interfold } = await loadFixture(setup);

      await expect(
        interfold.setCiphertextVerifier(newEncryptionSchemeId, AddressTwo),
      )
        .to.be.revertedWithCustomError(interfold, "InvalidEncryptionScheme")
        .withArgs(newEncryptionSchemeId);
    });

    it("emits the verifier selected for future requests", async function () {
      const { interfold, mocks } = await loadFixture(setup);
      const verifier = await mocks.ciphertextVerifier.getAddress();

      await expect(
        interfold.setCiphertextVerifier(newEncryptionSchemeId, verifier),
      )
        .to.emit(interfold, "CiphertextVerifierSet")
        .withArgs(newEncryptionSchemeId, verifier);
    });
  });

  describe("registerE3Program()", function () {
    it("reverts if not called by owner", async function () {
      const { interfold, notTheOwner } = await loadFixture(setup);

      await expect(interfold.connect(notTheOwner).registerE3Program(AddressTwo))
        .to.be.revertedWithCustomError(interfold, "OwnableUnauthorizedAccount")
        .withArgs(notTheOwner);
    });

    it("reverts if E3 Program is already registered", async function () {
      const {
        interfold,
        mocks: { e3Program },
      } = await loadFixture(setup);
      await expect(interfold.registerE3Program(e3Program))
        .to.be.revertedWithCustomError(interfold, "ModuleAlreadyEnabled")
        .withArgs(e3Program);
    });
    it("reverts if E3 Program is the zero address", async function () {
      const { interfold } = await loadFixture(setup);
      await expect(interfold.registerE3Program(ethers.ZeroAddress))
        .to.be.revertedWithCustomError(interfold, "E3ProgramNotAllowed")
        .withArgs(ethers.ZeroAddress);
    });
    it("reverts if E3 Program has no deployed code", async function () {
      const { interfold } = await loadFixture(setup);
      await expect(interfold.registerE3Program(AddressTwo))
        .to.be.revertedWithCustomError(interfold, "E3ProgramNotAllowed")
        .withArgs(AddressTwo);
    });
    it("registers E3 Program correctly", async function () {
      const { interfold } = await loadFixture(setup);
      const e3Program = await deployUnregisteredE3Program();
      const e3ProgramAddress = await e3Program.getAddress();
      await interfold.registerE3Program(e3ProgramAddress);
      expect(await interfold.e3Programs(e3ProgramAddress)).to.be.true;
    });
    it("emits E3ProgramRegistered event", async function () {
      const { interfold } = await loadFixture(setup);
      const e3Program = await deployUnregisteredE3Program();
      const e3ProgramAddress = await e3Program.getAddress();
      await expect(interfold.registerE3Program(e3ProgramAddress))
        .to.emit(interfold, "E3ProgramRegistered")
        .withArgs(e3ProgramAddress);
    });
  });

  describe("unregisterE3Program()", function () {
    it("closes new request admission without changing existing E3 records", async function () {
      const {
        interfold,
        notTheOwner,
        request,
        usdcToken,
        mocks: { e3Program },
      } = await loadFixture(setup);
      const e3ProgramAddress = await e3Program.getAddress();

      await usdcToken.approve(await interfold.getAddress(), ethers.MaxUint256);
      await interfold.request(request);
      expect((await interfold.getE3(firstE3Id)).e3Program).to.equal(
        e3ProgramAddress,
      );

      await expect(
        interfold.connect(notTheOwner).unregisterE3Program(e3ProgramAddress),
      )
        .to.be.revertedWithCustomError(interfold, "OwnableUnauthorizedAccount")
        .withArgs(notTheOwner);

      await expect(interfold.unregisterE3Program(e3ProgramAddress))
        .to.emit(interfold, "E3ProgramUnregistered")
        .withArgs(e3ProgramAddress);
      expect(await interfold.e3Programs(e3ProgramAddress)).to.be.false;
      expect((await interfold.getE3(firstE3Id)).e3Program).to.equal(
        e3ProgramAddress,
      );

      await expect(interfold.unregisterE3Program(e3ProgramAddress))
        .to.be.revertedWithCustomError(interfold, "E3ProgramNotAllowed")
        .withArgs(e3ProgramAddress);
      const requestTime = await time.latest();
      const requestAfterUnregister = {
        ...request,
        inputWindow: [
          requestTime + 60,
          requestTime + 60 + inputWindowDuration,
        ] as [number, number],
      };
      await expect(interfold.request(requestAfterUnregister))
        .to.be.revertedWithCustomError(interfold, "E3ProgramNotAllowed")
        .withArgs(e3ProgramAddress);
    });
  });

  describe("request()", function () {
    it("rejects a fee token that differs from the accepted quote", async function () {
      const { interfold, request } = await loadFixture(setup);
      await expect(
        interfold.request({ ...request, expectedFeeToken: AddressTwo }),
      ).to.be.revertedWithCustomError(interfold, "FeeTokenChanged");
    });

    it("rejects a quote above the requester's fee limit", async function () {
      const { interfold, request } = await loadFixture(setup);
      await expect(
        interfold.request({ ...request, maxFee: 0 }),
      ).to.be.revertedWithCustomError(interfold, "FeeExceedsMaximum");
    });

    it("rejects a circuit configuration that changed after quoting", async function () {
      const { interfold, request } = await loadFixture(setup);
      await expect(
        interfold.request({
          ...request,
          expectedCryptoConfigId: ethers.ZeroHash,
        }),
      ).to.be.revertedWithCustomError(interfold, "CryptoConfigChanged");
    });

    it("reverts if USDC allowance is insufficient", async function () {
      const { interfold, request, usdcToken } = await loadFixture(setup);
      await expect(
        interfold.request({
          committeeSize: request.committeeSize,
          inputWindow: request.inputWindow,
          e3Program: request.e3Program,
          paramSet: request.paramSet,
          computeProviderParams: request.computeProviderParams,
          customParams: request.customParams,
          expectedFeeToken: request.expectedFeeToken,
          expectedCryptoConfigId: request.expectedCryptoConfigId,
          maxFee: request.maxFee,
        }),
      ).to.be.revertedWithCustomError(usdcToken, "ERC20InsufficientAllowance");
    });
    it("reverts if committee size is not configured", async function () {
      const { interfold, request } = await loadFixture(setup);
      const unconfiguredCommitteeSize = 1;
      const unconfiguredParams = {
        committeeSize: unconfiguredCommitteeSize,
        inputWindow: request.inputWindow,
        e3Program: request.e3Program,
        paramSet: request.paramSet,
        computeProviderParams: request.computeProviderParams,
        customParams: request.customParams,
        expectedFeeToken: request.expectedFeeToken,
        expectedCryptoConfigId: request.expectedCryptoConfigId,
        maxFee: request.maxFee,
      };
      await expect(interfold.getE3Quote.staticCall(unconfiguredParams))
        .to.be.revertedWithCustomError(interfold, "CommitteeSizeNotConfigured")
        .withArgs(unconfiguredCommitteeSize);
    });
    it("reverts if total duration is greater than maxDuration", async function () {
      const { interfold, request, usdcToken } = await loadFixture(setup);

      await expect(
        makeRequest(interfold, usdcToken, {
          committeeSize: request.committeeSize,
          inputWindow: [
            request.inputWindow[0],
            Number(request.inputWindow[1]) + time.duration.days(31),
          ],
          e3Program: request.e3Program,
          paramSet: request.paramSet,
          computeProviderParams: request.computeProviderParams,
          customParams: request.customParams,
        }),
      ).to.be.revertedWithCustomError(interfold, "InvalidDuration");
    });
    it("allows total duration equal to maxDuration", async function () {
      const { interfold, request, usdcToken } = await loadFixture(setup);
      await usdcToken.approve(await interfold.getAddress(), ethers.MaxUint256);
      const requestAt = BigInt((await time.latest()) + 10);
      const maxDuration = await interfold.maxDuration();
      const inputEnd =
        requestAt +
        maxDuration -
        BigInt(timeoutConfig.computeWindow) -
        BigInt(timeoutConfig.decryptionWindow);
      const exactDurationRequest = {
        ...request,
        inputWindow: [requestAt, inputEnd] as [bigint, bigint],
      };
      await time.setNextBlockTimestamp(requestAt);

      await interfold.request(exactDurationRequest);
      const e3Id = uint256ControllerPrefix(await interfold.getAddress());
      expect(await interfold.nexte3Id()).to.equal(e3Id + 1n);
    });
    it("allows compute to start after a late committee finalization", async function () {
      const { interfold, ciphernodeRegistryContract, request, usdcToken } =
        await loadFixture(setup);
      const sortitionWindow = time.duration.days(1);

      await ciphernodeRegistryContract.setSortitionSubmissionWindow(
        sortitionWindow,
      );
      await usdcToken.approve(await interfold.getAddress(), ethers.MaxUint256);
      const requestAt = BigInt((await time.latest()) + 1);
      const impossibleRequest = {
        ...request,
        inputWindow: [requestAt, requestAt + 10n] as [bigint, bigint],
      };
      await time.setNextBlockTimestamp(requestAt);
      await interfold.request(impossibleRequest);
      const e3Id = uint256ControllerPrefix(await interfold.getAddress());
      expect(await interfold.nexte3Id()).to.equal(e3Id + 1n);
      expect(await interfold.getE3LifecycleDeadline(e3Id)).to.be.gt(
        impossibleRequest.inputWindow[1],
      );
    });
    it("reverts if E3 Program is not enabled", async function () {
      const { interfold, request, usdcToken } = await loadFixture(setup);

      await expect(
        makeRequest(interfold, usdcToken, {
          committeeSize: request.committeeSize,
          inputWindow: request.inputWindow,
          e3Program: ethers.ZeroAddress,
          paramSet: request.paramSet,
          computeProviderParams: request.computeProviderParams,
          customParams: request.customParams,
        }),
      )
        .to.be.revertedWithCustomError(interfold, "E3ProgramNotAllowed")
        .withArgs(ethers.ZeroAddress);
    });
    it("instantiates a new E3", async function () {
      const {
        interfold,
        request,
        usdcToken,
        mocks: { e3Program },
      } = await loadFixture(setup);
      await usdcToken.approve(await interfold.getAddress(), ethers.MaxUint256);
      const requestAt = BigInt((await time.latest()) + 1);
      const freshRequest = {
        ...request,
        inputWindow: [requestAt, requestAt + BigInt(inputWindowDuration)] as [
          bigint,
          bigint,
        ],
      };
      await time.setNextBlockTimestamp(requestAt);
      await interfold.request(freshRequest);

      const e3 = await interfold.getE3(firstE3Id);
      const block = await ethers.provider.getBlock("latest").catch((e) => e);

      expect(e3.committeeSize).to.equal(request.committeeSize);
      expect(e3.inputWindow[0]).to.equal(freshRequest.inputWindow[0]);
      expect(e3.inputWindow[1]).to.equal(freshRequest.inputWindow[1]);
      expect(e3.e3Program).to.equal(request.e3Program);
      // H-26: `requestBlock` now stores `block.timestamp` (a stable EIP-6372
      // clock) instead of `block.number`, so the snapshot agrees with the
      // bonding registry / token checkpoints across L2s with variable block
      // production.
      expect(e3.requestBlock).to.equal(block.timestamp);
      expect(await e3Program.validationRequestTimes(firstE3Id)).to.equal(
        block.timestamp,
      );
      expect(e3.decryptionVerifier).to.equal(
        abiCoder.decode(["address"], request.computeProviderParams)[0],
      );
      expect(e3.committeePublicKey).to.equal(ethers.ZeroHash);
      expect(e3.ciphertextOutput).to.equal(ethers.ZeroHash);
      expect(e3.plaintextOutput).to.equal("0x");
    });
    it("emits E3Requested event", async function () {
      const { interfold, request, usdcToken } = await loadFixture(setup);
      await usdcToken.approve(await interfold.getAddress(), ethers.MaxUint256);
      const requestAt = BigInt((await time.latest()) + 1);
      const freshRequest = {
        ...request,
        inputWindow: [requestAt, requestAt + BigInt(inputWindowDuration)] as [
          bigint,
          bigint,
        ],
      };
      await time.setNextBlockTimestamp(requestAt);
      const tx = await interfold.request(freshRequest);
      const e3 = await interfold.getE3(firstE3Id);

      await expect(tx)
        .to.emit(interfold, "E3Requested")
        .withArgs(firstE3Id, e3, ACTIVE_CRYPTO_CONFIG_ID);
    });
  });

  describe("publishCiphertextOutput()", function () {
    it("reverts if E3 does not exist", async function () {
      const { interfold } = await loadFixture(setup);

      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          0,
          "0x",
          ethers.ZeroHash,
          "0x",
        ),
      )
        .to.be.revertedWithCustomError(interfold, "E3DoesNotExist")
        .withArgs(0);
    });

    it("reverts if output has already been published", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;
      await usdcToken.approve(await interfold.getAddress(), ethers.MaxUint256);
      const requestAt = BigInt((await time.latest()) + 1);
      const freshRequest = {
        ...request,
        inputWindow: [requestAt, requestAt + BigInt(inputWindowDuration)] as [
          bigint,
          bigint,
        ],
      };
      await time.setNextBlockTimestamp(requestAt);
      await interfold.request(freshRequest);

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });

      await publishAvailableCiphertextOutput(
        interfold,
        e3Id,
        data,
        ciphertextCommitment,
        proof,
      );
      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          e3Id,
          data,
          ciphertextCommitment,
          proof,
        ),
      )
        .to.be.revertedWithCustomError(interfold, "InvalidStage")
        .withArgs(e3Id, 3, 4);
    });
    it("reverts if committee duties are over", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, {
        interval: inputWindowDuration + timeoutConfig.computeWindow,
      });
      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          e3Id,
          data,
          ciphertextCommitment,
          proof,
        ),
      ).to.be.revertedWithCustomError(interfold, "CommitteeDutiesCompleted");
    });
    it("reverts if output is not valid", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        committeeSize: request.committeeSize,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
        e3Program: request.e3Program,
        paramSet: request.paramSet,
        computeProviderParams: request.computeProviderParams,
        customParams: request.customParams,
      });

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          e3Id,
          "0x",
          ethers.ZeroHash,
          "0x",
        ),
      ).to.be.revertedWithCustomError(interfold, "InvalidOutput");
    });
    it("does not assign an unverified ciphertext to the committee", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
        mocks,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });
      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await mocks.ciphertextVerifier.setResult(false);

      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          e3Id,
          data,
          ciphertextCommitment,
          proof,
        ),
      ).to.be.revertedWithCustomError(interfold, "InvalidOutput");
      expect(await interfold.getE3Stage(e3Id)).to.equal(3);
      const e3 = await interfold.getE3(e3Id);
      expect(e3.ciphertextOutput).to.equal(ethers.ZeroHash);
      expect(e3.ciphertextCommitment).to.equal(ethers.ZeroHash);
    });

    it("rejects an availability proof for different ciphertext bytes atomically", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });
      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });

      const mismatchedReference = abiCoder.encode(
        [
          "tuple(bytes32 contentHash,bytes32 ciphertextCommitment,bytes computeProof,bytes availabilityProof)",
        ],
        [
          {
            contentHash: ethers.keccak256(data),
            ciphertextCommitment,
            computeProof: proof,
            availabilityProof: "0xdeadbeef",
          },
        ],
      );
      await expect(
        interfold.publishCiphertextOutput(e3Id, mismatchedReference),
      ).to.be.revert(ethers);
      expect(await interfold.getE3Stage(e3Id)).to.equal(3);
      expect((await interfold.getE3(e3Id)).ciphertextOutput).to.equal(
        ethers.ZeroHash,
      );
    });

    it("rejects an availability receipt for a different content hash atomically", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
        mocks,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });
      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await mocks.e3Program.setReturnMismatchedAvailabilityHash(true);

      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          e3Id,
          data,
          ciphertextCommitment,
          proof,
        ),
      ).to.be.revertedWithCustomError(interfold, "InvalidOutput");
      expect(await interfold.getE3Stage(e3Id)).to.equal(3);
      expect((await interfold.getE3(e3Id)).ciphertextOutput).to.equal(
        ethers.ZeroHash,
      );
    });

    it("keeps the request-time verifier after verifier rotation", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
        mocks,
      } = await loadFixture(setup);
      const replacement = await ethers.deployContract("MockCiphertextVerifier");
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });
      await interfold.setCiphertextVerifier(
        encryptionSchemeId,
        await replacement.getAddress(),
      );
      await mocks.ciphertextVerifier.setResult(false);
      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });

      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          e3Id,
          data,
          ciphertextCommitment,
          proof,
        ),
      ).to.be.revertedWithCustomError(interfold, "InvalidOutput");

      await mocks.ciphertextVerifier.setResult(true);
      await replacement.setResult(false);
      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          e3Id,
          data,
          ciphertextCommitment,
          proof,
        ),
      ).to.emit(interfold, "CiphertextOutputReferencePublished");
    });
    it("sets ciphertextOutput correctly", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
        mocks,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await mocks.e3Program.setExpectedCiphertextCommitment(
        e3Id,
        ciphertextCommitment,
      );
      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          e3Id,
          data,
          ethers.keccak256("0xbad0"),
          proof,
        ),
      ).to.be.revertedWithCustomError(interfold, "InvalidOutput");
      await publishAvailableCiphertextOutput(
        interfold,
        e3Id,
        data,
        ciphertextCommitment,
        proof,
      );
      const e3 = await interfold.getE3(e3Id);
      expect(e3.ciphertextOutput).to.equal(ethers.keccak256(data));
      expect(e3.ciphertextCommitment).to.equal(ciphertextCommitment);
    });

    it("accepts a valid output reference", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          e3Id,
          data,
          ciphertextCommitment,
          proof,
        ),
      ).to.emit(interfold, "CiphertextOutputReferencePublished");
    });
    it("emits the verified ciphertext reference", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          e3Id,
          data,
          ciphertextCommitment,
          proof,
        ),
      )
        .to.emit(interfold, "CiphertextOutputReferencePublished")
        .withArgs(e3Id, ethers.keccak256(data), ciphertextCommitment, 1, 1);
    });

    it("blocks plaintext publication during ciphertext verification", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
        mocks,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });
      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await mocks.e3Program.setReentrantPlaintextPublication(data, proof);

      await expect(
        publishAvailableCiphertextOutput(
          interfold,
          e3Id,
          data,
          ciphertextCommitment,
          proof,
        ),
      ).to.be.revertedWithCustomError(
        interfold,
        "ReentrancyGuardReentrantCall",
      );
      expect(await interfold.getE3Stage(e3Id)).to.equal(3);
    });
  });

  describe("publishPlaintextOutput()", function () {
    it("reverts if E3 does not exist", async function () {
      const { interfold } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await expect(interfold.publishPlaintextOutput(e3Id, data, "0x"))
        .to.be.revertedWithCustomError(interfold, "E3DoesNotExist")
        .withArgs(e3Id);
    });

    it("reverts if ciphertextOutput has not been published", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await expect(
        interfold.publishPlaintextOutput(e3Id, data, "0x"),
      ).to.be.revertedWithCustomError(interfold, "InvalidStage");
    });
    it("reverts if plaintextOutput has already been published", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await publishAvailableCiphertextOutput(
        interfold,
        e3Id,
        data,
        ciphertextCommitment,
        proof,
      );
      await interfold.publishPlaintextOutput(e3Id, data, proof);
      await expect(
        interfold.publishPlaintextOutput(e3Id, data, proof),
      ).to.be.revertedWithCustomError(interfold, "InvalidStage");
    });
    it("AUD-C02: requires a final decryption proof", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });
      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await publishAvailableCiphertextOutput(
        interfold,
        e3Id,
        data,
        ciphertextCommitment,
        proof,
      );

      await expect(
        interfold.publishPlaintextOutput(e3Id, data, "0x"),
      ).to.be.revertedWithCustomError(interfold, "ProofRequired");
    });
    it("reverts if output is not valid", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });

      const operators = [operator1, operator2, operator3];
      const { proof, bundle } = await buildMockAggregationPublishArgs(
        operators,
        e3Id,
        data,
        await ciphernodeRegistryContract.dkgFoldAttestationVerifier(),
        await ciphernodeRegistryContract.getAddress(),
      );
      await setupAndPublishCommittee(
        ciphernodeRegistryContract,
        e3Id,
        data,
        operators,
        proof,
        bundle,
      );
      await mine(2, { interval: inputWindowDuration });
      await publishAvailableCiphertextOutput(
        interfold,
        e3Id,
        data,
        ciphertextCommitment,
        proof,
      );
      // M-35: decryption verifier now reverts with a typed error instead of
      // returning false, so the call reverts before Interfold's own InvalidOutput
      // wrapping (which now only guards ciphertext output).
      await expect(
        interfold.publishPlaintextOutput(e3Id, data, "0xdeadbeef"),
      ).to.be.revert(ethers);
    });
    it("rejects a false decryption verifier result", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
        mocks,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });
      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await publishAvailableCiphertextOutput(
        interfold,
        e3Id,
        data,
        ciphertextCommitment,
        proof,
      );

      await expect(
        interfold.publishPlaintextOutput(e3Id, data, "0xfafafafa"),
      ).to.be.revertedWithCustomError(mocks.decryptionVerifier, "InvalidProof");
    });
    it("sets plaintextOutput correctly", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await publishAvailableCiphertextOutput(
        interfold,
        e3Id,
        data,
        ciphertextCommitment,
        proof,
      );
      expect(await interfold.publishPlaintextOutput(e3Id, data, proof));

      const e3 = await interfold.getE3(e3Id);
      expect(e3.plaintextOutput).to.equal(data);
    });
    it("returns true if output is published successfully", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await publishAvailableCiphertextOutput(
        interfold,
        e3Id,
        data,
        ciphertextCommitment,
        proof,
      );
      expect(
        await interfold.publishPlaintextOutput.staticCall(e3Id, data, proof),
      ).to.equal(true);
    });
    it("emits PlaintextOutputPublished event", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = firstE3Id;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
      });

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await publishAvailableCiphertextOutput(
        interfold,
        e3Id,
        data,
        ciphertextCommitment,
        proof,
      );
      await expect(await interfold.publishPlaintextOutput(e3Id, data, proof))
        .to.emit(interfold, "PlaintextOutputPublished")
        .withArgs(e3Id, data, proof);
    });
  });
});
