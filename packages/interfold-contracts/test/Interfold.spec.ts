// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import {
  ADDRESS_TWO as AddressTwo,
  COMMITTEE_THRESHOLDS_DEFAULT,
  buildMockAggregationPublishArgs,
  deployInterfoldSystem,
  ENCRYPTION_SCHEME_ID as encryptionSchemeId,
  ethers,
  makeRequest,
  networkHelpers,
  setupAndPublishCommittee,
  DEFAULT_TIMEOUT_CONFIG as timeoutConfig,
} from "./fixtures";

const { loadFixture, time, mine } = networkHelpers;

describe("Interfold", function () {
  const newEncryptionSchemeId =
    "0x0000000000000000000000000000000000000000000000000000000000000002";

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  const polynomial_degree = ethers.toBigInt(512);
  const plaintext_modulus = ethers.toBigInt(10);
  const moduli = [
    ethers.toBigInt("0xffffee001"),
    ethers.toBigInt("0xffffc4001"),
  ];

  const encodedE3ProgramParams = abiCoder.encode(
    ["uint256", "uint256", "uint256[]"],
    [polynomial_degree, plaintext_modulus, moduli],
  );

  const data = "0xda7a";
  const proof = "0x1337";

  const inputWindowDuration = 300;

  const setup = async () => {
    const sys = await deployInterfoldSystem({ wireSlashingManager: false });
    const dkgFoldAttestationVerifier = await ethers.deployContract(
      "DkgFoldAttestationVerifier",
    );
    await sys.ciphernodeRegistry.setInitialDkgFoldAttestationVerifier(
      await dkgFoldAttestationVerifier.getAddress(),
    );
    return {
      owner: sys.owner,
      notTheOwner: sys.notTheOwner,
      operator1: sys.operator1!,
      operator2: sys.operator2!,
      operator3: sys.operator3!,
      interfold: sys.interfold,
      ciphernodeRegistryContract: sys.ciphernodeRegistry,
      bondingRegistry: sys.bondingRegistry,
      licenseToken: sys.licenseToken,
      ticketToken: sys.ticketToken,
      usdcToken: sys.usdcToken,
      slashingManager: sys.slashingManager,
      dkgFoldAttestationVerifier,
      request: sys.request,
      mocks: {
        decryptionVerifier: sys.mocks.decryptionVerifier,
        e3Program: sys.mocks.e3Program,
        mockComputeProvider: sys.mocks.mockComputeProvider,
      },
    };
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
      const { interfold } = await loadFixture(setup);

      expect(await interfold.ciphernodeRegistry()).to.not.equal(AddressTwo);
      await interfold.setCiphernodeRegistry(AddressTwo);
      expect(await interfold.ciphernodeRegistry()).to.equal(AddressTwo);
    });

    it("emits CiphernodeRegistrySet event", async function () {
      const { interfold } = await loadFixture(setup);

      await expect(interfold.setCiphernodeRegistry(AddressTwo))
        .to.emit(interfold, "CiphernodeRegistrySet")
        .withArgs(AddressTwo);
    });
  });

  describe("setParamSet()", function () {
    it("reverts if not called by owner", async function () {
      const { interfold, notTheOwner } = await loadFixture(setup);

      await expect(
        interfold.connect(notTheOwner).setParamSet(0, encodedE3ProgramParams),
      )
        .to.be.revertedWithCustomError(interfold, "OwnableUnauthorizedAccount")
        .withArgs(notTheOwner);
    });

    it("registers param set and emits event", async function () {
      const { interfold } = await loadFixture(setup);

      await expect(interfold.setParamSet(1, encodedE3ProgramParams))
        .to.emit(interfold, "ParamSetRegistered")
        .withArgs(1, encodedE3ProgramParams);

      expect(await interfold.paramSetRegistry(1)).to.equal(
        encodedE3ProgramParams,
      );
    });

    it("reverts with empty params", async function () {
      const { interfold } = await loadFixture(setup);

      // `debug.revertStrings: "strip"` is enabled in hardhat.config.ts to
      // keep `Interfold` under the EIP-170 24,576-byte runtime cap, so the
      // original "Empty params" reason string is removed from bytecode.
      // Behaviour (revert) is preserved.
      await expect(interfold.setParamSet(0, "0x")).to.be.revertedWithoutReason(
        ethers,
      );
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
        proofAggregationEnabled: false,
      });

      const e3 = await interfold.getE3(0);

      expect(e3.committeeSize).to.equal(request.committeeSize);
      expect(e3.inputWindow[0]).to.equal(request.inputWindow[0]);
      expect(e3.inputWindow[1]).to.equal(request.inputWindow[1]);
      expect(e3.e3Program).to.equal(request.e3Program);
      expect(e3.paramSet).to.equal(request.paramSet);
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

  describe("disableEncryptionScheme()", function () {
    it("reverts if caller is not owner", async function () {
      const { interfold, notTheOwner } = await loadFixture(setup);

      await expect(
        interfold
          .connect(notTheOwner)
          .disableEncryptionScheme(encryptionSchemeId),
      )
        .to.be.revertedWithCustomError(interfold, "OwnableUnauthorizedAccount")
        .withArgs(notTheOwner);
    });
    it("reverts if encryption scheme is not already enabled", async function () {
      const { interfold } = await loadFixture(setup);

      await expect(interfold.disableEncryptionScheme(newEncryptionSchemeId))
        .to.be.revertedWithCustomError(interfold, "InvalidEncryptionScheme")
        .withArgs(newEncryptionSchemeId);
    });
    it("disables encryption scheme", async function () {
      const { interfold } = await loadFixture(setup);

      expect(await interfold.disableEncryptionScheme(encryptionSchemeId));
      expect(
        await interfold.getDecryptionVerifier(encryptionSchemeId),
      ).to.equal(ethers.ZeroAddress);
    });
    it("emits EncryptionSchemeDisabled", async function () {
      const { interfold } = await loadFixture(setup);

      await expect(await interfold.disableEncryptionScheme(encryptionSchemeId))
        .to.emit(interfold, "EncryptionSchemeDisabled")
        .withArgs(encryptionSchemeId);
    });
  });

  describe("registerE3Program()", function () {
    it("reverts if E3 Program is already registered", async function () {
      const {
        interfold,
        mocks: { e3Program },
      } = await loadFixture(setup);
      await expect(interfold.registerE3Program(e3Program))
        .to.be.revertedWithCustomError(interfold, "ModuleAlreadyEnabled")
        .withArgs(e3Program);
    });
    it("registers E3 Program correctly", async function () {
      const { interfold } = await loadFixture(setup);
      await interfold.registerE3Program(AddressTwo);
      expect(await interfold.e3Programs(AddressTwo)).to.be.true;
    });
    it("emits E3ProgramRegistered event", async function () {
      const { interfold } = await loadFixture(setup);
      await expect(interfold.registerE3Program(AddressTwo))
        .to.emit(interfold, "E3ProgramRegistered")
        .withArgs(AddressTwo);
    });
  });

  describe("request()", function () {
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
          proofAggregationEnabled: false,
        }),
      ).to.be.revertedWithCustomError(usdcToken, "ERC20InsufficientAllowance");
    });
    it("reverts if committee size is not configured", async function () {
      const { interfold, request } = await loadFixture(setup);
      const configuredSizes = COMMITTEE_THRESHOLDS_DEFAULT.map(
        ([size]) => size,
      );
      const unconfiguredCommitteeSize = configuredSizes.length;
      expect(unconfiguredCommitteeSize).to.equal(3);
      const unconfiguredParams = {
        committeeSize: unconfiguredCommitteeSize,
        inputWindow: request.inputWindow,
        e3Program: request.e3Program,
        paramSet: request.paramSet,
        computeProviderParams: request.computeProviderParams,
        customParams: request.customParams,
        proofAggregationEnabled: false,
      };
      // `CommitteeSizeNotConfigured(3)` reverts correctly on-chain; ethers cannot
      // decode the custom error when the enum arg is not a named variant (0..2).
      await expect(
        interfold.getE3Quote.staticCall(unconfiguredParams),
      ).to.be.revert(ethers);
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
          proofAggregationEnabled: false,
        }),
      ).to.be.revertedWithCustomError(interfold, "InvalidDuration");
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
          proofAggregationEnabled: false,
        }),
      )
        .to.be.revertedWithCustomError(interfold, "E3ProgramNotAllowed")
        .withArgs(ethers.ZeroAddress);
    });
    it("reverts if given encryption scheme is not enabled", async function () {
      const { interfold, request, usdcToken } = await loadFixture(setup);
      await interfold.disableEncryptionScheme(encryptionSchemeId);
      await expect(
        makeRequest(interfold, usdcToken, {
          committeeSize: request.committeeSize,
          inputWindow: request.inputWindow,
          e3Program: request.e3Program,
          paramSet: request.paramSet,
          computeProviderParams: request.computeProviderParams,
          customParams: request.customParams,
          proofAggregationEnabled: false,
        }),
      )
        .to.be.revertedWithCustomError(interfold, "InvalidEncryptionScheme")
        .withArgs(encryptionSchemeId);
    });
    it("instantiates a new E3", async function () {
      const { interfold, request, usdcToken } = await loadFixture(setup);

      await makeRequest(interfold, usdcToken, {
        committeeSize: request.committeeSize,
        inputWindow: request.inputWindow,
        e3Program: request.e3Program,
        paramSet: request.paramSet,
        computeProviderParams: request.computeProviderParams,
        customParams: request.customParams,
        proofAggregationEnabled: false,
      });

      const e3 = await interfold.getE3(0);
      const block = await ethers.provider.getBlock("latest").catch((e) => e);

      expect(e3.committeeSize).to.equal(request.committeeSize);
      expect(e3.inputWindow[0]).to.equal(request.inputWindow[0]);
      expect(e3.inputWindow[1]).to.equal(request.inputWindow[1]);
      expect(e3.e3Program).to.equal(request.e3Program);
      // H-26: `requestBlock` now stores `block.timestamp` (a stable EIP-6372
      // clock) instead of `block.number`, so the snapshot agrees with the
      // bonding registry / token checkpoints across L2s with variable block
      // production.
      expect(e3.requestBlock).to.equal(block.timestamp);
      expect(e3.decryptionVerifier).to.equal(
        abiCoder.decode(["address"], request.computeProviderParams)[0],
      );
      expect(e3.committeePublicKey).to.equal(ethers.ZeroHash);
      expect(e3.ciphertextOutput).to.equal(ethers.ZeroHash);
      expect(e3.plaintextOutput).to.equal("0x");
    });
    it("emits E3Requested event", async function () {
      const { interfold, request, usdcToken } = await loadFixture(setup);
      const tx = await makeRequest(interfold, usdcToken, {
        committeeSize: request.committeeSize,
        inputWindow: request.inputWindow,
        e3Program: request.e3Program,
        paramSet: request.paramSet,
        computeProviderParams: request.computeProviderParams,
        customParams: request.customParams,
        proofAggregationEnabled: false,
      });
      const e3 = await interfold.getE3(0);

      await expect(tx)
        .to.emit(interfold, "E3Requested")
        .withArgs(0, e3, request.e3Program);
    });
  });

  describe("publishCiphertextOutput()", function () {
    it("reverts if E3 does not exist", async function () {
      const { interfold } = await loadFixture(setup);

      await expect(interfold.publishCiphertextOutput(0, "0x", "0x"))
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
      const e3Id = 0;

      await makeRequest(interfold, usdcToken, {
        committeeSize: request.committeeSize,
        inputWindow: request.inputWindow,
        e3Program: request.e3Program,
        paramSet: request.paramSet,
        computeProviderParams: request.computeProviderParams,
        customParams: request.customParams,
        proofAggregationEnabled: false,
      });

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });

      await interfold.publishCiphertextOutput(e3Id, data, proof);
      await expect(interfold.publishCiphertextOutput(e3Id, data, proof))
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
      const e3Id = 0;

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
        interfold.publishCiphertextOutput(e3Id, data, proof),
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
      const e3Id = 0;

      await makeRequest(interfold, usdcToken, {
        committeeSize: request.committeeSize,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
        e3Program: request.e3Program,
        paramSet: request.paramSet,
        computeProviderParams: request.computeProviderParams,
        customParams: request.customParams,
        proofAggregationEnabled: false,
      });

      await setupAndPublishCommittee(ciphernodeRegistryContract, e3Id, data, [
        operator1,
        operator2,
        operator3,
      ]);
      await mine(2, { interval: inputWindowDuration });
      await expect(
        interfold.publishCiphertextOutput(e3Id, "0x", "0x"),
      ).to.be.revertedWithCustomError(interfold, "InvalidOutput");
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
      } = await loadFixture(setup);
      const e3Id = 0;

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
      expect(await interfold.publishCiphertextOutput(e3Id, data, proof));
      const e3 = await interfold.getE3(e3Id);
      expect(e3.ciphertextOutput).to.equal(ethers.keccak256(data));
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
      const e3Id = 0;

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
      expect(
        await interfold.publishCiphertextOutput.staticCall(e3Id, data, proof),
      ).to.equal(true);
    });
    it("emits CiphertextOutputPublished event", async function () {
      const {
        interfold,
        request,
        usdcToken,
        ciphernodeRegistryContract,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = 0;

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
      await expect(interfold.publishCiphertextOutput(e3Id, data, proof))
        .to.emit(interfold, "CiphertextOutputPublished")
        .withArgs(e3Id, data);
    });
  });

  describe("publishPlaintextOutput()", function () {
    it("reverts if E3 does not exist", async function () {
      const { interfold } = await loadFixture(setup);
      const e3Id = 0;

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
      const e3Id = 0;

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
      const e3Id = 0;

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
      await interfold.publishCiphertextOutput(e3Id, data, proof);
      await interfold.publishPlaintextOutput(e3Id, data, proof);
      await expect(
        interfold.publishPlaintextOutput(e3Id, data, proof),
      ).to.be.revertedWithCustomError(interfold, "InvalidStage");
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
        dkgFoldAttestationVerifier,
      } = await loadFixture(setup);
      const e3Id = 0;

      await makeRequest(interfold, usdcToken, {
        ...request,
        inputWindow: [(await time.latest()) + 20, (await time.latest()) + 100],
        proofAggregationEnabled: true,
      });

      const operators = [operator1, operator2, operator3];
      const { proof, bundle } = await buildMockAggregationPublishArgs(
        operators,
        e3Id,
        data,
        await dkgFoldAttestationVerifier.getAddress(),
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
      await interfold.publishCiphertextOutput(e3Id, data, proof);
      // M-35: decryption verifier now reverts with a typed error instead of
      // returning false, so the call reverts before Interfold's own InvalidOutput
      // wrapping (which now only guards ciphertext output).
      await expect(
        interfold.publishPlaintextOutput(e3Id, data, "0xdeadbeef"),
      ).to.be.revert(ethers);
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
      const e3Id = 0;

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
      await interfold.publishCiphertextOutput(e3Id, data, proof);
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
      const e3Id = 0;

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
      await interfold.publishCiphertextOutput(e3Id, data, proof);
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
      const e3Id = 0;

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
      await interfold.publishCiphertextOutput(e3Id, data, proof);
      await expect(await interfold.publishPlaintextOutput(e3Id, data, proof))
        .to.emit(interfold, "PlaintextOutputPublished")
        .withArgs(e3Id, data, proof);
    });
  });
});
