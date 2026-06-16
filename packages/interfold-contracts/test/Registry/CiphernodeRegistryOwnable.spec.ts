// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import type { Signer } from "ethers";

import { CiphernodeRegistryOwnable__factory as CiphernodeRegistryFactory } from "../../types";
import {
  ADDRESS_ONE as AddressOne,
  ADDRESS_TWO as AddressTwo,
  deployInterfoldSystem,
  ethers,
  networkHelpers,
} from "../fixtures";

const { loadFixture } = networkHelpers;

const data = "0xda7a";
const dataHash = ethers.id(data);
const SORTITION_SUBMISSION_WINDOW = 3;

describe("CiphernodeRegistryOwnable", function () {
  async function finalizeCommitteeAfterWindow(
    registry: any,
    e3Id: number,
  ): Promise<void> {
    await networkHelpers.time.increase(SORTITION_SUBMISSION_WINDOW + 1);
    await registry.finalizeCommittee(e3Id);
  }

  async function setup() {
    const sys = await deployInterfoldSystem({
      submissionWindow: SORTITION_SUBMISSION_WINDOW,
      bfvParams: "large",
      committeeThresholds: [[0, [1, 3]]],
    });
    return {
      owner: sys.owner,
      notTheOwner: sys.notTheOwner,
      operator1: sys.operator1!,
      operator2: sys.operator2!,
      operator3: sys.operator3!,
      registry: sys.ciphernodeRegistry,
      interfold: sys.interfold,
      bondingRegistry: sys.bondingRegistry,
      licenseToken: sys.licenseToken,
      ticketToken: sys.ticketToken,
      usdcToken: sys.usdcToken,
      mockE3Program: sys.mocks.e3Program,
      mockDecryptionVerifier: sys.mocks.decryptionVerifier,
    };
  }

  // Helper to make a request through the Interfold contract
  async function makeRequest(
    interfold: any,
    usdcToken: any,
    mockE3Program: any,
    mockDecryptionVerifier: any,
    signer?: Signer,
  ) {
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();

    const currentTime = await networkHelpers.time.latest();
    const requestParams = {
      committeeSize: 0,
      inputWindow: [currentTime + 100, currentTime + 300] as [number, number],
      e3Program: await mockE3Program.getAddress(),
      paramSet: 0,
      computeProviderParams: abiCoder.encode(
        ["address"],
        [await mockDecryptionVerifier.getAddress()],
      ),
      customParams: abiCoder.encode(
        ["address"],
        ["0x1234567890123456789012345678901234567890"],
      ),
      proofAggregationEnabled: false,
    };

    const fee = await interfold.getE3Quote(requestParams);
    const tokenContract = signer ? usdcToken.connect(signer) : usdcToken;
    const interfoldContract = signer ? interfold.connect(signer) : interfold;

    await tokenContract.approve(await interfold.getAddress(), fee);
    return interfoldContract.request(requestParams);
  }

  describe("constructor / initialize()", function () {
    it("correctly sets `_owner` and `interfold` ", async function () {
      const poseidonFactory = await ethers.getContractFactory("PoseidonT3");
      const poseidonDeployment = await poseidonFactory.deploy();
      await poseidonDeployment.waitForDeployment();
      const poseidonAddress = await poseidonDeployment.getAddress();
      const [deployer] = await ethers.getSigners();
      if (!deployer) throw new Error("Bad getSigners() output");

      const ciphernodeRegistryFactory = await ethers.getContractFactory(
        "CiphernodeRegistryOwnable",
        {
          libraries: {
            PoseidonT3: poseidonAddress,
          },
        },
      );
      const implementation = await ciphernodeRegistryFactory.deploy();
      await implementation.waitForDeployment();
      const implementationAddress = await implementation.getAddress();

      const initData = ciphernodeRegistryFactory.interface.encodeFunctionData(
        "initialize",
        [deployer.address, SORTITION_SUBMISSION_WINDOW],
      );

      const proxyFactory = await ethers.getContractFactory(
        "TransparentUpgradeableProxy",
      );
      const proxy = await proxyFactory.deploy(
        implementationAddress,
        deployer.address,
        initData,
      );
      await proxy.waitForDeployment();
      const proxyAddress = await proxy.getAddress();

      const ciphernodeRegistry = CiphernodeRegistryFactory.connect(
        proxyAddress,
        deployer,
      );

      expect(await ciphernodeRegistry.owner()).to.equal(deployer.address);
      expect(await ciphernodeRegistry.sortitionSubmissionWindow()).to.equal(
        SORTITION_SUBMISSION_WINDOW,
      );
    });
  });

  describe("requestCommittee()", function () {
    it("stores rootAt for the requested e3Id after a successful request", async function () {
      const {
        registry,
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      } = await loadFixture(setup);
      // Request through Interfold
      await makeRequest(
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      );
      expect(await registry.rootAt(0)).to.equal(await registry.root());
    });
    it("stores the root of the ciphernode registry at the time of the request", async function () {
      const {
        registry,
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      } = await loadFixture(setup);
      await makeRequest(
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      );
      expect(await registry.rootAt(0)).to.equal(await registry.root());
    });
    it("emits a CommitteeRequested event", async function () {
      const {
        registry,
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      } = await loadFixture(setup);

      const tx = await makeRequest(
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      );

      // Should emit CommitteeRequested from registry
      await expect(tx).to.emit(registry, "CommitteeRequested");
    });
    it("returns true if the request is successful", async function () {
      const {
        registry,
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      } = await loadFixture(setup);
      // We can verify by checking that root is stored after request
      await makeRequest(
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      );
      expect(await registry.rootAt(0)).to.not.equal(0);
    });
  });

  describe("publishCommittee()", function () {
    it("allows any caller to publish a finalized committee", async function () {
      const {
        registry,
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
        notTheOwner,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      await makeRequest(
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      );

      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await finalizeCommitteeAfterWindow(registry, 0);

      await expect(
        registry
          .connect(notTheOwner)
          .publishCommittee(0, data, dataHash, "0x", "0x"),
      )
        .to.emit(registry, "CommitteePublished")
        .withArgs(
          0,
          [
            await operator3.getAddress(),
            await operator1.getAddress(),
            await operator2.getAddress(),
          ],
          data,
          dataHash,
          "0x",
        );
    });
    it("stores the public key of the committee", async function () {
      const {
        registry,
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      await makeRequest(
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      );

      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await finalizeCommitteeAfterWindow(registry, 0);

      await registry.publishCommittee(0, data, dataHash, "0x", "0x");
      expect(await registry.committeePublicKey(0)).to.equal(dataHash);
    });
    it("emits a CommitteePublished event", async function () {
      const {
        registry,
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      await makeRequest(
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      );

      // Submit tickets from all operators and finalize
      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await finalizeCommitteeAfterWindow(registry, 0);

      await expect(
        await registry.publishCommittee(0, data, dataHash, "0x", "0x"),
      )
        .to.emit(registry, "CommitteePublished")
        .withArgs(
          0,
          [
            await operator3.getAddress(),
            await operator1.getAddress(),
            await operator2.getAddress(),
          ],
          data,
          dataHash,
          "0x",
        );
    });
  });

  describe("getActiveCommitteeNodes()", function () {
    it("returns active committee nodes with their scores", async function () {
      const {
        registry,
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      await makeRequest(
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      );

      await registry.connect(operator1).submitTicket(0, 1);
      await registry.connect(operator2).submitTicket(0, 1);
      await registry.connect(operator3).submitTicket(0, 1);
      await finalizeCommitteeAfterWindow(registry, 0);

      const finalizedEvents = await registry.queryFilter(
        registry.filters.SortitionCommitteeFinalized(0),
      );
      expect(finalizedEvents.length).to.equal(1);

      const finalizedEvent = finalizedEvents[0];
      const [activeNodes, activeScores] =
        await registry.getActiveCommitteeNodes(0);

      expect(activeNodes).to.deep.equal(finalizedEvent.args.committee);
      expect(activeScores).to.deep.equal(finalizedEvent.args.scores);
    });
  });

  describe("addCiphernode()", function () {
    it("reverts if the caller is not the owner", async function () {
      const { registry, notTheOwner } = await loadFixture(setup);
      await expect(
        registry.connect(notTheOwner).addCiphernode(AddressTwo),
      ).to.be.revertedWithCustomError(registry, "NotOwnerOrBondingRegistry");
    });
    it("adds the ciphernode to the registry", async function () {
      const { registry } = await loadFixture(setup);
      expect(await registry.addCiphernode(AddressTwo));
      expect(await registry.isEnabled(AddressTwo)).to.be.true;
    });
    it("increments numCiphernodes", async function () {
      const { registry } = await loadFixture(setup);
      const numCiphernodes = await registry.numCiphernodes();
      expect(await registry.addCiphernode(AddressTwo));
      expect(await registry.numCiphernodes()).to.equal(
        numCiphernodes + BigInt(1),
      );
    });
    it("emits a CiphernodeAdded event", async function () {
      const { registry } = await loadFixture(setup);
      const treeSize = await registry.treeSize();
      const numCiphernodes = await registry.numCiphernodes();
      await expect(await registry.addCiphernode(AddressTwo))
        .to.emit(registry, "CiphernodeAdded")
        .withArgs(
          AddressTwo,
          treeSize,
          numCiphernodes + BigInt(1),
          treeSize + BigInt(1),
        );
    });
  });

  describe("removeCiphernode()", function () {
    it("reverts if the caller is not the owner", async function () {
      const { registry, notTheOwner } = await loadFixture(setup);
      await expect(
        registry.connect(notTheOwner).removeCiphernode(AddressOne),
      ).to.be.revertedWithCustomError(registry, "NotOwnerOrBondingRegistry");
    });
    it("removes the ciphernode from the registry", async function () {
      const { registry, operator1 } = await loadFixture(setup);
      const operator1Address = await operator1.getAddress();
      const rootBefore = await registry.root();
      expect(await registry.isEnabled(operator1Address)).to.be.true;
      await registry.removeCiphernode(operator1Address);
      expect(await registry.isEnabled(operator1Address)).to.be.false;
      expect(await registry.root()).to.not.equal(rootBefore);
    });
    it("decrements numCiphernodes", async function () {
      const { registry, operator1 } = await loadFixture(setup);
      const operator1Address = await operator1.getAddress();
      const numCiphernodes = await registry.numCiphernodes();
      await registry.removeCiphernode(operator1Address);
      expect(await registry.numCiphernodes()).to.equal(
        numCiphernodes - BigInt(1),
      );
    });
    it("emits a CiphernodeRemoved event", async function () {
      const { registry, operator1 } = await loadFixture(setup);
      const operator1Address = await operator1.getAddress();
      const numCiphernodes = await registry.numCiphernodes();
      const size = await registry.treeSize();
      const index = await registry.ciphernodeTreeIndex(operator1Address);
      await expect(registry.removeCiphernode(operator1Address))
        .to.emit(registry, "CiphernodeRemoved")
        .withArgs(operator1Address, index, numCiphernodes - BigInt(1), size);
    });
  });

  describe("setInterfold()", function () {
    it("reverts if the caller is not the owner", async function () {
      const { registry, notTheOwner } = await loadFixture(setup);
      await expect(
        registry.connect(notTheOwner).setInterfold(AddressTwo),
      ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });
    it("sets the interfold address", async function () {
      const { registry } = await loadFixture(setup);
      expect(await registry.setInterfold(AddressTwo));
      expect(await registry.interfold()).to.equal(AddressTwo);
    });
    it("emits an InterfoldSet event", async function () {
      const { registry } = await loadFixture(setup);
      await expect(await registry.setInterfold(AddressTwo))
        .to.emit(registry, "InterfoldSet")
        .withArgs(AddressTwo);
    });
  });

  describe("committeePublicKey()", function () {
    it("returns the public key of the committee for the given e3Id", async function () {
      const {
        registry,
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
        operator1,
        operator2,
        operator3,
      } = await loadFixture(setup);
      const e3Id = 0;
      await makeRequest(
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      );

      await registry.connect(operator1).submitTicket(e3Id, 1);
      await registry.connect(operator2).submitTicket(e3Id, 1);
      await registry.connect(operator3).submitTicket(e3Id, 1);
      await finalizeCommitteeAfterWindow(registry, e3Id);

      await registry.publishCommittee(e3Id, data, dataHash, "0x", "0x");
      expect(await registry.committeePublicKey(e3Id)).to.equal(dataHash);
    });
    it("reverts if the committee has not been published", async function () {
      const {
        registry,
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      } = await loadFixture(setup);
      const e3Id = 0;
      await makeRequest(
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      );
      await expect(
        registry.committeePublicKey(e3Id),
      ).to.be.revertedWithCustomError(registry, "CommitteeNotPublished");
    });
  });

  describe("isCiphernodeEligible()", function () {
    it("returns true if the ciphernode is in the registry", async function () {
      const { registry, operator1 } = await loadFixture(setup);
      expect(await registry.isEnabled(await operator1.getAddress())).to.be.true;
    });
    it("returns false if the ciphernode is not in the registry", async function () {
      const { registry } = await loadFixture(setup);
      expect(await registry.isCiphernodeEligible(AddressTwo)).to.be.false;
    });
  });

  describe("isEnabled()", function () {
    it("returns true if the ciphernode is currently enabled", async function () {
      const { registry, operator1 } = await loadFixture(setup);
      expect(await registry.isEnabled(await operator1.getAddress())).to.be.true;
    });
    it("returns false if the ciphernode is not currently enabled", async function () {
      const { registry } = await loadFixture(setup);
      expect(await registry.isEnabled(AddressTwo)).to.be.false;
    });
  });

  describe("root()", function () {
    it("returns a non-zero root when ciphernodes are registered", async function () {
      const { registry } = await loadFixture(setup);
      expect(await registry.root()).to.not.equal(0);
    });
  });

  describe("rootAt()", function () {
    it("returns the root of the ciphernode registry merkle tree at the given e3Id", async function () {
      const {
        registry,
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      } = await loadFixture(setup);
      const e3Id = 0;
      const rootBeforeRequest = await registry.root();
      await makeRequest(
        interfold,
        usdcToken,
        mockE3Program,
        mockDecryptionVerifier,
      );
      expect(await registry.rootAt(e3Id)).to.equal(rootBeforeRequest);
    });
  });

  describe("treeSize()", function () {
    it("returns the size of the ciphernode registry merkle tree", async function () {
      const { registry } = await loadFixture(setup);
      // Three operators registered in setup
      expect(await registry.treeSize()).to.equal(3);
    });
  });
});
