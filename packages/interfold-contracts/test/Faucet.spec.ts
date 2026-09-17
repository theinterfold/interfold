// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { network } from "hardhat";

import {
  Faucet__factory as FaucetFactory,
  MockFeeOnTransferToken__factory as MockFeeTokenFactory,
  MockUSDC__factory as MockUSDCFactory,
} from "../types";

const { ethers } = await network.connect();

describe("Faucet", function () {
  for (const feeDecimals of [6, 18]) {
    it(`funds each token at its ${feeDecimals}-decimal amount`, async function () {
      const [deployer, user] = await ethers.getSigners();
      const fold = await new MockFeeTokenFactory(deployer).deploy(0);
      const fee =
        feeDecimals === 6
          ? await new MockUSDCFactory(deployer).deploy(0)
          : await new MockFeeTokenFactory(deployer).deploy(0);
      const faucet = await new FaucetFactory(deployer).deploy(
        await fold.getAddress(),
        await fee.getAddress(),
      );
      const foldAmount = ethers.parseUnits("200", 18);
      const feeAmount = ethers.parseUnits("200", feeDecimals);
      expect(await faucet.AMOUNT_FOLD()).to.equal(foldAmount);
      expect(await faucet.AMOUNT_FEE_TOKEN()).to.equal(feeAmount);

      await fold.mint(await faucet.getAddress(), 2n * foldAmount);
      await fee.mint(await faucet.getAddress(), 2n * feeAmount);
      await faucet.connect(user).faucet();
      expect(await fold.balanceOf(await user.getAddress())).to.equal(
        foldAmount,
      );
      expect(await fee.balanceOf(await user.getAddress())).to.equal(feeAmount);

      await fee.connect(user).transfer(await deployer.getAddress(), feeAmount);
      await faucet.connect(user).faucet();
      expect(await fold.balanceOf(await user.getAddress())).to.equal(
        foldAmount,
      );
      expect(await fee.balanceOf(await user.getAddress())).to.equal(feeAmount);
    });
  }
});
