// SPDX-License-Identifier: LGPL-3.0-only
import poseidon from "poseidon-solidity";

export async function ensurePoseidonT3(ethers: any): Promise<string> {
  if ((await ethers.provider.getCode(poseidon.proxy.address)) === "0x") {
    const [sender] = await ethers.getSigners();
    await (
      await sender.sendTransaction({
        to: poseidon.proxy.from,
        value: poseidon.proxy.gas,
      })
    ).wait();
    await (
      await ethers.provider.broadcastTransaction(poseidon.proxy.tx)
    ).wait();
  }

  if ((await ethers.provider.getCode(poseidon.PoseidonT3.address)) === "0x") {
    const [sender] = await ethers.getSigners();
    await (
      await sender.sendTransaction({
        to: poseidon.proxy.address,
        data: poseidon.PoseidonT3.data,
      })
    ).wait();
  }

  return poseidon.PoseidonT3.address;
}
