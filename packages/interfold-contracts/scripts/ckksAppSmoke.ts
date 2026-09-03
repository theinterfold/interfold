// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Smoke: deploy both three-leg CKKS app programs through
 * `deployAndSaveCkksAppProgram` on the selected network and push each
 * REAL fixture through them (`npx hardhat run scripts/ckksAppSmoke.ts`).
 * Local runs write a `localhost`/`hardhat` entry to deployed_contracts.json
 * like every other deployAndSave script.
 */
import { readFileSync } from "fs";
import hre from "hardhat";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

import {
  CkksAuctionE3Program__factory,
  CkksSalaryE3Program__factory,
} from "../types";
import { deployAndSaveCkksAppProgram } from "./deployAndSave/ckksAppProgram";

interface Leg {
  proof: string;
  publicInputs: string[];
}
interface Fixture {
  ciphertext: string;
  ct0: Leg;
  ct1: Leg;
  app: Leg;
  cap: number;
  extra: Record<string, string | number>;
}

const GAS = 29_000_000;
const fixtures = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "test",
  "fixtures",
);
const load = (name: string): Fixture =>
  JSON.parse(
    readFileSync(join(fixtures, name, "verified_input.json"), "utf-8"),
  ) as Fixture;

async function main() {
  const { ethers } = await hre.network.connect();
  const [signer] = await ethers.getSigners();
  const encode = (f: Fixture) =>
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "bytes",
        "bytes",
        "bytes32[]",
        "bytes",
        "bytes32[]",
        "bytes",
        "bytes32[]",
      ],
      [
        f.ciphertext,
        f.ct0.proof,
        f.ct0.publicInputs,
        f.ct1.proof,
        f.ct1.publicInputs,
        f.app.proof,
        f.app.publicInputs,
      ],
    );

  const salary = load("ckks_salary_ps3");
  const s = await deployAndSaveCkksAppProgram({
    hre,
    app: "salary",
    cap: BigInt(salary.cap),
  });
  const salaryProgram = CkksSalaryE3Program__factory.connect(
    s.programAddress,
    s.ethers.provider,
  );
  const salaryTx = await salaryProgram
    .connect(await s.ethers.provider.getSigner(await signer.getAddress()))
    .publishInput(1n, encode(salary), { gasLimit: GAS });
  await salaryTx.wait();
  console.log(
    `CkksSalaryE3Program ${s.programAddress}: submissions=${await salaryProgram.submissionCount(1n)}`,
  );

  const auction = load("ckks_auction_ps2");
  const a = await deployAndSaveCkksAppProgram({
    hre,
    app: "auction",
    cap: BigInt(auction.cap),
  });
  const owner = await a.ethers.provider.getSigner(await signer.getAddress());
  const auctionProgram = CkksAuctionE3Program__factory.connect(
    a.programAddress,
    owner,
  );
  await (
    await auctionProgram.setBalanceRoot(1n, String(auction.extra.merkleRoot))
  ).wait();
  await (
    await auctionProgram.publishInput(1n, encode(auction), { gasLimit: GAS })
  ).wait();
  console.log(
    `CkksAuctionE3Program ${a.programAddress}: submissions=${await auctionProgram.submissionCount(1n)}`,
  );
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
