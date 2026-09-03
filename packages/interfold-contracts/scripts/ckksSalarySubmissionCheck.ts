// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Offline check for a browser/Node-produced `submission.json` (the
 * examples/ckks-salary-survey SDK output): deploy a fresh
 * `CkksSalaryE3Program` on the in-process hardhat network and push the
 * submission through `publishInput`; then replay it and expect
 * `DuplicateSubmission`.
 *
 *   SUBMISSION=/tmp/sub.json npx hardhat run scripts/ckksSalarySubmissionCheck.ts
 */
import { readFileSync } from "fs";
import hre from "hardhat";

import { CkksSalaryE3Program__factory } from "../types";
import { deployAndSaveCkksAppProgram } from "./deployAndSave/ckksAppProgram";

interface Leg {
  proofHex: string;
  publicInputs: string[];
}
interface Submission {
  ciphertextHex: string;
  ct0: Leg;
  ct1: Leg;
  appLeg: Leg;
}

async function main() {
  const file = process.env.SUBMISSION;
  if (!file) throw new Error("set SUBMISSION=<path to submission.json>");
  const sub = JSON.parse(readFileSync(file, "utf-8")) as Submission;
  const cap = BigInt(sub.appLeg.publicInputs[0]);

  const { ethers, programAddress } = await deployAndSaveCkksAppProgram({
    hre,
    app: "salary",
    cap,
  });
  const [signer] = await ethers.getSigners();
  const program = CkksSalaryE3Program__factory.connect(programAddress, signer);
  const data = ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes", "bytes", "bytes32[]", "bytes", "bytes32[]", "bytes", "bytes32[]"],
    [
      sub.ciphertextHex,
      sub.ct0.proofHex,
      sub.ct0.publicInputs,
      sub.ct1.proofHex,
      sub.ct1.publicInputs,
      sub.appLeg.proofHex,
      sub.appLeg.publicInputs,
    ],
  );
  const tx = await program.publishInput(7n, data, { gasLimit: 29_000_000 });
  const receipt = await tx.wait();
  console.log(
    `ACCEPTED gas=${receipt?.gasUsed} submissions=${await program.submissionCount(7n)}`,
  );
  try {
    await program.publishInput.staticCall(7n, data, { gasLimit: 29_000_000 });
    throw new Error("replay was NOT rejected");
  } catch (e) {
    const msg = String(e);
    if (!msg.includes("DuplicateSubmission")) throw e;
    console.log("REPLAY REJECTED: DuplicateSubmission");
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
