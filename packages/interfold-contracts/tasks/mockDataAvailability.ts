// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
import { getBytes, isHexString, keccak256 } from "ethers";
import fs from "fs";
import path from "path";

/** Store an object for the local HTTP data-availability fixture. */
export function stageMockDataAvailabilityObject(
  directory: string,
  object: string,
): string {
  if (!directory) {
    throw new Error("The mock data-availability directory is empty");
  }
  if (!isHexString(object) || object === "0x") {
    throw new Error(
      "The mock data-availability object must be non-empty hex bytes",
    );
  }

  const bytes = Buffer.from(getBytes(object));
  const contentHash = keccak256(bytes);
  const objectDirectory = path.resolve(directory);
  const objectPath = path.join(
    objectDirectory,
    contentHash.slice(2).toLowerCase(),
  );

  fs.mkdirSync(objectDirectory, { recursive: true });
  if (fs.existsSync(objectPath)) {
    const existing = fs.readFileSync(objectPath);
    if (!existing.equals(bytes)) {
      throw new Error(`The stored mock object does not match ${contentHash}`);
    }
    return contentHash;
  }

  const temporaryPath = `${objectPath}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(temporaryPath, bytes, { flag: "wx" });
    fs.renameSync(temporaryPath, objectPath);
  } finally {
    fs.rmSync(temporaryPath, { force: true });
  }

  return contentHash;
}
