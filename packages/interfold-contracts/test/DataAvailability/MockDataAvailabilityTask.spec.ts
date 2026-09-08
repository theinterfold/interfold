// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";
import { keccak256 } from "ethers";
import fs from "fs";
import os from "os";
import path from "path";

import { stageMockDataAvailabilityObject } from "../../tasks/mockDataAvailability";

describe("mock data-availability task", function () {
  let directory: string;

  beforeEach(function () {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "interfold-mock-da-"));
  });

  afterEach(function () {
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("stores exact bytes under their content hash", function () {
    const object = "0x01020304";
    const contentHash = stageMockDataAvailabilityObject(directory, object);
    const stored = fs.readFileSync(
      path.join(directory, contentHash.slice(2).toLowerCase()),
    );

    expect(contentHash).to.equal(keccak256(object));
    expect(stored.toString("hex")).to.equal(object.slice(2));
  });

  it("accepts an identical retry", function () {
    const object = "0xaabbccdd";
    const first = stageMockDataAvailabilityObject(directory, object);
    const second = stageMockDataAvailabilityObject(directory, object);

    expect(second).to.equal(first);
  });

  it("rejects an empty object", function () {
    expect(() => stageMockDataAvailabilityObject(directory, "0x")).to.throw(
      "must be non-empty hex bytes",
    );
  });
});
