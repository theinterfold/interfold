// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { expect } from "chai";

import type {
  StandardCompilerInput,
  StorageLayout,
  StorageMetadata,
  StorageType,
} from "../../scripts/storageLayouts";
import {
  compilerInputSha256,
  diffLayouts,
  persistedEnumName,
  pnpmPackageKeys,
} from "../../scripts/storageLayouts";

const emptyMetadata = (): StorageMetadata => ({
  enums: {},
  namespaces: {},
});

function layoutWithStructContainer(
  encoding: "dynamic_array" | "mapping",
  structSize: string,
  includeAppendedMember: boolean,
): StorageLayout {
  const container: StorageType =
    encoding === "dynamic_array"
      ? {
          base: "t_struct",
          encoding,
          label: "struct Item[]",
          numberOfBytes: "32",
        }
      : {
          encoding,
          key: "t_address",
          label: "mapping(address => struct Item)",
          numberOfBytes: "32",
          value: "t_struct",
        };
  return {
    storage: [
      {
        astId: 1,
        contract: "Example",
        label: "items",
        offset: 0,
        slot: "0",
        type: "t_container",
      },
    ],
    types: {
      t_address: {
        encoding: "inplace",
        label: "address",
        numberOfBytes: "20",
      },
      t_container: container,
      t_struct: {
        encoding: "inplace",
        label: "struct Item",
        members: [
          {
            astId: 2,
            contract: "Example",
            label: "value",
            offset: 0,
            slot: "0",
            type: "t_uint",
          },
          ...(includeAppendedMember
            ? [
                {
                  astId: 3,
                  contract: "Example",
                  label: "added",
                  offset: 0,
                  slot: "1",
                  type: "t_uint",
                },
              ]
            : []),
        ],
        numberOfBytes: structSize,
      },
      t_uint: {
        encoding: "inplace",
        label: "uint256",
        numberOfBytes: "32",
      },
    },
  };
}

describe("storage layout validation", function () {
  it("rejects dynamic-array element growth", function () {
    const before = layoutWithStructContainer("dynamic_array", "32", false);
    const after = layoutWithStructContainer("dynamic_array", "64", true);

    expect(diffLayouts("Example", before, after)).to.include(
      "Example: items.base dynamic-array element stride changed from 32 to 64 bytes.",
    );
  });

  it("allows a mapping value struct to append a field", function () {
    const before = layoutWithStructContainer("mapping", "32", false);
    const after = layoutWithStructContainer("mapping", "64", true);

    expect(diffLayouts("Example", before, after)).to.deep.equal([]);
  });

  it("rejects persisted enum insertion and reordering", function () {
    const layout: StorageLayout = { storage: [], types: {} };
    const before = emptyMetadata();
    before.enums["Example.Stage"] = ["Requested", "Complete"];
    for (const members of [
      ["Complete", "Requested"],
      ["Requested", "Processing", "Complete"],
    ]) {
      const after = emptyMetadata();
      after.enums["Example.Stage"] = members;
      expect(diffLayouts("Example", layout, layout, before, after)).to.include(
        "Example: persisted enum Example.Stage member order changed.",
      );
    }
  });

  it("allows a persisted enum to append a member", function () {
    const layout: StorageLayout = { storage: [], types: {} };
    const before = emptyMetadata();
    before.enums["Example.Stage"] = ["Requested", "Complete"];
    const after = emptyMetadata();
    after.enums["Example.Stage"] = ["Requested", "Complete", "Failed"];

    expect(diffLayouts("Example", layout, layout, before, after)).to.deep.equal(
      [],
    );
  });

  it("rejects removing a persisted enum member", function () {
    const layout: StorageLayout = { storage: [], types: {} };
    const before = emptyMetadata();
    before.enums["Example.Stage"] = ["Requested", "Complete"];
    const after = emptyMetadata();
    after.enums["Example.Stage"] = ["Requested"];

    expect(diffLayouts("Example", layout, layout, before, after)).to.include(
      "Example: persisted enum Example.Stage member order changed.",
    );
  });

  it("extracts enum definitions without treating array wrappers as enums", function () {
    expect(
      persistedEnumName({
        encoding: "inplace",
        label: "enum Example.Stage",
        numberOfBytes: "1",
      }),
    ).to.equal("Example.Stage");

    for (const type of [
      {
        base: "t_enum",
        encoding: "dynamic_array",
        label: "enum Example.Stage[]",
        numberOfBytes: "32",
      },
      {
        base: "t_enum",
        encoding: "inplace",
        label: "enum Example.Stage[3]",
        numberOfBytes: "32",
      },
    ]) {
      expect(persistedEnumName(type)).to.equal(undefined);
    }
  });

  it("rejects changes to existing namespace members", function () {
    const layout: StorageLayout = { storage: [], types: {} };
    const before = emptyMetadata();
    before.namespaces["erc7201:example.storage.State"] = {
      root: "Example.State",
      types: {
        "Example.State": {
          kind: "struct",
          members: [
            { name: "owner", type: "address" },
            { name: "count", type: "uint256" },
          ],
        },
      },
    };
    const after = structuredClone(before);
    after.namespaces["erc7201:example.storage.State"]!.types[
      "Example.State"
    ]!.members.reverse();

    expect(diffLayouts("Example", layout, layout, before, after)).to.include(
      "Example: storage namespace erc7201:example.storage.State type Example.State member order or type changed.",
    );
  });

  it("fingerprints every source in the compiler input", function () {
    const before: StandardCompilerInput = {
      language: "Solidity",
      settings: {},
      sources: {
        "project/contracts/Example.sol": { content: "contract Example {}" },
        "npm/example@1.0.0/Imported.sol": {
          content: "library Imported {}",
        },
      },
    };
    const after = structuredClone(before);
    after.sources["npm/example@1.0.0/Imported.sol"]!.content =
      "library Imported { uint256 constant X = 1; }";

    expect(compilerInputSha256(before)).not.to.equal(
      compilerInputSha256(after),
    );

    const renamed = structuredClone(before);
    renamed.sources["npm/example@1.0.0/Renamed.sol"] =
      renamed.sources["npm/example@1.0.0/Imported.sol"]!;
    delete renamed.sources["npm/example@1.0.0/Imported.sol"];

    expect(compilerInputSha256(before)).not.to.equal(
      compilerInputSha256(renamed),
    );
  });

  it("matches exact pnpm package keys", function () {
    const packages = pnpmPackageKeys(`
lockfileVersion: '9.0'
packages:
  '@scope/exact@1.2.3': {}
  not-safe-buffer@5.1.2: {}
`);

    expect(packages.has("@scope/exact@1.2.3")).to.equal(true);
    expect(packages.has("not-safe-buffer@5.1.2")).to.equal(true);
    expect(packages.has("safe-buffer@5.1.2")).to.equal(false);
  });
});
