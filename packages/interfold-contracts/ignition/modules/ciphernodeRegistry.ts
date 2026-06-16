// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("CiphernodeRegistry", (m) => {
  const owner = m.getParameter("owner");
  const submissionWindow = m.getParameter("submissionWindow");

  const poseidonT3 = m.library("PoseidonT3");

  const cipherNodeRegistryImpl = m.contract("CiphernodeRegistryOwnable", [], {
    libraries: {
      PoseidonT3: poseidonT3,
    },
  });

  const initData = m.encodeFunctionCall(cipherNodeRegistryImpl, "initialize", [
    owner,
    submissionWindow,
  ]);

  const cipherNodeRegistry = m.contract("TransparentUpgradeableProxy", [
    cipherNodeRegistryImpl,
    owner,
    initData,
  ]);

  return { cipherNodeRegistry };
}) as any;
