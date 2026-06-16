// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import hre from "hardhat";

import { configureLocalSlashingPolicies } from "./configureLocalSlashingPolicies";

configureLocalSlashingPolicies(hre).catch((error) => {
  console.error(error);
  process.exit(1);
});
