// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import path from "path";
import { fileURLToPath } from "url";

import { updateE3Config } from "./utils";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const contractMapping: Record<string, string> = {
  MockE3Program: "e3_program",
  Interfold: "interfold",
  CiphernodeRegistryOwnable: "ciphernode_registry",
  BondingRegistry: "bonding_registry",
  SlashingManager: "slashing_manager",
  MockUSDC: "fee_token",
};

const integrationConfigPath = path.resolve(
  __dirname,
  "../../../tests/integration/interfold.config.yaml",
);

const chain = process.env.HARDHAT_NETWORK ?? "localhost";

updateE3Config(chain, integrationConfigPath, contractMapping);
