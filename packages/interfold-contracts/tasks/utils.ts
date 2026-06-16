// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { task } from "hardhat/config";
import { ArgumentType } from "hardhat/types/arguments";

import { cleanLocalDeployments } from "../scripts/utils";

export const cleanDeploymentsTask = task(
  "utils:clean-deployments",
  "Clean deployments for a given network",
)
  .addOption({
    name: "chain",
    description: "network to clean deployments for",
    defaultValue: "localhost",
    type: ArgumentType.STRING,
  })
  .setAction(async () => ({
    default: ({ chain }) => {
      cleanLocalDeployments(chain);
    },
  }))
  .build();
