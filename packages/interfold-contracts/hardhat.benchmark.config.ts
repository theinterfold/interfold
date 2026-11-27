// SPDX-License-Identifier: LGPL-3.0-only
import type { HardhatUserConfig } from "hardhat/config";

import config from "./hardhat.config";

const url = new URL(process.env.E3_BENCHMARK_RPC ?? "");
if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || !url.port)
  throw new Error("Expected an ephemeral local Anvil endpoint");

export default {
  ...config,
  paths: { ...config.paths, ignition: process.env.E3_BENCHMARK_IGNITION! },
  ignition: { requiredConfirmations: 1, blockPollingInterval: 50 },
  networks: {
    benchmark: {
      type: "http",
      chainId: 31337,
      url: url.href,
      accounts: "remote",
    },
  },
} satisfies HardhatUserConfig;
