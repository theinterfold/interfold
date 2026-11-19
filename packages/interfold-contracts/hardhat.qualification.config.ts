// SPDX-License-Identifier: LGPL-3.0-only
import config from "./hardhat.config";

// Qualification commands must fail even when their grep or opt-in flag is stale.
export default {
  ...config,
  test: {
    ...config.test,
    mocha: { ...config.test?.mocha, failZero: true, forbidPending: true },
  },
};
