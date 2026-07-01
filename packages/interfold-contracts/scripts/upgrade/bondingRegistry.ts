// SPDX-License-Identifier: LGPL-3.0-only
import { proposeProxyUpgrade } from "./safeProxyUpgrade";

proposeProxyUpgrade("bondingRegistry").catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
