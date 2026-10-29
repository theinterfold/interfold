// SPDX-License-Identifier: LGPL-3.0-only
import { verifyRecordedDeployments } from "../sourceVerification";
import { proposeProxyUpgrade } from "./safeProxyUpgrade";

proposeProxyUpgrade("bondingRegistry")
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(verifyRecordedDeployments);
