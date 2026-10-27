// SPDX-License-Identifier: LGPL-3.0-only
import { main } from "./sale/main";
import { verifyRecordedDeployments } from "./sourceVerification";

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(verifyRecordedDeployments);
