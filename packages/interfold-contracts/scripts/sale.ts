// SPDX-License-Identifier: LGPL-3.0-only
import { main } from "./sale/main";

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

