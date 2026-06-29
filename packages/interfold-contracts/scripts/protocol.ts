// SPDX-License-Identifier: LGPL-3.0-only
import { main } from "./protocol/main";

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
