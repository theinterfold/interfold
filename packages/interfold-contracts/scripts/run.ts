// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { deployInterfold } from "./deployInterfold";

deployInterfold().catch((error) => {
  console.error(error);
  process.exit(1);
});
