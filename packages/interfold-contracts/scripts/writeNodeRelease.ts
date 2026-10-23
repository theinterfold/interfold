// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
// Writes dist/node-release.json from the monorepo release files. `currentNodeRelease` reads it
// when the package is installed outside the monorepo, where those files do not exist.
import fs from "node:fs";

import { readRepoNodeRelease } from "./protocol/nodeRelease";
import { getRepoRoot } from "./utils";

const output = new URL("../dist/node-release.json", import.meta.url);
fs.mkdirSync(new URL(".", output), { recursive: true });
fs.writeFileSync(
  output,
  `${JSON.stringify(readRepoNodeRelease(getRepoRoot()), null, 2)}\n`,
);
console.log(`Wrote ${output.pathname}`);
