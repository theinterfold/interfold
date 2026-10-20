// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

import { ACTIVE_BFV_CONFIG, bfvHonkSource } from "../../scripts/utils";

const SOURCE = bfvHonkSource(ACTIVE_BFV_CONFIG, "DkgAggregatorV2Verifier");

export default buildModule("DkgAggregatorV2Verifier", (m) => {
  const zkTranscriptLib = m.library(`${SOURCE}:ZKTranscriptLib`);
  const relationsLib = m.library(`${SOURCE}:RelationsLib`);
  const dkgAggregatorV2Verifier = m.contract(
    `${SOURCE}:DkgAggregatorV2Verifier`,
    [],
    {
      libraries: {
        ZKTranscriptLib: zkTranscriptLib,
        RelationsLib: relationsLib,
      },
    },
  );

  return { dkgAggregatorV2Verifier };
}) as any;
