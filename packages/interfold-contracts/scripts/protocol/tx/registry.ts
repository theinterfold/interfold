// SPDX-License-Identifier: LGPL-3.0-only
import { safeTx } from "../safe";
import type {
  ProtocolConfigFile,
  ProtocolContracts,
  ProtocolInterfaces,
  SafeTransaction,
} from "../types";
import { optionalAddress } from "../values";

export function appendRegistryTxs(
  txs: SafeTransaction[],
  config: ProtocolConfigFile,
  c: ProtocolContracts,
  i: ProtocolInterfaces,
) {
  txs.push(
    safeTx(
      c.ciphernodeRegistry,
      i.registry.encodeFunctionData("setInterfold", [c.interfold]),
    ),
    safeTx(
      c.ciphernodeRegistry,
      i.registry.encodeFunctionData("setBondingRegistry", [
        config.bondingRegistryProxy,
      ]),
    ),
    safeTx(
      c.ciphernodeRegistry,
      i.registry.encodeFunctionData("setSlashingManager", [c.slashingManager]),
    ),
  );

  const dkg = optionalAddress(
    config.verifiers?.dkgFoldAttestationVerifier,
    "dkgFoldAttestationVerifier",
  );
  if (dkg) {
    txs.push(
      safeTx(
        c.ciphernodeRegistry,
        i.registry.encodeFunctionData("setInitialDkgFoldAttestationVerifier", [
          dkg,
        ]),
      ),
    );
  }
}
