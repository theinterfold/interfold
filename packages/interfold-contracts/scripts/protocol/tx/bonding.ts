// SPDX-License-Identifier: LGPL-3.0-only
import { proxyAdminInterface } from "../constants";
import { safeTx } from "../safe";
import type {
  ProtocolConfigFile,
  ProtocolContracts,
  ProtocolInterfaces,
  SafeTransaction,
} from "../types";

export function bondingUpgradeTx(
  config: ProtocolConfigFile,
  contracts: ProtocolContracts,
  interfaces: ProtocolInterfaces,
): SafeTransaction {
  return safeTx(
    config.bondingRegistryProxyAdmin,
    proxyAdminInterface.encodeFunctionData("upgradeAndCall", [
      config.bondingRegistryProxy,
      contracts.bondingRegistryImplementation,
      bondingInitData(config, contracts, interfaces),
    ]),
  );
}

export function appendBondingTxs(
  txs: SafeTransaction[],
  config: ProtocolConfigFile,
  c: ProtocolContracts,
  i: ProtocolInterfaces,
) {
  txs.push(
    safeTx(
      config.bondingRegistryProxy,
      i.bonding.encodeFunctionData("setSlashingManager", [c.slashingManager]),
    ),
    safeTx(
      config.bondingRegistryProxy,
      i.bonding.encodeFunctionData("setRewardDistributor", [c.interfold, true]),
    ),
    safeTx(
      config.bondingRegistryProxy,
      i.bonding.encodeFunctionData("setRewardDistributor", [
        c.e3RefundManager,
        true,
      ]),
    ),
  );
}

function bondingInitData(
  config: ProtocolConfigFile,
  c: ProtocolContracts,
  i: ProtocolInterfaces,
): string {
  return i.bonding.encodeFunctionData("initialize", [
    config.safe,
    c.ticketToken,
    config.fold,
    c.ciphernodeRegistry,
    config.slashedFundsTreasury,
    BigInt(config.bonding.ticketPrice),
    BigInt(config.bonding.licenseRequiredBond),
    BigInt(config.bonding.minTicketBalance),
    BigInt(config.bonding.exitDelay),
  ]);
}
