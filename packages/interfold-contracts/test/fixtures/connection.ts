// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Shared Hardhat network connection. All fixture modules must import from
// here so they share the same EdrProvider instance — otherwise snapshots
// taken via `loadFixture` only revert state seen by one provider, leaving
// mutations made through other providers persisted across tests.
import { network } from "hardhat";

type Connection = Awaited<ReturnType<typeof network.connect>>;

export const connection: Connection = await network.connect();
export const ethers: Connection["ethers"] = connection.ethers;
export const ignition: Connection["ignition"] = connection.ignition;
export const networkHelpers: Connection["networkHelpers"] =
  connection.networkHelpers;
