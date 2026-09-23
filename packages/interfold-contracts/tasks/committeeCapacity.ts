// SPDX-License-Identifier: LGPL-3.0-only
import { BaseContract, Contract, ZeroAddress } from "ethers";

/** Check distinct eligible owners before the request tool pays for an E3. */
export async function assertCommitteeOwnerCapacity(
  interfold: BaseContract,
  committeeSize: number,
  registryFromBlock: number,
): Promise<{
  blockNumber: number;
  requiredOwners: number;
  eligibleOwners: number;
}> {
  const provider = interfold.runner?.provider;
  if (!provider)
    throw new Error("Committee capacity check requires a provider");
  const block = await provider.getBlock("latest");
  if (!block || !block.hash || block.timestamp === 0) {
    throw new Error("Committee capacity check could not read the chain head");
  }
  if (
    !Number.isSafeInteger(registryFromBlock) ||
    registryFromBlock < 0 ||
    registryFromBlock > block.number
  ) {
    throw new Error("Invalid registry history start block");
  }
  const at = { blockTag: block.number };
  const timepoint = block.timestamp - 1;
  const requiredOwners = Number(
    await interfold.getFunction("committeeThresholds")(committeeSize, 1, at),
  );
  if (!Number.isSafeInteger(requiredOwners) || requiredOwners <= 0) {
    throw new Error("The selected committee has no configured size");
  }
  const registry = new Contract(
    await interfold.getFunction("ciphernodeRegistry")(at),
    [
      "function bondingRegistry() view returns (address)",
      "function isEnabled(address) view returns (bool)",
      "event CiphernodeAdded(address indexed node, uint256 index, uint256 numNodes, uint256 size)",
    ],
    provider,
  );
  const bonding = new Contract(
    await registry.bondingRegistry(at),
    [
      "function eligibilityAt(address,uint256) view returns (bool,uint256)",
      "function isActive(address) view returns (bool)",
      "function bondOwnerAt(address,uint256) view returns (address)",
      "function ticketToken() view returns (address)",
      "function ticketPrice() view returns (uint256)",
    ],
    provider,
  );
  const ticket = new Contract(
    await bonding.ticketToken(at),
    ["function getPastVotes(address,uint256) view returns (uint256)"],
    provider,
  );
  const ticketPrice: bigint = await bonding.ticketPrice(at);
  if (ticketPrice === 0n) throw new Error("Committee ticket price is zero");
  // Check the history API even when the pool is empty or all operators are inactive.
  await bonding.bondOwnerAt(ZeroAddress, timepoint, at);

  const operators = new Set<string>();
  for (let start = registryFromBlock; start <= block.number; start += 2_000) {
    const logs = await registry.queryFilter(
      registry.filters.CiphernodeAdded(),
      start,
      Math.min(start + 1_999, block.number),
    );
    for (const log of logs) {
      const event = registry.interface.parseLog(log);
      if (!event)
        throw new Error("Cannot decode the registry's operator history");
      operators.add(String(event.args.node).toLowerCase());
    }
  }
  const owners = new Set<string>();
  const nodes = [...operators];
  for (let start = 0; start < nodes.length; start += 16) {
    await Promise.all(
      nodes.slice(start, start + 16).map(async (operator) => {
        const [enabled, active, [activeAtRequest], balance] = await Promise.all(
          [
            registry.isEnabled(operator, at),
            bonding.isActive(operator, at),
            bonding.eligibilityAt(operator, timepoint, at),
            ticket.getPastVotes(operator, timepoint, at),
          ],
        );
        if (!enabled || !active || !activeAtRequest || balance < ticketPrice)
          return;
        const owner: string = await bonding.bondOwnerAt(
          operator,
          timepoint,
          at,
        );
        if (owner !== ZeroAddress) owners.add(owner.toLowerCase());
      }),
    );
  }
  if ((await provider.getBlock(block.number))?.hash !== block.hash) {
    throw new Error(
      "The chain changed during the committee capacity check; retry the request",
    );
  }
  if (owners.size < requiredOwners) {
    throw new Error(
      `Committee needs ${requiredOwners} distinct eligible bond owners; found ${owners.size} at block ${block.number}. No E3 was requested.`,
    );
  }
  // This is a snapshot, not a reservation or proof that operators will remain online.
  return {
    blockNumber: block.number,
    requiredOwners,
    eligibleOwners: owners.size,
  };
}
