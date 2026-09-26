// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
import { ZeroAddress } from "ethers";
import { task } from "hardhat/config";
import { ArgumentType } from "hardhat/types/arguments";

/**
 * Resolve the right impersonation RPC prefix for the connected provider.
 * Anvil exposes `anvil_*`; Hardhat's in-process network exposes `hardhat_*`.
 * Probes once via `anvil_impersonateAccount` and falls back to `hardhat_*`.
 * Throws a clear error if neither is supported (e.g. a real RPC).
 */
async function resolveImpersonationRpc(
  provider: { send: (method: string, params: unknown[]) => Promise<unknown> },
  probeAddress: string,
): Promise<{
  impersonate: string;
  setBalance: string;
  stopImpersonating: string;
}> {
  try {
    await provider.send("anvil_impersonateAccount", [probeAddress]);
    await provider.send("anvil_stopImpersonatingAccount", [probeAddress]);
    return {
      impersonate: "anvil_impersonateAccount",
      setBalance: "anvil_setBalance",
      stopImpersonating: "anvil_stopImpersonatingAccount",
    };
  } catch {
    try {
      await provider.send("hardhat_impersonateAccount", [probeAddress]);
      await provider.send("hardhat_stopImpersonatingAccount", [probeAddress]);
      return {
        impersonate: "hardhat_impersonateAccount",
        setBalance: "hardhat_setBalance",
        stopImpersonating: "hardhat_stopImpersonatingAccount",
      };
    } catch {
      throw new Error(
        "Provider does not support account impersonation. Run this task against an Anvil or Hardhat local node (e.g. `--network localhost` with `anvil` or `npx hardhat node`)",
      );
    }
  }
}

export const ciphernodeAdd = task(
  "ciphernode:add",
  "Register a ciphernode to the bonding registry and ciphernode registry",
)
  .addOption({
    name: "ciphernodeBondAmount",
    description:
      "amount of FOLD to bond (in wei, e.g., 1000000000000000000000 for 1000 FOLD)",
    defaultValue: "1000000000000000000000",
  })
  .addOption({
    name: "ticketAmount",
    description:
      "amount of USDC to deposit for tickets (in wei, e.g., 1,000,000,000 for 1000 USDC)",
    defaultValue: "1000000000",
  })
  .setAction(async () => ({
    default: async ({ ciphernodeBondAmount, ticketAmount }, hre) => {
      const connection = await hre.network.connect();
      const { ethers } = connection;

      const [bondOwner, operator] = await ethers.getSigners();
      console.log(`Bond owner: ${bondOwner.address}`);
      console.log(`Registering ciphernode: ${operator.address}`);

      const { deployAndSaveBondingRegistry } = await import(
        "../scripts/deployAndSave/bondingRegistry"
      );
      const { deployAndSaveInterfoldTicketToken } = await import(
        "../scripts/deployAndSave/interfoldTicketToken"
      );
      const { deployAndSaveInterfoldToken } = await import(
        "../scripts/deployAndSave/interfoldToken"
      );
      const { deployAndSaveMockStableToken } = await import(
        "../scripts/deployAndSave/mockStableToken"
      );
      const { bondingRegistry } = await deployAndSaveBondingRegistry({ hre });
      const { interfoldToken } = await deployAndSaveInterfoldToken({ hre });
      const { interfoldTicketToken } = await deployAndSaveInterfoldTicketToken({
        hre,
      });
      const { mockStableToken } = await deployAndSaveMockStableToken({ hre });

      const ciphernodeBondToken = interfoldToken.connect(bondOwner);
      const ticketToken = interfoldTicketToken.connect(bondOwner);
      const usdcToken = mockStableToken.connect(bondOwner);
      const bondingRegistryConnected = bondingRegistry.connect(bondOwner);

      try {
        console.log("Step 1: Checking balances...");
        const foldBalance = await ciphernodeBondToken.balanceOf(
          bondOwner.address,
        );
        const usdcBalance = await usdcToken.balanceOf(bondOwner.address);

        console.log(`FOLD balance: ${ethers.formatEther(foldBalance)}`);
        console.log(`USDC balance: ${ethers.formatUnits(usdcBalance, 6)}`);

        const ciphernodeBondAmountBigInt = BigInt(ciphernodeBondAmount);
        const ticketAmountBigInt = BigInt(ticketAmount);

        if (foldBalance < ciphernodeBondAmountBigInt) {
          throw new Error(
            `Insufficient FOLD balance. Need: ${ethers.formatEther(ciphernodeBondAmountBigInt)}, Have: ${ethers.formatEther(foldBalance)}`,
          );
        }

        if (usdcBalance < ticketAmountBigInt) {
          throw new Error(
            `Insufficient USDC balance. Need: ${ethers.formatUnits(ticketAmountBigInt, 6)}, Have: ${ethers.formatUnits(usdcBalance, 6)}`,
          );
        }

        console.log("Step 2: Approving FOLD for ciphernode bond...");
        const approveTx = await ciphernodeBondToken.approve(
          await bondingRegistry.getAddress(),
          ciphernodeBondAmountBigInt,
        );
        await approveTx.wait();
        console.log("FOLD approved");

        console.log("Step 3: Bonding ciphernodeBond...");
        await (
          await bondingRegistry
            .connect(operator)
            .setBondOwner(bondOwner.address)
        ).wait();
        const bondTx = await bondingRegistryConnected.bondCiphernodeFor(
          operator.address,
          ciphernodeBondAmountBigInt,
        );
        await bondTx.wait();
        console.log(
          `Ciphernode bonded: ${ethers.formatEther(ciphernodeBondAmountBigInt)} FOLD`,
        );

        console.log("Step 4: Registering as operator...");
        const isRegistered = await bondingRegistry.isRegistered(
          operator.address,
        );
        if (!isRegistered) {
          const registerTx = await bondingRegistryConnected.registerOperatorFor(
            operator.address,
          );
          await registerTx.wait();
          console.log(
            "Operator registered (automatically added to CiphernodeRegistry)",
          );
        } else {
          console.log("Ciphernode is already registered as operator");
        }

        console.log("Step 5: Approving USDC for ticket purchase...");
        const approveUsdcTx = await usdcToken.approve(
          ticketToken.getAddress(),
          ticketAmountBigInt,
        );
        await approveUsdcTx.wait();
        console.log("USDC approved");

        console.log("Step 6: Adding ticket balance...");
        const ticketTx = await bondingRegistryConnected.addTicketBalanceFor(
          operator.address,
          ticketAmountBigInt,
        );
        await ticketTx.wait();
        console.log(
          `Ticket balance added: ${ethers.formatUnits(ticketAmountBigInt, 6)} USDC worth`,
        );

        const isActive = await bondingRegistry.isActive(operator.address);
        const ciphernodeBond = await bondingRegistry.getCiphernodeBond(
          operator.address,
        );
        const ticketBalance = await bondingRegistry.getTicketBalance(
          operator.address,
        );

        console.log("\n=== Registration Complete ===");
        console.log(`Ciphernode: ${operator.address}`);
        console.log(`Registered: ${isRegistered}`);
        console.log(`Active: ${isActive}`);
        console.log(
          `Ciphernode Bond: ${ethers.formatEther(ciphernodeBond)} FOLD`,
        );
        console.log(
          `Ticket Balance: ${ethers.formatUnits(ticketBalance, 6)} USDC worth`,
        );
      } catch (error) {
        console.error("Registration failed:", error);
        throw error;
      }
    },
  }))
  .build();

export const ciphernodeRemove = task(
  "ciphernode:remove",
  "Deregister a ciphernode from the bonding registry",
)
  .setAction(async () => ({
    default: async (_, hre) => {
      const connection = await hre.network.connect();
      const { ethers } = connection;

      const [bondOwner, operator] = await ethers.getSigners();
      console.log(`Deregistering ciphernode: ${operator.address}`);

      const { deployAndSaveBondingRegistry } = await import(
        "../scripts/deployAndSave/bondingRegistry"
      );
      const { bondingRegistry } = await deployAndSaveBondingRegistry({ hre });

      const bondingRegistryConnected = bondingRegistry.connect(bondOwner);

      try {
        console.log(
          "Deregistering operator (will also remove from CiphernodeRegistry)...",
        );
        const tx = await bondingRegistryConnected.deregisterOperatorFor(
          operator.address,
        );
        await tx.wait();

        console.log(`Ciphernode ${operator.address} deregistered`);
        console.log(
          "Note: Funds are now in the exit queue. The bond owner can call claimExitsFor() after the delay.",
        );
      } catch (error) {
        console.error("Deregistration failed:", error);
        throw error;
      }
    },
  }))
  .build();

export const ciphernodeMintTokens = task(
  "ciphernode:mint-tokens",
  "Mint FOLD and USDC tokens for a ciphernode (for testing)",
)
  .addOption({
    name: "ciphernodeAddress",
    description: "address of ciphernode to mint tokens for",
    defaultValue: ZeroAddress,
  })
  .addOption({
    name: "foldAmount",
    description:
      "amount of FOLD to mint (in ether units, e.g., 2000 for 2000 FOLD)",
    defaultValue: "2000",
  })
  .addOption({
    name: "usdcAmount",
    description:
      "amount of USDC to mint (in USDC units, e.g., 1000 for 1000 USDC)",
    defaultValue: "1000",
  })
  .setAction(async () => ({
    default: async ({ ciphernodeAddress, foldAmount, usdcAmount }, hre) => {
      const connection = await hre.network.connect();
      const { ethers } = connection;

      if (ciphernodeAddress === ZeroAddress) {
        throw new Error(
          "Ciphernode address is required. Use --ciphernode-address option.",
        );
      }

      const { deployAndSaveInterfoldToken } = await import(
        "../scripts/deployAndSave/interfoldToken"
      );
      const { interfoldToken } = await deployAndSaveInterfoldToken({ hre });

      const { deployAndSaveMockStableToken } = await import(
        "../scripts/deployAndSave/mockStableToken"
      );
      const { mockStableToken } = await deployAndSaveMockStableToken({
        hre,
      });

      const [signer] = await ethers.getSigners();
      const interfoldTokenContract = interfoldToken.connect(signer);
      const mockUSDCContract = mockStableToken.connect(signer);

      try {
        console.log(`Minting tokens for: ${ciphernodeAddress}`);

        console.log(`Minting ${foldAmount} FOLD...`);
        const foldTx = await interfoldTokenContract.mint(
          ciphernodeAddress,
          ethers.parseEther(foldAmount),
          ethers.encodeBytes32String("cn-alloc"),
        );
        await foldTx.wait();
        console.log(`${foldAmount} FOLD minted`);

        console.log(`Minting ${usdcAmount} USDC...`);
        const usdcTx = await mockUSDCContract.mint(
          ciphernodeAddress,
          ethers.parseUnits(usdcAmount, 6),
        );
        await usdcTx.wait();
        console.log(`${usdcAmount} USDC minted`);

        const foldBalance =
          await interfoldTokenContract.balanceOf(ciphernodeAddress);
        const usdcBalance = await mockUSDCContract.balanceOf(ciphernodeAddress);

        console.log("\n=== Token Balances ===");
        console.log(`FOLD: ${ethers.formatEther(foldBalance)}`);
        console.log(`USDC: ${ethers.formatUnits(usdcBalance, 6)}`);

        const tgeTs = await interfoldTokenContract.tgeTimestamp();
        if (tgeTs === 0n) {
          console.log("Firing TGE to enable transfers...");
          try {
            await (await interfoldTokenContract.tge()).wait();
            console.log("InterfoldToken TGE fired, transfers enabled");
          } catch (e: any) {
            console.warn(
              "TGE not yet available (CCA cooldown may not have passed):",
              e.reason ?? e.message ?? e,
            );
          }
        }
      } catch (error) {
        console.error("Token minting failed:", error);
        throw error;
      }
    },
  }))
  .build();

export const ciphernodeAdminAdd = task(
  "ciphernode:admin-add",
  "Register a ciphernode using admin privileges (for testing/setup). Requires a local node that supports account impersonation (Anvil or Hardhat).",
)
  .addOption({
    name: "ciphernodeAddress",
    description: "address of ciphernode to register",
    defaultValue: ZeroAddress,
  })
  .addOption({
    name: "adminPrivateKey",
    description:
      "private key of admin wallet (optional, uses anvil first key if not provided)",
    defaultValue: "",
  })
  .addOption({
    name: "bondOwnerAddress",
    description:
      "bond owner address (defaults to the operator for distinct-owner local committees)",
    defaultValue: ZeroAddress,
  })
  .addOption({
    name: "ciphernodeBondAmount",
    description:
      "amount of FOLD to bond (in ether units, e.g., 1000 for 1000 FOLD)",
    defaultValue: "1000",
  })
  .addOption({
    name: "ticketAmount",
    description:
      "amount of USDC for tickets (in USDC units, e.g., 1000 for 1000 USDC)",
    defaultValue: "1000",
  })
  .setAction(async () => ({
    default: async (
      {
        ciphernodeAddress,
        adminPrivateKey,
        bondOwnerAddress,
        ciphernodeBondAmount,
        ticketAmount,
      },
      hre,
    ) => {
      const connection = await hre.network.connect();
      const { ethers } = connection;
      const provider = ethers.provider;

      if (!provider) {
        throw new Error(
          "No provider on Hardhat network connection. Use --network localhost with Anvil running.",
        );
      }

      if (ciphernodeAddress === ZeroAddress) {
        throw new Error(
          "Ciphernode address is required. Use --ciphernode-address option.",
        );
      }

      const [defaultSigner] = await ethers.getSigners();
      const adminWallet = adminPrivateKey
        ? new ethers.Wallet(adminPrivateKey, provider)
        : defaultSigner;
      const ownerAddress =
        bondOwnerAddress === ZeroAddress ? ciphernodeAddress : bondOwnerAddress;

      console.log(`Admin wallet: ${adminWallet.address}`);
      console.log(`Registering ciphernode: ${ciphernodeAddress}`);
      console.log(`Bond owner: ${ownerAddress}`);

      const { deployAndSaveBondingRegistry } = await import(
        "../scripts/deployAndSave/bondingRegistry"
      );
      const { deployAndSaveInterfoldTicketToken } = await import(
        "../scripts/deployAndSave/interfoldTicketToken"
      );
      const { deployAndSaveInterfoldToken } = await import(
        "../scripts/deployAndSave/interfoldToken"
      );
      const { deployAndSaveMockStableToken } = await import(
        "../scripts/deployAndSave/mockStableToken"
      );
      const { bondingRegistry } = await deployAndSaveBondingRegistry({ hre });
      const { interfoldToken } = await deployAndSaveInterfoldToken({ hre });
      const { interfoldTicketToken } = await deployAndSaveInterfoldTicketToken({
        hre,
      });
      const { mockStableToken: mockUSDC } = await deployAndSaveMockStableToken({
        hre,
        initialSupply: 1_000_000,
      });

      const bondingRegistryAddress = await bondingRegistry.getAddress();
      const registryCode = await provider.getCode(bondingRegistryAddress);
      if (registryCode === "0x") {
        throw new Error(
          `BondingRegistry not deployed at ${bondingRegistryAddress}. ` +
            "Run pnpm evm:deploy with Anvil on localhost:8545 first.",
        );
      }

      const interfoldTokenConnected = interfoldToken.connect(adminWallet);
      const mockUSDCConnected = mockUSDC.connect(adminWallet);

      const ticketTokenAddress = await interfoldTicketToken.getAddress();

      try {
        const ciphernodeBondWei = ethers.parseEther(ciphernodeBondAmount);
        const ticketAmountWei = ethers.parseUnits(ticketAmount, 6);

        console.log("Step 1: Minting FOLD to the bond owner...");

        const foldTx = await interfoldTokenConnected.mint(
          ownerAddress,
          ciphernodeBondWei,
          ethers.encodeBytes32String("admin-cn-reg"),
        );
        await foldTx.wait();

        console.log("Step 2: Minting USDC to the bond owner...");
        const usdcTx = await mockUSDCConnected.mint(
          ownerAddress,
          ticketAmountWei,
        );
        await usdcTx.wait();
        console.log(`${ticketAmount} USDC minted to the bond owner`);

        console.log(
          "Step 3: Impersonating ciphernode to authorize the bond owner...",
        );
        const impersonationRpc = await resolveImpersonationRpc(
          provider,
          ciphernodeAddress,
        );
        await provider.send(impersonationRpc.impersonate, [ciphernodeAddress]);
        await provider.send(impersonationRpc.setBalance, [
          ciphernodeAddress,
          "0x1000000000000000000000",
        ]);

        const ciphernodeSigner = await ethers.getSigner(ciphernodeAddress);
        const bondingRegistryAsCiphernode =
          bondingRegistry.connect(ciphernodeSigner);

        const ownerTx =
          await bondingRegistryAsCiphernode.setBondOwner(ownerAddress);
        await ownerTx.wait();
        await provider.send(impersonationRpc.stopImpersonating, [
          ciphernodeAddress,
        ]);

        await provider.send(impersonationRpc.impersonate, [ownerAddress]);
        await provider.send(impersonationRpc.setBalance, [
          ownerAddress,
          "0x1000000000000000000000",
        ]);
        const ownerSigner = await ethers.getSigner(ownerAddress);
        const approveTx = await interfoldToken
          .connect(ownerSigner)
          .approve(await bondingRegistry.getAddress(), ciphernodeBondWei);
        await approveTx.wait();

        const bondingRegistryAsOwner = bondingRegistry.connect(ownerSigner);
        const bondTx = await bondingRegistryAsOwner.bondCiphernodeFor(
          ciphernodeAddress,
          ciphernodeBondWei,
        );
        await bondTx.wait();
        console.log(`Ciphernode bonded: ${ciphernodeBondAmount} FOLD`);

        const registerTx =
          await bondingRegistryAsOwner.registerOperatorFor(ciphernodeAddress);
        await registerTx.wait();
        console.log(
          "Operator registered (automatically added to CiphernodeRegistry)",
        );

        console.log("Step 4: Adding ticket balance via the bond owner...");

        const approveUsdcAsOwnerTx = await mockUSDC
          .connect(ownerSigner)
          .approve(ticketTokenAddress, ticketAmountWei);
        await approveUsdcAsOwnerTx.wait();

        const addTicketTx = await bondingRegistryAsOwner.addTicketBalanceFor(
          ciphernodeAddress,
          ticketAmountWei,
        );
        await addTicketTx.wait();
        await provider.send(impersonationRpc.stopImpersonating, [ownerAddress]);
        console.log(`Ticket balance added: ${ticketAmount} USDC worth`);

        const isRegistered =
          await bondingRegistry.isRegistered(ciphernodeAddress);
        const isActive = await bondingRegistry.isActive(ciphernodeAddress);
        const ciphernodeBond =
          await bondingRegistry.getCiphernodeBond(ciphernodeAddress);
        const ticketBalance =
          await bondingRegistry.getTicketBalance(ciphernodeAddress);

        console.log("\n=== Registration Complete ===");
        console.log(`Ciphernode: ${ciphernodeAddress}`);
        console.log(`Registered: ${isRegistered}`);
        console.log(`Active: ${isActive}`);
        console.log(
          `Ciphernode Bond: ${ethers.formatEther(ciphernodeBond)} FOLD`,
        );
        console.log(
          `Ticket Balance: ${ethers.formatUnits(ticketBalance, 6)} USDC worth`,
        );
      } catch (error) {
        console.error("Admin registration failed:", error);
        throw error;
      }
    },
  }))
  .build();

export const updateSubmissionWindow = task(
  "ciphernode:window",
  "Update the submission window for the ciphernode registry",
)
  .addOption({
    name: "newWindow",
    description: "the new submission window",
    defaultValue: 10,
    type: ArgumentType.INT,
  })
  .setAction(async () => ({
    default: async ({ newWindow }, hre) => {
      const { deployAndSaveCiphernodeRegistryOwnable } = await import(
        "../scripts/deployAndSave/ciphernodeRegistryOwnable"
      );

      const { deployAndSavePoseidonT3 } = await import(
        "../scripts/deployAndSave/poseidonT3"
      );
      const poseidonT3 = await deployAndSavePoseidonT3({ hre });

      const { ciphernodeRegistry } =
        await deployAndSaveCiphernodeRegistryOwnable({
          hre,
          poseidonT3Address: poseidonT3,
        });

      const tx =
        await ciphernodeRegistry.setSortitionSubmissionWindow(newWindow);

      console.log("Updating submission window... ", tx.hash);
      await tx.wait();

      console.log(`Submission window update to ${newWindow}`);
    },
  }))
  .build();
