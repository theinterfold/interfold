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
    name: "licenseBondAmount",
    description:
      "amount of INTF to bond (in wei, e.g., 1000000000000000000000 for 1000 INTF)",
    defaultValue: "1000000000000000000000",
  })
  .addOption({
    name: "ticketAmount",
    description:
      "amount of USDC to deposit for tickets (in wei, e.g., 1,000,000,000 for 1000 USDC)",
    defaultValue: "1000000000",
  })
  .setAction(async () => ({
    default: async ({ licenseBondAmount, ticketAmount }, hre) => {
      const connection = await hre.network.connect();
      const { ethers } = connection;

      const [signer] = await ethers.getSigners();
      console.log(`Registering ciphernode: ${signer.address}`);

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

      const licenseToken = interfoldToken.connect(signer);
      const ticketToken = interfoldTicketToken.connect(signer);
      const usdcToken = mockStableToken.connect(signer);
      const bondingRegistryConnected = bondingRegistry.connect(signer);

      try {
        console.log("Step 1: Checking balances...");
        const intfBalance = await licenseToken.balanceOf(signer.address);
        const usdcBalance = await usdcToken.balanceOf(signer.address);

        console.log(`INTF balance: ${ethers.formatEther(intfBalance)}`);
        console.log(`USDC balance: ${ethers.formatUnits(usdcBalance, 6)}`);

        const licenseBondAmountBigInt = BigInt(licenseBondAmount);
        const ticketAmountBigInt = BigInt(ticketAmount);

        if (intfBalance < licenseBondAmountBigInt) {
          throw new Error(
            `Insufficient INTF balance. Need: ${ethers.formatEther(licenseBondAmountBigInt)}, Have: ${ethers.formatEther(intfBalance)}`,
          );
        }

        if (usdcBalance < ticketAmountBigInt) {
          throw new Error(
            `Insufficient USDC balance. Need: ${ethers.formatUnits(ticketAmountBigInt, 6)}, Have: ${ethers.formatUnits(usdcBalance, 6)}`,
          );
        }

        console.log("Step 2: Approving INTF for license bond...");
        const approveTx = await licenseToken.approve(
          await bondingRegistry.getAddress(),
          licenseBondAmountBigInt,
        );
        await approveTx.wait();
        console.log("INTF approved");

        console.log("Step 3: Bonding license...");
        const bondTx = await bondingRegistryConnected.bondLicense(
          licenseBondAmountBigInt,
        );
        await bondTx.wait();
        console.log(
          `Licensed bonded: ${ethers.formatEther(licenseBondAmountBigInt)} INTF`,
        );

        console.log("Step 4: Registering as operator...");
        const isRegistered = await bondingRegistry.isRegistered(signer.address);
        if (!isRegistered) {
          const registerTx = await bondingRegistryConnected.registerOperator();
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
        const ticketTx =
          await bondingRegistryConnected.addTicketBalance(ticketAmountBigInt);
        await ticketTx.wait();
        console.log(
          `Ticket balance added: ${ethers.formatUnits(ticketAmountBigInt, 6)} USDC worth`,
        );

        const isActive = await bondingRegistry.isActive(signer.address);
        const licenseBond = await bondingRegistry.getLicenseBond(
          signer.address,
        );
        const ticketBalance = await bondingRegistry.getTicketBalance(
          signer.address,
        );

        console.log("\n=== Registration Complete ===");
        console.log(`Ciphernode: ${signer.address}`);
        console.log(`Registered: ${isRegistered}`);
        console.log(`Active: ${isActive}`);
        console.log(`License Bond: ${ethers.formatEther(licenseBond)} INTF`);
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

      const [signer] = await ethers.getSigners();
      console.log(`Deregistering ciphernode: ${signer.address}`);

      const { deployAndSaveBondingRegistry } = await import(
        "../scripts/deployAndSave/bondingRegistry"
      );
      const { bondingRegistry } = await deployAndSaveBondingRegistry({ hre });

      const bondingRegistryConnected = bondingRegistry.connect(signer);

      try {
        console.log(
          "Deregistering operator (will also remove from CiphernodeRegistry)...",
        );
        const tx = await bondingRegistryConnected.deregisterOperator();
        await tx.wait();

        console.log(`Ciphernode ${signer.address} deregistered`);
        console.log(
          "Note: Funds are now in exit queue. Use claimExits() after the exit delay period.",
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
  "Mint INTF and USDC tokens for a ciphernode (for testing)",
)
  .addOption({
    name: "ciphernodeAddress",
    description: "address of ciphernode to mint tokens for",
    defaultValue: ZeroAddress,
  })
  .addOption({
    name: "intfAmount",
    description:
      "amount of INTF to mint (in ether units, e.g., 2000 for 2000 INTF)",
    defaultValue: "2000",
  })
  .addOption({
    name: "usdcAmount",
    description:
      "amount of USDC to mint (in USDC units, e.g., 1000 for 1000 USDC)",
    defaultValue: "1000",
  })
  .setAction(async () => ({
    default: async ({ ciphernodeAddress, intfAmount, usdcAmount }, hre) => {
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

        console.log(`Minting ${intfAmount} INTF...`);
        const intfTx = await interfoldTokenContract.mint(
          ciphernodeAddress,
          ethers.parseEther(intfAmount),
          ethers.encodeBytes32String("cn-alloc"),
        );
        await intfTx.wait();
        console.log(`${intfAmount} INTF minted`);

        console.log(`Minting ${usdcAmount} USDC...`);
        const usdcTx = await mockUSDCContract.mint(
          ciphernodeAddress,
          ethers.parseUnits(usdcAmount, 6),
        );
        await usdcTx.wait();
        console.log(`${usdcAmount} USDC minted`);

        const intfBalance =
          await interfoldTokenContract.balanceOf(ciphernodeAddress);
        const usdcBalance = await mockUSDCContract.balanceOf(ciphernodeAddress);

        console.log("\n=== Token Balances ===");
        console.log(`INTF: ${ethers.formatEther(intfBalance)}`);
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
    name: "licenseBondAmount",
    description:
      "amount of INTF to bond (in ether units, e.g., 1000 for 1000 INTF)",
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
      { ciphernodeAddress, adminPrivateKey, licenseBondAmount, ticketAmount },
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

      console.log(`Admin wallet: ${adminWallet.address}`);
      console.log(`Registering ciphernode: ${ciphernodeAddress}`);

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
        const licenseBondWei = ethers.parseEther(licenseBondAmount);
        const ticketAmountWei = ethers.parseUnits(ticketAmount, 6);

        console.log("Step 1: Minting and transferring INTF to ciphernode...");

        const intfTx = await interfoldTokenConnected.mint(
          adminWallet.address,
          licenseBondWei,
          ethers.encodeBytes32String("admin-cn-reg"),
        );
        await intfTx.wait();

        const transferTx = await interfoldTokenConnected.transfer(
          ciphernodeAddress,
          licenseBondWei,
        );
        await transferTx.wait();
        console.log(`${licenseBondAmount} INTF transferred to ciphernode`);

        console.log("Step 2: Minting USDC to admin...");
        const usdcTx = await mockUSDCConnected.mint(
          adminWallet.address,
          ticketAmountWei,
        );
        await usdcTx.wait();
        console.log(`${ticketAmount} USDC minted to admin`);

        console.log(
          "Step 3: Impersonating ciphernode for license operations...",
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
        const interfoldTokenAsCiphernode =
          interfoldToken.connect(ciphernodeSigner);
        const bondingRegistryAsCiphernode =
          bondingRegistry.connect(ciphernodeSigner);

        const approveTx = await interfoldTokenAsCiphernode.approve(
          await bondingRegistry.getAddress(),
          licenseBondWei,
        );
        await approveTx.wait();

        const bondTx =
          await bondingRegistryAsCiphernode.bondLicense(licenseBondWei);
        await bondTx.wait();
        console.log(`License bonded: ${licenseBondAmount} INTF`);

        const registerTx = await bondingRegistryAsCiphernode.registerOperator();
        await registerTx.wait();
        console.log(
          "Operator registered (automatically added to CiphernodeRegistry)",
        );

        await provider.send(impersonationRpc.stopImpersonating, [
          ciphernodeAddress,
        ]);

        console.log("Step 4: Adding ticket balance via admin...");

        const approveUsdcTx = await mockUSDCConnected.approve(
          ticketTokenAddress,
          ticketAmountWei,
        );
        await approveUsdcTx.wait();

        await provider.send(impersonationRpc.impersonate, [ciphernodeAddress]);
        await provider.send(impersonationRpc.setBalance, [
          ciphernodeAddress,
          "0x1000000000000000000000",
        ]);

        const ciphernodeSigner2 = await ethers.getSigner(ciphernodeAddress);
        const bondingRegistryAsCiphernode2 =
          bondingRegistry.connect(ciphernodeSigner2);

        const usdcTransferTx = await mockUSDCConnected.transfer(
          ciphernodeAddress,
          ticketAmountWei,
        );
        await usdcTransferTx.wait();

        const mockUSDCAsCiphernode = mockUSDC.connect(ciphernodeSigner2);
        const approveUsdcAsCiphernodeTx = await mockUSDCAsCiphernode.approve(
          ticketTokenAddress,
          ticketAmountWei,
        );
        await approveUsdcAsCiphernodeTx.wait();

        const addTicketTx =
          await bondingRegistryAsCiphernode2.addTicketBalance(ticketAmountWei);
        await addTicketTx.wait();
        console.log(`Ticket balance added: ${ticketAmount} USDC worth`);

        await provider.send(impersonationRpc.stopImpersonating, [
          ciphernodeAddress,
        ]);

        const isRegistered =
          await bondingRegistry.isRegistered(ciphernodeAddress);
        const isActive = await bondingRegistry.isActive(ciphernodeAddress);
        const licenseBond =
          await bondingRegistry.getLicenseBond(ciphernodeAddress);
        const ticketBalance =
          await bondingRegistry.getTicketBalance(ciphernodeAddress);

        console.log("\n=== Registration Complete ===");
        console.log(`Ciphernode: ${ciphernodeAddress}`);
        console.log(`Registered: ${isRegistered}`);
        console.log(`Active: ${isActive}`);
        console.log(`License Bond: ${ethers.formatEther(licenseBond)} INTF`);
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
