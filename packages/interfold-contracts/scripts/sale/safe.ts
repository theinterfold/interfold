// SPDX-License-Identifier: LGPL-3.0-only
import SafeApiKit from "@safe-global/api-kit";
import Safe from "@safe-global/protocol-kit";
import { MetaTransactionData, OperationType } from "@safe-global/types-kit";
import { ethers as ethersLib } from "ethers";

import { arg } from "./cli";
import {
  PREDICATE_VALIDATION_HOOK_ABI,
  ZERO,
} from "./constants";
import {
  safeProposalPath,
  safeTransactionsPath,
  writeJson,
} from "./files";
import type {
  DeploymentFile,
  SafeAction,
  SafeProposal,
  SafeTransactionFallbackFile,
  SaleConfigFile,
} from "./types";
import { address } from "./values";

function privateKeyForSafeProposal(): string {
  if (process.env.PRIVATE_KEY) return process.env.PRIVATE_KEY;
  if (process.env.MNEMONIC) {
    return ethersLib.HDNodeWallet.fromPhrase(
      process.env.MNEMONIC,
      undefined,
      "m/44'/60'/0'/0/0",
    ).privateKey;
  }
  throw new Error(
    "Set PRIVATE_KEY or MNEMONIC so the Safe SDK can sign the proposal hash.",
  );
}

function rpcUrlForSafeProposal(): string {
  const rpcUrl = process.env.RPC_URL;
  if (!rpcUrl) {
    throw new Error("Set RPC_URL so the Safe SDK can read the Safe.");
  }
  return rpcUrl;
}

function safeAppPrefix(chainId: number): string | undefined {
  if (chainId === 1) return "eth";
  if (chainId === 11155111) return "sep";
  if (chainId === 8453) return "base";
  if (chainId === 84532) return "basesep";
  if (chainId === 42161) return "arb1";
  if (chainId === 10) return "oeth";
  if (chainId === 137) return "matic";
  return undefined;
}

function safeTransactionUrl(
  chainId: number,
  safeAddress: string,
  safeTxHash: string,
): string | undefined {
  const prefix = safeAppPrefix(chainId);
  if (!prefix) return undefined;
  return `https://app.safe.global/transactions/tx?safe=${prefix}:${safeAddress}&id=multisig_${safeAddress}_${safeTxHash}`;
}

export async function proposeSafeTransactions(
  config: SaleConfigFile,
  transactions: MetaTransactionData[],
  origin: string,
): Promise<SafeProposal> {
  if (transactions.length === 0) {
    throw new Error("No Safe transactions to propose");
  }
  const privateKey = privateKeyForSafeProposal();
  const proposer = address(
    new ethersLib.Wallet(privateKey).address,
    "Safe proposal signer",
  );
  const apiKit = new SafeApiKit({
    chainId: BigInt(config.chainId),
    apiKey: process.env.SAFE_API_KEY || undefined,
    txServiceUrl: process.env.SAFE_TX_SERVICE_URL || undefined,
  });
  const protocolKit = await Safe.init({
    provider: rpcUrlForSafeProposal(),
    signer: privateKey,
    safeAddress: config.safe,
  });

  const nonce = Number(
    arg("safe-nonce") ?? (await apiKit.getNextNonce(config.safe)),
  );
  const safeTransaction = await protocolKit.createTransaction({
    transactions,
    onlyCalls: true,
    options: { nonce },
  });
  const safeTxHash = await protocolKit.getTransactionHash(safeTransaction);
  const signature = await protocolKit.signHash(safeTxHash);

  await apiKit.proposeTransaction({
    safeAddress: config.safe,
    safeTransactionData: safeTransaction.data,
    safeTxHash,
    senderAddress: proposer,
    senderSignature: signature.data,
    origin,
  });

  const url = safeTransactionUrl(config.chainId, config.safe, safeTxHash);
  console.log(
    `Safe proposal URL: ${url ?? "(open the Safe UI pending queue)"}`,
  );

  const proposal: SafeProposal = {
    safeTxHash,
    safeAddress: config.safe,
    proposer,
    nonce,
    transactionCount: transactions.length,
    origin,
    url,
    proposedAt: new Date().toISOString(),
  };
  writeJson(safeProposalPath(config), proposal);
  return proposal;
}

export function safeActionsToTransactions(
  actions: SafeAction[],
): MetaTransactionData[] {
  return actions.map((action) => action.transaction);
}

export function writeSafeTransactionFallback(
  config: SaleConfigFile,
  actions: SafeAction[],
  origin: string,
): SafeTransactionFallbackFile {
  const fallback: SafeTransactionFallbackFile = {
    name: config.name,
    chainId: config.chainId,
    safe: config.safe,
    origin,
    createdAt: new Date().toISOString(),
    transactions: actions.map(({ description, transaction }) => ({
      description,
      to: transaction.to,
      value: transaction.value,
      data: transaction.data,
      operation: Number(transaction.operation ?? OperationType.Call),
    })),
  };
  writeJson(safeTransactionsPath(config), fallback);
  return fallback;
}

export function printSafeTransactionFallback(
  config: SaleConfigFile,
  fallback: SafeTransactionFallbackFile,
  reason?: string,
): void {
  const reasonLine = reason ? `\n  reason: ${reason}` : "";
  const transactionLines = fallback.transactions
    .map(
      (tx, index) => `
  ${index + 1}. ${tx.description}
     to:        ${tx.to}
     value:     ${tx.value}
     operation: ${tx.operation} (CALL)
     data:      ${tx.data}`,
    )
    .join("\n");

  console.log(`
Safe transaction fallback${reasonLine}
  safe:  ${fallback.safe}
  chain: ${fallback.chainId}
  file:  ${safeTransactionsPath(config)}

Add these as a Safe batch transaction:
${transactionLines}
`);
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function buildSaleSafeActions(
  config: SaleConfigFile,
  deployment: DeploymentFile,
): SafeAction[] {
  const acceptOwnership: MetaTransactionData = {
    to: deployment.fold,
    value: "0",
    data: "0x79ba5097",
    operation: OperationType.Call,
  };
  const actions: SafeAction[] = [
    {
      description: "FOLD.acceptOwnership()",
      transaction: acceptOwnership,
    },
  ];
  const validationHook =
    deployment.validationHook ?? config.auction.validationHook;
  if (validationHook && validationHook !== ZERO) {
    const hookInterface = new ethersLib.Interface(
      PREDICATE_VALIDATION_HOOK_ABI,
    );
    actions.push({
      description: `PredicateValidationHook.setAuction(${deployment.auction})`,
      transaction: {
        to: validationHook,
        value: "0",
        data: hookInterface.encodeFunctionData("setAuction", [
          deployment.auction,
        ]),
        operation: OperationType.Call,
      },
    });
  }
  return actions;
}

export async function proposeSaleSafeActions(
  config: SaleConfigFile,
  deployment: DeploymentFile,
): Promise<SafeProposal> {
  const origin = `Interfold ${config.name} sale Safe activation`;
  const actions = buildSaleSafeActions(config, deployment);
  writeSafeTransactionFallback(config, actions, origin);
  return proposeSafeTransactions(
    config,
    safeActionsToTransactions(actions),
    origin,
  );
}

