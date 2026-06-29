// SPDX-License-Identifier: LGPL-3.0-only
import SafeApiKit from "@safe-global/api-kit";
import Safe from "@safe-global/protocol-kit";
import { MetaTransactionData, OperationType } from "@safe-global/types-kit";
import { ethers as ethersLib } from "ethers";

import { arg } from "./cli";
import { safeProposalPath, writeJson } from "./files";
import type {
  ProtocolConfigFile,
  SafeProposal,
  SafeTransaction,
} from "./types";
import { address } from "./values";

export function safeTx(to: string, data: string): SafeTransaction {
  return {
    to,
    value: "0",
    data,
    operation: 0,
    contractMethod: null,
    contractInputsValues: null,
  };
}

export function safeBatch(
  config: ProtocolConfigFile,
  transactions: SafeTransaction[],
) {
  return {
    version: "1.0",
    chainId: config.chainId.toString(),
    createdAt: Date.now(),
    meta: {
      name: `${config.name} protocol wiring`,
      description:
        "Upgrade the existing bonding registry proxy and wire the Interfold protocol contracts.",
      txBuilderVersion: "1.18.0",
      createdFromSafeAddress: config.safe,
    },
    transactions,
  };
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
) {
  const prefix = safeAppPrefix(chainId);
  if (!prefix) return undefined;
  return `https://app.safe.global/transactions/tx?safe=${prefix}:${safeAddress}&id=multisig_${safeAddress}_${safeTxHash}`;
}

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
  if (!rpcUrl)
    throw new Error("Set RPC_URL so the Safe SDK can read the Safe.");
  return rpcUrl;
}

function toMetaTransaction(tx: SafeTransaction): MetaTransactionData {
  return {
    to: tx.to,
    value: tx.value,
    data: tx.data,
    operation:
      tx.operation === 1 ? OperationType.DelegateCall : OperationType.Call,
  };
}

export async function proposeSafeBatch(
  config: ProtocolConfigFile,
  transactions: SafeTransaction[],
): Promise<SafeProposal> {
  if (transactions.length === 0)
    throw new Error("Safe batch has no transactions to propose");

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
  const origin = arg("origin") ?? `Interfold ${config.name} protocol wiring`;
  const safeTransaction = await protocolKit.createTransaction({
    transactions: transactions.map(toMetaTransaction),
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

  const proposal = {
    safeTxHash,
    safeAddress: config.safe,
    proposer,
    nonce,
    transactionCount: transactions.length,
    origin,
    url: safeTransactionUrl(config.chainId, config.safe, safeTxHash),
    proposedAt: new Date().toISOString(),
  };
  writeJson(safeProposalPath(config), proposal);
  return proposal;
}
