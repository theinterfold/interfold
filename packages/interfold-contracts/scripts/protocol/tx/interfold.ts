// SPDX-License-Identifier: LGPL-3.0-only
import { ethers as ethersLib } from "ethers";

import { bfvParamSetConfigsForChain } from "../../utils";
import { BFV_PARAMS } from "../constants";
import { safeTx } from "../safe";
import type {
  ProtocolConfigFile,
  ProtocolContracts,
  ProtocolInterfaces,
  SafeTransaction,
} from "../types";
import { encodeBfvParams, feeAssetConfig, optionalAddress } from "../values";

export function appendInterfoldTxs(
  txs: SafeTransaction[],
  config: ProtocolConfigFile,
  c: ProtocolContracts,
  i: ProtocolInterfaces,
) {
  txs.push(
    safeTx(
      c.interfold,
      i.interfold.encodeFunctionData("setE3RefundManager", [c.e3RefundManager]),
    ),
    safeTx(
      c.interfold,
      i.interfold.encodeFunctionData("setSlashingManager", [c.slashingManager]),
    ),
  );

  if (BigInt(config.interfold.markFailedGracePeriod) > 0n) {
    txs.push(
      safeTx(
        c.interfold,
        i.interfold.encodeFunctionData("setMarkFailedGracePeriod", [
          BigInt(config.interfold.markFailedGracePeriod),
        ]),
      ),
    );
  }
  if (config.interfold.allowFeeToken) {
    txs.push(
      safeTx(
        c.interfold,
        i.interfold.encodeFunctionData("setFeeTokenAllowed", [
          config.feeToken,
          true,
        ]),
      ),
    );
  }
  appendCommitteeAndPricingTxs(txs, config, c, i);
}

function appendCommitteeAndPricingTxs(
  txs: SafeTransaction[],
  config: ProtocolConfigFile,
  c: ProtocolContracts,
  i: ProtocolInterfaces,
) {
  for (const threshold of config.interfold.committeeThresholds) {
    txs.push(
      safeTx(
        c.interfold,
        i.interfold.encodeFunctionData("setCommitteeThresholds", [
          BigInt(threshold.size),
          [BigInt(threshold.quorum), BigInt(threshold.total)],
        ]),
      ),
    );
  }
  if (config.interfold.registerActiveBfvParamSet) {
    for (const bfvConfig of bfvParamSetConfigsForChain(config.chainId)) {
      const activeParams =
        bfvConfig.paramSet === 0
          ? BFV_PARAMS.insecure512
          : bfvConfig.paramSet === 1
            ? BFV_PARAMS.secure8192
            : BFV_PARAMS.secure16384;
      txs.push(
        safeTx(
          c.interfold,
          i.interfold.encodeFunctionData("setParamSet", [
            bfvConfig.paramSet,
            encodeBfvParams(activeParams),
          ]),
        ),
      );
    }
  }
  txs.push(
    safeTx(
      c.interfold,
      i.interfold.encodeFunctionData("setFeeAssetConfig", [
        feeAssetConfig(config),
      ]),
    ),
  );
  appendVerifierTxs(txs, config, c, i);
}

function appendVerifierTxs(
  txs: SafeTransaction[],
  config: ProtocolConfigFile,
  c: ProtocolContracts,
  i: ProtocolInterfaces,
) {
  const decryption =
    c.decryptionVerifier ??
    optionalAddress(config.verifiers?.decryptionVerifier, "decryptionVerifier");
  if (decryption) {
    txs.push(
      safeTx(
        c.interfold,
        i.interfold.encodeFunctionData("setDecryptionVerifier", [
          ethersLib.id("fhe.rs:BFV"),
          decryption,
        ]),
      ),
    );
  }
  const pk =
    c.pkVerifier ?? optionalAddress(config.verifiers?.pkVerifier, "pkVerifier");
  if (pk) {
    txs.push(
      safeTx(
        c.interfold,
        i.interfold.encodeFunctionData("setPkVerifier", [
          ethersLib.id("fhe.rs:BFV"),
          pk,
        ]),
      ),
    );
  }
  // The compute-receipt verifier. Each E3 snapshots this at request time, so a later change never
  // affects an E3 in flight; leaving it unset means no protocol-level ciphertext verification.
  //
  // Three sources, in precedence order. A verifier deployed by this run wins, because it is the one
  // the rest of the deployment just wired up. Otherwise the config decides, and it is read from both
  // shapes `ProtocolConfig` declares: `verifiers.ciphertextVerifier` groups it with the other
  // verifier addresses, and the top-level field predates that grouping. Preferring one config shape
  // and ignoring the other would silently resolve to `undefined` for any config written against the
  // other, and an unset verifier is indistinguishable from one deliberately omitted — it just means
  // no ciphertext verification, with nothing to say it was a mistake.
  const ciphertext =
    c.ciphertextVerifier ??
    optionalAddress(
      config.verifiers?.ciphertextVerifier ?? config.ciphertextVerifier,
      "ciphertextVerifier",
    );
  if (ciphertext) {
    txs.push(
      safeTx(
        c.interfold,
        i.interfold.encodeFunctionData("setCiphertextVerifier", [
          ethersLib.id("fhe.rs:BFV"),
          ciphertext,
        ]),
      ),
    );
  }
  if (config.bindInitialE3Program) {
    const program = new ethersLib.Interface([
      "function bindInterfold(address interfold)",
    ]);
    txs.push(
      safeTx(
        config.e3Programs[0],
        program.encodeFunctionData("bindInterfold", [c.interfold]),
      ),
    );
  }
}
