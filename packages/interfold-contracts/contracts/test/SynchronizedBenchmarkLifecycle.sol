// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import { Proxy } from "@openzeppelin/contracts/proxy/Proxy.sol";
import { Interfold } from "../Interfold.sol";
import { IInterfold } from "../interfaces/IInterfold.sol";
import { BfvProtocol } from "../lib/BfvProtocol.sol";
import { ActiveCryptoConfig } from "../lib/ActiveCryptoConfig.sol";
import { InterfoldLifecycle } from "../lib/InterfoldLifecycle.sol";
import {
    SynchronizedDecryptionVerifier
} from "../verifiers/bfv/SynchronizedDecryptionVerifier.sol";

/// @dev Link only on the private benchmark chain. Interfold still takes the request snapshot;
/// all lifecycle selectors except the quote check delegate to the normal library.
contract SynchronizedBenchmarkLifecycle is Proxy {
    function _implementation() internal pure override returns (address) {
        return address(InterfoldLifecycle);
    }

    function validateQuoteLimit(
        address feeToken,
        address expectedToken,
        uint8 paramSet,
        uint8 size,
        bytes32 expectedId,
        uint256 maxFee,
        uint256 fee
    ) external view {
        if (
            block.chainid != 31337 || size != BfvProtocol.MINIMUM_COMMITTEE_SIZE
        ) revert IInterfold.UnsupportedCryptoConfig();
        bytes32 id = paramSet == BfvProtocol.SECURE_PARAM_SET
            ? BfvProtocol.SYNC_SECURE_8192_MINIMUM_CONFIG_ID
            : BfvProtocol.SYNC_INSECURE_64_MINIMUM_CONFIG_ID;
        if (expectedId != id)
            revert IInterfold.CryptoConfigChanged(expectedId, id);
        Interfold controller = Interfold(address(this));
        SynchronizedDecryptionVerifier verifier = SynchronizedDecryptionVerifier(
                address(
                    controller.getDecryptionVerifier(
                        BfvProtocol.ENCRYPTION_SCHEME_ID
                    )
                )
            );
        if (
            verifier.CRYPTO_CONFIG_ID() != id ||
            address(verifier.REGISTRY()) !=
            address(controller.ciphernodeRegistry())
        ) revert IInterfold.UnsupportedCryptoConfig();
        // Reuse the normal token, supported parameter slot, committee and fee checks. Only the
        // quote identity above differs. The caller stores the original synchronized identity.
        InterfoldLifecycle.validateQuoteLimit(
            feeToken,
            expectedToken,
            paramSet,
            size,
            ActiveCryptoConfig.configIdForRequest(paramSet, size),
            maxFee,
            fee
        );
    }
}
