// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../storage/P2pYieldProxyClientStorage.sol";
import "../P2pYieldProxyErrors.sol";

abstract contract P2pYieldProxyClientCallable is P2pYieldProxyClientStorage {
    modifier onlyClient() {
        if (msg.sender != s_client) {
            revert P2pYieldProxy__NotClientCalled(msg.sender, s_client);
        }
        _;
    }
}
