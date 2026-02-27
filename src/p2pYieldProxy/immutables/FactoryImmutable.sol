// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../p2pYieldProxyFactory/IP2pYieldProxyFactory.sol";
import "../P2pYieldProxyErrors.sol";

abstract contract FactoryImmutable {
    IP2pYieldProxyFactory internal immutable i_factory;

    constructor(address _factory) {
        require(_factory != address(0), P2pYieldProxy__ZeroAddressFactory());
        i_factory = IP2pYieldProxyFactory(_factory);
    }
}
