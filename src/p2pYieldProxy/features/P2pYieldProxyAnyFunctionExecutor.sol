// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../@openzeppelin/contracts/utils/Address.sol";
import "../IP2pYieldProxy.sol";
import "./P2pYieldProxyClientCallable.sol";
import "./P2pYieldProxyCalldataAllowed.sol";

abstract contract P2pYieldProxyAnyFunctionExecutor is P2pYieldProxyClientCallable, P2pYieldProxyCalldataAllowed {
    using Address for address;

    function _callAnyFunction(
        address _yieldProtocolAddress,
        bytes calldata _yieldProtocolCalldata
    ) internal {
        emit IP2pYieldProxy.P2pYieldProxy__CalledAsAnyFunction(_yieldProtocolAddress);
        _yieldProtocolAddress.functionCall(_yieldProtocolCalldata);
    }
}
