// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../@openzeppelin/contracts-upgradable/security/ReentrancyGuardUpgradeable.sol";
import "../../@openzeppelin/contracts/utils/Address.sol";
import "../IP2pYieldProxy.sol";
import "./ClientCallable.sol";
import "./CalldataAllowed.sol";

abstract contract AnyFunctionExecutor is ReentrancyGuardUpgradeable, ClientCallable, CalldataAllowed, IP2pYieldProxy {
    using Address for address;

    function callAnyFunction(
        address _yieldProtocolAddress,
        bytes calldata _yieldProtocolCalldata
    )
        public
        virtual
        override
        onlyClient
        nonReentrant
        calldataShouldBeAllowed(_yieldProtocolAddress, _yieldProtocolCalldata)
    {
        _callAnyFunction(_yieldProtocolAddress, _yieldProtocolCalldata);
    }

    function _callAnyFunction(
        address _yieldProtocolAddress,
        bytes calldata _yieldProtocolCalldata
    ) internal {
        emit IP2pYieldProxy.P2pYieldProxy__CalledAsAnyFunction(_yieldProtocolAddress);
        _yieldProtocolAddress.functionCall(_yieldProtocolCalldata);
    }
}
