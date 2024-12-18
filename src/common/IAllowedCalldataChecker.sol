// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;
import "./P2pStructs.sol";

interface IAllowedCalldataChecker {
    function isAllowedCalldata(
        address _target,
        bytes4 _selector,
        bytes calldata _calldataAfterSelector,
        P2pStructs.FunctionType _functionType
    ) external view returns (bool);
}
