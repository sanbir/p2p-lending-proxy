// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "./P2pStructs.sol";

/// @title IAllowedCalldataChecker
/// @author P2P Validator <info@p2p.org>
/// @notice Interface for checking if a calldata is allowed
interface IAllowedCalldataChecker {
    function checkCalldata(
        address _target,
        bytes4 _selector,
        bytes calldata _calldataAfterSelector,
        P2pStructs.FunctionType _functionType
    ) external view;
}
