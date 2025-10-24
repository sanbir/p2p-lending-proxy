// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "./IAllowedCalldataChecker.sol";
import "./P2pStructs.sol";

/// @dev Error for when the calldata is too short
error AllowedCalldataChecker__DataTooShort();

/// @title AllowedCalldataChecker
/// @author P2P Validator <info@p2p.org>
/// @notice Abstract contract for checking if a calldata is allowed
abstract contract AllowedCalldataChecker is IAllowedCalldataChecker {

    /// @dev Modifier for checking if a calldata is allowed
    /// @param _lendingProtocolAddress The address of the lending protocol
    /// @param _lendingProtocolCalldata The calldata (encoded signature + arguments) to be passed to the lending protocol
    /// @param _functionType Deposit, Withdraw, or None
    modifier calldataShouldBeAllowed(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,
        P2pStructs.FunctionType _functionType
    ) {
        // validate lendingProtocolCalldata for lendingProtocolAddress
        bytes4 selector = _getFunctionSelector(_lendingProtocolCalldata);
        checkCalldata(
            _lendingProtocolAddress,
            selector,
            _lendingProtocolCalldata[4:],
            _functionType
        );
        _;
    }

    /// @notice Returns function selector (first 4 bytes of data)
    /// @param _data calldata (encoded signature + arguments)
    /// @return functionSelector function selector
    function _getFunctionSelector(
        bytes calldata _data
    ) private pure returns (bytes4 functionSelector) {
        require (_data.length >= 4, AllowedCalldataChecker__DataTooShort());
        return bytes4(_data[:4]);
    }

    /// @notice Checks if the calldata is allowed
    /// @param _target The address of the lending protocol
    /// @param _selector The selector of the function
    /// @param _calldataAfterSelector The calldata after the selector
    /// @param _functionType Deposit, Withdraw, or None
    function checkCalldata(
        address _target,
        bytes4 _selector,
        bytes calldata _calldataAfterSelector,
        P2pStructs.FunctionType _functionType
    ) public virtual view;
}
