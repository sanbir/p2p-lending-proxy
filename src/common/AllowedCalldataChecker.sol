// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "./IAllowedCalldataChecker.sol";
import "./P2pStructs.sol";

error AllowedCalldataChecker__DataTooShort();

abstract contract AllowedCalldataChecker is IAllowedCalldataChecker {

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

    function checkCalldata(
        address _target,
        bytes4 _selector,
        bytes calldata _calldataAfterSelector,
        P2pStructs.FunctionType _functionType
    ) public virtual view;
}
