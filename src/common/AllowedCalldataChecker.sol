// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../p2pLendingProxyFactory/P2pLendingProxyFactoryStructs.sol";

error AllowedCalldataChecker__DataTooShort();
error AllowedCalldataChecker__NotAllowedToCall(
    address _target,
    bytes4 _selector
);

abstract contract AllowedCalldataChecker {

    modifier calldataShouldBeAllowed(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata
    ) {
        // validate lendingProtocolCalldata for lendingProtocolAddress
        bytes4 selector = _getFunctionSelector(_lendingProtocolCalldata);
        bool isAllowed = isAllowedCalldata(
            _lendingProtocolAddress,
            selector,
            _lendingProtocolCalldata[4:],
            P2pLendingProxyFactoryStructs.FunctionType.Deposit
        );

        require (isAllowed, AllowedCalldataChecker__NotAllowedToCall(_lendingProtocolAddress, selector));
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

    function isAllowedCalldata(
        address _target,
        bytes4 _selector,
        bytes calldata _calldataAfterSelector,
        P2pLendingProxyFactoryStructs.FunctionType _functionType
    ) public virtual view returns (bool);
}
