// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @dev External interface of P2pLendingProxyFactory
interface IP2pLendingProxyFactory is IERC165 {

    /// @notice Allow selectors (function signatures) for clients to call on LendingNetwork via P2pLendingProxy
    /// @param _selectors selectors (function signatures) to allow for clients
    function setAllowedSelectorsForClient(bytes4[] calldata _selectors) external;

    /// @notice Disallow selectors (function signatures) for clients to call on LendingNetwork via P2pLendingProxy
    /// @param _selectors selectors (function signatures) to disallow for clients
    function removeAllowedSelectorsForClient(bytes4[] calldata _selectors) external;

    /// @notice Computes the address of a P2pLendingProxy created by `_createP2pLendingProxy` function
    /// @dev P2pLendingProxy instances are guaranteed to have the same address if _feeDistributorInstance is the same
    /// @param _feeDistributorInstance The address of FeeDistributor instance
    /// @return address client P2pLendingProxy instance that will be or has been deployed
    function predictP2pLendingProxyAddress(
        address _feeDistributorInstance
    ) external view returns (address);

    /// @notice Deploy P2pLendingProxy instance if not deployed before
    /// @param _feeDistributorInstance The address of FeeDistributor instance
    /// @return p2pLendingProxyInstance client P2pLendingProxy instance that has been deployed
    function createP2pLendingProxy(
        address _feeDistributorInstance
    ) external returns(address p2pLendingProxyInstance);

    /// @notice Returns a template set by P2P to be used for new P2pLendingProxy instances
    /// @return a template set by P2P to be used for new P2pLendingProxy instances
    function getReferenceP2pLendingProxy() external view returns (address);
}
