// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../p2pLendingProxyFactory/IP2pLendingProxyFactory.sol";

/// @dev External interface of P2pMorphoProxyFactory
interface IP2pMorphoProxyFactory is IP2pLendingProxyFactory {

    /// @dev Sets the trusted distributor
    /// @param _newTrustedDistributor The new trusted distributor
    function setTrustedDistributor(
        address _newTrustedDistributor
    ) external;

    /// @dev Removes the trusted distributor
    /// @param _trustedDistributor The trusted distributor
    function removeTrustedDistributor(
        address _trustedDistributor
    ) external;

    /// @dev Checks if the morpho URD claim is valid
    /// @param _p2pOperatorToCheck The P2pOperator to check
    /// @param _shouldCheckP2pOperator If the P2pOperator should be checked
    /// @param _distributor The distributor address
    function checkMorphoUrdClaim(
        address _p2pOperatorToCheck,
        bool _shouldCheckP2pOperator,
        address _distributor
    ) external view;

    /// @dev Checks if the distributor is trusted
    /// @param _distributor The distributor address
    /// @return If the distributor is trusted or not
    function isTrustedDistributor(address _distributor) external view returns (bool);
}
