// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

interface IP2pMorphoProxyFactory {
    /// @notice Emitted when a distributor is marked as trusted
    event P2pMorphoProxyFactory__TrustedDistributorSet(address indexed _newTrustedDistributor);
    /// @notice Emitted when a distributor loses the trusted status
    event P2pMorphoProxyFactory__TrustedDistributorRemoved(address indexed _trustedDistributor);

    /// @notice Marks a distributor as trusted for URD claims
    /// @param _newTrustedDistributor The distributor address to trust
    function setTrustedDistributor(address _newTrustedDistributor) external;

    /// @notice Removes a distributor from the trusted list
    /// @param _trustedDistributor The distributor address to remove
    function removeTrustedDistributor(address _trustedDistributor) external;

    /// @notice Validates whether a URD claim can be executed
    /// @param _p2pOperatorToCheck The operator whose permissions should be verified
    /// @param _shouldCheckP2pOperator Indicates if operator verification is required
    /// @param _distributor The distributor address involved in the claim
    function checkMorphoUrdClaim(address _p2pOperatorToCheck, bool _shouldCheckP2pOperator, address _distributor)
        external
        view;

    /// @notice Returns whether a distributor is trusted
    /// @param _distributor The distributor address to query
    /// @return isTrusted True if the distributor is trusted, false otherwise
    function isTrustedDistributor(address _distributor) external view returns (bool);
}
