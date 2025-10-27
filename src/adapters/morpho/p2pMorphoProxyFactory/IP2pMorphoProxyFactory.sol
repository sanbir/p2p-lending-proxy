// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../p2pYieldProxyFactory/IP2pYieldProxyFactory.sol";

interface IP2pMorphoProxyFactory is IP2pYieldProxyFactory {
    event P2pMorphoProxyFactory__TrustedDistributorSet(address indexed _newTrustedDistributor);
    event P2pMorphoProxyFactory__TrustedDistributorRemoved(address indexed _trustedDistributor);

    function setTrustedDistributor(address _newTrustedDistributor) external;

    function removeTrustedDistributor(address _trustedDistributor) external;

    function checkMorphoUrdClaim(address _p2pOperatorToCheck, bool _shouldCheckP2pOperator, address _distributor)
        external
        view;

    function isTrustedDistributor(address _distributor) external view returns (bool);
}
