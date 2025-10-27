// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../p2pYieldProxyFactory/IP2pYieldProxyFactory.sol";

interface IP2pMorphoProxyFactory is IP2pYieldProxyFactory {
    event P2pMorphoProxyFactory__TrustedDistributorSet(address indexed _newTrustedDistributor);
    event P2pMorphoProxyFactory__TrustedDistributorRemoved(address indexed _trustedDistributor);
    event P2pMorphoProxyFactory__AssetVaultPairSet(address indexed _asset, address indexed _vault);
    event P2pMorphoProxyFactory__AssetVaultPairRemoved(address indexed _asset, address indexed _vault);

    function setTrustedDistributor(address _newTrustedDistributor) external;

    function removeTrustedDistributor(address _trustedDistributor) external;

    function checkMorphoUrdClaim(address _p2pOperatorToCheck, bool _shouldCheckP2pOperator, address _distributor)
        external
        view;

    function isTrustedDistributor(address _distributor) external view returns (bool);

    function setAssetVaultPair(address _asset, address _vault) external;

    function removeAssetVaultPair(address _asset) external;

    function getVaultForAsset(address _asset) external view returns (address);

    function getAssetForVault(address _vault) external view returns (address);
}
