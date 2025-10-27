// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../@openzeppelin/contracts/interfaces/IERC4626.sol";
import "../../../common/IMorphoBundler.sol";
import "../../../p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "./IP2pMorphoProxyFactory.sol";
import "../p2pMorphoProxy/P2pMorphoProxy.sol";

error P2pMorphoProxyFactory__DistributorNotTrusted(address _distributor);
error P2pMorphoProxyFactory__ZeroTrustedDistributorAddress();
error P2pMorphoProxyFactory__ZeroAssetAddress();
error P2pMorphoProxyFactory__ZeroVaultAddress();
error P2pMorphoProxyFactory__VaultAssetMismatch(address _asset, address _vault);
error P2pMorphoProxyFactory__AssetAlreadyConfigured(address _asset, address _existingVault);
error P2pMorphoProxyFactory__VaultAlreadyConfigured(address _vault, address _existingAsset);
error P2pMorphoProxyFactory__AssetVaultPairNotConfigured(address _asset);

contract P2pMorphoProxyFactory is P2pYieldProxyFactory, IP2pMorphoProxyFactory {
    IMorphoBundler private immutable i_morphoBundler;

    mapping(address => bool) private s_trustedDistributors;
    mapping(address => address) private s_assetToVault;
    mapping(address => address) private s_vaultToAsset;

    constructor(
        address _p2pSigner,
        address _p2pTreasury,
        address _allowedCalldataChecker,
        address _morphoBundler
    ) P2pYieldProxyFactory(_p2pSigner) {
        i_morphoBundler = IMorphoBundler(_morphoBundler);
        i_referenceP2pYieldProxy =
            new P2pMorphoProxy(address(this), _p2pTreasury, _allowedCalldataChecker, _morphoBundler);
    }

    function setTrustedDistributor(address _newTrustedDistributor) external onlyP2pOperator {
        require(_newTrustedDistributor != address(0), P2pMorphoProxyFactory__ZeroTrustedDistributorAddress());
        s_trustedDistributors[_newTrustedDistributor] = true;
        emit P2pMorphoProxyFactory__TrustedDistributorSet(_newTrustedDistributor);
    }

    function removeTrustedDistributor(address _trustedDistributor) external onlyP2pOperator {
        s_trustedDistributors[_trustedDistributor] = false;
        emit P2pMorphoProxyFactory__TrustedDistributorRemoved(_trustedDistributor);
    }

    function setAssetVaultPair(address _asset, address _vault) external override onlyP2pOperator {
        require(_asset != address(0), P2pMorphoProxyFactory__ZeroAssetAddress());
        require(_vault != address(0), P2pMorphoProxyFactory__ZeroVaultAddress());

        require(IERC4626(_vault).asset() == _asset, P2pMorphoProxyFactory__VaultAssetMismatch(_asset, _vault));

        address existingVault = s_assetToVault[_asset];
        if (existingVault != address(0) && existingVault != _vault) {
            revert P2pMorphoProxyFactory__AssetAlreadyConfigured(_asset, existingVault);
        }

        address existingAsset = s_vaultToAsset[_vault];
        if (existingAsset != address(0) && existingAsset != _asset) {
            revert P2pMorphoProxyFactory__VaultAlreadyConfigured(_vault, existingAsset);
        }

        s_assetToVault[_asset] = _vault;
        s_vaultToAsset[_vault] = _asset;

        emit P2pMorphoProxyFactory__AssetVaultPairSet(_asset, _vault);
    }

    function removeAssetVaultPair(address _asset) external override onlyP2pOperator {
        address vault = s_assetToVault[_asset];
        if (vault == address(0)) {
            revert P2pMorphoProxyFactory__AssetVaultPairNotConfigured(_asset);
        }

        delete s_assetToVault[_asset];
        delete s_vaultToAsset[vault];

        emit P2pMorphoProxyFactory__AssetVaultPairRemoved(_asset, vault);
    }

    function getVaultForAsset(address _asset) external view override returns (address) {
        return s_assetToVault[_asset];
    }

    function getAssetForVault(address _vault) external view override returns (address) {
        return s_vaultToAsset[_vault];
    }

    function checkMorphoUrdClaim(address _p2pOperatorToCheck, bool _shouldCheckP2pOperator, address _distributor)
        external
        view
        override
    {
        if (_shouldCheckP2pOperator) {
            require(getP2pOperator() == _p2pOperatorToCheck, P2pOperator__UnauthorizedAccount(_p2pOperatorToCheck));
        }
        require(s_trustedDistributors[_distributor], P2pMorphoProxyFactory__DistributorNotTrusted(_distributor));
    }

    function isTrustedDistributor(address _distributor) external view override returns (bool) {
        return s_trustedDistributors[_distributor];
    }

    function getP2pOperator() public view override(P2pYieldProxyFactory, IP2pYieldProxyFactory) returns (address) {
        return super.getP2pOperator();
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(P2pYieldProxyFactory, IERC165)
        returns (bool)
    {
        return interfaceId == type(IP2pMorphoProxyFactory).interfaceId || super.supportsInterface(interfaceId);
    }
}
