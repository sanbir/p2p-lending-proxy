// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../p2pYieldProxy/P2pYieldProxy.sol";
import "../../../common/IMorphoBundler.sol";
import "../../../@openzeppelin/contracts/interfaces/IERC4626.sol";
import "../p2pMorphoProxyFactory/IP2pMorphoProxyFactory.sol";
import "./IP2pMorphoProxy.sol";

error P2pMorphoProxy__UnsupportedAsset(address _asset);
error P2pMorphoProxy__NothingClaimed();
error P2pMorphoProxy__NotP2pOperator(address _caller);
error P2pMorphoProxy__ZeroAccruedRewards();

contract P2pMorphoProxy is P2pYieldProxy, IP2pMorphoProxy {
    using SafeERC20 for IERC20;

    IMorphoBundler private immutable i_morphoBundler;

    modifier onlyP2pOperator() {
        address p2pOperator = i_factory.getP2pOperator();
        require(msg.sender == p2pOperator, P2pMorphoProxy__NotP2pOperator(msg.sender));
        _;
    }

    constructor(
        address _factory,
        address _p2pTreasury,
        address _allowedCalldataChecker,
        address _morphoBundler
    ) P2pYieldProxy(_factory, _p2pTreasury, _allowedCalldataChecker) {
        i_morphoBundler = IMorphoBundler(_morphoBundler);
    }

    function deposit(address _asset, uint256 _amount) external override(IP2pMorphoProxy, P2pYieldProxy) {
        address vault = _vaultForAsset(_asset);
        uint256 minShares = IERC4626(vault).convertToShares(_amount);
        bytes[] memory dataForMulticall = new bytes[](1);
        dataForMulticall[0] =
            abi.encodeCall(IMorphoBundler.erc4626Deposit, (vault, _amount, minShares, address(this)));
        bytes memory depositCalldata = abi.encodeCall(IMorphoBundler.multicall, (dataForMulticall));
        _deposit(vault, address(i_morphoBundler), depositCalldata, _asset, _amount, true);
    }

    function withdraw(address _vault, uint256 _shares) external override onlyClient {
        uint256 minAssets = IERC4626(_vault).convertToAssets(_shares);
        bytes[] memory dataForMulticall = new bytes[](1);
        dataForMulticall[0] = abi.encodeCall(
            IMorphoBundler.erc4626Redeem, (_vault, _shares, minAssets, address(this), address(this))
        );
        bytes memory redeemCalldata = abi.encodeCall(IMorphoBundler.multicall, (dataForMulticall));
        _withdraw(_vault, _assetForVault(_vault), address(i_morphoBundler), redeemCalldata, _shares);
    }

    function withdrawAccruedRewards(address _vault) external onlyP2pOperator {
        address asset = _assetForVault(_vault);
        int256 amount = calculateAccruedRewards(_vault, asset);
        require(amount > 0, P2pMorphoProxy__ZeroAccruedRewards());

        uint256 shares = IERC4626(_vault).convertToShares(uint256(amount));
        uint256 minAssets = IERC4626(_vault).convertToAssets(shares);
        bytes[] memory dataForMulticall = new bytes[](1);
        dataForMulticall[0] = abi.encodeCall(
            IMorphoBundler.erc4626Redeem, (_vault, shares, minAssets, address(this), address(this))
        );
        bytes memory redeemCalldata = abi.encodeCall(IMorphoBundler.multicall, (dataForMulticall));
        _withdraw(_vault, asset, address(i_morphoBundler), redeemCalldata, shares);
    }

    function morphoUrdClaim(address _distributor, address _reward, uint256 _amount, bytes32[] calldata _proof)
        external
        nonReentrant
    {
        bool shouldCheckP2pOperator;
        if (msg.sender != s_client) {
            shouldCheckP2pOperator = true;
        }
        IP2pMorphoProxyFactory(address(i_factory)).checkMorphoUrdClaim(msg.sender, shouldCheckP2pOperator, _distributor);

        bytes memory urdClaimCalldata =
            abi.encodeCall(IMorphoBundler.urdClaim, (_distributor, address(this), _reward, _amount, _proof, false));
        bytes[] memory dataForMulticall = new bytes[](1);
        dataForMulticall[0] = urdClaimCalldata;

        uint256 assetAmountBefore = IERC20(_reward).balanceOf(address(this));
        i_morphoBundler.multicall(dataForMulticall);
        uint256 assetAmountAfter = IERC20(_reward).balanceOf(address(this));

        uint256 newAssetAmount = assetAmountAfter - assetAmountBefore;
        require(newAssetAmount > 0, P2pMorphoProxy__NothingClaimed());

        uint256 p2pAmount = (newAssetAmount * (10_000 - s_clientBasisPoints)) / 10_000;
        uint256 clientAmount = newAssetAmount - p2pAmount;

        if (p2pAmount > 0) {
            IERC20(_reward).safeTransfer(i_p2pTreasury, p2pAmount);
        }
        IERC20(_reward).safeTransfer(s_client, clientAmount);

        emit P2pMorphoProxy__ClaimedMorphoUrd(_distributor, _reward, newAssetAmount, p2pAmount, clientAmount);
    }

    function calculateAccruedRewards(address _vault, address _asset)
        public
        view
        override(P2pYieldProxy)
        returns (int256)
    {
        uint256 shares = IERC20(_vault).balanceOf(address(this));
        uint256 currentAmount = IERC4626(_vault).convertToAssets(shares);
        uint256 userPrincipal = getUserPrincipal(_asset);
        return int256(currentAmount) - int256(userPrincipal);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(P2pYieldProxy, IERC165)
        returns (bool)
    {
        return interfaceId == type(IP2pMorphoProxy).interfaceId || super.supportsInterface(interfaceId);
    }

    function _vaultForAsset(address _asset) private view returns (address vault) {
        vault = IP2pMorphoProxyFactory(address(i_factory)).getVaultForAsset(_asset);
        if (vault != address(0)) {
            return vault;
        }
        revert P2pMorphoProxy__UnsupportedAsset(_asset);
    }

    function _assetForVault(address _vault) private view returns (address asset) {
        asset = IP2pMorphoProxyFactory(address(i_factory)).getAssetForVault(_vault);
        if (asset != address(0)) {
            return asset;
        }
        revert P2pMorphoProxy__UnsupportedAsset(_vault);
    }
}
