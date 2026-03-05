// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../aave/@aave/IAaveProtocolDataProvider.sol";
import "../../aave/@aave/IAaveV3Pool.sol";
import "../../../p2pYieldProxy/P2pYieldProxy.sol";
import "./IP2pSparkProxy.sol";

error P2pSparkProxy__ZeroAddressAsset();
error P2pSparkProxy__AssetNotSupported(address _asset);
error P2pSparkProxy__NotP2pOperator(address _caller);
error P2pSparkProxy__ZeroAccruedRewards();
error P2pSparkProxy__ZeroSparkPool();
error P2pSparkProxy__ZeroSparkDataProvider();

/// @title P2pSparkProxy
/// @notice P2P Yield Proxy adapter for SparkLend (Aave V3 fork).
/// SparkLend uses the identical IAaveV3Pool interface.
/// Deposit: pool.supply(asset, amount, proxy, 0).
/// Withdrawal: pool.withdraw(asset, amount, proxy) — instant.
contract P2pSparkProxy is P2pYieldProxy, IP2pSparkProxy {
    IAaveV3Pool private immutable i_sparkPool;
    IAaveProtocolDataProvider private immutable i_sparkDataProvider;

    constructor(
        address _factory,
        address _p2pTreasury,
        address _allowedCalldataChecker,
        address _allowedCalldataByClientToP2pChecker,
        address _sparkPool,
        address _sparkDataProvider
    ) P2pYieldProxy(_factory, _p2pTreasury, _allowedCalldataChecker, _allowedCalldataByClientToP2pChecker) {
        require(_sparkPool != address(0), P2pSparkProxy__ZeroSparkPool());
        require(_sparkDataProvider != address(0), P2pSparkProxy__ZeroSparkDataProvider());
        i_sparkPool = IAaveV3Pool(_sparkPool);
        i_sparkDataProvider = IAaveProtocolDataProvider(_sparkDataProvider);
    }

    /// @notice Deposits into SparkLend.
    /// The factory calls deposit(_asset, _amount) where _asset is the underlying token.
    /// @param _asset The underlying asset address.
    /// @param _amount Amount of the asset to deposit.
    function deposit(address _asset, uint256 _amount) external override {
        require(_asset != address(0), P2pSparkProxy__ZeroAddressAsset());
        address spToken = getSpToken(_asset);
        bytes memory supplyCalldata = abi.encodeCall(IAaveV3Pool.supply, (_asset, _amount, address(this), 0));
        _deposit(spToken, address(i_sparkPool), supplyCalldata, _asset, _amount, false);
    }

    /// @inheritdoc IP2pSparkProxy
    function withdraw(address _asset, uint256 _amount) external override onlyClient {
        require(_asset != address(0), P2pSparkProxy__ZeroAddressAsset());
        address spToken = getSpToken(_asset);
        bytes memory withdrawCalldata = abi.encodeCall(IAaveV3Pool.withdraw, (_asset, _amount, address(this)));
        _withdraw(spToken, _asset, address(i_sparkPool), withdrawCalldata, 0);
    }

    /// @inheritdoc IP2pSparkProxy
    function withdrawAccruedRewards(address _asset) external override onlyP2pOperator {
        require(_asset != address(0), P2pSparkProxy__ZeroAddressAsset());
        address spToken = getSpToken(_asset);

        int256 accruedBefore = calculateAccruedRewards(spToken, _asset);
        require(accruedBefore > 0, P2pSparkProxy__ZeroAccruedRewards());

        bytes memory withdrawCalldata =
            abi.encodeCall(IAaveV3Pool.withdraw, (_asset, uint256(accruedBefore), address(this)));
        uint256 withdrawn = _withdraw(spToken, _asset, address(i_sparkPool), withdrawCalldata, 0);
        _requireWithdrawnWithinAccrued(withdrawn, accruedBefore, 0);
    }

    /// @notice Calculates accrued rewards as current spToken balance minus tracked user principal.
    function calculateAccruedRewards(address, address _asset)
        public
        view
        override
        returns (int256)
    {
        address spToken = getSpToken(_asset);
        uint256 currentAmount = IERC20(spToken).balanceOf(address(this));
        uint256 userPrincipal = getUserPrincipal(_asset);
        return int256(currentAmount) - int256(userPrincipal);
    }

    /// @inheritdoc IP2pSparkProxy
    function getSparkPool() external view override returns (address) {
        return address(i_sparkPool);
    }

    /// @inheritdoc IP2pSparkProxy
    function getSparkDataProvider() external view override returns (address) {
        return address(i_sparkDataProvider);
    }

    /// @inheritdoc IP2pSparkProxy
    function getSpToken(address _asset) public view override returns (address) {
        try i_sparkDataProvider.getReserveTokensAddresses(_asset) returns (address spToken, address, address) {
            require(spToken != address(0), P2pSparkProxy__AssetNotSupported(_asset));
            return spToken;
        } catch {
            revert P2pSparkProxy__AssetNotSupported(_asset);
        }
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(P2pYieldProxy)
        returns (bool)
    {
        return interfaceId == type(IP2pSparkProxy).interfaceId || super.supportsInterface(interfaceId);
    }

    function _getP2pOperator() internal view override returns (address) {
        return i_factory.getP2pOperator();
    }

    function _revertNotP2pOperator(address _caller) internal pure override {
        revert P2pSparkProxy__NotP2pOperator(_caller);
    }
}
