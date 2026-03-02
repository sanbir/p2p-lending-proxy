// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../interfaces/IAaveProtocolDataProvider.sol";
import "../../../interfaces/IAaveV3Pool.sol";
import "../../../access/P2pOperatorCallable.sol";
import "../../../p2pYieldProxy/P2pYieldProxy.sol";
import "./IP2pAaveProxy.sol";

error P2pAaveProxy__ZeroAddressAsset();
error P2pAaveProxy__AssetNotSupported(address _asset);
error P2pAaveProxy__NotP2pOperator(address _caller);
error P2pAaveProxy__ZeroAccruedRewards();
error P2pAaveProxy__ZeroAavePool();
error P2pAaveProxy__ZeroAaveDataProvider();

contract P2pAaveProxy is P2pYieldProxy, P2pOperatorCallable, IP2pAaveProxy {
    IAaveV3Pool private immutable i_aavePool;
    IAaveProtocolDataProvider private immutable i_aaveDataProvider;

    constructor(
        address _factory,
        address _p2pTreasury,
        address _allowedCalldataChecker,
        address _aavePool,
        address _aaveDataProvider
    ) P2pYieldProxy(_factory, _p2pTreasury, _allowedCalldataChecker) {
        require(_aavePool != address(0), P2pAaveProxy__ZeroAavePool());
        require(_aaveDataProvider != address(0), P2pAaveProxy__ZeroAaveDataProvider());
        i_aavePool = IAaveV3Pool(_aavePool);
        i_aaveDataProvider = IAaveProtocolDataProvider(_aaveDataProvider);
    }

    function deposit(address _asset, uint256 _amount) external override {
        require(_asset != address(0), P2pAaveProxy__ZeroAddressAsset());
        address aToken = getAToken(_asset);
        bytes memory supplyCalldata = abi.encodeCall(IAaveV3Pool.supply, (_asset, _amount, address(this), 0));
        _deposit(aToken, address(i_aavePool), supplyCalldata, _asset, _amount, false);
    }

    function withdraw(address _asset, uint256 _amount) external override onlyClient {
        require(_asset != address(0), P2pAaveProxy__ZeroAddressAsset());
        address aToken = getAToken(_asset);
        bytes memory withdrawCalldata = abi.encodeCall(IAaveV3Pool.withdraw, (_asset, _amount, address(this)));
        _withdraw(aToken, _asset, address(i_aavePool), withdrawCalldata, 0);
    }

    function withdrawAccruedRewards(address _asset) external override onlyP2pOperator {
        require(_asset != address(0), P2pAaveProxy__ZeroAddressAsset());
        address aToken = getAToken(_asset);

        int256 accruedBefore = calculateAccruedRewards(aToken, _asset);
        require(accruedBefore > 0, P2pAaveProxy__ZeroAccruedRewards());

        bytes memory withdrawCalldata =
            abi.encodeCall(IAaveV3Pool.withdraw, (_asset, uint256(accruedBefore), address(this)));
        uint256 withdrawn = _withdraw(aToken, _asset, address(i_aavePool), withdrawCalldata, 0);
        _requireWithdrawnWithinAccrued(withdrawn, accruedBefore, 0);
    }

    function calculateAccruedRewards(address, address _asset)
        public
        view
        override
        returns (int256)
    {
        address aToken = getAToken(_asset);
        uint256 currentAmount = IERC20(aToken).balanceOf(address(this));
        uint256 userPrincipal = getUserPrincipal(_asset);
        return int256(currentAmount) - int256(userPrincipal);
    }

    function getAavePool() external view override returns (address) {
        return address(i_aavePool);
    }

    function getAaveDataProvider() external view override returns (address) {
        return address(i_aaveDataProvider);
    }

    function getAToken(address _asset) public view override returns (address) {
        try i_aaveDataProvider.getReserveTokensAddresses(_asset) returns (address aToken, address, address) {
            require(aToken != address(0), P2pAaveProxy__AssetNotSupported(_asset));
            return aToken;
        } catch {
            revert P2pAaveProxy__AssetNotSupported(_asset);
        }
    }

    function _getP2pOperator() internal view override returns (address) {
        return i_factory.getP2pOperator();
    }

    function _revertNotP2pOperator(address _caller) internal pure override {
        revert P2pAaveProxy__NotP2pOperator(_caller);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(P2pYieldProxy)
        returns (bool)
    {
        return interfaceId == type(IP2pAaveProxy).interfaceId || super.supportsInterface(interfaceId);
    }
}
