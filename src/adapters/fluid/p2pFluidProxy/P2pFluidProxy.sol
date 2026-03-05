// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../p2pYieldProxy/P2pYieldProxy.sol";
import "../../../p2pYieldProxy/interfaces/IDepositable.sol";
import "../../../@openzeppelin/contracts/interfaces/IERC4626.sol";
import "./IP2pFluidProxy.sol";

error P2pFluidProxy__ZeroFTokenAddress();
error P2pFluidProxy__NotP2pOperator(address _caller);
error P2pFluidProxy__ZeroAccruedRewards();

/// @title P2pFluidProxy
/// @notice P2P Yield Proxy adapter for Fluid fTokens (ERC-4626 lending vaults).
/// fTokens are standard ERC-4626 with yield from lending interest + rewards rate model.
/// Deposit: fToken.deposit(amount, proxy) — standard ERC-4626.
/// Withdrawal: fToken.redeem(shares, proxy, proxy) — instant, no queue.
contract P2pFluidProxy is P2pYieldProxy, IP2pFluidProxy {
    using SafeERC20 for IERC20;

    constructor(
        address _factory,
        address _p2pTreasury,
        address _allowedCalldataChecker,
        address _allowedCalldataByClientToP2pChecker
    ) P2pYieldProxy(_factory, _p2pTreasury, _allowedCalldataChecker, _allowedCalldataByClientToP2pChecker) {}

    /// @notice Deposits into a Fluid fToken.
    /// The factory calls deposit(_fToken, _amount) where _fToken is the Fluid fToken address
    /// passed as the `_asset` parameter in the factory's deposit() call.
    /// The actual underlying asset is resolved from fToken.asset().
    /// @param _fToken The Fluid fToken address (passed by factory as `_asset`).
    /// @param _amount Amount of the underlying asset to deposit.
    function deposit(address _fToken, uint256 _amount) external override(IDepositable) {
        require(_fToken != address(0), P2pFluidProxy__ZeroFTokenAddress());
        address asset = IERC4626(_fToken).asset();
        bytes memory depositCalldata = abi.encodeCall(IERC4626.deposit, (_amount, address(this)));
        _deposit(_fToken, _fToken, depositCalldata, asset, _amount, false);
    }

    /// @inheritdoc IP2pFluidProxy
    function withdraw(address _fToken, uint256 _shares) external override onlyClient {
        require(_fToken != address(0), P2pFluidProxy__ZeroFTokenAddress());
        address asset = IERC4626(_fToken).asset();
        bytes memory redeemCalldata = abi.encodeCall(IERC4626.redeem, (_shares, address(this), address(this)));
        _withdraw(_fToken, asset, _fToken, redeemCalldata, _shares);
    }

    /// @inheritdoc IP2pFluidProxy
    function withdrawAccruedRewards(address _fToken) external override onlyP2pOperator {
        require(_fToken != address(0), P2pFluidProxy__ZeroFTokenAddress());
        address asset = IERC4626(_fToken).asset();

        int256 accruedBefore = calculateAccruedRewards(_fToken, asset);
        require(accruedBefore > 0, P2pFluidProxy__ZeroAccruedRewards());

        uint256 shares = IERC4626(_fToken).convertToShares(uint256(accruedBefore));
        bytes memory redeemCalldata = abi.encodeCall(IERC4626.redeem, (shares, address(this), address(this)));
        uint256 withdrawn = _withdraw(_fToken, asset, _fToken, redeemCalldata, shares);
        _requireWithdrawnWithinAccrued(withdrawn, accruedBefore, 1);
    }

    /// @notice Calculates accrued rewards as current fToken assets minus tracked user principal.
    function calculateAccruedRewards(address _fToken, address _asset)
        public
        view
        override
        returns (int256)
    {
        uint256 shares = IERC20(_fToken).balanceOf(address(this));
        uint256 currentAmount = IERC4626(_fToken).convertToAssets(shares);
        uint256 userPrincipal = getUserPrincipal(_asset);
        return int256(currentAmount) - int256(userPrincipal);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(P2pYieldProxy)
        returns (bool)
    {
        return interfaceId == type(IP2pFluidProxy).interfaceId || super.supportsInterface(interfaceId);
    }

    function _getP2pOperator() internal view override returns (address) {
        return i_factory.getP2pOperator();
    }

    function _revertNotP2pOperator(address _caller) internal pure override {
        revert P2pFluidProxy__NotP2pOperator(_caller);
    }
}
