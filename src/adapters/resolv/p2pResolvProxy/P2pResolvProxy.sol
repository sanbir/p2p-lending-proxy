// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../@resolv/IResolvStaking.sol";
import "../../../@resolv/IStUSR.sol";
import "../../../p2pYieldProxy/P2pYieldProxy.sol";
import "./IP2pResolvProxy.sol";

error P2pResolvProxy__ZeroAddress_USR();
error P2pResolvProxy__AssetNotSupported(address _asset);

contract P2pResolvProxy is P2pYieldProxy, IP2pResolvProxy {
    using SafeERC20 for IERC20;

    /// @dev USR address
    address internal immutable i_USR;

    /// @dev stUSR address
    address internal immutable i_stUSR;

    /// @dev RESOLV address
    address internal immutable i_RESOLV;

    /// @dev stRESOLV address
    address internal immutable i_stRESOLV;

    /// @notice Constructor for P2pResolvProxy
    /// @param _factory Factory address
    /// @param _p2pTreasury P2pTreasury address
    /// @param _stUSR stUSR address
    /// @param _USR USR address
    /// @param _stRESOLV stRESOLV address
    /// @param _RESOLV RESOLV address
    constructor(
        address _factory,
        address _p2pTreasury,
        address _stUSR,
        address _USR,
        address _stRESOLV,
        address _RESOLV
    ) P2pYieldProxy(_factory, _p2pTreasury) {
        require(_USR != address(0), P2pResolvProxy__ZeroAddress_USR());

        i_USR = _USR;
        i_stUSR = _stUSR;

        i_RESOLV = _RESOLV;
        i_stRESOLV = _stRESOLV;
    }

    /// @inheritdoc IP2pYieldProxy
    function deposit(address _asset, uint256 _amount) external override {
        if (_asset == i_USR) {
            _deposit(
                i_stUSR,
                abi.encodeWithSelector(IStUSR.deposit.selector, _amount),
                i_USR,
                _amount
            );
        } else if (_asset == i_RESOLV) {
            _deposit(
                i_stRESOLV,
                abi.encodeWithSelector(IResolvStaking.deposit.selector, _amount, address(this)),
                i_RESOLV,
                _amount
            );
        } else {
            revert P2pResolvProxy__AssetNotSupported(_asset);
        }
    }

    /// @inheritdoc IP2pResolvProxy
    function withdrawUSR(uint256 _amount)
    external
    onlyClient {
        _withdraw(
            i_stUSR,
            i_USR,
            abi.encodeWithSelector(IStUSR.withdraw.selector, _amount)
        );
    }

    /// @inheritdoc IP2pResolvProxy
    function withdrawAllUSR()
    external
    onlyClient {
        _withdraw(
            i_stUSR,
            i_USR,
            abi.encodeCall(IStUSR.withdrawAll, ())
        );
    }

    /// @inheritdoc IP2pResolvProxy
    function initiateWithdrawalRESOLV(uint256 _amount)
    external
    onlyClient {
        return IResolvStaking(i_stRESOLV).initiateWithdrawal(_amount);
    }

    /// @inheritdoc IP2pResolvProxy
    function withdrawRESOLV(uint256 _amount)
    external
    onlyClient {
        bool isEnabled = IResolvStaking(i_stRESOLV).claimEnabled();

        _withdraw(
            i_stRESOLV,
            i_RESOLV,
            abi.encodeWithSelector(IResolvStaking.withdraw.selector, isEnabled, address(this))
        );
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pYieldProxy) returns (bool) {
        return interfaceId == type(IP2pResolvProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
