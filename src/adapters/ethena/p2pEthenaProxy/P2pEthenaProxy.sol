// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../p2pYieldProxy/P2pYieldProxy.sol";
import "../IStakedUSDe.sol";
import "./IP2pEthenaProxy.sol";

error P2pEthenaProxy__ZeroAddressUSDe();

contract P2pEthenaProxy is P2pYieldProxy, IP2pEthenaProxy {
    using SafeERC20 for IERC20;

    /// @dev USDe address
    address internal immutable i_USDe;

    /// @notice Constructor for P2pEthenaProxy
    /// @param _factory Factory address
    /// @param _p2pTreasury P2pTreasury address
    /// @param _stakedUSDeV2 StakedUSDeV2 address
    /// @param _USDe USDe address
    constructor(
        address _factory,
        address _p2pTreasury,
        address _stakedUSDeV2,
        address _USDe
    ) P2pYieldProxy(_factory, _p2pTreasury, _stakedUSDeV2) {
        require(_USDe != address(0), P2pEthenaProxy__ZeroAddressUSDe());

        i_USDe = _USDe;
    }

    /// @inheritdoc IP2pYieldProxy
    function deposit(
        IAllowanceTransfer.PermitSingle calldata _permitSingleForP2pYieldProxy,
        bytes calldata _permit2SignatureForP2pYieldProxy
    ) external {
        _deposit(
            abi.encodeCall(
                IERC4626.deposit,
                (uint256(_permitSingleForP2pYieldProxy.details.amount), address(this))
            ),
        _permitSingleForP2pYieldProxy,
        _permit2SignatureForP2pYieldProxy,
            false
        );
    }

    /// @inheritdoc IP2pEthenaProxy
    function cooldownAssets(uint256 _assets)
    external
    onlyClient
    returns (uint256 shares) {
        return IStakedUSDe(i_yieldProtocolAddress).cooldownAssets(_assets);
    }

    /// @inheritdoc IP2pEthenaProxy
    function cooldownShares(uint256 _shares)
    external
    onlyClient
    returns (uint256 assets) {
        return IStakedUSDe(i_yieldProtocolAddress).cooldownShares(_shares);
    }

    /// @inheritdoc IP2pEthenaProxy
    function withdrawAfterCooldown() external {
        _withdraw(
            i_USDe,
            abi.encodeCall(
                IStakedUSDe.unstake,
                (address(this))
            )
        );
    }

    /// @inheritdoc IP2pEthenaProxy
    function withdrawWithoutCooldown(uint256 _assets) external {
        _withdraw(
            i_USDe,
            abi.encodeCall(
                IERC4626.withdraw,
                (_assets, address(this), address(this))
            )
        );
    }

    /// @inheritdoc IP2pEthenaProxy
    function redeemWithoutCooldown(uint256 _shares) external {
        _withdraw(
            i_USDe,
            abi.encodeCall(
                IERC4626.redeem,
                (_shares, address(this), address(this))
            )
        );
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pYieldProxy) returns (bool) {
        return interfaceId == type(IP2pEthenaProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
