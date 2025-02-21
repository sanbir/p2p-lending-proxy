// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../p2pLendingProxy/P2pLendingProxy.sol";
import "../IStakedUSDe.sol";
import "./IP2pEthenaProxy.sol";

contract P2pEthenaProxy is P2pLendingProxy, IP2pEthenaProxy {
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
    ) P2pLendingProxy(_factory, _p2pTreasury, _stakedUSDeV2) {
        i_USDe = _USDe;
    }

    function deposit(
        IAllowanceTransfer.PermitSingle calldata _permitSingleForP2pLendingProxy,
        bytes calldata _permit2SignatureForP2pLendingProxy
    ) external {
        _deposit(
            abi.encodeCall(
                IERC4626.deposit,
                (uint256(_permitSingleForP2pLendingProxy.details.amount), address(this))
            ),
        _permitSingleForP2pLendingProxy,
        _permit2SignatureForP2pLendingProxy,
            false
        );
    }

    function cooldownAssets(uint256 _assets)
    external
    onlyClient
    returns (uint256 shares) {
        return IStakedUSDe(i_yieldProtocolAddress).cooldownAssets(_assets);
    }

    function cooldownShares(uint256 _shares)
    external
    onlyClient
    returns (uint256 assets) {
        return IStakedUSDe(i_yieldProtocolAddress).cooldownShares(_shares);
    }

    function withdrawAfterCooldown() external {
        _withdraw(
            i_USDe,
            abi.encodeCall(
                IStakedUSDe.unstake,
                (address(this))
            )
        );
    }

    function withdrawWithoutCooldown(uint256 _assets) external {
        _withdraw(
            i_USDe,
            abi.encodeCall(
                IERC4626.withdraw,
                (_assets, address(this), address(this))
            )
        );
    }

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
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pLendingProxy) returns (bool) {
        return interfaceId == type(IP2pEthenaProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
