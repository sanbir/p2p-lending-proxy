// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

/// @title IMorphoBundler
/// @notice Based on https://github.com/morpho-org/morpho-blue-bundlers
interface IMorphoBundler {
    function erc4626Deposit(address vault, uint256 assets, uint256 minShares, address receiver) external payable;

    function erc4626Redeem(address vault, uint256 shares, uint256 minAssets, address receiver, address owner)
        external
        payable;

    function urdClaim(
        address distributor,
        address account,
        address reward,
        uint256 amount,
        bytes32[] calldata proof,
        bool skipRevert
    ) external payable;

    function multicall(bytes[] memory data) external payable;
}
