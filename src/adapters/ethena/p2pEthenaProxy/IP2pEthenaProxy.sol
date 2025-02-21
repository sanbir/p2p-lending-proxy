// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

interface IP2pEthenaProxy {
    function cooldownAssets(uint256 _assets) external returns (uint256 shares);

    function cooldownShares(uint256 _shares) external returns (uint256 assets);

    function withdrawAfterCooldown() external;

    function withdrawWithoutCooldown(uint256 _assets) external;

    function redeemWithoutCooldown(uint256 _shares) external;
}
