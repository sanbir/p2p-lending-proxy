// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

interface IP2pEthenaProxy {
    /// @notice redeem assets and starts a cooldown to claim the converted underlying asset
    /// @param _assets assets to redeem
    function cooldownAssets(uint256 _assets) external returns (uint256 shares);

    /// @notice redeem shares into assets and starts a cooldown to claim the converted underlying asset
    /// @param _shares shares to redeem
    function cooldownShares(uint256 _shares) external returns (uint256 assets);

    /// @notice withdraw assets after cooldown has elapsed
    function withdrawAfterCooldown() external;

    /// @notice withdraw assets without cooldown if cooldownDuration has been set to 0 on StakedUSDeV2
    /// @param _assets assets to redeem
    function withdrawWithoutCooldown(uint256 _assets) external;

    /// @notice withdraw shares without cooldown if cooldownDuration has been set to 0 on StakedUSDeV2
    /// @param _shares shares to redeem
    function redeemWithoutCooldown(uint256 _shares) external;
}
