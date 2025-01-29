// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../@openzeppelin/contracts/interfaces/IERC4626.sol";

interface IStakedUSDe is IERC4626 {
    /// @notice redeem assets and starts a cooldown to claim the converted underlying asset
    /// @param assets assets to redeem
    function cooldownAssets(uint256 assets) external returns (uint256 shares);

    /// @notice redeem shares into assets and starts a cooldown to claim the converted underlying asset
    /// @param shares shares to redeem
    function cooldownShares(uint256 shares) external returns (uint256 assets);

    /// @notice Claim the staking amount after the cooldown has finished. The address can only retire the full amount of assets.
    /// @dev unstake can be called after cooldown have been set to 0, to let accounts to be able to claim remaining assets locked at Silo
    /// @param receiver Address to send the assets by the staker
    function unstake(address receiver) external;
}
