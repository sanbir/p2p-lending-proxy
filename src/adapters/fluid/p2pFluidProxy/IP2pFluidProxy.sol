// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

interface IP2pFluidProxy {
    /// @notice Withdraws from a Fluid fToken. Only callable by client.
    /// @param _fToken The Fluid fToken address.
    /// @param _shares Amount of fToken shares to redeem.
    function withdraw(address _fToken, uint256 _shares) external;

    /// @notice Withdraws only the accrued rewards portion. Only callable by P2P operator.
    /// @param _fToken The Fluid fToken address.
    function withdrawAccruedRewards(address _fToken) external;
}
