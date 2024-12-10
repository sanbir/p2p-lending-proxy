// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@permit2/interfaces/IAllowanceTransfer.sol";

interface IMorphoEthereumBundlerV2 {
    /// @notice Approves the given `amount` of `asset` from the initiator to be spent by `permitSingle.spender` via
    /// Permit2 with the given `deadline` & EIP-712 `signature`.
    /// @param permitSingle The `PermitSingle` struct.
    /// @param signature The signature, serialized.
    /// @param skipRevert Whether to avoid reverting the call in case the signature is frontrunned.
    function approve2(IAllowanceTransfer.PermitSingle calldata permitSingle, bytes calldata signature, bool skipRevert)
    external
    payable;

    /// @notice Transfers the given `amount` of `asset` from the initiator to the bundler via Permit2.
    /// @param asset The address of the ERC20 token to transfer.
    /// @param amount The amount of `asset` to transfer from the initiator. Capped at the initiator's balance.
    function transferFrom2(address asset, uint256 amount) external payable;

    /// @notice Deposits the given amount of `assets` on the given ERC4626 `vault`, on behalf of `receiver`.
    /// @dev Initiator must have previously transferred their assets to the bundler.
    /// @dev Assumes the given `vault` implements EIP-4626.
    /// @param vault The address of the vault.
    /// @param assets The amount of assets to deposit. Capped at the bundler's assets.
    /// @param minShares The minimum amount of shares to mint in exchange for `assets`. This parameter is proportionally
    /// scaled down in case there are fewer assets than `assets` on the bundler.
    /// @param receiver The address to which shares will be minted.
    function erc4626Deposit(address vault, uint256 assets, uint256 minShares, address receiver)
    external
    payable;

    /// @notice Executes a series of delegate calls to the contract itself.
    /// @dev Locks the initiator so that the sender can uniquely be identified in callbacks.
    /// @dev All functions delegatecalled must be `payable` if `msg.value` is non-zero.
    function multicall(bytes[] memory data) external payable;
}
