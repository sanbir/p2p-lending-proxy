// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

interface IP2pResolvProxy {
    function withdrawUSR(uint256 _amount) external;

    function withdrawAllUSR() external;

    function initiateWithdrawalRESOLV(uint256 _amount) external;

    function withdrawRESOLV(uint256 _amount) external;

    function claimStakedTokenDistributor(
        uint256 _index,
        uint256 _amount,
        bytes32[] calldata _merkleProof
    )
    external;

    event P2pResolvProxy__Claimed(uint256 _amount);
}
