// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

interface IP2pResolvProxy {
    function withdraw(uint256 _usrAmount) external;

    function withdrawAll() external;
}
