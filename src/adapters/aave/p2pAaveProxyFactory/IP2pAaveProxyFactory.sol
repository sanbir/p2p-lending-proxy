// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

interface IP2pAaveProxyFactory {
    function getAavePool() external view returns (address);

    function getAaveDataProvider() external view returns (address);
}
