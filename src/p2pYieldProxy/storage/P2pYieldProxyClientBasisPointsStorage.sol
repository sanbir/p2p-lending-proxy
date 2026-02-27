// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

abstract contract P2pYieldProxyClientBasisPointsStorage {
    uint96 internal s_clientBasisPoints;

    function getClientBasisPointsStorage() public view virtual returns (uint96) {
        return s_clientBasisPoints;
    }
}
