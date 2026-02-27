// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../structs/P2pStructs.sol";

abstract contract TotalWithdrawnStorage {
    mapping(address => Withdrawn) internal s_totalWithdrawn;
}
