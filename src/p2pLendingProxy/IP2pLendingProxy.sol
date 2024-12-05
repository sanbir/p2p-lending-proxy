// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";



/// @dev External interface of P2pLendingProxy declared to support ERC165 detection.
interface IP2pLendingProxy is IERC165 {

    event P2pLendingProxy__Initialized(
        address _client,
        uint96 _clientBasisPoints
    );
}