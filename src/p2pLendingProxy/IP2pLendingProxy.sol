// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../common/IAllowedCalldataChecker.sol";



/// @dev External interface of P2pLendingProxy declared to support ERC165 detection.
interface IP2pLendingProxy is IAllowedCalldataChecker, IERC165 {

    event P2pLendingProxy__Initialized();

    event P2pLendingProxy__Deposited(
        address indexed _lendingProtocolAddress,
        address indexed _asset,
        uint160 _amount,
        uint256 _totalDepositedAfter
    );

    event P2pLendingProxy__Withdrawn(
        address indexed _lendingProtocolAddress,
        address indexed _vault,
        address indexed _asset,
        uint256 _shares,
        uint256 _assets,
        uint256 _totalWithdrawnAfter,
        uint256 _newProfit,
        uint256 _p2pAmount,
        uint256 _clientAmount
    );

    event P2pLendingProxy__CalledAsAnyFunction(
        address indexed _lendingProtocolAddress
    );

    event P2pLendingProxy__ClaimedMorphoUrd(
        address _distributor,
        address _reward,
        uint256 _totalAmount,
        uint256 _p2pAmount,
        uint256 _clientAmount
    );
}