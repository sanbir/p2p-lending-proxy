// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../p2pLendingProxy/IP2pLendingProxy.sol";

/// @dev External interface of P2pMorphoProxy declared to support ERC165 detection.
interface IP2pMorphoProxy is IP2pLendingProxy {
    /// @notice Emitted when a Morpho Urd claim is made
    event P2pMorphoProxy__ClaimedMorphoUrd(
        address _distributor,
        address _reward,
        uint256 _totalAmount,
        uint256 _p2pAmount,
        uint256 _clientAmount
    );

    /// @notice Claims Morpho Urd rewards
    /// @dev This function is Morpho specific. Cannot be reused for other protocols.
    /// @param _distributor The distributor address
    /// @param _reward The reward address
    /// @param _amount The amount to claim
    /// @param _proof The proof for the claim
    function morphoUrdClaim(
        address _distributor,
        address _reward,
        uint256 _amount,
        bytes32[] calldata _proof
    )
    external;


}
