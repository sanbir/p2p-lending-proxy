// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../p2pYieldProxy/IP2pYieldProxy.sol";

interface IP2pMorphoProxy is IP2pYieldProxy {
    event P2pMorphoProxy__ClaimedMorphoUrd(
        address _distributor, address _reward, uint256 _totalAmount, uint256 _p2pAmount, uint256 _clientAmount
    );

    function deposit(address _asset, uint256 _amount) external override;

    function withdraw(address _vault, uint256 _shares) external;

    function withdrawAccruedRewards(address _vault) external;

    function morphoUrdClaim(address _distributor, address _reward, uint256 _amount, bytes32[] calldata _proof)
        external;
}
