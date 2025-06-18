// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../@permit2/interfaces/IAllowanceTransfer.sol";
import "../../../p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "../p2pResolvProxy/P2pResolvProxy.sol";

/// @title Entry point for depositing into Resolv with P2P.org
contract P2pResolvProxyFactory is P2pYieldProxyFactory {

    /// @notice Constructor for P2pResolvProxyFactory
    /// @param _p2pSigner The P2pSigner address
    /// @param _p2pTreasury The P2pTreasury address
    /// @param _stUSR stUSR address
    /// @param _USR USR address
    constructor(
        address _p2pSigner,
        address _p2pTreasury,
        address _stUSR,
        address _USR
    ) P2pYieldProxyFactory(_p2pSigner) {
        i_referenceP2pYieldProxy = new P2pResolvProxy(
            address(this),
            _p2pTreasury,
            _stUSR,
            _USR
        );
    }
}
