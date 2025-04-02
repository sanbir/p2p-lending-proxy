// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../@permit2/interfaces/IAllowanceTransfer.sol";
import "../../../p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "../p2pSuperformProxy/P2pSuperformProxy.sol";
import "./IP2pSuperformProxyFactory.sol";
import {IERC4626} from "../../../@openzeppelin/contracts/interfaces/IERC4626.sol";

/// @title Entry point for depositing into Superform with P2P.org
contract P2pSuperformProxyFactory is P2pYieldProxyFactory, IP2pSuperformProxyFactory {

    /// @notice Constructor for P2pSuperformProxyFactory
    /// @param _p2pSigner The P2pSigner address
    /// @param _p2pTreasury The P2pTreasury address
    /// @param _superformRouter SuperformRouter address
    /// @param _superPositions SuperPositions address
    /// @param _allowedCalldataChecker AllowedCalldataChecker
    constructor(
        address _p2pSigner,
        address _p2pTreasury,
        address _superformRouter,
        address _superPositions,
        address _allowedCalldataChecker
    ) P2pYieldProxyFactory(_p2pSigner) {
        i_referenceP2pYieldProxy = new P2pSuperformProxy(
            address(this),
            _p2pTreasury,
            _superformRouter,
            _superPositions,
            _allowedCalldataChecker
        );
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pYieldProxyFactory) returns (bool) {
        return interfaceId == type(IP2pSuperformProxyFactory).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
