// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "./IP2pYieldProxy.sol";
import "./features/AccruedRewardsWithTreasury.sol";
import "./features/AnyFunctionWithCalldataChecker.sol";
import "./features/ProxyInitializer.sol";
import "./immutables/FactoryImmutable.sol";
import "./interfaces/IDepositable.sol";

/// @title P2pYieldProxy
/// @notice P2pYieldProxy is a contract that allows a client to deposit and withdraw assets from a yield protocol.
abstract contract P2pYieldProxy is
    ERC165,
    IDepositable,
    FactoryImmutable,
    AccruedRewardsWithTreasury,
    AnyFunctionWithCalldataChecker,
    ProxyInitializer
{
    /// @notice Constructor for P2pYieldProxy
    /// @param _factoryAddress The factory address
    /// @param _p2pTreasuryAddress_ The P2pTreasury address
    /// @param _allowedCalldataCheckerAddress AllowedCalldataChecker
    constructor(
        address _factoryAddress,
        address _p2pTreasuryAddress_,
        address _allowedCalldataCheckerAddress
    )
        FactoryImmutable(_factoryAddress)
        AccruedRewardsWithTreasury(_p2pTreasuryAddress_)
        AnyFunctionWithCalldataChecker(_allowedCalldataCheckerAddress)
    {}

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165)
        returns (bool)
    {
        return interfaceId == type(IP2pYieldProxy).interfaceId || super.supportsInterface(interfaceId);
    }
}
