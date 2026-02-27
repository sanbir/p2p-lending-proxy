// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../common/AllowedCalldataChecker.sol";
import "../../p2pYieldProxyFactory/IP2pYieldProxyFactory.sol";
import "../../structs/P2pStructs.sol";
import "../P2pYieldProxyErrors.sol";

abstract contract P2pYieldProxyFactoryStorage {
    IP2pYieldProxyFactory internal immutable i_factory;

    constructor(address _factory) {
        require(_factory != address(0), P2pYieldProxy__ZeroAddressFactory());
        i_factory = IP2pYieldProxyFactory(_factory);
    }

    function getFactory() public view virtual returns (address) {
        return address(i_factory);
    }
}

abstract contract P2pYieldProxyTreasuryStorage {
    address internal immutable i_p2pTreasury;

    constructor(address _p2pTreasury) {
        require(_p2pTreasury != address(0), P2pYieldProxy__ZeroAddressP2pTreasury());
        i_p2pTreasury = _p2pTreasury;
    }

    function getP2pTreasury() public view virtual returns (address) {
        return i_p2pTreasury;
    }
}

abstract contract P2pYieldProxyAllowedCalldataCheckerStorage {
    IAllowedCalldataChecker internal immutable i_allowedCalldataChecker;

    constructor(address _allowedCalldataChecker) {
        require(_allowedCalldataChecker != address(0), P2pYieldProxy__ZeroAllowedCalldataChecker());
        i_allowedCalldataChecker = IAllowedCalldataChecker(_allowedCalldataChecker);
    }
}

abstract contract P2pYieldProxyClientStorage {
    address internal s_client;

    function getClientStorage() public view virtual returns (address) {
        return s_client;
    }
}

abstract contract P2pYieldProxyClientBasisPointsStorage {
    uint96 internal s_clientBasisPoints;

    function getClientBasisPointsStorage() public view virtual returns (uint96) {
        return s_clientBasisPoints;
    }
}

abstract contract P2pYieldProxyTotalDepositedStorage {
    mapping(address => uint256) internal s_totalDeposited;

    function getTotalDepositedStorage(address _asset) public view virtual returns (uint256) {
        return s_totalDeposited[_asset];
    }
}

abstract contract P2pYieldProxyTotalWithdrawnStorage {
    mapping(address => Withdrawn) internal s_totalWithdrawn;

    function getTotalWithdrawnStorage(address _asset) public view virtual returns (uint256) {
        return s_totalWithdrawn[_asset].amount;
    }

    function getLastFeeCollectionTimeStorage(address _asset) public view virtual returns (uint48) {
        return s_totalWithdrawn[_asset].lastFeeCollectionTime;
    }
}
