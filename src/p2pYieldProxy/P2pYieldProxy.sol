// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../common/AllowedCalldataChecker.sol";
import "../p2pYieldProxyFactory/IP2pYieldProxyFactory.sol";
import "./IP2pYieldProxy.sol";
import "./P2pYieldProxyErrors.sol";
import "./features/Withdrawable.sol";
import "./features/AnyFunctionExecutor.sol";
import "./immutables/FactoryImmutable.sol";
import "./immutables/TreasuryImmutable.sol";
import "./immutables/AllowedCalldataCheckerImmutable.sol";
import "./storage/ClientStorage.sol";
import "./storage/ClientBasisPointsStorage.sol";
import "./storage/TotalDepositedStorage.sol";
import "./storage/TotalWithdrawnStorage.sol";

/// @title P2pYieldProxy
/// @notice P2pYieldProxy is a contract that allows a client to deposit and withdraw assets from a yield protocol.
abstract contract P2pYieldProxy is
    Initializable,
    ERC165,
    IP2pYieldProxy,
    FactoryImmutable,
    TreasuryImmutable,
    AllowedCalldataCheckerImmutable,
    Withdrawable,
    AnyFunctionExecutor
{
    /// @notice Constructor for P2pYieldProxy
    /// @param _factory The factory address
    /// @param _p2pTreasury The P2pTreasury address
    /// @param _allowedCalldataChecker AllowedCalldataChecker
    constructor(
        address _factory,
        address _p2pTreasury,
        address _allowedCalldataChecker
    )
        FactoryImmutable(_factory)
        TreasuryImmutable(_p2pTreasury)
        AllowedCalldataCheckerImmutable(_allowedCalldataChecker)
    {}

    /// @inheritdoc IP2pYieldProxy
    function initialize(
        address _client,
        uint96 _clientBasisPoints
    )
        external
        override
        initializer
        onlyFactory
    {
        __ReentrancyGuard_init();

        require(
            _clientBasisPoints > 0 && _clientBasisPoints <= 10_000,
            P2pYieldProxy__InvalidClientBasisPoints(_clientBasisPoints)
        );

        s_client = _client;
        s_clientBasisPoints = _clientBasisPoints;

        emit IP2pYieldProxy.P2pYieldProxy__Initialized();
    }

    /// @inheritdoc IP2pYieldProxy
    function deposit(address _asset, uint256 _amount) external virtual;

    /// @inheritdoc IP2pYieldProxy
    function getFactory() public view override returns (address) {
        return address(i_factory);
    }

    /// @inheritdoc IP2pYieldProxy
    function getP2pTreasury() public view override returns (address) {
        return i_p2pTreasury;
    }

    /// @inheritdoc IP2pYieldProxy
    function getClient()
        external
        view
        override
        returns (address)
    {
        return getClientStorage();
    }

    /// @inheritdoc IP2pYieldProxy
    function getClientBasisPoints()
        external
        view
        override
        returns (uint96)
    {
        return getClientBasisPointsStorage();
    }

    /// @inheritdoc IP2pYieldProxy
    function getTotalDeposited(address _asset) external view override returns (uint256) {
        return getTotalDepositedStorage(_asset);
    }

    /// @inheritdoc IP2pYieldProxy
    function getTotalWithdrawn(address _asset) external view override returns (uint256) {
        return getTotalWithdrawnStorage(_asset);
    }

    /// @inheritdoc IP2pYieldProxy
    function getUserPrincipal(address _asset)
        public
        view
        virtual
        override
        returns (uint256)
    {
        return _getUserPrincipal(_asset);
    }

    /// @inheritdoc IP2pYieldProxy
    function calculateAccruedRewards(address _yieldProtocolAddress, address _asset)
        public
        view
        virtual
        override(IP2pYieldProxy, Withdrawable)
        returns (int256)
    {
        uint256 currentAmount = _getCurrentAssetAmount(_yieldProtocolAddress, _asset);
        uint256 userPrincipal = _getUserPrincipal(_asset);
        return int256(currentAmount) - int256(userPrincipal);
    }

    /// @inheritdoc IP2pYieldProxy
    function getLastFeeCollectionTime(address _asset) public view override returns (uint48) {
        return getLastFeeCollectionTimeStorage(_asset);
    }

    function _getCurrentAssetAmount(address _yieldProtocolAddress, address) internal view virtual returns (uint256) {
        return IERC20(_yieldProtocolAddress).balanceOf(address(this));
    }

    function _factoryRef() internal view override returns (IP2pYieldProxyFactory) {
        return i_factory;
    }

    function _allowedCalldataCheckerRef() internal view override returns (IAllowedCalldataChecker) {
        return i_allowedCalldataChecker;
    }

    function _p2pTreasuryAddress() internal view override returns (address) {
        return i_p2pTreasury;
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165, IERC165)
        returns (bool)
    {
        return interfaceId == type(IP2pYieldProxy).interfaceId || super.supportsInterface(interfaceId);
    }
}
