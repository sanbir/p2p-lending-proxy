// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../@openzeppelin/contracts-upgradable/security/ReentrancyGuardUpgradeable.sol";
import "../@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../common/AllowedCalldataChecker.sol";
import "../p2pYieldProxyFactory/IP2pYieldProxyFactory.sol";
import "./IP2pYieldProxy.sol";
import "./P2pYieldProxyErrors.sol";
import "./features/P2pYieldProxyWithdrawable.sol";
import "./features/P2pYieldProxyAnyFunctionExecutor.sol";
import "./storage/P2pYieldProxyClientStorage.sol";
import "./storage/P2pYieldProxyClientBasisPointsStorage.sol";
import "./storage/P2pYieldProxyTotalDepositedStorage.sol";
import "./storage/P2pYieldProxyTotalWithdrawnStorage.sol";

/// @title P2pYieldProxy
/// @notice P2pYieldProxy is a contract that allows a client to deposit and withdraw assets from a yield protocol.
abstract contract P2pYieldProxy is
    Initializable,
    ReentrancyGuardUpgradeable,
    ERC165,
    IP2pYieldProxy,
    P2pYieldProxyWithdrawable,
    P2pYieldProxyAnyFunctionExecutor
{
    /// @dev P2pYieldProxyFactory
    IP2pYieldProxyFactory internal immutable i_factory;

    /// @dev P2pTreasury
    address internal immutable i_p2pTreasury;

    IAllowedCalldataChecker internal immutable i_allowedCalldataChecker;

    /// @notice Constructor for P2pYieldProxy
    /// @param _factory The factory address
    /// @param _p2pTreasury The P2pTreasury address
    /// @param _allowedCalldataChecker AllowedCalldataChecker
    constructor(
        address _factory,
        address _p2pTreasury,
        address _allowedCalldataChecker
    ) {
        require(_factory != address(0), P2pYieldProxy__ZeroAddressFactory());
        i_factory = IP2pYieldProxyFactory(_factory);

        require(_p2pTreasury != address(0), P2pYieldProxy__ZeroAddressP2pTreasury());
        i_p2pTreasury = _p2pTreasury;

        require(_allowedCalldataChecker != address(0), P2pYieldProxy__ZeroAllowedCalldataChecker());
        i_allowedCalldataChecker = IAllowedCalldataChecker(_allowedCalldataChecker);
    }

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

    function _withdraw(
        address _yieldProtocolAddress,
        address _asset,
        bytes memory _yieldProtocolWithdrawalCalldata
    )
        internal
        virtual
        override
        nonReentrant
        returns (uint256)
    {
        return super._withdraw(_yieldProtocolAddress, _asset, _yieldProtocolWithdrawalCalldata);
    }

    function _withdraw(
        address _vault,
        address _asset,
        address _callTarget,
        bytes memory _yieldProtocolWithdrawalCalldata,
        uint256 _shares
    )
        internal
        virtual
        override
        nonReentrant
        returns (uint256)
    {
        return super._withdraw(_vault, _asset, _callTarget, _yieldProtocolWithdrawalCalldata, _shares);
    }

    /// @inheritdoc IP2pYieldProxy
    function callAnyFunction(
        address _yieldProtocolAddress,
        bytes calldata _yieldProtocolCalldata
    )
        external
        override
        onlyClient
        nonReentrant
        calldataShouldBeAllowed(_yieldProtocolAddress, _yieldProtocolCalldata)
    {
        _callAnyFunction(_yieldProtocolAddress, _yieldProtocolCalldata);
    }

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
        override(IP2pYieldProxy, P2pYieldProxyWithdrawable)
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
