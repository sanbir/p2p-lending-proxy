// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "../../../p2pYieldProxyFactory/IP2pYieldProxyFactory.sol";
import "../p2pAaveProxy/P2pAaveProxy.sol";
import "./IP2pAaveProxyFactory.sol";

error P2pAaveProxyFactory__ZeroAavePoolAddress();
error P2pAaveProxyFactory__ZeroAaveDataProviderAddress();

contract P2pAaveProxyFactory is P2pYieldProxyFactory, IP2pAaveProxyFactory {
    address private immutable i_aavePool;
    address private immutable i_aaveDataProvider;

    constructor(
        address _p2pSigner,
        address _p2pTreasury,
        address _allowedCalldataChecker,
        address _aavePool,
        address _aaveDataProvider
    ) P2pYieldProxyFactory(_p2pSigner) {
        require(_aavePool != address(0), P2pAaveProxyFactory__ZeroAavePoolAddress());
        require(_aaveDataProvider != address(0), P2pAaveProxyFactory__ZeroAaveDataProviderAddress());
        i_aavePool = _aavePool;
        i_aaveDataProvider = _aaveDataProvider;
        i_referenceP2pYieldProxy =
            new P2pAaveProxy(address(this), _p2pTreasury, _allowedCalldataChecker, _aavePool, _aaveDataProvider);
    }

    function getAavePool() external view override returns (address) {
        return i_aavePool;
    }

    function getAaveDataProvider() external view override returns (address) {
        return i_aaveDataProvider;
    }

    function deposit(
        address _asset,
        uint256 _amount,
        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline,
        bytes calldata _p2pSignerSignature
    )
        public
        override(IP2pYieldProxyFactory, P2pYieldProxyFactory)
        returns (address)
    {
        return super.deposit(_asset, _amount, _clientBasisPoints, _p2pSignerSigDeadline, _p2pSignerSignature);
    }

    function predictP2pYieldProxyAddress(address _client, uint96 _clientBasisPoints)
        public
        view
        override(IP2pYieldProxyFactory, P2pYieldProxyFactory)
        returns (address)
    {
        return super.predictP2pYieldProxyAddress(_client, _clientBasisPoints);
    }

    function getReferenceP2pYieldProxy()
        public
        view
        override(IP2pYieldProxyFactory, P2pYieldProxyFactory)
        returns (address)
    {
        return super.getReferenceP2pYieldProxy();
    }

    function getHashForP2pSigner(address _client, uint96 _clientBasisPoints, uint256 _p2pSignerSigDeadline)
        public
        view
        override(IP2pYieldProxyFactory, P2pYieldProxyFactory)
        returns (bytes32)
    {
        return super.getHashForP2pSigner(_client, _clientBasisPoints, _p2pSignerSigDeadline);
    }

    function transferP2pSigner(address _newP2pSigner)
        public
        override(IP2pYieldProxyFactory, P2pYieldProxyFactory)
        onlyP2pOperator
    {
        super.transferP2pSigner(_newP2pSigner);
    }

    function getP2pSigner()
        public
        view
        override(IP2pYieldProxyFactory, P2pYieldProxyFactory)
        returns (address)
    {
        return super.getP2pSigner();
    }

    function getAllProxies()
        public
        view
        override(IP2pYieldProxyFactory, P2pYieldProxyFactory)
        returns (address[] memory)
    {
        return super.getAllProxies();
    }

    /// @inheritdoc IP2pYieldProxyFactory
    function transferP2pOperator(address _newP2pOperator)
        public
        override(IP2pYieldProxyFactory, P2pYieldProxyFactory)
        onlyP2pOperator
    {
        super.transferP2pOperator(_newP2pOperator);
    }

    /// @inheritdoc IP2pYieldProxyFactory
    function acceptP2pOperator()
        public
        override(IP2pYieldProxyFactory, P2pYieldProxyFactory)
    {
        super.acceptP2pOperator();
    }

    /// @inheritdoc IP2pYieldProxyFactory
    function getP2pOperator()
        public
        view
        override(IP2pYieldProxyFactory, P2pYieldProxyFactory)
        returns (address)
    {
        return super.getP2pOperator();
    }

    /// @inheritdoc IP2pYieldProxyFactory
    function getPendingP2pOperator()
        public
        view
        override(IP2pYieldProxyFactory, P2pYieldProxyFactory)
        returns (address)
    {
        return super.getPendingP2pOperator();
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(P2pYieldProxyFactory, IERC165)
        returns (bool)
    {
        return interfaceId == type(IP2pAaveProxyFactory).interfaceId || super.supportsInterface(interfaceId);
    }
}
