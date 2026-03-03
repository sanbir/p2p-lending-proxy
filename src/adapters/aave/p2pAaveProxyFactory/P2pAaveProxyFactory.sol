// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "../p2pAaveProxy/P2pAaveProxy.sol";
import "./IP2pAaveProxyFactory.sol";

error P2pAaveProxyFactory__ZeroAavePoolAddress();
error P2pAaveProxyFactory__ZeroAaveDataProviderAddress();

contract P2pAaveProxyFactory is IP2pAaveProxyFactory, P2pYieldProxyFactory {
    address private immutable i_referenceP2pYieldProxy;

    constructor(
        address _p2pSigner,
        address _p2pTreasury,
        address _allowedCalldataChecker,
        address _aavePool,
        address _aaveDataProvider
    ) P2pYieldProxyFactory(_p2pSigner) {
        require(_aavePool != address(0), P2pAaveProxyFactory__ZeroAavePoolAddress());
        require(_aaveDataProvider != address(0), P2pAaveProxyFactory__ZeroAaveDataProviderAddress());
        i_referenceP2pYieldProxy = address(
            new P2pAaveProxy(
                address(this),
                _p2pTreasury,
                _allowedCalldataChecker,
                _aavePool,
                _aaveDataProvider
            )
        );
        addReferenceP2pYieldProxy(i_referenceP2pYieldProxy);
    }

    function deposit(
        address _asset,
        uint256 _amount,
        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline,
        bytes calldata _p2pSignerSignature
    ) external returns (address) {
        return super.deposit(
            i_referenceP2pYieldProxy,
            _asset,
            _amount,
            _clientBasisPoints,
            _p2pSignerSigDeadline,
            _p2pSignerSignature
        );
    }

    function predictP2pYieldProxyAddress(address _client, uint96 _clientBasisPoints)
        external
        view
        returns (address proxyAddress)
    {
        return super.predictP2pYieldProxyAddress(i_referenceP2pYieldProxy, _client, _clientBasisPoints);
    }

    function getReferenceP2pYieldProxy() external view returns (address referenceProxy) {
        return i_referenceP2pYieldProxy;
    }

    function getHashForP2pSigner(address _client, uint96 _clientBasisPoints, uint256 _p2pSignerSigDeadline)
        external
        view
        returns (bytes32 signerHash)
    {
        return super.getHashForP2pSigner(
            i_referenceP2pYieldProxy,
            _client,
            _clientBasisPoints,
            _p2pSignerSigDeadline
        );
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(P2pYieldProxyFactory)
        returns (bool)
    {
        return interfaceId == type(IP2pAaveProxyFactory).interfaceId || super.supportsInterface(interfaceId);
    }
}
