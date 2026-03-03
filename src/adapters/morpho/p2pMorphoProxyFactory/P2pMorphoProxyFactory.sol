// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "./IP2pMorphoProxyFactory.sol";
import "../p2pMorphoProxy/P2pMorphoProxy.sol";
import "../p2pMorphoTrustedDistributorRegistry/P2pMorphoTrustedDistributorRegistry.sol";

contract P2pMorphoProxyFactory is IP2pMorphoProxyFactory, P2pYieldProxyFactory {
    address private immutable i_referenceP2pYieldProxy;
    P2pMorphoTrustedDistributorRegistry private immutable i_trustedDistributorRegistry;

    constructor(
        address _p2pSigner,
        address _p2pTreasury,
        address _allowedCalldataChecker,
        address _morphoBundler
    ) P2pYieldProxyFactory(_p2pSigner) {
        i_trustedDistributorRegistry = new P2pMorphoTrustedDistributorRegistry(address(this));
        i_referenceP2pYieldProxy = address(
            new P2pMorphoProxy(
                address(this),
                _p2pTreasury,
                _allowedCalldataChecker,
                _morphoBundler,
                address(i_trustedDistributorRegistry)
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

    /// @inheritdoc IP2pMorphoProxyFactory
    function setTrustedDistributor(address _newTrustedDistributor) external override onlyP2pOperator {
        i_trustedDistributorRegistry.setTrustedDistributor(_newTrustedDistributor);
        emit P2pMorphoProxyFactory__TrustedDistributorSet(_newTrustedDistributor);
    }

    /// @inheritdoc IP2pMorphoProxyFactory
    function removeTrustedDistributor(address _trustedDistributor) external override onlyP2pOperator {
        i_trustedDistributorRegistry.removeTrustedDistributor(_trustedDistributor);
        emit P2pMorphoProxyFactory__TrustedDistributorRemoved(_trustedDistributor);
    }

    /// @inheritdoc IP2pMorphoProxyFactory
    function checkMorphoUrdClaim(address _p2pOperatorToCheck, bool _shouldCheckP2pOperator, address _distributor)
        external
        view
        override
    {
        i_trustedDistributorRegistry.checkMorphoUrdClaim(_p2pOperatorToCheck, _shouldCheckP2pOperator, _distributor);
    }

    /// @inheritdoc IP2pMorphoProxyFactory
    function isTrustedDistributor(address _distributor) external view override returns (bool) {
        return i_trustedDistributorRegistry.isTrustedDistributor(_distributor);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(P2pYieldProxyFactory)
        returns (bool)
    {
        return interfaceId == type(IP2pMorphoProxyFactory).interfaceId || super.supportsInterface(interfaceId);
    }
}
