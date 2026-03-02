// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../common/IMorphoBundler.sol";
import "../../../p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "./IP2pMorphoProxyFactory.sol";
import "../p2pMorphoProxy/P2pMorphoProxy.sol";

error P2pMorphoProxyFactory__DistributorNotTrusted(address _distributor);
error P2pMorphoProxyFactory__ZeroTrustedDistributorAddress();

contract P2pMorphoProxyFactory is IP2pMorphoProxyFactory, P2pYieldProxyFactory {
    IMorphoBundler private immutable i_morphoBundler;

    mapping(address => bool) private s_trustedDistributors;

    constructor(
        address _p2pSigner,
        address _p2pTreasury,
        address _allowedCalldataChecker,
        address _morphoBundler
    ) P2pYieldProxyFactory(_p2pSigner) {
        i_morphoBundler = IMorphoBundler(_morphoBundler);
        i_referenceP2pYieldProxy =
            new P2pMorphoProxy(address(this), _p2pTreasury, _allowedCalldataChecker, _morphoBundler);
    }

    /// @inheritdoc IP2pMorphoProxyFactory
    function setTrustedDistributor(address _newTrustedDistributor) external override onlyP2pOperator {
        require(_newTrustedDistributor != address(0), P2pMorphoProxyFactory__ZeroTrustedDistributorAddress());
        s_trustedDistributors[_newTrustedDistributor] = true;
        emit P2pMorphoProxyFactory__TrustedDistributorSet(_newTrustedDistributor);
    }

    /// @inheritdoc IP2pMorphoProxyFactory
    function removeTrustedDistributor(address _trustedDistributor) external override onlyP2pOperator {
        s_trustedDistributors[_trustedDistributor] = false;
        emit P2pMorphoProxyFactory__TrustedDistributorRemoved(_trustedDistributor);
    }

    /// @inheritdoc IP2pMorphoProxyFactory
    function checkMorphoUrdClaim(address _p2pOperatorToCheck, bool _shouldCheckP2pOperator, address _distributor)
        external
        view
        override
    {
        if (_shouldCheckP2pOperator) {
            require(getP2pOperator() == _p2pOperatorToCheck, P2pOperator__UnauthorizedAccount(_p2pOperatorToCheck));
        }
        require(s_trustedDistributors[_distributor], P2pMorphoProxyFactory__DistributorNotTrusted(_distributor));
    }

    /// @inheritdoc IP2pMorphoProxyFactory
    function isTrustedDistributor(address _distributor) external view override returns (bool) {
        return s_trustedDistributors[_distributor];
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
