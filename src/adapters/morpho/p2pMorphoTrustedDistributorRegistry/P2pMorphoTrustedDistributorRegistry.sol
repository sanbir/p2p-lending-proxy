// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../access/P2pOperator.sol";
import "../../../p2pYieldProxyFactory/IP2pYieldProxyFactory.sol";
import "./IP2pMorphoTrustedDistributorRegistry.sol";

error P2pMorphoTrustedDistributorRegistry__DistributorNotTrusted(address _distributor);
error P2pMorphoTrustedDistributorRegistry__ZeroTrustedDistributorAddress();
error P2pMorphoTrustedDistributorRegistry__ZeroFactoryAddress();
error P2pMorphoProxyFactory__DistributorNotTrusted(address _distributor);
error P2pMorphoProxyFactory__ZeroTrustedDistributorAddress();

contract P2pMorphoTrustedDistributorRegistry is IP2pMorphoTrustedDistributorRegistry {
    IP2pYieldProxyFactory private immutable i_factory;
    mapping(address => bool) private s_trustedDistributors;

    constructor(address _factoryAddress) {
        require(_factoryAddress != address(0), P2pMorphoTrustedDistributorRegistry__ZeroFactoryAddress());
        i_factory = IP2pYieldProxyFactory(_factoryAddress);
    }

    function setTrustedDistributor(address _newTrustedDistributor) external override onlyP2pOperator {
        require(
            _newTrustedDistributor != address(0),
            P2pMorphoProxyFactory__ZeroTrustedDistributorAddress()
        );
        s_trustedDistributors[_newTrustedDistributor] = true;
        emit P2pMorphoTrustedDistributorRegistry__TrustedDistributorSet(_newTrustedDistributor);
    }

    function removeTrustedDistributor(address _trustedDistributor) external override onlyP2pOperator {
        s_trustedDistributors[_trustedDistributor] = false;
        emit P2pMorphoTrustedDistributorRegistry__TrustedDistributorRemoved(_trustedDistributor);
    }

    function checkMorphoUrdClaim(address _p2pOperatorToCheck, bool _shouldCheckP2pOperator, address _distributor)
        external
        view
        override
    {
        if (_shouldCheckP2pOperator) {
            require(
                i_factory.getP2pOperator() == _p2pOperatorToCheck,
                P2pOperator.P2pOperator__UnauthorizedAccount(_p2pOperatorToCheck)
            );
        }
        require(
            s_trustedDistributors[_distributor],
            P2pMorphoProxyFactory__DistributorNotTrusted(_distributor)
        );
    }

    function isTrustedDistributor(address _distributor) external view override returns (bool) {
        return s_trustedDistributors[_distributor];
    }

    modifier onlyP2pOperator() {
        address p2pOperator = i_factory.getP2pOperator();
        require(
            msg.sender == p2pOperator,
            P2pOperator.P2pOperator__UnauthorizedAccount(msg.sender)
        );
        _;
    }
}
