// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../@openzeppelin/contracts/proxy/Clones.sol";
import "../../p2pYieldProxy/P2pYieldProxy.sol";
import "../IP2pYieldProxyFactory.sol";
import "../interfaces/IFactoryPredictProxyAddress.sol";
import "../storage/AllProxiesStorage.sol";
import "../storage/ReferenceP2pYieldProxyStorage.sol";

abstract contract DeterministicProxyCreation is
    IFactoryPredictProxyAddress,
    ReferenceP2pYieldProxyStorage,
    AllProxiesStorage
{
    function predictP2pYieldProxyAddress(address _client, uint96 _clientBasisPoints)
        public
        view
        virtual
        override(IFactoryPredictProxyAddress)
        returns (address)
    {
        return Clones.predictDeterministicAddress(address(i_referenceP2pYieldProxy), _getSalt(_client, _clientBasisPoints));
    }

    function _getOrCreateP2pYieldProxy(uint96 _clientBasisPoints) internal returns (P2pYieldProxy p2pYieldProxy) {
        address p2pYieldProxyAddress = predictP2pYieldProxyAddress(msg.sender, _clientBasisPoints);
        if (p2pYieldProxyAddress.code.length > 0) {
            return P2pYieldProxy(p2pYieldProxyAddress);
        }

        p2pYieldProxy = P2pYieldProxy(
            Clones.cloneDeterministic(address(i_referenceP2pYieldProxy), _getSalt(msg.sender, _clientBasisPoints))
        );

        p2pYieldProxy.initialize(msg.sender, _clientBasisPoints);
        s_allProxies.push(address(p2pYieldProxy));

        emit IP2pYieldProxyFactory.P2pYieldProxyFactory__ProxyCreated(address(p2pYieldProxy), msg.sender, _clientBasisPoints);
    }

    function _getSalt(address _clientAddress, uint96 _clientBasisPoints) private pure returns (bytes32) {
        return keccak256(abi.encode(_clientAddress, _clientBasisPoints));
    }
}
