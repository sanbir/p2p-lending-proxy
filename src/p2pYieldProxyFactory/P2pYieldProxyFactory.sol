// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../access/P2pOperator2Step.sol";
import "../common/AllowedCalldataChecker.sol";
import "./IP2pYieldProxyFactory.sol";
import "./features/FactoryDepositExecutor.sol";
import "./features/P2pSignerTransferable.sol";
import "./features/P2pSignerHashing.sol";
import "./features/DeterministicProxyCreation.sol";
import "./storage/P2pSignerStorage.sol";
import "./storage/AllProxiesStorage.sol";
import "./storage/ReferenceP2pYieldProxyStorage.sol";

/// @title P2pYieldProxyFactory
/// @author P2P Validator <info@p2p.org>
/// @notice P2pYieldProxyFactory is a factory contract for creating P2pYieldProxy contracts
abstract contract P2pYieldProxyFactory is
    AllowedCalldataChecker,
    P2pOperator2Step,
    ERC165,
    IP2pYieldProxyFactory,
    FactoryDepositExecutor,
    P2pSignerTransferable
{
    /// @notice Constructor for P2pYieldProxyFactory
    /// @param _p2pSigner The P2pSigner address
    constructor(address _p2pSigner) P2pOperator(msg.sender) {
        _setP2pSigner(_p2pSigner);
    }

    function deposit(
        address _asset,
        uint256 _amount,
        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline,
        bytes calldata _p2pSignerSignature
    )
        public
        virtual
        override(IP2pYieldProxyFactory, FactoryDepositExecutor)
        returns (address p2pYieldProxyAddress)
    {
        return super.deposit(_asset, _amount, _clientBasisPoints, _p2pSignerSigDeadline, _p2pSignerSignature);
    }

    function predictP2pYieldProxyAddress(address _client, uint96 _clientBasisPoints)
        public
        view
        virtual
        override(IP2pYieldProxyFactory, DeterministicProxyCreation)
        returns (address)
    {
        return super.predictP2pYieldProxyAddress(_client, _clientBasisPoints);
    }

    function getReferenceP2pYieldProxy()
        public
        view
        virtual
        override(IP2pYieldProxyFactory, ReferenceP2pYieldProxyStorage)
        returns (address)
    {
        return super.getReferenceP2pYieldProxy();
    }

    function getHashForP2pSigner(
        address _client,
        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline
    )
        public
        view
        virtual
        override(IP2pYieldProxyFactory, P2pSignerHashing)
        returns (bytes32)
    {
        return super.getHashForP2pSigner(_client, _clientBasisPoints, _p2pSignerSigDeadline);
    }

    function getP2pSigner()
        public
        view
        virtual
        override(IP2pYieldProxyFactory, P2pSignerStorage)
        returns (address)
    {
        return super.getP2pSigner();
    }

    function getAllProxies()
        public
        view
        virtual
        override(IP2pYieldProxyFactory, AllProxiesStorage)
        returns (address[] memory)
    {
        return super.getAllProxies();
    }

    function transferP2pSigner(address _newP2pSigner)
        public
        virtual
        override(IP2pYieldProxyFactory)
        onlyP2pOperator
    {
        _setP2pSigner(_newP2pSigner);
    }

    function transferP2pOperator(address _newP2pOperator)
        public
        virtual
        override(IP2pYieldProxyFactory, P2pOperator2Step)
        onlyP2pOperator
    {
        super.transferP2pOperator(_newP2pOperator);
    }

    function acceptP2pOperator()
        public
        virtual
        override(IP2pYieldProxyFactory, P2pOperator2Step)
    {
        super.acceptP2pOperator();
    }

    function getPendingP2pOperator()
        public
        view
        virtual
        override(IP2pYieldProxyFactory, P2pOperator2Step)
        returns (address)
    {
        return super.getPendingP2pOperator();
    }

    function getP2pOperator()
        public
        view
        virtual
        override(IP2pYieldProxyFactory, P2pOperator)
        returns (address)
    {
        return super.getP2pOperator();
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IP2pYieldProxyFactory).interfaceId || super.supportsInterface(interfaceId);
    }
}
