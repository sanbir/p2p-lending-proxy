// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "../p2pEthenaProxy/P2pEthenaProxy.sol";
import "./IP2pEthenaProxyFactory.sol";

/// @title Entry point for depositing into Ethena with P2P.org
contract P2pEthenaProxyFactory is IP2pEthenaProxyFactory, P2pYieldProxyFactory {
    address private immutable i_referenceP2pYieldProxy;

    /// @notice Constructor for P2pEthenaProxyFactory
    /// @param _p2pSigner The P2pSigner address
    /// @param _p2pTreasury The P2pTreasury address
    /// @param _allowedCalldataChecker AllowedCalldataChecker proxy address
    /// @param _stakedUSDeV2 StakedUSDeV2 vault address
    /// @param _USDe USDe token address
    constructor(
        address _p2pSigner,
        address _p2pTreasury,
        address _allowedCalldataChecker,
        address _stakedUSDeV2,
        address _USDe
    ) P2pYieldProxyFactory(_p2pSigner) {
        i_referenceP2pYieldProxy = address(
            new P2pEthenaProxy(
                address(this),
                _p2pTreasury,
                _allowedCalldataChecker,
                _stakedUSDeV2,
                _USDe
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

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(P2pYieldProxyFactory)
        returns (bool)
    {
        return interfaceId == type(IP2pEthenaProxyFactory).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
