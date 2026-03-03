// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../../p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "../p2pResolvProxy/P2pResolvProxy.sol";

/// @title Entry point for depositing into Resolv with P2P.org
contract P2pResolvProxyFactory is P2pYieldProxyFactory {
    address private immutable i_referenceP2pYieldProxy;

    /// @notice Constructor for P2pResolvProxyFactory
    /// @param _p2pSigner The P2pSigner address
    /// @param _p2pTreasury The P2pTreasury address
    /// @param _stUSR stUSR address
    /// @param _USR USR address
    /// @param _stRESOLV stRESOLV
    /// @param _RESOLV RESOLV
    /// @param _allowedCalldataChecker AllowedCalldataChecker
    constructor(
        address _p2pSigner,
        address _p2pTreasury,
        address _stUSR,
        address _USR,
        address _stRESOLV,
        address _RESOLV,
        address _allowedCalldataChecker
    ) P2pYieldProxyFactory(_p2pSigner) {
        i_referenceP2pYieldProxy = address(
            new P2pResolvProxy(
                address(this),
                _p2pTreasury,
                _allowedCalldataChecker,
                _stUSR,
                _USR,
                _stRESOLV,
                _RESOLV
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
}
