// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../p2pLendingProxyFactory/P2pLendingProxyFactory.sol";

error P2pMorphoProxyFactory__approve2_amount_ne_permitSingleForP2pLendingProxy_amount();
error P2pMorphoProxyFactory__transferFrom2_amount_ne_permitSingleForP2pLendingProxy_amount();
error P2pMorphoProxyFactory__erc4626Deposit_assets_ne_permitSingleForP2pLendingProxy_amount();
error P2pMorphoProxyFactory__approve2_token_ne_permitSingleForP2pLendingProxy_token();
error P2pMorphoProxyFactory__transferFrom2_asset_ne_permitSingleForP2pLendingProxy_token();
error P2pMorphoProxyFactory__erc4626Deposit_receiver_ne_proxy();

contract P2pMorphoProxyFactory is P2pLendingProxyFactory {

    /// @notice Constructor for P2pMorphoProxyFactory
    /// @param _morphoBundler The morpho bundler address
    /// @param _p2pSigner The P2pSigner address
    /// @param _p2pTreasury The P2pTreasury address
    constructor(
        address _morphoBundler,
        address _p2pSigner,
        address _p2pTreasury
    ) P2pLendingProxyFactory(_morphoBundler, _p2pSigner, _p2pTreasury) {
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function deposit(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,

        IAllowanceTransfer.PermitSingle memory _permitSingleForP2pLendingProxy,
        bytes calldata _permit2SignatureForP2pLendingProxy,

        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline,
        bytes calldata _p2pSignerSignature
    )
    public
    override
    returns (address p2pLendingProxyAddress) {
        // morpho multicall
        (, bytes[] memory dataForMulticall) = abi.decode(
            _lendingProtocolCalldata,
            (bytes4, bytes[])
        );

        // morpho approve2
        (, IAllowanceTransfer.PermitSingle memory permitSingle,,) = abi.decode(
            dataForMulticall[0],
            (bytes4, IAllowanceTransfer.PermitSingle, bytes, bool)
        );

        // morpho transferFrom2
        (, address asset, uint256 amount) = abi.decode(
            dataForMulticall[1],
            (bytes4, address, uint256)
        );

        // morpho erc4626Deposit
        (,, uint256 assets,, address receiver) = abi.decode(
            dataForMulticall[2],
            (bytes4, address, uint256, uint256, address)
        );

        require(
            permitSingle.details.amount == _permitSingleForP2pLendingProxy.details.amount,
            P2pMorphoProxyFactory__approve2_amount_ne_permitSingleForP2pLendingProxy_amount()
        );
        require(
            amount == _permitSingleForP2pLendingProxy.details.amount,
            P2pMorphoProxyFactory__transferFrom2_amount_ne_permitSingleForP2pLendingProxy_amount()
        );
        require(
            assets == _permitSingleForP2pLendingProxy.details.amount,
            P2pMorphoProxyFactory__erc4626Deposit_assets_ne_permitSingleForP2pLendingProxy_amount()
        );

        require(
            permitSingle.details.token == _permitSingleForP2pLendingProxy.details.token,
            P2pMorphoProxyFactory__approve2_token_ne_permitSingleForP2pLendingProxy_token()
        );
        require(
            asset == _permitSingleForP2pLendingProxy.details.token,
            P2pMorphoProxyFactory__transferFrom2_asset_ne_permitSingleForP2pLendingProxy_token()
        );

        address proxy = predictP2pLendingProxyAddress(
            msg.sender,
            _clientBasisPoints
        );
        require(
            receiver == proxy,
            P2pMorphoProxyFactory__erc4626Deposit_receiver_ne_proxy()
        );

        return super.deposit(
            _lendingProtocolAddress,
            _lendingProtocolCalldata,

            _permitSingleForP2pLendingProxy,
            _permit2SignatureForP2pLendingProxy,

            _clientBasisPoints,
            _p2pSignerSigDeadline,
            _p2pSignerSignature
        );
    }
}
