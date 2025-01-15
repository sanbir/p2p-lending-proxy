// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../p2pLendingProxyFactory/P2pLendingProxyFactory.sol";

error P2pMorphoProxyFactory__IncorrectLengthOf_dataForMulticall();
error P2pMorphoProxyFactory__InvalidSlice();
error P2pMorphoProxyFactory__approve2_amount_ne_permitSingleForP2pLendingProxy_amount();
error P2pMorphoProxyFactory__transferFrom2_amount_ne_permitSingleForP2pLendingProxy_amount();
error P2pMorphoProxyFactory__erc4626Deposit_assets_ne_permitSingleForP2pLendingProxy_amount();
error P2pMorphoProxyFactory__approve2_token_ne_permitSingleForP2pLendingProxy_token();
error P2pMorphoProxyFactory__transferFrom2_asset_ne_permitSingleForP2pLendingProxy_token();
error P2pMorphoProxyFactory__erc4626Deposit_receiver_ne_proxy();

contract P2pMorphoProxyFactory is P2pLendingProxyFactory {

    uint256 private constant SELECTOR_LENGTH = 4;

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
        bytes[] memory dataForMulticall = abi.decode(_lendingProtocolCalldata[SELECTOR_LENGTH:], (bytes[]));

        require(
            dataForMulticall.length == 3,
            P2pMorphoProxyFactory__IncorrectLengthOf_dataForMulticall()
        );

        // morpho approve2
        (IAllowanceTransfer.PermitSingle memory permitSingle,,) = abi.decode(
            _slice(dataForMulticall[0], SELECTOR_LENGTH, dataForMulticall[0].length - SELECTOR_LENGTH),
            (IAllowanceTransfer.PermitSingle, bytes, bool)
        );

        // morpho transferFrom2
        (address asset, uint256 amount) = abi.decode(
            _slice(dataForMulticall[1], SELECTOR_LENGTH, dataForMulticall[1].length - SELECTOR_LENGTH),
            (address, uint256)
        );

        // morpho erc4626Deposit
        (,uint256 assets,, address receiver) = abi.decode(
            _slice(dataForMulticall[2], SELECTOR_LENGTH, dataForMulticall[2].length - SELECTOR_LENGTH),
            (address, uint256, uint256, address)
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

    // Helper function to slice bytes
    function _slice(bytes memory data, uint256 start, uint256 length) internal pure returns (bytes memory) {
        require(
            data.length >= (start + length),
            P2pMorphoProxyFactory__InvalidSlice()
        );

        bytes memory tempBytes;

        assembly {
            switch iszero(length)
            case 0 {
            // Allocate memory for the sliced bytes
                tempBytes := mload(0x40)
            // Set the length
                mstore(tempBytes, length)
            // Copy the data
                let src := add(data, add(0x20, start))
                let dest := add(tempBytes, 0x20)
                for { let i := 0 } lt(i, length) { i := add(i, 0x20) } {
                    mstore(add(dest, i), mload(add(src, i)))
                }
            // Update the free memory pointer
                mstore(0x40, add(dest, length))
            }
            default {
                tempBytes := mload(0x40)
                mstore(tempBytes, 0)
                mstore(0x40, add(tempBytes, 0x20))
            }
        }

        return tempBytes;
    }
}
