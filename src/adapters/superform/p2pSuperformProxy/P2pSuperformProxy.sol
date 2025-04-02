// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../p2pYieldProxy/P2pYieldProxy.sol";
import "../IBaseRouter.sol";
import "../IERC1155A.sol";
import "./IP2pSuperformProxy.sol";

error P2pSuperformProxy__SuperformCalldataTooShort();
error P2pSuperformProxy__SelectorNotSupported(bytes4 _selector);
error P2pSuperformProxy__MsgValueLessThanliqRequestNativeAmount(
    uint256 _msgValue,
    uint256 _liqRequestNativeAmount
);
error P2pSuperformProxy__MsgValueLessThanAmount(
    uint256 _msgValue,
    uint256 _amount
);
error P2pSuperformProxy__LiqRequestTokenShouldBeEqualToPermitSingleForP2pYieldProxyToken(
    address _liqRequestToken,
    address _permitSingleForP2pYieldProxyToken
);
error P2pSuperformProxy__ShouldNotRetain4626();
error P2pSuperformProxy__ReceiverAddressShouldBeP2pSuperformProxy(
    address _receiverAddress
);
error P2pSuperformProxy__ReceiverAddressSPShouldBeP2pSuperformProxy(
    address _receiverAddressSP
);
error P2pSuperformProxy__AssetShouldNotBeZeroAddress();

contract P2pSuperformProxy is P2pYieldProxy, IP2pSuperformProxy {
    using SafeERC20 for IERC20;

    address internal immutable i_superPositions;

    /// @notice Constructor for P2pEthenaProxy
    /// @param _factory Factory address
    /// @param _p2pTreasury P2pTreasury address
    /// @param _superformRouter SuperformRouter address
    /// @param _superPositions SuperPositions address
    /// @param _allowedCalldataChecker AllowedCalldataChecker
    constructor(
        address _factory,
        address _p2pTreasury,
        address _superformRouter,
        address _superPositions,
        address _allowedCalldataChecker
    ) P2pYieldProxy(_factory, _p2pTreasury, _superformRouter, _allowedCalldataChecker) {
        i_superPositions = _superPositions;
    }

    /// @inheritdoc IP2pYieldProxy
    function deposit(
        IAllowanceTransfer.PermitSingle calldata _permitSingleForP2pYieldProxy,
        bytes calldata _permit2SignatureForP2pYieldProxy,
        bytes calldata _superformCalldata
    ) external override payable {
        require (_superformCalldata.length > 4, P2pSuperformProxy__SuperformCalldataTooShort());

        bytes4 selector = bytes4(_superformCalldata[:4]);
        require (
            selector == IBaseRouter.singleDirectSingleVaultDeposit.selector,
            P2pSuperformProxy__SelectorNotSupported(selector)
        );

        SingleDirectSingleVaultStateReq memory req = abi.decode(_superformCalldata[4:], (SingleDirectSingleVaultStateReq));

        bool isNative = req.superformData.liqRequest.token == NATIVE;
        if (isNative) {
            require (
                msg.value >= req.superformData.liqRequest.nativeAmount,
                P2pSuperformProxy__MsgValueLessThanliqRequestNativeAmount(msg.value, req.superformData.liqRequest.nativeAmount)
            );
            require (
                msg.value >= req.superformData.amount,
                P2pSuperformProxy__MsgValueLessThanAmount(msg.value, req.superformData.amount)
            );
        } else {
            require (
                req.superformData.liqRequest.token == _permitSingleForP2pYieldProxy.details.token,
                P2pSuperformProxy__LiqRequestTokenShouldBeEqualToPermitSingleForP2pYieldProxyToken(
                    req.superformData.liqRequest.token,
                    _permitSingleForP2pYieldProxy.details.token
                )
            );
            // ETH can still be used to pay for bridging, swaps, etc., so msg.value can be > 0
        }
        require (!req.superformData.retain4626, P2pSuperformProxy__ShouldNotRetain4626());
        require (
            req.superformData.receiverAddress == address(this),
            P2pSuperformProxy__ReceiverAddressShouldBeP2pSuperformProxy(req.superformData.receiverAddress)
        );
        require (
            req.superformData.receiverAddressSP == address(this),
            P2pSuperformProxy__ReceiverAddressSPShouldBeP2pSuperformProxy(req.superformData.receiverAddressSP)
        );

        _deposit(
            req.superformData.superformId,
            _superformCalldata,
        _permitSingleForP2pYieldProxy,
        _permit2SignatureForP2pYieldProxy,
            false,
            isNative
        );

        IERC1155A(i_superPositions).increaseAllowance(
            i_yieldProtocolAddress,
            req.superformData.superformId,
            req.superformData.outputAmount
        );
    }

    function withdraw(
        bytes calldata _superformCalldata
    ) external {
        require (_superformCalldata.length > 4, P2pSuperformProxy__SuperformCalldataTooShort());
        bytes4 selector = bytes4(_superformCalldata[:4]);

        require (
            selector == IBaseRouter.singleDirectSingleVaultWithdraw.selector,
            P2pSuperformProxy__SelectorNotSupported(selector)
        );

        SingleDirectSingleVaultStateReq memory req = abi.decode(_superformCalldata[4:], (SingleDirectSingleVaultStateReq));

        require (
            req.superformData.receiverAddress == address(this),
            P2pSuperformProxy__ReceiverAddressShouldBeP2pSuperformProxy(req.superformData.receiverAddress)
        );
        require (
            req.superformData.receiverAddressSP == address(this),
            P2pSuperformProxy__ReceiverAddressSPShouldBeP2pSuperformProxy(req.superformData.receiverAddressSP)
        );

        address asset;
        if (req.superformData.liqRequest.token == address(0)) {
            address superform = address(uint160(req.superformData.superformId));
            IERC4626 vault = IERC4626(superform);
            asset = vault.asset();
        } else {
            asset = req.superformData.liqRequest.token;
        }
        require (asset != address(0), P2pSuperformProxy__AssetShouldNotBeZeroAddress());

        _withdraw(
            req.superformData.superformId,
            asset,
            _superformCalldata
        );
    }

    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external pure returns (bytes4) {
        return bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external pure returns (bytes4) {
        return bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"));
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pYieldProxy, IERC165) returns (bool) {
        return interfaceId == type(IP2pSuperformProxy).interfaceId ||
            interfaceId == type(IERC1155Receiver).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
