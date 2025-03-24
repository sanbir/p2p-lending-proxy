// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../p2pYieldProxy/P2pYieldProxy.sol";
import "../IBaseRouter.sol";
import "./IP2pSuperformProxy.sol";

contract P2pSuperformProxy is P2pYieldProxy, IP2pSuperformProxy {
    using SafeERC20 for IERC20;

    /// @dev USDe address
    address internal immutable i_superPositions;

    /// @notice Constructor for P2pEthenaProxy
    /// @param _factory Factory address
    /// @param _p2pTreasury P2pTreasury address
    /// @param _superformRouter SuperformRouter address
    /// @param _superPositions SuperPositions address
    constructor(
        address _factory,
        address _p2pTreasury,
        address _superformRouter,
        address _superPositions
    ) P2pYieldProxy(_factory, _p2pTreasury, _superformRouter) {
        i_superPositions = _superPositions;
    }

    /// @inheritdoc IP2pYieldProxy
    function deposit(
        IAllowanceTransfer.PermitSingle calldata _permitSingleForP2pYieldProxy,
        bytes calldata _permit2SignatureForP2pYieldProxy,
        bytes calldata _superformCalldata
    ) external override payable {
        require (_superformCalldata.length > 4);

        bytes4 selector = bytes4(_superformCalldata[:4]);
        require (selector == IBaseRouter.singleDirectSingleVaultDeposit.selector, "Selector not supported");

        SingleDirectSingleVaultStateReq memory req = abi.decode(_superformCalldata[4:], (SingleDirectSingleVaultStateReq));

        bool isNative = req.superformData.liqRequest.token == NATIVE;
        if (isNative) {
            require(msg.value >= req.superformData.liqRequest.nativeAmount);
            require(msg.value >= req.superformData.amount);
        } else {
            require(req.superformData.liqRequest.token == _permitSingleForP2pYieldProxy.details.token);
            // ETH can still be used to pay for bridging, swaps, etc., so msg.value can be > 0
        }
        require(!req.superformData.retain4626);
        require(req.superformData.receiverAddress == address(this));
        require(req.superformData.receiverAddressSP == address(this));

        _deposit(
            req.superformData.superformId,
            _superformCalldata,
        _permitSingleForP2pYieldProxy,
        _permit2SignatureForP2pYieldProxy,
            false,
            isNative
        );
    }

    function withdraw(
        bytes calldata _superformCalldata
    ) external {
        require (_superformCalldata.length > 4);
        bytes4 selector = bytes4(_superformCalldata[:4]);

        require (selector == IBaseRouter.singleDirectSingleVaultWithdraw.selector, "Selector not supported");

        SingleDirectSingleVaultStateReq memory req = abi.decode(_superformCalldata[4:], (SingleDirectSingleVaultStateReq));

        require(req.superformData.receiverAddress == address(this));
        require(req.superformData.receiverAddressSP == address(this));

        address superform = address(uint160(req.superformData.superformId));
        IERC4626 vault = IERC4626(superform);
        address asset = vault.asset();

        _withdraw(
            req.superformData.superformId,
            asset,
            _superformCalldata
        );
    }


    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pYieldProxy) returns (bool) {
        return interfaceId == type(IP2pSuperformProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
