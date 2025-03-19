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
    /// @param _SuperPositions SuperPositions address
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
    ) external payable {
        require (_superformCalldata.length > 4);
        bytes4 selector = bytes4(_superformCalldata[:4]);

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

    /// @inheritdoc IP2pEthenaProxy
    function cooldownAssets(uint256 _assets)
    external
    onlyClient
    returns (uint256 shares) {
        return IStakedUSDe(i_yieldProtocolAddress).cooldownAssets(_assets);
    }

    /// @inheritdoc IP2pEthenaProxy
    function cooldownShares(uint256 _shares)
    external
    onlyClient
    returns (uint256 assets) {
        return IStakedUSDe(i_yieldProtocolAddress).cooldownShares(_shares);
    }

    /// @inheritdoc IP2pEthenaProxy
    function withdrawAfterCooldown() external {
        _withdraw(
            i_USDe,
            abi.encodeCall(
                IStakedUSDe.unstake,
                (address(this))
            )
        );
    }


    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pYieldProxy) returns (bool) {
        return interfaceId == type(IP2pEthenaProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
