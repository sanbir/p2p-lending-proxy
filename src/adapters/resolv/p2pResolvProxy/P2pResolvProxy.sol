// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../p2pYieldProxy/P2pYieldProxy.sol";
import "../IStUSR.sol";
import "./IP2pResolvProxy.sol";

error P2pResolvProxy__ZeroAddress_USR();

contract P2pResolvProxy is P2pYieldProxy, IP2pResolvProxy {
    using SafeERC20 for IERC20;

    /// @dev USDe address
    address internal immutable i_USR;

    /// @notice Constructor for P2pResolvProxy
    /// @param _factory Factory address
    /// @param _p2pTreasury P2pTreasury address
    /// @param _stUSR stUSR address
    /// @param _USR USR address
    constructor(
        address _factory,
        address _p2pTreasury,
        address _stUSR,
        address _USR
    ) P2pYieldProxy(_factory, _p2pTreasury, _stUSR) {
        require(_USR != address(0), P2pResolvProxy__ZeroAddress_USR());

        i_USR = _USR;
    }

    /// @inheritdoc IP2pYieldProxy
    function deposit(
        IAllowanceTransfer.PermitSingle calldata _permitSingleForP2pYieldProxy,
        bytes calldata _permit2SignatureForP2pYieldProxy
    ) external {
        _deposit(
            abi.encodeWithSelector(
                bytes4(keccak256("deposit(uint256,address)")),
                uint256(_permitSingleForP2pYieldProxy.details.amount),
                address(this)
            ),
            _permitSingleForP2pYieldProxy,
            _permit2SignatureForP2pYieldProxy,
            false
        );
    }

    /// @inheritdoc IP2pResolvProxy
    function withdraw(uint256 _assets)
    external
    onlyClient {
        IStUSR(i_yieldProtocolAddress).withdraw(_assets);
    }

    /// @inheritdoc IP2pResolvProxy
    function withdrawAll()
    external
    onlyClient {
        IStUSR(i_yieldProtocolAddress).withdrawAll();
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pYieldProxy) returns (bool) {
        return interfaceId == type(IP2pResolvProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
