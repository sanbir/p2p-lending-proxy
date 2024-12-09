// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../@permit2/libraries/Permit2Lib.sol";
import "../@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../@openzeppelin/contracts/utils/Address.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import "../p2pLendingProxyFactory/IP2pLendingProxyFactory.sol";
import "./IP2pLendingProxy.sol";

error P2pLendingProxy__NotFactory(address _factory);

/// @notice Only factory can call `initialize`.
/// @param _msgSender sender address.
/// @param _actualFactory the actual factory address that can call `initialize`.
error P2pLendingProxy__NotFactoryCalled(
    address _msgSender,
    IP2pLendingProxyFactory _actualFactory
);

contract P2pLendingProxy is ERC165, IP2pLendingProxy {

    IP2pLendingProxyFactory private immutable i_factory;

    address private s_client;
    uint96 private s_clientBasisPoints;

    /// @notice If caller is not factory, revert
    modifier onlyFactory() {
        if (msg.sender != address(i_factory)) {
            revert P2pLendingProxy__NotFactoryCalled(msg.sender, i_factory);
        }
        _;
    }

    constructor(
        address _factory
    ) {
        if (!ERC165Checker.supportsInterface(
            _factory,
            type(IP2pLendingProxyFactory).interfaceId)
        ) {
            revert P2pLendingProxy__NotFactory(_factory);
        }
        i_factory = IP2pLendingProxyFactory(_factory);
    }

    function initialize(
        address _client,
        uint96 _clientBasisPoints
    ) external onlyFactory
    {
        s_client = _client;
        s_clientBasisPoints = _clientBasisPoints;

        emit P2pLendingProxy__Initialized(_client, _clientBasisPoints);
    }

    function deposit(
        address lendingProtocolAddress,
        bytes calldata lendingProtocolCalldata,
        IAllowanceTransfer.PermitSingle memory permitSingleForP2pLendingProxy,
        bytes calldata permit2SignatureForP2pLendingProxy
    )
    external onlyFactory
    {
        address client = s_client;

        // transfer tokens into Proxy
        Permit2Lib.PERMIT2.permit(
            client,
            permitSingleForP2pLendingProxy,
            permit2SignatureForP2pLendingProxy
        );
        Permit2Lib.PERMIT2.transferFrom(
            client,
            address(this),
            permitSingleForP2pLendingProxy.details.amount,
            permitSingleForP2pLendingProxy.details.token
        );

        SafeERC20.safeApprove(
            permitSingleForP2pLendingProxy.details.token,
            address(Permit2Lib.PERMIT2),
            type(uint256).max
        );

        Address.functionCall(lendingProtocolAddress, lendingProtocolCalldata);
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165) returns (bool) {
        return interfaceId == type(IP2pLendingProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
