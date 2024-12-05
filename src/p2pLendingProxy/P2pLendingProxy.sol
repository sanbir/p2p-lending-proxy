// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

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
    ) external onlyFactory {
        s_client = _client;
        s_clientBasisPoints = _clientBasisPoints;

        i_ssvToken.approve(address(i_ssvNetwork), type(uint256).max);

        emit P2pLendingProxy__Initialized(_client, _clientBasisPoints);
    }
}
