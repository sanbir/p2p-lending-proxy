// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../@permit2/interfaces/IAllowanceTransfer.sol";
import "../../../p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "../p2pEthenaProxy/P2pEthenaProxy.sol";
import "./IP2pEthenaProxyFactory.sol";
import {IERC4626} from "../../../@openzeppelin/contracts/interfaces/IERC4626.sol";

contract P2pEthenaProxyFactory is P2pYieldProxyFactory, IP2pEthenaProxyFactory {

    /// @notice Constructor for P2pEthenaProxyFactory
    /// @param _p2pSigner The P2pSigner address
    /// @param _p2pTreasury The P2pTreasury address
    /// @param _stakedUSDeV2 StakedUSDeV2
    /// @param _USDe USDe address
    constructor(
        address _p2pSigner,
        address _p2pTreasury,
        address _stakedUSDeV2,
        address _USDe
    ) P2pYieldProxyFactory(_p2pSigner) {
        i_referenceP2pYieldProxy = new P2pEthenaProxy(
            address(this),
            _p2pTreasury,
            _stakedUSDeV2,
            _USDe
        );
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pYieldProxyFactory) returns (bool) {
        return interfaceId == type(IP2pEthenaProxyFactory).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
