// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../p2pYieldProxy/P2pYieldProxy.sol";
import "../interfaces/IFactoryGetReferenceProxy.sol";

abstract contract ReferenceP2pYieldProxyStorage is IFactoryGetReferenceProxy {
    P2pYieldProxy internal i_referenceP2pYieldProxy;

    function getReferenceP2pYieldProxy()
        public
        view
        virtual
        override(IFactoryGetReferenceProxy)
        returns (address)
    {
        return address(i_referenceP2pYieldProxy);
    }
}
