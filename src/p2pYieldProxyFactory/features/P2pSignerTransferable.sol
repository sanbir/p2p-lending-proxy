// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../IP2pYieldProxyFactory.sol";
import "../P2pYieldProxyFactoryErrors.sol";
import "../storage/P2pSignerStorage.sol";

abstract contract P2pSignerTransferable is P2pSignerStorage {
    function _setP2pSigner(address _newP2pSigner) internal {
        require(_newP2pSigner != address(0), P2pYieldProxyFactory__ZeroP2pSignerAddress());
        emit IP2pYieldProxyFactory.P2pYieldProxyFactory__P2pSignerTransferred(s_p2pSigner, _newP2pSigner);
        s_p2pSigner = _newP2pSigner;
    }
}
