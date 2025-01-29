// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../@permit2/interfaces/IAllowanceTransfer.sol";
import "../../../p2pLendingProxyFactory/P2pLendingProxyFactory.sol";
import "../p2pEthenaProxy/P2pEthenaProxy.sol";
import "./IP2pEthenaProxyFactory.sol";
import {IERC4626} from "../../../@openzeppelin/contracts/interfaces/IERC4626.sol";

contract P2pEthenaProxyFactory is P2pLendingProxyFactory, IP2pEthenaProxyFactory {

    /// @notice Constructor for P2pMorphoProxyFactory
    /// @param _p2pSigner The P2pSigner address
    /// @param _p2pTreasury The P2pTreasury address
    /// @param _stakedUSDeV2 StakedUSDeV2
    constructor(
        address _p2pSigner,
        address _p2pTreasury,
        address _stakedUSDeV2
    ) P2pLendingProxyFactory(_p2pSigner) {
        i_referenceP2pLendingProxy = new P2pEthenaProxy(
            address(this),
            _p2pTreasury,
            _stakedUSDeV2
        );
    }

    function deposit(
        IAllowanceTransfer.PermitSingle calldata _permitSingleForP2pLendingProxy,
        bytes calldata _permit2SignatureForP2pLendingProxy,

        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline,
        bytes calldata _p2pSignerSignature
    )
    external
    returns (address p2pLendingProxyAddress) {
        return _deposit(
            abi.encodeCall(
                IStakedUSDe.deposit,
                (uint256(_permitSingleForP2pLendingProxy.details.amount), address(this))
            ),
            false,

            _permitSingleForP2pLendingProxy,
            _permit2SignatureForP2pLendingProxy,

            _clientBasisPoints,
            _p2pSignerSigDeadline,
            _p2pSignerSignature
        );
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pLendingProxyFactory) returns (bool) {
        return interfaceId == type(IP2pEthenaProxyFactory).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
