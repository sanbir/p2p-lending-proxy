// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "./P2pLendingProxyFactoryStructs.sol";

/// @dev External interface of P2pLendingProxyFactory
interface IP2pLendingProxyFactory is IERC165 {

    /// @notice Set allowed calldata for a specific contract and selector
    /// @param _contract The contract address
    /// @param _selector The selector of the function
    /// @param _allowedCalldata The allowed calldata for the function
    function setAllowedFunctionForContract(
        address _contract,
        bytes4 _selector,
        P2pLendingProxyFactoryStructs.AllowedCalldata calldata _allowedCalldata
    ) external;

    /// @notice Remove allowed calldata for a specific contract and selector
    /// @param _contract The contract address
    /// @param _selector The selector of the function
    function removeAllowedFunctionForContract(
        address _contract,
        bytes4 _selector
    ) external;

    function deposit(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,
        IAllowanceTransfer.PermitSingle memory _permitSingleForP2pLendingProxy,
        bytes calldata _permit2SignatureForP2pLendingProxy,

        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline,
        bytes calldata _p2pSignerSignature
    )
    external
    returns (address p2pLendingProxyAddress);

    function isAllowedCalldata(
        address _target,
        bytes4 _selector,
        bytes calldata _calldataAfterSelector,
        P2pLendingProxyFactoryStructs.FunctionType _functionType
    ) external view returns (bool);

    /// @notice Computes the address of a P2pLendingProxy created by `_createP2pLendingProxy` function
    /// @dev P2pLendingProxy instances are guaranteed to have the same address if _feeDistributorInstance is the same
    /// @param _client The address of client
    /// @return _clientBasisPoints
    function predictP2pLendingProxyAddress(
        address _client,
        uint96 _clientBasisPoints
    ) external view returns (address);

    function getHashForP2pSigner(
        address _client,
        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline
    ) external view returns (bytes32);

    /// @notice Returns a template set by P2P to be used for new P2pLendingProxy instances
    /// @return a template set by P2P to be used for new P2pLendingProxy instances
    function getReferenceP2pLendingProxy() external view returns (address);
}
