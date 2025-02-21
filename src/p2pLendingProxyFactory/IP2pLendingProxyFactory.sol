// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../common/IAllowedCalldataChecker.sol";
import "../common/P2pStructs.sol";

/// @dev External interface of P2pLendingProxyFactory
interface IP2pLendingProxyFactory is IAllowedCalldataChecker, IERC165 {

    /// @dev Emitted when the P2pSigner is transferred
    event P2pLendingProxyFactory__P2pSignerTransferred(
        address indexed _previousP2pSigner,
        address indexed _newP2pSigner
    );

    /// @dev Emitted when the calldata rules are set
    event P2pLendingProxyFactory__CalldataRulesSet(
        address indexed _contract,
        bytes4 indexed _selector,
        P2pStructs.Rule[] _rules
    );

    /// @dev Emitted when the calldata rules are removed
    event P2pLendingProxyFactory__CalldataRulesRemoved(
        address indexed _contract,
        bytes4 indexed _selector
    );

    /// @dev Emitted when the deposit is made
    event P2pLendingProxyFactory__Deposited(
        address indexed _client,
        uint96 indexed _clientBasisPoints
    );

    /// @dev Sets the calldata rules
    /// @param _contract The contract address
    /// @param _selector The selector
    /// @param _rules The rules
    function setCalldataRules(
        address _contract,
        bytes4 _selector,
        P2pStructs.Rule[] calldata _rules
    ) external;

    /// @dev Removes the calldata rules
    /// @param _contract The contract address
    /// @param _selector The selector
    function removeCalldataRules(
        address _contract,
        bytes4 _selector
    ) external;

    /// @dev Computes the address of a P2pLendingProxy created by `_createP2pLendingProxy` function
    /// @dev P2pLendingProxy instances are guaranteed to have the same address if _feeDistributorInstance is the same
    /// @param _client The address of client
    /// @return address The address of the P2pLendingProxy instance
    function predictP2pLendingProxyAddress(
        address _client,
        uint96 _clientBasisPoints
    ) external view returns (address);

    /// @dev Transfers the P2pSigner
    /// @param _newP2pSigner The new P2pSigner address
    function transferP2pSigner(
        address _newP2pSigner
    ) external;

    /// @dev Returns a template set by P2P to be used for new P2pLendingProxy instances
    /// @return a template set by P2P to be used for new P2pLendingProxy instances
    function getReferenceP2pLendingProxy() external view returns (address);

    /// @dev Gets the hash for the P2pSigner
    /// @param _client The address of client
    /// @param _clientBasisPoints The client basis points
    /// @param _p2pSignerSigDeadline The P2pSigner signature deadline
    /// @return The hash for the P2pSigner
    function getHashForP2pSigner(
        address _client,
        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline
    ) external view returns (bytes32);

    /// @dev Gets the permit2 hash typed data
    /// @param _permitSingle The permit single
    /// @return The permit2 hash typed data
    function getPermit2HashTypedData(IAllowanceTransfer.PermitSingle calldata _permitSingle) external view returns (bytes32);

    /// @dev Gets the permit2 hash typed data
    /// @param _permitHash The permit hash
    /// @return The permit2 hash typed data
    function getPermit2HashTypedData(bytes32 _permitHash) external view returns (bytes32);

    /// @dev Gets the permit hash
    /// @param _permitSingle The permit single
    /// @return The permit hash
    function getPermitHash(IAllowanceTransfer.PermitSingle calldata _permitSingle) external view returns (bytes32);

    /// @dev Gets the calldata rules
    /// @param _contract The contract address
    /// @param _selector The selector
    /// @return The calldata rules
    function getCalldataRules(
        address _contract,
        bytes4 _selector
    ) external view returns (P2pStructs.Rule[] memory);

    /// @dev Gets the P2pSigner
    /// @return The P2pSigner address
    function getP2pSigner() external view returns (address);

    /// @dev Gets all proxies
    /// @return The proxy addresses
    function getAllProxies() external view returns (address[] memory);
}
