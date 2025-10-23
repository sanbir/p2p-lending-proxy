// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
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
        P2pStructs.FunctionType indexed _functionType,
        address indexed _contract,
        bytes4 indexed _selector,
        P2pStructs.Rule[] _rules
    );

    /// @dev Emitted when the calldata rules are removed
    event P2pLendingProxyFactory__CalldataRulesRemoved(
        P2pStructs.FunctionType indexed _functionType,
        address indexed _contract,
        bytes4 indexed _selector
    );

    /// @dev Emitted when the deposit is made
    event P2pLendingProxyFactory__Deposited(
        address indexed _client,
        uint96 indexed _clientBasisPoints
    );

    /// @dev Sets the calldata rules
    /// @param _functionType The function type
    /// @param _contract The contract address
    /// @param _selector The selector
    /// @param _rules The rules
    function setCalldataRules(
        P2pStructs.FunctionType _functionType,
        address _contract,
        bytes4 _selector,
        P2pStructs.Rule[] calldata _rules
    ) external;

    /// @dev Removes the calldata rules
    /// @param _functionType The function type
    /// @param _contract The contract address
    /// @param _selector The selector
    function removeCalldataRules(
        P2pStructs.FunctionType _functionType,
        address _contract,
        bytes4 _selector
    ) external;

    /// @dev Deposits into a lending protocol via the client's proxy
    /// @param _vault The vault that receives the deposit
    /// @param _amount The amount of asset being supplied
    /// @param _clientBasisPoints The client basis points
    /// @param _p2pSignerSigDeadline The P2pSigner signature deadline
    /// @param _p2pSignerSignature The P2pSigner signature
    /// @return p2pLendingProxyAddress The client's P2pLendingProxy instance address
    function deposit(
        address _vault,
        uint256 _amount,

        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline,
        bytes calldata _p2pSignerSignature
    )
    external
    returns (address p2pLendingProxyAddress);

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

    /// @dev Gets the calldata rules
    /// @param _functionType The function type
    /// @param _contract The contract address
    /// @param _selector The selector
    /// @return The calldata rules
    function getCalldataRules(
        P2pStructs.FunctionType _functionType,
        address _contract,
        bytes4 _selector
    ) external view returns (P2pStructs.Rule[] memory);

    /// @dev Gets the P2pSigner
    /// @return The P2pSigner address
    function getP2pSigner() external view returns (address);

    /// @dev Gets the P2pOperator
    /// @return The P2pOperator address
    function getP2pOperator() external view returns (address);

    /// @dev Gets all proxies
    /// @return The proxy addresses
    function getAllProxies() external view returns (address[] memory);
}
