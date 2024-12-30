// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../common/IAllowedCalldataChecker.sol";
import "../common/P2pStructs.sol";

/// @dev External interface of P2pLendingProxyFactory
interface IP2pLendingProxyFactory is IAllowedCalldataChecker, IERC165 {

    event P2pLendingProxyFactory__P2pSignerTransferred(
        address indexed _previousP2pSigner,
        address indexed _newP2pSigner
    );

    event P2pLendingProxyFactory__CalldataRulesSet(
        P2pStructs.FunctionType indexed _functionType,
        address indexed _contract,
        bytes4 indexed _selector,
        P2pStructs.Rule[] _rules
    );

    event P2pLendingProxyFactory__CalldataRulesRemoved(
        P2pStructs.FunctionType indexed _functionType,
        address indexed _contract,
        bytes4 indexed _selector
    );

    event P2pLendingProxyFactory__TrustedDistributorSet(
        address indexed _newTrustedDistributor
    );

    event P2pLendingProxyFactory__TrustedDistributorRemoved(
        address indexed _trustedDistributor
    );

    event P2pLendingProxyFactory__Deposited(
        address indexed _client,
        uint96 indexed _clientBasisPoints
    );

    function setCalldataRules(
        P2pStructs.FunctionType _functionType,
        address _contract,
        bytes4 _selector,
        P2pStructs.Rule[] calldata _rules
    ) external;

    function removeCalldataRules(
        P2pStructs.FunctionType _functionType,
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

    function checkMorphoUrdClaim(
        address _p2pOperatorToCheck,
        bool _shouldCheckP2pOperator,
        address _distributor
    ) external view;
}
