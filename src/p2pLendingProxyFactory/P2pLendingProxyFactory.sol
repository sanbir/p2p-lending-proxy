// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/proxy/Clones.sol";
import "../@openzeppelin/contracts/utils/Address.sol";
import "../@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../@permit2/libraries/PermitHash.sol";
import "../access/P2pOperator2Step.sol";
import "../common/AllowedCalldataChecker.sol";
import "../common/P2pStructs.sol";
import "../p2pLendingProxy/P2pLendingProxy.sol";
import "./IP2pLendingProxyFactory.sol";

/// @dev Error when the P2pSigner address is zero
error P2pLendingProxyFactory__ZeroP2pSignerAddress();

/// @dev Error when the P2pSigner signature is invalid
error P2pLendingProxyFactory__InvalidP2pSignerSignature();

/// @dev Error when the P2pSigner signature is expired
error P2pLendingProxyFactory__P2pSignerSignatureExpired(
    uint256 _p2pSignerSigDeadline
);

/// @dev Error when no rules are defined
error P2pLendingProxyFactory__NoRulesDefined(
    P2pStructs.FunctionType _functionType,
    address _target,
    bytes4 _selector
);

/// @dev Error when no calldata is allowed
error P2pLendingProxyFactory__NoCalldataAllowed(
    P2pStructs.FunctionType _functionType,
    address _target,
    bytes4 _selector
);

/// @dev Error when the calldata is too short for the start with rule
error P2pLendingProxyFactory__CalldataTooShortForStartsWithRule(
    uint256 _calldataAfterSelectorLength,
    uint32 _ruleIndex,
    uint32 _bytesCount
);

/// @dev Error when the calldata starts with rule is violated
error P2pLendingProxyFactory__CalldataStartsWithRuleViolated(
    bytes _actual,
    bytes _expected
);

/// @dev Error when the calldata is too short for the ends with rule
error P2pLendingProxyFactory__CalldataTooShortForEndsWithRule(
    uint256 _calldataAfterSelectorLength,
    uint32 _bytesCount
);

/// @dev Error when the calldata ends with rule is violated
error P2pLendingProxyFactory__CalldataEndsWithRuleViolated(
    bytes _actual,
    bytes _expected
);

/// @title P2pLendingProxyFactory
/// @author P2P Validator <info@p2p.org>
/// @notice P2pLendingProxyFactory is a factory contract for creating P2pLendingProxy contracts
abstract contract P2pLendingProxyFactory is
    AllowedCalldataChecker,
    P2pOperator2Step,
    P2pStructs,
    ERC165,
    IP2pLendingProxyFactory {

    using SafeCast160 for uint256;
    using SignatureChecker for address;
    using ECDSA for bytes32;

    /// @notice Reference P2pLendingProxy contract
    P2pLendingProxy internal immutable i_referenceP2pLendingProxy;

    // FunctionType => Contract => Selector => Rule[]
    // all rules must be followed for (FunctionType, Contract, Selector)
    mapping(FunctionType => mapping(address => mapping(bytes4 => Rule[]))) internal s_calldataRules;

    /// @notice P2pSigner address   
    address internal s_p2pSigner;

    /// @notice All proxies
    address[] internal s_allProxies;

    /// @notice Modifier to check if the P2pSigner signature should not expire
    modifier p2pSignerSignatureShouldNotExpire(uint256 _p2pSignerSigDeadline) {
        require (
            block.timestamp < _p2pSignerSigDeadline,
            P2pLendingProxyFactory__P2pSignerSignatureExpired(_p2pSignerSigDeadline)
        );
        _;
    }

    /// @notice Modifier to check if the P2pSigner signature should be valid
    modifier p2pSignerSignatureShouldBeValid(
        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline,
        bytes calldata _p2pSignerSignature
    ) {
        require (
            s_p2pSigner.isValidSignatureNow(
            getHashForP2pSigner(
            msg.sender,
            _clientBasisPoints,
            _p2pSignerSigDeadline
                ).toEthSignedMessageHash(),
        _p2pSignerSignature
            ),
            P2pLendingProxyFactory__InvalidP2pSignerSignature()
        );
        _;
    }

    /// @notice Constructor for P2pLendingProxyFactory
    /// @param _p2pSigner The P2pSigner address
    constructor(
        address _p2pSigner
    ) P2pOperator(msg.sender) {
        _transferP2pSigner(_p2pSigner);
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function transferP2pSigner(
        address _newP2pSigner
    ) external onlyP2pOperator {
        _transferP2pSigner(_newP2pSigner);
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function setCalldataRules(
        FunctionType _functionType,
        address _contract,
        bytes4 _selector,
        Rule[] calldata _rules
    ) external onlyP2pOperator {
        s_calldataRules[_functionType][_contract][_selector] = _rules;
        emit P2pLendingProxyFactory__CalldataRulesSet(
            _functionType,
            _contract,
            _selector,
            _rules
        );
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function removeCalldataRules(
        FunctionType _functionType,
        address _contract,
        bytes4 _selector
    ) external onlyP2pOperator {
        delete s_calldataRules[_functionType][_contract][_selector];
        emit P2pLendingProxyFactory__CalldataRulesRemoved(
            _functionType,
            _contract,
            _selector
        );
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function deposit(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,

        IAllowanceTransfer.PermitSingle memory _permitSingleForP2pLendingProxy,
        bytes calldata _permit2SignatureForP2pLendingProxy,

        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline,
        bytes calldata _p2pSignerSignature
    )
    public
    virtual
    p2pSignerSignatureShouldNotExpire(_p2pSignerSigDeadline)
    p2pSignerSignatureShouldBeValid(_clientBasisPoints, _p2pSignerSigDeadline, _p2pSignerSignature)
    calldataShouldBeAllowed(_lendingProtocolAddress, _lendingProtocolCalldata, FunctionType.Deposit)
    returns (address p2pLendingProxyAddress)
    {
        // create proxy if not created yet
        P2pLendingProxy p2pLendingProxy = _getOrCreateP2pLendingProxy(_clientBasisPoints);

        // deposit via proxy
        p2pLendingProxy.deposit(
            _lendingProtocolAddress,
            _lendingProtocolCalldata,
            _permitSingleForP2pLendingProxy,
            _permit2SignatureForP2pLendingProxy
        );

        emit P2pLendingProxyFactory__Deposited(msg.sender, _clientBasisPoints);

        p2pLendingProxyAddress = address(p2pLendingProxy);
    }

    function _transferP2pSigner(
        address _newP2pSigner
    ) private {
        require (_newP2pSigner != address(0), P2pLendingProxyFactory__ZeroP2pSignerAddress());
        emit P2pLendingProxyFactory__P2pSignerTransferred(s_p2pSigner, _newP2pSigner);
        s_p2pSigner = _newP2pSigner;
    }

    /// @notice Creates a new P2pLendingProxy contract instance if not created yet
    function _getOrCreateP2pLendingProxy(uint96 _clientBasisPoints)
    private
    returns (P2pLendingProxy p2pLendingProxy)
    {
        address p2pLendingProxyAddress = predictP2pLendingProxyAddress(
            msg.sender,
            _clientBasisPoints
        );
        uint256 codeSize = p2pLendingProxyAddress.code.length;
        if (codeSize > 0) {
            return P2pLendingProxy(p2pLendingProxyAddress);
        }

        p2pLendingProxy = P2pLendingProxy(
                Clones.cloneDeterministic(
                address(i_referenceP2pLendingProxy),
                _getSalt(
                    msg.sender,
                    _clientBasisPoints
                )
            )
        );

        p2pLendingProxy.initialize(
            msg.sender,
            _clientBasisPoints
        );

        s_allProxies.push(address(p2pLendingProxy));
    }

    /// @notice Calculates the salt required for deterministic clone creation
    /// depending on client address and client basis points
    /// @param _clientAddress address
    /// @param _clientBasisPoints basis points (10000 = 100%)
    /// @return bytes32 salt
    function _getSalt(
        address _clientAddress,
        uint96 _clientBasisPoints
    ) private pure returns (bytes32)
    {
        return keccak256(abi.encode(_clientAddress, _clientBasisPoints));
    }

    /// @inheritdoc IAllowedCalldataChecker
    function checkCalldata(
        address _target,
        bytes4 _selector,
        bytes calldata _calldataAfterSelector,
        FunctionType _functionType
    ) public view override(AllowedCalldataChecker, IAllowedCalldataChecker) {
        Rule[] memory rules = s_calldataRules[_functionType][_target][_selector];
        require (
            rules.length > 0,
            P2pLendingProxyFactory__NoRulesDefined(_functionType, _target, _selector)
        );

        for (uint256 i = 0; i < rules.length; i++) {
            Rule memory rule = rules[i];
            RuleType ruleType = rule.ruleType;

            require (
                ruleType != RuleType.None || _calldataAfterSelector.length == 0,
                P2pLendingProxyFactory__NoCalldataAllowed(_functionType, _target, _selector)
            );

            uint32 bytesCount = uint32(rule.allowedBytes.length);
            if (ruleType == RuleType.StartsWith) {
                // Ensure the calldata is at least as long as the range defined by startIndex and bytesCount
                require (
                    _calldataAfterSelector.length >= rule.index + bytesCount,
                    P2pLendingProxyFactory__CalldataTooShortForStartsWithRule(
                        _calldataAfterSelector.length,
                        rule.index,
                        bytesCount
                    )
                );
                // Compare the specified range in the calldata with the allowed bytes
                require (
                    keccak256(_calldataAfterSelector[rule.index:rule.index + bytesCount]) == keccak256(rule.allowedBytes),
                    P2pLendingProxyFactory__CalldataStartsWithRuleViolated(
                        _calldataAfterSelector[rule.index:rule.index + bytesCount],
                        rule.allowedBytes
                    )
                );
            }
            if (ruleType == RuleType.EndsWith) {
                // Ensure the calldata is at least as long as bytesCount
                require (
                    _calldataAfterSelector.length >= bytesCount,
                    P2pLendingProxyFactory__CalldataTooShortForEndsWithRule(
                        _calldataAfterSelector.length,
                        bytesCount
                    )
                );
                // Compare the end of the calldata with the allowed bytes
                require (
                    keccak256(_calldataAfterSelector[_calldataAfterSelector.length - bytesCount:]) == keccak256(rule.allowedBytes),
                    P2pLendingProxyFactory__CalldataEndsWithRuleViolated(
                        _calldataAfterSelector[_calldataAfterSelector.length - bytesCount:],
                        rule.allowedBytes
                    )
                );
            }
            // if (ruleType == RuleType.AnyCalldata) do nothing
        }
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function predictP2pLendingProxyAddress(
        address _client,
        uint96 _clientBasisPoints
    ) public view returns (address) {
        return Clones.predictDeterministicAddress(
            address(i_referenceP2pLendingProxy),
            _getSalt(_client, _clientBasisPoints)
        );
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function getReferenceP2pLendingProxy() external view returns (address) {
        return address(i_referenceP2pLendingProxy);
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function getHashForP2pSigner(
        address _client,
        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            _client,
            _clientBasisPoints,
            _p2pSignerSigDeadline,
            address(this),
            block.chainid
        ));
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function getPermit2HashTypedData(IAllowanceTransfer.PermitSingle calldata _permitSingle) external view returns (bytes32) {
        return getPermit2HashTypedData(getPermitHash(_permitSingle));
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function getPermit2HashTypedData(bytes32 _dataHash) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", Permit2Lib.PERMIT2.DOMAIN_SEPARATOR(), _dataHash));
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function getPermitHash(IAllowanceTransfer.PermitSingle calldata _permitSingle) public pure returns (bytes32) {
        return PermitHash.hash(_permitSingle);
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function getCalldataRules(
        FunctionType _functionType,
        address _contract,
        bytes4 _selector
    ) external view returns (Rule[] memory) {
        return s_calldataRules[_functionType][_contract][_selector];
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function getP2pSigner() external view returns (address) {
        return s_p2pSigner;
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function getAllProxies() external view returns (address[] memory) {
        return s_allProxies;
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IP2pLendingProxyFactory).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
