// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/proxy/Clones.sol";
import "../@openzeppelin/contracts/utils/Address.sol";
import "../@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../@permit2/libraries/PermitHash.sol";
import "../common/AllowedCalldataChecker.sol";
import "../p2pLendingProxy/P2pLendingProxy.sol";
import "./IP2pLendingProxyFactory.sol";
import "../common/P2pStructs.sol";

error P2pLendingProxyFactory__InvalidP2pSignerSignature();
error P2pLendingProxyFactory__NotP2pOperatorCalled(
    address _msgSender,
    address _actualP2pOperator
);
error P2pLendingProxyFactory__P2pSignerSignatureExpired(
    uint256 _p2pSignerSigDeadline
);
error P2pLendingProxyFactory__NoRulesDefined(
    P2pStructs.FunctionType _functionType,
    address _target,
    bytes4 _selector
);
error P2pLendingProxyFactory__NoCalldataAllowed(
    P2pStructs.FunctionType _functionType,
    address _target,
    bytes4 _selector
);
error P2pLendingProxyFactory__CalldataTooShortForStartsWithRule(
    uint256 _calldataAfterSelectorLength,
    uint32 _ruleIndex,
    uint32 _bytesCount
);
error P2pLendingProxyFactory__CalldataStartsWithRuleViolated(
    bytes _actual,
    bytes _expected
);
error P2pLendingProxyFactory__CalldataTooShortForEndsWithRule(
    uint256 _calldataAfterSelectorLength,
    uint32 _bytesCount
);
error P2pLendingProxyFactory__CalldataEndsWithRuleViolated(
    bytes _actual,
    bytes _expected
);

contract P2pLendingProxyFactory is
    AllowedCalldataChecker,
    P2pStructs,
    ERC165,
    IP2pLendingProxyFactory {

    using SafeCast160 for uint256;
    using SignatureChecker for address;
    using ECDSA for bytes32;

    /// @notice Reference P2pLendingProxy contract
    P2pLendingProxy private immutable i_referenceP2pLendingProxy;

    // FunctionType => Contract => Selector => Rule[]
    // all rules must be followed for (FunctionType, Contract, Selector)
    mapping(FunctionType => mapping(address => mapping(bytes4 => Rule[]))) private s_calldataRules;

    address private s_p2pSigner;
    address private s_p2pOperator;

    /// @notice If caller is not P2P operator, revert
    modifier onlyP2pOperator() {
        address p2pOperator = s_p2pOperator;
        if (msg.sender != p2pOperator) {
            revert P2pLendingProxyFactory__NotP2pOperatorCalled(msg.sender, p2pOperator);
        }
        _;
    }

    modifier p2pSignerSignatureShouldNotExpire(uint256 _p2pSignerSigDeadline) {
        require (
            block.timestamp < _p2pSignerSigDeadline,
            P2pLendingProxyFactory__P2pSignerSignatureExpired(_p2pSignerSigDeadline)
        );
        _;
    }

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

    constructor(address _p2pSigner, address _p2pTreasury) {
        i_referenceP2pLendingProxy = new P2pLendingProxy(address(this), _p2pTreasury);

        s_p2pSigner = _p2pSigner;
        s_p2pOperator = msg.sender;
    }

    // TODO: add 2 step
    function setP2pOperator(
        address _newP2pOperator
    ) external onlyP2pOperator {
        s_p2pOperator = _newP2pOperator;
    }

    function setP2pSigner(
        address _newP2pSigner
    ) external onlyP2pOperator {
        s_p2pSigner = _newP2pSigner;
    }

    function setCalldataRules(
        FunctionType _functionType,
        address _contract,
        bytes4 _selector,
        Rule[] calldata _rules
    ) external onlyP2pOperator {
        s_calldataRules[_functionType][_contract][_selector] = _rules;
    }

    function removeCalldataRules(
        FunctionType _functionType,
        address _contract,
        bytes4 _selector
    ) external onlyP2pOperator {
        delete s_calldataRules[_functionType][_contract][_selector];
    }

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

        p2pLendingProxyAddress = address(p2pLendingProxy);
    }

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
                ruleType != RuleType.None,
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
    }

    /// @notice Predicts the address of a P2pLendingProxy contract instance
    /// @return The address of the P2pLendingProxy contract instance
    function predictP2pLendingProxyAddress(
        address _client,
        uint96 _clientBasisPoints
    ) public view returns (address) {
        return Clones.predictDeterministicAddress(
            address(i_referenceP2pLendingProxy),
            _getSalt(_client, _clientBasisPoints)
        );
    }

    /// @notice Returns the address of the reference P2pLendingProxy contract
    /// @return The address of the reference P2pLendingProxy contract
    function getReferenceP2pLendingProxy() external view returns (address) {
        return address(i_referenceP2pLendingProxy);
    }

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

    function getPermit2HashTypedData(IAllowanceTransfer.PermitSingle calldata _permitSingle) external view returns (bytes32) {
        return getPermit2HashTypedData(getPermitHash(_permitSingle));
    }

    /// @notice Creates an EIP-712 typed data hash for Permit2
    function getPermit2HashTypedData(bytes32 _dataHash) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", Permit2Lib.PERMIT2.DOMAIN_SEPARATOR(), _dataHash));
    }

    function getPermitHash(IAllowanceTransfer.PermitSingle calldata _permitSingle) public pure returns (bytes32) {
        return PermitHash.hash(_permitSingle);
    }

    function getCalldataRules(
        FunctionType _functionType,
        address _contract,
        bytes4 _selector
    ) external view returns (Rule[] memory) {
        return s_calldataRules[_functionType][_contract][_selector];
    }

    function getP2pSigner() external view returns (address) {
        return s_p2pSigner;
    }

    function getP2pOperator() external view returns (address) {
        return s_p2pOperator;
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

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IP2pLendingProxyFactory).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
