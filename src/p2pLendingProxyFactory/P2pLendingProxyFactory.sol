// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/proxy/Clones.sol";
import "../@openzeppelin/contracts/utils/Address.sol";
import "../@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../@permit2/libraries/PermitHash.sol";
import "../p2pLendingProxy/P2pLendingProxy.sol";
import "./IP2pLendingProxyFactory.sol";
import "./P2pLendingProxyFactoryStructs.sol";

error P2pLendingProxyFactory__InvalidP2pSignerSignature();
error P2pLendingProxyFactory__DataTooShort();
error P2pLendingProxyFactory__NotAllowedToCall(
    address _target,
    bytes4 _selector
);
error P2pLendingProxyFactory__NotP2pOperatorCalled(
    address _msgSender,
    address _actualP2pOperator
);
error P2pLendingProxyFactory__P2pSignerSignatureExpired(
    uint256 _p2pSignerSigDeadline
);

contract P2pLendingProxyFactory is P2pLendingProxyFactoryStructs, ERC165, IP2pLendingProxyFactory {
    using SafeCast160 for uint256;

    /// @notice Reference P2pLendingProxy contract
    P2pLendingProxy private immutable i_referenceP2pLendingProxy;

    // contract => selector => AllowedCalldata
    // all rules must be followed
    mapping(address => mapping(bytes4 => AllowedCalldata)) private s_allowedFunctionsForContracts;

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

    function setAllowedFunctionForContract(
        address _contract,
        bytes4 _selector,
        P2pLendingProxyFactoryStructs.AllowedCalldata calldata _allowedCalldata
    ) external onlyP2pOperator {
        s_allowedFunctionsForContracts[_contract][_selector] = _allowedCalldata;
    }

    function removeAllowedFunctionForContract(
        address _contract,
        bytes4 _selector
    ) external onlyP2pOperator {
        delete s_allowedFunctionsForContracts[_contract][_selector];
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
    returns (address p2pLendingProxyAddress)
    {
        if (block.timestamp > _p2pSignerSigDeadline) {
            revert P2pLendingProxyFactory__P2pSignerSignatureExpired(_p2pSignerSigDeadline);
        }

        // verify P2P Signer signature
        bytes32 hash = getHashForP2pSigner(
            msg.sender,
            _clientBasisPoints,
            _p2pSignerSigDeadline
        );
        bytes32 ethSignedMessageHash = ECDSA.toEthSignedMessageHash(hash);
        bool isValid = SignatureChecker.isValidSignatureNow(
            s_p2pSigner,
            ethSignedMessageHash,
            _p2pSignerSignature
        );
        if (!isValid) {
            revert P2pLendingProxyFactory__InvalidP2pSignerSignature();
        }

        // validate lendingProtocolCalldata for lendingProtocolAddress
        bytes4 selector = _getFunctionSelector(_lendingProtocolCalldata);
        bool isAllowed = isAllowedCalldata(
            _lendingProtocolAddress,
            selector,
            _lendingProtocolCalldata[4:],
            FunctionType.Deposit
        );

        if (!isAllowed) {
            revert P2pLendingProxyFactory__NotAllowedToCall(_lendingProtocolAddress, selector);
        }

        // create proxy if not created yet
        P2pLendingProxy p2pLendingProxy = _createP2pLendingProxy(_clientBasisPoints);

        // deposit via proxy
        p2pLendingProxy.deposit(
            _lendingProtocolAddress,
            _lendingProtocolCalldata,
            _permitSingleForP2pLendingProxy,
            _permit2SignatureForP2pLendingProxy
        );

        p2pLendingProxyAddress = address(p2pLendingProxy);
    }

    /// @notice Returns function selector (first 4 bytes of data)
    /// @param _data calldata (encoded signature + arguments)
    /// @return functionSelector function selector
    function _getFunctionSelector(
        bytes calldata _data
    ) private pure returns (bytes4 functionSelector) {
        if (_data.length < 4) {
            revert P2pLendingProxyFactory__DataTooShort();
        }
        return bytes4(_data[:4]);
    }

    function isAllowedCalldata(
        address _target,
        bytes4 _selector,
        bytes calldata _calldataAfterSelector,
        FunctionType _functionType
    ) public view returns (bool) {
        AllowedCalldata storage allowedCalldata = s_allowedFunctionsForContracts[_target][_selector];
        if (_functionType != allowedCalldata.functionType) {
            return false;
        }

        Rule[] memory rules = allowedCalldata.rules;
        for (uint256 i = 0; i < rules.length; i++) {
            Rule memory rule = rules[i];

            RuleType ruleType = rule.ruleType;
            uint32 bytesCount = uint32(rule.allowedBytes.length);

            if (ruleType == RuleType.None) {
                return false;
            } else if (ruleType == RuleType.AnyCalldata) {
                continue; // skip further checks for this rule
            } else if (ruleType == RuleType.StartsWith) {
                // Ensure the calldata is at least as long as the range defined by startIndex and bytesCount
                if (_calldataAfterSelector.length < rule.index + bytesCount)
                    return false;
                // Compare the specified range in the calldata with the allowed bytes
                bool isAllowed = keccak256(_calldataAfterSelector[rule.index:rule.index + bytesCount]) == keccak256(rule.allowedBytes);
                if (!isAllowed) {
                    return false;
                } else {
                    continue; // skip further checks for this rule
                }
            } else if (ruleType == RuleType.EndsWith) {
                // Ensure the calldata is at least as long as bytesCount
                if (_calldataAfterSelector.length < bytesCount) return false;
                // Compare the end of the calldata with the allowed bytes
                bool isAllowed = keccak256(_calldataAfterSelector[_calldataAfterSelector.length - bytesCount:]) == keccak256(rule.allowedBytes);
                if (!isAllowed) {
                    return false;
                } else {
                    continue; // skip further checks for this rule
                }
            }

            return false; // Default to false if none of the conditions are met
        }

        return true; // If all checks pass, allow
    }

    /// @notice Creates a new P2pLendingProxy contract instance
    function _createP2pLendingProxy(uint96 _clientBasisPoints)
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

    function getAllowedCalldata(address _contract, bytes4 _selector) external view returns (AllowedCalldata memory) {
        return s_allowedFunctionsForContracts[_contract][_selector];
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
