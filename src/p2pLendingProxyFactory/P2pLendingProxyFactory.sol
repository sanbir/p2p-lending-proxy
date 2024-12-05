// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../lib/permit2/src/interfaces/IAllowanceTransfer.sol";
import "../../lib/permit2/src/libraries/Permit2Lib.sol";
import "../@openzeppelin/contracts/proxy/Clones.sol";
import "../@openzeppelin/contracts/utils/Address.sol";
import "../@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../p2pLendingProxy/P2pLendingProxy.sol";
import "./IP2pLendingProxyFactory.sol";
import "./P2pLendingProxyFactoryStructs.sol";

error P2pLendingProxyFactory__InvalidP2pSignerSignature();
error P2pLendingProxyFactory__DataTooShort();
error P2pLendingProxyFactory__NotAllowedToCall(
    address _target,
    bytes4 _selector
);

contract P2pLendingProxyFactory is P2pLendingProxyFactoryStructs, ERC165, IP2pLendingProxyFactory {
    using SafeCast160 for uint256;

    /// @notice Reference P2pLendingProxy contract
    P2pLendingProxy private immutable i_referenceP2pLendingProxy;

    // contract => selector => AllowedCalldata
    // all rules must be followed
    mapping(address => mapping(bytes4 => AllowedCalldata)) private s_allowedFunctionsForContracts;

    address private s_p2pSigner;

    constructor(address _p2pSigner) {
        i_referenceP2pLendingProxy = new P2pLendingProxy(this);

        s_p2pSigner = _p2pSigner;
    }

    function deposit(
        IAllowanceTransfer.PermitSingle memory permitSingle,
        bytes calldata signature,

        uint256 fee,
        uint256 p2pSignerSigDeadline,
        bytes calldata p2pSignerSignature,

        address lendingProtocolAddress,
        bytes calldata lendingProtocolCalldata
    )
    external
    returns (P2pLendingProxy p2pLendingProxy)
    {
        // verify P2P Signer signature
        bytes32 hash = getHashForP2pSigner(
            msg.sender,
            fee,
            p2pSignerSigDeadline
        );
        bool isValid = SignatureChecker.isValidSignatureNow(
            s_p2pSigner,
            hash,
            p2pSignerSignature
        );
        if (!isValid) {
            revert P2pLendingProxyFactory__InvalidP2pSignerSignature();
        }

        // transfer tokens into Factory
        Permit2Lib.PERMIT2.permit(
            msg.sender,
            permitSingle,
            signature
        );
        Permit2Lib.PERMIT2.transferFrom(
            msg.sender,
            address(this),
            permitSingle.details.amount,
            permitSingle.details.token
        );

        _call(
            lendingProtocolAddress,
            lendingProtocolCalldata,
            FunctionType.Deposit
        );
    }

    /// @notice Call a function on a specific contract
    /// @param _target The target address of the function call
    /// @param _data The calldata of the function call
    function _call(
        address _target,
        bytes calldata _data,
        FunctionType _functionType
    ) private {
        bytes4 selector = _getFunctionSelector(_data);
        bool isAllowed = isAllowedCalldata(
            _target,
            selector,
            _data[4:],
            _functionType
        );

        if (isAllowed) {
            Address.functionCall(_target, _data);
        } else {
            revert P2pLendingProxyFactory__NotAllowedToCall(_target, selector);
        }
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
            uint32 bytesCount = rule.allowedBytes.length;

            if (ruleType == RuleType.None) {
                return false;
            } else if (ruleType == RuleType.AnyCalldata) {
                return true;
            } else if (ruleType == RuleType.StartsWith) {
                // Ensure the calldata is at least as long as the range defined by startIndex and bytesCount
                if (_calldataAfterSelector.length < rule.index + bytesCount)
                    return false;
                // Compare the specified range in the calldata with the allowed bytes
                return
                    keccak256(
                        _calldataAfterSelector[rule.index:rule.index + bytesCount]
                    ) == keccak256(rule.allowedBytes);
            } else if (ruleType == RuleType.EndsWith) {
                // Ensure the calldata is at least as long as bytesCount
                if (_calldataAfterSelector.length < bytesCount) return false;
                // Compare the end of the calldata with the allowed bytes
                return
                    keccak256(
                        _calldataAfterSelector[_calldataAfterSelector.length - bytesCount:]
                    ) == keccak256(rule.allowedBytes);
            }

            return false; // Default to false if none of the conditions are met
        }

        return true; // If all checks pass, allow
    }

    /// @notice Creates a new P2pLendingProxy contract instance
    /// @return P2pLendingProxy The new P2pLendingProxy contract instance
    function createP2pLendingProxy()
    external
    returns (P2pLendingProxy p2pLendingProxy)
    {
        address p2pLendingProxyAddress = predictP2pLendingProxyAddress(
            msg.sender
        );
        uint256 codeSize = p2pLendingProxyAddress.code.length;
        if (codeSize > 0) {
            return P2pLendingProxy(p2pLendingProxyAddress);
        }

        p2pLendingProxy = P2pLendingProxy(
                Clones.cloneDeterministic(
                address(i_referenceP2pLendingProxy),
                _getSalt(msg.sender, _clientBasisPoints)
            )
        );

        p2pLendingProxy.initialize(msg.sender);
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
        address user,
        uint256 fee,
        uint256 p2pSignerSigDeadline
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            user,
            fee,
            p2pSignerSigDeadline,
            address(this),
            block.chainid
        ));
    }

    /// @notice Calculates the salt required for deterministic clone creation
    /// depending on client address and client basis points
    /// @param _clientAddress address
    /// @param _clientBasisPoints
    /// @return bytes32 salt
    function _getSalt(
        address _clientAddress,
        uint96 _clientBasisPoints
    ) private pure returns (bytes32)
    {
        return keccak256(abi.encode(_clientAddress, _clientBasisPoints));
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165) returns (bool) {
        return interfaceId == type(IP2pLendingProxyFactory).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
