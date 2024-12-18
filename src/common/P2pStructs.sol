// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

abstract contract P2pStructs {
    /// @title Enum representing the type of rule for allowed calldata
    enum RuleType {
        /// @notice No calldata beyond selector is allowed
        None,
        /// @notice Any calldata beyond selector is allowed
        AnyCalldata,
        /// @notice Limits calldata starting from index to match allowedBytes
        StartsWith,
        /// @notice Limits calldata ending at index to match allowedBytes
        EndsWith
    }

    /// @title Enum
    enum FunctionType {
        None,
        Deposit,
        Withdrawal
    }

    /// @notice Struct representing a rule for allowed calldata
    /// @param ruleType The type of rule
    /// @param index The start (or end, depending on StartsWith/EndsWith) index of the bytes to check
    /// @param allowedBytes The allowed bytes
    struct Rule {
        RuleType ruleType;
        uint32 index;
        bytes allowedBytes;
    }

    /// @notice Struct representing allowed calldata
    /// @param function type
    /// @param rules
    struct AllowedCalldata {
        FunctionType functionType;
        Rule[] rules;
    }
}
