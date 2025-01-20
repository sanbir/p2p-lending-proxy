// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

error CalldataParser__InvalidSlice();

abstract contract CalldataParser {
    uint256 internal constant SELECTOR_LENGTH = 4;

    // Helper function to slice bytes
    function _slice(bytes memory data, uint256 start, uint256 length) internal pure returns (bytes memory) {
        require(
            data.length >= (start + length),
            CalldataParser__InvalidSlice()
        );

        bytes memory tempBytes;

        assembly {
            switch iszero(length)
            case 0 {
            // Allocate memory for the sliced bytes
                tempBytes := mload(0x40)
            // Set the length
                mstore(tempBytes, length)
            // Copy the data
                let src := add(data, add(0x20, start))
                let dest := add(tempBytes, 0x20)
                for { let i := 0 } lt(i, length) { i := add(i, 0x20) } {
                    mstore(add(dest, i), mload(add(src, i)))
                }
            // Update the free memory pointer
                mstore(0x40, add(dest, length))
            }
            default {
                tempBytes := mload(0x40)
                mstore(tempBytes, 0)
                mstore(0x40, add(tempBytes, 0x20))
            }
        }

        return tempBytes;
    }
}
