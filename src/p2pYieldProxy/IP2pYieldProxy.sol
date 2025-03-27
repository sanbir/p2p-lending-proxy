// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../common/IAllowedCalldataChecker.sol";

/// @dev External interface of P2pYieldProxy declared to support ERC165 detection.
interface IP2pYieldProxy is IAllowedCalldataChecker, IERC165 {

    /// @notice Emitted when the P2pYieldProxy is initialized
    event P2pYieldProxy__Initialized();

    /// @notice Emitted when a deposit is made
    event P2pYieldProxy__Deposited(
        address indexed _yieldProtocolAddress,
        address indexed _asset,
        uint256 _amount,
        uint256 _totalDepositedAfter
    );

    /// @notice Emitted when a withdrawal is made
    event P2pYieldProxy__Withdrawn(
        address indexed _yieldProtocolAddress,
        uint256 indexed _vaultId,
        address indexed _asset,
        uint256 _assets,
        uint256 _totalWithdrawnAfter,
        uint256 _newProfit,
        uint256 _p2pAmount,
        uint256 _clientAmount
    );

    /// @notice Emitted when an arbitrary allowed function is called
    event P2pYieldProxy__CalledAsAnyFunction(
        address indexed _yieldProtocolAddress
    );

    /// @notice Initializes the P2pYieldProxy
    /// @param _client The client address
    /// @param _clientBasisPoints The client basis points
    function initialize(
        address _client,
        uint96 _clientBasisPoints
    )
    external;

    function deposit(
        IAllowanceTransfer.PermitSingle calldata _permitSingleForP2pYieldProxy,
        bytes calldata _permit2SignatureForP2pYieldProxy,
        bytes calldata _superformCalldata
    ) external payable;

    /// @notice Calls an arbitrary allowed function
    /// @param _yieldProtocolAddress The address of the yield protocol
    /// @param _yieldProtocolCalldata The calldata to call the yield protocol
    function callAnyFunction(
        address _yieldProtocolAddress,
        bytes calldata _yieldProtocolCalldata
    )
    external;

    /// @notice Gets the factory address
    /// @return The factory address
    function getFactory() external view returns (address);

    /// @notice Gets the P2pTreasury address
    /// @return The P2pTreasury address
    function getP2pTreasury() external view returns (address);

    /// @notice Gets the client address
    /// @return The client address
    function getClient() external view returns (address);

    /// @notice Gets the client basis points
    /// @return The client basis points
    function getClientBasisPoints() external view returns (uint96);

    /// @notice Gets the total deposited for an asset
    /// @param _vaultId vault ID
    /// @param _asset The asset address
    /// @return The total deposited
    function getTotalDeposited(uint256 _vaultId, address _asset) external view returns (uint256);

    /// @notice Gets the total withdrawn for an asset
    /// @param _vaultId vault ID
    /// @param _asset The asset address
    /// @return The total withdrawn
    function getTotalWithdrawn(uint256 _vaultId, address _asset) external view returns (uint256);
}
