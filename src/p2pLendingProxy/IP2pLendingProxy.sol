// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../common/IAllowedCalldataChecker.sol";

/// @dev External interface of P2pLendingProxy declared to support ERC165 detection.
interface IP2pLendingProxy is IAllowedCalldataChecker, IERC165 {

    /// @notice Emitted when the P2pLendingProxy is initialized
    event P2pLendingProxy__Initialized();

    /// @notice Emitted when a deposit is made
    event P2pLendingProxy__Deposited(
        address indexed _lendingProtocolAddress,
        address indexed _asset,
        uint256 _amount,
        uint256 _totalDepositedAfter
    );

    /// @notice Emitted when a withdrawal is made
    event P2pLendingProxy__Withdrawn(
        address indexed _lendingProtocolAddress,
        address indexed _vault,
        address indexed _asset,
        uint256 _shares,
        uint256 _assets,
        uint256 _totalWithdrawnAfter,
        uint256 _newProfit,
        uint256 _p2pAmount,
        uint256 _clientAmount
    );

    /// @notice Emitted when an arbitrary allowed function is called
    event P2pLendingProxy__CalledAsAnyFunction(
        address indexed _lendingProtocolAddress
    );

    /// @notice Initializes the P2pLendingProxy
    /// @param _client The client address
    /// @param _clientBasisPoints The client basis points
    function initialize(
        address _client,
        uint96 _clientBasisPoints
    )
    external;

    /// @notice Deposits assets into the lending protocol
    /// @param _lendingProtocolAddress The address of the lending protocol
    /// @param _lendingProtocolCalldata The calldata to call the lending protocol
    /// @param _permitSingleForP2pLendingProxy The permit single for the P2pLendingProxy
    /// @param _permit2SignatureForP2pLendingProxy The permit2 signature for the P2pLendingProxy
    function deposit(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,
        IAllowanceTransfer.PermitSingle calldata _permitSingleForP2pLendingProxy,
        bytes calldata _permit2SignatureForP2pLendingProxy
    )
    external;

    /// @notice Withdraws assets from the lending protocol
    /// @param _lendingProtocolAddress The address of the lending protocol
    /// @param _lendingProtocolCalldata The calldata to call the lending protocol
    /// @param _vault The vault address
    /// @param _shares The shares to withdraw
    function withdraw(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,
        address _vault,
        uint256 _shares
    )
    external;

    /// @notice Calls an arbitrary allowed function
    /// @param _lendingProtocolAddress The address of the lending protocol
    /// @param _lendingProtocolCalldata The calldata to call the lending protocol
    function callAnyFunction(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata
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
    /// @param _asset The asset address
    /// @return The total deposited
    function getTotalDeposited(address _asset) external view returns (uint256);

    /// @notice Gets the total withdrawn for an asset
    /// @param _asset The asset address
    /// @return The total withdrawn
    function getTotalWithdrawn(address _asset) external view returns (uint256);
}
