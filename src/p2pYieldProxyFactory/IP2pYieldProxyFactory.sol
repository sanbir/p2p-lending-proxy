// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @dev External interface of P2pYieldProxyFactory
interface IP2pYieldProxyFactory is IERC165 {

    /// @dev Emitted when the P2pSigner is transferred
    event P2pYieldProxyFactory__P2pSignerTransferred(
        address indexed _previousP2pSigner,
        address indexed _newP2pSigner
    );

    /// @dev Emitted when the deposit is made
    event P2pYieldProxyFactory__Deposited(
        address indexed _client,
        uint48 indexed _clientBasisPointsOfDeposit,
        uint48 indexed _clientBasisPointsOfProfit
    );

    /// @dev Emitted when the a new proxy is created
    event P2pYieldProxyFactory__ProxyCreated(
        address _proxy,
        address _client,
        uint48 _clientBasisPointsOfDeposit,
        uint48 _clientBasisPointsOfProfit
    );

    /// @dev Deposits the yield protocol
    /// @param _vaultId vault ID
    /// @param _asset ERC-20 asset address (use NATIVE sentinel for ETH)
    /// @param _amount Amount of ERC-20 asset to transfer from client (ignored for native deposits)
    /// @param _yieldProtocolCalldata Yield protocol calldata
    /// @param _clientBasisPointsOfDeposit The client basis points (share) of deposit
    /// @param _clientBasisPointsOfProfit The client basis points (share) of profit
    /// @param _p2pSignerSigDeadline The P2pSigner signature deadline
    /// @param _p2pSignerSignature The P2pSigner signature
    /// @return p2pYieldProxyAddress The client's P2pYieldProxy instance address
    function deposit(
        uint256 _vaultId,
        address _asset,
        uint256 _amount,
        bytes calldata _yieldProtocolCalldata,

        uint48 _clientBasisPointsOfDeposit,
        uint48 _clientBasisPointsOfProfit,
        uint256 _p2pSignerSigDeadline,
        bytes calldata _p2pSignerSignature
    )
    external
    payable
    returns (address p2pYieldProxyAddress);

    /// @dev Computes the address of a P2pYieldProxy created by `_getOrCreateP2pYieldProxy` function
    /// @dev P2pYieldProxy instances are guaranteed to have the same address if _feeDistributorInstance is the same
    /// @param _client The address of client
    /// @param _clientBasisPointsOfDeposit The client basis points (share) of deposit
    /// @param _clientBasisPointsOfProfit The client basis points (share) of profit
    /// @return address The address of the P2pYieldProxy instance
    function predictP2pYieldProxyAddress(
        address _client,
        uint48 _clientBasisPointsOfDeposit,
        uint48 _clientBasisPointsOfProfit
    ) external view returns (address);

    /// @dev Transfers the P2pSigner
    /// @param _newP2pSigner The new P2pSigner address
    function transferP2pSigner(
        address _newP2pSigner
    ) external;

    /// @dev Returns a template set by P2P to be used for new P2pYieldProxy instances
    /// @return a template set by P2P to be used for new P2pYieldProxy instances
    function getReferenceP2pYieldProxy() external view returns (address);

    /// @dev Gets the hash for the P2pSigner
    /// @param _client The address of client
    /// @param _clientBasisPointsOfDeposit The client basis points (share) of deposit
    /// @param _clientBasisPointsOfProfit The client basis points (share) of profit
    /// @param _p2pSignerSigDeadline The P2pSigner signature deadline
    /// @return The hash for the P2pSigner
    function getHashForP2pSigner(
        address _client,
        uint48 _clientBasisPointsOfDeposit,
        uint48 _clientBasisPointsOfProfit,
        uint256 _p2pSignerSigDeadline
    ) external view returns (bytes32);


    /// @dev Gets the P2pSigner
    /// @return The P2pSigner address
    function getP2pSigner() external view returns (address);

    /// @dev Gets all proxies
    /// @return The proxy addresses
    function getAllProxies() external view returns (address[] memory);
}
