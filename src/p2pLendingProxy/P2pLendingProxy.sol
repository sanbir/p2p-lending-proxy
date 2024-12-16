// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/interfaces/IERC1271.sol";
import "../@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../@openzeppelin/contracts/utils/Address.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../@permit2/libraries/Permit2Lib.sol";
import "../@permit2/libraries/SignatureVerification.sol";
import "../p2pLendingProxyFactory/IP2pLendingProxyFactory.sol";
import "./IP2pLendingProxy.sol";
import {IERC4626} from "../@openzeppelin/contracts/interfaces/IERC4626.sol";

    error P2pLendingProxy__NotFactory(address _factory);

/// @notice Called by an address other than factory
/// @param _msgSender sender address.
/// @param _actualFactory the actual factory address.
error P2pLendingProxy__NotFactoryCalled(
    address _msgSender,
    IP2pLendingProxyFactory _actualFactory
);

/// @notice Called by an address other than client
/// @param _msgSender sender address.
/// @param _actualClient the actual client address.
error P2pLendingProxy__NotClientCalled(
    address _msgSender,
    address _actualClient
);

contract P2pLendingProxy is ERC165, IP2pLendingProxy, IERC1271 {

    IP2pLendingProxyFactory private immutable i_factory;

    address private s_client;
    uint96 private s_clientBasisPoints;

    uint256 private totalDeposited;
    uint256 private totalWithdrawn;

    /// @notice If caller is not factory, revert
    modifier onlyFactory() {
        if (msg.sender != address(i_factory)) {
            revert P2pLendingProxy__NotFactoryCalled(msg.sender, i_factory);
        }
        _;
    }

    /// @notice If caller is not client, revert
    modifier onlyClient() {
        if (msg.sender != address(s_client)) {
            revert P2pLendingProxy__NotClientCalled(msg.sender, s_client);
        }
        _;
    }

    constructor(
        address _factory
    ) {
        i_factory = IP2pLendingProxyFactory(_factory);
    }

    function initialize(
        address _client,
        uint96 _clientBasisPoints
    ) external onlyFactory
    {
        s_client = _client;
        s_clientBasisPoints = _clientBasisPoints;

        emit P2pLendingProxy__Initialized(_client, _clientBasisPoints);
    }

    function deposit(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,
        IAllowanceTransfer.PermitSingle memory _permitSingleForP2pLendingProxy,
        bytes calldata _permit2SignatureForP2pLendingProxy
    )
    external onlyFactory
    {
        address client = s_client;

        // transfer tokens into Proxy
        Permit2Lib.PERMIT2.permit(
            client,
            _permitSingleForP2pLendingProxy,
            _permit2SignatureForP2pLendingProxy
        );
        Permit2Lib.PERMIT2.transferFrom(
            client,
            address(this),
            _permitSingleForP2pLendingProxy.details.amount,
            _permitSingleForP2pLendingProxy.details.token
        );

        SafeERC20.safeApprove(
            IERC20(_permitSingleForP2pLendingProxy.details.token),
            address(Permit2Lib.PERMIT2),
            type(uint256).max
        );

        Address.functionCall(_lendingProtocolAddress, _lendingProtocolCalldata);
    }

    function withdraw(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,
        address _vault,
        uint256 _shares
    )
    external onlyClient
    {
        IERC20(_vault).approve(_lendingProtocolAddress, _shares);

        Address.functionCall(_lendingProtocolAddress, _lendingProtocolCalldata);


        IERC4626(_vault).convertToAssets(_shares);


        require(assetAmount > 0, "Cannot withdraw zero");

        // In a real ERC4626:
        // - User would specify shares to redeem.
        // - Convert shares to underlying asset amount (assetAmount).
        // For demonstration, we trust `assetAmount` is correct or computed elsewhere.

        // Check how much user deposited vs. will have withdrawn after this withdrawal
        uint256 userTotalWithdrawnAfter = totalWithdrawn + assetAmount;
        uint256 userTotalDeposited = totalDeposited;

        // Calculate profit increment
        // profit = (total withdrawn after this - total deposited)
        // If it's negative or zero, no profit yet
        uint256 profit;
        if (userTotalWithdrawnAfter > userTotalDeposited) {
            profit = userTotalWithdrawnAfter - userTotalDeposited;
        } else {
            profit = 0;
        }

        // Compute the incremental profit for this withdrawal
        uint256 previousProfit;
        if (totalWithdrawn > userTotalDeposited) {
            previousProfit = totalWithdrawn - userTotalDeposited;
        }

        uint256 newProfit = profit > previousProfit ? (profit - previousProfit) : 0;

        // Apply fee on the incremental profit portion only
        uint256 feeAmount = 0;
        if (newProfit > 0) {
            feeAmount = (newProfit * feeBps) / 10_000;
        }

        // Update accounting
        totalWithdrawn = userTotalWithdrawnAfter;

        // Transfer fee if applicable
        if (feeAmount > 0) {
            require(assetToken.transfer(feeRecipient, feeAmount), "Fee transfer failed");
        }

        // Transfer net amount to user (assetAmount - feeAmount)
        uint256 userAmount = assetAmount - feeAmount;
        require(userAmount <= assetAmount, "Fee exceeds withdrawal");
        require(assetToken.transfer(msg.sender, userAmount), "User transfer failed");
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue) {
        SignatureVerification.verify(signature, hash, s_client);

        return IERC1271.isValidSignature.selector;
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IP2pLendingProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
