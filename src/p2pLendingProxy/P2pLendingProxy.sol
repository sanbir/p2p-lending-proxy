// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/interfaces/IERC1271.sol";
import "../@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "../@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../@openzeppelin/contracts/utils/Address.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../@permit2/libraries/Permit2Lib.sol";
import "../@permit2/libraries/SignatureVerification.sol";
import "../common/AllowedCalldataChecker.sol";
import "../p2pLendingProxyFactory/IP2pLendingProxyFactory.sol";
import "../common/P2pStructs.sol";
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

contract P2pLendingProxy is
    AllowedCalldataChecker,
    P2pStructs,
    ReentrancyGuard,
    ERC165,
    IP2pLendingProxy,
    IERC1271 {

    using SafeERC20 for IERC20;
    using Address for address;

    IP2pLendingProxyFactory private immutable i_factory;
    address private immutable i_p2pTreasury;

    address private s_client;
    uint96 private s_clientBasisPoints;

    // asset => amount
    mapping(address => uint256) private s_totalDeposited;

    // asset => amount
    mapping(address => uint256) private s_totalWithdrawn;

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
        address _factory,
        address _p2pTreasury
    ) {
        i_factory = IP2pLendingProxyFactory(_factory);
        i_p2pTreasury = _p2pTreasury;
    }

    function initialize(
        address _client,
        uint96 _clientBasisPoints
    )
    external
    onlyFactory
    {
        s_client = _client;
        s_clientBasisPoints = _clientBasisPoints;

        emit P2pLendingProxy__Initialized(_client, _clientBasisPoints);
    }

    function deposit(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,
        IAllowanceTransfer.PermitSingle calldata _permitSingleForP2pLendingProxy,
        bytes calldata _permit2SignatureForP2pLendingProxy
    )
    external
    onlyFactory
    {
        address asset = _permitSingleForP2pLendingProxy.details.token;
        uint160 amount = _permitSingleForP2pLendingProxy.details.amount;

        s_totalDeposited[asset] += amount;

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
            amount,
            asset
        );

        IERC20(asset).safeApprove(
            address(Permit2Lib.PERMIT2),
            type(uint256).max
        );

        _lendingProtocolAddress.functionCall(_lendingProtocolCalldata);
    }

    function withdraw(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,
        address _vault,
        uint256 _shares
    )
    external
    onlyClient
    nonReentrant
    calldataShouldBeAllowed(_lendingProtocolAddress, _lendingProtocolCalldata, FunctionType.Withdrawal)
    {
        // approve shares from Proxy to Protocol
        IERC20(_vault).safeApprove(_lendingProtocolAddress, _shares);

        // withdraw assets from Protocol
        _lendingProtocolAddress.functionCall(_lendingProtocolCalldata);

        address asset = IERC4626(_vault).asset();
        uint256 newAssetAmount = IERC20(asset).balanceOf(address(this));

        uint256 totalWithdrawnBefore = s_totalWithdrawn[asset];
        uint256 totalWithdrawnAfter = totalWithdrawnBefore + newAssetAmount;
        uint256 totalDeposited = s_totalDeposited[asset];

        // update total withdrawn
        s_totalWithdrawn[asset] = totalWithdrawnAfter;

        // Calculate profit increment
        // profit = (total withdrawn after this - total deposited)
        // If it's negative or zero, no profit yet
        uint256 profitBefore;
        if (totalWithdrawnBefore > totalDeposited) {
            profitBefore = totalWithdrawnBefore - totalDeposited;
        }
        uint256 profitAfter;
        if (totalWithdrawnAfter > totalDeposited) {
            profitAfter = totalWithdrawnAfter - totalDeposited;
        }
        uint256 newProfit;
        if (profitAfter > profitBefore) {
            newProfit = profitAfter - profitBefore;
        }

        uint256 p2pAmount;
        if (newProfit > 0) {
            p2pAmount = (newProfit * (10_000 - s_clientBasisPoints)) / 10_000;
        }
        uint256 clientAmount = newAssetAmount - p2pAmount;

        if (p2pAmount > 0) {
            IERC20(asset).safeTransfer(i_p2pTreasury, p2pAmount);
        }
        // clientAmount must be > 0 at this point
        IERC20(asset).safeTransfer(s_client, clientAmount);
    }

    function checkCalldata(
        address _target,
        bytes4 _selector,
        bytes calldata _calldataAfterSelector,
        FunctionType _functionType
    ) public view override(AllowedCalldataChecker, IAllowedCalldataChecker) {
        i_factory.checkCalldata(
            _target,
            _selector,
            _calldataAfterSelector,
            _functionType
        );
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue) {
        SignatureVerification.verify(signature, hash, s_client);

        return IERC1271.isValidSignature.selector;
    }

    function getFactory() external view returns (address) {
        return address(i_factory);
    }

    function getP2pTreasury() external view returns (address) {
        return i_p2pTreasury;
    }

    function getClient() external view returns (address) {
        return s_client;
    }

    function getClientBasisPoints() external view returns (uint96) {
        return s_clientBasisPoints;
    }

    function getTotalDeposited(address _asset) external view returns (uint256) {
        return s_totalDeposited[_asset];
    }

    function getTotalWithdrawn(address _asset) external view returns (uint256) {
        return s_totalWithdrawn[_asset];
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IP2pLendingProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
