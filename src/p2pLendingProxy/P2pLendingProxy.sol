// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
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
import "../common/IMorphoBundler.sol";
import "../common/P2pStructs.sol";
import "../p2pLendingProxyFactory/IP2pLendingProxyFactory.sol";
import "./IP2pLendingProxy.sol";
import {IERC4626} from "../@openzeppelin/contracts/interfaces/IERC4626.sol";

/// @dev Error when the asset address is zero   
error P2pLendingProxy__ZeroAddressAsset();

/// @dev Error when the asset amount is zero
error P2pLendingProxy__ZeroAssetAmount();

/// @dev Error when the shares amount is zero
error P2pLendingProxy__ZeroSharesAmount();

/// @dev Error when the client basis points are invalid
error P2pLendingProxy__InvalidClientBasisPoints(uint96 _clientBasisPoints);

/// @dev Error when the factory is not the caller
error P2pLendingProxy__NotFactory(address _factory);

/// @dev Error when the factory is not the caller
/// @param _msgSender sender address.
/// @param _actualFactory the actual factory address.
error P2pLendingProxy__NotFactoryCalled(
    address _msgSender,
    IP2pLendingProxyFactory _actualFactory
);

/// @dev Error when the client is not the caller
/// @param _msgSender sender address.
/// @param _actualClient the actual client address.
error P2pLendingProxy__NotClientCalled(
    address _msgSender,
    address _actualClient
);

/// @title P2pLendingProxy
/// @notice P2pLendingProxy is a contract that allows a client to deposit and withdraw assets from a lending protocol.
/// @dev The reference implementation is based on Morpho's lending protocol.
abstract contract P2pLendingProxy is
    AllowedCalldataChecker,
    P2pStructs,
    ReentrancyGuard,
    ERC165,
    IP2pLendingProxy,
    IERC1271 {

    using SafeERC20 for IERC20;
    using Address for address;

    /// @dev P2pLendingProxyFactory
    IP2pLendingProxyFactory internal immutable i_factory;

    /// @dev P2pTreasury
    address internal immutable i_p2pTreasury;

    /// @dev Client
    address internal s_client;

    /// @dev Client basis points
    uint96 internal s_clientBasisPoints;

    // asset => amount
    mapping(address => uint256) internal s_totalDeposited;

    // asset => amount
    mapping(address => uint256) internal s_totalWithdrawn;

    /// @notice If caller is not factory, revert
    modifier onlyFactory() {
        if (msg.sender != address(i_factory)) {
            revert P2pLendingProxy__NotFactoryCalled(msg.sender, i_factory);
        }
        _;
    }

    /// @notice If caller is not client, revert
    modifier onlyClient() {
        if (msg.sender != s_client) {
            revert P2pLendingProxy__NotClientCalled(msg.sender, s_client);
        }
        _;
    }

    /// @notice Constructor for P2pLendingProxy
    /// @param _factory The factory address
    /// @param _p2pTreasury The P2pTreasury address
    constructor(
        address _factory,
        address _p2pTreasury
    ) {
        i_factory = IP2pLendingProxyFactory(_factory);
        i_p2pTreasury = _p2pTreasury;
    }

    /// @inheritdoc IP2pLendingProxy
    function initialize(
        address _client,
        uint96 _clientBasisPoints
    )
    external
    onlyFactory
    {
        require(
            _clientBasisPoints > 0 && _clientBasisPoints <= 10_000,
            P2pLendingProxy__InvalidClientBasisPoints(_clientBasisPoints)
        );

        s_client = _client;
        s_clientBasisPoints = _clientBasisPoints;

        emit P2pLendingProxy__Initialized();
    }

    /// @inheritdoc IP2pLendingProxy
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
        require (asset != address(0), P2pLendingProxy__ZeroAddressAsset());

        uint160 amount = _permitSingleForP2pLendingProxy.details.amount;
        require (amount > 0, P2pLendingProxy__ZeroAssetAmount());

        address client = s_client;

        // transfer tokens into Proxy
        try Permit2Lib.PERMIT2.permit(
            client,
            _permitSingleForP2pLendingProxy,
            _permit2SignatureForP2pLendingProxy
        ) {}
        catch {} // prevent unintended reverts due to invalidated nonce

        uint256 assetAmountBefore = IERC20(asset).balanceOf(address(this));

        Permit2Lib.PERMIT2.transferFrom(
            client,
            address(this),
            amount,
            asset
        );

        uint256 assetAmountAfter = IERC20(asset).balanceOf(address(this));
        uint256 actualAmount = assetAmountAfter - assetAmountBefore;

        uint256 totalDepositedAfter = s_totalDeposited[asset] + actualAmount;
        s_totalDeposited[asset] = totalDepositedAfter;
        emit P2pLendingProxy__Deposited(
            _lendingProtocolAddress,
            asset,
            actualAmount,
            totalDepositedAfter
        );

        if (IERC20(asset).allowance(address(this), address(Permit2Lib.PERMIT2)) == 0) {
            IERC20(asset).safeApprove(
                address(Permit2Lib.PERMIT2),
                type(uint256).max
            );
        }

        _lendingProtocolAddress.functionCall(_lendingProtocolCalldata);
    }

    /// @inheritdoc IP2pLendingProxy
    function withdraw(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,
        address _vault,
        uint256 _shares
    )
    public
    virtual
    onlyClient
    nonReentrant
    calldataShouldBeAllowed(_lendingProtocolAddress, _lendingProtocolCalldata, FunctionType.Withdrawal)
    {
        require (_shares > 0, P2pLendingProxy__ZeroSharesAmount());

        address asset = IERC4626(_vault).asset();
        uint256 assetAmountBefore = IERC20(asset).balanceOf(address(this));

        // approve shares from Proxy to Protocol
        IERC20(_vault).safeIncreaseAllowance(_lendingProtocolAddress, _shares);

        // withdraw assets from Protocol
        _lendingProtocolAddress.functionCall(_lendingProtocolCalldata);

        uint256 assetAmountAfter = IERC20(asset).balanceOf(address(this));

        uint256 newAssetAmount = assetAmountAfter - assetAmountBefore;

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
            // That extra 9999 ensures that any nonzero remainder will push the result up by 1 (ceiling division).
            p2pAmount = (newProfit * (10_000 - s_clientBasisPoints) + 9999) / 10_000;
        }
        uint256 clientAmount = newAssetAmount - p2pAmount;

        if (p2pAmount > 0) {
            IERC20(asset).safeTransfer(i_p2pTreasury, p2pAmount);
        }
        // clientAmount must be > 0 at this point
        IERC20(asset).safeTransfer(s_client, clientAmount);

        emit P2pLendingProxy__Withdrawn(
            _lendingProtocolAddress,
            _vault,
            asset,
            _shares,
            newAssetAmount,
            totalWithdrawnAfter,
            newProfit,
            p2pAmount,
            clientAmount
        );
    }

    /// @inheritdoc IP2pLendingProxy
    function callAnyFunction(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata
    )
    external
    onlyClient
    nonReentrant
    calldataShouldBeAllowed(_lendingProtocolAddress, _lendingProtocolCalldata, FunctionType.None)
    {
        emit P2pLendingProxy__CalledAsAnyFunction(_lendingProtocolAddress);
        _lendingProtocolAddress.functionCall(_lendingProtocolCalldata);
    }

    /// @inheritdoc IAllowedCalldataChecker
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

    /// @inheritdoc IP2pLendingProxy
    function getFactory() external view returns (address) {
        return address(i_factory);
    }

    /// @inheritdoc IP2pLendingProxy
    function getP2pTreasury() external view returns (address) {
        return i_p2pTreasury;
    }

    /// @inheritdoc IP2pLendingProxy
    function getClient() external view returns (address) {
        return s_client;
    }

    /// @inheritdoc IP2pLendingProxy
    function getClientBasisPoints() external view returns (uint96) {
        return s_clientBasisPoints;
    }

    /// @inheritdoc IP2pLendingProxy
    function getTotalDeposited(address _asset) external view returns (uint256) {
        return s_totalDeposited[_asset];
    }

    /// @inheritdoc IP2pLendingProxy
    function getTotalWithdrawn(address _asset) external view returns (uint256) {
        return s_totalWithdrawn[_asset];
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IP2pLendingProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
