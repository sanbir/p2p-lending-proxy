// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "../@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../@openzeppelin/contracts/utils/Address.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import "../@permit2/interfaces/IAllowanceTransfer.sol";
import "../@permit2/libraries/Permit2Lib.sol";
import "../common/AllowedCalldataChecker.sol";
import "../common/P2pStructs.sol";
import "../p2pYieldProxyFactory/IP2pYieldProxyFactory.sol";
import "./IP2pYieldProxy.sol";
import {IERC4626} from "../@openzeppelin/contracts/interfaces/IERC4626.sol";

/// @dev Error when the asset address is zero   
error P2pYieldProxy__ZeroAddressAsset();

/// @dev Error when the asset amount is zero
error P2pYieldProxy__ZeroAssetAmount();

/// @dev Error when the shares amount is zero
error P2pYieldProxy__ZeroSharesAmount();

/// @dev Error when the client basis points are invalid
error P2pYieldProxy__InvalidClientBasisPoints(uint96 _clientBasisPoints);

/// @dev Error when the factory is not the caller
error P2pYieldProxy__NotFactory(address _factory);

error P2pYieldProxy__DifferentActuallyDepositedAmount(
    uint256 _requestedAmount,
    uint256 _actualAmount
);

/// @dev Error when the factory is not the caller
/// @param _msgSender sender address.
/// @param _actualFactory the actual factory address.
error P2pYieldProxy__NotFactoryCalled(
    address _msgSender,
    IP2pYieldProxyFactory _actualFactory
);

/// @dev Error when the client is not the caller
/// @param _msgSender sender address.
/// @param _actualClient the actual client address.
error P2pYieldProxy__NotClientCalled(
    address _msgSender,
    address _actualClient
);

error P2pYieldProxy__ZeroAddressFactory();
error P2pYieldProxy__ZeroAddressP2pTreasury();
error P2pYieldProxy__ZeroAddressYieldProtocolAddress();

/// @title P2pYieldProxy
/// @notice P2pYieldProxy is a contract that allows a client to deposit and withdraw assets from a yield protocol.
abstract contract P2pYieldProxy is
    AllowedCalldataChecker,
    P2pStructs,
    ReentrancyGuard,
    ERC165,
    IP2pYieldProxy {

    using SafeERC20 for IERC20;
    using Address for address;

    address constant NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @dev P2pYieldProxyFactory
    IP2pYieldProxyFactory internal immutable i_factory;

    /// @dev P2pTreasury
    address internal immutable i_p2pTreasury;

    /// @dev Yield protocol address
    address internal immutable i_yieldProtocolAddress;

    /// @dev Client
    address internal s_client;

    /// @dev Client basis points
    uint96 internal s_clientBasisPoints;

    mapping(uint256 vaultId => mapping(address asset => uint256 amount)) internal s_totalDeposited;

    mapping(uint256 vaultId => mapping(address asset => uint256 amount)) internal s_totalWithdrawn;

    /// @notice If caller is not factory, revert
    modifier onlyFactory() {
        if (msg.sender != address(i_factory)) {
            revert P2pYieldProxy__NotFactoryCalled(msg.sender, i_factory);
        }
        _;
    }

    /// @notice If caller is not client, revert
    modifier onlyClient() {
        if (msg.sender != s_client) {
            revert P2pYieldProxy__NotClientCalled(msg.sender, s_client);
        }
        _;
    }

    /// @notice Constructor for P2pYieldProxy
    /// @param _factory The factory address
    /// @param _p2pTreasury The P2pTreasury address
    /// @param _yieldProtocolAddress Yield protocol address
    constructor(
        address _factory,
        address _p2pTreasury,
        address _yieldProtocolAddress
    ) {
        require(_factory != address(0), P2pYieldProxy__ZeroAddressFactory());
        i_factory = IP2pYieldProxyFactory(_factory);

        require(_p2pTreasury != address(0), P2pYieldProxy__ZeroAddressP2pTreasury());
        i_p2pTreasury = _p2pTreasury;

        require(_yieldProtocolAddress != address(0), P2pYieldProxy__ZeroAddressYieldProtocolAddress());
        i_yieldProtocolAddress = _yieldProtocolAddress;
    }

    /// @inheritdoc IP2pYieldProxy
    function initialize(
        address _client,
        uint96 _clientBasisPoints
    )
    external
    onlyFactory
    {
        require(
            _clientBasisPoints > 0 && _clientBasisPoints <= 10_000,
            P2pYieldProxy__InvalidClientBasisPoints(_clientBasisPoints)
        );

        s_client = _client;
        s_clientBasisPoints = _clientBasisPoints;

        emit P2pYieldProxy__Initialized();
    }

    /// @notice Deposit assets into yield protocol
    /// @param _vaultId vault ID
    /// @param _yieldProtocolDepositCalldata calldata for deposit function of yield protocol
    /// @param _permitSingleForP2pYieldProxy PermitSingle for P2pYieldProxy to pull assets from client
    /// @param _permit2SignatureForP2pYieldProxy signature of PermitSingle for P2pYieldProxy
    /// @param _usePermit2 whether should use Permit2 or native ERC-20 transferFrom
    /// @param _isNative whether ETH (native currency) is being deposited
    function _deposit(
        uint256 _vaultId,
        bytes memory _yieldProtocolDepositCalldata,
        IAllowanceTransfer.PermitSingle calldata _permitSingleForP2pYieldProxy,
        bytes calldata _permit2SignatureForP2pYieldProxy,
        bool _usePermit2,
        bool _isNative
    )
    internal
    onlyFactory
    {
        if (_isNative) {
            uint256 totalDepositedAfter = s_totalDeposited[_vaultId][NATIVE] + msg.value;
            s_totalDeposited[_vaultId][NATIVE] = totalDepositedAfter;
            emit P2pYieldProxy__Deposited(
                i_yieldProtocolAddress,
                NATIVE,
                msg.value,
                totalDepositedAfter
            );
        } else {
            address asset = _permitSingleForP2pYieldProxy.details.token;
            require (asset != address(0), P2pYieldProxy__ZeroAddressAsset());

            uint160 amount = _permitSingleForP2pYieldProxy.details.amount;
            require (amount > 0, P2pYieldProxy__ZeroAssetAmount());

            address client = s_client;

            // transfer tokens into Proxy
            try Permit2Lib.PERMIT2.permit(
                client,
                _permitSingleForP2pYieldProxy,
                _permit2SignatureForP2pYieldProxy
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

            require (
                actualAmount == amount,
                P2pYieldProxy__DifferentActuallyDepositedAmount(amount, actualAmount)
            ); // no support for fee-on-transfer or rebasing tokens

            uint256 totalDepositedAfter = s_totalDeposited[_vaultId][asset] + actualAmount;
            s_totalDeposited[_vaultId][asset] = totalDepositedAfter;
            emit P2pYieldProxy__Deposited(
                i_yieldProtocolAddress,
                asset,
                actualAmount,
                totalDepositedAfter
            );

            if (_usePermit2) {
                IERC20(asset).safeIncreaseAllowance(
                    address(Permit2Lib.PERMIT2),
                    actualAmount
                );
            } else {
                IERC20(asset).safeIncreaseAllowance(
                    i_yieldProtocolAddress,
                    actualAmount
                );
            }
        }

        i_yieldProtocolAddress.functionCallWithValue(
            _yieldProtocolDepositCalldata,
            msg.value
        );
    }

    /// @notice Withdraw assets from yield protocol
    /// @param _asset ERC-20 asset address
    /// @param _yieldProtocolWithdrawalCalldata calldata for withdraw function of yield protocol
    function _withdraw(
        address _asset,
        bytes memory _yieldProtocolWithdrawalCalldata
    )
    internal
    onlyClient
    nonReentrant
    {
        uint256 assetAmountBefore = IERC20(_asset).balanceOf(address(this));

        // withdraw assets from Protocol
        i_yieldProtocolAddress.functionCall(_yieldProtocolWithdrawalCalldata);

        uint256 assetAmountAfter = IERC20(_asset).balanceOf(address(this));

        uint256 newAssetAmount = assetAmountAfter - assetAmountBefore;

        uint256 totalWithdrawnBefore = s_totalWithdrawn[_asset];
        uint256 totalWithdrawnAfter = totalWithdrawnBefore + newAssetAmount;
        uint256 totalDeposited = s_totalDeposited[_asset];

        // update total withdrawn
        s_totalWithdrawn[_asset] = totalWithdrawnAfter;

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
            IERC20(_asset).safeTransfer(i_p2pTreasury, p2pAmount);
        }
        // clientAmount must be > 0 at this point
        IERC20(_asset).safeTransfer(s_client, clientAmount);

        emit P2pYieldProxy__Withdrawn(
            i_yieldProtocolAddress,
            i_yieldProtocolAddress,
            _asset,
            newAssetAmount,
            totalWithdrawnAfter,
            newProfit,
            p2pAmount,
            clientAmount
        );
    }

    /// @inheritdoc IP2pYieldProxy
    function callAnyFunction(
        address _yieldProtocolAddress,
        bytes calldata _yieldProtocolCalldata
    )
    external
    onlyClient
    nonReentrant
    calldataShouldBeAllowed(_yieldProtocolAddress, _yieldProtocolCalldata)
    {
        emit P2pYieldProxy__CalledAsAnyFunction(_yieldProtocolAddress);
        _yieldProtocolAddress.functionCall(_yieldProtocolCalldata);
    }

    /// @inheritdoc IAllowedCalldataChecker
    function checkCalldata(
        address _target,
        bytes4 _selector,
        bytes calldata _calldataAfterSelector
    ) public view override(AllowedCalldataChecker, IAllowedCalldataChecker) {
        i_factory.checkCalldata(
            _target,
            _selector,
            _calldataAfterSelector
        );
    }

    /// @inheritdoc IP2pYieldProxy
    function getFactory() external view returns (address) {
        return address(i_factory);
    }

    /// @inheritdoc IP2pYieldProxy
    function getP2pTreasury() external view returns (address) {
        return i_p2pTreasury;
    }

    /// @inheritdoc IP2pYieldProxy
    function getClient() external view returns (address) {
        return s_client;
    }

    /// @inheritdoc IP2pYieldProxy
    function getClientBasisPoints() external view returns (uint96) {
        return s_clientBasisPoints;
    }

    /// @inheritdoc IP2pYieldProxy
    function getTotalDeposited(address _asset) external view returns (uint256) {
        return s_totalDeposited[_asset];
    }

    /// @inheritdoc IP2pYieldProxy
    function getTotalWithdrawn(address _asset) external view returns (uint256) {
        return s_totalWithdrawn[_asset];
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IP2pYieldProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
