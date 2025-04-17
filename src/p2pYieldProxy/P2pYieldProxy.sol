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
import "../common/IAllowedCalldataChecker.sol";
import "../p2pYieldProxyFactory/IP2pYieldProxyFactory.sol";
import "./IP2pYieldProxy.sol";
import {IERC4626} from "../@openzeppelin/contracts/interfaces/IERC4626.sol";

error P2pYieldProxy__ZeroAddressAsset();
error P2pYieldProxy__ZeroAssetAmount(address _asset);
error P2pYieldProxy__ZeroSharesAmount();
error P2pYieldProxy__InvalidClientBasisPointsOfDeposit(uint48 _clientBasisPointsOfDeposit);
error P2pYieldProxy__InvalidClientBasisPointsOfProfit(uint48 _clientBasisPointsOfProfit);
error P2pYieldProxy__NotFactory(address _factory);
error P2pYieldProxy__DifferentActuallyDepositedAmount(
    address _asset,
    uint256 _requestedAmount,
    uint256 _actualAmount
);
error P2pYieldProxy__NotFactoryCalled(
    address _msgSender,
    IP2pYieldProxyFactory _actualFactory
);
error P2pYieldProxy__NotClientCalled(
    address _msgSender,
    address _actualClient
);
error P2pYieldProxy__ZeroAddressFactory();
error P2pYieldProxy__ZeroAddressP2pTreasury();
error P2pYieldProxy__ZeroAddressYieldProtocolAddress();
error P2pYieldProxy__ZeroNewAssetAmount(address _asset);
error P2pYieldProxy__ZeroAllowedCalldataChecker();
error P2pYieldProxy__DataTooShort();
error P2pYieldProxy__AllAssetsMustBeUnique();

/// @title P2pYieldProxy
/// @notice P2pYieldProxy is a contract that allows a client to deposit and withdraw assets from a yield protocol.
abstract contract P2pYieldProxy is
    ReentrancyGuard,
    ERC165,
    IP2pYieldProxy {

    using SafeERC20 for IERC20;
    using Address for address;

    address constant NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @dev P2pYieldProxyFactory
    IP2pYieldProxyFactory internal immutable i_factory;

    /// @dev P2pTreasury
    address payable internal immutable i_p2pTreasury;

    /// @dev Yield protocol address
    address internal immutable i_yieldProtocolAddress;

    IAllowedCalldataChecker internal immutable i_allowedCalldataChecker;

    /// @dev Client
    address payable internal s_client;

    /// @dev Client basis points of deposit
    uint48 internal s_clientBasisPointsOfDeposit;

    /// @dev Client basis points of profit
    uint48 internal s_clientBasisPointsOfProfit;

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

    /// @dev Modifier for checking if a calldata is allowed
    /// @param _yieldProtocolAddress The address of the yield protocol
    /// @param _yieldProtocolCalldata The calldata (encoded signature + arguments) to be passed to the yield protocol
    modifier calldataShouldBeAllowed(
        address _yieldProtocolAddress,
        bytes calldata _yieldProtocolCalldata
    ) {
        // validate yieldProtocolCalldata for yieldProtocolAddress
        bytes4 selector = _getFunctionSelector(_yieldProtocolCalldata);
        i_allowedCalldataChecker.checkCalldata(
            _yieldProtocolAddress,
            selector,
            _yieldProtocolCalldata[4:]
        );
        _;
    }

    /// @notice Constructor for P2pYieldProxy
    /// @param _factory The factory address
    /// @param _p2pTreasury The P2pTreasury address
    /// @param _yieldProtocolAddress Yield protocol address
    /// @param _allowedCalldataChecker AllowedCalldataChecker
    constructor(
        address _factory,
        address _p2pTreasury,
        address _yieldProtocolAddress,
        address _allowedCalldataChecker
    ) {
        require (_factory != address(0), P2pYieldProxy__ZeroAddressFactory());
        i_factory = IP2pYieldProxyFactory(_factory);

        require (_p2pTreasury != address(0), P2pYieldProxy__ZeroAddressP2pTreasury());
        i_p2pTreasury = payable(_p2pTreasury);

        require (_yieldProtocolAddress != address(0), P2pYieldProxy__ZeroAddressYieldProtocolAddress());
        i_yieldProtocolAddress = _yieldProtocolAddress;

        require (_allowedCalldataChecker != address(0), P2pYieldProxy__ZeroAllowedCalldataChecker());
        i_allowedCalldataChecker = IAllowedCalldataChecker(_allowedCalldataChecker);
    }

    /// @inheritdoc IP2pYieldProxy
    function initialize(
        address _client,
        uint48 _clientBasisPointsOfDeposit,
        uint48 _clientBasisPointsOfProfit
    )
    external
    onlyFactory
    {
        require (
            _clientBasisPointsOfDeposit >= 0 && _clientBasisPointsOfDeposit <= 10_000,
            P2pYieldProxy__InvalidClientBasisPointsOfDeposit(_clientBasisPointsOfDeposit)
        );
        require (
            _clientBasisPointsOfProfit >= 0 && _clientBasisPointsOfProfit <= 10_000,
            P2pYieldProxy__InvalidClientBasisPointsOfProfit(_clientBasisPointsOfProfit)
        );

        s_client = payable(_client);
        s_clientBasisPointsOfDeposit = _clientBasisPointsOfDeposit;
        s_clientBasisPointsOfProfit = _clientBasisPointsOfProfit;

        emit P2pYieldProxy__Initialized();
    }

    function deposit(
        IAllowanceTransfer.PermitSingle calldata _permitSingleForP2pYieldProxy,
        bytes calldata _permit2SignatureForP2pYieldProxy,
        bytes calldata _superformCalldata
    ) external virtual payable;

    function depositBatch(
        IAllowanceTransfer.PermitBatch calldata _permitBatchForP2pYieldProxy,
        bytes calldata _permit2SignatureForP2pYieldProxy,
        uint256[] calldata _fundingAssetAmounts,
        bytes calldata _superformCalldata
    ) external virtual payable;

    /// @notice Deposit assets into yield protocol
    /// @param _vaultId vault ID
    /// @param _yieldProtocolDepositCalldata calldata for deposit function of yield protocol
    /// @param _permitSingleForP2pYieldProxy PermitSingle for P2pYieldProxy to pull assets from client
    /// @param _permit2SignatureForP2pYieldProxy signature of PermitSingle for P2pYieldProxy
    /// @param _usePermit2 whether should use Permit2 or native ERC-20 transferFrom
    /// @param _isNative whether ETH (native currency) is being deposited
    /// @param _nativeAmountToDepositAfterFee native amount to deposit after fee
    function _deposit(
        uint256 _vaultId,
        bytes memory _yieldProtocolDepositCalldata,
        IAllowanceTransfer.PermitSingle calldata _permitSingleForP2pYieldProxy,
        bytes calldata _permit2SignatureForP2pYieldProxy,
        bool _usePermit2,
        bool _isNative,
        uint256 _nativeAmountToDepositAfterFee
    )
    internal
    onlyFactory
    {
        if (_isNative) {
            uint256 totalDepositedAfter = s_totalDeposited[_vaultId][NATIVE] + _nativeAmountToDepositAfterFee;
            s_totalDeposited[_vaultId][NATIVE] = totalDepositedAfter;
            emit P2pYieldProxy__Deposited(
                i_yieldProtocolAddress,
                NATIVE,
                _nativeAmountToDepositAfterFee,
                totalDepositedAfter,
                _vaultId
            );
        } else {
            address asset = _permitSingleForP2pYieldProxy.details.token;
            require (asset != address(0), P2pYieldProxy__ZeroAddressAsset());

            uint160 amount = _permitSingleForP2pYieldProxy.details.amount;
            require (amount > 0, P2pYieldProxy__ZeroAssetAmount(asset));

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
                P2pYieldProxy__DifferentActuallyDepositedAmount(asset, amount, actualAmount)
            ); // no support for fee-on-transfer or rebasing tokens

            uint256 amountToDepositAfterFee = actualAmount * s_clientBasisPointsOfDeposit / 10_000;

            uint256 totalDepositedAfter = s_totalDeposited[_vaultId][asset] + amountToDepositAfterFee;
            s_totalDeposited[_vaultId][asset] = totalDepositedAfter;
            emit P2pYieldProxy__Deposited(
                i_yieldProtocolAddress,
                asset,
                amountToDepositAfterFee,
                totalDepositedAfter,
                _vaultId
            );

            if (_usePermit2) {
                IERC20(asset).safeIncreaseAllowance(
                    address(Permit2Lib.PERMIT2),
                    amountToDepositAfterFee
                );
            } else {
                IERC20(asset).safeIncreaseAllowance(
                    i_yieldProtocolAddress,
                    amountToDepositAfterFee
                );
            }
        }

        Address.sendValue(i_p2pTreasury,msg.value - _nativeAmountToDepositAfterFee);
        i_yieldProtocolAddress.functionCallWithValue(
            _yieldProtocolDepositCalldata,
            _nativeAmountToDepositAfterFee
        );
    }

    /// @notice Deposit assets into yield protocol
    /// @param _vaultIds vault IDs
    /// @param _yieldProtocolDepositCalldata calldata for deposit function of yield protocol
    /// @param _permitBatchForP2pYieldProxy PermitBatch for P2pYieldProxy to pull assets from client
    /// @param _permit2SignatureForP2pYieldProxy signature of PermitSingle for P2pYieldProxy
    /// @param _usePermit2 whether should use Permit2 or native ERC-20 transferFrom
    /// @param _assets asset addresses
    /// @param _fundingAssetAmounts amount for each deposit
    /// @param _nativeAmounts amount of ETH for each deposit
    /// @param _nativeAmountToDepositAfterFee native amount to deposit after fee
    function _depositBatch(
        uint256[] memory _vaultIds,
        bytes memory _yieldProtocolDepositCalldata,
        IAllowanceTransfer.PermitBatch calldata _permitBatchForP2pYieldProxy,
        bytes calldata _permit2SignatureForP2pYieldProxy,
        bool _usePermit2,
        address[] memory _assets,
        uint256[] calldata _fundingAssetAmounts,
        uint256[] memory _nativeAmounts,
        uint256 _nativeAmountToDepositAfterFee
    )
    internal
    onlyFactory
    {
        address client = s_client;
        uint48 clientBasisPointsOfDeposit = s_clientBasisPointsOfDeposit;

        (address[] memory uniqueTokens, uint256 uniqueCount) = _getUniqueAssets(_assets, false);

        IAllowanceTransfer.AllowanceTransferDetails[] memory transferDetails =
                    new IAllowanceTransfer.AllowanceTransferDetails[](uniqueCount);
        uint256[] memory uniqueTokenAmountsBefore = new uint256[](uniqueCount);

        for (uint256 unique_i = 0; unique_i < uniqueCount; ++unique_i) {
            address uniqueToken = uniqueTokens[unique_i];

            uint160 amount;
            for (uint256 permit_i = 0; permit_i < _permitBatchForP2pYieldProxy.details.length; ++permit_i) {
                if (_permitBatchForP2pYieldProxy.details[permit_i].token == uniqueToken) {
                    amount += _permitBatchForP2pYieldProxy.details[permit_i].amount;
                }
            }
            require (amount > 0, P2pYieldProxy__ZeroAssetAmount(uniqueToken));

            transferDetails[unique_i] = IAllowanceTransfer.AllowanceTransferDetails({
                from: client,
                to: address(this),
                amount: amount,
                token: uniqueToken
            });

            uniqueTokenAmountsBefore[unique_i] = IERC20(uniqueToken).balanceOf(address(this));
        }

        if (uniqueCount > 0) {
            // batch transfer tokens into Proxy
            try Permit2Lib.PERMIT2.permit(
                client,
                _permitBatchForP2pYieldProxy,
                _permit2SignatureForP2pYieldProxy
            ) {}
            catch {} // prevent unintended reverts due to invalidated nonce
            Permit2Lib.PERMIT2.transferFrom(transferDetails);
        }

        for (uint256 vault_i = 0; vault_i < _vaultIds.length; ++vault_i) {
            uint256 vaultId = _vaultIds[vault_i];
            address asset = _assets[vault_i];

            if (asset == NATIVE) {
                // check for nativeAmountToDepositAfterFee >= sum(_nativeAmounts) has been done in P2pSuperformProxy

                uint256 totalDepositedAfter = s_totalDeposited[vaultId][NATIVE] + _nativeAmounts[vault_i];
                s_totalDeposited[vaultId][NATIVE] = totalDepositedAfter;
                emit P2pYieldProxy__Deposited(
                    i_yieldProtocolAddress,
                    NATIVE,
                    _nativeAmounts[vault_i],
                    totalDepositedAfter,
                    vaultId
                );
            }
        }

        for (uint256 unique_i = 0; unique_i < uniqueCount; ++unique_i) {
            address uniqueToken = uniqueTokens[unique_i];
            uint256 assetAmountAfter = IERC20(uniqueToken).balanceOf(address(this));
            uint256 actualAmountBeforeFee = assetAmountAfter - uniqueTokenAmountsBefore[unique_i];
            uint256 amountToDepositAfterFee = actualAmountBeforeFee * clientBasisPointsOfDeposit / 10_000;

            uint256 totalUniqueTokenAmount;
            for (uint256 i = 0; i < _vaultIds.length; ++i) {
                uint256 vaultId = _vaultIds[i];

                if (_assets[i] == uniqueToken) {
                    totalUniqueTokenAmount += _fundingAssetAmounts[i];

                    uint256 totalDepositedAfter = s_totalDeposited[vaultId][uniqueToken] + _fundingAssetAmounts[i];
                    s_totalDeposited[vaultId][uniqueToken] = totalDepositedAfter;
                    emit P2pYieldProxy__Deposited(
                        i_yieldProtocolAddress,
                        uniqueToken,
                        _fundingAssetAmounts[i],
                        totalDepositedAfter,
                        vaultId
                    );
                }
            }

            require (
                amountToDepositAfterFee >= totalUniqueTokenAmount,
                P2pYieldProxy__DifferentActuallyDepositedAmount(uniqueToken, totalUniqueTokenAmount, amountToDepositAfterFee)
            ); // no support for fee-on-transfer or rebasing tokens

            uint256 tokenFee = actualAmountBeforeFee - amountToDepositAfterFee;
            if (tokenFee > 0) {
                // transfer uniqueToken to P2P treasury
                emit P2pYieldProxy__DepositFee(uniqueToken, tokenFee);
                IERC20(uniqueToken).safeTransfer(i_p2pTreasury, tokenFee);
            }

            if (_usePermit2) {
                IERC20(uniqueToken).safeIncreaseAllowance(
                    address(Permit2Lib.PERMIT2),
                    totalUniqueTokenAmount
                );
            } else {
                IERC20(uniqueToken).safeIncreaseAllowance(
                    i_yieldProtocolAddress,
                    totalUniqueTokenAmount
                );
            }
        }

        uint256 nativeFee = msg.value - _nativeAmountToDepositAfterFee;
        if (nativeFee > 0) {
            // transfer ETH to P2P treasury
            emit P2pYieldProxy__DepositFee(NATIVE, nativeFee);
            Address.sendValue(i_p2pTreasury, nativeFee);
        }

        i_yieldProtocolAddress.functionCallWithValue(
            _yieldProtocolDepositCalldata,
            _nativeAmountToDepositAfterFee
        );
    }

    function _getUniqueAssets(
        address[] memory _assets,
        bool _withNative
    ) internal pure returns(
        address[] memory uniqueAssets,
        uint256 uniqueCount
    ) {
        // Determine the worst-case total number of token addresses.
        uint256 totalCount = _assets.length;

        // Allocate a memory array for potential unique assets.
        uniqueAssets = new address[](totalCount);
        uniqueCount = 0;

        for (uint256 total_i = 0; total_i < totalCount; ++total_i) {
            address asset = _assets[total_i];

            require (asset != address(0), P2pYieldProxy__ZeroAddressAsset());

            if (asset == NATIVE && !_withNative) {
                continue;
            }

            bool found;
            for (uint256 unique_i = 0; unique_i < uniqueCount; ++unique_i) {
                if (uniqueAssets[unique_i] == asset) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                uniqueAssets[uniqueCount] = asset;
                uniqueCount++;
            }
        }
    }

    /// @notice Batch withdraw assets from yield protocol
    /// @param _vaultIds vault IDs
    /// @param _assets ERC-20 asset addresses
    /// @param _yieldProtocolWithdrawalCalldata calldata for withdraw function of yield protocol
    function _withdrawBatch(
        uint256[] memory _vaultIds,
        address[] memory _assets,
        bytes memory _yieldProtocolWithdrawalCalldata
    )
    internal
    onlyClient
    nonReentrant
    {
        (, uint256 uniqueCount) = _getUniqueAssets(_assets, true);
        require (uniqueCount == _assets.length, P2pYieldProxy__AllAssetsMustBeUnique());

        uint256[] memory assetAmountsBefore = new uint256[](uniqueCount);
        for (uint256 i = 0; i < uniqueCount; ++i) {
            address asset = _assets[i];
            bool isNative = asset == NATIVE;

            assetAmountsBefore[i] = isNative
                ? address(this).balance
                : IERC20(asset).balanceOf(address(this));
        }

        // withdraw assets from Protocol
        i_yieldProtocolAddress.functionCall(_yieldProtocolWithdrawalCalldata);

        for (uint256 i = 0; i < uniqueCount; ++i) {
            address asset = _assets[i];
            bool isNative = asset == NATIVE;

            uint256 assetAmountAfter = isNative
                ? address(this).balance
                : IERC20(asset).balanceOf(address(this));

            uint256 newAssetAmount = assetAmountAfter - assetAmountsBefore[i];

            require (newAssetAmount != 0, P2pYieldProxy__ZeroNewAssetAmount(asset));

            uint256 vaultId = _vaultIds[i];

            uint256 totalWithdrawnBefore = s_totalWithdrawn[vaultId][asset];
            uint256 totalWithdrawnAfter = totalWithdrawnBefore + newAssetAmount;
            uint256 totalDeposited = s_totalDeposited[vaultId][asset];

            // update total withdrawn
            s_totalWithdrawn[vaultId][asset] = totalWithdrawnAfter;

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
                p2pAmount = (newProfit * (10_000 - s_clientBasisPointsOfProfit) + 9999) / 10_000;
            }
            uint256 clientAmount = newAssetAmount - p2pAmount;

            if (p2pAmount > 0) {
                if (isNative) {
                    Address.sendValue(i_p2pTreasury, p2pAmount);
                } else {
                    IERC20(asset).safeTransfer(i_p2pTreasury, p2pAmount);
                }
            }
            // clientAmount must be > 0 at this point
            if (isNative) {
                Address.sendValue(s_client, clientAmount);
            } else {
                IERC20(asset).safeTransfer(s_client, clientAmount);
            }

            emit P2pYieldProxy__Withdrawn(
                i_yieldProtocolAddress,
                vaultId,
                asset,
                newAssetAmount,
                totalWithdrawnAfter,
                newProfit,
                p2pAmount,
                clientAmount
            );
        }
    }

    /// @notice Withdraw assets from yield protocol
    /// @param _vaultId vault ID
    /// @param _asset ERC-20 asset address
    /// @param _yieldProtocolWithdrawalCalldata calldata for withdraw function of yield protocol
    function _withdraw(
        uint256 _vaultId,
        address _asset,
        bytes memory _yieldProtocolWithdrawalCalldata
    )
    internal
    onlyClient
    nonReentrant
    {
        bool isNative = _asset == NATIVE;

        uint256 assetAmountBefore = isNative
            ? address(this).balance
            : IERC20(_asset).balanceOf(address(this));

        // withdraw assets from Protocol
        i_yieldProtocolAddress.functionCall(_yieldProtocolWithdrawalCalldata);

        uint256 assetAmountAfter = isNative
            ? address(this).balance
            : IERC20(_asset).balanceOf(address(this));

        uint256 newAssetAmount = assetAmountAfter - assetAmountBefore;

        require (newAssetAmount != 0, P2pYieldProxy__ZeroNewAssetAmount(_asset));

        uint256 totalWithdrawnBefore = s_totalWithdrawn[_vaultId][_asset];
        uint256 totalWithdrawnAfter = totalWithdrawnBefore + newAssetAmount;
        uint256 totalDeposited = s_totalDeposited[_vaultId][_asset];

        // update total withdrawn
        s_totalWithdrawn[_vaultId][_asset] = totalWithdrawnAfter;

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
            p2pAmount = (newProfit * (10_000 - s_clientBasisPointsOfProfit) + 9999) / 10_000;
        }
        uint256 clientAmount = newAssetAmount - p2pAmount;

        if (p2pAmount > 0) {
            if (isNative) {
                Address.sendValue(i_p2pTreasury, p2pAmount);
            } else {
                IERC20(_asset).safeTransfer(i_p2pTreasury, p2pAmount);
            }
        }
        // clientAmount must be > 0 at this point
        if (isNative) {
            Address.sendValue(s_client, clientAmount);
        } else {
            IERC20(_asset).safeTransfer(s_client, clientAmount);
        }

        emit P2pYieldProxy__Withdrawn(
            i_yieldProtocolAddress,
            _vaultId,
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

    /// @notice Returns function selector (first 4 bytes of data)
    /// @param _data calldata (encoded signature + arguments)
    /// @return functionSelector function selector
    function _getFunctionSelector(
        bytes calldata _data
    ) private pure returns (bytes4 functionSelector) {
        require (_data.length >= 4, P2pYieldProxy__DataTooShort());
        return bytes4(_data[:4]);
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
    function getClientBasisPointsOfDeposit() external view returns (uint48) {
        return s_clientBasisPointsOfDeposit;
    }

    /// @inheritdoc IP2pYieldProxy
    function getClientBasisPointsOfProfit() external view returns (uint48) {
        return s_clientBasisPointsOfProfit;
    }

    /// @inheritdoc IP2pYieldProxy
    function getTotalDeposited(uint256 _vaultId, address _asset) external view returns (uint256) {
        return s_totalDeposited[_vaultId][_asset];
    }

    /// @inheritdoc IP2pYieldProxy
    function getTotalWithdrawn(uint256 _vaultId, address _asset) external view returns (uint256) {
        return s_totalWithdrawn[_vaultId][_asset];
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IP2pYieldProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
