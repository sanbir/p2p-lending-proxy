// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../@openzeppelin/contracts-upgradable/security/ReentrancyGuardUpgradeable.sol";
import "../@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../@openzeppelin/contracts/utils/Address.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import "../common/AllowedCalldataChecker.sol";
import "../p2pYieldProxyFactory/IP2pYieldProxyFactory.sol";
import "../structs/P2pStructs.sol";
import "./IP2pYieldProxy.sol";

error P2pYieldProxy__ZeroAddressAsset();
error P2pYieldProxy__ZeroAssetAmount();
error P2pYieldProxy__ZeroSharesAmount();
error P2pYieldProxy__InvalidClientBasisPoints(uint96 _clientBasisPoints);
error P2pYieldProxy__NotFactory(address _factory);
error P2pYieldProxy__DifferentActuallyDepositedAmount(
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
error P2pYieldProxy__ZeroAllowedCalldataChecker();
error P2pYieldProxy__DataTooShort();

/// @title P2pYieldProxy
/// @notice P2pYieldProxy is a contract that allows a client to deposit and withdraw assets from a yield protocol.
abstract contract P2pYieldProxy is
    Initializable,
    ReentrancyGuardUpgradeable,
    ERC165,
    IP2pYieldProxy {

    using SafeERC20 for IERC20;
    using Address for address;

    /// @dev P2pYieldProxyFactory
    IP2pYieldProxyFactory internal immutable i_factory;

    /// @dev P2pTreasury
    address internal immutable i_p2pTreasury;

    IAllowedCalldataChecker internal immutable i_allowedCalldataChecker;

    /// @dev Client
    address internal s_client;

    /// @dev Client basis points
    uint96 internal s_clientBasisPoints;

    // asset => amount
    mapping(address => uint256) internal s_totalDeposited;

    // asset => amount
    mapping(address => Withdrawn) internal s_totalWithdrawn;

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
    /// @param _allowedCalldataChecker AllowedCalldataChecker
    constructor(
        address _factory,
        address _p2pTreasury,
        address _allowedCalldataChecker
    ) {
        require(_factory != address(0), P2pYieldProxy__ZeroAddressFactory());
        i_factory = IP2pYieldProxyFactory(_factory);

        require(_p2pTreasury != address(0), P2pYieldProxy__ZeroAddressP2pTreasury());
        i_p2pTreasury = _p2pTreasury;

        require (_allowedCalldataChecker != address(0), P2pYieldProxy__ZeroAllowedCalldataChecker());
        i_allowedCalldataChecker = IAllowedCalldataChecker(_allowedCalldataChecker);
    }

    /// @inheritdoc IP2pYieldProxy
    function initialize(
        address _client,
        uint96 _clientBasisPoints
    )
    external
    initializer
    onlyFactory
    {
        __ReentrancyGuard_init();

        require(
            _clientBasisPoints > 0 && _clientBasisPoints <= 10_000,
            P2pYieldProxy__InvalidClientBasisPoints(_clientBasisPoints)
        );

        s_client = _client;
        s_clientBasisPoints = _clientBasisPoints;

        emit P2pYieldProxy__Initialized();
    }

    /// @inheritdoc IP2pYieldProxy
    function deposit(address _asset, uint256 _amount) external virtual;

    /// @notice Deposit assets into yield protocol
    /// @param _yieldProtocolAddress yield protocol address
    /// @param _yieldProtocolDepositCalldata calldata for deposit function of yield protocol
    /// @param _asset asset to deposit
    /// @param _amount amount to deposit
    function _deposit(
        address _yieldProtocolAddress,
        bytes memory _yieldProtocolDepositCalldata,
        address _asset,
        uint256 _amount
    )
    internal
    onlyFactory
    {
        _deposit(
            _yieldProtocolAddress,
            _yieldProtocolAddress,
            _yieldProtocolDepositCalldata,
            _asset,
            _amount,
            false
        );
    }

    /// @notice Deposit assets into yield protocol via a dedicated call target
    /// @param _vault yield-bearing vault token or accounting target
    /// @param _callTarget contract that executes the deposit
    /// @param _yieldProtocolDepositCalldata calldata for deposit function of yield protocol
    /// @param _asset asset to deposit
    /// @param _amount amount to deposit
    /// @param _transferBeforeCall whether assets should be transferred to call target before invoking it
    function _deposit(
        address _vault,
        address _callTarget,
        bytes memory _yieldProtocolDepositCalldata,
        address _asset,
        uint256 _amount,
        bool _transferBeforeCall
    ) internal onlyFactory {
        require(_asset != address(0), P2pYieldProxy__ZeroAddressAsset());
        require(_amount > 0, P2pYieldProxy__ZeroAssetAmount());

        address client = s_client;

        uint256 assetAmountBefore = IERC20(_asset).balanceOf(address(this));

        // transfer tokens into Proxy
        IERC20(_asset).safeTransferFrom(client, address(this), _amount);

        uint256 assetAmountAfter = IERC20(_asset).balanceOf(address(this));
        uint256 actualAmount = assetAmountAfter - assetAmountBefore;

        require(
            actualAmount == _amount,
            P2pYieldProxy__DifferentActuallyDepositedAmount(_amount, actualAmount)
        ); // no support for fee-on-transfer or rebasing tokens

        uint256 totalDepositedAfter = s_totalDeposited[_asset] + actualAmount;
        s_totalDeposited[_asset] = totalDepositedAfter;
        emit P2pYieldProxy__Deposited(_vault, _asset, actualAmount, totalDepositedAfter);

        if (_transferBeforeCall) {
            IERC20(_asset).safeTransfer(_callTarget, actualAmount);
        } else {
            IERC20(_asset).safeIncreaseAllowance(_callTarget, actualAmount);
        }

        _callTarget.functionCall(_yieldProtocolDepositCalldata);
    }

    /// @notice Withdraw assets from yield protocol
    /// @param _yieldProtocolAddress yield protocol address
    /// @param _asset ERC-20 asset address
    /// @param _yieldProtocolWithdrawalCalldata calldata for withdraw function of yield protocol
    function _withdraw(
        address _yieldProtocolAddress,
        address _asset,
        bytes memory _yieldProtocolWithdrawalCalldata
    )
    internal
    returns (uint256)
    {
        return _withdraw(_yieldProtocolAddress, _asset, _yieldProtocolWithdrawalCalldata, false);
    }

    /// @notice Withdraw assets from yield protocol
    /// @param _yieldProtocolAddress yield protocol address
    /// @param _asset ERC-20 asset address
    /// @param _yieldProtocolWithdrawalCalldata calldata for withdraw function of yield protocol
    /// @param _rewardsOnly if true, prioritize treating the withdrawal as profit (used by operator reward flows)
    function _withdraw(
        address _yieldProtocolAddress,
        address _asset,
        bytes memory _yieldProtocolWithdrawalCalldata,
        bool _rewardsOnly
    )
    internal
    nonReentrant
    returns (uint256)
    {
        return _executeWithdraw(
            _yieldProtocolAddress,
            _yieldProtocolAddress,
            _yieldProtocolAddress,
            _asset,
            _yieldProtocolAddress,
            _yieldProtocolWithdrawalCalldata,
            _rewardsOnly
        );
    }

    /// @notice Withdraw assets from yield protocol via a dedicated call target
    /// @param _vault yield-bearing vault token used for accounting and allowance
    /// @param _asset ERC-20 asset address
    /// @param _callTarget contract that executes the withdrawal
    /// @param _yieldProtocolWithdrawalCalldata calldata for withdraw function of yield protocol
    /// @param _shares amount of vault shares to allow for redemption
    function _withdraw(
        address _vault,
        address _asset,
        address _callTarget,
        bytes memory _yieldProtocolWithdrawalCalldata,
        uint256 _shares
    )
        internal
        nonReentrant
        returns (uint256)
    {
        if (_shares > 0) {
            IERC20(_vault).safeIncreaseAllowance(_callTarget, _shares);
        }
        return _executeWithdraw(
            _vault,
            _callTarget,
            _vault,
            _asset,
            _callTarget,
            _yieldProtocolWithdrawalCalldata,
            false
        );
    }

    function _executeWithdraw(
        address _accrualTarget,
        address _eventYieldProtocolAddress,
        address _eventVaultAddress,
        address _asset,
        address _callTarget,
        bytes memory _yieldProtocolWithdrawalCalldata,
        bool _rewardsOnly
    )
        private
        returns (uint256)
    {
        int256 accruedRewardsBefore = calculateAccruedRewards(_accrualTarget, _asset);
        uint256 assetAmountBefore = IERC20(_asset).balanceOf(address(this));
        _callTarget.functionCall(_yieldProtocolWithdrawalCalldata);
        uint256 newAssetAmount = IERC20(_asset).balanceOf(address(this)) - assetAmountBefore;

        Withdrawn memory withdrawn = s_totalWithdrawn[_asset];
        (uint256 principalPortion, uint256 profitPortion) = _splitWithdrawalAmount(
            newAssetAmount,
            s_totalDeposited[_asset],
            withdrawn.amount,
            accruedRewardsBefore,
            _rewardsOnly
        );

        uint256 totalWithdrawnAfter = _updateWithdrawnState(_asset, withdrawn, principalPortion);
        (uint256 p2pAmount, uint256 clientAmount) = _distributeWithdrawal(_asset, newAssetAmount, profitPortion);

        emit P2pYieldProxy__Withdrawn(
            _eventYieldProtocolAddress,
            _eventVaultAddress,
            _asset,
            newAssetAmount,
            totalWithdrawnAfter,
            int256(profitPortion),
            p2pAmount,
            clientAmount
        );

        return newAssetAmount;
    }

    function _splitWithdrawalAmount(
        uint256 _newAssetAmount,
        uint256 _totalDeposited,
        uint256 _withdrawnAmount,
        int256 _accruedRewardsBefore,
        bool _rewardsOnly
    )
        private
        view
        returns (uint256 principalPortion, uint256 profitPortion)
    {
        uint256 remainingPrincipal = _totalDeposited > _withdrawnAmount
            ? _totalDeposited - _withdrawnAmount
            : 0;
        uint256 profitFromAccrued = _min(_newAssetAmount, _positivePart(_accruedRewardsBefore));

        if (_rewardsOnly) {
            profitPortion = profitFromAccrued;
            principalPortion = _min(_newAssetAmount - profitPortion, remainingPrincipal);
            return (principalPortion, profitPortion);
        }

        bool isClient = msg.sender == s_client;
        bool isClosingWithdrawal = isClient && _withdrawnAmount + _newAssetAmount >= _totalDeposited;
        if (isClosingWithdrawal) {
            principalPortion = _min(_newAssetAmount, remainingPrincipal);
            profitPortion = _newAssetAmount - principalPortion;
            return (principalPortion, profitPortion);
        }

        uint256 remainingAfterAccrued = _newAssetAmount - profitFromAccrued;
        principalPortion = _min(remainingAfterAccrued, remainingPrincipal);
        profitPortion = profitFromAccrued + (remainingAfterAccrued - principalPortion);
    }

    function _updateWithdrawnState(
        address _asset,
        Withdrawn memory _withdrawn,
        uint256 _principalPortion
    )
        private
        returns (uint256 totalWithdrawnAfter)
    {
        totalWithdrawnAfter = uint256(_withdrawn.amount) + _principalPortion;
        _withdrawn.amount = uint208(totalWithdrawnAfter);
        _withdrawn.lastFeeCollectionTime = uint48(block.timestamp);
        s_totalWithdrawn[_asset] = _withdrawn;
    }

    function _distributeWithdrawal(
        address _asset,
        uint256 _newAssetAmount,
        uint256 _profitPortion
    )
        private
        returns (uint256 p2pAmount, uint256 clientAmount)
    {
        // That extra 9999 ensures that any nonzero remainder will push the result up by 1 (ceiling division).
        p2pAmount = calculateP2pFeeAmount(_profitPortion);
        clientAmount = _newAssetAmount - p2pAmount;

        if (p2pAmount > 0) {
            IERC20(_asset).safeTransfer(i_p2pTreasury, p2pAmount);
        }
        IERC20(_asset).safeTransfer(s_client, clientAmount);
    }

    function _positivePart(int256 _value) private pure returns (uint256) {
        return _value > 0 ? uint256(_value) : 0;
    }

    function _min(uint256 _a, uint256 _b) private pure returns (uint256) {
        return _a < _b ? _a : _b;
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
    function getClientBasisPoints() external view returns (uint96) {
        return s_clientBasisPoints;
    }

    /// @inheritdoc IP2pYieldProxy
    function getTotalDeposited(address _asset) external view returns (uint256) {
        return s_totalDeposited[_asset];
    }

    /// @inheritdoc IP2pYieldProxy
    function getTotalWithdrawn(address _asset) external view returns (uint256) {
        return s_totalWithdrawn[_asset].amount;
    }

    function getUserPrincipal(address _asset) public view returns(uint256) {
        uint256 totalDeposited = s_totalDeposited[_asset];
        uint256 totalWithdrawn = s_totalWithdrawn[_asset].amount;
        if (totalDeposited > totalWithdrawn) {
            return totalDeposited - totalWithdrawn;
        }
        return 0;
    }

    function calculateAccruedRewards(address _yieldProtocolAddress, address _asset) public view virtual returns(int256) {
        uint256 currentAmount = _getCurrentAssetAmount(_yieldProtocolAddress, _asset);
        uint256 userPrincipal = getUserPrincipal(_asset);
        return int256(currentAmount) - int256(userPrincipal);
    }

    function _getCurrentAssetAmount(address _yieldProtocolAddress, address) internal view virtual returns (uint256) {
        return IERC20(_yieldProtocolAddress).balanceOf(address(this));
    }

    function getLastFeeCollectionTime(address _asset) public view returns(uint48) {
        return s_totalWithdrawn[_asset].lastFeeCollectionTime;
    }

    /// @notice Calculates P2P treasury fee amount using ceiling division
    /// @param _amount amount
    /// @return p2pFeeAmount p2p fee amount
    function calculateP2pFeeAmount(uint256 _amount) internal view returns (uint256 p2pFeeAmount) {
        if (_amount == 0) return 0;
        p2pFeeAmount = (_amount * (10_000 - s_clientBasisPoints) + 9999) / 10_000;
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IP2pYieldProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
