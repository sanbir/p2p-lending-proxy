// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../../@openzeppelin/contracts/utils/Address.sol";
import "../../common/AllowedCalldataChecker.sol";
import "../../p2pYieldProxyFactory/IP2pYieldProxyFactory.sol";
import "../../structs/P2pStructs.sol";
import "../P2pYieldProxyErrors.sol";
import "../IP2pYieldProxy.sol";
import "../storage/P2pYieldProxyStorage.sol";

abstract contract P2pYieldProxyFactoryCallable {
    function _factoryRef() internal view virtual returns (IP2pYieldProxyFactory);

    modifier onlyFactory() {
        IP2pYieldProxyFactory factory = _factoryRef();
        if (msg.sender != address(factory)) {
            revert P2pYieldProxy__NotFactoryCalled(msg.sender, factory);
        }
        _;
    }
}

abstract contract P2pYieldProxyClientCallable is P2pYieldProxyClientStorage {
    modifier onlyClient() {
        if (msg.sender != s_client) {
            revert P2pYieldProxy__NotClientCalled(msg.sender, s_client);
        }
        _;
    }
}

abstract contract P2pYieldProxyCalldataAllowed {
    function _allowedCalldataCheckerRef() internal view virtual returns (IAllowedCalldataChecker);

    modifier calldataShouldBeAllowed(
        address _yieldProtocolAddress,
        bytes calldata _yieldProtocolCalldata
    ) {
        bytes4 selector = _getFunctionSelector(_yieldProtocolCalldata);
        _allowedCalldataCheckerRef().checkCalldata(
            _yieldProtocolAddress,
            selector,
            _yieldProtocolCalldata[4:]
        );
        _;
    }

    function _getFunctionSelector(
        bytes calldata _data
    ) private pure returns (bytes4 functionSelector) {
        require(_data.length >= 4, P2pYieldProxy__DataTooShort());
        return bytes4(_data[:4]);
    }
}

abstract contract P2pYieldProxyFeeMath is P2pYieldProxyClientBasisPointsStorage {
    function calculateP2pFeeAmount(uint256 _amount) internal view returns (uint256 p2pFeeAmount) {
        if (_amount == 0) return 0;
        p2pFeeAmount = (_amount * (10_000 - s_clientBasisPoints) + 9999) / 10_000;
    }
}

abstract contract P2pYieldProxyDepositable is
    P2pYieldProxyFactoryCallable,
    P2pYieldProxyTotalDepositedStorage,
    P2pYieldProxyClientStorage
{
    using SafeERC20 for IERC20;
    using Address for address;

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
        IERC20(_asset).safeTransferFrom(client, address(this), _amount);
        uint256 actualAmount = IERC20(_asset).balanceOf(address(this)) - assetAmountBefore;

        require(
            actualAmount == _amount,
            P2pYieldProxy__DifferentActuallyDepositedAmount(_amount, actualAmount)
        );

        uint256 totalDepositedAfter = s_totalDeposited[_asset] + actualAmount;
        s_totalDeposited[_asset] = totalDepositedAfter;
        emit IP2pYieldProxy.P2pYieldProxy__Deposited(_vault, _asset, actualAmount, totalDepositedAfter);

        if (_transferBeforeCall) {
            IERC20(_asset).safeTransfer(_callTarget, actualAmount);
        } else {
            IERC20(_asset).safeIncreaseAllowance(_callTarget, actualAmount);
        }

        _callTarget.functionCall(_yieldProtocolDepositCalldata);
    }
}

abstract contract P2pYieldProxyWithdrawable is
    P2pYieldProxyDepositable,
    P2pYieldProxyFeeMath,
    P2pYieldProxyTotalWithdrawnStorage
{
    using SafeERC20 for IERC20;
    using Address for address;

    function _withdraw(
        address _yieldProtocolAddress,
        address _asset,
        bytes memory _yieldProtocolWithdrawalCalldata
    )
        internal
        virtual
        returns (uint256)
    {
        return _executeWithdraw(
            _yieldProtocolAddress,
            _yieldProtocolAddress,
            _yieldProtocolAddress,
            _asset,
            _yieldProtocolAddress,
            _yieldProtocolWithdrawalCalldata
        );
    }

    function _withdraw(
        address _vault,
        address _asset,
        address _callTarget,
        bytes memory _yieldProtocolWithdrawalCalldata,
        uint256 _shares
    )
        internal
        virtual
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
            _yieldProtocolWithdrawalCalldata
        );
    }

    function _executeWithdraw(
        address _accrualTarget,
        address _eventYieldProtocolAddress,
        address _eventVaultAddress,
        address _asset,
        address _callTarget,
        bytes memory _yieldProtocolWithdrawalCalldata
    )
        private
        returns (uint256)
    {
        int256 accruedRewardsBefore = calculateAccruedRewards(_accrualTarget, _asset);
        uint256 newAssetAmount = _callAndGetDelta(_asset, _callTarget, _yieldProtocolWithdrawalCalldata);

        Withdrawn memory withdrawn = s_totalWithdrawn[_asset];
        (uint256 principalPortion, uint256 profitPortion) = _splitWithdrawalAmount(
            newAssetAmount,
            s_totalDeposited[_asset],
            withdrawn.amount,
            accruedRewardsBefore
        );

        uint256 totalWithdrawnAfter = _updateWithdrawnState(_asset, withdrawn, principalPortion);
        (uint256 p2pAmount, uint256 clientAmount) = _distributeWithFeeBase(_asset, newAssetAmount, profitPortion);

        emit IP2pYieldProxy.P2pYieldProxy__Withdrawn(
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

    function _getUserPrincipal(address _asset) internal view returns (uint256) {
        uint256 totalDeposited = getTotalDepositedStorage(_asset);
        uint256 totalWithdrawn = getTotalWithdrawnStorage(_asset);
        if (totalDeposited > totalWithdrawn) {
            return totalDeposited - totalWithdrawn;
        }
        return 0;
    }

    function calculateAccruedRewards(address _yieldProtocolAddress, address _asset)
        public
        view
        virtual
        returns (int256);

    function _splitWithdrawalAmount(
        uint256 _newAssetAmount,
        uint256 _totalDeposited,
        uint256 _withdrawnAmount,
        int256 _accruedRewardsBefore
    )
        private
        view
        returns (uint256 principalPortion, uint256 profitPortion)
    {
        uint256 remainingPrincipal = _totalDeposited > _withdrawnAmount ? _totalDeposited - _withdrawnAmount : 0;
        uint256 profitFromAccrued = _min(_newAssetAmount, _positivePart(_accruedRewardsBefore));

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

    function _positivePart(int256 _value) private pure returns (uint256) {
        return _value > 0 ? uint256(_value) : 0;
    }

    function _min(uint256 _a, uint256 _b) private pure returns (uint256) {
        return _a < _b ? _a : _b;
    }

    function _requireWithdrawnWithinAccrued(
        uint256 _withdrawn,
        int256 _accruedBefore,
        uint256 _tolerance
    ) internal pure {
        uint256 maxAllowed = _positivePart(_accruedBefore) + _tolerance;
        require(_withdrawn <= maxAllowed, P2pYieldProxy__AmountExceedsAccrued(_withdrawn, maxAllowed));
    }

    function _callAndGetDelta(
        address _asset,
        address _target,
        bytes memory _callData
    ) internal returns (uint256 delta) {
        uint256 beforeBalance = IERC20(_asset).balanceOf(address(this));
        _target.functionCall(_callData);
        delta = IERC20(_asset).balanceOf(address(this)) - beforeBalance;
    }

    function _distributeWithFeeBase(
        address _asset,
        uint256 _totalAmount,
        uint256 _feeBaseAmount
    ) internal returns (uint256 p2pAmount, uint256 clientAmount) {
        p2pAmount = calculateP2pFeeAmount(_feeBaseAmount);
        clientAmount = _totalAmount - p2pAmount;

        if (p2pAmount > 0) {
            IERC20(_asset).safeTransfer(_p2pTreasuryAddress(), p2pAmount);
        }

        if (clientAmount > 0) {
            IERC20(_asset).safeTransfer(s_client, clientAmount);
        }
    }

    function _p2pTreasuryAddress() internal view virtual returns (address);
}

abstract contract P2pYieldProxyAnyFunctionExecutor is P2pYieldProxyClientCallable, P2pYieldProxyCalldataAllowed {
    using Address for address;

    function _callAnyFunction(
        address _yieldProtocolAddress,
        bytes calldata _yieldProtocolCalldata
    ) internal {
        emit IP2pYieldProxy.P2pYieldProxy__CalledAsAnyFunction(_yieldProtocolAddress);
        _yieldProtocolAddress.functionCall(_yieldProtocolCalldata);
    }
}
