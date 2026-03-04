// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../@openzeppelin/contracts-upgradable/proxy/utils/Initializable.sol";
import "../../common/AllowedCalldataChecker.sol";
import "./@aave/IRewardsController.sol";
import "../morpho/@morpho/IDistributor.sol";

/// @title AaveRewardsAllowedCalldataChecker
/// @notice Whitelists calldata patterns for claiming additional Aave rewards:
///   - Aave Governance rewards via RewardsController.claimAllRewardsToSelf
///   - Safety/Umbrella staking incentives via Umbrella RewardsController.claimAllRewardsToSelf
///   - Merit rewards via Merkl Distributor.claim
contract AaveRewardsAllowedCalldataChecker is IAllowedCalldataChecker, Initializable {
    address public immutable i_aaveRewardsController;
    address public immutable i_umbrellaRewardsController;
    address public immutable i_merklDistributor;

    bytes4 private constant CLAIM_ALL_REWARDS_TO_SELF_SELECTOR =
        IRewardsController.claimAllRewardsToSelf.selector;
    bytes4 private constant MERKL_CLAIM_SELECTOR =
        IDistributor.claim.selector;

    constructor(
        address _aaveRewardsController,
        address _umbrellaRewardsController,
        address _merklDistributor
    ) {
        i_aaveRewardsController = _aaveRewardsController;
        i_umbrellaRewardsController = _umbrellaRewardsController;
        i_merklDistributor = _merklDistributor;
    }

    function initialize() public initializer {}

    /// @inheritdoc IAllowedCalldataChecker
    function checkCalldata(
        address _target,
        bytes4 _selector,
        bytes calldata
    ) external view {
        if (_target == i_aaveRewardsController || _target == i_umbrellaRewardsController) {
            if (_selector == CLAIM_ALL_REWARDS_TO_SELF_SELECTOR) {
                return;
            }
        }

        if (_target == i_merklDistributor) {
            if (_selector == MERKL_CLAIM_SELECTOR) {
                return;
            }
        }

        revert AllowedCalldataChecker__NoAllowedCalldata();
    }
}
