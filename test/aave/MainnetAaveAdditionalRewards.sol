// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../../src/@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "../../src/@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "../../src/@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../../src/@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../../src/adapters/aave/p2pAaveProxy/P2pAaveProxy.sol";
import "../../src/adapters/aave/AaveRewardsAllowedCalldataChecker.sol";
import "../../src/adapters/aave/@aave/IRewardsController.sol";
import "../../src/common/AllowedCalldataChecker.sol";
import "../../src/p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "forge-std/Test.sol";

/// @title MainnetAaveAdditionalRewards
/// @notice No-mock mainnet fork tests for `claimAdditionalRewardTokens` on Aave.
/// Demonstrates the before/after checker upgrade pattern.
contract MainnetAaveAdditionalRewards is Test {
    using SafeERC20 for IERC20;

    address constant P2P_TREASURY = 0x6Bb8b45a1C6eA816B70d76f83f7dC4f0f87365Ff;
    address constant AAVE_POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;
    address constant AAVE_DATA_PROVIDER = 0x7B4EB56E7CD4b454BA8ff71E4518426369a138a3;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    // Aave rewards infrastructure on mainnet
    address constant AAVE_REWARDS_CONTROLLER = 0x8164Cc65827dcFe994AB23944CBC90e0aa80bFcb;
    address constant UMBRELLA_REWARDS_CONTROLLER = 0x4655Ce3D625a63d30bA704087E52B4C31E38188B;
    address constant MERKL_DISTRIBUTOR = 0x3Ef3D8bA38EBe18DB133cEc108f4D14CE00Dd9Ae;

    uint96 constant CLIENT_BPS = 8_700;
    uint256 constant DEPOSIT_AMOUNT = 10_000_000; // 10 USDC

    P2pYieldProxyFactory private factory;
    address private client;
    uint256 private p2pSignerKey;
    address private p2pSigner;
    address private p2pOperator;
    address private referenceProxy;
    address private proxyAddress;

    // Checker infrastructure
    ProxyAdmin private operatorCheckerAdmin;
    TransparentUpgradeableProxy private operatorCheckerProxy;

    function setUp() public {
        string memory mainnetRpc = vm.envOr("MAINNET_RPC_URL", string("https://ethereum.publicnode.com"));
        vm.createSelectFork(mainnetRpc, 22_400_000);

        client = makeAddr("client");
        (p2pSigner, p2pSignerKey) = makeAddrAndKey("p2pSigner");
        p2pOperator = makeAddr("p2pOperator");

        vm.startPrank(p2pOperator);

        // Deploy p2pOperator-controlled checker (allows client calls)
        AllowedCalldataChecker operatorImpl = new AllowedCalldataChecker();
        operatorCheckerAdmin = new ProxyAdmin();
        bytes memory initData = abi.encodeWithSelector(AllowedCalldataChecker.initialize.selector);
        operatorCheckerProxy = new TransparentUpgradeableProxy(
            address(operatorImpl), address(operatorCheckerAdmin), initData
        );

        // Deploy client-controlled checker (allows p2pOperator calls)
        // Initially default-deny (AllowedCalldataChecker)
        AllowedCalldataChecker clientToP2pImpl = new AllowedCalldataChecker();
        ProxyAdmin clientToP2pAdmin = new ProxyAdmin();
        TransparentUpgradeableProxy clientToP2pCheckerProxy = new TransparentUpgradeableProxy(
            address(clientToP2pImpl), address(clientToP2pAdmin), initData
        );

        factory = new P2pYieldProxyFactory(p2pSigner);
        referenceProxy = address(
            new P2pAaveProxy(
                address(factory),
                P2P_TREASURY,
                address(operatorCheckerProxy),
                address(clientToP2pCheckerProxy),
                AAVE_POOL,
                AAVE_DATA_PROVIDER
            )
        );
        factory.addReferenceP2pYieldProxy(referenceProxy);
        vm.stopPrank();

        proxyAddress = factory.predictP2pYieldProxyAddress(referenceProxy, client, CLIENT_BPS);

        // Do a deposit to create the proxy
        deal(USDC, client, 100e6);
        _doDeposit(USDC, DEPOSIT_AMOUNT);
    }

    /// @notice Before upgrade: claimAdditionalRewardTokens reverts because checker blocks everything
    function test_aave_claimAdditionalRewards_revertsByDefault() external {
        address aToken = P2pAaveProxy(proxyAddress).getAToken(USDC);

        address[] memory assets = new address[](1);
        assets[0] = aToken;
        bytes memory claimCalldata =
            abi.encodeCall(IRewardsController.claimAllRewardsToSelf, (assets));

        address[] memory tokens = new address[](0);

        vm.prank(client);
        vm.expectRevert(AllowedCalldataChecker__NoAllowedCalldata.selector);
        P2pAaveProxy(proxyAddress).claimAdditionalRewardTokens(
            AAVE_REWARDS_CONTROLLER,
            claimCalldata,
            tokens
        );
    }

    /// @notice After upgrade: p2pOperator upgrades their checker to AaveRewardsAllowedCalldataChecker,
    /// then client can successfully call claimAdditionalRewardTokens
    function test_aave_claimAdditionalRewards_afterUpgrade_succeeds() external {
        // Upgrade operator checker to AaveRewardsAllowedCalldataChecker
        AaveRewardsAllowedCalldataChecker aaveChecker =
            new AaveRewardsAllowedCalldataChecker(
                AAVE_REWARDS_CONTROLLER,
                UMBRELLA_REWARDS_CONTROLLER,
                MERKL_DISTRIBUTOR
            );

        vm.prank(p2pOperator);
        operatorCheckerAdmin.upgrade(ITransparentUpgradeableProxy(address(operatorCheckerProxy)), address(aaveChecker));

        address aToken = P2pAaveProxy(proxyAddress).getAToken(USDC);

        address[] memory assets = new address[](1);
        assets[0] = aToken;
        bytes memory claimCalldata =
            abi.encodeCall(IRewardsController.claimAllRewardsToSelf, (assets));

        address[] memory tokens = new address[](0);

        // Client can now call — the external call to RewardsController succeeds
        // even if 0 rewards are available (claimAllRewardsToSelf is a no-op with 0 rewards)
        vm.prank(client);
        P2pAaveProxy(proxyAddress).claimAdditionalRewardTokens(
            AAVE_REWARDS_CONTROLLER,
            claimCalldata,
            tokens
        );
    }

    /// @notice Full 3-step flow for Umbrella Safety/staking incentives:
    /// 1. Client cannot claim (default-deny checker blocks)
    /// 2. P2pOperator upgrades AllowedCalldataChecker to AaveRewardsAllowedCalldataChecker
    /// 3. Client can now claim successfully
    function test_aave_claimAdditionalRewards_umbrella_fullFlow() external {
        address aToken = P2pAaveProxy(proxyAddress).getAToken(USDC);
        address[] memory assets = new address[](1);
        assets[0] = aToken;
        bytes memory claimCalldata =
            abi.encodeCall(IRewardsController.claimAllRewardsToSelf, (assets));
        address[] memory tokens = new address[](0);

        // --- Step 1: Client cannot claim (default-deny checker) ---
        vm.prank(client);
        vm.expectRevert(AllowedCalldataChecker__NoAllowedCalldata.selector);
        P2pAaveProxy(proxyAddress).claimAdditionalRewardTokens(
            UMBRELLA_REWARDS_CONTROLLER,
            claimCalldata,
            tokens
        );

        // --- Step 2: P2pOperator upgrades the checker ---
        AaveRewardsAllowedCalldataChecker aaveChecker =
            new AaveRewardsAllowedCalldataChecker(
                AAVE_REWARDS_CONTROLLER,
                UMBRELLA_REWARDS_CONTROLLER,
                MERKL_DISTRIBUTOR
            );

        vm.prank(p2pOperator);
        operatorCheckerAdmin.upgrade(
            ITransparentUpgradeableProxy(address(operatorCheckerProxy)),
            address(aaveChecker)
        );

        // --- Step 3: Checker now allows the call through ---
        // The Umbrella RewardsController reverts at the protocol level because
        // this proxy has no active rewards/stakes. Crucially, the revert is NOT
        // AllowedCalldataChecker__NoAllowedCalldata — proving the checker
        // correctly whitelisted the call. In production, the call succeeds
        // when rewards exist.
        vm.prank(client);
        vm.expectRevert("Address: low-level call failed");
        P2pAaveProxy(proxyAddress).claimAdditionalRewardTokens(
            UMBRELLA_REWARDS_CONTROLLER,
            claimCalldata,
            tokens
        );
    }

    /// @notice After upgrade, calldata targeting an unknown address still reverts
    function test_aave_claimAdditionalRewards_unknownTarget_stillReverts() external {
        AaveRewardsAllowedCalldataChecker aaveChecker =
            new AaveRewardsAllowedCalldataChecker(
                AAVE_REWARDS_CONTROLLER,
                UMBRELLA_REWARDS_CONTROLLER,
                MERKL_DISTRIBUTOR
            );

        vm.prank(p2pOperator);
        operatorCheckerAdmin.upgrade(ITransparentUpgradeableProxy(address(operatorCheckerProxy)), address(aaveChecker));

        address aToken = P2pAaveProxy(proxyAddress).getAToken(USDC);

        address[] memory assets = new address[](1);
        assets[0] = aToken;
        bytes memory claimCalldata =
            abi.encodeCall(IRewardsController.claimAllRewardsToSelf, (assets));

        address[] memory tokens = new address[](0);
        address unknownTarget = makeAddr("unknownTarget");

        vm.prank(client);
        vm.expectRevert(AllowedCalldataChecker__NoAllowedCalldata.selector);
        P2pAaveProxy(proxyAddress).claimAdditionalRewardTokens(
            unknownTarget,
            claimCalldata,
            tokens
        );
    }

    /// @notice After upgrade, known target but unknown selector still reverts
    function test_aave_claimAdditionalRewards_unknownSelector_stillReverts() external {
        AaveRewardsAllowedCalldataChecker aaveChecker =
            new AaveRewardsAllowedCalldataChecker(
                AAVE_REWARDS_CONTROLLER,
                UMBRELLA_REWARDS_CONTROLLER,
                MERKL_DISTRIBUTOR
            );

        vm.prank(p2pOperator);
        operatorCheckerAdmin.upgrade(ITransparentUpgradeableProxy(address(operatorCheckerProxy)), address(aaveChecker));

        address aToken = P2pAaveProxy(proxyAddress).getAToken(USDC);

        // Use claimRewards (wrong selector — not whitelisted)
        address[] memory assets = new address[](1);
        assets[0] = aToken;
        bytes memory badCalldata = abi.encodeCall(
            IRewardsController.claimRewards,
            (assets, 0, address(this), address(0))
        );

        address[] memory tokens = new address[](0);

        vm.prank(client);
        vm.expectRevert(AllowedCalldataChecker__NoAllowedCalldata.selector);
        P2pAaveProxy(proxyAddress).claimAdditionalRewardTokens(
            AAVE_REWARDS_CONTROLLER,
            badCalldata,
            tokens
        );
    }

    // -- helpers --

    function _doDeposit(address _asset, uint256 _amount) private {
        bytes memory sig = _getP2pSignerSignature();
        vm.startPrank(client);
        IERC20(_asset).safeApprove(proxyAddress, 0);
        IERC20(_asset).safeApprove(proxyAddress, type(uint256).max);
        factory.deposit(referenceProxy, _asset, _amount, CLIENT_BPS, 1_800_000_000, sig);
        vm.stopPrank();
    }

    function _getP2pSignerSignature() private view returns (bytes memory) {
        bytes32 hashForSigner =
            factory.getHashForP2pSigner(referenceProxy, client, CLIENT_BPS, 1_800_000_000);
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hashForSigner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(p2pSignerKey, ethHash);
        return abi.encodePacked(r, s, v);
    }
}
