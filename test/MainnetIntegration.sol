// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../src/@openzeppelin/contracts/interfaces/IERC4626.sol";
import "../src/@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "../src/@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "../src/@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/access/P2pOperator.sol";
import "../src/adapters/morpho/p2pMorphoProxy/P2pMorphoProxy.sol";
import "../src/adapters/morpho/p2pMorphoProxyFactory/P2pMorphoProxyFactory.sol";
import "../src/common/AllowedCalldataChecker.sol";
import "forge-std/Test.sol";

contract MainnetIntegration is Test {
    using SafeERC20 for IERC20;

    address constant P2P_TREASURY = 0x6Bb8b45a1C6eA816B70d76f83f7dC4f0f87365Ff;
    address constant MORPHO_BUNDLER = 0x4095F064B8d3c3548A3bebfd0Bbfd04750E30077;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant VAULT_USDC = 0x8eB67A509616cd6A7c1B3c8C21D48FF57df3d458;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant VAULT_USDT = 0xbEef047a543E45807105E51A8BBEFCc5950fcfBa;

    uint256 constant SIG_DEADLINE = 1734464723;
    uint96 constant CLIENT_BASIS_POINTS = 8700;
    uint256 constant DEPOSIT_AMOUNT = 10_000_000; // 10 tokens

    P2pMorphoProxyFactory private factory;

    address private client;
    uint256 private clientKey;
    address private p2pSigner;
    uint256 private p2pSignerKey;
    address private p2pOperator;
    address private nobody;

    address private proxyAddress;

    address asset;
    address vault;

    function setUp() public {
        vm.createSelectFork("mainnet", 21308893);

        (client, clientKey) = makeAddrAndKey("client");
        (p2pSigner, p2pSignerKey) = makeAddrAndKey("p2pSigner");
        p2pOperator = makeAddr("p2pOperator");
        nobody = makeAddr("nobody");

        vm.startPrank(p2pOperator);
        AllowedCalldataChecker implementation = new AllowedCalldataChecker();
        ProxyAdmin admin = new ProxyAdmin();
        bytes memory initData = abi.encodeWithSelector(AllowedCalldataChecker.initialize.selector);
        TransparentUpgradeableProxy checkerProxy =
            new TransparentUpgradeableProxy(address(implementation), address(admin), initData);
        factory = new P2pMorphoProxyFactory(
            p2pSigner, P2P_TREASURY, address(checkerProxy), MORPHO_BUNDLER, USDC, VAULT_USDC, USDT, VAULT_USDT
        );
        vm.stopPrank();

        proxyAddress = factory.predictP2pYieldProxyAddress(client, CLIENT_BASIS_POINTS);
    }

    function test_HappyPath_USDC_Mainnet() external {
        asset = USDC;
        vault = VAULT_USDC;
        _happyPath();
    }

    function test_HappyPath_USDT_Mainnet() external {
        asset = USDT;
        vault = VAULT_USDT;
        _happyPath();
    }

    function test_profitSplit_Mainnet() external {
        asset = USDC;
        vault = VAULT_USDC;
        deal(asset, client, 100e6);

        uint256 clientBalanceBefore = IERC20(asset).balanceOf(client);
        uint256 treasuryBalanceBefore = IERC20(asset).balanceOf(P2P_TREASURY);

        _doDeposit();

        uint256 shares = IERC20(vault).balanceOf(proxyAddress);
        uint256 assetsBefore = IERC4626(vault).convertToAssets(shares);

        _forward(1_000_000);

        uint256 assetsAfter = IERC4626(vault).convertToAssets(shares);
        uint256 profit = assetsAfter - assetsBefore;

        _doWithdraw(1);

        uint256 clientBalanceAfter = IERC20(asset).balanceOf(client);
        uint256 treasuryBalanceAfter = IERC20(asset).balanceOf(P2P_TREASURY);

        uint256 clientChange = clientBalanceAfter - clientBalanceBefore;
        uint256 treasuryChange = treasuryBalanceAfter - treasuryBalanceBefore;
        uint256 totalChange = clientChange + treasuryChange;

        assertApproxEqAbs(totalChange, profit, 1);

        uint256 clientShare = clientChange * 10_000 / totalChange;
        uint256 treasuryShare = treasuryChange * 10_000 / totalChange;

        assertApproxEqAbs(CLIENT_BASIS_POINTS, clientShare, 1);
        assertApproxEqAbs(10_000 - CLIENT_BASIS_POINTS, treasuryShare, 1);
    }

    function test_withdrawAccruedRewards_byOperator() external {
        asset = USDC;
        vault = VAULT_USDC;
        deal(asset, client, 100e6);

        _doDeposit();
        _forward(1_000_000);

        uint256 simulatedYield = 5e6;
        deal(asset, vault, IERC20(asset).balanceOf(vault) + simulatedYield);

        vm.startPrank(p2pOperator);
        uint256 treasuryBefore = IERC20(asset).balanceOf(P2P_TREASURY);
        P2pMorphoProxy(proxyAddress).withdrawAccruedRewards(vault);
        uint256 treasuryAfter = IERC20(asset).balanceOf(P2P_TREASURY);
        vm.stopPrank();

        assertGt(treasuryAfter, treasuryBefore);
    }

    function test_withdrawAccruedRewards_revertsForClient() external {
        asset = USDC;
        vault = VAULT_USDC;
        deal(asset, client, 100e6);
        _doDeposit();

        vm.startPrank(client);
        vm.expectRevert(abi.encodeWithSelector(P2pMorphoProxy__NotP2pOperator.selector, client));
        P2pMorphoProxy(proxyAddress).withdrawAccruedRewards(vault);
        vm.stopPrank();
    }

    function test_transferP2pSigner() external {
        vm.startPrank(nobody);
        vm.expectRevert(abi.encodeWithSelector(P2pOperator.P2pOperator__UnauthorizedAccount.selector, nobody));
        factory.transferP2pSigner(nobody);
        vm.stopPrank();

        vm.startPrank(p2pOperator);
        factory.transferP2pSigner(nobody);
        vm.stopPrank();

        assertEq(factory.getP2pSigner(), nobody);
    }

    function _happyPath() private {
        deal(asset, client, 50e6);
        uint256 balanceBefore = IERC20(asset).balanceOf(client);

        _doDeposit();

        uint256 clientAfterDeposit = IERC20(asset).balanceOf(client);
        assertEq(balanceBefore - clientAfterDeposit, DEPOSIT_AMOUNT);

        uint256 shares = IERC20(vault).balanceOf(proxyAddress);
        assertGt(shares, 0);

        _doWithdraw(1);

        assertEq(IERC20(vault).balanceOf(proxyAddress), 0);
    }

    function _doDeposit() private {
        bytes memory signerSignature = _getP2pSignerSignature(client, CLIENT_BASIS_POINTS, SIG_DEADLINE);
        vm.startPrank(client);
        IERC20(asset).safeApprove(proxyAddress, 0);
        IERC20(asset).safeApprove(proxyAddress, type(uint256).max);
        factory.deposit(asset, DEPOSIT_AMOUNT, CLIENT_BASIS_POINTS, SIG_DEADLINE, signerSignature);
        vm.stopPrank();
    }

    function _doWithdraw(uint256 denominator) private {
        uint256 sharesBalance = IERC20(vault).balanceOf(proxyAddress);
        uint256 sharesToWithdraw = sharesBalance / denominator;

        vm.startPrank(client);
        P2pMorphoProxy(proxyAddress).withdraw(vault, sharesToWithdraw);
        vm.stopPrank();
    }

    function _getP2pSignerSignature(address _client, uint96 _clientBasisPoints, uint256 _sigDeadline)
        private
        view
        returns (bytes memory)
    {
        bytes32 hashForSigner = factory.getHashForP2pSigner(_client, _clientBasisPoints, _sigDeadline);
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hashForSigner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(p2pSignerKey, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _forward(uint256 blocks) internal {
        vm.roll(block.number + blocks);
        vm.warp(block.timestamp + blocks);
    }
}
