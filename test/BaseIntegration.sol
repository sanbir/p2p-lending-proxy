// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../src/@openzeppelin/contracts/interfaces/IERC4626.sol";
import "../src/@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "../src/@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "../src/@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../src/adapters/morpho/p2pMorphoProxy/P2pMorphoProxy.sol";
import "../src/adapters/morpho/p2pMorphoProxyFactory/P2pMorphoProxyFactory.sol";
import "../src/common/AllowedCalldataChecker.sol";
import "forge-std/Test.sol";

contract BaseIntegration is Test {
    using SafeERC20 for IERC20;

    address constant P2P_TREASURY = 0x6Bb8b45a1C6eA816B70d76f83f7dC4f0f87365Ff;
    address constant MORPHO_BUNDLER = 0x23055618898e202386e6c13955a58D3C68200BFB;
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address constant VAULT_USDC = 0xeE8F4eC5672F09119b96Ab6fB59C27E1b7e44b61;

    uint256 constant SIG_DEADLINE = 1_734_464_723;
    uint96 constant CLIENT_BPS = 8_700;
    uint256 constant DEPOSIT_AMOUNT = 10_000_000;

    P2pMorphoProxyFactory private factory;
    address private client;
    uint256 private clientKey;
    address private p2pSigner;
    uint256 private p2pSignerKey;
    address private p2pOperator;
    address private proxyAddress;

    function setUp() public {
        vm.createSelectFork("base", 23_607_078);

        (client, clientKey) = makeAddrAndKey("client");
        (p2pSigner, p2pSignerKey) = makeAddrAndKey("p2pSigner");
        p2pOperator = makeAddr("p2pOperator");

        deal(USDC, client, 100_000_000e6);

        vm.startPrank(p2pOperator);
        AllowedCalldataChecker implementation = new AllowedCalldataChecker();
        ProxyAdmin admin = new ProxyAdmin();
        bytes memory initData = abi.encodeWithSelector(AllowedCalldataChecker.initialize.selector);
        TransparentUpgradeableProxy checkerProxy =
            new TransparentUpgradeableProxy(address(implementation), address(admin), initData);
        factory = new P2pMorphoProxyFactory(p2pSigner, P2P_TREASURY, address(checkerProxy), MORPHO_BUNDLER);
        vm.stopPrank();

        proxyAddress = factory.predictP2pYieldProxyAddress(client, CLIENT_BPS);
    }

    function test_HappyPath_Base() external {
        _doDeposit();

        uint256 shares = IERC20(VAULT_USDC).balanceOf(proxyAddress);
        assertGt(shares, 0);

        vm.startPrank(client);
        P2pMorphoProxy(proxyAddress).withdraw(VAULT_USDC, shares);
        vm.stopPrank();

        assertEq(IERC20(VAULT_USDC).balanceOf(proxyAddress), 0);
    }

    function _doDeposit() internal {
        bytes32 hashForSigner = factory.getHashForP2pSigner(client, CLIENT_BPS, SIG_DEADLINE);
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hashForSigner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(p2pSignerKey, ethHash);
        bytes memory p2pSignature = abi.encodePacked(r, s, v);

        vm.startPrank(client);
        IERC20(USDC).safeApprove(proxyAddress, 0);
        IERC20(USDC).safeApprove(proxyAddress, type(uint256).max);
        factory.deposit(VAULT_USDC, DEPOSIT_AMOUNT, CLIENT_BPS, SIG_DEADLINE, p2pSignature);
        vm.stopPrank();
    }
}
