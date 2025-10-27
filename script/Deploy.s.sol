// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.30;

import "../lib/forge-std/src/Vm.sol";
import "../src/@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "../src/@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "../src/common/AllowedCalldataChecker.sol";
import "../src/adapters/morpho/p2pMorphoProxy/P2pMorphoProxy.sol";
import "../src/adapters/morpho/p2pMorphoProxyFactory/P2pMorphoProxyFactory.sol";
import {Script} from "forge-std/Script.sol";

contract Deploy is Script {
    address constant P2P_TREASURY = 0x6Bb8b45a1C6eA816B70d76f83f7dC4f0f87365Ff;
    address constant MORPHO_BUNDLER = 0x4095F064B8d3c3548A3bebfd0Bbfd04750E30077;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant VAULT_USDC = 0x8eB67A509616cd6A7c1B3c8C21D48FF57df3d458;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant VAULT_USDT = 0xbEef047a543E45807105E51A8BBEFCc5950fcfBa;

    function run() external returns (P2pMorphoProxyFactory factory, P2pMorphoProxy proxy) {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        Vm.Wallet memory wallet = vm.createWallet(deployerKey);

        vm.startBroadcast(deployerKey);
        AllowedCalldataChecker implementation = new AllowedCalldataChecker();
        ProxyAdmin admin = new ProxyAdmin();
        bytes memory initData = abi.encodeWithSelector(AllowedCalldataChecker.initialize.selector);
        TransparentUpgradeableProxy checkerProxy =
            new TransparentUpgradeableProxy(address(implementation), address(admin), initData);
        factory = new P2pMorphoProxyFactory(wallet.addr, P2P_TREASURY, address(checkerProxy), MORPHO_BUNDLER);
        vm.stopBroadcast();

        proxy = P2pMorphoProxy(factory.getReferenceP2pYieldProxy());
        return (factory, proxy);
    }
}
