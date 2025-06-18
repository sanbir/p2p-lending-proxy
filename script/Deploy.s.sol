// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../lib/forge-std/src/Vm.sol";
import "../src/adapters/resolv/p2pResolvProxyFactory/P2pEthenaProxyFactory.sol";
import {Script} from "forge-std/Script.sol";

contract Deploy is Script {
    address constant USR = 0x66a1E37c9b0eAddca17d3662D6c05F4DECf3e110;
    address constant stUSR = 0x6c8984bc7DBBeDAf4F6b2FD766f16eBB7d10AAb4;
    address constant P2pTreasury = 0xfeef177E6168F9b7fd59e6C5b6c2d87FF398c6FD;

    function run()
        external
        returns (P2pResolvProxyFactory factory, P2pResolvProxy proxy)
    {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        Vm.Wallet memory wallet = vm.createWallet(deployerKey);

        vm.startBroadcast(deployerKey);
            factory = new P2pResolvProxyFactory(
                wallet.addr,
                P2pTreasury,
                stUSR,
                USR
            );
        vm.stopBroadcast();

        proxy = P2pResolvProxy(factory.getReferenceP2pYieldProxy());

        return (factory, proxy);
    }
}
