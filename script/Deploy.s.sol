// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../lib/forge-std/src/Vm.sol";
import "../src/adapters/ethena/p2pEthenaProxyFactory/P2pEthenaProxyFactory.sol";
import "../src/common/IMorphoBundler.sol";
import {Script} from "forge-std/Script.sol";

contract Deploy is Script {
    address constant USDe = 0x4c9EDD5852cd905f086C759E8383e09bff1E68B3;
    address constant sUSDe = 0x9D39A5DE30e57443BfF2A8307A4256c8797A3497;
    address constant P2pTreasury = 0xfeef177E6168F9b7fd59e6C5b6c2d87FF398c6FD;

    function run()
        external
        returns (P2pEthenaProxyFactory factory, P2pEthenaProxy proxy)
    {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        Vm.Wallet memory wallet = vm.createWallet(deployerKey);

        vm.startBroadcast(deployerKey);
            factory = new P2pEthenaProxyFactory(
                wallet.addr,
                P2pTreasury,
                sUSDe,
                USDe
            );
        vm.stopBroadcast();

        proxy = P2pEthenaProxy(factory.getReferenceP2pLendingProxy());

        return (factory, proxy);
    }
}
