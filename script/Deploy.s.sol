// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../src/p2pLendingProxyFactory/P2pLendingProxyFactory.sol";
import {Script} from "forge-std/Script.sol";

contract Deploy is Script {
    function run()
        external
        returns (P2pLendingProxyFactory factory, P2pLendingProxy proxy)
    {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerKey);
        factory = new P2pLendingProxyFactory(
            0x000000005504F0f5CF39b1eD609B892d23028E57,
            0x6Bb8b45a1C6eA816B70d76f83f7dC4f0f87365Ff
        );
        vm.stopBroadcast();

        proxy = P2pLendingProxy(factory.getReferenceP2pLendingProxy());

        return (factory, proxy);
    }
}
