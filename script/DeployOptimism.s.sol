// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../lib/forge-std/src/Vm.sol";
import "../src/adapters/superform/p2pSuperformProxyFactory/P2pSuperformProxyFactory.sol";
import {Script} from "forge-std/Script.sol";

contract DeployOptimism is Script {
    address constant SuperformRouter = 0xa195608C2306A26f727d5199D5A382a4508308DA;
    address constant SuperPositions = 0x01dF6fb6a28a89d6bFa53b2b3F20644AbF417678;
    address constant P2pTreasury = 0x641ca805C75cC5D1ffa78C0181Aba1F77BD17904;

    function run()
    external
    returns (P2pSuperformProxyFactory factory, P2pSuperformProxy proxy)
    {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        Vm.Wallet memory wallet = vm.createWallet(deployerKey);

        vm.startBroadcast(deployerKey);
        factory = new P2pSuperformProxyFactory(
            wallet.addr,
            P2pTreasury,
            SuperformRouter,
            SuperPositions
        );
        vm.stopBroadcast();

        proxy = P2pSuperformProxy(factory.getReferenceP2pYieldProxy());

        return (factory, proxy);
    }
}

