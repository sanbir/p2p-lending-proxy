// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../lib/forge-std/src/Vm.sol";
import "../src/adapters/morpho/p2pMorphoProxy/P2pMorphoProxy.sol";
import "../src/adapters/morpho/p2pMorphoProxyFactory/P2pMorphoProxyFactory.sol";
import "../src/common/IMorphoBundler.sol";
import {Script} from "forge-std/Script.sol";

contract Deploy is Script {
    address constant MorphoEthereumBundlerV2 = 0x23055618898e202386e6c13955a58D3C68200BFB;
    address constant P2pTreasury = 0x6Bb8b45a1C6eA816B70d76f83f7dC4f0f87365Ff;

    function run()
        external
        returns (P2pMorphoProxyFactory factory, P2pMorphoProxy proxy)
    {
        // allowed calldata for factory
        bytes4 multicallSelector = IMorphoBundler.multicall.selector;

        P2pStructs.Rule[] memory rulesDeposit = new P2pStructs.Rule[](1);
        rulesDeposit[0] = P2pStructs.Rule({
            ruleType: P2pStructs.RuleType.AnyCalldata,
            index: 0,
            allowedBytes: bytes("")
        });

        P2pStructs.Rule memory rule0Withdrawal = P2pStructs.Rule({ // erc4626Redeem
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 0,
            allowedBytes: hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a4a7f6e606"
        });

        P2pStructs.Rule[] memory rulesWithdrawal = new P2pStructs.Rule[](1);
        rulesWithdrawal[0] = rule0Withdrawal;

        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        Vm.Wallet memory wallet = vm.createWallet(deployerKey);

        vm.startBroadcast(deployerKey);
            factory = new P2pMorphoProxyFactory(
        MorphoEthereumBundlerV2,
                wallet.addr,
                P2pTreasury
            );
            factory.setCalldataRules(
                P2pStructs.FunctionType.Deposit,
                MorphoEthereumBundlerV2,
                multicallSelector,
                rulesDeposit
            );
            factory.setCalldataRules(
                P2pStructs.FunctionType.Withdrawal,
                MorphoEthereumBundlerV2,
                multicallSelector,
                rulesWithdrawal
            );
        vm.stopBroadcast();

        proxy = P2pMorphoProxy(factory.getReferenceP2pLendingProxy());

        return (factory, proxy);
    }
}
