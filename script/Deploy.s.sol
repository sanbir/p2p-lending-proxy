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

        P2pStructs.Rule memory rule0Deposit = P2pStructs.Rule({ // approve2
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 0,
            allowedBytes: hex"000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000184af504202"
        });
        P2pStructs.Rule memory rule1Deposit = P2pStructs.Rule({ // spender in approve2 must be MorphoEthereumBundlerV2
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 336,
            allowedBytes: abi.encodePacked(MorphoEthereumBundlerV2)
        });
        P2pStructs.Rule memory rule2Deposit = P2pStructs.Rule({ // transferFrom2
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 640,
            allowedBytes: hex"54c53ef0"
        });
        P2pStructs.Rule memory rule3Deposit = P2pStructs.Rule({ // erc4626Deposit
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 768,
            allowedBytes: hex"6ef5eeae"
        });
        P2pStructs.Rule[] memory rulesDeposit = new P2pStructs.Rule[](4);
        rulesDeposit[0] = rule0Deposit;
        rulesDeposit[1] = rule1Deposit;
        rulesDeposit[2] = rule2Deposit;
        rulesDeposit[3] = rule3Deposit;

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
