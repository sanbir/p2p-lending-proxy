// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../lib/forge-std/src/Vm.sol";
import "../src/adapters/superform/p2pSuperformProxyFactory/P2pSuperformProxyFactory.sol";
import {Script} from "forge-std/Script.sol";
import {PermitHash} from "../src/@permit2/libraries/PermitHash.sol";

contract RunTestWithdrawBase is Script {
    using SafeERC20 for IERC20;

    uint96 constant ClientBasisPoints = 8700; // 13% fee

    P2pSuperformProxyFactory factory;
    address proxyAddress;

    function run()
    external
    {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        Vm.Wallet memory wallet = vm.createWallet(deployerKey);

        factory = P2pSuperformProxyFactory(0x2b2CBe3Cb583EDDa67B6121E29962405C9856FE9);
        proxyAddress = factory.predictP2pYieldProxyAddress(wallet.addr, ClientBasisPoints);

        bytes memory superformCalldata = hex'407c7b1d00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000020000000000000210500000001668bcc80d9b85de4e683a5e1d64946e175a3a748000000000000000000000000000000000000000000000000000000000001dcb5000000000000000000000000000000000000000000000000000000000001e20700000000000000000000000000000000000000000000000000000000000013880000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e1158d9158d41186994b400ab833b85284f2e06c000000000000000000000000e1158d9158d41186994b400ab833b85284f2e06c000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'; //abi.encodeCall(IBaseRouter.singleDirectSingleVaultDeposit, (req));

        vm.startBroadcast(deployerKey);
        P2pSuperformProxy(proxyAddress).withdraw(superformCalldata);
        vm.stopBroadcast();
    }
}

