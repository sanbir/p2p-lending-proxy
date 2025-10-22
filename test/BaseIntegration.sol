// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../src/@openzeppelin/contracts/interfaces/IERC4626.sol";
import "../src/adapters/morpho/p2pMorphoProxy/P2pMorphoProxy.sol";
import "../src/adapters/morpho/p2pMorphoProxyFactory/P2pMorphoProxyFactory.sol";
import "../src/common/IMorphoBundler.sol";
import "../src/common/P2pStructs.sol";
import "../src/p2pLendingProxyFactory/P2pLendingProxyFactory.sol";
import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/console2.sol";

contract BaseIntegration is Test {
    address constant P2pTreasury = 0x6Bb8b45a1C6eA816B70d76f83f7dC4f0f87365Ff;
    P2pMorphoProxyFactory private factory;

    address private clientAddress;
    uint256 private clientPrivateKey;

    address private p2pSignerAddress;
    uint256 private p2pSignerPrivateKey;

    address private p2pOperatorAddress;
    address private nobody;

    address constant MorphoEthereumBundlerV2 = 0x23055618898e202386e6c13955a58D3C68200BFB;
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address constant VaultUSDC = 0xeE8F4eC5672F09119b96Ab6fB59C27E1b7e44b61;

    uint256 constant SigDeadline = 1734464723;
    uint96 constant ClientBasisPoints = 8700; // 13% fee
    uint256 constant DepositAmount = 10000000;

    address proxyAddress;

    function setUp() public {
        vm.createSelectFork("base", 23607078);

        (clientAddress, clientPrivateKey) = makeAddrAndKey("client");
        (p2pSignerAddress, p2pSignerPrivateKey) = makeAddrAndKey("p2pSigner");
        p2pOperatorAddress = makeAddr("p2pOperator");
        nobody = makeAddr("nobody");

        deal(USDC, clientAddress, 10000e18);

        vm.startPrank(p2pOperatorAddress);
        factory = new P2pMorphoProxyFactory(
            MorphoEthereumBundlerV2,
            p2pSignerAddress,
            P2pTreasury
        );
        vm.stopPrank();

        proxyAddress = factory.predictP2pLendingProxyAddress(clientAddress, ClientBasisPoints);
    }

    function test_HappyPath_Base() external {
        // allowed calldata for factory
        bytes4 multicallSelector = IMorphoBundler.multicall.selector;

        P2pStructs.Rule[] memory rulesDeposit = new P2pStructs.Rule[](1);
        rulesDeposit[0] = P2pStructs.Rule({
            ruleType: P2pStructs.RuleType.AnyCalldata,
            index: 0,
            allowedBytes: bytes("")
        });

        vm.startPrank(p2pOperatorAddress);
        factory.setCalldataRules(
            P2pStructs.FunctionType.Deposit,
            MorphoEthereumBundlerV2,
            multicallSelector,
            rulesDeposit
        );
        vm.stopPrank();

        P2pStructs.Rule memory rule0Withdrawal = P2pStructs.Rule({ // erc4626Redeem
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 0,
            allowedBytes: hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a4a7f6e606"
        });

        P2pStructs.Rule[] memory rulesWithdrawal = new P2pStructs.Rule[](1);
        rulesWithdrawal[0] = rule0Withdrawal;

        vm.startPrank(p2pOperatorAddress);
        factory.setCalldataRules(
            P2pStructs.FunctionType.Withdrawal,
            MorphoEthereumBundlerV2,
            multicallSelector,
            rulesWithdrawal
        );
        vm.stopPrank();

        // morpho erc4626Deposit
        uint256 shares = IERC4626(VaultUSDC).convertToShares(DepositAmount);
        bytes memory erc4626DepositCallData = abi.encodeCall(IMorphoBundler.erc4626Deposit, (
            VaultUSDC,
            DepositAmount,
            (shares * 100) / 102,
            proxyAddress
        ));

        // morpho multicall
        bytes[] memory dataForMulticall = new bytes[](1);
        dataForMulticall[0] = erc4626DepositCallData;
        bytes memory multicallCallData = abi.encodeCall(IMorphoBundler.multicall, (dataForMulticall));

        // p2p signer signing
        bytes32 hashForP2pSigner = factory.getHashForP2pSigner(
        clientAddress,
            ClientBasisPoints,
            SigDeadline
        );
        bytes32 ethSignedMessageHashForP2pSigner = ECDSA.toEthSignedMessageHash(hashForP2pSigner);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(p2pSignerPrivateKey, ethSignedMessageHashForP2pSigner);
        bytes memory p2pSignerSignature = abi.encodePacked(r2, s2, v2);

        vm.startPrank(clientAddress);
        IERC20(USDC).approve(proxyAddress, type(uint256).max);
        factory.deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            USDC,
            DepositAmount,

            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );
        vm.stopPrank();

        uint256 sharesBalance = IERC20(VaultUSDC).balanceOf(proxyAddress);

        // morpho erc4626Redeem
        uint256 assets = IERC4626(VaultUSDC).convertToAssets(sharesBalance);
        bytes memory erc4626RedeemCallData = abi.encodeCall(IMorphoBundler.erc4626Redeem, (
            VaultUSDC,
            sharesBalance,
            (assets * 100) / 102,
            proxyAddress,
            proxyAddress
        ));

        // morpho multicall
        bytes[] memory dataForMulticallWithdrawal = new bytes[](1);
        dataForMulticallWithdrawal[0] = erc4626RedeemCallData;
        bytes memory multicallWithdrawalCallData = abi.encodeCall(IMorphoBundler.multicall, (dataForMulticallWithdrawal));

        vm.startPrank(clientAddress);
        P2pMorphoProxy(proxyAddress).withdraw(
            MorphoEthereumBundlerV2,
            multicallWithdrawalCallData,
            VaultUSDC,
            sharesBalance
        );
        vm.stopPrank();
    }
}
