// SPDX-FileCopyrightText: 2024 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../src/@openzeppelin/contracts/interfaces/IERC4626.sol";
import "../src/mocks/IMorphoEthereumBundlerV2.sol";
import "../src/p2pLendingProxyFactory/P2pLendingProxyFactory.sol";
import "../src/common/P2pStructs.sol";
import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/console2.sol";
import {PermitHash} from "../src/@permit2/libraries/PermitHash.sol";


contract MainnetIntegration is Test {
    address constant P2pTreasury = 0x6Bb8b45a1C6eA816B70d76f83f7dC4f0f87365Ff;
    P2pLendingProxyFactory private factory;

    address private clientAddress;
    uint256 private clientPrivateKey;

    address private p2pSignerAddress;
    uint256 private p2pSignerPrivateKey;

    address private p2pOperatorAddress;
    address private nobody;

    address constant MorphoEthereumBundlerV2 = 0x4095F064B8d3c3548A3bebfd0Bbfd04750E30077;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant VaultUSDC = 0x8eB67A509616cd6A7c1B3c8C21D48FF57df3d458;
    // address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    uint256 constant SigDeadline = 1734464723;
    uint96 constant ClientBasisPoints = 8700; // 13% fee
    uint256 constant DepositAmount = 10000000;

    address proxyAddress;

    function setUp() public {
        vm.createSelectFork("mainnet", 21308893);

        (clientAddress, clientPrivateKey) = makeAddrAndKey("client");
        (p2pSignerAddress, p2pSignerPrivateKey) = makeAddrAndKey("p2pSigner");
        p2pOperatorAddress = makeAddr("p2pOperator");
        nobody = makeAddr("nobody");

        deal(USDC, clientAddress, 10000e18);

        vm.startPrank(p2pOperatorAddress);
        factory = new P2pLendingProxyFactory(p2pSignerAddress, P2pTreasury);
        vm.stopPrank();

        proxyAddress = factory.predictP2pLendingProxyAddress(clientAddress, ClientBasisPoints);
    }

    function test_HappyPath_Mainnet() external {
        // allowed calldata for factory
        bytes4 multicallSelector = IMorphoEthereumBundlerV2.multicall.selector;
        bytes memory allowedBytes = "";
        P2pStructs.Rule memory rule = P2pStructs.Rule({
            ruleType: P2pStructs.RuleType.AnyCalldata,
            index: 0,
            allowedBytes: allowedBytes
        });
        P2pStructs.Rule[] memory rules = new P2pStructs.Rule[](1);
        rules[0] = rule;

        vm.startPrank(p2pOperatorAddress);
        factory.setCalldataRules(
            P2pStructs.FunctionType.Deposit,
            MorphoEthereumBundlerV2,
            multicallSelector,
            rules
        );
        factory.setCalldataRules(
            P2pStructs.FunctionType.Withdrawal,
            MorphoEthereumBundlerV2,
            multicallSelector,
            rules
        );
        vm.stopPrank();

        // morpho approve2
        IAllowanceTransfer.PermitDetails memory permitDetails = IAllowanceTransfer.PermitDetails({
            token: USDC,
            amount: uint160(DepositAmount),
            expiration: type(uint48).max,
            nonce: 0
        });
        IAllowanceTransfer.PermitSingle memory permitSingle = IAllowanceTransfer.PermitSingle({
            details: permitDetails,
            spender: MorphoEthereumBundlerV2,
            sigDeadline: SigDeadline
        });
        bytes32 permitSingleHash = factory.getPermit2HashTypedData(permitSingle);
        (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(clientPrivateKey, permitSingleHash);
        bytes memory signatureForApprove2 = abi.encodePacked(r0, s0, v0);
        bytes memory approve2CallData = abi.encodeCall(IMorphoEthereumBundlerV2.approve2, (
            permitSingle,
            signatureForApprove2,
            true
        ));

        // morpho transferFrom2
        bytes memory transferFrom2CallData = abi.encodeCall(IMorphoEthereumBundlerV2.transferFrom2, (
            USDC,
            DepositAmount
        ));

        // morpho erc4626Deposit
        uint256 shares = IERC4626(VaultUSDC).convertToShares(DepositAmount);
        bytes memory erc4626Deposit2CallData = abi.encodeCall(IMorphoEthereumBundlerV2.erc4626Deposit, (
            VaultUSDC,
            DepositAmount,
            (shares * 100) / 102,
            proxyAddress
        ));

        // morpho multicall
        bytes[] memory dataForMulticall = new bytes[](3);
        dataForMulticall[0] = approve2CallData;
        dataForMulticall[1] = transferFrom2CallData;
        dataForMulticall[2] = erc4626Deposit2CallData;
        bytes memory multicallCallData = abi.encodeCall(IMorphoEthereumBundlerV2.multicall, (dataForMulticall));

        // data for factory
        IAllowanceTransfer.PermitSingle memory permitSingleForP2pLendingProxy = IAllowanceTransfer.PermitSingle({
            details: permitDetails,
            spender: proxyAddress,
            sigDeadline: SigDeadline
        });
        bytes32 permitSingleForP2pLendingProxyHash = factory.getPermit2HashTypedData(permitSingleForP2pLendingProxy);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(clientPrivateKey, permitSingleForP2pLendingProxyHash);
        bytes memory permit2SignatureForP2pLendingProxy = abi.encodePacked(r1, s1, v1);

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
        IERC20(USDC).approve(address(Permit2Lib.PERMIT2), type(uint256).max);
        factory.deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingleForP2pLendingProxy,
            permit2SignatureForP2pLendingProxy,

            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );
        vm.stopPrank();

        uint256 sharesBalance = IERC20(VaultUSDC).balanceOf(proxyAddress);

        // morpho erc4626Redeem
        uint256 assets = IERC4626(VaultUSDC).convertToAssets(sharesBalance);
        bytes memory erc4626RedeemCallData = abi.encodeCall(IMorphoEthereumBundlerV2.erc4626Redeem, (
            VaultUSDC,
            sharesBalance,
            (assets * 100) / 102,
            proxyAddress,
            proxyAddress
        ));

        // morpho multicall
        bytes[] memory dataForMulticallWithdrawal = new bytes[](1);
        dataForMulticallWithdrawal[0] = erc4626RedeemCallData;
        bytes memory multicallWithdrawalCallData = abi.encodeCall(IMorphoEthereumBundlerV2.multicall, (dataForMulticallWithdrawal));

        vm.startPrank(clientAddress);
        P2pLendingProxy(proxyAddress).withdraw(
            MorphoEthereumBundlerV2,
            multicallWithdrawalCallData,
            VaultUSDC,
            sharesBalance
        );
        vm.stopPrank();
    }
}