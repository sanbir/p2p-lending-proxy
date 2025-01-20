// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../src/@openzeppelin/contracts/interfaces/IERC4626.sol";
import "../src/@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/access/P2pOperator.sol";
import "../src/adapters/morpho/p2pMorphoProxy/P2pMorphoProxy.sol";
import "../src/adapters/morpho/p2pMorphoProxyFactory/P2pMorphoProxyFactory.sol";
import "../src/common/IMorphoBundler.sol";
import "../src/common/P2pStructs.sol";
import "../src/p2pLendingProxyFactory/P2pLendingProxyFactory.sol";
import {PermitHash} from "../src/@permit2/libraries/PermitHash.sol";
import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/console2.sol";


contract MainnetIntegration is Test {
    using SafeERC20 for IERC20;

    address constant P2pTreasury = 0x6Bb8b45a1C6eA816B70d76f83f7dC4f0f87365Ff;
    P2pMorphoProxyFactory private factory;

    address private clientAddress;
    uint256 private clientPrivateKey;

    address private p2pSignerAddress;
    uint256 private p2pSignerPrivateKey;

    address private p2pOperatorAddress;
    address private nobody;

    address constant MorphoEthereumBundlerV2 = 0x4095F064B8d3c3548A3bebfd0Bbfd04750E30077;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant VaultUSDC = 0x8eB67A509616cd6A7c1B3c8C21D48FF57df3d458;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant VaultUSDT = 0xbEef047a543E45807105E51A8BBEFCc5950fcfBa;

    address asset;
    address vault;

    uint256 constant SigDeadline = 1734464723;
    uint96 constant ClientBasisPoints = 8700; // 13% fee
    uint256 constant DepositAmount = 10000000;

    address proxyAddress;

    uint48 nonce;

    function setUp() public {
        vm.createSelectFork("mainnet", 21308893);

        (clientAddress, clientPrivateKey) = makeAddrAndKey("client");
        (p2pSignerAddress, p2pSignerPrivateKey) = makeAddrAndKey("p2pSigner");
        p2pOperatorAddress = makeAddr("p2pOperator");
        nobody = makeAddr("nobody");

        vm.startPrank(p2pOperatorAddress);
        factory = new P2pMorphoProxyFactory(
            MorphoEthereumBundlerV2,
            p2pSignerAddress,
            P2pTreasury
        );
        vm.stopPrank();

        proxyAddress = factory.predictP2pLendingProxyAddress(clientAddress, ClientBasisPoints);

        _setRules();

        asset = USDC;
        vault = VaultUSDC;
    }

    function test_HappyPath_USDT_Mainnet() external {
        asset = USDT;
        vault = VaultUSDT;
        _happyPath_Mainnet();
    }

    function test_HappyPath_USDC_Mainnet() external {
        asset = USDC;
        vault = VaultUSDC;
        _happyPath_Mainnet();
    }

    function test_profitSplit_Mainnet() public {
        asset = USDC;
        vault = VaultUSDC;
        deal(asset, clientAddress, 100e6);

        uint256 clientAssetBalanceBefore = IERC20(asset).balanceOf(clientAddress);
        uint256 p2pAssetBalanceBefore = IERC20(asset).balanceOf(P2pTreasury);

        _doDeposit();

        uint256 shares = IERC20(vault).balanceOf(proxyAddress);
        uint256 assetsInMorphoBefore = IERC4626(vault).convertToAssets(shares);

        _forward(10000000);

        uint256 assetsInMorphoAfter = IERC4626(vault).convertToAssets(shares);
        uint256 profit = assetsInMorphoAfter - assetsInMorphoBefore;

        _doWithdraw(1);

        uint256 clientAssetBalanceAfter = IERC20(asset).balanceOf(clientAddress);
        uint256 p2pAssetBalanceAfter = IERC20(asset).balanceOf(P2pTreasury);
        uint256 clientBalanceChange = clientAssetBalanceAfter - clientAssetBalanceBefore;
        uint256 p2pBalanceChange = p2pAssetBalanceAfter - p2pAssetBalanceBefore;
        uint256 sumOfBalanceChanges = clientBalanceChange + p2pBalanceChange;

        assertApproxEqAbs(sumOfBalanceChanges, profit, 1);

        uint256 clientBasisPointsDeFacto = clientBalanceChange * 10_000 / sumOfBalanceChanges;
        uint256 p2pBasisPointsDeFacto = p2pBalanceChange * 10_000 / sumOfBalanceChanges;

        assertApproxEqAbs(ClientBasisPoints, clientBasisPointsDeFacto, 1);
        assertApproxEqAbs(10_000 - ClientBasisPoints, p2pBasisPointsDeFacto, 1);
    }

    function test_transferP2pSigner_Mainnet() public {
        vm.startPrank(nobody);
        vm.expectRevert(abi.encodeWithSelector(P2pOperator.P2pOperator__UnauthorizedAccount.selector, nobody));
        factory.transferP2pSigner(nobody);

        address oldSigner = factory.getP2pSigner();
        assertEq(oldSigner, p2pSignerAddress);

        vm.startPrank(p2pOperatorAddress);
        factory.transferP2pSigner(nobody);

        address newSigner = factory.getP2pSigner();
        assertEq(newSigner, nobody);
    }

    function test_setCalldataRules_Mainnet() public {
        vm.startPrank(nobody);
        vm.expectRevert(abi.encodeWithSelector(P2pOperator.P2pOperator__UnauthorizedAccount.selector, nobody));
        factory.setCalldataRules(P2pStructs.FunctionType.None, address(0), bytes4(0), new P2pStructs.Rule[](0));

        vm.startPrank(p2pOperatorAddress);
        vm.expectEmit();
        emit IP2pLendingProxyFactory.P2pLendingProxyFactory__CalldataRulesSet(
            P2pStructs.FunctionType.None,
            address(0),
            bytes4(0),
            new P2pStructs.Rule[](0)
        );
        factory.setCalldataRules(P2pStructs.FunctionType.None, address(0), bytes4(0), new P2pStructs.Rule[](0));
    }

    function test_removeCalldataRules_Mainnet() public {
        vm.startPrank(nobody);
        vm.expectRevert(abi.encodeWithSelector(P2pOperator.P2pOperator__UnauthorizedAccount.selector, nobody));
        factory.removeCalldataRules(P2pStructs.FunctionType.None, address(0), bytes4(0));

        vm.startPrank(p2pOperatorAddress);
        vm.expectEmit();
        emit IP2pLendingProxyFactory.P2pLendingProxyFactory__CalldataRulesRemoved(
            P2pStructs.FunctionType.None,
            address(0),
            bytes4(0)
        );
        factory.removeCalldataRules(P2pStructs.FunctionType.None, address(0), bytes4(0));
    }

    function test_clientBasisPointsGreaterThan10000_Mainnet() public {
        uint96 invalidBasisPoints = 10001;

        vm.startPrank(clientAddress);
        (bytes memory multicallCallData, IAllowanceTransfer.PermitSingle memory permitSingle) = 
            _getMulticallDataAndPermitSingleForP2pLendingProxy();
        bytes memory permit2Signature = _getPermit2SignatureForP2pLendingProxy(permitSingle);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            invalidBasisPoints,
            SigDeadline
        );

        vm.expectRevert(P2pMorphoProxyFactory__erc4626Deposit_receiver_ne_proxy.selector);
        factory.deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingle,
            permit2Signature,
            invalidBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );
    }

    function test_zeroAddressAsset_Mainnet() public {
        vm.startPrank(clientAddress);
        
        // Get the multicall data and permit details
        (bytes memory multicallCallData, IAllowanceTransfer.PermitSingle memory permitSingle) = 
            _getMulticallDataAndPermitSingleForP2pLendingProxy();
        
        // Set token to zero address
        permitSingle.details.token = address(0);
        
        bytes memory permit2Signature = _getPermit2SignatureForP2pLendingProxy(permitSingle);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        vm.expectRevert(P2pMorphoProxyFactory__approve2_token_ne_permitSingleForP2pLendingProxy_token.selector);
        factory.deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );
    }

    function test_zeroAssetAmount_Mainnet() public {
        vm.startPrank(clientAddress);
        
        // Get the multicall data and permit details
        (bytes memory multicallCallData, IAllowanceTransfer.PermitSingle memory permitSingle) = 
            _getMulticallDataAndPermitSingleForP2pLendingProxy();
        
        // Set amount to zero
        permitSingle.details.amount = 0;
        
        bytes memory permit2Signature = _getPermit2SignatureForP2pLendingProxy(permitSingle);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        vm.expectRevert(P2pMorphoProxyFactory__approve2_amount_ne_permitSingleForP2pLendingProxy_amount.selector);
        factory.deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );
    }

    function test_depositDirectlyOnProxy_Mainnet() public {
        vm.startPrank(clientAddress);
        
        // Add this line to give initial tokens to the client
        deal(asset, clientAddress, DepositAmount);
        
        // Add this line to approve tokens for Permit2
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        
        // Get the multicall data and permit details
        (bytes memory multicallCallData, IAllowanceTransfer.PermitSingle memory permitSingle) = 
            _getMulticallDataAndPermitSingleForP2pLendingProxy();
        
        bytes memory permit2Signature = _getPermit2SignatureForP2pLendingProxy(permitSingle);

        // Create proxy first via factory
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        factory.deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );

        // Now try to call deposit directly on the proxy
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pLendingProxy__NotFactoryCalled.selector,
                clientAddress,
                address(factory)
            )
        );
        P2pMorphoProxy(proxyAddress).deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingle,
            permit2Signature
        );
    }

    function test_initializeDirectlyOnProxy_Mainnet() public {
        // Create the proxy first since we need a valid proxy address to test with
        proxyAddress = factory.predictP2pLendingProxyAddress(clientAddress, ClientBasisPoints);
        P2pMorphoProxy proxy = P2pMorphoProxy(proxyAddress);
        
        vm.startPrank(clientAddress);
        
        // Add this line to give initial tokens to the client
        deal(asset, clientAddress, DepositAmount);
        
        // Add this line to approve tokens for Permit2
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        
        (bytes memory multicallCallData, IAllowanceTransfer.PermitSingle memory permitSingle) = 
            _getMulticallDataAndPermitSingleForP2pLendingProxy();
        bytes memory permit2Signature = _getPermit2SignatureForP2pLendingProxy(permitSingle);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        // This will create the proxy
        factory.deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );

        // Now try to initialize it directly
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pLendingProxy__NotFactoryCalled.selector,
                clientAddress,
                address(factory)
            )
        );
        proxy.initialize(
            clientAddress,
            ClientBasisPoints
        );
        vm.stopPrank();
    }

    function test_withdrawOnProxyOnlyCallableByClient_Mainnet() public {
        // Create proxy and do initial deposit
        deal(asset, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        
        (bytes memory multicallCallData, IAllowanceTransfer.PermitSingle memory permitSingle) = 
            _getMulticallDataAndPermitSingleForP2pLendingProxy();
        bytes memory permit2Signature = _getPermit2SignatureForP2pLendingProxy(permitSingle);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        factory.deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );
        vm.stopPrank();

        // Try to withdraw as non-client
        vm.startPrank(nobody);
        P2pMorphoProxy proxy = P2pMorphoProxy(proxyAddress);
        
        // Get withdrawal calldata
        uint256 sharesBalance = IERC20(vault).balanceOf(proxyAddress);
        bytes memory withdrawalCallData = _getMulticallWithdrawalCallData(sharesBalance);
        
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pLendingProxy__NotClientCalled.selector,
                nobody,        // _msgSender (the nobody address trying to call)
                clientAddress  // _actualClient (the actual client address)
            )
        );
        
        proxy.withdraw(
            MorphoEthereumBundlerV2,
            withdrawalCallData,
            vault,
            sharesBalance
        );
        vm.stopPrank();
    }

    function test_incorrectWithdrawalCalldata_Mainnet() public {
        // Create proxy and do initial deposit
        deal(asset, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        
        // Do initial deposit
        _doDeposit();

        // Try to withdraw with incorrect calldata
        P2pMorphoProxy proxy = P2pMorphoProxy(proxyAddress);
        uint256 sharesBalance = IERC20(vault).balanceOf(proxyAddress);
        
        // Create incorrect withdrawal calldata (empty bytes)
        bytes memory incorrectWithdrawalCalldata = "";
        
        vm.startPrank(clientAddress);

        vm.expectRevert();
        proxy.withdraw(
            MorphoEthereumBundlerV2,
            incorrectWithdrawalCalldata,
            vault,
            sharesBalance
        );
        vm.stopPrank();
    }

    function test_withdrawViaCallAnyFunction_Mainnet() public {
        // Create proxy and do initial deposit
        deal(asset, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        
        // Do initial deposit
        _doDeposit();

        // Try to withdraw using callAnyFunction
        P2pMorphoProxy proxy = P2pMorphoProxy(proxyAddress);
        uint256 sharesBalance = IERC20(vault).balanceOf(proxyAddress);
        bytes memory withdrawalCallData = _getMulticallWithdrawalCallData(sharesBalance);
        
        vm.startPrank(clientAddress);
        
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pLendingProxyFactory__NoRulesDefined.selector,
                P2pStructs.FunctionType.None,
                MorphoEthereumBundlerV2,
                IMorphoBundler.multicall.selector
            )
        );
        
        proxy.callAnyFunction(
            MorphoEthereumBundlerV2,
            withdrawalCallData
        );
        vm.stopPrank();
    }

    function test_calldataTooShortForStartsWithRule_Mainnet() public {
        // Create proxy and do initial deposit
        deal(asset, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        
        // Do initial deposit
        _doDeposit();
        vm.stopPrank();

        // Set rule that requires first 32 bytes to match
        P2pStructs.Rule[] memory rules = new P2pStructs.Rule[](1);
        rules[0] = P2pStructs.Rule({
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 0,
            allowedBytes: new bytes(32)
        });

        vm.startPrank(p2pOperatorAddress);
        factory.setCalldataRules(
            P2pStructs.FunctionType.None,
            vault,
            IERC20.balanceOf.selector,
            rules
        );
        vm.stopPrank();

        // Create calldata that's too short (only 4 bytes)
        bytes memory shortCalldata = abi.encodeWithSelector(IERC20.balanceOf.selector);

        vm.startPrank(clientAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pLendingProxyFactory__CalldataTooShortForStartsWithRule.selector,
                0, // calldata length after selector
                0, // rule index
                32 // required bytes count
            )
        );
        P2pMorphoProxy(proxyAddress).callAnyFunction(
            vault,
            shortCalldata
        );
        vm.stopPrank();
    }

    function test_calldataStartsWithRuleViolated_Mainnet() public {
        // Create proxy and do initial deposit
        deal(asset, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        
        // Do initial deposit
        _doDeposit();
        vm.stopPrank();

        // Set rule that requires first 32 bytes to match specific value
        bytes memory expectedBytes = new bytes(32);
        for(uint i = 0; i < 32; i++) {
            expectedBytes[i] = bytes1(uint8(i));
        }

        P2pStructs.Rule[] memory rules = new P2pStructs.Rule[](1);
        rules[0] = P2pStructs.Rule({
            ruleType: P2pStructs.RuleType.StartsWith,
            index: 0,
            allowedBytes: expectedBytes
        });

        vm.startPrank(p2pOperatorAddress);
        factory.setCalldataRules(
            P2pStructs.FunctionType.None,
            vault,
            IERC20.balanceOf.selector,
            rules
        );
        vm.stopPrank();

        // Create calldata with different first 32 bytes
        bytes memory differentBytes = new bytes(32);
        bytes memory wrongCalldata = abi.encodePacked(
            IERC20.balanceOf.selector,
            differentBytes
        );

        vm.startPrank(clientAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pLendingProxyFactory__CalldataStartsWithRuleViolated.selector,
                differentBytes,
                expectedBytes
            )
        );
        P2pMorphoProxy(proxyAddress).callAnyFunction(
            vault,
            wrongCalldata
        );
        vm.stopPrank();
    }

    function test_calldataTooShortForEndsWithRule_Mainnet() public {
        // Create proxy and do initial deposit
        deal(asset, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        
        // Do initial deposit
        _doDeposit();
        vm.stopPrank();

        // Set rule that requires last 32 bytes to match
        P2pStructs.Rule[] memory rules = new P2pStructs.Rule[](1);
        rules[0] = P2pStructs.Rule({
            ruleType: P2pStructs.RuleType.EndsWith,
            index: 0,
            allowedBytes: new bytes(32)
        });

        vm.startPrank(p2pOperatorAddress);
        factory.setCalldataRules(
            P2pStructs.FunctionType.None,
            vault,
            IERC20.balanceOf.selector,
            rules
        );
        vm.stopPrank();

        // Create calldata that's too short (only selector)
        bytes memory shortCalldata = abi.encodeWithSelector(IERC20.balanceOf.selector);

        vm.startPrank(clientAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pLendingProxyFactory__CalldataTooShortForEndsWithRule.selector,
                0, // calldata length after selector
                32 // required bytes count
            )
        );
        P2pMorphoProxy(proxyAddress).callAnyFunction(
            vault,
            shortCalldata
        );
        vm.stopPrank();
    }

    function test_calldataEndsWithRuleViolated_Mainnet() public {
        // Create proxy and do initial deposit
        deal(asset, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        
        // Do initial deposit
        _doDeposit();
        vm.stopPrank();

        // Set rule that requires last 32 bytes to match specific value
        bytes memory expectedEndBytes = new bytes(32);
        for(uint i = 0; i < 32; i++) {
            expectedEndBytes[i] = bytes1(uint8(i));
        }

        P2pStructs.Rule[] memory rules = new P2pStructs.Rule[](1);
        rules[0] = P2pStructs.Rule({
            ruleType: P2pStructs.RuleType.EndsWith,
            index: 0,
            allowedBytes: expectedEndBytes
        });

        vm.startPrank(p2pOperatorAddress);
        factory.setCalldataRules(
            P2pStructs.FunctionType.None,
            vault,
            IERC20.balanceOf.selector,
            rules
        );
        vm.stopPrank();

        // Create calldata with different ending bytes
        bytes memory wrongEndBytes = new bytes(32);
        for(uint i = 0; i < 32; i++) {
            wrongEndBytes[i] = bytes1(uint8(100 + i));
        }
        bytes memory wrongCalldata = abi.encodePacked(
            IERC20.balanceOf.selector,
            wrongEndBytes
        );

        vm.startPrank(clientAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pLendingProxyFactory__CalldataEndsWithRuleViolated.selector,
                wrongEndBytes,
                expectedEndBytes
            )
        );
        P2pMorphoProxy(proxyAddress).callAnyFunction(
            vault,
            wrongCalldata
        );
        vm.stopPrank();
    }

    function test_callBalanceOfViaCallAnyFunction_Mainnet() public {
        // Create proxy and do initial deposit
        deal(asset, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        
        // Do initial deposit
        _doDeposit();
        vm.stopPrank();

        bytes memory balanceOfCalldata = abi.encodeWithSelector(
            IERC20.balanceOf.selector,
            proxyAddress
        );

        vm.startPrank(clientAddress);

        vm.expectRevert(
            abi.encodeWithSelector(
                P2pLendingProxyFactory__NoRulesDefined.selector,
                P2pStructs.FunctionType.None,
                vault,
                IERC20.balanceOf.selector
            )
        );
        P2pMorphoProxy(proxyAddress).callAnyFunction(
            vault,
            balanceOfCalldata
        );
        vm.stopPrank();

        P2pStructs.Rule[] memory rules = new P2pStructs.Rule[](1);
        rules[0] = P2pStructs.Rule({
            ruleType: P2pStructs.RuleType.AnyCalldata,
            index: 0,
            allowedBytes: ""
        });

        vm.startPrank(p2pOperatorAddress);
        factory.setCalldataRules(
            P2pStructs.FunctionType.None, // This is correct
            vault,
            IERC20.balanceOf.selector,
            rules
        );
        vm.stopPrank();

        // Call balanceOf via callAnyFunction
        vm.startPrank(clientAddress);
        P2pMorphoProxy proxy = P2pMorphoProxy(proxyAddress);
        proxy.callAnyFunction(
            vault,
            balanceOfCalldata
        );
        vm.stopPrank();
    }

    function test_getP2pLendingProxyFactory__NoRulesDefined_Mainnet() public {
        // Create proxy first via factory
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        // Get the multicall data and permit details
        (bytes memory multicallCallData, IAllowanceTransfer.PermitSingle memory permitSingle) = 
            _getMulticallDataAndPermitSingleForP2pLendingProxy();
        
        bytes memory permit2Signature = _getPermit2SignatureForP2pLendingProxy(permitSingle);

        // Add this line to give tokens to the client before attempting deposit
        deal(asset, clientAddress, DepositAmount);
        
        vm.startPrank(clientAddress);
        
        // Add this line to approve tokens for Permit2
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);

        factory.deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );

        // Try to call a function with no rules defined
        bytes memory someCalldata = abi.encodeWithSelector(
            IERC20.transfer.selector,
            address(0),
            0
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                P2pLendingProxyFactory__NoRulesDefined.selector,
                P2pStructs.FunctionType.None,
                asset,
                IERC20.transfer.selector
            )
        );

        P2pMorphoProxy(proxyAddress).callAnyFunction(
            asset,
            someCalldata
        );

        vm.stopPrank();
    }

    function test_getP2pLendingProxyFactory__ZeroP2pSignerAddress_Mainnet() public {
        vm.startPrank(p2pOperatorAddress);
        vm.expectRevert(P2pLendingProxyFactory__ZeroP2pSignerAddress.selector);
        factory.transferP2pSigner(address(0));
        vm.stopPrank();
    }

    function test_getHashForP2pSigner_Mainnet() public view {
        bytes32 expectedHash = keccak256(abi.encode(
            clientAddress,
            ClientBasisPoints,
            SigDeadline,
            address(factory),
            block.chainid
        ));

        bytes32 actualHash = factory.getHashForP2pSigner(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        assertEq(actualHash, expectedHash);
    }

    function test_getPermit2HashTypedData_Mainnet() public view {
        // Create a permit single struct
        IAllowanceTransfer.PermitSingle memory permitSingle = IAllowanceTransfer.PermitSingle({
            details: IAllowanceTransfer.PermitDetails({
                token: asset,
                amount: uint160(DepositAmount),
                expiration: uint48(SigDeadline),
                nonce: 0
            }),
            spender: proxyAddress,
            sigDeadline: SigDeadline
        });

        // Get the permit hash
        bytes32 permitHash = factory.getPermitHash(permitSingle);

        // Get the typed data hash
        bytes32 actualTypedDataHash = factory.getPermit2HashTypedData(permitHash);

        // Calculate expected hash
        bytes32 expectedTypedDataHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                Permit2Lib.PERMIT2.DOMAIN_SEPARATOR(),
                permitHash
            )
        );

        assertEq(actualTypedDataHash, expectedTypedDataHash);

        // Test the overloaded function that takes PermitSingle directly
        bytes32 actualTypedDataHashFromPermitSingle = factory.getPermit2HashTypedData(permitSingle);
        assertEq(actualTypedDataHashFromPermitSingle, expectedTypedDataHash);
    }

    function test_supportsInterface_Mainnet() public view {
        // Test IP2pLendingProxyFactory interface support
        bool supportsP2pLendingProxyFactory = factory.supportsInterface(type(IP2pLendingProxyFactory).interfaceId);
        assertTrue(supportsP2pLendingProxyFactory);

        // Test IERC165 interface support 
        bool supportsERC165 = factory.supportsInterface(type(IERC165).interfaceId);
        assertTrue(supportsERC165);

        // Test non-supported interface
        bytes4 nonSupportedInterfaceId = bytes4(keccak256("nonSupportedInterface()"));
        bool supportsNonSupported = factory.supportsInterface(nonSupportedInterfaceId);
        assertFalse(supportsNonSupported);
    }

    function test_p2pSignerSignatureExpired_Mainnet() public {
        // Add this line to give tokens to the client before attempting deposit
        deal(asset, clientAddress, DepositAmount);
        
        vm.startPrank(clientAddress);
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);

        // Get the multicall data and permit details
        (bytes memory multicallCallData, IAllowanceTransfer.PermitSingle memory permitSingle) = 
            _getMulticallDataAndPermitSingleForP2pLendingProxy();
        
        bytes memory permit2Signature = _getPermit2SignatureForP2pLendingProxy(permitSingle);

        // Get p2p signer signature with expired deadline
        uint256 expiredDeadline = block.timestamp - 1;
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            expiredDeadline
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                P2pLendingProxyFactory__P2pSignerSignatureExpired.selector,
                expiredDeadline
            )
        );

        factory.deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            expiredDeadline,
            p2pSignerSignature
        );
        vm.stopPrank();
    }

    function test_invalidP2pSignerSignature_Mainnet() public {
        // Add this line to give tokens to the client before attempting deposit
        deal(asset, clientAddress, DepositAmount);
        
        vm.startPrank(clientAddress);
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);

        // Get the multicall data and permit details
        (bytes memory multicallCallData, IAllowanceTransfer.PermitSingle memory permitSingle) = 
            _getMulticallDataAndPermitSingleForP2pLendingProxy();
        
        bytes memory permit2Signature = _getPermit2SignatureForP2pLendingProxy(permitSingle);

        // Create an invalid signature by using a different private key
        uint256 wrongPrivateKey = 0x12345; // Some random private key
        bytes32 messageHash = ECDSA.toEthSignedMessageHash(
            factory.getHashForP2pSigner(
                clientAddress,
                ClientBasisPoints,
                SigDeadline
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, messageHash);
        bytes memory invalidSignature = abi.encodePacked(r, s, v);

        vm.expectRevert(P2pLendingProxyFactory__InvalidP2pSignerSignature.selector);

        factory.deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            SigDeadline,
            invalidSignature
        );
        vm.stopPrank();
    }

    function test_viewFunctions_Mainnet() public {
        // Add this line to give tokens to the client before attempting deposit
        deal(asset, clientAddress, DepositAmount);
        
        vm.startPrank(clientAddress);
        
        // Add this line to approve tokens for Permit2
        IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        
        // Create proxy first via factory
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        // Get the multicall data and permit details
        (bytes memory multicallCallData, IAllowanceTransfer.PermitSingle memory permitSingle) = 
            _getMulticallDataAndPermitSingleForP2pLendingProxy();
        
        bytes memory permit2Signature = _getPermit2SignatureForP2pLendingProxy(permitSingle);

        factory.deposit(
            MorphoEthereumBundlerV2,
            multicallCallData,
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );

        P2pMorphoProxy proxy = P2pMorphoProxy(proxyAddress);
        assertEq(proxy.getFactory(), address(factory));
        assertEq(proxy.getP2pTreasury(), P2pTreasury);
        assertEq(proxy.getClient(), clientAddress);
        assertEq(proxy.getClientBasisPoints(), ClientBasisPoints);
        assertEq(proxy.getTotalDeposited(asset), DepositAmount);
        assertEq(factory.getP2pSigner(), p2pSignerAddress);
        assertEq(factory.predictP2pLendingProxyAddress(clientAddress, ClientBasisPoints), proxyAddress);
    }

    function test_acceptP2pOperator_Mainnet() public {
        // Initial state check
        assertEq(factory.getP2pOperator(), p2pOperatorAddress);

        // Only operator can initiate transfer
        vm.startPrank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pOperator.P2pOperator__UnauthorizedAccount.selector,
                nobody
            )
        );
        factory.transferP2pOperator(nobody);
        vm.stopPrank();

        // Operator initiates transfer
        address newOperator = makeAddr("newOperator");
        vm.startPrank(p2pOperatorAddress);
        factory.transferP2pOperator(newOperator);
        
        // Check pending operator is set
        assertEq(factory.getPendingP2pOperator(), newOperator);
        // Check current operator hasn't changed yet
        assertEq(factory.getP2pOperator(), p2pOperatorAddress);
        vm.stopPrank();

        // Wrong address cannot accept transfer
        vm.startPrank(nobody);
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pOperator.P2pOperator__UnauthorizedAccount.selector,
                nobody
            )
        );
        factory.acceptP2pOperator();
        vm.stopPrank();

        // New operator accepts transfer
        vm.startPrank(newOperator);
        factory.acceptP2pOperator();
        
        // Check operator was updated
        assertEq(factory.getP2pOperator(), newOperator);
        // Check pending operator was cleared
        assertEq(factory.getPendingP2pOperator(), address(0));
        vm.stopPrank();

        // Old operator can no longer call operator functions
        vm.startPrank(p2pOperatorAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pOperator.P2pOperator__UnauthorizedAccount.selector,
                p2pOperatorAddress
            )
        );
        factory.transferP2pOperator(p2pOperatorAddress);
        vm.stopPrank();
    }

    function _happyPath_Mainnet() private {
        deal(asset, clientAddress, 10000e18);

        uint256 assetBalanceBefore = IERC20(asset).balanceOf(clientAddress);
        uint256 sharesBalanceBefore = IERC20(vault).balanceOf(proxyAddress);
        assertEq(sharesBalanceBefore, 0);

        _doDeposit();

        uint256 assetBalanceAfter1 = IERC20(asset).balanceOf(clientAddress);
        uint256 sharesBalanceAfter1 = IERC20(vault).balanceOf(proxyAddress);
        assertNotEq(sharesBalanceAfter1, 0);
        assertEq(assetBalanceBefore - assetBalanceAfter1, DepositAmount);

        _doDeposit();

        uint256 assetBalanceAfter2 = IERC20(asset).balanceOf(clientAddress);
        uint256 sharesBalanceAfter2 = IERC20(vault).balanceOf(proxyAddress);

        assertEq(assetBalanceAfter1 - assetBalanceAfter2, DepositAmount);
        assertEq(sharesBalanceAfter2 - sharesBalanceAfter1, sharesBalanceAfter1);

        _doDeposit();
        _doDeposit();

        uint256 assetBalanceAfterAllDeposits = IERC20(asset).balanceOf(clientAddress);

        _doWithdraw(10);

        uint256 assetBalanceAfterWithdraw1 = IERC20(asset).balanceOf(clientAddress);

        assertApproxEqAbs(assetBalanceAfterWithdraw1 - assetBalanceAfterAllDeposits, DepositAmount * 4 / 10, 1);

        _doWithdraw(5);
        _doWithdraw(3);
        _doWithdraw(2);
        _doWithdraw(1);

        uint256 assetBalanceAfterAllWithdrawals = IERC20(asset).balanceOf(clientAddress);
        uint256 sharesBalanceAfterAfterAllWithdrawals = IERC20(vault).balanceOf(proxyAddress);

        assertApproxEqAbs(assetBalanceAfterAllWithdrawals, assetBalanceBefore, 1);
        assertEq(sharesBalanceAfterAfterAllWithdrawals, 0);
    }

    function _setRules() private {
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
    }

    function _getMulticallDataAndPermitSingleForP2pLendingProxy() private returns(bytes memory, IAllowanceTransfer.PermitSingle memory) {
        // morpho approve2
        IAllowanceTransfer.PermitDetails memory permitDetails = IAllowanceTransfer.PermitDetails({
            token: asset,
            amount: uint160(DepositAmount),
            expiration: uint48(SigDeadline),
            nonce: nonce
        });
        nonce++;
        IAllowanceTransfer.PermitSingle memory permitSingle = IAllowanceTransfer.PermitSingle({
            details: permitDetails,
            spender: MorphoEthereumBundlerV2,
            sigDeadline: SigDeadline
        });
        bytes32 permitSingleHash = factory.getPermit2HashTypedData(PermitHash.hash(permitSingle));
        (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(clientPrivateKey, permitSingleHash);
        bytes memory signatureForApprove2 = abi.encodePacked(r0, s0, v0);
        bytes memory approve2CallData = abi.encodeCall(IMorphoBundler.approve2, (
            permitSingle,
            signatureForApprove2,
            true
        ));

        // morpho transferFrom2
        bytes memory transferFrom2CallData = abi.encodeCall(IMorphoBundler.transferFrom2, (
            asset,
            DepositAmount
        ));

        // morpho erc4626Deposit
        uint256 shares = IERC4626(vault).convertToShares(DepositAmount);
        bytes memory erc4626Deposit2CallData = abi.encodeCall(IMorphoBundler.erc4626Deposit, (
            vault,
            DepositAmount,
            (shares * 100) / 102,
            proxyAddress
        ));

        // morpho multicall
        bytes[] memory dataForMulticall = new bytes[](3);
        dataForMulticall[0] = approve2CallData;
        dataForMulticall[1] = transferFrom2CallData;
        dataForMulticall[2] = erc4626Deposit2CallData;
        bytes memory multicallCallData = abi.encodeCall(IMorphoBundler.multicall, (dataForMulticall));

        // data for factory
        IAllowanceTransfer.PermitSingle memory permitSingleForP2pLendingProxy = IAllowanceTransfer.PermitSingle({
            details: permitDetails,
            spender: proxyAddress,
            sigDeadline: SigDeadline
        });

        return (multicallCallData, permitSingleForP2pLendingProxy);
    }

    function _getPermit2SignatureForP2pLendingProxy(IAllowanceTransfer.PermitSingle memory permitSingleForP2pLendingProxy) private view returns(bytes memory) {
        bytes32 permitSingleForP2pLendingProxyHash = factory.getPermit2HashTypedData(PermitHash.hash(permitSingleForP2pLendingProxy));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(clientPrivateKey, permitSingleForP2pLendingProxyHash);
        bytes memory permit2SignatureForP2pLendingProxy = abi.encodePacked(r1, s1, v1);
        return permit2SignatureForP2pLendingProxy;
    }

    function _getP2pSignerSignature(
        address _clientAddress,
        uint96 _clientBasisPoints,
        uint256 _sigDeadline
    ) private view returns(bytes memory) {
        // p2p signer signing
        bytes32 hashForP2pSigner = factory.getHashForP2pSigner(
            _clientAddress,
            _clientBasisPoints,
            _sigDeadline
        );
        bytes32 ethSignedMessageHashForP2pSigner = ECDSA.toEthSignedMessageHash(hashForP2pSigner);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(p2pSignerPrivateKey, ethSignedMessageHashForP2pSigner);
        bytes memory p2pSignerSignature = abi.encodePacked(r2, s2, v2);
        return p2pSignerSignature;
    }

    function _doDeposit() private {
        (
            bytes memory multicallCallData,
            IAllowanceTransfer.PermitSingle memory permitSingleForP2pLendingProxy
        ) = _getMulticallDataAndPermitSingleForP2pLendingProxy();
        bytes memory permit2SignatureForP2pLendingProxy = _getPermit2SignatureForP2pLendingProxy(permitSingleForP2pLendingProxy);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        vm.startPrank(clientAddress);
        if (IERC20(asset).allowance(clientAddress, address(Permit2Lib.PERMIT2)) == 0) {
            IERC20(asset).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        }
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
    }

    function _getMulticallWithdrawalCallData(uint256 sharesToWithdraw) private view returns(bytes memory) {
        // morpho erc4626Redeem
        uint256 assets = IERC4626(vault).convertToAssets(sharesToWithdraw);
        bytes memory erc4626RedeemCallData = abi.encodeCall(IMorphoBundler.erc4626Redeem, (
            vault,
            sharesToWithdraw,
            (assets * 100) / 102,
            proxyAddress,
            proxyAddress
        ));

        // morpho multicall
        bytes[] memory dataForMulticallWithdrawal = new bytes[](1);
        dataForMulticallWithdrawal[0] = erc4626RedeemCallData;
        bytes memory multicallWithdrawalCallData = abi.encodeCall(IMorphoBundler.multicall, (dataForMulticallWithdrawal));

        return multicallWithdrawalCallData;
    }

    function _doWithdraw(uint256 denominator) private {
        uint256 sharesBalance = IERC20(vault).balanceOf(proxyAddress);
        uint256 sharesToWithdraw = sharesBalance / denominator;
        bytes memory multicallWithdrawalCallData = _getMulticallWithdrawalCallData(sharesToWithdraw);

        vm.startPrank(clientAddress);
        P2pMorphoProxy(proxyAddress).withdraw(
            MorphoEthereumBundlerV2,
            multicallWithdrawalCallData,
            vault,
            sharesToWithdraw
        );
        vm.stopPrank();
    }

    /// @dev Rolls & warps the given number of blocks forward the blockchain.
    function _forward(uint256 blocks) internal {
        vm.roll(block.number + blocks);
        vm.warp(block.timestamp + blocks);
    }
}