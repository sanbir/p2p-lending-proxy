// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../src/@openzeppelin/contracts/interfaces/IERC4626.sol";
import "../src/@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/access/P2pOperator.sol";
import "../src/adapters/ethena/p2pEthenaProxyFactory/P2pEthenaProxyFactory.sol";
import "../src/common/P2pStructs.sol";
import "../src/p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/console2.sol";
import {PermitHash} from "../src/@permit2/libraries/PermitHash.sol";


contract MainnetIntegration is Test {
    using SafeERC20 for IERC20;

    address constant USDe = 0x4c9EDD5852cd905f086C759E8383e09bff1E68B3;
    address constant sUSDe = 0x9D39A5DE30e57443BfF2A8307A4256c8797A3497;
    address constant P2pTreasury = 0xfeef177E6168F9b7fd59e6C5b6c2d87FF398c6FD;

    P2pEthenaProxyFactory private factory;

    address private clientAddress;
    uint256 private clientPrivateKey;

    address private p2pSignerAddress;
    uint256 private p2pSignerPrivateKey;

    address private p2pOperatorAddress;
    address private nobody;

    uint256 constant SigDeadline = 1734464723;
    uint96 constant ClientBasisPoints = 8700; // 13% fee
    uint256 constant DepositAmount = 10 ether;

    address proxyAddress;

    uint48 nonce;

    function setUp() public {
        vm.createSelectFork("mainnet", 21308893);

        (clientAddress, clientPrivateKey) = makeAddrAndKey("client");
        (p2pSignerAddress, p2pSignerPrivateKey) = makeAddrAndKey("p2pSigner");
        p2pOperatorAddress = makeAddr("p2pOperator");
        nobody = makeAddr("nobody");

        vm.startPrank(p2pOperatorAddress);
        factory = new P2pEthenaProxyFactory(
            p2pSignerAddress,
            P2pTreasury,
            sUSDe,
            USDe
        );
        vm.stopPrank();

        proxyAddress = factory.predictP2pYieldProxyAddress(clientAddress, ClientBasisPoints);
    }

    function test_happyPath_Mainnet() public {
        deal(USDe, clientAddress, 10000e18);

        uint256 assetBalanceBefore = IERC20(USDe).balanceOf(clientAddress);

        _doDeposit();

        uint256 assetBalanceAfter1 = IERC20(USDe).balanceOf(clientAddress);
        assertEq(assetBalanceBefore - assetBalanceAfter1, DepositAmount);

        _doDeposit();

        uint256 assetBalanceAfter2 = IERC20(USDe).balanceOf(clientAddress);
        assertEq(assetBalanceAfter1 - assetBalanceAfter2, DepositAmount);

        _doDeposit();
        _doDeposit();

        uint256 assetBalanceAfterAllDeposits = IERC20(USDe).balanceOf(clientAddress);

        _doWithdraw(10);

        uint256 assetBalanceAfterWithdraw1 = IERC20(USDe).balanceOf(clientAddress);

        assertApproxEqAbs(assetBalanceAfterWithdraw1 - assetBalanceAfterAllDeposits, DepositAmount * 4 / 10, 1);

        _doWithdraw(5);
        _doWithdraw(3);
        _doWithdraw(2);
        _doWithdraw(1);

        uint256 assetBalanceAfterAllWithdrawals = IERC20(USDe).balanceOf(clientAddress);

        uint256 profit = 1414853635425232;
        assertApproxEqAbs(assetBalanceAfterAllWithdrawals, assetBalanceBefore + profit, 1);
    }

    function test_profitSplit_Mainnet() public {
        deal(USDe, clientAddress, 100e18);

        uint256 clientAssetBalanceBefore = IERC20(USDe).balanceOf(clientAddress);
        uint256 p2pAssetBalanceBefore = IERC20(USDe).balanceOf(P2pTreasury);

        _doDeposit();

        uint256 shares = IERC20(sUSDe).balanceOf(proxyAddress);
        uint256 assetsInEthenaBefore = IERC4626(sUSDe).convertToAssets(shares);

        _forward(10000000);

        uint256 assetsInEthenaAfter = IERC4626(sUSDe).convertToAssets(shares);
        uint256 profit = assetsInEthenaAfter - assetsInEthenaBefore;

        _doWithdraw(1);

        uint256 clientAssetBalanceAfter = IERC20(USDe).balanceOf(clientAddress);
        uint256 p2pAssetBalanceAfter = IERC20(USDe).balanceOf(P2pTreasury);
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
        factory.setCalldataRules(address(0), bytes4(0), new P2pStructs.Rule[](0));

        vm.startPrank(p2pOperatorAddress);
        vm.expectEmit();
        emit IP2pYieldProxyFactory.P2pYieldProxyFactory__CalldataRulesSet(
            address(0),
            bytes4(0),
            new P2pStructs.Rule[](0)
        );
        factory.setCalldataRules(address(0), bytes4(0), new P2pStructs.Rule[](0));
    }

    function test_removeCalldataRules_Mainnet() public {
        vm.startPrank(nobody);
        vm.expectRevert(abi.encodeWithSelector(P2pOperator.P2pOperator__UnauthorizedAccount.selector, nobody));
        factory.removeCalldataRules(address(0), bytes4(0));

        vm.startPrank(p2pOperatorAddress);
        vm.expectEmit();
        emit IP2pYieldProxyFactory.P2pYieldProxyFactory__CalldataRulesRemoved(
            address(0),
            bytes4(0)
        );
        factory.removeCalldataRules(address(0), bytes4(0));
    }

    function test_clientBasisPointsGreaterThan10000_Mainnet() public {
        uint96 invalidBasisPoints = 10001;

        vm.startPrank(clientAddress);
        IAllowanceTransfer.PermitSingle memory permitSingle = _getPermitSingleForP2pYieldProxy();
        bytes memory permit2Signature = _getPermit2SignatureForP2pYieldProxy(permitSingle);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            invalidBasisPoints,
            SigDeadline
        );

        vm.expectRevert(abi.encodeWithSelector(P2pYieldProxy__InvalidClientBasisPoints.selector, invalidBasisPoints));
        factory.deposit(
            permitSingle,
            permit2Signature,
            invalidBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );
    }

    function test_zeroAddressAsset_Mainnet() public {
        vm.startPrank(clientAddress);

        // Get the permit details
        IAllowanceTransfer.PermitSingle memory permitSingle = _getPermitSingleForP2pYieldProxy();

        // Set token to zero address
        permitSingle.details.token = address(0);

        bytes memory permit2Signature = _getPermit2SignatureForP2pYieldProxy(permitSingle);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        vm.expectRevert(P2pYieldProxy__ZeroAddressAsset.selector);
        factory.deposit(
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );
    }

    function test_zeroAssetAmount_Mainnet() public {
        vm.startPrank(clientAddress);

        // Get the permit details
        IAllowanceTransfer.PermitSingle memory permitSingle = _getPermitSingleForP2pYieldProxy();

        // Set amount to zero
        permitSingle.details.amount = 0;

        bytes memory permit2Signature = _getPermit2SignatureForP2pYieldProxy(permitSingle);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        vm.expectRevert(P2pYieldProxy__ZeroAssetAmount.selector);
        factory.deposit(
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
        deal(USDe, clientAddress, DepositAmount);

        // Add this line to approve tokens for Permit2
        IERC20(USDe).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);

        // Get the permit details
        IAllowanceTransfer.PermitSingle memory permitSingle = _getPermitSingleForP2pYieldProxy();

        bytes memory permit2Signature = _getPermit2SignatureForP2pYieldProxy(permitSingle);

        // Create proxy first via factory
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        factory.deposit(
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );

        // Now try to call deposit directly on the proxy
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pYieldProxy__NotFactoryCalled.selector,
                clientAddress,
                address(factory)
            )
        );
        P2pEthenaProxy(proxyAddress).deposit(
            permitSingle,
            permit2Signature
        );
    }

    function test_initializeDirectlyOnProxy_Mainnet() public {
        // Create the proxy first since we need a valid proxy address to test with
        proxyAddress = factory.predictP2pYieldProxyAddress(clientAddress, ClientBasisPoints);
        P2pEthenaProxy proxy = P2pEthenaProxy(proxyAddress);

        vm.startPrank(clientAddress);

        // Add this line to give initial tokens to the client
        deal(USDe, clientAddress, DepositAmount);

        // Add this line to approve tokens for Permit2
        IERC20(USDe).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);

        IAllowanceTransfer.PermitSingle memory permitSingle = _getPermitSingleForP2pYieldProxy();

        bytes memory permit2Signature = _getPermit2SignatureForP2pYieldProxy(permitSingle);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        // This will create the proxy
        factory.deposit(
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );

        // Now try to initialize it directly
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pYieldProxy__NotFactoryCalled.selector,
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
        deal(USDe, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(USDe).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);

        IAllowanceTransfer.PermitSingle memory permitSingle = _getPermitSingleForP2pYieldProxy();

        bytes memory permit2Signature = _getPermit2SignatureForP2pYieldProxy(permitSingle);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        factory.deposit(
            permitSingle,
            permit2Signature,
            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );
        vm.stopPrank();

        // Try to withdraw as non-client
        vm.startPrank(nobody);
        P2pEthenaProxy proxy = P2pEthenaProxy(proxyAddress);

        vm.expectRevert(
            abi.encodeWithSelector(
                P2pYieldProxy__NotClientCalled.selector,
                nobody,        // _msgSender (the nobody address trying to call)
                clientAddress  // _actualClient (the actual client address)
            )
        );
        proxy.withdrawAfterCooldown();
        vm.stopPrank();
    }

    function test_withdrawViaCallAnyFunction_Mainnet() public {
        // Create proxy and do initial deposit
        deal(USDe, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(USDe).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);

        // Do initial deposit
        _doDeposit();

        // Try to withdraw using callAnyFunction
        P2pEthenaProxy proxy = P2pEthenaProxy(proxyAddress);
        bytes memory withdrawalCallData = abi.encodeCall(
            IStakedUSDe.unstake,
            clientAddress
        );

        vm.startPrank(clientAddress);

        vm.expectRevert(
            abi.encodeWithSelector(
                P2pYieldProxyFactory__NoRulesDefined.selector,
                USDe,
                IStakedUSDe.unstake.selector
            )
        );

        proxy.callAnyFunction(
            USDe,
            withdrawalCallData
        );
        vm.stopPrank();
    }

    function test_calldataTooShortForStartsWithRule_Mainnet() public {
        // Create proxy and do initial deposit
        deal(USDe, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(USDe).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);

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
            sUSDe,
            IERC20.balanceOf.selector,
            rules
        );
        vm.stopPrank();

        // Create calldata that's too short (only 4 bytes)
        bytes memory shortCalldata = abi.encodeWithSelector(IERC20.balanceOf.selector);

        vm.startPrank(clientAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pYieldProxyFactory__CalldataTooShortForStartsWithRule.selector,
                0, // calldata length after selector
                0, // rule index
                32 // required bytes count
            )
        );
        P2pEthenaProxy(proxyAddress).callAnyFunction(
            sUSDe,
            shortCalldata
        );
        vm.stopPrank();
    }

    function test_calldataStartsWithRuleViolated_Mainnet() public {
        // Create proxy and do initial deposit
        deal(USDe, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(USDe).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);

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
            sUSDe,
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
                P2pYieldProxyFactory__CalldataStartsWithRuleViolated.selector,
                differentBytes,
                expectedBytes
            )
        );
        P2pEthenaProxy(proxyAddress).callAnyFunction(
            sUSDe,
            wrongCalldata
        );
        vm.stopPrank();
    }

    function test_calldataTooShortForEndsWithRule_Mainnet() public {
        // Create proxy and do initial deposit
        deal(USDe, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(USDe).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);

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
            sUSDe,
            IERC20.balanceOf.selector,
            rules
        );
        vm.stopPrank();

        // Create calldata that's too short (only selector)
        bytes memory shortCalldata = abi.encodeWithSelector(IERC20.balanceOf.selector);

        vm.startPrank(clientAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                P2pYieldProxyFactory__CalldataTooShortForEndsWithRule.selector,
                0, // calldata length after selector
                32 // required bytes count
            )
        );
        P2pEthenaProxy(proxyAddress).callAnyFunction(
            sUSDe,
            shortCalldata
        );
        vm.stopPrank();
    }

    function test_calldataEndsWithRuleViolated_Mainnet() public {
        // Create proxy and do initial deposit
        deal(USDe, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(USDe).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);

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
            sUSDe,
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
                P2pYieldProxyFactory__CalldataEndsWithRuleViolated.selector,
                wrongEndBytes,
                expectedEndBytes
            )
        );
        P2pEthenaProxy(proxyAddress).callAnyFunction(
            sUSDe,
            wrongCalldata
        );
        vm.stopPrank();
    }

    function test_callBalanceOfViaCallAnyFunction_Mainnet() public {
        // Create proxy and do initial deposit
        deal(USDe, clientAddress, DepositAmount);
        vm.startPrank(clientAddress);
        IERC20(USDe).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);

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
                P2pYieldProxyFactory__NoRulesDefined.selector,
                sUSDe,
                IERC20.balanceOf.selector
            )
        );
        P2pEthenaProxy(proxyAddress).callAnyFunction(
            sUSDe,
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
            sUSDe,
            IERC20.balanceOf.selector,
            rules
        );
        vm.stopPrank();

        // Call balanceOf via callAnyFunction
        vm.startPrank(clientAddress);
        P2pEthenaProxy proxy = P2pEthenaProxy(proxyAddress);
        proxy.callAnyFunction(
            sUSDe,
            balanceOfCalldata
        );
        vm.stopPrank();
    }

    function _getPermitSingleForP2pYieldProxy() private returns(IAllowanceTransfer.PermitSingle memory) {
        IAllowanceTransfer.PermitDetails memory permitDetails = IAllowanceTransfer.PermitDetails({
            token: USDe,
            amount: uint160(DepositAmount),
            expiration: uint48(SigDeadline),
            nonce: nonce
        });
        nonce++;

        // data for factory
        IAllowanceTransfer.PermitSingle memory permitSingleForP2pYieldProxy = IAllowanceTransfer.PermitSingle({
            details: permitDetails,
            spender: proxyAddress,
            sigDeadline: SigDeadline
        });

        return permitSingleForP2pYieldProxy;
    }

    function _getPermit2SignatureForP2pYieldProxy(IAllowanceTransfer.PermitSingle memory permitSingleForP2pYieldProxy) private view returns(bytes memory) {
        bytes32 permitSingleForP2pYieldProxyHash = factory.getPermit2HashTypedData(PermitHash.hash(permitSingleForP2pYieldProxy));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(clientPrivateKey, permitSingleForP2pYieldProxyHash);
        bytes memory permit2SignatureForP2pYieldProxy = abi.encodePacked(r1, s1, v1);
        return permit2SignatureForP2pYieldProxy;
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
        IAllowanceTransfer.PermitSingle memory permitSingleForP2pYieldProxy = _getPermitSingleForP2pYieldProxy();
        bytes memory permit2SignatureForP2pYieldProxy = _getPermit2SignatureForP2pYieldProxy(permitSingleForP2pYieldProxy);
        bytes memory p2pSignerSignature = _getP2pSignerSignature(
            clientAddress,
            ClientBasisPoints,
            SigDeadline
        );

        vm.startPrank(clientAddress);
        if (IERC20(USDe).allowance(clientAddress, address(Permit2Lib.PERMIT2)) == 0) {
            IERC20(USDe).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        }
        factory.deposit(
            permitSingleForP2pYieldProxy,
            permit2SignatureForP2pYieldProxy,

            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );
        vm.stopPrank();
    }

    function _doWithdraw(uint256 denominator) private {
        uint256 sharesBalance = IERC20(sUSDe).balanceOf(proxyAddress);
        console.log("sharesBalance");
        console.log(sharesBalance);

        uint256 sharesToWithdraw = sharesBalance / denominator;

        vm.startPrank(clientAddress);
        P2pEthenaProxy(proxyAddress).cooldownShares(sharesToWithdraw);

        _forward(10_000 * 7);

        P2pEthenaProxy(proxyAddress).withdrawAfterCooldown();
        vm.stopPrank();
    }

    /// @dev Rolls & warps the given number of blocks forward the blockchain.
    function _forward(uint256 blocks) internal {
        vm.roll(block.number + blocks);
        vm.warp(block.timestamp + blocks * 13);
    }
}