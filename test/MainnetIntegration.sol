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