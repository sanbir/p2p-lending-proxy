// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../src/@openzeppelin/contracts/interfaces/IERC4626.sol";
import "../src/@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/access/P2pOperator.sol";
import "../src/common/IMorphoBundler.sol";
import "../src/common/P2pStructs.sol";
import "../src/mocks/@murky/Merkle.sol";
import "../src/mocks/IUniversalRewardsDistributor.sol";
import "../src/p2pLendingProxyFactory/P2pLendingProxyFactory.sol";
import "../src/adapters/morpho/p2pMorphoProxyFactory/P2pMorphoProxyFactory.sol";
import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/console2.sol";
import {PermitHash} from "../src/@permit2/libraries/PermitHash.sol";
import {P2pMorphoProxy} from "../src/adapters/morpho/p2pMorphoProxy/P2pMorphoProxy.sol";


contract MainnetMorphoClaiming is Test {
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

    Merkle internal merkle;
    address internal distributor = 0x330eefa8a787552DC5cAd3C3cA644844B1E61Ddb;
    address MORPHO_token = 0x58D97B57BB95320F9a05dC918Aef65434969c2B2;
    address MORPHO_OWNER = 0xcBa28b38103307Ec8dA98377ffF9816C164f9AFa;

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

        merkle = new Merkle();
    }

    function test_MorphoClaimingByClient_Mainnet() public {
        uint256 claimable = 10 ether;

        deal(asset, clientAddress, 100e6);

        _doDeposit();

        uint256 clientBalanceBefore = IERC20(MORPHO_token).balanceOf(clientAddress);
        uint256 p2pBalanceBefore = IERC20(MORPHO_token).balanceOf(P2pTreasury);

        bytes32[] memory tree = _setupRewards(claimable);
        bytes32[] memory proof = merkle.getProof(tree, 0);

        vm.prank(clientAddress);
        vm.expectRevert(abi.encodeWithSelector(P2pMorphoProxyFactory__DistributorNotTrusted.selector, distributor));
        P2pMorphoProxy(proxyAddress).morphoUrdClaim(
            distributor,
            MORPHO_token,
            claimable,
            proof
        );

        vm.prank(p2pOperatorAddress);
        factory.setTrustedDistributor(distributor);

        vm.prank(clientAddress);
        P2pMorphoProxy(proxyAddress).morphoUrdClaim(
            distributor,
            MORPHO_token,
            claimable,
            proof
        );

        uint256 clientBalanceAfter = IERC20(MORPHO_token).balanceOf(clientAddress);
        uint256 p2pBalanceAfter = IERC20(MORPHO_token).balanceOf(P2pTreasury);

        assertEq(clientBalanceAfter - clientBalanceBefore, claimable * ClientBasisPoints / 10_000);
        assertEq(p2pBalanceAfter - p2pBalanceBefore, claimable * (10_000 - ClientBasisPoints) / 10_000);
    }

    function test_MorphoClaimingByOperator_Mainnet() public {
        uint256 claimable = 10 ether;

        deal(asset, clientAddress, 100e6);

        _doDeposit();

        uint256 clientBalanceBefore = IERC20(MORPHO_token).balanceOf(clientAddress);
        uint256 p2pBalanceBefore = IERC20(MORPHO_token).balanceOf(P2pTreasury);

        bytes32[] memory tree = _setupRewards(claimable);
        bytes32[] memory proof = merkle.getProof(tree, 0);

        vm.startPrank(p2pOperatorAddress);
        vm.expectRevert(abi.encodeWithSelector(P2pMorphoProxyFactory__DistributorNotTrusted.selector, distributor));
        P2pMorphoProxy(proxyAddress).morphoUrdClaim(
            distributor,
            MORPHO_token,
            claimable,
            proof
        );
        factory.setTrustedDistributor(distributor);
        P2pMorphoProxy(proxyAddress).morphoUrdClaim(
            distributor,
            MORPHO_token,
            claimable,
            proof
        );

        uint256 clientBalanceAfter = IERC20(MORPHO_token).balanceOf(clientAddress);
        uint256 p2pBalanceAfter = IERC20(MORPHO_token).balanceOf(P2pTreasury);

        assertEq(clientBalanceAfter - clientBalanceBefore, claimable * ClientBasisPoints / 10_000);
        assertEq(p2pBalanceAfter - p2pBalanceBefore, claimable * (10_000 - ClientBasisPoints) / 10_000);
    }

    function _setupRewards(uint256 claimable) internal returns (bytes32[] memory tree) {
        tree = new bytes32[](2);
        tree[0] = keccak256(bytes.concat(keccak256(abi.encode(proxyAddress, MORPHO_token, claimable))));
        tree[1] = keccak256(bytes.concat(keccak256(abi.encode(nobody, MORPHO_token, claimable))));
        bytes32 root = merkle.getRoot(tree);

        vm.prank(MORPHO_OWNER);
        IUniversalRewardsDistributor(distributor).setRoot(root, bytes32(0));
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
}