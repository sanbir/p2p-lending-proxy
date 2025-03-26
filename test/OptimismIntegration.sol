// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../src/@openzeppelin/contracts/interfaces/IERC4626.sol";
import "../src/@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/access/P2pOperator.sol";
import "../src/adapters/superform/p2pSuperformProxyFactory/P2pSuperformProxyFactory.sol";
import "../src/common/P2pStructs.sol";
import "../src/p2pYieldProxyFactory/P2pYieldProxyFactory.sol";
import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/console2.sol";
import {PermitHash} from "../src/@permit2/libraries/PermitHash.sol";


contract BaseIntegrationUSDA is Test {
    using SafeERC20 for IERC20;

    address constant USDT = 0x94b008aA00579c1307B0EF2c499aD98a8ce58e58;
    address constant SuperformRouter = 0xa195608C2306A26f727d5199D5A382a4508308DA;
    address constant SuperPositions = 0x01dF6fb6a28a89d6bFa53b2b3F20644AbF417678;

    address constant P2pTreasury = 0x641ca805C75cC5D1ffa78C0181Aba1F77BD17904;

    uint256 constant SuperformId = 62771017356190754913478451444852273738203985736479809223259;

    P2pSuperformProxyFactory private factory;

    address private clientAddress;
    uint256 private clientPrivateKey;

    address private p2pSignerAddress;
    uint256 private p2pSignerPrivateKey;

    address private p2pOperatorAddress;
    address private nobody;

    uint256 constant SigDeadline = 1789558996;
    uint96 constant ClientBasisPoints = 8700; // 13% fee
    uint256 constant DepositAmount = 199918306828021388981;
    uint256 constant SharesAmount = 199918306828021388981;

    address proxyAddress;

    uint48 nonce;

    function setUp() public {
        vm.createSelectFork("optimism", 130409572);

        (clientAddress, clientPrivateKey) = makeAddrAndKey("client");
        (p2pSignerAddress, p2pSignerPrivateKey) = makeAddrAndKey("p2pSigner");
        p2pOperatorAddress = makeAddr("p2pOperator");
        nobody = makeAddr("nobody");

        vm.startPrank(p2pOperatorAddress);
        factory = new P2pSuperformProxyFactory(
            p2pSignerAddress,
            P2pTreasury,
            SuperformRouter,
            SuperPositions
        );
        vm.stopPrank();

        proxyAddress = factory.predictP2pYieldProxyAddress(clientAddress, ClientBasisPoints);
    }

    function test_happyPath_Optimism() public {
        deal(USDT, clientAddress, 10000e18);

        uint256 assetBalanceBefore = IERC20(USDT).balanceOf(clientAddress);

        _doDeposit();

        // dealERC1155(SuperPositions, proxyAddress, SuperformId, 111138854024009730);

        uint256 assetBalanceAfterAllDeposits = IERC20(USDT).balanceOf(clientAddress);
        _doWithdraw(1);

        uint256 assetBalanceAfterAllWithdrawals = IERC20(USDT).balanceOf(clientAddress);
    }

    function _getVaultAddress() private pure returns(address) {
        return address(uint160(SuperformId));
    }

    function _getPermitSingleForP2pYieldProxy() private returns(IAllowanceTransfer.PermitSingle memory) {
        IAllowanceTransfer.PermitDetails memory permitDetails = IAllowanceTransfer.PermitDetails({
            token: USDT,
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
        if (IERC20(USDT).allowance(clientAddress, address(Permit2Lib.PERMIT2)) == 0) {
            IERC20(USDT).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        }

        LiqRequest memory liqRequest = LiqRequest({
            txData: hex"4630a0d81d8becdaaca0bf8a0fd3c198c0a94bbee28edfdb5134b26472a6034e1f568bd000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000097116661c85c4e1ee35aa10f7fc5fe5e67b83a5b00000000000000000000000000000000000000000000000ac88d3da4acdb2df40000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000000d7375706572666f726d2e78797a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a30783030303030303030303030303030303030303030303030303030303030303030303030303030303000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000006131b5fae19ea4f9d964eac0408e4408b66337b50000000000000000000000006131b5fae19ea4f9d964eac0408e4408b66337b500000000000000000000000094b008aa00579c1307b0ef2c499ad98a8ce58e58000000000000000000000000c40f949f8a4e094d1b49a23ea9241d289b7b2819000000000000000000000000000000000000000000000000000000000bebc20000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000006c4e21fd0e9000000000000000000000000000000000000000000000000000000000000002000000000000000000000000011ddd59c33c73c44733b4123a86ea5ce57f6e854000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000440000000000000000000000000000000000000000000000000000000000000012f0102000000510011ddd59c33c73c44733b4123a86ea5ce57f6e854000000a73c628eaf6e283e26a7b1f8001cf186aa4c0e8e0000000000000000000000000bebc2000100000000000000000000000000000000000000000a000000420011ddd59c33c73c44733b4123a86ea5ce57f6e8540000008ac2f9dac7a2852d44f3c09634444d533e4c078e010100000000000000000000000000000000000000000a94b008aa00579c1307b0ef2c499ad98a8ce58e58c40f949f8a4e094d1b49a23ea9241d289b7b28191231deb6f5749ef6ce6943a275a1d3e7486f4eae000000000000000000000000677fa71000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000b5d31ba99ef5000000000000000ad66c80d8f5c3d6b5000000000000000000000000000000000000000000000000000000000094b008aa00579c1307b0ef2c499ad98a8ce58e58000000000000000000000000c40f949f8a4e094d1b49a23ea9241d289b7b2819000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000002000000000000000000000000001231deb6f5749ef6ce6943a275a1d3e7486f4eae000000000000000000000000000000000000000000000000000000000bebc20000000000000000000000000000000000000000000000000ac88d3da4acdb2df400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000000100000000000000000000000011ddd59c33c73c44733b4123a86ea5ce57f6e8540000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000bebc20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002317b22536f75726365223a226c692e6669222c22416d6f756e74496e555344223a223230302e3034303237343339313538373533222c22416d6f756e744f7574555344223a223230302e3234393838323339313338353436222c22526566657272616c223a22222c22466c616773223a302c22416d6f756e744f7574223a22313939393138333036383238303231333838393831222c2254696d657374616d70223a313733363431373838382c22496e74656772697479496e666f223a7b224b65794944223a2231222c225369676e6174757265223a22453344324a4445553147426737324f30314d5141424f38373465344b792f384b3454613073547a3530326f74747749424d6761374137423131416e567839613458426a527a4651574e454233303478515a67744630376778763234525754517a636d68524753554a575044574c457358676e62426a7a375333396345453377634f79745649796b3047772b47577a5946366962343262454873624b464c6e6d3472384270643067644e75725938466766617851305a2f376d7a477150415365684a6b314859513458414f73673131546d36447a4761753379597548413430306573564538774b667a6237467a2f44626b4361636c746973716f7958757a327a2b576e5942346b5a33784f38775168717a676a494a35594964506c6974306e5a6a5149427075524d344279335a4c2f55736e5235304d42692b7a6542426e4e556d4475306144776b65323138534b386450644355372f773d3d227d7d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            token: USDT,
            interimToken: address(0),
            bridgeId: 101,
            liqDstChainId: 10,
            nativeAmount: 0
        });
        SingleVaultSFData memory superformData = SingleVaultSFData({
            superformId: SuperformId,
            amount: DepositAmount,
            outputAmount: SharesAmount,
            maxSlippage: 50,
            liqRequest: liqRequest,
            permit2data: "",
            hasDstSwap: false,
            retain4626: false,
            receiverAddress: proxyAddress,
            receiverAddressSP: proxyAddress,
            extraFormData: ""
        });
        SingleDirectSingleVaultStateReq memory req = SingleDirectSingleVaultStateReq({
            superformData: superformData
        });

        bytes memory superformCalldata = abi.encodeCall(IBaseRouter.singleDirectSingleVaultDeposit, (req));

        factory.deposit(
            permitSingleForP2pYieldProxy,
            permit2SignatureForP2pYieldProxy,

        superformCalldata,

            ClientBasisPoints,
            SigDeadline,
            p2pSignerSignature
        );
        vm.stopPrank();
    }

    function _doWithdraw(uint256 denominator) private {
//        uint256 sharesBalance = IERC1155(SuperPositions).balanceOf(proxyAddress, SuperformId);
//        console.log("sharesBalance");
//        console.log(sharesBalance);
//
//        uint256 sharesToWithdraw = sharesBalance / denominator;

        LiqRequest memory liqRequest = LiqRequest({
            txData: hex"4630a0d851a1c96f20939c005d23596f3694831748f74fde7e486d7f082bdb0dea283e6a00000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000588ede4403df0082c5ab245b35f0f79eb2d8033a000000000000000000000000000000000000000000000000000000000001dfd10000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000000d7375706572666f726d2e78797a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a307830303030303030303030303030303030303030303030303030303030303030303030303030303030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000019ceead7105607cd444f5ad10dd51356436095a100000000000000000000000019ceead7105607cd444f5ad10dd51356436095a10000000000000000000000000000206329b97db379d5e1bf586bbdb969c63274000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda0291300000000000000000000000000000000000000000000000001b6953b5040e8c800000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000bf83bd37f900010000206329b97db379d5e1bf586bbdb969c6327400040801b6953b5040e8c80301e23a0147ae000152bb904473e0adc699c7b103962d35a0f53d9e1e000000011231deb6f5749ef6ce6943a275a1d3e7486f4eae59725ade0301020400350101010203ff000000000000000000000000000000000000000000222222880e079445df703c0604706e71a538fd4f0000206329b97db379d5e1bf586bbdb969c63274833589fcd6edb6e08f4c7c32d4f71b54bda029130000000000",
            token: USDT,
            interimToken: address(0),
            bridgeId: 101,
            liqDstChainId: 10,
            nativeAmount: 0
        });
        SingleVaultSFData memory superformData = SingleVaultSFData({
            superformId: SuperformId,
            amount: 199914817472094798787,
            outputAmount: 199914817472094798787,
            maxSlippage: 50,
            liqRequest: liqRequest,
            permit2data: "",
            hasDstSwap: false,
            retain4626: false,
            receiverAddress: proxyAddress,
            receiverAddressSP: proxyAddress,
            extraFormData: ""
        });
        SingleDirectSingleVaultStateReq memory req = SingleDirectSingleVaultStateReq({
            superformData: superformData
        });
        bytes memory superformCalldata = abi.encodeCall(IBaseRouter.singleDirectSingleVaultWithdraw, (req));

        vm.startPrank(clientAddress);
        P2pSuperformProxy(proxyAddress).withdraw(superformCalldata);
        vm.stopPrank();
    }

    /// @dev Rolls & warps the given number of blocks forward the blockchain.
    function _forward(uint256 blocks) internal {
        vm.roll(block.number + blocks);
        vm.warp(block.timestamp + blocks * 13);
    }
}