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

    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address constant SuperformRouter = 0xa195608C2306A26f727d5199D5A382a4508308DA;
    address constant SuperPositions = 0x01dF6fb6a28a89d6bFa53b2b3F20644AbF417678;

    address constant P2pTreasury = 0x641ca805C75cC5D1ffa78C0181Aba1F77BD17904;

    uint256 constant SuperformId = 53060340969225896615497461540294763454791116705941340942333597;

    P2pSuperformProxyFactory private factory;

    address private clientAddress;
    uint256 private clientPrivateKey;

    address private p2pSignerAddress;
    uint256 private p2pSignerPrivateKey;

    address private p2pOperatorAddress;
    address private nobody;

    uint256 constant SigDeadline = 1789558996;
    uint96 constant ClientBasisPoints = 8700; // 13% fee
    uint256 constant DepositAmount = 123450000000000032;
    uint256 constant SharesAmount = 111138856676506222;

    address proxyAddress;

    uint48 nonce;

    function setUp() public {
        vm.createSelectFork("base", 28093084);

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

    function test_happyPath_USDA() public {
        deal(USDC, clientAddress, 10000e18);

        uint256 assetBalanceBefore = IERC20(USDC).balanceOf(clientAddress);

        _doDeposit();

        dealERC1155(SuperPositions, proxyAddress, SuperformId, 111138854024009730);

        uint256 assetBalanceAfterAllDeposits = IERC20(USDC).balanceOf(clientAddress);
        _doWithdraw(1);

        uint256 assetBalanceAfterAllWithdrawals = IERC20(USDC).balanceOf(clientAddress);
    }

    function _getVaultAddress() private pure returns(address) {
        return address(uint160(SuperformId));
    }

    function _getPermitSingleForP2pYieldProxy() private returns(IAllowanceTransfer.PermitSingle memory) {
        IAllowanceTransfer.PermitDetails memory permitDetails = IAllowanceTransfer.PermitDetails({
            token: USDC,
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
        if (IERC20(USDC).allowance(clientAddress, address(Permit2Lib.PERMIT2)) == 0) {
            IERC20(USDC).safeApprove(address(Permit2Lib.PERMIT2), type(uint256).max);
        }

        LiqRequest memory liqRequest = LiqRequest({
            txData: hex"4630a0d8fb3c5573a8e53e1242c4f33f0bf3825c17792cf4bef7219f1a90a5b177fec7db00000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000090176dd603a63c0ed67315391fefbb1402d1769d00000000000000000000000000000000000000000000000001b463bc3e88cc200000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000000d7375706572666f726d2e78797a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a307830303030303030303030303030303030303030303030303030303030303030303030303030303030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000019ceead7105607cd444f5ad10dd51356436095a100000000000000000000000019ceead7105607cd444f5ad10dd51356436095a1000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda029130000000000000000000000000000206329b97db379d5e1bf586bbdb969c63274000000000000000000000000000000000000000000000000000000000001e23a00000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000bf83bd37f9000400010000206329b97db379d5e1bf586bbdb969c632740301e23a0801b6951ef585a0200147ae000152bb904473e0adc699c7b103962d35a0f53d9e1e000000011231deb6f5749ef6ce6943a275a1d3e7486f4eae59725ade0301020400350101010203ff000000000000000000000000000000000000000000222222880e079445df703c0604706e71a538fd4f833589fcd6edb6e08f4c7c32d4f71b54bda029130000206329b97db379d5e1bf586bbdb969c632740000000000",
            token: USDC,
            interimToken: address(0),
            bridgeId: 101,
            liqDstChainId: 8453,
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
            token: USDC,
            interimToken: address(0),
            bridgeId: 101,
            liqDstChainId: 8453,
            nativeAmount: 0
        });
        SingleVaultSFData memory superformData = SingleVaultSFData({
            superformId: SuperformId,
            amount: 111138854024009730,
            outputAmount: 123450121781307592,
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