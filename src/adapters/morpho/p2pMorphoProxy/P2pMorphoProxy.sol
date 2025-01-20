// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../p2pLendingProxy/P2pLendingProxy.sol";
import "../../common/CalldataParser.sol";
import "../p2pMorphoProxyFactory/IP2pMorphoProxyFactory.sol";
import "./IP2pMorphoProxy.sol";

error P2pMorphoProxy__IncorrectLengthOf_dataForMulticall();
error P2pMorphoProxy__erc4626Redeem_vault_ne_vault();
error P2pMorphoProxy__erc4626Redeem_shares_ne_shares();
error P2pMorphoProxy__erc4626Redeem_receiver_ne_proxy();
error P2pMorphoProxy__erc4626Redeem_owner_ne_proxy();
error P2pMorphoProxy__NothingClaimed();

contract P2pMorphoProxy is P2pLendingProxy, CalldataParser, IP2pMorphoProxy {
    using SafeERC20 for IERC20;

    /// @dev Morpho bundler
    IMorphoBundler private immutable i_morphoBundler;

    /// @notice Constructor for P2pMorphoProxy
    /// @param _morphoBundler The morpho bundler address
    /// @param _factory The factory address
    /// @param _p2pTreasury The P2pTreasury address
    constructor(
        address _morphoBundler,
        address _factory,
        address _p2pTreasury
    ) P2pLendingProxy(_factory, _p2pTreasury) {
        i_morphoBundler = IMorphoBundler(_morphoBundler);
    }

    /// @inheritdoc IP2pLendingProxy
    function withdraw(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,
        address _vault,
        uint256 _shares
    )
    public
    override(P2pLendingProxy, IP2pLendingProxy) {
        // morpho multicall
        bytes[] memory dataForMulticall = abi.decode(_lendingProtocolCalldata[SELECTOR_LENGTH:], (bytes[]));

        require(
            dataForMulticall.length == 1,
            P2pMorphoProxy__IncorrectLengthOf_dataForMulticall()
        );

        // morpho erc4626Redeem
        (address vault, uint256 shares,, address receiver, address owner) = abi.decode(
            _slice(dataForMulticall[0], SELECTOR_LENGTH, dataForMulticall[0].length - SELECTOR_LENGTH),
            (address, uint256, uint256, address, address)
        );

        require(
            _vault == vault,
            P2pMorphoProxy__erc4626Redeem_vault_ne_vault()
        );
        require(
            _shares == shares,
            P2pMorphoProxy__erc4626Redeem_shares_ne_shares()
        );
        require(
            receiver == address(this),
            P2pMorphoProxy__erc4626Redeem_receiver_ne_proxy()
        );
        require(
            owner == address(this),
            P2pMorphoProxy__erc4626Redeem_owner_ne_proxy()
        );

        super.withdraw(
            _lendingProtocolAddress,
            _lendingProtocolCalldata,
            _vault,
            _shares
        );
    }

    /// @inheritdoc IP2pMorphoProxy
    function morphoUrdClaim(
        address _distributor,
        address _reward,
        uint256 _amount,
        bytes32[] calldata _proof
    )
    external
    nonReentrant
    {
        bool shouldCheckP2pOperator;
        if (msg.sender != s_client) {
            shouldCheckP2pOperator = true;
        }
        IP2pMorphoProxyFactory(address(i_factory)).checkMorphoUrdClaim(
            msg.sender,
            shouldCheckP2pOperator,
            _distributor
        );

        bytes memory urdClaimCalldata = abi.encodeCall(IMorphoBundler.urdClaim, (
            _distributor,
            address(this),
            _reward,
            _amount,
            _proof,
            false
        ));
        bytes[] memory dataForMulticall = new bytes[](1);
        dataForMulticall[0] = urdClaimCalldata;

        uint256 assetAmountBefore = IERC20(_reward).balanceOf(address(this));

        // claim _reward token from Morpho
        i_morphoBundler.multicall(dataForMulticall);

        uint256 assetAmountAfter = IERC20(_reward).balanceOf(address(this));

        uint256 newAssetAmount = assetAmountAfter - assetAmountBefore;
        require (newAssetAmount > 0, P2pMorphoProxy__NothingClaimed());

        uint256 p2pAmount = (newAssetAmount * (10_000 - s_clientBasisPoints)) / 10_000;
        uint256 clientAmount = newAssetAmount - p2pAmount;

        if (p2pAmount > 0) {
            IERC20(_reward).safeTransfer(i_p2pTreasury, p2pAmount);
        }
        // clientAmount must be > 0 at this point
        IERC20(_reward).safeTransfer(s_client, clientAmount);

        emit P2pMorphoProxy__ClaimedMorphoUrd(
            _distributor,
            _reward,
            newAssetAmount,
            p2pAmount,
            clientAmount
        );
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pLendingProxy, IERC165) returns (bool) {
        return interfaceId == type(IP2pMorphoProxy).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
