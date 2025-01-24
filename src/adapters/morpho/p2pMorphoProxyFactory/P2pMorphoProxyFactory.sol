// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../@permit2/interfaces/IAllowanceTransfer.sol";
import "../../../p2pLendingProxyFactory/P2pLendingProxyFactory.sol";
import "../../common/CalldataParser.sol";
import "./IP2pMorphoProxyFactory.sol";
import {P2pMorphoProxy} from "../p2pMorphoProxy/P2pMorphoProxy.sol";
import {IERC4626} from "../../../@openzeppelin/contracts/interfaces/IERC4626.sol";

error P2pMorphoProxyFactory__DistributorNotTrusted(address _distributor);
error P2pMorphoProxyFactory__IncorrectLengthOf_dataForMulticall();
error P2pMorphoProxyFactory__approve2_amount_ne_permitSingleForP2pLendingProxy_amount();
error P2pMorphoProxyFactory__transferFrom2_amount_ne_permitSingleForP2pLendingProxy_amount();
error P2pMorphoProxyFactory__erc4626Deposit_assets_ne_permitSingleForP2pLendingProxy_amount();
error P2pMorphoProxyFactory__approve2_token_ne_permitSingleForP2pLendingProxy_token();
error P2pMorphoProxyFactory__transferFrom2_asset_ne_permitSingleForP2pLendingProxy_token();
error P2pMorphoProxyFactory__erc4626Deposit_vault_asset_ne_permitSingleForP2pLendingProxy_token();
error P2pMorphoProxyFactory__erc4626Deposit_receiver_ne_proxy();
error P2pMorphoProxyFactory__ZeroTrustedDistributorAddress();

contract P2pMorphoProxyFactory is P2pLendingProxyFactory, CalldataParser, IP2pMorphoProxyFactory {
    /// @dev Emitted when the trusted distributor is set
    event P2pMorphoProxyFactory__TrustedDistributorSet(
        address indexed _newTrustedDistributor
    );

    /// @dev Emitted when the trusted distributor is removed
    event P2pMorphoProxyFactory__TrustedDistributorRemoved(
        address indexed _trustedDistributor
    );

    // distributor address => true
    mapping(address => bool) private s_trustedDistributors;

    /// @notice Constructor for P2pMorphoProxyFactory
    /// @param _morphoBundler The morpho bundler address
    /// @param _p2pSigner The P2pSigner address
    /// @param _p2pTreasury The P2pTreasury address
    constructor(
        address _morphoBundler,
        address _p2pSigner,
        address _p2pTreasury
    ) P2pLendingProxyFactory(_p2pSigner) {
        i_referenceP2pLendingProxy = new P2pMorphoProxy(
            _morphoBundler,
            address(this),
            _p2pTreasury
        );
    }

    /// @inheritdoc IP2pLendingProxyFactory
    function deposit(
        address _lendingProtocolAddress,
        bytes calldata _lendingProtocolCalldata,

        IAllowanceTransfer.PermitSingle memory _permitSingleForP2pLendingProxy,
        bytes calldata _permit2SignatureForP2pLendingProxy,

        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline,
        bytes calldata _p2pSignerSignature
    )
    public
    override(P2pLendingProxyFactory, IP2pLendingProxyFactory)
    returns (address p2pLendingProxyAddress) {
        // morpho multicall
        bytes[] memory dataForMulticall = abi.decode(_lendingProtocolCalldata[SELECTOR_LENGTH:], (bytes[]));

        require(
            dataForMulticall.length == 3,
            P2pMorphoProxyFactory__IncorrectLengthOf_dataForMulticall()
        );

        // morpho approve2
        (IAllowanceTransfer.PermitSingle memory permitSingle,,) = abi.decode(
            _slice(dataForMulticall[0], SELECTOR_LENGTH, dataForMulticall[0].length - SELECTOR_LENGTH),
            (IAllowanceTransfer.PermitSingle, bytes, bool)
        );

        // morpho transferFrom2
        (address asset, uint256 amount) = abi.decode(
            _slice(dataForMulticall[1], SELECTOR_LENGTH, dataForMulticall[1].length - SELECTOR_LENGTH),
            (address, uint256)
        );

        // morpho erc4626Deposit
        (address vault, uint256 assets,, address receiver) = abi.decode(
            _slice(dataForMulticall[2], SELECTOR_LENGTH, dataForMulticall[2].length - SELECTOR_LENGTH),
            (address, uint256, uint256, address)
        );

        require(
            permitSingle.details.amount == _permitSingleForP2pLendingProxy.details.amount,
            P2pMorphoProxyFactory__approve2_amount_ne_permitSingleForP2pLendingProxy_amount()
        );
        require(
            amount == _permitSingleForP2pLendingProxy.details.amount,
            P2pMorphoProxyFactory__transferFrom2_amount_ne_permitSingleForP2pLendingProxy_amount()
        );
        require(
            assets == _permitSingleForP2pLendingProxy.details.amount,
            P2pMorphoProxyFactory__erc4626Deposit_assets_ne_permitSingleForP2pLendingProxy_amount()
        );

        require(
            permitSingle.details.token == _permitSingleForP2pLendingProxy.details.token,
            P2pMorphoProxyFactory__approve2_token_ne_permitSingleForP2pLendingProxy_token()
        );
        require(
            asset == _permitSingleForP2pLendingProxy.details.token,
            P2pMorphoProxyFactory__transferFrom2_asset_ne_permitSingleForP2pLendingProxy_token()
        );
        require(
            IERC4626(vault).asset() == _permitSingleForP2pLendingProxy.details.token,
            P2pMorphoProxyFactory__erc4626Deposit_vault_asset_ne_permitSingleForP2pLendingProxy_token()
        );

        require(
            receiver == predictP2pLendingProxyAddress(
                msg.sender,
                _clientBasisPoints
            ),
            P2pMorphoProxyFactory__erc4626Deposit_receiver_ne_proxy()
        );

        return super.deposit(
            _lendingProtocolAddress,
            _lendingProtocolCalldata,

            _permitSingleForP2pLendingProxy,
            _permit2SignatureForP2pLendingProxy,

            _clientBasisPoints,
            _p2pSignerSigDeadline,
            _p2pSignerSignature
        );
    }

    /// @dev Sets the trusted distributor
    /// @param _newTrustedDistributor The new trusted distributor
    function setTrustedDistributor(
        address _newTrustedDistributor
    ) external onlyP2pOperator {
        require (
            _newTrustedDistributor != address(0),
            P2pMorphoProxyFactory__ZeroTrustedDistributorAddress()
        );
        emit P2pMorphoProxyFactory__TrustedDistributorSet(_newTrustedDistributor);
        s_trustedDistributors[_newTrustedDistributor] = true;
    }

    /// @dev Removes the trusted distributor
    /// @param _trustedDistributor The trusted distributor
    function removeTrustedDistributor(
        address _trustedDistributor
    ) external onlyP2pOperator {
        emit P2pMorphoProxyFactory__TrustedDistributorRemoved(_trustedDistributor);
        s_trustedDistributors[_trustedDistributor] = false;
    }

    /// @dev Checks if the morpho URD claim is valid
    /// @param _p2pOperatorToCheck The P2pOperator to check
    /// @param _shouldCheckP2pOperator If the P2pOperator should be checked
    /// @param _distributor The distributor address
    function checkMorphoUrdClaim(
        address _p2pOperatorToCheck,
        bool _shouldCheckP2pOperator,
        address _distributor
    ) public view {
        if (_shouldCheckP2pOperator) {
            require(
                getP2pOperator() == _p2pOperatorToCheck,
                P2pOperator__UnauthorizedAccount(_p2pOperatorToCheck)
            );
        }
        require(
            s_trustedDistributors[_distributor],
            P2pMorphoProxyFactory__DistributorNotTrusted(_distributor)
        );
    }

    /// @dev Checks if the distributor is trusted
    /// @param _distributor The distributor address
    /// @return If the distributor is trusted or not
    function isTrustedDistributor(address _distributor) external view returns (bool) {
        return s_trustedDistributors[_distributor];
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pLendingProxyFactory, IERC165) returns (bool) {
        return interfaceId == type(IP2pMorphoProxyFactory).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
