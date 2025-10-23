// SPDX-FileCopyrightText: 2025 P2P Validator <info@p2p.org>
// SPDX-License-Identifier: MIT

pragma solidity 0.8.27;

import "../../../p2pLendingProxyFactory/P2pLendingProxyFactory.sol";
import "../../../common/IMorphoBundler.sol";
import "./IP2pMorphoProxyFactory.sol";
import {P2pMorphoProxy} from "../p2pMorphoProxy/P2pMorphoProxy.sol";
import {IERC4626} from "../../../@openzeppelin/contracts/interfaces/IERC4626.sol";

error P2pMorphoProxyFactory__DistributorNotTrusted(address _distributor);
error P2pMorphoProxyFactory__erc4626Deposit_assets_ne_amount();
error P2pMorphoProxyFactory__erc4626Deposit_vault_asset_mismatch();
error P2pMorphoProxyFactory__erc4626Deposit_receiver_ne_proxy();
error P2pMorphoProxyFactory__ZeroVaultAddress();
error P2pMorphoProxyFactory__ZeroTrustedDistributorAddress();

contract P2pMorphoProxyFactory is P2pLendingProxyFactory, IP2pMorphoProxyFactory {
    /// @dev Emitted when the trusted distributor is set
    event P2pMorphoProxyFactory__TrustedDistributorSet(
        address indexed _newTrustedDistributor
    );

    /// @dev Emitted when the trusted distributor is removed
    event P2pMorphoProxyFactory__TrustedDistributorRemoved(
        address indexed _trustedDistributor
    );

    /// @dev Morpho bundler
    IMorphoBundler private immutable i_morphoBundler;

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
        i_morphoBundler = IMorphoBundler(_morphoBundler);
        i_referenceP2pLendingProxy = new P2pMorphoProxy(
            _morphoBundler,
            address(this),
            _p2pTreasury
        );
    }

    function _prepareDepositCall(
        address _client,
        address _asset,
        address _vault,
        uint256 _amount,
        uint96 _clientBasisPoints
    ) internal view override returns (address lendingProtocol, bytes memory lendingCalldata) {
        require(_vault != address(0), P2pMorphoProxyFactory__ZeroVaultAddress());

        require(
            IERC4626(_vault).asset() == _asset,
            P2pMorphoProxyFactory__erc4626Deposit_vault_asset_mismatch()
        );

        address predictedProxy = predictP2pLendingProxyAddress(
            _client,
            _clientBasisPoints
        );

        require(
            predictedProxy != address(0),
            P2pMorphoProxyFactory__erc4626Deposit_receiver_ne_proxy()
        );

        require(
            _amount > 0,
            P2pMorphoProxyFactory__erc4626Deposit_assets_ne_amount()
        );

        uint256 minShares = IERC4626(_vault).convertToShares(_amount);
        minShares = (minShares * 100) / 102;

        bytes memory erc4626DepositCall = abi.encodeCall(IMorphoBundler.erc4626Deposit, (
            _vault,
            _amount,
            minShares,
            predictedProxy
        ));

        bytes[] memory dataForMulticall = new bytes[](1);
        dataForMulticall[0] = erc4626DepositCall;

        lendingProtocol = address(i_morphoBundler);
        lendingCalldata = abi.encodeCall(IMorphoBundler.multicall, (dataForMulticall));
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

    /// @inheritdoc IP2pLendingProxyFactory
    function getP2pOperator() public view override(P2pLendingProxyFactory, IP2pLendingProxyFactory) returns (address) {
        return super.getP2pOperator();
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override(P2pLendingProxyFactory, IERC165) returns (bool) {
        return interfaceId == type(IP2pMorphoProxyFactory).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
