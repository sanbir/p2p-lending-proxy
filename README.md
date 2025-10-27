## p2p-morpho-proxy

Contracts for client-specific ERC-20 yield proxies.
The current implementation integrates with [Morpho Blue](https://www.morpho.org/) via the Morpho Ethereum Bundler.

## Running tests

```shell
curl -L https://foundry.paradigm.xyz | bash
source /Users/$USER/.bashrc
foundryup
forge test
```

## Deployment

```shell
forge script script/Deploy.s.sol:Deploy --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --chain $CHAIN_ID --json --verify --etherscan-api-key $ETHERSCAN_API_KEY -vvvvv
```

This script will:

- deploy and verify on Etherscan the **P2pMorphoProxyFactory** and the reference **P2pMorphoProxy**
- set the **P2pTreasury** address permanently in the P2pMorphoProxyFactory
- deploy the upgradeable **AllowedCalldataChecker** that guards `callAnyFunction`

## Basic use case

![Basic use case diagram](image-1.png)

#### Morpho deposit flow

Look at [function _doDeposit()](test/MainnetIntegration.sol#L176) for a reference implementation of the flow.

1. Website User (called Client in contracts) calls Backend with its (User's) Ethereum address and some Merchant info.

2. Backend uses Merchant info to determine the P2P fee (expressed as client basis points in the contracts).

3. Backend calls `P2pMorphoProxyFactory.getHashForP2pSigner` to get the hash for the P2pSigner.

```solidity
    /// @notice Computes the P2pSigner hash for a deposit authorization
    /// @param _client The address of client
    /// @param _clientBasisPoints The client basis points
    /// @param _p2pSignerSigDeadline The P2pSigner signature deadline
    /// @return The hash for the P2pSigner
    function getHashForP2pSigner(
        address _client,
        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline
    ) external view returns (bytes32);
```

4. Backend signs the hash with the P2pSigner's private key using `eth_sign`. Signing is necessary to authenticate the client basis points in the contracts.

5. Backend returns JSON to the User with (client address, client basis points, signature deadline, and the signature).

6. Client-side code prepares all the necessary data for the Morpho deposit function. The deposited tokens first move from the client to the client's `P2pMorphoProxy` and are then forwarded into the Morpho vault. The client approves the proxy address returned by `predictP2pYieldProxyAddress` via a standard ERC-20 `approve` call:

```solidity
    /// @dev Computes the address of a proxy created by `_createP2pYieldProxy`
    /// @param _client The address of client
    /// @param _clientBasisPoints The client basis points
    /// @return address The address of the proxy instance
    function predictP2pYieldProxyAddress(address _client, uint96 _clientBasisPoints) external view returns (address);
```

7. Client-side logic checks whether the proxy already has sufficient allowance. If not, it prompts the user to call the token’s `approve(proxyAddress, amount)`.

8. Client-side logic prompts the User to call the `deposit` function of `P2pMorphoProxyFactory`:

```solidity
    /// @notice Deposits into the Morpho vault through the user-specific proxy
    /// @param _vault The ERC4626 vault to deposit into
    /// @param _amount The amount of underlying asset to deposit
    /// @param _clientBasisPoints The client basis points
    /// @param _p2pSignerSigDeadline The P2pSigner signature deadline
    /// @param _p2pSignerSignature The P2pSigner signature
    /// @return p2pYieldProxyAddress The client's P2pMorphoProxy instance address
    function deposit(
        address _vault,
        uint256 _amount,
        uint96 _clientBasisPoints,
        uint256 _p2pSignerSigDeadline,
        bytes calldata _p2pSignerSignature
    ) external returns (address p2pYieldProxyAddress);
```

#### Morpho withdrawal flow

Look at [function _doWithdraw()](test/MainnetIntegration.sol#L185) for a reference implementation of the flow.

1. Client-side code determines how many shares to redeem from the Morpho vault.
2. Client calls `P2pMorphoProxy.withdraw(vault, shares)` from their address.
3. The proxy redeems shares through the bundler, retains the protocol fee, and transfers the remaining assets back to the client.


## Calling any function on any contracts via P2pMorphoProxy

It is possible for the client to call arbitrary functions through their proxy when explicitly allowed.
By default no additional calls are permitted; the upgradeable `AllowedCalldataChecker` can be upgraded in the future to permit extra selectors if needed.

Once the rules are configured, the client can call the permitted function via `P2pMorphoProxy.callAnyFunction`:

```solidity
    /// @notice Calls an arbitrary allowed function
    /// @param _yieldProtocolAddress The address of the yield protocol
    /// @param _yieldProtocolCalldata The calldata to call the yield protocol
    function callAnyFunction(
        address _yieldProtocolAddress,
        bytes calldata _yieldProtocolCalldata
    )
    external;
```
