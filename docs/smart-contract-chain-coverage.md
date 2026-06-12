# Smart-Contract Chain Coverage

## EVM Monitor

The continuous monitor is EVM-first and passive:

- source intake: Sourcify verified contracts
- liveness filter: native balance, major token balance, recent logs
- static scan: local source analysis only
- runtime checks: read-only RPC calls only
- alerts: private Telegram chat id only; channels and group ids are rejected

Default enabled EVM config:

- Ethereum `1`
- Base `8453`
- Arbitrum One `42161`
- Optimism `10`
- Polygon PoS `137`
- BNB Smart Chain `56`
- Avalanche C-Chain `43114`
- Linea `59144`
- Scroll `534352`
- zkSync Era `324`
- Gnosis Chain `100`
- Blast `81457`
- Mantle `5000`
- Celo `42220`

Prepared EVM candidates:

- none currently enabled as candidates in the default config

Before using a chain in production, verify:

- public RPC stability
- Sourcify coverage
- token contract addresses
- native/token value thresholds
- monitor timer staggering

## Non-EVM Coverage

Non-EVM chains should not be forced through the Solidity/EVM detector. They need
separate modules because source formats, value movement, and execution models are
different.

Default enabled non-EVM config:

- Solana: passive BPF Upgradeable Loader monitor.

The Solana monitor tracks:

- new loader signatures
- deploy, upgrade, close, and authority-change events
- program account and program-data account metadata
- current upgrade authority where JSON-RPC exposes it

Solana limitations:

- this is not source-level Rust/Anchor auditing yet
- program accounts are usually stateless; value often sits in PDAs or token
  accounts, so EVM-style contract balance filtering does not transfer directly
- high-signal alerts are upgrade and authority-change events plus direct value
  signals; they are still triage leads, not confirmed funds-at-risk findings

Recommended next modules:

- Sui: Move package collector, object/coin balance filter, Sui Move public entry detectors.
- Aptos: Move module collector, coin balance/activity filter, Aptos Move public entry detectors.
- CosmWasm chains: contract/code collector, bank/token balance filter, Rust/CosmWasm message detectors.

Shared output should stay the same where possible:

- `targets.jsonl`
- `live-filter-summary.json`
- `all-signals.jsonl`
- `high-value-triage.jsonl`
- Telegram alert events

This keeps triage and alerting common while allowing each chain family to use a
correct parser and value model.
