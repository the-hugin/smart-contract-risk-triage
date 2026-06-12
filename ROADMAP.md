# Roadmap

This is a triage tool, not an exploit framework. The roadmap is ordered by
review value and false-positive reduction, not by chain count.

## Current Baseline

- EVM Sourcify intake and local source scanning.
- EVM balance, token, recent-log, runtime-precheck, and high-value triage flows.
- Continuous EVM monitors for Ethereum, Base, Arbitrum, Optimism, Polygon, BNB
  Smart Chain, Avalanche, Linea, Scroll, zkSync Era, Gnosis, Blast, Mantle, and
  Celo.
- Passive Solana BPF Upgradeable Loader monitor with conservative value context.
- Private Telegram alert support is opt-in and disabled in public defaults.

## Near Term

1. Keep CI strict.
   - Run regression fixtures on every push and pull request.
   - Compile every Python script.
   - Validate EVM and non-EVM monitor configs.
   - Block internal paths, secret-looking assignments, and enabled public alerts.

2. Reduce EVM false positives.
   - Improve Sourcify runtime-file selection.
   - Add fixtures for every suppression rule.
   - Expand read-only prechecks for proxies, roles, ownership, and claim state.
   - Keep severity promotion tied to money-path evidence.

3. Improve Solana triage.
   - Separate loader events, upgrade-authority risk, and value-proximity signals.
   - Add better PDA and token-owner context where public RPC data is enough.
   - Keep shared fee accounts and user-owned accounts out of high-severity alerts.
   - Treat Anchor or Rust source analysis as a separate module.

## Next Chain Families

1. Sui
   - Package collector.
   - Object and coin balance filter.
   - Move public entry detectors for transfer, withdraw, claim, admin, and shared
     object patterns.

2. Aptos
   - Module collector.
   - Coin balance and activity filter.
   - Move public entry detectors adapted to Aptos resource and signer semantics.

3. CosmWasm
   - Contract and code-id collector.
   - Bank/token balance filter.
   - Message-pattern detectors for withdraw, migrate, admin, and unchecked
     recipient/value flows.

## Output Contract

New modules should keep the same review surfaces where possible:

- `targets.jsonl`
- `all-signals.jsonl`
- `live-filter-summary.json`
- `triage/high-value-triage.jsonl`
- `triage/high-value-triage.md`
- compact monitor status files

The chain-specific parser can differ. The operator workflow should not.

## Non-Goals

- No transaction sending.
- No exploit execution.
- No brute force or endpoint fuzzing.
- No credential collection.
- No public feed that claims findings are confirmed vulnerabilities.
